// Sombra — SombraClient: the only API the UI uses (SPEC §4.4, §5).
//
// Responsibilities:
//   * account lifecycle (create, unlock/lock, backup, delete, panic wipe)
//   * X3DH session establishment + Double Ratchet messaging, sealed sender
//   * the receiving algorithm of SPEC §5.3 (identity checks, key-change detection,
//     prekey/msg handling, previous sessions, simultaneous initiation)
//   * application semantics: receipts, delete-for-everyone, disappearing
//     messages, groups (pairwise fan-out), files, safety numbers
//   * prekey maintenance (OPK replenishment, SPK rotation)
//
// Concurrency: every mutation of persistent state runs inside `_serial()`, a
// promise-chain mutex, so concurrent incoming messages / sends can never interleave
// ratchet updates. Ratchet state is persisted before a message is ACKed to the
// server and before ciphertext is handed to the network.
//
// Isomorphic: no DOM, no IndexedDB (the backend is injected).

import {
  b64uEncode, b64uDecode, utf8Encode, utf8Decode, zeroize,
} from '../crypto/encoding.js';
import { randomBytes, ed25519Sign, sha256 } from '../crypto/primitives.js';
import {
  generateIdentity, publicIdentity, verifyPublicIdentity, generateSignedPrekey,
  generateOneTimePrekeys, x3dhInitiate, x3dhRespond,
  serializeKeyPair, deserializeKeyPair, serializeIdentity, deserializeIdentity,
} from '../crypto/x3dh.js';
import * as R from '../crypto/ratchet.js';
import { pad, unpad } from '../crypto/padding.js';
import { seal, unseal } from '../crypto/sealed.js';
import { safetyNumber, formatSafetyNumber } from '../crypto/safety.js';
import { createVault, unlockVault, PBKDF2_ITERATIONS } from '../crypto/vault.js';
import { MemoryBackend, EncryptedStore, META_KEY } from './store.js';
import { ServerApi, USERNAME_RE, RESERVED_USERNAMES } from './api.js';

const { ratchetInitSender, ratchetInitReceiver, ratchetEncrypt, ratchetDecrypt, ratchetNeedsRekey, ratchetPurgeSkipped } = R;
/** Signal-style bound on skipped keys (ratchet.js). */
const RATCHET_MAX_SKIP = R.MAX_SKIP;
/**
 * CRYPTO-2: a sending chain that reached REKEY_AFTER (ratchet.js) starts a fresh X3DH
 * session. If that fails transiently (network, server) the old session may still be
 * used, but never beyond this hard limit, so no loss gap can exceed MAX_SKIP.
 */
const REKEY_HARD_LIMIT = RATCHET_MAX_SKIP - 100;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const SECOND = 1000;
const DAY = 24 * 3600 * SECOND;

const INITIAL_OPKS = 100;
const OPK_LOW_WATERMARK = 20;
const OPK_BATCH = 100;
const MAX_LOCAL_OPKS = 2000;
const SPK_ROTATE_MS = 7 * DAY;
const SPK_KEEP_MS = 30 * DAY;

const MAX_PREVIOUS_SESSIONS = 3;
const MAX_REMEMBERED_EKS = 200;   // replay guard for prekey messages (see _decryptPrekey)
const SEEN_MAX = 2000;            // remembered app ids per conversation (dedup)

const SWEEP_INTERVAL_MS = 5 * SECOND;
const PARTS_TTL_MS = DAY;         // incomplete chunked files are discarded after this

export const MAX_FILE_BYTES = 8 * 1024 * 1024;
// Files larger than this are sent as several chunk messages. Each wrapping layer
// (file data b64u → ratchet ct b64u → sealed inner b64u) expands by 4/3 plus padding
// buckets, so one 8 MiB payload would produce a ~20 MiB blob, above the server's
// 12 MiB per-blob limit (SPEC §3.4). A 3 MiB chunk yields a ~9 MiB blob.
const FILE_CHUNK_BYTES = 3 * 1024 * 1024;
const MAX_FILE_PARTS = 64;
const MAX_TEXT_CHARS = 65536;
const MAX_GROUP_NAME = 64;
const MAX_GROUP_MEMBERS = 100;
const MAX_TIMER_SECONDS = 365 * 24 * 3600;
const MAX_IDS_PER_CONTROL = 1000;
const DELETE_ACCOUNT_TIMEOUT_MS = 15 * SECOND;

// --- Audit fixes (constants) -------------------------------------------------
// CRYPTO-1: unauthenticated work per incoming message. A forged header can make the
// receiver derive skipped keys and run DH ratchet steps BEFORE the AEAD check, so:
//  * total skipped-key derivations per message (abandoned chain + new chain) are
//    capped at MAX_SKIP (senders re-key after REKEY_AFTER = 500 messages, so a
//    legitimate pn-gap + n never exceeds this);
//  * only the current session may pay for an expensive step; previous sessions are
//    tried only when the step is cheap (they exist for in-flight messages);
//  * incoming frames go through a pump that yields between messages, so user
//    actions (send, receipts, sweeps) never wait behind a flood of forged blobs.
const MAX_TOTAL_SKIP = RATCHET_MAX_SKIP;
const PREVIOUS_SESSION_MAX_SKIP = 100;
// VC-4: pre-authentication skip budget when a prekey message would CREATE a session.
const NEW_SESSION_MAX_SKIP = 100;
// VC-1/VC-2: un-ACKed messages are redelivered via a 'resync' request (rate-limited).
const RESYNC_DELAY_MS = 2000;
const RESYNC_MIN_INTERVAL_MS = 11000; // server accepts one 'resync' per 10 s per connection
const MAX_INCOMING_QUEUE = 10000;
// CL-1 / SRV-01 / CRYPTO-5 / CL-5: prekey messages from an identity that is not the
// pinned contact (first contact, or a changed identity) are authenticated first
// (X3DH + AEAD), then parked in an encrypted `pend:<from>` record and confirmed
// against /api/identity LATER, after a random delay and outside the receive path.
// Nothing about the contact changes before both checks pass.
const PENDING_MAX_SENDERS = 64;
const PENDING_MAX_IDENTITIES = 3;     // distinct claimed identities parked per sender
const PENDING_MAX_PAYLOADS = 100;
const PENDING_MAX_BYTES = 16 * 1024 * 1024;
const PENDING_TOTAL_MAX_BYTES = 32 * 1024 * 1024; // CL-7: all parked senders together
const PENDING_TTL_MS = 7 * DAY;
// CL-5: payloads from a VERIFIED contact whose identity changed are held (not shown)
// until the user accepts the new safety number (acceptKeyChange / setVerified).
const HELD_MAX_PAYLOADS = 100;
const HELD_MAX_BYTES = 16 * 1024 * 1024;
// CRYPTO-8: session hygiene sweep (hourly and on every unlock).
const SESSION_SWEEP_INTERVAL_MS = 3600 * SECOND;
const PREVIOUS_SESSION_MAX_IDLE_MS = 30 * DAY;
// CL-7: storage quotas for strangers / spam.
const MAX_INFLIGHT_FILES_PER_SENDER = 2;
const FPARTS_MAX_BYTES = 32 * 1024 * 1024;
const MAX_GROUPS_PER_CREATOR = 32;
const MAX_GROUPS_TOTAL = 512;
// Default privacy delays (ms), uniformly random in [min, max]:
//  * receipts (CL-1 / SRV-01): 2-30 s, the audit's recommendation — the "delivered"
//    tick lags, in exchange the receipt POST is not an instant echo of the delivery;
//  * deferred identity confirmation of a first-contact / changed identity: 1-10 s;
//  * OPK replenishment after the pool runs low (SRV-06 presence oracle): 1-10 min.
// Stronger privacy: disable receipts or raise the delays (setPrivacyOptions). Residual
// risk: on clearnet the server still sees one source IP; Tor is the real mitigation.
const DEFAULT_PRIVACY = Object.freeze({
  deliveryReceipts: true,
  readReceipts: true,
  receiptDelayMs: [2000, 30000],
  identityDelayMs: [1000, 10000],
  prekeyRefillDelayMs: [60000, 600000],
  sendJitterMs: 250,
});
const GID_LABEL = utf8Encode('SOMBRA-GID-v1');
const REG_LABEL = utf8Encode('SOMBRA-REG-v1');

const ID_RE = /^[A-Za-z0-9_-]{22}$/;      // b64u(16 bytes): app ids, group ids
const MIME_RE = /^[a-z0-9][a-z0-9!#$&^_.+-]{0,63}\/[a-z0-9][a-z0-9!#$&^_.+-]{0,63}$/;

const STATUS_RANK = { failed: -1, sending: 0, sent: 1, delivered: 2, read: 3 };

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** A failure that must NOT cause the message to be ACKed (retry after reconnect). */
class TransientError extends Error {}

function newId() {
  return b64uEncode(randomBytes(16));
}

function normalizeUsername(u) {
  return String(u ?? '').trim().replace(/^@/, '').toLowerCase();
}

function isUint32(n) {
  return Number.isInteger(n) && n >= 0 && n <= 0xffffffff;
}

function isPlainObject(o) {
  return o !== null && typeof o === 'object' && !Array.isArray(o);
}

function directId(username) {
  return `d:${username}`;
}

function groupConvId(gid) {
  return `g:${gid}`;
}

// BUG-2: control characters (C0/C1), bidi overrides/isolates/marks, line/paragraph
// separators, zero-width and BOM characters enable display spoofing
// ("fdp.exe" shown as "exe.pdf", fake line breaks in group names).
const SPOOF_CHARS_RE = /[\u0000-\u001f\u007f-\u009f\u061c\u200b-\u200f\u2028-\u202e\u2060-\u2069\ufeff]/g;

/** Cut to at most `max` code points without splitting a surrogate pair. */
function cutCodePoints(s, max) {
  const cps = Array.from(s);
  return cps.length > max ? cps.slice(0, max).join('') : s;
}

/** Group names: strip spoofing characters, collapse whitespace, cap length. '' if empty. */
function cleanGroupName(name) {
  const s = String(name ?? '').replace(SPOOF_CHARS_RE, ' ').replace(/\s+/g, ' ').trim();
  return cutCodePoints(s, MAX_GROUP_NAME).trim();
}

function sanitizeFileName(name) {
  let s = String(name ?? '').replace(SPOOF_CHARS_RE, '').replace(/[/\\]/g, '_').trim();
  if (!s) s = 'archivo';
  return cutCodePoints(s, 255);
}

/**
 * CRYPTO-6 / CL-6: dictionaries keyed by peer-controlled strings (usernames) must
 * not inherit from Object.prototype ('__proto__', 'constructor' ...). Converts a
 * parsed JSON object into a null-prototype copy (own "__proto__" keys become plain
 * data properties and survive JSON round trips).
 */
function dict(o) {
  const d = Object.create(null);
  if (o && typeof o === 'object' && !Array.isArray(o)) {
    for (const k of Object.keys(o)) d[k] = o[k];
  }
  return d;
}

function own(d, k) {
  return d && Object.prototype.hasOwnProperty.call(d, k) ? d[k] : undefined;
}

/**
 * CRYPTO-9: X25519 ignores bit 255 and reduces mod p, so several encodings map to
 * the same point; string-keyed replay guards (ek) would treat them as different.
 * Only canonical encodings (b64u round trip, top bit clear, u < 2^255-19) are accepted.
 */
function isCanonicalX25519(str) {
  if (typeof str !== 'string' || str.length !== 43) return false;
  let b;
  try { b = b64uDecode(str); } catch { return false; }
  if (b.length !== 32 || b64uEncode(b) !== str) return false;
  if (b[31] & 0x80) return false;
  if (b[31] === 0x7f && b[0] >= 0xed) {
    let allFF = true;
    for (let i = 1; i < 31; i++) if (b[i] !== 0xff) { allFF = false; break; }
    if (allFF) return false; // u in [p, 2^255)
  }
  return true;
}

/** Uniform CSPRNG integer in [min, max]. */
function randomBetween(min, max) {
  const lo = Math.max(0, Math.floor(min));
  const hi = Math.max(lo, Math.floor(max));
  const b = randomBytes(4);
  const x = ((b[0] << 24) | (b[1] << 16) | (b[2] << 8) | b[3]) >>> 0;
  return lo + Math.floor((x / 0x100000000) * (hi - lo + 1));
}

/**
 * SRV-06: prekey ids are random (1..2^32-1), not counters — sequential OPK ids told
 * anyone fetching one bundle how many sessions were ever started with the user, and
 * sequential SPK ids (weekly rotation) the account's age. `taken` avoids collisions.
 */
function randomPrekeyId(taken) {
  for (;;) {
    const b = randomBytes(4);
    const id = ((b[0] << 24) | (b[1] << 16) | (b[2] << 8) | b[3]) >>> 0;
    if (id !== 0 && !taken.has(id)) { taken.add(id); return id; }
  }
}

/** `count` fresh OPKs with random ids not in `taken`; each local entry records its age. */
async function newOneTimePrekeys(count, taken) {
  const keys = await generateOneTimePrekeys(1, count);
  for (const o of keys) o.id = randomPrekeyId(taken); // OPKs are unsigned: the id is free
  return keys;
}

function shuffled(arr) {
  const a = [...arr];
  for (let i = a.length - 1; i > 0; i--) {
    const j = randomBetween(0, i);
    [a[i], a[j]] = [a[j], a[i]];
  }
  return a;
}

/** CL-4: group id bound to its creator: b64u(SHA-256(label || u8(len) || creator || salt16)[0..16)). */
async function groupIdFor(creator, saltBytes) {
  const name = utf8Encode(creator);
  const buf = new Uint8Array(GID_LABEL.length + 1 + name.length + saltBytes.length);
  buf.set(GID_LABEL, 0);
  buf[GID_LABEL.length] = name.length;
  buf.set(name, GID_LABEL.length + 1);
  buf.set(saltBytes, GID_LABEL.length + 1 + name.length);
  const h = await sha256(buf);
  return b64uEncode(h.slice(0, 16));
}

/**
 * CRYPTO-1: estimated skipped-key derivations ratchetDecrypt would perform for
 * `h` on `st` before authenticating, or -1 when the ratchet would reject anyway.
 * Mirrors ratchet.js: skipped-key hit (0), same chain (n - nr), or new ratchet key
 * (abandoned chain gap + n, plus one DH step).
 */
function ratchetCost(st, h) {
  if (!st || typeof st !== 'object' || st.v !== 1) return { skips: -1, dhStep: false };
  if (Array.isArray(st.skipped) && st.skipped.some((k) => k && k.dh === h.dh && k.n === h.n)) {
    return { skips: 0, dhStep: false };
  }
  if (st.dhr !== null && st.dhr !== undefined && h.dh === st.dhr) {
    if (st.ckr === null || h.n < st.nr) return { skips: -1, dhStep: false };
    return { skips: h.n - st.nr, dhStep: false };
  }
  const gap = st.ckr !== null && st.ckr !== undefined ? Math.max(0, h.pn - st.nr) : 0;
  return { skips: gap + h.n, dhStep: true };
}

function sanitizeMime(mime) {
  const m = String(mime ?? '').toLowerCase().trim();
  return MIME_RE.test(m) ? m : 'application/octet-stream';
}

/** Spanish human duration for system messages. */
function durationLabel(s) {
  if (s < 60) return `${s} s`;
  if (s < 3600) return `${Math.round(s / 60)} min`;
  if (s < 86400) return `${Math.round(s / 3600)} h`;
  if (s < 604800) return `${Math.round(s / 86400)} d`;
  return `${Math.round(s / 604800)} sem`;
}

function previewText(m) {
  if (!m) return '';
  if (m.kind === 'file') return `Archivo: ${m.file ? m.file.name : ''}`;
  return String(m.text || '').slice(0, 200);
}

function sameIk(a, b) {
  return !!a && !!b && a.ik_sig === b.ik_sig && a.ik_dh === b.ik_dh;
}

function emptySessions() {
  return { current: null, previous: [], eks: [] };
}

// ---------------------------------------------------------------------------
// SombraClient
// ---------------------------------------------------------------------------

export class SombraClient extends EventTarget {
  /**
   * @param {object} opts
   * @param {string} opts.serverUrl
   * @param {object} [opts.backend]        MemoryBackend / IdbBackend
   * @param {number} [opts.kdfIterations]  PBKDF2 iterations for NEW vaults — tests only.
   *                                       Default (production) is PBKDF2_ITERATIONS = 600000.
   * @param {Function} [opts.fetch]        fetch override (tests)
   * @param {Function} [opts.WebSocket]    WebSocket override (tests)
   * @param {Function} [opts.now]          clock override returning ms (tests)
   */
  constructor({ serverUrl, backend, kdfIterations, fetch, WebSocket, now, privacy } = {}) {
    super();
    this.backend = backend || new MemoryBackend();
    this.api = new ServerApi(serverUrl, { fetch, WebSocket });
    this._kdfIterations = Number.isInteger(kdfIterations) && kdfIterations > 0 ? kdfIterations : PBKDF2_ITERATIONS;
    this._now = typeof now === 'function' ? now : () => Date.now();
    this._gen = 0;
    this._queue = Promise.resolve();
    this._privacy = { ...DEFAULT_PRIVACY };
    this._accountLock = null;
    this._accountLockGone = null;
    this.setPrivacyOptions(privacy || {});
    this._resetMemory();
  }

  /**
   * Privacy knobs (CL-1 / SRV-01). receiptDelayMs / identityDelayMs: [min, max] ms of
   * uniformly random delay; deliveryReceipts / readReceipts: send them at all.
   */
  setPrivacyOptions(opts = {}) {
    const range = (v, dflt) => (Array.isArray(v) && v.length === 2 && v.every((x) => Number.isFinite(x) && x >= 0) && v[0] <= v[1]
      ? [v[0], v[1]] : dflt);
    const p = this._privacy;
    if (typeof opts.deliveryReceipts === 'boolean') p.deliveryReceipts = opts.deliveryReceipts;
    if (typeof opts.readReceipts === 'boolean') p.readReceipts = opts.readReceipts;
    p.receiptDelayMs = range(opts.receiptDelayMs, p.receiptDelayMs);
    p.identityDelayMs = range(opts.identityDelayMs, p.identityDelayMs);
    p.prekeyRefillDelayMs = range(opts.prekeyRefillDelayMs, p.prekeyRefillDelayMs);
    if (Number.isFinite(opts.sendJitterMs) && opts.sendJitterMs >= 0) p.sendJitterMs = opts.sendJitterMs;
  }

  _resetMemory() {
    if (this._receiptQ) for (const e of this._receiptQ.values()) clearTimeout(e.timer);
    if (this._timers) for (const t of this._timers) clearTimeout(t);
    this._receiptQ = new Map();
    this._timers = new Set();
    this._incoming = [];
    this._pumpGen = -1;
    this._confirming = new Set();
    this._store = null;
    this._account = null;
    this._identity = null;
    this._pubId = null;
    this._username = null;
    this._conn = null;
    this._sweeper = null;
    this._opkUploadPending = false;
    this._opkRefillTimer = null;
    this._spkRotatePending = false;
    this._lastSessionSweep = 0; // 0 → the first sweep after unlock runs it (CRYPTO-8)
    this._resyncTimer = null;
    this._deleteWaiter = null;
    this._unlocking = null;
  }

  // ------------------------------------------------------------------ basics

  static async hasAccount(backend) {
    const m = await backend.get(META_KEY);
    return typeof m === 'string' && m.length > 0;
  }

  get username() {
    return this._username;
  }

  get connected() {
    return !!(this._conn && this._conn.connected);
  }

  get unlocked() {
    return !!this._store;
  }

  _emit(type, detail = {}) {
    try {
      this.dispatchEvent(new CustomEvent(type, { detail }));
    } catch { /* listener errors must not break the client */ }
  }

  _emitError(message) {
    this._emit('error', { message: String(message) });
  }

  _requireUnlocked() {
    if (!this._store || this._store.closed) throw new Error('locked');
  }

  /** setTimeout bound to the current unlock generation (cleared on lock). */
  _later(ms, fn) {
    const gen = this._gen;
    const t = setTimeout(() => {
      this._timers.delete(t);
      if (gen === this._gen) { try { fn(); } catch { /* ignore */ } }
    }, ms);
    if (typeof t.unref === 'function') t.unref();
    this._timers.add(t);
    return t;
  }

  /**
   * VC-1 / VC-2: ask the server to redeliver every message we have not ACKed (it only
   * re-sends un-ACKed rows on (re)authentication otherwise). Debounced; the server also
   * rate-limits it. Duplicates are harmless: a message already processed fails the
   * ratchet (keys are single-use) and is dropped.
   */
  _requestResync() {
    if (this._resyncTimer) return;
    const now = Date.now();
    const wait = Math.max(RESYNC_DELAY_MS, (this._lastResyncAt || 0) + RESYNC_MIN_INTERVAL_MS - now);
    this._resyncTimer = this._later(wait, () => {
      this._resyncTimer = null;
      if (this._conn && this._conn.send({ t: 'resync' })) this._lastResyncAt = Date.now();
    });
  }

  // ------------------------------------------------------------------ account lock (CRYPTO-3)

  /**
   * One unlocked instance per backend (browser: per origin across tabs) via an
   * exclusive Web Lock held for the whole unlocked lifetime. Two instances on one
   * IndexedDB would read-modify-write the same ratchet state and reuse message
   * keys (AES-GCM key+IV reuse). Throws Error('open_elsewhere') if it is taken.
   * Environments without navigator.locks or a backend without `lockName` skip it.
   */
  async _acquireAccountLock() {
    const name = this.backend && typeof this.backend.lockName === 'string' ? this.backend.lockName : null;
    const locks = globalThis.navigator && globalThis.navigator.locks;
    if (!name || !locks || typeof locks.request !== 'function') return;
    if (this._accountLock) return;
    if (this._accountLockGone) await this._accountLockGone; // our own previous hold is fully released
    let release;
    const held = new Promise((r) => { release = r; });
    let granted;
    const got = new Promise((r) => { granted = r; });
    const done = locks.request(name, { mode: 'exclusive', ifAvailable: true }, (lock) => {
      granted(!!lock);
      return lock ? held : undefined;
    });
    const gone = done.then(() => {}, () => {});
    if (!(await got)) {
      await gone;
      throw new Error('open_elsewhere');
    }
    this._accountLock = { release };
    this._accountLockGone = gone;
  }

  _releaseAccountLock() {
    if (this._accountLock) {
      this._accountLock.release();
      this._accountLock = null;
    }
  }

  /**
   * Run `fn` exclusively (promise-chain mutex). Operations queued before a lock()
   * fail with Error('locked') instead of running against the next session.
   */
  _serial(fn) {
    const gen = this._gen;
    const run = async () => {
      if (gen !== this._gen) throw new Error('locked');
      this._requireUnlocked();
      return fn();
    };
    const p = this._queue.then(run, run);
    this._queue = p.catch(() => {});
    return p;
  }

  // ------------------------------------------------------------------ records

  async _get(name, dflt) {
    const v = await this._store.get(name);
    return v === undefined ? dflt : v;
  }

  _set(name, obj) {
    return this._store.set(name, obj);
  }

  // Null-prototype dictionaries (CRYPTO-6 / CL-6).
  async _getContacts() { return dict(await this._get('contacts', null)); }
  async _getConvs() { return dict(await this._get('convs', null)); }
  async _getGroups() { return dict(await this._get('groups', null)); }
  async _getFparts() { return dict(await this._get('fparts', null)); }
  _getMsgs(convId) { return this._get(`msgs:${convId}`, []); }

  async _getSessions(username) {
    const rec = await this._get(`session:${username}`, null);
    if (!rec) return emptySessions();
    if (!Array.isArray(rec.previous)) rec.previous = [];
    if (!Array.isArray(rec.eks)) rec.eks = [];
    return rec;
  }

  async _saveAccount() {
    await this._set('account', this._account);
  }

  // ------------------------------------------------------------------ account lifecycle

  /**
   * Create keys, register (with PoW), create the local vault, connect.
   * onProgress receives {stage: 'keys'|'prekeys'|'pow'|'register'|'vault'|'connect'|'done', tries?}.
   */
  async createAccount(username, passphrase, { onProgress } = {}) {
    if (this._store) throw new Error('already unlocked');
    // CL-9: captured before the first await, so a lock() issued at any point of the
    // creation (even synchronously right after the call) abandons the activation.
    const gen = this._gen;
    const progress = (p) => { if (typeof onProgress === 'function') { try { onProgress(p); } catch { /* ignore */ } } };
    const u = normalizeUsername(username);
    if (!USERNAME_RE.test(u) || RESERVED_USERNAMES.has(u)) throw new Error('bad_username'); // CL-6
    if (typeof passphrase !== 'string' || passphrase.length === 0) throw new Error('bad passphrase');
    if (await SombraClient.hasAccount(this.backend)) throw new Error('account_exists');
    if (gen !== this._gen) throw new Error('locked');
    await this._acquireAccountLock();
    if (gen !== this._gen) { this._releaseAccountLock(); throw new Error('locked'); }
    try {
      await this._createAccountLocked(u, passphrase, progress, gen);
    } catch (err) {
      if (!this._store) this._releaseAccountLock();
      throw err;
    }
  }

  async _createAccountLocked(u, passphrase, progress, gen) {
    progress({ stage: 'keys' });
    const identity = await generateIdentity();
    const pubId = await publicIdentity(identity);
    const spk = await generateSignedPrekey(identity, randomPrekeyId(new Set())); // SRV-06
    progress({ stage: 'prekeys' });
    const opks = await newOneTimePrekeys(INITIAL_OPKS, new Set());
    // CRYPTO-7: proof of possession of IK_sig bound to the username (server-verified;
    // copying another user's public identity under a new name no longer registers).
    const name = utf8Encode(u);
    const regMsg = new Uint8Array(REG_LABEL.length + 1 + name.length + 32);
    regMsg.set(REG_LABEL, 0);
    regMsg[REG_LABEL.length] = name.length;
    regMsg.set(name, REG_LABEL.length + 1);
    regMsg.set(b64uDecode(pubId.ik_dh), REG_LABEL.length + 1 + name.length);
    const regSig = await ed25519Sign(identity.sig, regMsg);

    await this.api.register({
      username: u,
      ...pubId,
      reg_sig: b64uEncode(regSig),
      spk: { id: spk.id, pub: spk.pub, sig: spk.sig },
      opks: opks.map((o) => ({ id: o.id, pub: o.pub })),
    }, { onProgress: progress });

    progress({ stage: 'vault' });
    const { meta, keys } = await createVault(passphrase, { iterations: this._kdfIterations });
    const store = new EncryptedStore(this.backend, keys);
    zeroize(keys.encKey);
    zeroize(keys.macKey);

    const now = this._now();
    const account = {
      username: u,
      identity: serializeIdentity(identity),
      spks: [{ id: spk.id, keyPair: serializeKeyPair(spk.keyPair), pub: spk.pub, sig: spk.sig, created: now }],
      opks: Object.fromEntries(opks.map((o) => [String(o.id), { ...serializeKeyPair(o.keyPair), t: now }])),
      lastSpkRotation: now,
    };
    for (const o of opks) zeroize(o.keyPair.priv);
    zeroize(spk.keyPair.priv);
    await store.set('account', account);
    await store.set('contacts', {});
    await store.set('convs', {});
    await store.set('groups', {});
    // The meta record is written last: its presence marks a complete local account.
    await this.backend.set(META_KEY, JSON.stringify(meta));

    // CL-9: a lock() during creation must not be undone by a late activation.
    if (gen !== this._gen) {
      store.close();
      zeroize(identity.sig.priv);
      zeroize(identity.dh.priv);
      throw new Error('locked');
    }
    progress({ stage: 'connect' });
    this._activate(store, account, identity, pubId);
    progress({ stage: 'done' });
  }

  /** Derive vault keys, load the account, connect. Throws Error('bad passphrase'). */
  async unlock(passphrase) {
    if (this._store) return;
    if (this._unlocking) return this._unlocking;
    // CL-9: capture the generation; lock() while the KDF runs bumps it and the
    // pending activation is abandoned (keys zeroized, store closed) instead of
    // silently re-opening the account after the UI believes it is locked.
    const gen = this._gen;
    const p = (async () => {
      let store = null;
      let identity = null;
      const abandoned = () => gen !== this._gen;
      const bail = () => {
        if (store) store.close();
        if (identity) { zeroize(identity.sig.priv); zeroize(identity.dh.priv); }
        this._releaseAccountLock();
        return new Error('locked');
      };
      const metaStr = await this.backend.get(META_KEY);
      if (typeof metaStr !== 'string') throw new Error('no_account');
      let meta;
      try { meta = JSON.parse(metaStr); } catch { throw new Error('no_account'); }
      if (abandoned()) throw bail();
      await this._acquireAccountLock(); // CRYPTO-3: throws 'open_elsewhere'
      try {
        if (abandoned()) throw bail();
        const keys = await unlockVault(passphrase, meta); // throws 'bad passphrase'
        store = new EncryptedStore(this.backend, keys);
        zeroize(keys.encKey);
        zeroize(keys.macKey);
        if (abandoned()) throw bail();
        let account;
        try {
          account = await store.get('account');
        } catch {
          if (abandoned()) throw bail();
          store.close();
          throw new Error('bad passphrase');
        }
        if (abandoned()) throw bail();
        if (!account) { store.close(); throw new Error('no_account'); }
        identity = deserializeIdentity(account.identity);
        const pubId = await publicIdentity(identity);
        if (abandoned()) throw bail();
        await this._afterRestore(store, account, meta);
        if (abandoned()) throw bail();
        this._activate(store, account, identity, pubId);
      } catch (err) {
        if (!this._store || abandoned()) this._releaseAccountLock();
        throw err;
      }
    })();
    this._unlocking = p;
    try {
      await p;
    } finally {
      if (this._unlocking === p) this._unlocking = null;
    }
  }

  /**
   * CL-3 / CRYPTO-4: first unlock after importBackup(). The restored ratchet states
   * are a snapshot: encrypting from them would reuse (dh, n) pairs — i.e. AES-GCM
   * key+IV — already used after the backup was taken. Bump the account epoch: every
   * session created before it may still DECRYPT (harmless) but never ENCRYPT; the
   * next send to each peer starts a fresh X3DH session. The SPK is rotated at once and
   * the server's whole OPK pool is replaced ('replace_opks'): OPKs uploaded after the
   * backup was taken have no private key here, so a peer using one would send an
   * undecryptable first message. Residual (documented): a backup must never be live
   * on two devices at once.
   */
  async _afterRestore(store, account, meta) {
    if (!meta || !meta.restored) return;
    account.epoch = (Number.isInteger(account.epoch) ? account.epoch : 0) + 1;
    account.lastSpkRotation = 0; // rotate on the next 'ready' / sweep
    account.replaceOpks = true;  // on the next 'ready' (cleared by 'opks_replaced')
    await store.set('account', account);
    const clean = { ...meta };
    delete clean.restored;
    await this.backend.set(META_KEY, JSON.stringify(clean)); // after the epoch is saved
  }

  _activate(store, account, identity, pubId) {
    account.opks = dict(account.opks);
    this._store = store;
    this._account = account;
    this._identity = identity;
    this._pubId = pubId;
    this._username = account.username;
    this._queue = Promise.resolve();
    this._connect();
    const gen = this._gen;
    this._sweeper = setInterval(() => {
      if (gen === this._gen) this._sweep().catch(() => {});
    }, SWEEP_INTERVAL_MS);
    if (typeof this._sweeper.unref === 'function') this._sweeper.unref();
    this._sweep().catch(() => {});
    // Pending (unconfirmed) identities left from a previous unlock: confirm later.
    this._serial(async () => {
      for (const from of await this._get('pendidx', [])) this._scheduleConfirm(from, 0);
      // C2: receipts queued before the last lock are re-armed with a FRESH random delay
      // (flushing them right away on unlock would re-create the timing link of CL-1).
      const saved = await this._get('rcptq', []);
      if (Array.isArray(saved)) {
        for (const e of saved) {
          if (!isPlainObject(e) || !USERNAME_RE.test(e.to) || !Array.isArray(e.ids)) continue;
          if (e.status !== 'delivered' && e.status !== 'read') continue;
          for (const id of e.ids) if (typeof id === 'string') this._armReceipt(e.to, e.gid || null, id, e.status);
        }
      }
    }).catch(() => {});
  }

  /** Close the socket, stop timers, drop (and zeroize) keys and state. Synchronous. */
  lock() {
    const wasUnlocked = !!this._store;
    this._gen++;
    if (this._conn) { try { this._conn.close(); } catch { /* ignore */ } }
    if (this._sweeper) clearInterval(this._sweeper);
    if (this._store) this._store.close();
    if (this._identity) {
      zeroize(this._identity.sig.priv);
      zeroize(this._identity.dh.priv);
    }
    if (this._deleteWaiter) this._deleteWaiter.reject(new Error('locked'));
    this._releaseAccountLock();
    this._resetMemory();
    this._queue = Promise.resolve();
    if (wasUnlocked) this._emit('status', { connected: false });
  }

  // ------------------------------------------------------------------ socket

  _connect() {
    const gen = this._gen;
    const identity = this._identity;
    this._conn = this.api.connect({
      username: this._username,
      sign: async (bytes) => {
        if (gen !== this._gen) throw new Error('locked');
        return ed25519Sign(identity.sig, bytes);
      },
      onMessage: (m) => { if (gen === this._gen) this._onSocketMessage(m, gen); },
      onStatus: (connected) => { if (gen === this._gen) this._emit('status', { connected }); },
      onEvent: (f) => { if (gen === this._gen) this._onSocketEvent(f, gen); },
    });
  }

  _onSocketMessage(m, gen) {
    if (!m || typeof m.id !== 'string' || typeof m.blob !== 'string') return;
    // CRYPTO-1: bounded in-memory queue drained by a pump that yields between
    // messages. Overflow is simply not ACKed: the server redelivers after reconnect.
    if (this._incoming.length >= MAX_INCOMING_QUEUE) return;
    this._incoming.push({ m, conn: this._conn, gen });
    this._pumpIncoming();
  }

  /**
   * One incoming message per _serial() turn, then a macrotask yield, so operations
   * queued meanwhile (sends, receipts, sweeps, UI reads) run between messages
   * instead of behind the whole backlog.
   */
  _pumpIncoming() {
    const gen = this._gen;
    if (this._pumpGen === gen) return;
    this._pumpGen = gen;
    const step = () => {
      if (gen !== this._gen) return; // locked: a new generation owns the (new) queue
      const item = this._incoming.shift();
      if (!item) { this._pumpGen = -1; return; }
      this._serial(() => this._processIncoming(item))
        .catch(() => {})
        .finally(() => { if (gen === this._gen) setTimeout(step, 0); });
    };
    step();
  }

  async _processIncoming({ m, conn, gen }) {
    let ack = true;
    try {
      await this._receiveBlob(m.blob);
    } catch (err) {
      // SPEC §5.3 step 4: failures are dropped silently (no oracle) but still ACKed.
      // Exceptions: we were locked mid-way, or a transient failure — then the server
      // keeps the message for redelivery.
      if (err instanceof TransientError || gen !== this._gen || (this._store && this._store.closed)) ack = false;
    }
    // Handled + ratchet persisted (or deliberately dropped) — only now tell the server.
    if (ack && gen === this._gen && conn) conn.send({ t: 'ack', ids: [m.id] });
  }

  _onSocketEvent(f, gen) {
    switch (f.t) {
      case 'ready':
        this._opkUploadPending = false;
        this._spkRotatePending = false;
        this._serial(() => this._maintainPrekeys(f.opk_count, f.spk_id)).catch(() => {});
        break;
      case 'opk_count':
        this._opkUploadPending = false;
        if (Number.isInteger(f.n) && f.n < OPK_LOW_WATERMARK) this._scheduleReplenish();
        break;
      case 'opks_replaced':
        this._opkUploadPending = false;
        this._serial(async () => {
          if (this._account.replaceOpks) { delete this._account.replaceOpks; await this._saveAccount(); }
        }).catch(() => {});
        break;
      case 'spk_ok':
        this._serial(() => this._onSpkOk(f.id)).catch(() => {});
        break;
      case 'deleted':
        if (this._deleteWaiter) this._deleteWaiter.resolve();
        break;
      case 'closed':
        if (f.code === 4004 && this._deleteWaiter) this._deleteWaiter.resolve();
        else if (f.code === 4005) {
          // CRYPTO-3: another instance (tab/device) authenticated as us. Two live
          // instances would diverge ratchet state and reuse message keys: lock.
          this.lock();
          this._emitError('replaced');
        }
        break;
      case 'error':
        if (f.code === 'auth_failed') this._emitError('auth_failed');
        else if (f.code === 'too_many_opks') this._opkUploadPending = false;
        break;
      default:
        break;
    }
    void gen;
  }

  // ------------------------------------------------------------------ prekey maintenance

  async _maintainPrekeys(opkCount, serverSpkId) {
    const acc = this._account;
    if (acc.replaceOpks) await this._replaceAllOpks();
    else if (Number.isInteger(opkCount) && opkCount < OPK_LOW_WATERMARK) this._scheduleReplenish();
    const latest = acc.spks[acc.spks.length - 1];
    if (latest && serverSpkId !== latest.id) {
      // A rotation that never got confirmed (e.g. socket dropped): re-send it.
      this._sendRotateSpk(latest);
    } else if (this._now() - (acc.lastSpkRotation || 0) >= SPK_ROTATE_MS) {
      await this._rotateSpk();
    }
    await this._pruneSpks();
  }

  /**
   * SRV-06: the server pushes opk_count when the pool runs low — right after a bundle
   * fetch, or on (re)connect. Replenishing at once would turn "drain the pool, watch
   * for fresh OPKs" into an online-presence oracle, so the upload waits a random
   * delay (privacy.prekeyRefillDelayMs). Sessions keep working meanwhile (X3DH without
   * OPK); the server's per-target OPK budget limits how fast anyone can drain the pool.
   */
  _scheduleReplenish() {
    if (this._opkRefillTimer) return;
    const [lo, hi] = this._privacy.prekeyRefillDelayMs;
    this._opkRefillTimer = this._later(randomBetween(lo, hi), () => {
      this._opkRefillTimer = null;
      this._serial(() => this._replenishOpks()).catch(() => {});
    });
  }

  /** Store fresh OPK private keys (persisted BEFORE the public halves are published). */
  async _addLocalOpks() {
    const acc = this._account;
    const fresh = await newOneTimePrekeys(OPK_BATCH, new Set(Object.keys(acc.opks).map(Number)));
    const now = this._now();
    for (const o of fresh) {
      acc.opks[String(o.id)] = { ...serializeKeyPair(o.keyPair), t: now };
      zeroize(o.keyPair.priv);
    }
    // Bound local storage (orphans from failed uploads): drop the oldest entries.
    const ids = Object.keys(acc.opks);
    if (ids.length > MAX_LOCAL_OPKS) {
      const age = (id) => (Number.isFinite(acc.opks[id].t) ? acc.opks[id].t : 0);
      ids.sort((a, b) => age(a) - age(b));
      for (const id of ids.slice(0, ids.length - MAX_LOCAL_OPKS)) delete acc.opks[id];
    }
    await this._saveAccount();
    return fresh.map((o) => ({ id: o.id, pub: o.pub }));
  }

  async _replenishOpks() {
    if (this._opkUploadPending || !this.connected) return;
    const pubs = await this._addLocalOpks();
    if (this._conn && this._conn.send({ t: 'upload_opks', opks: pubs })) this._opkUploadPending = true;
  }

  /** CL-3 / CRYPTO-4: after a restore, replace the server's whole OPK pool. */
  async _replaceAllOpks() {
    if (this._opkUploadPending || !this.connected) return;
    const pubs = await this._addLocalOpks();
    if (this._conn && this._conn.send({ t: 'replace_opks', opks: pubs })) this._opkUploadPending = true;
  }

  async _rotateSpk() {
    if (this._spkRotatePending || !this.connected) return;
    const acc = this._account;
    const id = randomPrekeyId(new Set(acc.spks.map((s) => s.id))); // SRV-06: not a counter
    const spk = await generateSignedPrekey(this._identity, id);
    const entry = { id, keyPair: serializeKeyPair(spk.keyPair), pub: spk.pub, sig: spk.sig, created: this._now() };
    zeroize(spk.keyPair.priv);
    acc.spks.push(entry);
    await this._saveAccount(); // persist before the server can hand it out
    this._sendRotateSpk(entry);
  }

  _sendRotateSpk(entry) {
    if (this._conn && this._conn.send({ t: 'rotate_spk', spk: { id: entry.id, pub: entry.pub, sig: entry.sig } })) {
      this._spkRotatePending = true;
    }
  }

  async _onSpkOk(id) {
    this._spkRotatePending = false;
    const acc = this._account;
    const latest = acc.spks[acc.spks.length - 1];
    if (!latest || latest.id !== id) return;
    const now = this._now();
    acc.lastSpkRotation = now;
    for (const s of acc.spks) if (s !== latest && !s.retiredAt) s.retiredAt = now;
    await this._saveAccount();
  }

  /** Previous SPKs are kept for 30 days after being replaced (late prekey messages). */
  async _pruneSpks() {
    const acc = this._account;
    const now = this._now();
    const latest = acc.spks[acc.spks.length - 1];
    const keep = acc.spks.filter((s) => s === latest || !s.retiredAt || now - s.retiredAt <= SPK_KEEP_MS);
    if (keep.length !== acc.spks.length) {
      acc.spks = keep;
      await this._saveAccount();
    }
  }

  // ------------------------------------------------------------------ contacts / identity

  /**
   * Record a server-confirmed identity change for `username`: update the stored keys,
   * clear verification, flag keyChanged, drop sessions bound to the old identity.
   */
  async _applyKeyChange(username, ik) {
    const contacts = await this._getContacts();
    const prev = own(contacts, username) || {};
    // CL-5 / R-3: a contact whose identity was already pinned (verified or not) is never
    // silently re-pinned for inbound traffic: a server-confirmed change is no evidence
    // against a malicious server. Everything that contact sends under the new identity is
    // held out of the conversations until the user accepts the new safety number
    // (acceptKeyChange / setVerified(true)). Before R-3 this only covered VERIFIED contacts,
    // so a server swapping the keys of an unverified contact had its messages shown at once.
    const hold = !!prev.ik_sig || !!prev.verified || !!prev.hold;
    // VC-2: remember the identity the user had pinned. Traffic still authenticated by a
    // session bound to it is genuine and keeps flowing; only the new identity is held.
    const heldPrevIk = hold
      ? (prev.heldPrevIk || (prev.ik_sig ? { ik_sig: prev.ik_sig, ik_dh: prev.ik_dh } : null))
      : null;
    contacts[username] = {
      ...prev,
      ik_sig: ik.ik_sig,
      ik_dh: ik.ik_dh,
      verified: false,
      keyChanged: true,
      hold,
      heldPrevIk,
      firstSeen: prev.firstSeen || this._now(),
    };
    await this._set('contacts', contacts);
    // CL-5: sessions bound to the old identity are NOT destroyed here: sending is
    // blocked while keyChanged, and if the change was forged (malicious server) the
    // genuine peer's in-flight messages still decrypt. acceptKeyChange() drops the
    // sessions that do not match the accepted identity.
    let text = `El número de seguridad de @${username} ha cambiado.`;
    if (hold) text += ' Sus mensajes nuevos quedan retenidos hasta que aceptes el nuevo número de seguridad.';
    const convs = await this._getConvs();
    if (own(convs, directId(username))) await this._addSystemMessage(directId(username), text);
    // CL-5: the warning also goes to every group shared with that user.
    const groups = await this._getGroups();
    for (const g of Object.values(groups)) {
      if (!g || g.left || !Array.isArray(g.members) || !g.members.includes(username)) continue;
      if (own(convs, groupConvId(g.id))) await this._addSystemMessage(groupConvId(g.id), text);
    }
    this._emit('keychange', { username });
  }

  /**
   * Route an authenticated payload: held (CL-5) while the sender's contact is on hold,
   * applied otherwise. Never touches session records (CL-10 invariant).
   */
  async _deliverPayload(from, p, sessIk = null, { force = false } = {}) {
    const c = own(await this._getContacts(), from);
    // VC-2: a payload authenticated by a session bound to the previously VERIFIED
    // identity is genuine — never hold it (a forged key change must not silence the
    // real contact).
    const fromVerifiedSession = !!(c && c.heldPrevIk && sessIk && sameIk(sessIk, c.heldPrevIk));
    if (c && c.hold && !fromVerifiedSession) {
      const held = await this._get(`held:${from}`, null) || { payloads: [], bytes: 0 };
      const size = JSON.stringify(p).length;
      // force: payloads released from the (already ACKed, separately bounded: ≤ 100 /
      // 16 MiB per sender) prekey quarantine must not be lost to a full held buffer.
      if (!force && (held.payloads.length >= HELD_MAX_PAYLOADS || held.bytes + size > HELD_MAX_BYTES)) {
        // VC-2: never drop+ACK. Not ACKed → the server keeps it; the ratchet state is not
        // committed (caller order), and it is redelivered after the hold is released.
        throw new TransientError('held_full');
      }
      held.payloads.push(p);
      held.bytes += size;
      await this._set(`held:${from}`, held);
      return;
    }
    await this._handlePayload(from, p);
  }

  /**
   * Apply what was held for `username`, in arrival order, then drop the record. The
   * caller clears contact.hold AFTERWARDS (an interruption re-applies on the next
   * accept; the (sender, id) dedup makes that idempotent).
   */
  async _releaseHeld(username) {
    const held = await this._get(`held:${username}`, null);
    if (!held) return;
    for (const p of held.payloads) {
      try {
        await this._handlePayload(username, p); // idempotent via (sender, id) dedup
      } catch (err) {
        if (!this._store || this._store.closed) throw err;
      }
    }
    await this._store.delete(`held:${username}`);
    this._requestResync(); // VC-2: messages refused while the held buffer was full
  }

  // ------------------------------------------------------------------ sessions (sending side)

  /** Fetch a bundle and create a new initiator session (X3DH + ratchetInitSender). */
  async _initiateSession(username, rec) {
    const bundle = await this.api.getBundle(username);
    if (!bundle) throw new Error(`user_not_found: ${username}`);
    if (bundle.username !== username) throw new Error('bad bundle signature');
    if (!(await verifyPublicIdentity(bundle))) throw new Error('bad bundle signature');
    const contacts = await this._getContacts();
    const c = own(contacts, username);
    if (c && !sameIk(c, bundle)) {
      // The server now serves different identity keys: a key change seen from the sending side.
      await this._applyKeyChange(username, bundle);
      throw new Error('key_changed');
    }
    // CRYPTO-7 (crypto team): bind both usernames into the AD (v2) — every client
    // initiates and responds with names, so there is no v1 fallback to downgrade to.
    const x = await x3dhInitiate(this._identity, bundle, { initiator: this._username, responder: username }); // verifies signatures
    if (!c) {
      contacts[username] = { ik_sig: bundle.ik_sig, ik_dh: bundle.ik_dh, verified: false, keyChanged: false, firstSeen: this._now() };
      await this._set('contacts', contacts);
    }
    const state = await ratchetInitSender(x.sk, x.spkPub);
    zeroize(x.sk);
    const session = {
      role: 'initiator',
      ek: x.ek,
      ad: b64uEncode(x.ad),
      ik_sig: bundle.ik_sig,
      ik_dh: bundle.ik_dh,
      peerConfirmed: false,
      x3dh: {
        ik_sig: this._pubId.ik_sig,
        ik_dh: this._pubId.ik_dh,
        ik_dh_sig: this._pubId.ik_dh_sig,
        ek: x.ek,
        spk_id: x.spk_id,
        opk_id: x.opk_id,
      },
      created: this._now(),
      epoch: this._epoch(),
      state,
    };
    if (rec.current) rec.previous.unshift(rec.current);
    rec.current = session;
    rec.previous = rec.previous.slice(0, MAX_PREVIOUS_SESSIONS);
    return session;
  }

  /**
   * Encrypt app payload bytes for `username`; persists the advanced ratchet state
   * and returns the sealed blob (b64u). Must run inside _serial().
   */
  async _encryptFor(username, paddedPayload) {
    const contacts = await this._getContacts();
    const c = own(contacts, username);
    if (c && c.keyChanged) throw new Error('key_changed');
    const rec = await this._getSessions(username);
    let s = rec.current;
    // Session bound to a different identity than the contact: start a new one (the
    // old one stays in `previous` for in-flight messages).
    if (s && c && !sameIk(s, c)) s = null;
    // CL-3 / CRYPTO-4: never encrypt from a session restored from a backup (its
    // sending chain may already have been used for other plaintexts).
    if (s && (Number.isInteger(s.epoch) ? s.epoch : 0) !== this._epoch()) s = null;
    // A responder session that was never sent on and has no sending chain yet
    // cannot encrypt.
    if (s && (!s.state || s.state.cks === null || s.state.cks === undefined)) s = null;
    if (!s) {
      s = await this._initiateSession(username, rec);
    } else if (ratchetNeedsRekey(s.state)) {
      // CRYPTO-2: REKEY_AFTER messages on one sending chain with no DH ratchet step
      // (peer silent or messages lost): re-key with a fresh X3DH session, so no loss
      // gap on a chain can reach MAX_SKIP (the receiver would refuse it forever). A
      // transient failure keeps the old session, but never past REKEY_HARD_LIMIT.
      try {
        s = await this._initiateSession(username, rec);
      } catch (err) {
        if ((err && err.message === 'key_changed') || s.state.ns >= REKEY_HARD_LIMIT ||
            !this._store || this._store.closed) {
          throw err;
        }
      }
    }
    const { state, header, ciphertext } = await ratchetEncrypt(s.state, paddedPayload, b64uDecode(s.ad), { now: this._now() });
    s.state = state;
    s.lastUsed = this._now(); // CRYPTO-8 (session age for the sweep)
    const prekey = s.role === 'initiator' && !s.peerConfirmed;
    const wire = { v: 1, type: prekey ? 'prekey' : 'msg' };
    if (prekey) wire.x3dh = s.x3dh;
    wire.header = header;
    wire.ct = b64uEncode(ciphertext);
    // Persist the advanced ratchet before the ciphertext can reach the network.
    await this._set(`session:${username}`, rec);
    const blob = await seal(this._username, b64uDecode(s.ik_dh), utf8Encode(JSON.stringify(wire)));
    return b64uEncode(blob);
  }

  /** Build + encrypt one payload for several recipients. Returns {blobs, failures}. */
  async _encryptPayload(recipients, payload) {
    const bytes = pad(utf8Encode(JSON.stringify(payload)));
    const blobs = [];
    const failures = [];
    for (const to of recipients) {
      try {
        blobs.push({ to, blob: await this._encryptFor(to, bytes) });
      } catch (err) {
        if (this._store && this._store.closed) throw err;
        failures.push({ to, ok: false, error: (err && err.message) || 'failed' });
      }
    }
    zeroize(bytes);
    return { blobs, failures };
  }

  _epoch() {
    const e = this._account && this._account.epoch;
    return Number.isInteger(e) ? e : 0;
  }

  /**
   * CL-8: every pairwise blob goes out in its OWN /api/send request (own PoW), in
   * random order with independent random jitter, so a group message is no longer a
   * single POST listing the member set (from which the sender is the one missing).
   * Residual: on clearnet all requests share the client's IP — documented; Tor
   * (separate circuits) is the real mitigation. Results keep the input order.
   */
  async _sendSplit(blobs) {
    if (!blobs.length) return [];
    const jitter = this._privacy.sendJitterMs;
    const order = shuffled(blobs.map((b, i) => i));
    const results = new Array(blobs.length);
    // APP-1: a 100-member group used to fire 99 concurrent POSTs (+99 PoW fetches), which
    // tripped the server's per-address in-flight cap (503 busy) and rate limit (429) and
    // marked the message failed. Use a small worker pool and retry transient refusals
    // with exponential backoff + jitter. Each blob still goes out in its own request.
    const POOL = 4;
    const TRANSIENT = new Set(['rate_limited', 'busy', 'network']);
    const MAX_ATTEMPTS = 6;
    const sendOne = async (i) => {
      for (let attempt = 0; ; attempt++) {
        let r;
        try {
          [r] = await this.api.send([blobs[i]]);
        } catch (err) {
          r = { to: blobs[i].to, ok: false, error: (err && err.code) || 'network' };
        }
        r = r || { to: blobs[i].to, ok: false, error: 'failed' };
        if (r.ok || !TRANSIENT.has(r.error) || attempt + 1 >= MAX_ATTEMPTS || !this.unlocked) return r;
        const base = Math.min(30000, 500 * 2 ** attempt);
        await new Promise((res) => setTimeout(res, base + randomBetween(0, base)));
      }
    };
    let next = 0;
    const worker = async () => {
      while (next < order.length) {
        const k = next++;
        const i = order[k];
        if (k > 0 && jitter > 0) await new Promise((r) => setTimeout(r, randomBetween(0, jitter)));
        results[i] = await sendOne(i);
      }
    };
    await Promise.all(Array.from({ length: Math.min(POOL, order.length) }, worker));
    return results;
  }

  /** Fire-and-forget network send (receipts etc.); never holds the mutex. */
  _dispatch(blobs) {
    if (!blobs.length) return;
    this._sendSplit(blobs).catch(() => {});
  }

  // ------------------------------------------------------------------ receiving (SPEC §5.3)

  async _receiveBlob(blobB64u) {
    // 1. Unseal with our identity DH key; validate the claimed sender.
    const { from, inner } = await unseal(this._identity.dh, b64uDecode(blobB64u));
    if (!USERNAME_RE.test(from) || from === this._username) throw new Error('drop');
    const wire = JSON.parse(utf8Decode(inner));
    if (!isPlainObject(wire) || wire.v !== 1 || !isPlainObject(wire.header) || typeof wire.ct !== 'string') {
      throw new Error('drop');
    }
    const h = wire.header;
    if (typeof h.dh !== 'string' || !isUint32(h.pn) || !isUint32(h.n)) throw new Error('drop');
    if (!isCanonicalX25519(h.dh)) throw new Error('drop'); // CRYPTO-9
    const header = { dh: h.dh, pn: h.pn, n: h.n };
    const ct = b64uDecode(wire.ct);

    let res;
    if (wire.type === 'prekey') res = await this._decryptPrekey(from, wire.x3dh, header, ct);
    else if (wire.type === 'msg') res = await this._decryptMsg(from, header, ct);
    else throw new Error('drop');

    let payload = null;
    try {
      payload = JSON.parse(utf8Decode(unpad(res.plaintext)));
    } catch {
      payload = null; // authenticated but malformed: advance the ratchet, drop the content
    } finally {
      zeroize(res.plaintext);
    }
    if (res.pending) {
      // Unconfirmed identity: session + payload parked together (one atomic record).
      await res.commit(payload);
      return;
    }
    // CL-10: apply the payload BEFORE persisting the advanced ratchet state. If we are
    // locked/killed in between, the message is not ACKed; on redelivery the old state
    // decrypts it again and the (sender, id) dedup drops the duplicate — nothing is
    // lost. Invariant: _handlePayload never reads or writes session records (receipts
    // are encrypted later, in their own _serial() task).
    if (payload !== null) await this._deliverPayload(from, payload, res.ik || null);
    await res.commit();
  }

  /** Insert a new responder session into a session record (SPEC §5.3 step 2). */
  _insertResponderSession(rec, session) {
    const cur = rec.current;
    if (cur && cur.role === 'initiator' && !cur.peerConfirmed && sameIk(cur, session) && cur.ek < session.ek) {
      // Simultaneous initiation: both sides keep the session with the smaller ek as
      // current, so they converge on one session. The other stays usable in `previous`.
      rec.previous.unshift(session);
    } else {
      if (cur) rec.previous.unshift(cur);
      rec.current = session;
    }
    rec.previous = rec.previous.slice(0, MAX_PREVIOUS_SESSIONS);
  }

  _rememberEk(list, ek) {
    if (!list.includes(ek)) list.push(ek);
    if (list.length > MAX_REMEMBERED_EKS) list.splice(0, list.length - MAX_REMEMBERED_EKS);
  }

  /**
   * 3. type "msg": current session, then previous ones — CRYPTO-1: candidates are
   * pre-screened with the work ratchetDecrypt would do before authenticating. Over
   * MAX_TOTAL_SKIP → never tried; previous sessions only when cheap; cheapest first.
   * Returns { plaintext, commit } — the advanced state is persisted by commit().
   */
  async _decryptMsg(from, header, ct) {
    const rec = await this._getSessions(from);
    const cands = [];
    [rec.current, ...rec.previous].forEach((s, i) => {
      if (!s || !s.state) return;
      const c = ratchetCost(s.state, header);
      if (c.skips < 0 || c.skips > MAX_TOTAL_SKIP) return;
      if (i > 0 && c.skips > PREVIOUS_SESSION_MAX_SKIP) return;
      cands.push({ s, i, cost: c.skips + (c.dhStep ? 64 : 0) });
    });
    cands.sort((a, b) => a.cost - b.cost || a.i - b.i);
    for (const { s } of cands) {
      let res;
      try {
        res = await ratchetDecrypt(s.state, header, ct, b64uDecode(s.ad), { now: this._now() });
      } catch {
        continue;
      }
      return {
        plaintext: res.plaintext,
        ik: { ik_sig: s.ik_sig, ik_dh: s.ik_dh }, // VC-2: identity the session is bound to
        commit: async () => {
          s.state = res.state;
          s.peerConfirmed = true; // initiator stops sending prekey messages
          s.lastUsed = this._now(); // CRYPTO-8
          await this._set(`session:${from}`, rec);
        },
      };
    }
    throw new Error('drop');
  }

  async _getPending(from) {
    const p = await this._get(`pend:${from}`, null);
    return p && Array.isArray(p.entries) ? p : { entries: [] };
  }

  async _savePending(from, pend) {
    const idx = await this._get('pendidx', []);
    // CL-7: parked bytes per sender ('pendsz'), so the total across senders is bounded.
    const sz = dict(await this._get('pendsz', null));
    if (pend.entries.length) {
      await this._set(`pend:${from}`, pend);
      if (!idx.includes(from)) { idx.push(from); await this._set('pendidx', idx); }
      sz[from] = pend.entries.reduce((n, e) => n + (Number.isFinite(e.bytes) ? e.bytes : 0), 0);
      await this._set('pendsz', sz);
    } else {
      await this._store.delete(`pend:${from}`);
      if (idx.includes(from)) await this._set('pendidx', idx.filter((u) => u !== from));
      if (own(sz, from) !== undefined) { delete sz[from]; await this._set('pendsz', sz); }
    }
  }

  /** Bytes still available for parked payloads of `from` (global CL-7 budget). */
  async _pendingRoom(from, pend) {
    const sz = dict(await this._get('pendsz', null));
    let used = 0;
    for (const [u, b] of Object.entries(sz)) if (u !== from && Number.isFinite(b)) used += b;
    for (const e of pend.entries) used += Number.isFinite(e.bytes) ? e.bytes : 0;
    return PENDING_TOTAL_MAX_BYTES - used;
  }

  /** Park a payload; returns false (nothing added) when the bounded quarantine is full. */
  _addPendingPayload(entry, payload, room) {
    if (payload === null || payload === undefined) return true;
    const size = JSON.stringify(payload).length;
    if (entry.payloads.length >= PENDING_MAX_PAYLOADS || entry.bytes + size > PENDING_MAX_BYTES || size > room) return false; // bounded
    entry.payloads.push(payload);
    entry.bytes += size;
    return true;
  }

  /**
   * 2. type "prekey". Returns { plaintext, commit, pending? }.
   *
   * CRYPTO-5: nothing about the contact (pinned keys, verified flag, sessions) is
   * touched before the message authenticates (X3DH + AEAD with the CLAIMED identity).
   * CL-1: an identity that is not the pinned contact is NOT looked up now (that
   * request, from our IP, right after the server pushed the blob, would reveal the
   * sealed sender). The session and payload are parked in `pend:<from>` and
   * confirmed against /api/identity later (_confirmPending).
   */
  async _decryptPrekey(from, x, header, ct) {
    if (!isPlainObject(x) || typeof x.ik_sig !== 'string' || typeof x.ik_dh !== 'string' ||
        typeof x.ik_dh_sig !== 'string' || typeof x.ek !== 'string' || !isUint32(x.spk_id) ||
        !(x.opk_id === null || x.opk_id === undefined || isUint32(x.opk_id))) {
      throw new Error('drop');
    }
    if (!isCanonicalX25519(x.ek) || !isCanonicalX25519(x.ik_dh)) throw new Error('drop'); // CRYPTO-9
    const ik = { ik_sig: x.ik_sig, ik_dh: x.ik_dh };
    if (!(await verifyPublicIdentity(x))) throw new Error('drop');
    const contacts = await this._getContacts();
    const c = own(contacts, from);
    const trusted = !!c && sameIk(c, ik);
    const rec = await this._getSessions(from);
    const opts = { now: this._now() };
    const checkCost = (st) => {
      const k = ratchetCost(st, header);
      if (k.skips < 0 || k.skips > MAX_TOTAL_SKIP) throw new Error('drop');
    };

    // Same X3DH ephemeral key as an existing responder session → continue that session
    // (the initiator repeats prekey messages until confirmed). Checking every stored
    // session, not only the current one, keeps simultaneous initiation lossless.
    for (const s of [rec.current, ...rec.previous]) {
      if (s && s.role === 'responder' && s.ek === x.ek && sameIk(s, ik)) {
        checkCost(s.state);
        const res = await ratchetDecrypt(s.state, header, ct, b64uDecode(s.ad), opts); // throws → drop
        return {
          plaintext: res.plaintext,
          ik, // VC-2: s is bound to this identity (checked above)
          commit: async () => {
            s.state = res.state;
            s.lastUsed = this._now(); // CRYPTO-8
            await this._set(`session:${from}`, rec);
          },
        };
      }
    }
    let pend = null;
    let entry = null;
    if (!trusted) {
      pend = await this._getPending(from);
      entry = pend.entries.find((e) => sameIk(e.ik, ik)) || null;
      for (const s of entry ? entry.sessions : []) {
        if (s.ek !== x.ek) continue;
        checkCost(s.state);
        const res = await ratchetDecrypt(s.state, header, ct, b64uDecode(s.ad), opts); // throws → drop
        return {
          plaintext: res.plaintext,
          pending: true,
          commit: async (payload) => {
            // VC-1: check room BEFORE advancing the parked state; when full, leave the
            // message un-ACKed on the server instead of dropping its content.
            if (!this._addPendingPayload(entry, payload, await this._pendingRoom(from, pend))) {
              throw new TransientError('pending_full');
            }
            s.state = res.state;
            s.lastUsed = this._now();
            await this._savePending(from, pend);
          },
        };
      }
    }
    // Replay guard: an ek we already answered must never create a second session
    // (matters for X3DH without OPK, where nothing else would stop the replay).
    if (rec.eks.includes(x.ek) || (pend && pend.entries.some((e) => e.eks.includes(x.ek)))) throw new Error('drop');
    // CRYPTO-1 / VC-4: a fresh receiver state skips `n` keys of the first chain before
    // anything is authenticated. A genuine initiator's first prekey message normally has
    // n = 0 (later ones continue the session above), so a brand-new session gets a much
    // smaller pre-authentication budget than an established one.
    if (header.n > NEW_SESSION_MAX_SKIP) throw new Error('drop');
    if (!trusted) {
      // CL-7: bounded quarantine (checked before any expensive work).
      // VC-1: when full, do NOT drop+ACK (a stranger could make a genuine first contact
      // vanish by occupying the slots): leave it on the server for redelivery once
      // unconfirmed entries clear (_requestResync after _confirmPending).
      const idx = await this._get('pendidx', []);
      if (!idx.includes(from) && idx.length >= PENDING_MAX_SENDERS) throw new TransientError('pending_full');
      if (!entry && pend.entries.length >= PENDING_MAX_IDENTITIES) throw new TransientError('pending_full');
    }

    const acc = this._account;
    const spkEntry = acc.spks.find((s) => s.id === x.spk_id);
    if (!spkEntry) throw new Error('drop');
    const opkId = x.opk_id === undefined ? null : x.opk_id;
    let opkKp = null;
    if (opkId !== null) {
      const o = own(acc.opks, String(opkId));
      if (!o) throw new Error('drop');
      opkKp = deserializeKeyPair(o);
    }
    const spkKp = deserializeKeyPair(spkEntry.keyPair);
    let sk;
    let ad;
    let state;
    try {
      ({ sk, ad } = await x3dhRespond(this._identity, spkKp, opkKp, ik, x.ek, { initiator: from, responder: this._username }));
      state = await ratchetInitReceiver(sk, spkKp);
    } finally {
      if (sk) zeroize(sk);
      zeroize(spkKp.priv);
      if (opkKp) zeroize(opkKp.priv);
    }
    const res = await ratchetDecrypt(state, header, ct, ad, opts); // throws → drop
    const session = {
      role: 'responder',
      ek: x.ek,
      ad: b64uEncode(ad),
      ik_sig: ik.ik_sig,
      ik_dh: ik.ik_dh,
      peerConfirmed: true,
      created: this._now(),
      lastUsed: this._now(),
      epoch: this._epoch(),
      state: res.state,
    };
    const forgetOpk = async () => {
      if (opkId !== null && own(acc.opks, String(opkId))) {
        delete acc.opks[String(opkId)]; // one-time prekey: forget it after use
        await this._saveAccount();
      }
    };
    if (trusted) {
      return {
        plaintext: res.plaintext,
        ik, // VC-2
        commit: async () => {
          this._insertResponderSession(rec, session);
          this._rememberEk(rec.eks, x.ek);
          await this._set(`session:${from}`, rec);
          await forgetOpk();
        },
      };
    }
    return {
      plaintext: res.plaintext,
      pending: true,
      commit: async (payload) => {
        let e = entry;
        if (!e) {
          e = { ik, sessions: [], eks: [], payloads: [], bytes: 0, created: this._now() };
        }
        // VC-1: no room for the payload → park nothing, leave it on the server.
        if (!this._addPendingPayload(e, payload, await this._pendingRoom(from, pend))) {
          throw new TransientError('pending_full');
        }
        if (!entry) pend.entries.push(e);
        e.sessions.push(session);
        if (e.sessions.length > MAX_PREVIOUS_SESSIONS + 1) e.sessions.shift();
        this._rememberEk(e.eks, x.ek);
        await this._savePending(from, pend);
        await forgetOpk();
        this._scheduleConfirm(from, 0);
      },
    };
  }

  _scheduleConfirm(from, attempt) {
    if (this._confirming.has(from)) return;
    this._confirming.add(from);
    const [lo, hi] = this._privacy.identityDelayMs;
    const backoff = attempt > 0 ? Math.min(300000, 2000 * 2 ** Math.min(attempt, 8)) : 0;
    this._later(randomBetween(lo, hi) + backoff, () => {
      this._confirmPending(from, attempt).catch(() => {});
    });
  }

  /**
   * Deferred identity confirmation of parked prekey sessions (CL-1, CRYPTO-5, CL-5).
   * The /api/identity request runs outside the mutex and long after the delivery.
   * Server confirms the claimed identity → pin (first contact) or record a key change,
   * then apply the parked payloads and move the sessions in. Otherwise everything
   * parked for that claim is discarded (its eks are remembered as a replay guard).
   */
  async _confirmPending(from, attempt) {
    this._confirming.delete(from);
    const gen = this._gen;
    let server = null;
    let netErr = false;
    try {
      server = await this.api.getIdentity(from);
    } catch {
      netErr = true;
    }
    if (gen !== this._gen) return;
    if (server && (!isPlainObject(server) || (server.username !== undefined && server.username !== from) ||
        !(await verifyPublicIdentity(server)))) {
      server = null;
    }
    let cleared = false;
    await this._serial(async () => {
      const pend = await this._getPending(from);
      if (!pend.entries.length) return;
      if (netErr) {
        const now = this._now();
        const before = pend.entries.length;
        pend.entries = pend.entries.filter((e) => now - (e.created || 0) <= PENDING_TTL_MS);
        await this._savePending(from, pend);
        if (pend.entries.length) this._scheduleConfirm(from, attempt + 1);
        if (pend.entries.length < before) cleared = true;
        return;
      }
      const entry = server ? pend.entries.find((e) => sameIk(e.ik, server)) : null;
      const rec = await this._getSessions(from);
      const known = !!(rec.current || rec.previous.length || rec.eks.length);
      if (entry) {
        const contacts = await this._getContacts();
        const c = own(contacts, from);
        if (!c) {
          contacts[from] = { ik_sig: entry.ik.ik_sig, ik_dh: entry.ik.ik_dh, verified: false, keyChanged: false, firstSeen: this._now() };
          await this._set('contacts', contacts);
        } else if (!sameIk(c, entry.ik)) {
          await this._applyKeyChange(from, entry.ik);
        }
        // Payloads first (idempotent via dedup), then sessions, then drop the record:
        // an interruption anywhere is repaired by the next confirmation run.
        for (const p of entry.payloads) {
          try {
            await this._deliverPayload(from, p, entry.ik, { force: true });
          } catch (err) {
            if (!this._store || this._store.closed || gen !== this._gen) throw err;
          }
        }
        for (const s of entry.sessions) this._insertResponderSession(rec, s);
      }
      for (const e of pend.entries) for (const ek of e.eks) this._rememberEk(rec.eks, ek);
      if (entry || known) await this._set(`session:${from}`, rec);
      await this._savePending(from, { entries: [] });
      cleared = true;
    });
    if (cleared) this._requestResync(); // VC-1: messages refused while the quarantine was full
  }

  /**
   * Validate and apply an application payload (SPEC §5.2).
   * Dedup (CL-2 / CL-11): keyed by (sender, app id) — ids are chosen by the sender, so
   * a bare id would let one group member suppress or overwrite another member's
   * message. The dedup entry is written AFTER the effect (CL-10: an interrupted
   * handler is re-run on redelivery; stored messages are also checked by (sender, id)).
   */
  async _handlePayload(from, p) {
    if (!isPlainObject(p) || typeof p.id !== 'string' || !ID_RE.test(p.id) || typeof p.kind !== 'string' ||
        !isPlainObject(p.body)) {
      return;
    }
    if (p.group !== undefined && (typeof p.group !== 'string' || !ID_RE.test(p.group))) return;
    const expire = Number.isInteger(p.expire) && p.expire > 0 && p.expire <= MAX_TIMER_SECONDS ? p.expire : 0;
    const now = this._now();
    const ts = Number.isFinite(p.ts) && p.ts > 0 ? Math.min(p.ts, now) : now; // ts is informational

    let convId;
    let group = null;
    if (p.group) {
      convId = groupConvId(p.group);
      const groups = await this._getGroups();
      group = own(groups, p.group) || null;
      if (!group) {
        // Unknown group: only a creation (group_update) is accepted (see _onGroupUpdate).
        if (p.kind !== 'group_update') return;
      } else {
        if (!Array.isArray(group.members) || !group.members.includes(from)) return; // non-member → drop
        if (p.kind === 'group_update' && from !== group.admin) return;              // admin only
        if (group.left && p.kind !== 'group_update') return;
        // CL-7: content for a group conversation the user deleted locally is dropped
        // (it would otherwise grow an invisible message list forever).
        if ((p.kind === 'text' || p.kind === 'file') && !own(await this._getConvs(), convId)) return;
      }
    } else {
      convId = directId(from);
    }

    const seenKey = `${from}|${p.id}`;
    const seen = await this._get(`seen:${convId}`, []);
    if (seen.includes(seenKey)) return;

    const ctx = { from, convId, group, gid: p.group || null, id: p.id, ts, now, expire };
    switch (p.kind) {
      case 'text': await this._onText(ctx, p.body); break;
      case 'file': await this._onFile(ctx, p.body); break;
      case 'receipt': await this._onReceipt(ctx, p.body); break;
      case 'delete': await this._onDelete(ctx, p.body); break;
      case 'timer': await this._onTimer(ctx, p.body); break;
      case 'group_update': await this._onGroupUpdate(ctx, p.body); break;
      case 'group_leave': await this._onGroupLeave(ctx); break;
      default: break; // unknown kinds are ignored (forward compatibility)
    }
    await this._markSeen(convId, seenKey);
  }

  async _markSeen(convId, key) {
    const seen = await this._get(`seen:${convId}`, []);
    if (seen.includes(key)) return;
    seen.push(key);
    if (seen.length > SEEN_MAX) seen.splice(0, seen.length - SEEN_MAX);
    await this._set(`seen:${convId}`, seen);
  }

  async _ensureDirectConv(peer) {
    const convs = await this._getConvs();
    const id = directId(peer);
    if (!own(convs, id)) {
      convs[id] = { id, type: 'direct', peer, title: peer, timer: 0, unread: 0, lastText: '', lastTs: 0, created: this._now() };
      await this._set('convs', convs);
    }
    return id;
  }

  async _onText(ctx, body) {
    if (typeof body.text !== 'string' || body.text.length === 0 || body.text.length > MAX_TEXT_CHARS) return;
    const msg = {
      id: ctx.id, convId: ctx.convId, from: ctx.from, mine: false, ts: ctx.ts, kind: 'text',
      text: body.text, status: 'delivered',
    };
    await this._storeIncoming(ctx, msg);
  }

  async _storeIncoming(ctx, msg, fileB64 = null) {
    const msgs = await this._getMsgs(ctx.convId);
    // CL-2 / CL-11: the same (sender, id) already stored → duplicate (survives SEEN_MAX
    // eviction). An id already used by ANOTHER message (other sender, or ours) gets a
    // fresh local id; the sender's id is kept as `rid` for receipts and deletions.
    // Local ids are therefore unique per conversation, and so are the file records
    // `file:<convId>:<id>` — nobody can overwrite or delete someone else's file data.
    if (msgs.some((m) => m.from === msg.from && (m.rid || m.id) === msg.id)) return;
    if (msgs.some((m) => m.id === msg.id)) {
      msg.rid = msg.id;
      msg.id = newId();
    }
    if (!ctx.gid) await this._ensureDirectConv(ctx.from);
    if (ctx.expire) {
      msg.expire = ctx.expire;
      msg.expiresAt = ctx.now + ctx.expire * SECOND; // receiver: counted from receipt
    }
    // CL-5: the sender's identity changed and the user has not accepted it yet.
    const contact = own(await this._getContacts(), ctx.from);
    if (contact && contact.keyChanged) msg.keyChanged = true;
    if (fileB64 !== null) await this._set(`file:${ctx.convId}:${msg.id}`, { data: fileB64 });
    await this._appendMessage(ctx.convId, msg, { unread: true });
    // Delivery receipt (never for receipts themselves): queued, sent later with a
    // random delay, outside the receive path (CL-1 / SRV-01).
    await this._queueReceipt(ctx.from, ctx.gid, msg.rid || msg.id, 'delivered');
    this._emit('message', { convId: ctx.convId, message: this._publicMessage(msg, fileB64 !== null ? b64uDecode(fileB64) : null) });
  }

  /**
   * CL-1 / SRV-01: receipts are never sent from the receive path. An immediate,
   * automatic POST /api/send to=<sender> from the recipient's IP, milliseconds after
   * the server pushed the blob, tells the server who sent the sealed message. They are
   * coalesced per (recipient, group, status) and flushed after an independent random
   * delay, each in its own request; they can be disabled (setPrivacyOptions).
   * SPEC §5.2 amended: "immediately" → "after a random delay, optional".
   * Residual risk (documented): timing correlation within the delay window and the
   * shared source IP on clearnet; use Tor and/or longer delays for stronger
   * unlinkability.
   */
  async _queueReceipt(to, gid, id, status) {
    if (!this._armReceipt(to, gid, id, status)) return;
    await this._saveReceiptQ(); // C2: survives lock / tab close until actually sent
  }

  /** Persist the pending receipt queue (encrypted store). Caller holds the mutex. */
  async _saveReceiptQ() {
    const list = [...this._receiptQ.values()].map((e) => ({ to: e.to, gid: e.gid || null, status: e.status, ids: e.ids }));
    if (list.length) await this._set('rcptq', list);
    else await this._store.delete('rcptq');
  }

  /** Add to the in-memory queue and arm its random-delay timer. Returns false if disabled. */
  _armReceipt(to, gid, id, status) {
    const p = this._privacy;
    if (status === 'delivered' ? !p.deliveryReceipts : !p.readReceipts) return false;
    const key = `${to}|${gid || ''}|${status}`;
    let e = this._receiptQ.get(key);
    if (!e) {
      e = { to, gid, status, ids: [], timer: null };
      this._receiptQ.set(key, e);
    }
    if (!e.ids.includes(id)) e.ids.push(id);
    if (!e.timer) {
      const [lo, hi] = p.receiptDelayMs;
      e.timer = this._later(randomBetween(lo, hi), () => this._flushReceipt(key));
    }
    return true;
  }

  _flushReceipt(key) {
    const e = this._receiptQ.get(key);
    if (!e) return;
    this._receiptQ.delete(key);
    this._serial(async () => {
      // C2: removed from the persisted queue in the same task that encrypts it (a lock
      // before this point keeps it queued; after it, the ratchet already advanced).
      await this._saveReceiptQ();
      const blobs = [];
      for (let i = 0; i < e.ids.length; i += MAX_IDS_PER_CONTROL) {
        const payload = { id: newId(), ts: this._now(), kind: 'receipt', body: { ids: e.ids.slice(i, i + MAX_IDS_PER_CONTROL), status: e.status } };
        if (e.gid) payload.group = e.gid;
        const enc = await this._encryptPayload([e.to], payload);
        blobs.push(...enc.blobs);
      }
      return blobs;
    }).then((blobs) => this._dispatch(blobs)).catch(() => {});
  }

  async _onFile(ctx, body) {
    const { name, mime, size, data, part } = body;
    if (typeof name !== 'string' || typeof mime !== 'string' || typeof data !== 'string' ||
        !Number.isInteger(size) || size < 0 || size > MAX_FILE_BYTES) {
      return;
    }
    let bytes;
    try { bytes = b64uDecode(data); } catch { return; }
    const meta = { name: sanitizeFileName(name), mime: sanitizeMime(mime), size };
    if (part === undefined) {
      if (bytes.length !== size) return;
      const msg = { id: ctx.id, convId: ctx.convId, from: ctx.from, mine: false, ts: ctx.ts, kind: 'file', file: meta, status: 'delivered' };
      return this._storeIncoming(ctx, msg, data);
    }
    // Chunked file: {fid, i, n}; reassembled once every part has arrived.
    if (!isPlainObject(part) || typeof part.fid !== 'string' || !ID_RE.test(part.fid) ||
        !Number.isInteger(part.n) || part.n < 2 || part.n > MAX_FILE_PARTS ||
        !Number.isInteger(part.i) || part.i < 0 || part.i >= part.n || bytes.length > FILE_CHUNK_BYTES) {
      return;
    }
    // CL-2: "already assembled" and dedup are per sender.
    const fidSeen = `${ctx.from}|${part.fid}`;
    if ((await this._get(`seen:${ctx.convId}`, [])).includes(fidSeen)) return;
    const msgs = await this._getMsgs(ctx.convId);
    if (msgs.some((m) => m.from === ctx.from && (m.rid || m.id) === part.fid)) return;
    const key = `${ctx.convId}|${ctx.from}|${part.fid}`;
    const index = await this._getFparts();
    let entry = own(index, key);
    if (!entry) {
      // CL-7: quotas — in-flight chunked files per sender and total reserved bytes.
      const entries = Object.values(index);
      if (entries.filter((e) => e.from === ctx.from).length >= MAX_INFLIGHT_FILES_PER_SENDER) return;
      if (entries.reduce((s, e) => s + (Number.isInteger(e.size) ? e.size : 0), 0) + size > FPARTS_MAX_BYTES) return;
      entry = { convId: ctx.convId, from: ctx.from, fid: part.fid, ...meta, n: part.n, got: [], bytes: 0, created: ctx.now, expire: ctx.expire, ts: ctx.ts, gid: ctx.gid };
      index[key] = entry;
    }
    if (entry.n !== part.n || entry.size !== size || entry.got.includes(part.i)) return;
    if (entry.bytes + bytes.length > entry.size) {
      for (const i of entry.got) await this._store.delete(`fpart:${key}:${i}`);
      delete index[key];
      await this._set('fparts', index);
      return;
    }
    await this._set(`fpart:${key}:${part.i}`, { data });
    entry.got.push(part.i);
    entry.bytes += bytes.length;
    await this._set('fparts', index);
    if (entry.got.length < entry.n) return;

    // Complete: assemble in order and verify the total length.
    const chunks = [];
    for (let i = 0; i < entry.n; i++) {
      const r = await this._get(`fpart:${key}:${i}`, null);
      if (!r) return;
      chunks.push(b64uDecode(r.data));
    }
    const total = chunks.reduce((s, c) => s + c.length, 0);
    if (total === entry.size) {
      const all = new Uint8Array(total);
      let off = 0;
      for (const c of chunks) { all.set(c, off); off += c.length; }
      const msg = {
        id: entry.fid, convId: entry.convId, from: entry.from, mine: false, ts: entry.ts, kind: 'file',
        file: { name: entry.name, mime: entry.mime, size: entry.size }, status: 'delivered',
      };
      await this._storeIncoming({ ...ctx, id: entry.fid, expire: entry.expire, ts: entry.ts }, msg, b64uEncode(all));
      await this._markSeen(ctx.convId, fidSeen);
    }
    for (let i = 0; i < entry.n; i++) await this._store.delete(`fpart:${key}:${i}`);
    delete index[key];
    await this._set('fparts', index);
  }

  async _onReceipt(ctx, body) {
    const { ids, status } = body;
    if (!Array.isArray(ids) || ids.length > MAX_IDS_PER_CONTROL || (status !== 'delivered' && status !== 'read')) return;
    const want = new Set(ids.filter((x) => typeof x === 'string'));
    const msgs = await this._getMsgs(ctx.convId);
    let changed = null;
    for (const m of msgs) {
      if (!m.mine || !want.has(m.id)) continue;
      if (!Array.isArray(m.to) || !m.to.includes(ctx.from)) continue;
      m.rcpt = dict(m.rcpt);
      const prev = own(m.rcpt, ctx.from);
      if (prev && STATUS_RANK[prev] >= STATUS_RANK[status]) continue;
      m.rcpt[ctx.from] = status;
      const agg = this._aggregateStatus(m);
      if (STATUS_RANK[agg] > STATUS_RANK[m.status]) m.status = agg;
      changed = changed || [];
      changed.push(m.id);
    }
    if (!changed) return;
    await this._set(`msgs:${ctx.convId}`, msgs);
    for (const id of changed) this._emit('update', { convId: ctx.convId, messageId: id });
  }

  /** delivered/read only once every recipient reported it. */
  _aggregateStatus(m) {
    const to = Array.isArray(m.to) ? m.to : [];
    if (!to.length) return m.status;
    const ranks = to.map((u) => STATUS_RANK[own(m.rcpt, u)] ?? STATUS_RANK.sent);
    const min = Math.min(...ranks);
    return min >= STATUS_RANK.read ? 'read' : min >= STATUS_RANK.delivered ? 'delivered' : 'sent';
  }

  async _onDelete(ctx, body) {
    if (!Array.isArray(body.ids) || body.ids.length > MAX_IDS_PER_CONTROL) return;
    const ids = new Set(body.ids.filter((x) => typeof x === 'string'));
    // Only the original sender may delete their own messages (matched by the
    // sender's id, CL-2: never another sender's message that reused the id).
    const removed = await this._removeMessages(ctx.convId, (m) => !m.mine && m.from === ctx.from && ids.has(m.rid || m.id));
    // A partially received chunked file being deleted: drop its parts.
    const index = await this._getFparts();
    let touched = false;
    for (const [key, e] of Object.entries(index)) {
      if (e.convId === ctx.convId && e.from === ctx.from && ids.has(e.fid)) {
        for (const i of e.got) await this._store.delete(`fpart:${key}:${i}`);
        delete index[key];
        touched = true;
      }
    }
    if (touched) await this._set('fparts', index);
    if (removed.length) this._emit('update', { convId: ctx.convId });
  }

  async _onTimer(ctx, body) {
    const s = body.seconds;
    if (!Number.isInteger(s) || s < 0 || s > MAX_TIMER_SECONDS) return;
    if (!ctx.gid) await this._ensureDirectConv(ctx.from);
    const convs = await this._getConvs();
    const conv = own(convs, ctx.convId);
    if (!conv) return;
    conv.timer = s;
    await this._set('convs', convs);
    await this._addSystemMessage(ctx.convId, s
      ? `@${ctx.from} activó los mensajes temporales (${durationLabel(s)}).`
      : `@${ctx.from} desactivó los mensajes temporales.`);
    this._emit('update', { convId: ctx.convId });
    this._emit('conversations', {});
  }

  _validGroupInfo(g, gid) {
    if (!isPlainObject(g) || g.id !== gid || typeof g.name !== 'string' || !Array.isArray(g.members) ||
        typeof g.admin !== 'string') {
      return null;
    }
    const name = cleanGroupName(g.name); // BUG-2
    const members = [...new Set(g.members)];
    if (!name || members.length < 1 || members.length > MAX_GROUP_MEMBERS ||
        !members.every((u) => typeof u === 'string' && USERNAME_RE.test(u)) || !members.includes(g.admin)) {
      return null;
    }
    return { id: gid, name, members, admin: g.admin };
  }

  /**
   * CL-4: a group id is bound to its creator (gid = H(creator, salt)). An update for
   * an unknown gid is accepted only as a creation by that creator, who must be the
   * admin. Without the binding any member (or ex-member) could "create" a known gid
   * on a victim first, become admin of the victim's view, choose the member list the
   * victim fans out to, and lock the real admin out.
   */
  async _checkGroupCreation(g, gid, from) {
    if (!isPlainObject(g) || g.creator !== from || g.admin !== from || typeof g.salt !== 'string') return null;
    let salt;
    try { salt = b64uDecode(g.salt); } catch { return null; }
    if (salt.length !== 16) return null;
    if ((await groupIdFor(from, salt)) !== gid) return null;
    return { creator: from, salt: g.salt };
  }

  async _onGroupUpdate(ctx, body) {
    const info = this._validGroupInfo(body.group, ctx.gid);
    if (!info) return;
    const groups = await this._getGroups();
    const existing = own(groups, ctx.gid);
    let binding;
    if (!existing) {
      // Creation: the sender is creator + admin and a member; we must be one too.
      if (info.admin !== ctx.from || !info.members.includes(this._username)) return;
      binding = await this._checkGroupCreation(body.group, ctx.gid, ctx.from);
      if (!binding) return;
      // CL-7: group-creation spam is bounded per creator and in total.
      const all = Object.values(groups);
      if (all.length >= MAX_GROUPS_TOTAL) return;
      if (all.filter((g) => g && g.creator === ctx.from && !g.left).length >= MAX_GROUPS_PER_CREATOR) return;
    } else if (ctx.from !== existing.admin) {
      return;
    } else {
      binding = { creator: existing.creator, salt: existing.salt };
    }
    const wasMember = existing ? !existing.left : false;
    const isMember = info.members.includes(this._username);
    groups[ctx.gid] = { ...info, ...binding, left: !isMember };
    await this._set('groups', groups);
    const convs = await this._getConvs();
    const convId = ctx.convId;
    if (!own(convs, convId)) {
      convs[convId] = { id: convId, type: 'group', group: ctx.gid, title: info.name, timer: 0, unread: 0, lastText: '', lastTs: 0, created: ctx.now };
    }
    convs[convId].title = info.name;
    await this._set('convs', convs);

    let text;
    if (!existing) text = `@${ctx.from} te añadió al grupo «${info.name}».`;
    else if (!isMember) text = `@${ctx.from} te eliminó del grupo.`;
    else if (!wasMember) text = `@${ctx.from} te volvió a añadir al grupo.`;
    else {
      const added = info.members.filter((u) => !existing.members.includes(u));
      const removed = existing.members.filter((u) => !info.members.includes(u));
      const parts = [];
      if (added.length) parts.push(`añadió a ${added.map((u) => '@' + u).join(', ')}`);
      if (removed.length) parts.push(`eliminó a ${removed.map((u) => '@' + u).join(', ')}`);
      if (existing.name !== info.name) parts.push(`renombró el grupo a «${info.name}»`);
      text = parts.length ? `@${ctx.from} ${parts.join('; ')}.` : null;
    }
    if (text) await this._addSystemMessage(convId, text);
    this._emit('conversations', {});
    this._emit('update', { convId });
  }

  async _onGroupLeave(ctx) {
    const groups = await this._getGroups();
    const g = own(groups, ctx.gid);
    if (!g) return;
    g.members = g.members.filter((u) => u !== ctx.from);
    // Admin left: deterministic successor so every member agrees without coordination.
    if (g.admin === ctx.from) g.admin = g.members[0] || '';
    await this._set('groups', groups);
    await this._addSystemMessage(ctx.convId, `@${ctx.from} salió del grupo.`);
    this._emit('conversations', {});
    this._emit('update', { convId: ctx.convId });
  }

  // ------------------------------------------------------------------ local message storage

  async _appendMessage(convId, msg, { unread = false } = {}) {
    const msgs = await this._getMsgs(convId);
    msgs.push(msg);
    await this._set(`msgs:${convId}`, msgs);
    const convs = await this._getConvs();
    const conv = own(convs, convId);
    if (conv) {
      conv.lastText = previewText(msg);
      conv.lastTs = msg.ts;
      if (unread) conv.unread = (conv.unread || 0) + 1;
      if (msg.expiresAt && (!conv.nextExpiry || msg.expiresAt < conv.nextExpiry)) conv.nextExpiry = msg.expiresAt;
      await this._set('convs', convs);
    }
  }

  async _addSystemMessage(convId, text) {
    const msg = { id: newId(), convId, from: '', mine: false, ts: this._now(), kind: 'system', text, status: 'read' };
    await this._appendMessage(convId, msg);
    return msg;
  }

  /** Remove messages matching `pred` (and their file data); fixes up the conv preview. */
  async _removeMessages(convId, pred) {
    const msgs = await this._getMsgs(convId);
    const removed = msgs.filter(pred);
    if (!removed.length) return removed;
    const keep = msgs.filter((m) => !pred(m));
    // CL-2: never delete a file record still referenced by a kept message (legacy
    // histories may contain duplicate ids from before per-conversation unique ids).
    const kept = new Set(keep.map((m) => m.id));
    for (const m of removed) if (m.kind === 'file' && !kept.has(m.id)) await this._store.delete(`file:${convId}:${m.id}`);
    await this._set(`msgs:${convId}`, keep);
    const convs = await this._getConvs();
    const conv = own(convs, convId);
    if (conv) {
      const last = keep[keep.length - 1];
      conv.lastText = last ? previewText(last) : '';
      conv.lastTs = last ? last.ts : conv.lastTs;
      conv.unread = keep.filter((m) => !m.mine && m.kind !== 'system' && !m.readSent).length;
      const exp = keep.filter((m) => m.expiresAt).map((m) => m.expiresAt);
      conv.nextExpiry = exp.length ? Math.min(...exp) : 0;
      await this._set('convs', convs);
    }
    return removed;
  }

  _publicMessage(m, fileData = null) {
    const out = {
      id: m.id, convId: m.convId, from: m.from, mine: m.mine, ts: m.ts, kind: m.kind, status: m.status,
    };
    if (m.text !== undefined) out.text = m.text;
    if (m.file) out.file = { name: m.file.name, mime: m.file.mime, size: m.file.size, data: fileData || new Uint8Array(0) };
    if (m.expiresAt) out.expiresAt = m.expiresAt;
    // CL-5: sent by an identity the user has not accepted yet (safety number changed).
    if (m.keyChanged) out.keyChanged = true;
    return out;
  }

  /** Disappearing messages + stale chunk cleanup; runs every 5 s while unlocked. */
  _sweep() {
    return this._serial(async () => {
      const now = this._now();
      const convs = await this._getConvs();
      for (const conv of Object.values(convs)) {
        if (!conv.nextExpiry || conv.nextExpiry > now) continue;
        const removed = await this._removeMessages(conv.id, (m) => m.expiresAt && m.expiresAt <= now);
        if (removed.length) this._emit('update', { convId: conv.id });
        else {
          // nextExpiry was stale: recompute
          const c2 = await this._getConvs();
          if (c2[conv.id]) { c2[conv.id].nextExpiry = 0; await this._set('convs', c2); }
        }
      }
      const index = await this._get('fparts', null);
      if (index) {
        let touched = false;
        for (const [key, e] of Object.entries(index)) {
          if (now - e.created > PARTS_TTL_MS) {
            for (const i of e.got) await this._store.delete(`fpart:${key}:${i}`);
            delete index[key];
            touched = true;
          }
        }
        if (touched) await this._set('fparts', index);
      }
      // Long-lived sessions: rotate the SPK on schedule without waiting for a reconnect.
      if (this.connected && now - (this._account.lastSpkRotation || 0) >= SPK_ROTATE_MS) await this._rotateSpk();
      // CRYPTO-8: session hygiene on unlock and then about hourly.
      if (!this._lastSessionSweep || now - this._lastSessionSweep >= SESSION_SWEEP_INTERVAL_MS) {
        this._lastSessionSweep = now;
        await this._sweepSessions(now);
      }
    });
  }

  /**
   * CRYPTO-8: forward-secrecy hygiene for stored sessions. ratchet.js expires skipped
   * message keys after SKIPPED_KEY_MAX_AGE_MS (the server's message TTL) whenever a
   * session encrypts/decrypts; idle sessions are purged here, so a ciphertext a
   * malicious server withholds is not decryptable from a seized vault forever.
   * Previous sessions unused (no encrypt/decrypt) for 30 days are dropped entirely.
   * Sessions exist only for pinned contacts, plus parked ones in `pend:` records.
   * Must run inside _serial().
   */
  async _sweepSessions(now) {
    const purge = (s) => {
      if (!s || !s.state || !Array.isArray(s.state.skipped)) return false;
      let st;
      try { st = ratchetPurgeSkipped(s.state, now); } catch { return false; }
      // Changed if keys were dropped or legacy entries got their first timestamp.
      if (JSON.stringify(st.skipped) === JSON.stringify(s.state.skipped)) return false;
      s.state = st;
      return true;
    };
    const contacts = await this._getContacts();
    for (const u of Object.keys(contacts)) {
      const rec = await this._get(`session:${u}`, null);
      if (!rec) continue;
      let changed = purge(rec.current);
      const prev = Array.isArray(rec.previous) ? rec.previous : [];
      const keep = [];
      for (const s of prev) {
        if (!s) { changed = true; continue; }
        const last = Number.isFinite(s.lastUsed) ? s.lastUsed : (Number.isFinite(s.created) ? s.created : null);
        if (last === null) { s.lastUsed = now; changed = true; } // legacy: start the clock now
        else if (now - last > PREVIOUS_SESSION_MAX_IDLE_MS) { changed = true; continue; }
        if (purge(s)) changed = true;
        keep.push(s);
      }
      if (changed) {
        rec.previous = keep;
        await this._set(`session:${u}`, rec);
      }
    }
    for (const from of await this._get('pendidx', [])) {
      const pend = await this._getPending(from);
      let changed = false;
      for (const e of pend.entries) for (const s of e.sessions || []) if (purge(s)) changed = true;
      if (changed) await this._savePending(from, pend);
    }
  }

  // ------------------------------------------------------------------ outgoing helpers

  /** Recipients (excluding self) for a conversation. Inside _serial(). */
  async _recipientsFor(conv) {
    if (conv.type === 'direct') return [conv.peer];
    const groups = await this._getGroups();
    const g = groups[conv.group];
    if (!g || g.left || !g.members.includes(this._username)) throw new Error('not_member');
    return g.members.filter((u) => u !== this._username);
  }

  /** Same, but awaits the network result (used by user-initiated actions). */
  async _sendControlNow(prep) {
    if (!prep.blobs.length) return prep.failures;
    const results = await this._sendSplit(prep.blobs);
    return [...results, ...prep.failures];
  }

  /**
   * Send one content message (text or file). Phase 1 (locked): store locally with
   * status 'sending', encrypt for every recipient (ratchets persisted). Phase 2:
   * network, outside the lock. Phase 3 (locked): status sent/failed.
   */
  async _sendContent(convId, kind, body, local, parts = null) {
    const prep = await this._serial(async () => {
      const convs = await this._getConvs();
      const conv = convs[convId];
      if (!conv) throw new Error('not_found');
      const recipients = await this._recipientsFor(conv);
      const now = this._now();
      const id = newId();
      const expire = conv.timer || 0;
      const msg = { id, convId, from: this._username, mine: true, ts: now, kind, status: 'sending', to: recipients, rcpt: {} };
      if (local.text !== undefined) msg.text = local.text;
      if (local.file) msg.file = { ...local.file };
      if (expire) { msg.expire = expire; msg.expiresAt = now + expire * SECOND; }
      // File bytes live in their own record, not in the (frequently rewritten) message list.
      if (local.fileB64 !== undefined) await this._set(`file:${convId}:${id}`, { data: local.fileB64 });
      await this._markSeen(convId, `${this._username}|${id}`);
      await this._appendMessage(convId, msg);
      this._emit('message', { convId, message: this._publicMessage(msg, local.fileBytes || null) });
      return { msg, recipients, expire, gid: conv.type === 'group' ? conv.group : null };
    });

    const makePayload = (pid, pbody) => {
      const p = { id: pid, ts: prep.msg.ts, kind, body: pbody };
      if (prep.gid) p.group = prep.gid;
      if (prep.expire) p.expire = prep.expire;
      return p;
    };
    const units = parts
      ? parts.map((pb) => makePayload(newId(), pb(prep.msg.id)))
      : [makePayload(prep.msg.id, body)];

    const okBy = new Map(prep.recipients.map((u) => [u, true]));
    let firstError = null;
    for (const payload of units) {
      // Encrypt one unit at a time (bounded memory for big chunked files).
      const enc = await this._serial(() => this._encryptPayload(prep.recipients.filter((u) => okBy.get(u)), payload));
      const results = await this._sendControlNow(enc);
      for (const r of results) {
        if (!r.ok) {
          okBy.set(r.to, false);
          firstError = firstError || r.error;
        }
      }
    }
    const anyOk = prep.recipients.length === 0 || [...okBy.values()].some(Boolean);

    const final = await this._serial(async () => {
      const msgs = await this._getMsgs(convId);
      const m = msgs.find((x) => x.id === prep.msg.id);
      if (!m) return prep.msg; // deleted meanwhile
      if (anyOk) {
        if (STATUS_RANK[m.status] < STATUS_RANK.sent) m.status = 'sent';
        m.to = (m.to || []).filter((u) => okBy.get(u));
        const agg = this._aggregateStatus(m);
        if (STATUS_RANK[agg] > STATUS_RANK[m.status]) m.status = agg;
      } else if (m.status === 'sending') {
        m.status = 'failed';
      }
      await this._set(`msgs:${convId}`, msgs);
      this._emit('update', { convId, messageId: m.id });
      return m;
    });
    if (!anyOk) throw new Error(firstError || 'send_failed');
    if (firstError) this._emitError(firstError);
    return this._publicMessage(final, local.fileBytes || null);
  }

  // ------------------------------------------------------------------ public API: conversations

  async listConversations() {
    this._requireUnlocked();
    const [convs, contacts, groups] = await Promise.all([this._getConvs(), this._getContacts(), this._getGroups()]);
    return Object.values(convs).map((c) => {
      const out = {
        id: c.id, type: c.type, title: c.title, lastText: c.lastText || '', lastTs: c.lastTs || 0,
        unread: c.unread || 0, timer: c.timer || 0, verified: false, keyChanged: false,
      };
      if (c.type === 'direct') {
        const ct = own(contacts, c.peer) || {};
        out.peer = c.peer;
        out.verified = !!ct.verified;
        out.keyChanged = !!ct.keyChanged;
      } else {
        const g = groups[c.group] || { members: [], admin: '', name: c.title };
        out.title = g.name || c.title;
        out.members = [...g.members];
        out.admin = g.admin;
        out.left = !!g.left;
      }
      return out;
    });
  }

  async getMessages(convId) {
    this._requireUnlocked();
    const msgs = await this._getMsgs(convId);
    const now = this._now();
    const out = [];
    for (const m of msgs) {
      if (m.expiresAt && m.expiresAt <= now) continue;
      let data = null;
      if (m.kind === 'file') {
        const r = await this._get(`file:${convId}:${m.id}`, null);
        data = r ? b64uDecode(r.data) : new Uint8Array(0);
      }
      out.push(this._publicMessage(m, data));
    }
    return out;
  }

  /** Validate the user exists (TOFU its identity) and open a direct conversation. */
  async startDirect(username) {
    const u = normalizeUsername(username);
    if (!USERNAME_RE.test(u)) throw new Error(`user_not_found: ${u}`);
    if (u === this._username) throw new Error('cannot_message_self');
    return this._serial(async () => {
      const id = directId(u);
      const convs = await this._getConvs();
      if (convs[id]) return id;
      const server = await this.api.getIdentity(u);
      if (!server) throw new Error(`user_not_found: ${u}`);
      if (!(await verifyPublicIdentity(server))) throw new Error('bad bundle signature');
      const contacts = await this._getContacts();
      const c = own(contacts, u);
      if (!c) {
        contacts[u] = { ik_sig: server.ik_sig, ik_dh: server.ik_dh, verified: false, keyChanged: false, firstSeen: this._now() };
        await this._set('contacts', contacts);
      } else if (!sameIk(c, server)) {
        await this._applyKeyChange(u, server);
      }
      await this._ensureDirectConv(u);
      this._emit('conversations', {});
      return id;
    });
  }

  /** Local-only removal of a conversation and its history (not in SPEC; used by the UI). */
  async deleteConversation(convId) {
    await this._serial(async () => {
      const msgs = await this._getMsgs(convId);
      for (const m of msgs) if (m.kind === 'file') await this._store.delete(`file:${convId}:${m.id}`);
      await this._store.delete(`msgs:${convId}`);
      const convs = await this._getConvs();
      delete convs[convId];
      await this._set('convs', convs);
    });
    this._emit('conversations', {});
  }

  async sendText(convId, text) {
    this._requireUnlocked();
    if (typeof text !== 'string' || text.trim().length === 0) throw new Error('empty');
    if (text.length > MAX_TEXT_CHARS) throw new Error('too large');
    return this._sendContent(convId, 'text', { text }, { text });
  }

  async sendFile(convId, { name, mime, bytes } = {}) {
    this._requireUnlocked();
    if (!(bytes instanceof Uint8Array)) throw new TypeError('bytes must be a Uint8Array');
    if (bytes.length > MAX_FILE_BYTES) throw new Error('file_too_large');
    const meta = { name: sanitizeFileName(name), mime: sanitizeMime(mime), size: bytes.length };
    const data = b64uEncode(bytes);
    const local = { file: meta, fileB64: data, fileBytes: bytes };
    if (bytes.length <= FILE_CHUNK_BYTES) {
      return this._sendContent(convId, 'file', { ...meta, data }, local);
    }
    const n = Math.ceil(bytes.length / FILE_CHUNK_BYTES);
    const parts = [];
    for (let i = 0; i < n; i++) {
      parts.push((fid) => ({
        ...meta,
        data: b64uEncode(bytes.subarray(i * FILE_CHUNK_BYTES, Math.min(bytes.length, (i + 1) * FILE_CHUNK_BYTES))),
        part: { fid, i, n },
      }));
    }
    return this._sendContent(convId, 'file', null, local, parts);
  }

  /**
   * Mark incoming messages read and queue E2E read receipts to their senders (sent
   * after a random delay, CL-1 — see _queueReceipt).
   */
  async markRead(convId) {
    await this._serial(async () => {
      const msgs = await this._getMsgs(convId);
      const bySender = new Map();
      for (const m of msgs) {
        if (m.mine || m.kind === 'system' || m.readSent) continue;
        m.readSent = true;
        m.status = 'read';
        if (!bySender.has(m.from)) bySender.set(m.from, []);
        bySender.get(m.from).push(m.rid || m.id); // the sender's id (CL-2)
      }
      const convs = await this._getConvs();
      const conv = own(convs, convId);
      if (conv && conv.unread) { conv.unread = 0; await this._set('convs', convs); }
      if (!bySender.size) return;
      await this._set(`msgs:${convId}`, msgs);
      const gid = conv && conv.type === 'group' ? conv.group : null;
      for (const [from, ids] of bySender) for (const id of ids) this._armReceipt(from, gid, id, 'read');
      await this._saveReceiptQ(); // C2
    });
  }

  async deleteMessages(convId, ids, forEveryone = false) {
    if (!Array.isArray(ids)) throw new TypeError('ids must be an array');
    const want = new Set(ids);
    const prep = await this._serial(async () => {
      const removed = await this._removeMessages(convId, (m) => want.has(m.id));
      const mineIds = removed.filter((m) => m.mine && m.kind !== 'system').map((m) => m.id);
      if (!forEveryone || !mineIds.length) return null;
      const convs = await this._getConvs();
      const conv = convs[convId];
      if (!conv) return null;
      let recipients;
      try { recipients = await this._recipientsFor(conv); } catch { return null; }
      const payload = { id: newId(), ts: this._now(), kind: 'delete', body: { ids: mineIds.slice(0, MAX_IDS_PER_CONTROL) } };
      if (conv.type === 'group') payload.group = conv.group;
      return this._encryptPayload(recipients, payload);
    });
    this._emit('update', { convId });
    if (prep) await this._sendControlNow(prep);
  }

  async setTimer(convId, seconds) {
    if (!Number.isInteger(seconds) || seconds < 0 || seconds > MAX_TIMER_SECONDS) throw new Error('bad_request');
    const prep = await this._serial(async () => {
      const convs = await this._getConvs();
      const conv = convs[convId];
      if (!conv) throw new Error('not_found');
      const recipients = await this._recipientsFor(conv);
      conv.timer = seconds;
      await this._set('convs', convs);
      await this._addSystemMessage(convId, seconds
        ? `Activaste los mensajes temporales (${durationLabel(seconds)}).`
        : 'Desactivaste los mensajes temporales.');
      const payload = { id: newId(), ts: this._now(), kind: 'timer', body: { seconds } };
      if (conv.type === 'group') payload.group = conv.group;
      return this._encryptPayload(recipients, payload);
    });
    this._emit('update', { convId });
    this._emit('conversations', {});
    await this._sendControlNow(prep);
  }

  // ------------------------------------------------------------------ groups

  async _validateMembers(usernames) {
    if (!Array.isArray(usernames)) throw new TypeError('usernames must be an array');
    const list = [...new Set(usernames.map(normalizeUsername))].filter((u) => u !== this._username);
    for (const u of list) {
      if (!USERNAME_RE.test(u)) throw new Error(`user_not_found: ${u}`);
      const id = await this.api.getIdentity(u);
      if (!id) throw new Error(`user_not_found: ${u}`);
    }
    return list;
  }

  async createGroup(name, usernames) {
    this._requireUnlocked();
    const title = cleanGroupName(name); // BUG-2
    if (!title) throw new Error('bad_request');
    const others = await this._validateMembers(usernames);
    if (others.length + 1 > MAX_GROUP_MEMBERS) throw new Error('too_many');
    // CL-4: gid = H(creator, salt) — receivers verify the binding on creation.
    const saltBytes = randomBytes(16);
    const salt = b64uEncode(saltBytes);
    const gid = await groupIdFor(this._username, saltBytes);
    const convId = groupConvId(gid);
    const prep = await this._serial(async () => {
      const group = { id: gid, name: title, members: [this._username, ...others], admin: this._username, creator: this._username, salt, left: false };
      const groups = await this._getGroups();
      groups[gid] = group;
      await this._set('groups', groups);
      const convs = await this._getConvs();
      convs[convId] = { id: convId, type: 'group', group: gid, title, timer: 0, unread: 0, lastText: '', lastTs: 0, created: this._now() };
      await this._set('convs', convs);
      await this._addSystemMessage(convId, `Creaste el grupo «${title}».`);
      // SPEC §5.2 extension (CL-4): group_update.group carries {creator, salt}.
      const payload = { id: newId(), ts: this._now(), kind: 'group_update', group: gid, body: { group: { id: gid, name: title, members: group.members, admin: group.admin, creator: group.creator, salt } } };
      return this._encryptPayload(others, payload);
    });
    this._emit('conversations', {});
    await this._sendControlNow(prep);
    return convId;
  }

  async addGroupMembers(convId, usernames) {
    this._requireUnlocked();
    const add = await this._validateMembers(usernames);
    const prep = await this._serial(async () => {
      const convs = await this._getConvs();
      const conv = own(convs, convId);
      if (!conv || conv.type !== 'group') throw new Error('not_found');
      const groups = await this._getGroups();
      const g = own(groups, conv.group);
      if (!g || g.left) throw new Error('not_member');
      if (g.admin !== this._username) throw new Error('not_admin');
      // CL-4: newcomers only accept a creation from the creator the gid is bound to,
      // so only the creator (while admin) can add members.
      if (g.creator !== this._username || typeof g.salt !== 'string') throw new Error('not_admin');
      const fresh = add.filter((u) => !g.members.includes(u));
      if (!fresh.length) return null;
      if (g.members.length + fresh.length > MAX_GROUP_MEMBERS) throw new Error('too_many');
      g.members = [...g.members, ...fresh];
      await this._set('groups', groups);
      await this._addSystemMessage(convId, `Añadiste a ${fresh.map((u) => '@' + u).join(', ')}.`);
      const payload = { id: newId(), ts: this._now(), kind: 'group_update', group: g.id, body: { group: { id: g.id, name: g.name, members: g.members, admin: g.admin, creator: g.creator, salt: g.salt } } };
      return this._encryptPayload(g.members.filter((u) => u !== this._username), payload);
    });
    this._emit('conversations', {});
    this._emit('update', { convId });
    if (prep) await this._sendControlNow(prep);
  }

  /** Notify the other members, then forget the group and its history locally. */
  async leaveGroup(convId) {
    const prep = await this._serial(async () => {
      const convs = await this._getConvs();
      const conv = convs[convId];
      if (!conv || conv.type !== 'group') throw new Error('not_found');
      const groups = await this._getGroups();
      const g = groups[conv.group];
      let enc = null;
      if (g && !g.left) {
        const payload = { id: newId(), ts: this._now(), kind: 'group_leave', group: g.id, body: {} };
        enc = await this._encryptPayload(g.members.filter((u) => u !== this._username), payload);
      }
      delete groups[conv.group];
      await this._set('groups', groups);
      const msgs = await this._getMsgs(convId);
      for (const m of msgs) if (m.kind === 'file') await this._store.delete(`file:${convId}:${m.id}`);
      await this._store.delete(`msgs:${convId}`);
      await this._store.delete(`seen:${convId}`);
      delete convs[convId];
      await this._set('convs', convs);
      return enc;
    });
    this._emit('conversations', {});
    if (prep) await this._sendControlNow(prep);
  }

  // ------------------------------------------------------------------ safety numbers / key changes

  async _contactFor(username) {
    const contacts = await this._getContacts();
    let c = own(contacts, username);
    if (!c) {
      const server = await this.api.getIdentity(username);
      if (!server || !(await verifyPublicIdentity(server))) throw new Error(`user_not_found: ${username}`);
      c = { ik_sig: server.ik_sig, ik_dh: server.ik_dh, verified: false, keyChanged: false, firstSeen: this._now() };
      contacts[username] = c;
      await this._set('contacts', contacts);
    }
    return c;
  }

  async getSafetyNumber(username) {
    const u = normalizeUsername(username);
    if (!USERNAME_RE.test(u)) throw new Error(`user_not_found: ${u}`);
    return this._serial(async () => {
      const c = await this._contactFor(u);
      const number = await safetyNumber(
        this._username, { ik_sig: this._pubId.ik_sig, ik_dh: this._pubId.ik_dh },
        u, { ik_sig: c.ik_sig, ik_dh: c.ik_dh },
      );
      return { number, formatted: formatSafetyNumber(number), verified: !!c.verified, keyChanged: !!c.keyChanged };
    });
  }

  /**
   * VC-3: throw 'key_changed' when the identity pinned NOW does not produce the safety
   * number the user compared (a key change landed while the dialog was open).
   */
  async _assertSafetyNumber(u, c, expected) {
    if (expected === undefined || expected === null) return;
    const number = await safetyNumber(
      this._username, { ik_sig: this._pubId.ik_sig, ik_dh: this._pubId.ik_dh },
      u, { ik_sig: c.ik_sig, ik_dh: c.ik_dh },
    );
    if (String(expected).split(' ').join('') !== number) throw new Error('key_changed');
  }

  /**
   * Marking verified also acknowledges a key change (the user compared the numbers).
   * VC-3: pass the safety number that was displayed as `expectedNumber`; the UI always
   * does. It is bound to what gets marked verified.
   */
  async setVerified(username, verified, expectedNumber) {
    const u = normalizeUsername(username);
    if (!USERNAME_RE.test(u)) throw new Error(`user_not_found: ${u}`); // CL-6
    await this._serial(async () => {
      await this._contactFor(u);
      const contacts = await this._getContacts();
      const c = own(contacts, u);
      if (!c) throw new Error(`user_not_found: ${u}`);
      if (verified) await this._assertSafetyNumber(u, c, expectedNumber);
      c.verified = !!verified;
      if (verified) {
        c.keyChanged = false;
        if (c.hold) {
          await this._releaseHeld(u); // CL-5: the user compared the new safety number
          c.hold = false;
          delete c.heldPrevIk;
        }
      }
      await this._set('contacts', contacts);
    });
    this._emit('conversations', {});
    this._emit('update', { convId: directId(u) });
  }

  /**
   * Accept the changed identity of `username`. CL-12: what gets pinned is exactly the
   * identity stored in the contact — the one whose safety number the user was shown
   * (already confirmed by the server when the change was recorded) — never whatever
   * the server returns at click time. If the server now serves yet another identity,
   * that is a NEW key change: it is recorded (new safety number) and nothing is
   * accepted (Error('key_changed')).
   */
  async acceptKeyChange(username, expectedNumber) {
    const u = normalizeUsername(username);
    if (!USERNAME_RE.test(u)) throw new Error(`user_not_found: ${u}`);
    await this._serial(async () => {
      const contacts = await this._getContacts();
      const c = own(contacts, u);
      if (!c) throw new Error(`user_not_found: ${u}`);
      await this._assertSafetyNumber(u, c, expectedNumber); // VC-3
      let server = null;
      try { server = await this.api.getIdentity(u); } catch { server = null; } // offline: accept what was shown
      if (server && isPlainObject(server) && !sameIk(server, c) && (await verifyPublicIdentity(server))) {
        await this._applyKeyChange(u, server);
        throw new Error('key_changed');
      }
      if (c.hold) {
        await this._releaseHeld(u); // CL-5: held messages appear only now
        c.hold = false;
        delete c.heldPrevIk;
      }
      c.verified = false;
      c.keyChanged = false;
      await this._set('contacts', contacts);
      // Drop sessions that are not bound to the accepted identity.
      const rec = await this._getSessions(u);
      const keep = [rec.current, ...rec.previous].filter((x) => x && sameIk(x, c));
      const curOk = rec.current && sameIk(rec.current, c);
      await this._set(`session:${u}`, {
        current: curOk ? rec.current : (keep[0] || null),
        previous: (curOk ? keep.slice(1) : keep.slice(1)).slice(0, MAX_PREVIOUS_SESSIONS),
        eks: rec.eks,
      });
    }).finally(() => {
      this._emit('conversations', {});
      this._emit('update', { convId: directId(u) });
    });
  }

  // ------------------------------------------------------------------ backup / wipe / delete

  /** All backend records (already encrypted) + the vault meta, as UTF-8 JSON bytes. */
  async exportBackup() {
    return this._serial(async () => {
      const keys = await this.backend.keys();
      const records = {};
      for (const k of keys) {
        const v = await this.backend.get(k);
        if (typeof v === 'string') records[k] = v;
      }
      return utf8Encode(JSON.stringify({ format: 'sombra-backup', v: 1, records }));
    });
  }

  /** Replace the backend contents with a backup produced by exportBackup(). */
  static async importBackup(backend, bytes) {
    let obj;
    try {
      const text = typeof bytes === 'string' ? bytes : utf8Decode(bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes));
      obj = JSON.parse(text);
    } catch {
      throw new Error('bad backup');
    }
    if (!isPlainObject(obj) || obj.format !== 'sombra-backup' || obj.v !== 1 || !isPlainObject(obj.records)) {
      throw new Error('bad backup');
    }
    const entries = Object.entries(obj.records);
    if (!entries.every(([k, v]) => typeof k === 'string' && k.length > 0 && typeof v === 'string')) {
      throw new Error('bad backup');
    }
    const metaStr = obj.records[META_KEY];
    let meta;
    try { meta = JSON.parse(metaStr); } catch { throw new Error('bad backup'); }
    if (!isPlainObject(meta) || meta.v !== 1 || typeof meta.salt !== 'string' || typeof meta.verifier !== 'string' ||
        !Number.isInteger(meta.iter)) {
      throw new Error('bad backup');
    }
    await backend.clear();
    // Meta last: an interrupted import never looks like a complete account.
    for (const [k, v] of entries) if (k !== META_KEY) await backend.set(k, v);
    // CL-3 / CRYPTO-4: flag the restore in the (clear, non-secret) vault meta; the
    // first unlock retires every restored ratchet session for sending (see
    // _afterRestore). A backup must never be restored on two live devices.
    await backend.set(META_KEY, JSON.stringify({ ...meta, restored: 1 }));
  }

  /** Delete the account on the server (via the authenticated socket), then wipe locally. */
  async deleteAccount() {
    this._requireUnlocked();
    if (!this._conn || !this.connected) throw new Error('network');
    const waiter = {};
    const done = new Promise((resolve, reject) => { waiter.resolve = resolve; waiter.reject = reject; });
    this._deleteWaiter = waiter;
    if (!this._conn.send({ t: 'delete_account' })) {
      this._deleteWaiter = null;
      throw new Error('network');
    }
    let timer;
    try {
      await Promise.race([
        done,
        new Promise((_, reject) => { timer = setTimeout(() => reject(new Error('network')), DELETE_ACCOUNT_TIMEOUT_MS); }),
      ]);
    } finally {
      clearTimeout(timer);
      this._deleteWaiter = null;
    }
    await this.panicWipe();
  }

  /** Local wipe only, immediate; works while locked too. */
  async panicWipe() {
    this.lock();
    await this.backend.clear();
  }
}
