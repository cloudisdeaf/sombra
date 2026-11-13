// Sombra — Double Ratchet (SPEC §2.5). Signal Double Ratchet, no header encryption.
//
// Functional API: every function takes a state and returns a NEW state; the
// input object is never mutated. Callers persist the returned state only on
// success, so a failed (forged, replayed, corrupted) message can never advance
// or damage the stored session.
//
// State is a plain JSON-serialisable object:
// {
//   v: 1,
//   rk:  b64u(32)                      root key
//   dhs: { pub: b64u, priv: b64u }     our current ratchet keypair
//   dhr: b64u | null                   peer's current ratchet public key
//   cks: b64u | null                   sending chain key
//   ckr: b64u | null                   receiving chain key
//   ns, nr, pn: uint32                 send / receive counters, previous send chain length
//   skipped: [{ dh: b64u, n: uint32, mk: b64u, t: ms }]   skipped message keys, oldest first
// }
//
// Audit fixes (local state only, no wire-format change):
// - CRYPTO-2: a new peer ratchet key whose header claims a previous chain longer
//   than MAX_SKIP no longer deadlocks the session: at most MAX_SKIP keys of the
//   abandoned chain are stored and the DH ratchet proceeds. Senders must also
//   bound their chains: when ratchetNeedsRekey(state) is true the caller starts
//   a fresh X3DH session instead of encrypting on this one.
// - CRYPTO-8: skipped keys carry their creation time `t` and are purged after
//   SKIPPED_KEY_MAX_AGE_MS (server message TTL) on every encrypt/decrypt and via
//   ratchetPurgeSkipped(), so withheld ciphertexts do not keep keys alive forever.

import { b64uEncode, b64uDecode, concatBytes, u32be, zeroize } from './encoding.js';
import { hkdf, aesGcmEncrypt, aesGcmDecrypt, generateX25519, x25519 } from './primitives.js';
import { hmacSha256Sync } from './pow.js';

export const MAX_SKIP = 1000;       // max message keys skipped in one chain step
export const MAX_SKIPPED_TOTAL = 2000; // max stored skipped keys (oldest evicted)
/** A sending chain with this many messages and no DH ratchet since must be replaced
 *  by a fresh X3DH session (keeps any loss gap on one chain below MAX_SKIP). */
export const REKEY_AFTER = 500;
/** Skipped keys older than this are deleted (= default server MESSAGE_TTL_DAYS). */
export const SKIPPED_KEY_MAX_AGE_MS = 14 * 24 * 3600 * 1000;

const RK_INFO = 'SOMBRA-RK-v1';
const MK_INFO = 'SOMBRA-MK-v1';
const ZERO32 = new Uint8Array(32);
const CK_MSG = new Uint8Array([0x01]);
const CK_NEXT = new Uint8Array([0x02]);
const UINT32_MAX = 0xffffffff;

function isUint32(n) {
  return Number.isInteger(n) && n >= 0 && n <= UINT32_MAX;
}

function decode32(str, what) {
  const b = b64uDecode(str);
  if (b.length !== 32) throw new Error(`${what}: expected 32 bytes`);
  return b;
}

// ---------------------------------------------------------------------------
// KDFs
// ---------------------------------------------------------------------------

/** KDF_RK(rk, dhOut) = HKDF(ikm=dhOut, salt=rk, info, 64) -> [rk', ck] */
async function kdfRk(rk, dhOut) {
  const okm = await hkdf(dhOut, rk, RK_INFO, 64);
  const out = [okm.slice(0, 32), okm.slice(32, 64)];
  zeroize(okm);
  return out;
}

/** KDF_CK(ck) -> [mk = HMAC(ck, 0x01), ck' = HMAC(ck, 0x02)] */
// VC-4: synchronous HMAC (pure JS) — identical output to WebCrypto HMAC-SHA256, but
// without two async importKey+sign round trips per chain step.
async function kdfCk(ck) {
  return [hmacSha256Sync(ck, CK_MSG), hmacSha256Sync(ck, CK_NEXT)];
}

/** Expand a message key into AES-256 key + 96-bit IV. */
async function expandMk(mk) {
  const okm = await hkdf(mk, ZERO32, MK_INFO, 44);
  const out = { key: okm.slice(0, 32), iv: okm.slice(32, 44) };
  zeroize(okm);
  return out;
}

function headerBytes(dhBytes, pn, n) {
  return concatBytes(dhBytes, u32be(pn), u32be(n));
}

async function encryptWithMk(mk, plaintext, aad) {
  const { key, iv } = await expandMk(mk);
  try {
    return await aesGcmEncrypt(key, iv, plaintext, aad);
  } finally {
    zeroize(key);
  }
}

async function decryptWithMk(mk, ciphertext, aad) {
  const { key, iv } = await expandMk(mk);
  try {
    return await aesGcmDecrypt(key, iv, ciphertext, aad);
  } finally {
    zeroize(key);
  }
}

// ---------------------------------------------------------------------------
// State helpers
// ---------------------------------------------------------------------------

/** Deep copy through JSON: guarantees the input is never mutated and the result is plain JSON. */
function cloneState(state) {
  if (!state || typeof state !== 'object' || state.v !== 1) throw new Error('invalid ratchet state');
  const s = JSON.parse(JSON.stringify(state));
  if (typeof s.rk !== 'string' || !s.dhs || typeof s.dhs.pub !== 'string' || typeof s.dhs.priv !== 'string' ||
      !isUint32(s.ns) || !isUint32(s.nr) || !isUint32(s.pn) || !Array.isArray(s.skipped)) {
    throw new Error('invalid ratchet state');
  }
  return s;
}

/** Resolve the clock from the optional opts argument. */
function resolveNow(opts) {
  if (opts === undefined || opts === null) return Date.now();
  if (typeof opts !== 'object') throw new TypeError('opts must be an object');
  if (opts.now === undefined) return Date.now();
  if (typeof opts.now !== 'number' || !Number.isFinite(opts.now)) throw new TypeError('opts.now must be a finite number');
  return opts.now;
}

/** Drop skipped keys older than maxAgeMs (in place, on a cloned state). */
function purgeSkipped(st, now, maxAgeMs = SKIPPED_KEY_MAX_AGE_MS) {
  const kept = [];
  for (const k of st.skipped) {
    if (!k || typeof k !== 'object') continue;
    let t = typeof k.t === 'number' && Number.isFinite(k.t) ? k.t : now; // legacy entry: clock starts now
    if (t > now) t = now; // future timestamp (clock skew): never extends a key's life
    if (now - t > maxAgeMs) continue;
    k.t = t;
    kept.push(k);
  }
  st.skipped = kept;
}

function validateHeader(header) {
  if (!header || typeof header !== 'object') throw new Error('invalid header');
  const { dh, pn, n } = header;
  if (typeof dh !== 'string' || !isUint32(pn) || !isUint32(n)) throw new Error('invalid header');
  const dhBytes = decode32(dh, 'header dh'); // strict decoding => canonical string
  return { dh, dhBytes, pn, n };
}

/**
 * Store skipped message keys of the current receiving chain up to (excluding) `until`.
 * With `clamp` (chain being abandoned for a new ratchet key) a gap larger than
 * MAX_SKIP stores only the first MAX_SKIP keys instead of throwing; returns true
 * when it clamped. Work is bounded by MAX_SKIP either way.
 */
async function skipMessageKeys(st, until, now, clamp = false) {
  if (st.ckr === null) return false;
  if (until <= st.nr) return false;
  let clamped = false;
  if (until - st.nr > MAX_SKIP) {
    if (!clamp) throw new Error('too many skipped messages');
    until = st.nr + MAX_SKIP;
    clamped = true;
  }
  let ck = decode32(st.ckr, 'ckr');
  while (st.nr < until) {
    const [mk, next] = await kdfCk(ck);
    zeroize(ck);
    ck = next;
    st.skipped.push({ dh: st.dhr, n: st.nr, mk: b64uEncode(mk), t: now });
    zeroize(mk);
    st.nr += 1;
  }
  st.ckr = b64uEncode(ck);
  zeroize(ck);
  // Global cap: evict the oldest keys (they are the least likely to still arrive).
  if (st.skipped.length > MAX_SKIPPED_TOTAL) st.skipped.splice(0, st.skipped.length - MAX_SKIPPED_TOTAL);
  return clamped;
}

/** DH ratchet step on receipt of a new peer ratchet key. */
async function dhRatchet(st, dhBytes) {
  st.pn = st.ns;
  st.ns = 0;
  st.nr = 0;
  st.dhr = b64uEncode(dhBytes);

  const ownPriv = decode32(st.dhs.priv, 'dhs priv');
  let rk = decode32(st.rk, 'rk');
  const dh1 = await x25519(ownPriv, dhBytes);
  zeroize(ownPriv);
  const [rk1, ckr] = await kdfRk(rk, dh1);
  zeroize(rk); zeroize(dh1);

  const fresh = await generateX25519();
  const dh2 = await x25519(fresh.priv, dhBytes);
  const [rk2, cks] = await kdfRk(rk1, dh2);
  zeroize(rk1); zeroize(dh2);

  st.dhs = { pub: b64uEncode(fresh.pub), priv: b64uEncode(fresh.priv) };
  zeroize(fresh.priv);
  st.rk = b64uEncode(rk2);
  st.ckr = b64uEncode(ckr);
  st.cks = b64uEncode(cks);
  zeroize(rk2); zeroize(ckr); zeroize(cks);
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Initiator (Alice): sk from X3DH, remoteRatchetPub = Bob's SPK public key.
 * @returns state
 */
export async function ratchetInitSender(sk, remoteRatchetPub) {
  if (!(sk instanceof Uint8Array) || sk.length !== 32) throw new TypeError('sk must be 32 bytes');
  if (!(remoteRatchetPub instanceof Uint8Array) || remoteRatchetPub.length !== 32) {
    throw new TypeError('remote ratchet key must be 32 bytes');
  }
  const dhs = await generateX25519();
  const dhOut = await x25519(dhs.priv, remoteRatchetPub);
  const [rk, cks] = await kdfRk(sk, dhOut);
  zeroize(dhOut);
  const state = {
    v: 1,
    rk: b64uEncode(rk),
    dhs: { pub: b64uEncode(dhs.pub), priv: b64uEncode(dhs.priv) },
    dhr: b64uEncode(remoteRatchetPub),
    cks: b64uEncode(cks),
    ckr: null,
    ns: 0, nr: 0, pn: 0,
    skipped: [],
  };
  zeroize(rk); zeroize(cks); zeroize(dhs.priv);
  return state;
}

/**
 * Responder (Bob): sk from X3DH, ownRatchetKeyPair = Bob's SPK keypair.
 * Bob cannot send until he has received the first message.
 * @returns state
 */
export async function ratchetInitReceiver(sk, ownRatchetKeyPair) {
  if (!(sk instanceof Uint8Array) || sk.length !== 32) throw new TypeError('sk must be 32 bytes');
  const kp = ownRatchetKeyPair;
  if (!kp || !(kp.pub instanceof Uint8Array) || kp.pub.length !== 32 ||
      !(kp.priv instanceof Uint8Array) || kp.priv.length !== 32) {
    throw new TypeError('ratchet keypair must be {pub, priv} of 32 bytes');
  }
  return {
    v: 1,
    rk: b64uEncode(sk),
    dhs: { pub: b64uEncode(kp.pub), priv: b64uEncode(kp.priv) },
    dhr: null,
    cks: null,
    ckr: null,
    ns: 0, nr: 0, pn: 0,
    skipped: [],
  };
}

/**
 * Encrypt one message. `opts.now` (ms, default Date.now()) drives skipped-key expiry.
 * Callers should check ratchetNeedsRekey(state) first (CRYPTO-2).
 * @returns {{ state, header: {dh, pn, n}, ciphertext: Uint8Array }}
 */
export async function ratchetEncrypt(state, plaintext, ad, opts) {
  if (!(plaintext instanceof Uint8Array)) throw new TypeError('plaintext must be a Uint8Array');
  if (!(ad instanceof Uint8Array)) throw new TypeError('ad must be a Uint8Array');
  const now = resolveNow(opts);
  const st = cloneState(state);
  purgeSkipped(st, now); // CRYPTO-8
  if (st.cks === null) throw new Error('cannot send before receiving the first message');
  if (st.ns >= UINT32_MAX) throw new Error('sending chain exhausted');

  const ck = decode32(st.cks, 'cks');
  const [mk, next] = await kdfCk(ck);
  zeroize(ck);
  const header = { dh: st.dhs.pub, pn: st.pn, n: st.ns };
  const aad = concatBytes(ad, headerBytes(decode32(header.dh, 'dhs pub'), header.pn, header.n));
  let ciphertext;
  try {
    ciphertext = await encryptWithMk(mk, plaintext, aad);
  } finally {
    zeroize(mk);
  }
  st.cks = b64uEncode(next);
  zeroize(next);
  st.ns += 1;
  return { state: st, header, ciphertext };
}

/**
 * Decrypt one message. Throws on any failure; the input state is never modified.
 * Each message key is usable exactly once, so replays are rejected.
 * `opts.now` (ms, default Date.now()) drives skipped-key expiry.
 * @returns {{ state, plaintext: Uint8Array }}
 */
export async function ratchetDecrypt(state, header, ciphertext, ad, opts) {
  if (!(ciphertext instanceof Uint8Array)) throw new TypeError('ciphertext must be a Uint8Array');
  if (!(ad instanceof Uint8Array)) throw new TypeError('ad must be a Uint8Array');
  const now = resolveNow(opts);
  const st = cloneState(state);
  purgeSkipped(st, now); // expired keys are never usable (CRYPTO-8)
  const { dh, dhBytes, pn, n } = validateHeader(header);
  const aad = concatBytes(ad, headerBytes(dhBytes, pn, n));

  // 1. A previously skipped message (out-of-order delivery)?
  const idx = st.skipped.findIndex((k) => k.dh === dh && k.n === n);
  if (idx >= 0) {
    const mk = b64uDecode(st.skipped[idx].mk);
    try {
      const plaintext = await decryptWithMk(mk, ciphertext, aad);
      st.skipped.splice(idx, 1); // single use
      return { state: st, plaintext };
    } finally {
      zeroize(mk);
    }
  }

  // 2. New ratchet public key from the peer -> finish the current receiving
  //    chain (store its skipped keys) and perform a DH ratchet step.
  let clamped = false;
  if (st.dhr === null || dh !== st.dhr) {
    // A gap > MAX_SKIP on the abandoned chain is clamped instead of rejected:
    // rejecting would deadlock the session forever (CRYPTO-2). pn is in the AAD,
    // so a forged pn only costs bounded work and the result is discarded.
    clamped = await skipMessageKeys(st, pn, now, true);
    await dhRatchet(st, dhBytes);
  }
  if (st.ckr === null) throw new Error('no receiving chain');

  // 3. Message on the current receiving chain. Anything below nr was either
  //    already decrypted or is stored in `skipped` (checked above): a replay.
  if (n < st.nr) throw new Error('duplicate or expired message');
  await skipMessageKeys(st, n, now);

  const ck = decode32(st.ckr, 'ckr');
  const [mk, next] = await kdfCk(ck);
  zeroize(ck);
  try {
    let plaintext;
    try {
      plaintext = await decryptWithMk(mk, ciphertext, aad);
    } catch (err) {
      // Forged header with an over-long pn: same error as before the clamp
      // (callers drop silently either way; state is never persisted).
      if (clamped) throw new Error('too many skipped messages');
      throw err;
    }
    st.ckr = b64uEncode(next);
    st.nr += 1;
    return { state: st, plaintext };
  } finally {
    zeroize(mk);
    zeroize(next);
  }
}

/**
 * CRYPTO-2: true when the current sending chain holds REKEY_AFTER or more messages
 * with no DH ratchet step since (peer silent or messages lost). The caller must
 * then start a fresh X3DH session instead of encrypting on this one, so no chain
 * can accumulate a loss gap the receiver refuses (MAX_SKIP).
 */
export function ratchetNeedsRekey(state) {
  const st = cloneState(state);
  return st.cks !== null && st.ns >= REKEY_AFTER;
}

/**
 * CRYPTO-8: returns a NEW state without skipped keys older than maxAgeMs (input
 * untouched). For a periodic sweep over stored sessions (current and previous),
 * so idle sessions do not keep keys of withheld ciphertexts indefinitely.
 */
export function ratchetPurgeSkipped(state, now = Date.now(), maxAgeMs = SKIPPED_KEY_MAX_AGE_MS) {
  if (typeof now !== 'number' || !Number.isFinite(now)) throw new TypeError('now must be a finite number');
  if (typeof maxAgeMs !== 'number' || !Number.isFinite(maxAgeMs) || maxAgeMs < 0) throw new TypeError('bad maxAgeMs');
  const st = cloneState(state);
  purgeSkipped(st, now, maxAgeMs);
  return st;
}
