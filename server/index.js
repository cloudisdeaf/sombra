// Sombra server: static files, security headers, REST API and WebSocket relay (SPEC §3).
//
// The server is deliberately "dumb": it stores public keys and relays opaque sealed blobs.
// It never learns who sends a message (sealed sender, unauthenticated /api/send) and keeps
// as little metadata as possible:
//   - nothing is logged except the startup line and generic "internal error" messages
//     (no IPs, usernames, paths, user agents or timings — ever);
//   - no cookies, sessions, analytics or third-party requests;
//   - rate limiting (optional) keys an in-memory map by HMAC(random startup secret, ip);
//   - queued blobs are deleted on ACK and carry only a day-granular expiry.

import http from 'node:http';
import https from 'node:https';
import fs from 'node:fs';
import net from 'node:net';
import path from 'node:path';
import { createHmac, randomBytes } from 'node:crypto';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { WebSocketServer } from 'ws';

import { config as envConfig, LIMITS } from './config.js';
import { openDatabase, roundUpToUtcDay } from './db.js';
import { AccessControl } from './access.js';
import { PowManager, sendPowExtraBits } from './pow.js';
import {
  ValidationError, assertObject, assertUsername, assertNewUsername, isPlainObject, isUsername,
  b64uDecodeStrict, b64uEncode, decodeKey, decodeSig, parseSignedPrekey, parseOpkList,
  parsePow, verifyIkDhSig, verifySpkSig, verifyAuthSig, verifyRegSig,
} from './validate.js';

const DEFAULT_PUBLIC_DIR = fileURLToPath(new URL('../public/', import.meta.url));
const DAY_MS = 24 * 60 * 60 * 1000;

// ---------------------------------------------------------------------------------------
// Security headers (SPEC §3.3)
// ---------------------------------------------------------------------------------------

const CSP = [
  "default-src 'none'", "script-src 'self'", "style-src 'self'", "img-src 'self' blob: data:",
  "media-src 'self' blob:", "connect-src 'self'", "font-src 'self'", "worker-src 'self'",
  "manifest-src 'self'", "base-uri 'none'", "form-action 'none'", "frame-ancestors 'none'",
].join('; ');

const BASE_SECURITY_HEADERS = Object.freeze({
  'Content-Security-Policy': CSP,
  'Referrer-Policy': 'no-referrer',
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'DENY',
  'Cross-Origin-Opener-Policy': 'same-origin',
  'Cross-Origin-Resource-Policy': 'same-origin',
  'Cross-Origin-Embedder-Policy': 'require-corp',
  'Permissions-Policy': 'camera=(), microphone=(), geolocation=(), interest-cohort=(), browsing-topics=()',
});
const HSTS = 'max-age=63072000; includeSubDomains';

// Explicit MIME map: anything not listed here is never served.
const MIME = Object.freeze({
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.mjs': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.webmanifest': 'application/manifest+json; charset=utf-8',
  '.txt': 'text/plain; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.jpeg': 'image/jpeg',
  '.gif': 'image/gif',
  '.webp': 'image/webp',
  '.ico': 'image/x-icon',
  '.woff': 'font/woff',
  '.woff2': 'font/woff2',
  '.wasm': 'application/wasm',
});

// Conservative whitelist for each static path segment: no dotfiles, no '..', no '\\',
// no ':' (Windows drive letters / alternate data streams), no spaces or '%'.
const SAFE_SEGMENT_RE = /^[A-Za-z0-9_][A-Za-z0-9._-]{0,127}$/;

// ---------------------------------------------------------------------------------------
// Errors & helpers
// ---------------------------------------------------------------------------------------

class HttpError extends Error {
  constructor(status, code) {
    super(code);
    this.status = status;
    this.code = code;
  }
}

function setSecurityHeaders(res, tls) {
  for (const [k, v] of Object.entries(BASE_SECURITY_HEADERS)) res.setHeader(k, v);
  if (tls) res.setHeader('Strict-Transport-Security', HSTS);
}

function sendJson(res, status, obj, extraHeaders = {}) {
  if (res.headersSent) { res.destroy(); return; }
  const body = Buffer.from(JSON.stringify(obj), 'utf8');
  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Content-Length': body.length,
    'Cache-Control': 'no-store',
    ...extraHeaders,
  });
  res.end(body);
}

function sendText(res, status, text, extraHeaders = {}) {
  if (res.headersSent) { res.destroy(); return; }
  const body = Buffer.from(text, 'utf8');
  res.writeHead(status, {
    'Content-Type': 'text/plain; charset=utf-8',
    'Content-Length': body.length,
    'Cache-Control': 'no-store',
    ...extraHeaders,
  });
  res.end(body);
}

/** Generic error reporting: never includes request data. Stack only with DEBUG=1. */
function makeLogError(debug) {
  return (err) => {
    console.error('internal error');
    if (debug && err && err.stack) console.error(err.stack);
  };
}

// After a 413 we keep reading (and discarding) up to max(limit, 4 MiB) extra bytes so a
// well-behaved client that is still uploading can read the 413 response instead of
// getting a TCP reset. Beyond that the socket is destroyed. Nothing is ever buffered,
// so a client can make us *read* at most ~2x the limit, in constant memory.
const MIN_DISCARD_CAP_BYTES = 4 * 1024 * 1024;

/**
 * Global accounting of request-body bytes buffered in memory (SRV-03). Every buffered
 * chunk is charged; the charge is released once the response is finished/closed (the
 * buffer is garbage after that). A request that would exceed the budget gets 503.
 */
class BodyBudget {
  constructor(max) {
    this.max = max;
    this.used = 0;
  }
}

/** Abort the request (socket) if no body data arrives for `idleMs`. Returns a handle. */
function idleGuard(req, idleMs) {
  const t = setTimeout(() => { req.socket?.destroy(); }, idleMs);
  t.unref?.();
  return { touch: () => t.refresh(), stop: () => clearTimeout(t) };
}

/** Discard the rest of a request body; destroy the socket once `cap` bytes are exceeded. */
function discardBody(req, cap, idleMs) {
  let discarded = 0;
  const idle = idleGuard(req, idleMs);
  req.removeAllListeners('data');
  req.on('data', (chunk) => {
    idle.touch();
    discarded += chunk.length;
    if (discarded > cap) { idle.stop(); req.socket.destroy(); }
  });
  req.on('end', () => idle.stop());
  req.on('close', () => idle.stop());
  req.on('error', () => {});
  req.resume();
}

/**
 * Read a request body while counting bytes as they stream in. Rejects with 413 as soon
 * as the limit is crossed (or immediately if Content-Length already exceeds it), with 503
 * when the global in-memory body budget would be exceeded, and aborts the socket when the
 * body stalls for `idleMs`. Rejected remainders are discarded (see discardBody), never
 * buffered.
 * @param {http.IncomingMessage} req
 * @param {http.ServerResponse} res  budget charge is released when it closes
 * @param {number} limit
 * @param {{budget: BodyBudget, idleMs: number}} ctx
 */
function readBody(req, res, limit, { budget, idleMs }) {
  const cap = Math.max(limit, MIN_DISCARD_CAP_BYTES);
  const cl = req.headers['content-length'];
  if (cl !== undefined) {
    if (!/^\d{1,15}$/.test(cl)) {
      const err = new HttpError(400, 'bad_request');
      err.closeConnection = true; // framing is unreliable: answer and close
      req.resume();
      return Promise.reject(err);
    }
    if (Number(cl) > limit) {
      const err = new HttpError(413, 'payload_too_large');
      if (Number(cl) > limit + cap) {
        err.closeConnection = true; // absurd declared size: answer and close, don't read it
        req.resume();
      } else {
        // The declared length is bounded (≤ limit + cap): drain exactly that much so the
        // keep-alive connection stays usable. Passing `cap` here destroyed the socket of
        // honest clients whose body was between cap and limit + cap AFTER the 413 had been
        // sent, so their next pooled request failed with ECONNRESET.
        discardBody(req, Number(cl), idleMs);
      }
      return Promise.reject(err);
    }
    if (budget.used + Number(cl) > budget.max) {
      // Over the global budget already at the declared size: refuse before reading.
      const err = new HttpError(503, 'busy');
      err.closeConnection = true;
      discardBody(req, cap, idleMs);
      return Promise.reject(err);
    }
  }
  return new Promise((resolve, reject) => {
    let chunks = [];
    let size = 0;
    let charged = 0;
    let settled = false;
    const idle = idleGuard(req, idleMs);
    const release = () => {
      budget.used -= charged;
      charged = 0;
    };
    res.once('close', release);
    const fail = (err) => {
      if (settled) return;
      settled = true;
      idle.stop();
      chunks = null;
      release(); // nothing retained
      reject(err);
    };
    req.on('data', (chunk) => {
      if (settled) return;
      idle.touch();
      size += chunk.length;
      if (size > limit) {
        fail(new HttpError(413, 'payload_too_large'));
        discardBody(req, cap, idleMs);
        return;
      }
      if (budget.used + chunk.length > budget.max) {
        const err = new HttpError(503, 'busy');
        err.closeConnection = true;
        fail(err);
        discardBody(req, cap, idleMs);
        return;
      }
      budget.used += chunk.length;
      charged += chunk.length;
      chunks.push(chunk);
    });
    req.on('end', () => {
      if (settled) return;
      settled = true;
      idle.stop();
      resolve(Buffer.concat(chunks, size));
    });
    req.on('error', () => fail(new HttpError(400, 'bad_request')));
    req.on('close', () => fail(new HttpError(400, 'bad_request')));
  });
}

const JSON_STRUCT_BYTES = [0x7b /* { */, 0x5b /* [ */, 0x2c /* , */, 0x3a /* : */];

/** True if `buf` contains more than `max` structural JSON bytes (early exit). */
function tooManyJsonTokens(buf, max) {
  let n = 0;
  for (const c of JSON_STRUCT_BYTES) {
    let i = buf.indexOf(c);
    while (i !== -1) {
      if (++n > max) return true;
      i = buf.indexOf(c, i + 1);
    }
  }
  return false;
}

async function readJsonObject(req, res, limit, ctx, maxTokens = Infinity) {
  const buf = await readBody(req, res, limit, ctx);
  // Bound the number of JSON values before JSON.parse (pre-PoW memory amplification).
  if (Number.isFinite(maxTokens) && tooManyJsonTokens(buf, maxTokens)) throw new ValidationError();
  let obj;
  try {
    obj = JSON.parse(buf.toString('utf8'));
  } catch {
    throw new ValidationError();
  }
  return assertObject(obj);
}

/**
 * Well-formed sealed envelope (SPEC §2.7): 0x01 || eph(32) || AES-GCM(pad(...)) where the
 * padded plaintext length is a §2.6 bucket (256..16384, powers of two up to 1 MiB, then
 * multiples of 1 MiB) and the GCM tag adds 16 bytes.
 */
export function isSealedEnvelope(blob) {
  const OVERHEAD = 1 + 32 + 16;
  if (blob.length < OVERHEAD + 256 || blob[0] !== 0x01) return false;
  const pt = blob.length - OVERHEAD;
  const MiB = 1024 * 1024;
  if (pt <= MiB) return (pt & (pt - 1)) === 0; // power of two, ≥ 256 checked above
  return pt % MiB === 0;
}

// ---------------------------------------------------------------------------------------
// Rate limiting (SPEC §3.2): in-memory, keyed by HMAC(startup secret, ip), 10 min buckets.
// ---------------------------------------------------------------------------------------

const RATE_WINDOW_MS = 10 * 60 * 1000;
const RESYNC_MIN_INTERVAL_MS = 10 * 1000; // VC-1/VC-2: per-connection 'resync' rate limit
const RATE_LIMITS = Object.freeze({ // requests per 10-minute window per address
  pow: 15000,   // APP-1: one per /api/send; group fan-out is one request per member
  register: 20,
  send: 12000,  // APP-1: ~120 msgs / 10 min to a 100-member group; PoW is the real cost control
  identity: 1200,
  bundle: 300,
  ws: 300,
  static: 5000,
});
const RATE_MAX_BUCKETS = 200000;
// IPv6 /48 aggregates get this multiple of the per-/64 limit (SRV-05): one /48 (65536
// /64s) can no longer multiply its quota by 65536.
const RATE_AGG_FACTOR = 16;

/**
 * Expand an IPv6 address to 8 hextets (numbers). Handles '::', zone ids and an embedded
 * dotted IPv4 tail. Returns null if `ip` is not valid IPv6.
 */
export function expandIPv6(ip) {
  if (typeof ip !== 'string') return null;
  const addr = ip.split('%')[0];
  if (!net.isIPv6(addr)) return null;
  let s = addr;
  const v4 = /(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(s);
  if (v4) {
    const o = v4.slice(1).map(Number);
    s = s.slice(0, v4.index) + ((o[0] << 8) | o[1]).toString(16) + ':' + ((o[2] << 8) | o[3]).toString(16);
  }
  const halves = s.split('::');
  if (halves.length > 2) return null;
  const parse = (h) => (h === '' ? [] : h.split(':').map((x) => parseInt(x, 16)));
  const head = parse(halves[0]);
  const tail = halves.length === 2 ? parse(halves[1]) : [];
  const zeros = halves.length === 2 ? 8 - head.length - tail.length : 0;
  const out = [...head, ...new Array(Math.max(0, zeros)).fill(0), ...tail];
  if (out.length !== 8 || out.some((x) => !(x >= 0 && x <= 0xffff))) return null;
  return out;
}

/**
 * Canonical network keys for an address: `key` (IPv4 address or IPv6 /64) and, for IPv6,
 * `agg` (/48). IPv4-mapped IPv6 is treated as IPv4. Anything unparsable is used verbatim.
 */
export function addressKeys(ip) {
  let a = typeof ip === 'string' ? ip.trim() : '';
  if (net.isIPv4(a)) return { key: a, agg: null };
  const h = expandIPv6(a);
  if (!h) return { key: a, agg: null };
  if (h.slice(0, 5).every((x) => x === 0) && h[5] === 0xffff) {
    return { key: `${h[6] >> 8}.${h[6] & 255}.${h[7] >> 8}.${h[7] & 255}`, agg: null };
  }
  const hex = h.map((x) => x.toString(16));
  return { key: hex.slice(0, 4).join(':') + '::/64', agg: hex.slice(0, 3).join(':') + '::/48' };
}

export class RateLimiter {
  constructor(enabled, trustProxy, { maxBuckets = RATE_MAX_BUCKETS, limits = RATE_LIMITS } = {}) {
    this.enabled = enabled;
    this.trustProxy = trustProxy;
    this.maxBuckets = maxBuckets;
    this.limits = limits;
    this.secret = randomBytes(32);
    /** Insertion order == window start order (buckets are re-inserted on reset).
     * @type {Map<string, {count:number, reset:number}>} */
    this.buckets = new Map();
  }

  /** Raw client address (proxy-aware). Never logged. */
  rawAddress(req) {
    let ip = req.socket?.remoteAddress || '';
    if (this.trustProxy) {
      const xff = req.headers['x-forwarded-for'];
      if (typeof xff === 'string' && xff.length > 0) {
        const parts = xff.split(',');
        ip = parts[parts.length - 1].trim() || ip; // the entry appended by our proxy
      }
    }
    return ip;
  }

  /** Network address used as the bucket key (IPv6 grouped by /64). Never logged. */
  clientAddress(req) {
    return addressKeys(this.rawAddress(req)).key;
  }

  /** Opaque per-address key for concurrency counters (HMAC'd, never logged). */
  addressId(req) {
    return createHmac('sha256', this.secret).update(`addr|${this.clientAddress(req)}`).digest('base64url');
  }

  bucket(key, now) {
    let b = this.buckets.get(key);
    if (b && b.reset > now) return b;
    if (b) this.buckets.delete(key); // re-insert at the end (keeps the map in window order)
    while (this.buckets.size >= this.maxBuckets) {
      // Full: evict the oldest window (O(1)) instead of failing closed for everyone.
      this.buckets.delete(this.buckets.keys().next().value);
    }
    b = { count: 0, reset: now + RATE_WINDOW_MS };
    this.buckets.set(key, b);
    return b;
  }

  allow(req, category) {
    if (!this.enabled) return true;
    const now = Date.now();
    const limit = this.limits[category];
    const { key, agg } = addressKeys(this.rawAddress(req));
    const h = (s) => createHmac('sha256', this.secret).update(s).digest('base64url');
    // Check the aggregate first so a throttled /48 cannot mint new /64 buckets.
    let ab = null;
    if (agg) {
      ab = this.bucket(h(`${category}|agg|${agg}`), now);
      if (ab.count >= limit * RATE_AGG_FACTOR) return false;
    }
    const b = this.bucket(h(`${category}|${key}`), now);
    if (b.count >= limit) return false;
    b.count++;
    if (ab) ab.count++;
    return true;
  }

  prune() {
    const now = Date.now();
    for (const [k, b] of this.buckets) {
      if (b.reset > now) break; // window order: the rest are newer
      this.buckets.delete(k);
    }
  }
}

/** Per-key concurrent-use counter (entries vanish at zero, so size == live keys). */
class ConcurrencyCounter {
  constructor() { this.m = new Map(); }
  count(k) { return this.m.get(k) || 0; }
  tryAcquire(k, max) {
    const n = this.count(k);
    if (n >= max) return false;
    this.m.set(k, n + 1);
    return true;
  }
  release(k) {
    const n = this.count(k) - 1;
    if (n <= 0) this.m.delete(k); else this.m.set(k, n);
  }
}

/**
 * Fetch Metadata guard (SRV-10): a browser request to /api/* or /ws that a third-party
 * page initiated carries Sec-Fetch-Site: cross-site|same-site. Reject those (no state
 * change, no OPK consumption). Non-browser clients send no Sec-Fetch-Site and pass.
 */
function crossSiteRequest(req) {
  const site = req.headers['sec-fetch-site'];
  if (site === undefined) return false;
  return site !== 'same-origin' && site !== 'none';
}

/** Legacy fallback for the WS upgrade when Sec-Fetch-Site is absent: Origin vs Host. */
function foreignOrigin(req) {
  const origin = req.headers.origin;
  if (origin === undefined) return false; // non-browser client
  const host = req.headers.host;
  try {
    return typeof host !== 'string' || new URL(origin).host !== host.toLowerCase();
  } catch {
    return true; // 'null' or garbage Origin
  }
}

// ---------------------------------------------------------------------------------------
// Server
// ---------------------------------------------------------------------------------------

function definedOnly(obj) {
  const out = {};
  for (const [k, v] of Object.entries(obj || {})) if (v !== undefined) out[k] = v;
  return out;
}

/**
 * Start a Sombra server.
 * @param {object} [options] overrides for config: {port, host, dataDir, powRegisterBits,
 *   powSendBits, rateLimit, messageTtlDays, tlsCert, tlsKey, trustProxy, debug,
 *   queueMaxTotalBytes, strictEnvelopes} plus test hooks {publicDir, authTimeoutMs,
 *   pingIntervalMs, bodyBudgetBytes, bodyIdleTimeoutMs, maxUnauthWs, maxUnauthWsPerAddr,
 *   stallTimeoutMs, wsHighWater, bundleOpksPerTarget}.
 * @returns {Promise<{port:number, close:() => Promise<void>}>}
 */
export async function startServer(options = {}) {
  const cfg = { ...envConfig, ...definedOnly(options) };
  const tls = !!(cfg.tlsCert && cfg.tlsKey);
  const publicDir = path.resolve(cfg.publicDir || DEFAULT_PUBLIC_DIR);
  const authTimeoutMs = cfg.authTimeoutMs ?? LIMITS.WS_AUTH_TIMEOUT_MS;
  const pingIntervalMs = cfg.pingIntervalMs ?? 30_000;
  const ttlMs = cfg.messageTtlDays * DAY_MS;
  const logError = makeLogError(cfg.debug);
  // Strict sealed-envelope validation (SRV-04) is opt-in for library callers and turned on
  // by the `node server/index.js` entry point (STRICT_ENVELOPES, default on). Rationale:
  // the legacy server.test.js fixtures send non-envelope junk blobs ('AAAA'); once they
  // are migrated, flip this default to envConfig.strictEnvelopes.
  const strictEnvelopes = options.strictEnvelopes === true;
  const queueMaxTotalBytes = cfg.queueMaxTotalBytes ?? Infinity;
  const queueReservedBytes = cfg.queueReservedBytes ?? LIMITS.QUEUE_RESERVED_BYTES;
  const bodyCtx = {
    budget: new BodyBudget(cfg.bodyBudgetBytes ?? LIMITS.BODY_BUDGET_BYTES),
    idleMs: cfg.bodyIdleTimeoutMs ?? LIMITS.BODY_IDLE_TIMEOUT_MS,
  };
  const maxUnauthWs = cfg.maxUnauthWs ?? LIMITS.MAX_UNAUTH_WS;
  const maxUnauthWsPerAddr = cfg.maxUnauthWsPerAddr ?? LIMITS.MAX_UNAUTH_WS_PER_ADDR;
  const stallTimeoutMs = cfg.stallTimeoutMs ?? LIMITS.WS_STALL_TIMEOUT_MS;
  const bundleOpksPerTarget = cfg.bundleOpksPerTarget ?? LIMITS.BUNDLE_OPKS_PER_TARGET;

  const db = openDatabase(path.resolve(cfg.dataDir));
  // R-1: who may register (open by default; the desktop launcher uses invite/closed).
  const access = new AccessControl({ dir: path.resolve(cfg.dataDir), mode: cfg.registration, localKey: cfg.localKey });
  const pow = new PowManager({
    registerBits: cfg.powRegisterBits,
    sendBits: cfg.powSendBits,
    ttlMs: LIMITS.POW_TTL_MS,
  });
  const limiter = new RateLimiter(cfg.rateLimit, cfg.trustProxy);
  // Per-address concurrency (only meaningful when addresses are distinguishable).
  const perAddrLimits = cfg.rateLimit;
  const inflightBodies = new ConcurrencyCounter();
  const unauthPerAddr = new ConcurrencyCounter();
  const connsPerAddr = new ConcurrencyCounter();

  db.purgeExpired(Date.now());

  /** username -> authenticated connection */
  const online = new Map();
  /** every live WebSocket connection (authenticated or not) */
  const conns = new Set();
  /** unauthenticated connections, oldest first (insertion order) */
  const unauth = new Set();

  // ----- static files ------------------------------------------------------------------

  let realPublicDir = null;
  async function getRealPublicDir() {
    if (realPublicDir) return realPublicDir;
    try {
      realPublicDir = await fs.promises.realpath(publicDir);
    } catch {
      return null; // public/ not present (yet)
    }
    return realPublicDir;
  }

  async function serveStatic(req, res, rawPath) {
    if (req.method !== 'GET' && req.method !== 'HEAD') {
      sendText(res, 405, 'Method not allowed', { Allow: 'GET, HEAD' });
      return;
    }
    if (!limiter.allow(req, 'static')) { sendText(res, 429, 'Too many requests'); return; }

    let decoded;
    try {
      decoded = decodeURIComponent(rawPath);
    } catch {
      sendText(res, 400, 'Bad request');
      return;
    }
    const rel = decoded === '/' ? '/index.html' : decoded;
    const segments = rel.split('/').slice(1);
    // Rejects '', '.', '..', dotfiles, backslashes, NUL, ':' etc. Trailing '/' → '' → 404
    // (no directory listings).
    if (segments.length === 0 || segments.length > 16 ||
        !segments.every((s) => SAFE_SEGMENT_RE.test(s))) {
      sendText(res, 404, 'Not found');
      return;
    }
    const mime = MIME[path.extname(segments[segments.length - 1]).toLowerCase()];
    if (!mime) { sendText(res, 404, 'Not found'); return; }

    const root = await getRealPublicDir();
    if (!root) { sendText(res, 404, 'Not found'); return; }
    const candidate = path.resolve(root, ...segments);
    if (!candidate.startsWith(root + path.sep)) { sendText(res, 404, 'Not found'); return; }

    let real, st;
    try {
      real = await fs.promises.realpath(candidate); // resolve symlinks, then re-check
      if (!real.startsWith(root + path.sep)) { sendText(res, 404, 'Not found'); return; }
      st = await fs.promises.stat(real);
    } catch {
      sendText(res, 404, 'Not found');
      return;
    }
    if (!st.isFile()) { sendText(res, 404, 'Not found'); return; }

    res.writeHead(200, {
      'Content-Type': mime,
      'Content-Length': st.size,
      // Always revalidate so security fixes to the client reach users immediately.
      'Cache-Control': 'no-cache',
    });
    if (req.method === 'HEAD') { res.end(); return; }
    const stream = fs.createReadStream(real);
    stream.on('error', () => res.destroy());
    stream.pipe(res);
  }

  // ----- REST API ----------------------------------------------------------------------

  function rateCheck(req, category) {
    if (!limiter.allow(req, category)) throw new HttpError(429, 'rate_limited');
  }

  /** Per-address cap on concurrently uploading request bodies (SRV-03). */
  function acquireBodySlot(req, res) {
    if (!perAddrLimits) return;
    const id = limiter.addressId(req);
    if (!inflightBodies.tryAcquire(id, LIMITS.MAX_INFLIGHT_BODIES_PER_ADDR)) {
      const err = new HttpError(429, 'rate_limited');
      err.closeConnection = true;
      throw err;
    }
    res.once('close', () => inflightBodies.release(id));
  }

  // Per-target OPK consumption budget (SRV-06): keyed by HMAC(secret, username), in
  // memory only, window-ordered with O(1) eviction of the oldest entry when full.
  const bundleSecret = randomBytes(32);
  /** @type {Map<string, {count:number, reset:number}>} */
  const bundleBudget = new Map();
  function consumeOpkAllowed(username) {
    const now = Date.now();
    const k = createHmac('sha256', bundleSecret).update(username).digest('base64url');
    let b = bundleBudget.get(k);
    if (!b || b.reset <= now) {
      if (b) bundleBudget.delete(k);
      while (bundleBudget.size >= LIMITS.BUNDLE_TARGET_MAX_ENTRIES) {
        bundleBudget.delete(bundleBudget.keys().next().value);
      }
      b = { count: 0, reset: now + LIMITS.BUNDLE_TARGET_WINDOW_MS };
      bundleBudget.set(k, b);
    }
    if (b.count >= bundleOpksPerTarget) return false;
    b.count++;
    return true;
  }
  function pruneBundleBudget() {
    const now = Date.now();
    for (const [k, b] of bundleBudget) {
      if (b.reset > now) break;
      bundleBudget.delete(k);
    }
  }

  function apiPow(req, res, query) {
    rateCheck(req, 'pow');
    const purpose = new URLSearchParams(query).get('purpose');
    if (purpose !== 'register' && purpose !== 'send') throw new ValidationError();
    sendJson(res, 200, pow.issue(purpose));
  }

  async function apiRegister(req, res) {
    rateCheck(req, 'register');
    acquireBodySlot(req, res);
    const body = await readJsonObject(req, res, LIMITS.REGISTER_BODY_BYTES, bodyCtx);
    const gate = access.check(req.headers);
    if (!gate.ok) throw new HttpError(403, gate.error);
    const username = assertNewUsername(body.username); // CL-6: reserved names refused
    const ikSig = decodeKey(body.ik_sig);
    const ikDh = decodeKey(body.ik_dh);
    const ikDhSig = decodeSig(body.ik_dh_sig);
    const regSig = decodeSig(body.reg_sig); // CRYPTO-7: required proof of possession
    const spk = parseSignedPrekey(body.spk);
    const opks = parseOpkList(body.opks, LIMITS.MAX_OPKS_PER_REGISTER);
    const sol = parsePow(body.pow);

    // PoW before the (comparatively expensive) signature checks and DB writes.
    if (!pow.verify('register', sol.challenge, sol.nonce)) throw new HttpError(403, 'bad_pow');
    if (!verifyIkDhSig(ikSig, ikDh, ikDhSig) || !verifySpkSig(ikSig, spk) ||
        !verifyRegSig(ikSig, username, ikDh, regSig)) {
      throw new HttpError(400, 'bad_signature');
    }
    const created = db.createUser({ username, ikSig, ikDh, ikDhSig, spk, opks });
    if (created === 'username_taken') throw new HttpError(409, 'username_taken');
    // CRYPTO-7: an identity key (ik_sig or ik_dh) already registered to another username.
    if (created === 'identity_taken') throw new HttpError(409, 'identity_taken');
    gate.consume(); // single-use invitation spent only on success
    sendJson(res, 201, { ok: true });
  }

  function publicIdentity(u) {
    return {
      username: u.username,
      ik_sig: b64uEncode(u.ik_sig),
      ik_dh: b64uEncode(u.ik_dh),
      ik_dh_sig: b64uEncode(u.ik_dh_sig),
    };
  }

  function apiIdentity(req, res, name) {
    rateCheck(req, 'identity');
    const username = assertUsername(name);
    const u = db.getUser(username);
    if (!u) throw new HttpError(404, 'not_found');
    sendJson(res, 200, publicIdentity(u));
  }

  function apiBundle(req, res, name) {
    rateCheck(req, 'bundle');
    const username = assertUsername(name);
    if (!db.userExists(username)) throw new HttpError(404, 'not_found');
    // Beyond the per-target budget the bundle is served with opk:null and nothing is
    // consumed: unauthenticated callers can no longer drain a victim's whole OPK pool, and
    // the answer looks the same as an empty pool (no extra oracle).
    const r = db.takeBundle(username, consumeOpkAllowed(username));
    if (!r) throw new HttpError(404, 'not_found');
    const { user, opk, remaining } = r;
    sendJson(res, 200, {
      ...publicIdentity(user),
      spk: { id: Number(user.spk_id), pub: b64uEncode(user.spk_pub), sig: b64uEncode(user.spk_sig) },
      opk: opk ? { id: Number(opk.id), pub: b64uEncode(opk.pub) } : null,
    });
    if (remaining < LIMITS.OPK_LOW_WATERMARK) {
      const conn = online.get(username);
      if (conn && conn.state === 'ready') wsSend(conn, { t: 'opk_count', n: remaining });
    }
  }

  async function apiSend(req, res) {
    rateCheck(req, 'send');
    acquireBodySlot(req, res);
    const body = await readJsonObject(req, res, LIMITS.SEND_BODY_BYTES, bodyCtx,
      LIMITS.SEND_MAX_JSON_TOKENS);
    const list = body.messages;
    if (!Array.isArray(list) || list.length < 1 || list.length > LIMITS.MAX_MESSAGES_PER_SEND) {
      throw new ValidationError();
    }
    // Cheap shape checks only; blobs are decoded after the PoW is verified (SRV-03).
    const maxB64 = Math.ceil((LIMITS.BLOB_MAX_BYTES * 4) / 3);
    const pending = list.map((m) => {
      assertObject(m);
      const to = assertUsername(m.to);
      if (typeof m.blob !== 'string' || m.blob.length < 2 || m.blob.length > maxB64) {
        throw new ValidationError();
      }
      return { to, b64: m.blob };
    });
    const sol = parsePow(body.pow);
    // SRV-04: the PoW cost scales with the number of messages and bytes stored.
    const extraBits = sendPowExtraBits(pending.length, pending.reduce((n, m) => n + m.b64.length, 0));
    if (!pow.verify('send', sol.challenge, sol.nonce, extraBits)) throw new HttpError(403, 'bad_pow');
    const messages = pending.map(({ to, b64 }) => {
      const blob = b64uDecodeStrict(b64, LIMITS.BLOB_MAX_BYTES);
      if (blob.length < 1 || blob.length > LIMITS.BLOB_MAX_BYTES) throw new ValidationError();
      if (strictEnvelopes && !isSealedEnvelope(blob)) throw new ValidationError();
      return { to, blob };
    });

    const expires = roundUpToUtcDay(Date.now() + ttlMs);
    const items = messages.map(({ to, blob }) => ({
      recipient: to, id: randomBytes(16).toString('base64url'), blob,
    }));
    // Stored first (one transaction; survives a dropped socket until ACKed), then pushed.
    const stored = db.enqueueBatch(items, expires, {
      maxMessages: LIMITS.QUEUE_MAX_MESSAGES,
      maxBytes: cfg.queueMaxBytes ?? LIMITS.QUEUE_MAX_BYTES,
      maxTotalBytes: queueMaxTotalBytes,
      reservedBytes: queueReservedBytes, // APP-2 fair-share eviction (db.js)
      // Keep each recipient's seq above its live connection's flush cursor (db.js).
      minSeq: (recipient) => online.get(recipient)?.seq ?? 0,
    });
    const results = items.map(({ recipient, id, blob }, i) => {
      const r = stored[i];
      if (!r.ok) return { to: recipient, ok: false, error: r.error };
      const conn = online.get(recipient);
      if (conn) pushLive(conn, { seq: r.seq, id, blob });
      return { to: recipient, ok: true };
    });
    sendJson(res, 202, { ok: true, results });
  }

  async function handleApi(req, res, rawPath, query) {
    let m;
    if (crossSiteRequest(req)) throw new HttpError(403, 'forbidden');
    if (rawPath === '/api/pow') {
      if (req.method !== 'GET') throw new HttpError(405, 'method_not_allowed');
      return apiPow(req, res, query);
    }
    if (rawPath === '/api/register') {
      if (req.method !== 'POST') throw new HttpError(405, 'method_not_allowed');
      return apiRegister(req, res);
    }
    if (rawPath === '/api/send') {
      if (req.method !== 'POST') throw new HttpError(405, 'method_not_allowed');
      return apiSend(req, res);
    }
    if ((m = /^\/api\/identity\/([^/]*)$/.exec(rawPath))) {
      if (req.method !== 'GET') throw new HttpError(405, 'method_not_allowed');
      return apiIdentity(req, res, m[1]);
    }
    if ((m = /^\/api\/bundle\/([^/]*)$/.exec(rawPath))) {
      if (req.method !== 'GET') throw new HttpError(405, 'method_not_allowed');
      return apiBundle(req, res, m[1]);
    }
    throw new HttpError(404, 'not_found');
  }

  async function onRequest(req, res) {
    res.sendDate = false; // no Date header: less metadata, nothing needs it
    setSecurityHeaders(res, tls);
    const url = typeof req.url === 'string' ? req.url : '';
    const q = url.indexOf('?');
    const rawPath = q === -1 ? url : url.slice(0, q);
    const query = q === -1 ? '' : url.slice(q + 1);
    try {
      if (!rawPath.startsWith('/')) throw new HttpError(400, 'bad_request');
      if (rawPath === '/api' || rawPath.startsWith('/api/')) {
        await handleApi(req, res, rawPath, query);
      } else {
        await serveStatic(req, res, rawPath);
      }
    } catch (err) {
      if (err instanceof ValidationError) {
        sendJson(res, 400, { error: 'bad_request' });
      } else if (err instanceof HttpError) {
        sendJson(res, err.status, { error: err.code },
          err.closeConnection ? { Connection: 'close' } : {});
      } else {
        logError(err);
        sendJson(res, 500, { error: 'internal' });
      }
    }
  }

  // ----- WebSocket (SPEC §3.7) ---------------------------------------------------------

  // Backpressure (SRV-09): a message frame is only handed to a socket that already holds
  // data if the result stays under the per-socket high-water mark, and only while the
  // global total of not-yet-written frame bytes stays under its cap. A single frame larger
  // than the mark is sent only into an empty buffer. A socket whose buffer makes no drain
  // progress for stallTimeoutMs is terminated (the ping heartbeat is a second backstop).
  const wsHighWater = cfg.wsHighWater ?? LIMITS.WS_HIGH_WATER;
  let wsBufferedTotal = 0;

  function canSendFrame(conn, len) {
    const b = conn.ws.bufferedAmount;
    if (b > 0 && b + len > wsHighWater) return false;
    if (wsBufferedTotal > 0 && wsBufferedTotal + len > LIMITS.WS_GLOBAL_HIGH_WATER) return false;
    return true;
  }

  function sendFrame(conn, frame) {
    if (conn.ws.readyState !== conn.ws.OPEN) return;
    const len = frame.length;
    wsBufferedTotal += len;
    conn.pendingBytes += len;
    conn.ws.send(frame, () => {
      if (conn.finalized) return; // already credited back on close
      conn.pendingBytes -= len;
      wsBufferedTotal -= len;
    });
  }

  function finalizeConn(conn) {
    if (conn.finalized) return;
    conn.finalized = true;
    wsBufferedTotal -= conn.pendingBytes;
    conn.pendingBytes = 0;
  }

  function msgFrame(row) {
    return JSON.stringify({ t: 'msg', id: row.id, blob: b64uEncode(row.blob) });
  }

  function wsSend(conn, obj) {
    if (conn.ws.readyState !== conn.ws.OPEN) return;
    conn.ws.send(JSON.stringify(obj));
  }

  function wsClose(conn, code, reason) {
    conn.state = 'closed';
    if (conn.username && online.get(conn.username) === conn) online.delete(conn.username);
    try { conn.ws.close(code, reason); } catch { conn.ws.terminate(); }
  }

  /** Deliver a freshly queued message to an online recipient (or let the flusher do it). */
  function pushLive(conn, row) {
    if (conn.state !== 'ready') return;
    if (conn.flushing) return; // the flush loop will pick it up (seq is monotonic)
    const frame = msgFrame(row);
    if (!canSendFrame(conn, frame.length)) { flush(conn); return; }
    sendFrame(conn, frame);
    conn.seq = row.seq;
  }

  /** Wait until a frame of `len` bytes may be sent; terminate a stalled reader. */
  function waitDrain(conn, len) {
    return new Promise((resolve) => {
      let lastB = conn.ws.bufferedAmount;
      let lastProgress = Date.now();
      const check = () => {
        if (conn.state !== 'ready' || canSendFrame(conn, len)) { resolve(); return; }
        const b = conn.ws.bufferedAmount;
        const now = Date.now();
        if (b < lastB || b === 0) { lastB = b; lastProgress = now; }
        if (b > 0 && now - lastProgress >= stallTimeoutMs) {
          conn.state = 'closed';
          if (conn.username && online.get(conn.username) === conn) online.delete(conn.username);
          conn.ws.terminate();
          resolve();
          return;
        }
        setTimeout(check, 25);
      };
      check();
    });
  }

  /** Send every queued (unexpired) message, paging by seq and honouring backpressure. */
  async function flush(conn) {
    conn.flushing = true;
    if (conn.flushRunning) return;
    conn.flushRunning = true;
    try {
      outer: while (conn.state === 'ready') {
        const rows = db.queuedAfter(conn.username, conn.seq, Date.now(), 64);
        if (rows.length === 0) { conn.flushing = false; break; } // same tick: no gap
        for (const r of rows) {
          const frame = msgFrame(r);
          if (!canSendFrame(conn, frame.length)) {
            await waitDrain(conn, frame.length);
            if (conn.state !== 'ready') break outer;
          }
          sendFrame(conn, frame);
          conn.seq = r.seq;
        }
      }
    } catch (err) {
      logError(err);
    } finally {
      conn.flushRunning = false;
    }
  }

  /** Leave the unauthenticated pool (idempotent). */
  function leaveUnauth(conn) {
    if (unauth.delete(conn) && conn.addrId) unauthPerAddr.release(conn.addrId);
  }

  function handleAuth(conn, msg) {
    clearTimeout(conn.authTimer);
    leaveUnauth(conn);
    let user = null;
    let ok = false;
    try {
      const username = assertUsername(msg.username);
      const sig = decodeSig(msg.sig);
      user = db.getUser(username);
      ok = !!user && verifyAuthSig(user.ik_sig, conn.nonce, sig);
    } catch {
      ok = false;
    }
    conn.nonce = null; // exactly one attempt per connection
    if (!ok) {
      wsSend(conn, { t: 'error', code: 'auth_failed' });
      wsClose(conn, 4003, 'auth failed');
      return;
    }
    conn.username = user.username;
    conn.state = 'ready';
    const prev = online.get(conn.username);
    if (prev && prev !== conn) wsClose(prev, 4005, 'replaced');
    online.set(conn.username, conn);
    wsSend(conn, { t: 'ready', opk_count: db.countOpks(conn.username), spk_id: Number(user.spk_id) });
    flush(conn);
  }

  function handleAuthed(conn, msg) {
    switch (msg.t) {
      case 'resync': {
        // VC-1 / VC-2: the client refused (did not ACK) some messages while a bounded
        // local buffer was full and asks for them again. Rewind the flush cursor; rows
        // already ACKed are gone, so only un-ACKed ones are re-sent. Rate-limited.
        const now = Date.now();
        if (conn.lastResync && now - conn.lastResync < RESYNC_MIN_INTERVAL_MS) return;
        conn.lastResync = now;
        conn.seq = 0;
        flush(conn);
        return;
      }
      case 'ack': {
        const ids = msg.ids;
        if (!Array.isArray(ids) || ids.length < 1 || ids.length > LIMITS.WS_MAX_ACK_IDS ||
            !ids.every((id) => typeof id === 'string' && /^[A-Za-z0-9_-]{22}$/.test(id))) {
          throw new ValidationError();
        }
        db.ack(conn.username, ids); // only rows whose recipient is this user
        return;
      }
      case 'upload_opks': {
        const opks = parseOpkList(msg.opks, LIMITS.MAX_OPKS_PER_UPLOAD);
        const n = db.addOpks(conn.username, opks, LIMITS.MAX_OPKS_STORED);
        if (n === null) { wsSend(conn, { t: 'error', code: 'too_many_opks' }); return; }
        wsSend(conn, { t: 'opk_count', n });
        return;
      }
      case 'replace_opks': {
        // CL-3 / CRYPTO-4: after a backup restore the client discards every stored OPK
        // (it lacks the private keys of those uploaded after the backup) for a new batch.
        const opks = parseOpkList(msg.opks, LIMITS.MAX_OPKS_PER_UPLOAD);
        const n = db.replaceOpks(conn.username, opks);
        wsSend(conn, { t: 'opks_replaced', n });
        return;
      }
      case 'rotate_spk': {
        const spk = parseSignedPrekey(msg.spk);
        const user = db.getUser(conn.username);
        if (!user || !verifySpkSig(user.ik_sig, spk)) {
          wsSend(conn, { t: 'error', code: 'bad_signature' });
          return;
        }
        db.updateSpk(conn.username, spk);
        wsSend(conn, { t: 'spk_ok', id: spk.id });
        return;
      }
      case 'delete_account': {
        db.deleteUser(conn.username);
        wsSend(conn, { t: 'deleted' });
        wsClose(conn, 4004, 'deleted');
        return;
      }
      default:
        throw new ValidationError(); // includes a second 'auth'
    }
  }

  function onWsMessage(conn, data, isBinary) {
    if (conn.state === 'closed') return;
    let msg = null;
    if (!isBinary) {
      try { msg = JSON.parse(data.toString('utf8')); } catch { msg = null; }
    }
    const valid = isPlainObject(msg) && typeof msg.t === 'string';
    if (conn.state === 'await_auth') {
      if (!valid || msg.t !== 'auth') { wsClose(conn, 4002, 'protocol error'); return; }
      handleAuth(conn, msg);
      return;
    }
    if (!valid) { wsSend(conn, { t: 'error', code: 'bad_request' }); return; }
    try {
      handleAuthed(conn, msg);
    } catch (err) {
      if (err instanceof ValidationError) wsSend(conn, { t: 'error', code: 'bad_request' });
      else { logError(err); wsSend(conn, { t: 'error', code: 'internal' }); }
    }
  }

  const wss = new WebSocketServer({
    noServer: true,
    maxPayload: LIMITS.WS_MAX_PAYLOAD,
    perMessageDeflate: false, // no compression: avoids compression side channels & zip bombs
    clientTracking: false,
  });

  function onWsConnection(ws, addrId) {
    const conn = {
      ws, state: 'await_auth', username: null, nonce: randomBytes(32), alive: true,
      seq: 0, flushing: false, flushRunning: false, authTimer: null,
      addrId: null, pendingBytes: 0, finalized: false,
    };
    // Unauthenticated sockets (SRV-08): per-address cap, and a global cap that evicts the
    // oldest pending socket instead of locking everyone out.
    if (addrId) {
      if (!unauthPerAddr.tryAcquire(addrId, maxUnauthWsPerAddr)) { ws.terminate(); return; }
      conn.addrId = addrId;
    }
    conns.add(conn);
    unauth.add(conn);
    while (unauth.size > maxUnauthWs) {
      const oldest = unauth.values().next().value;
      leaveUnauth(oldest);
      clearTimeout(oldest.authTimer);
      oldest.state = 'closed';
      oldest.ws.terminate(); // no closing handshake: free the slot now
    }
    ws.on('error', () => { /* never log; 'close' follows */ });
    ws.on('pong', () => { conn.alive = true; });
    ws.on('message', (data, isBinary) => {
      try { onWsMessage(conn, data, isBinary); } catch (err) { logError(err); }
    });
    ws.on('close', () => {
      clearTimeout(conn.authTimer);
      conn.state = 'closed';
      leaveUnauth(conn);
      finalizeConn(conn);
      conns.delete(conn);
      if (conn.username && online.get(conn.username) === conn) online.delete(conn.username);
    });
    conn.authTimer = setTimeout(() => {
      if (conn.state === 'await_auth') wsClose(conn, 4001, 'auth timeout');
    }, authTimeoutMs);
    wsSend(conn, { t: 'challenge', nonce: b64uEncode(conn.nonce) });
  }

  function rejectUpgrade(socket, status) {
    const text = http.STATUS_CODES[status] || 'Error';
    try {
      socket.end(`HTTP/1.1 ${status} ${text}\r\nConnection: close\r\nContent-Length: 0\r\n` +
        `X-Content-Type-Options: nosniff\r\n\r\n`);
    } catch { /* ignore */ }
    socket.destroy();
  }

  // ----- HTTP(S) server ----------------------------------------------------------------

  const server = tls
    ? https.createServer({
      cert: fs.readFileSync(cfg.tlsCert),
      key: fs.readFileSync(cfg.tlsKey),
      minVersion: 'TLSv1.2',
    }, onRequest)
    : http.createServer(onRequest);
  server.headersTimeout = 20_000;
  server.requestTimeout = LIMITS.REQUEST_TIMEOUT_MS; // body stalls are cut earlier (idle guard)
  server.keepAliveTimeout = 5_000;
  server.maxConnections = LIMITS.MAX_HTTP_CONNECTIONS;
  server.on('clientError', (_err, socket) => { socket.destroy(); });

  // Per-address raw connection cap (header slowloris / fd exhaustion). Not applied behind a
  // trusted proxy (every socket comes from the proxy) or with rate limiting off (Tor).
  if (perAddrLimits && !cfg.trustProxy) {
    server.on('connection', (socket) => {
      const id = createHmac('sha256', limiter.secret)
        .update(`conn|${addressKeys(socket.remoteAddress || '').key}`).digest('base64url');
      if (!connsPerAddr.tryAcquire(id, LIMITS.MAX_CONNECTIONS_PER_ADDR)) { socket.destroy(); return; }
      socket.once('close', () => connsPerAddr.release(id));
    });
  }

  server.on('upgrade', (req, socket, head) => {
    socket.on('error', () => {});
    const url = typeof req.url === 'string' ? req.url : '';
    const rawPath = url.split('?')[0];
    if (rawPath !== '/ws') { rejectUpgrade(socket, 404); return; }
    // Cross-site pages must not be able to open sockets from visitors' browsers (they
    // would burn shared per-address WS slots/buckets): Fetch Metadata, with an Origin/Host
    // fallback for browsers without it (skipped behind a proxy that may rewrite Host).
    if (crossSiteRequest(req) ||
        (req.headers['sec-fetch-site'] === undefined && !cfg.trustProxy && foreignOrigin(req))) {
      rejectUpgrade(socket, 403);
      return;
    }
    if (!limiter.allow(req, 'ws')) { rejectUpgrade(socket, 429); return; }
    if (conns.size >= LIMITS.MAX_WS_CONNECTIONS) { rejectUpgrade(socket, 503); return; }
    const addrId = perAddrLimits ? limiter.addressId(req) : null;
    if (addrId && unauthPerAddr.count(addrId) >= maxUnauthWsPerAddr) {
      rejectUpgrade(socket, 429);
      return;
    }
    wss.handleUpgrade(req, socket, head, (ws) => onWsConnection(ws, addrId));
  });

  // ----- timers ------------------------------------------------------------------------

  const timers = [
    setInterval(() => {
      try { db.purgeExpired(Date.now()); } catch (err) { logError(err); }
    }, 60 * 60 * 1000),
    setInterval(() => { pow.prune(); limiter.prune(); pruneBundleBudget(); }, 60 * 1000),
    setInterval(() => {
      for (const conn of conns) {
        if (!conn.alive) { conn.state = 'closed'; conn.ws.terminate(); continue; }
        conn.alive = false;
        try { conn.ws.ping(); } catch { /* ignore */ }
      }
    }, pingIntervalMs),
  ];
  for (const t of timers) t.unref();

  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(cfg.port, cfg.host, () => { server.off('error', reject); resolve(); });
  });
  server.on('error', logError);

  let closed = false;
  async function close() {
    if (closed) return;
    closed = true;
    for (const t of timers) clearInterval(t);
    // Close sockets gracefully, force-terminate stragglers.
    const pending = [...conns].map((conn) => new Promise((resolve) => {
      if (conn.ws.readyState === conn.ws.CLOSED) { resolve(); return; }
      conn.ws.once('close', resolve);
      clearTimeout(conn.authTimer);
      conn.state = 'closed';
      try { conn.ws.close(1001, 'server shutdown'); } catch { conn.ws.terminate(); }
      setTimeout(() => { conn.ws.terminate(); }, 1000).unref();
    }));
    await Promise.all(pending);
    online.clear();
    await new Promise((resolve) => {
      server.close(() => resolve());
      server.closeAllConnections?.();
    });
    wss.close();
    db.close();
  }

  return { port: server.address().port, close, access };
}

// ---------------------------------------------------------------------------------------
// Auto-start only when executed directly (`node server/index.js`).
// ---------------------------------------------------------------------------------------

const isMain = (() => {
  try {
    return !!process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href;
  } catch {
    return false;
  }
})();

// No top-level await: the desktop build loads this module with require(esm), which
// refuses module graphs that contain one.
if (isMain) {
  const logError = makeLogError(envConfig.debug);
  process.on('unhandledRejection', logError);
  process.on('uncaughtException', (err) => { logError(err); process.exit(1); });
  startServer({ strictEnvelopes: envConfig.strictEnvelopes }).then((srv) => {
    const proto = envConfig.tlsCert && envConfig.tlsKey ? 'https' : 'http';
    const host = envConfig.host.includes(':') ? `[${envConfig.host}]` : envConfig.host;
    console.log(`Sombra listening on ${proto}://${host}:${srv.port}`);
    const shutdown = () => { srv.close().finally(() => process.exit(0)); };
    process.once('SIGINT', shutdown);
    process.once('SIGTERM', shutdown);
  }, (err) => {
    logError(err);
    process.exit(1);
  });
}
