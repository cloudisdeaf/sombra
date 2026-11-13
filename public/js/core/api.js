// Sombra — server API client (SPEC §4.3).
//
// REST over fetch (no credentials, no cache, no referrer) and an authenticated
// WebSocket for receiving. Sending (/api/send) is deliberately an unauthenticated
// request on a code path separate from the socket: sealed sender hides the sender
// inside the blob, and the server cannot link a send to a logged-in connection at
// the application layer.
//
// Isomorphic: works with the browser's fetch/WebSocket and Node 26's globals.

import { b64uEncode, b64uDecode, utf8Encode, concatBytes } from '../crypto/encoding.js';
import { randomBytes } from '../crypto/primitives.js';
import { solvePow } from '../crypto/pow.js';

export const USERNAME_RE = /^[a-z0-9_]{3,32}$/;
/**
 * CRYPTO-6 / CL-6: syntactically valid names that collide with Object.prototype
 * members in JS code. Never registrable (client and server); the client also keys
 * every username-indexed dictionary by null-prototype objects.
 */
export const RESERVED_USERNAMES = Object.freeze(new Set(['__proto__', 'constructor', 'prototype']));
const AUTH_LABEL = utf8Encode('SOMBRA-AUTH-v1');

// Client-side batching limits for /api/send (server: 100 messages, 24 MiB body).
const SEND_MAX_ITEMS = 100;
const SEND_MAX_BATCH_CHARS = 20 * 1024 * 1024;


/** Smallest k with 2^k >= x (x >= 1), integer arithmetic only. */
function ceilLog2(x) {
  let k = 0;
  while (2 ** k < x) k++;
  return k;
}

/**
 * SRV-04: extra leading-zero bits a /api/send solution needs on top of the challenge's
 * base difficulty, so the cost scales with what a request stores: +ceil(log2(messages))
 * and +ceil(log2(bytes / 256 KiB)) beyond 256 KiB (bytes estimated from the b64u length,
 * known before anything is decoded). One small message: +0. Capped at 16.
 * Must stay identical in server/pow.js.
 */
export function sendPowExtraBits(count, b64Chars) {
  const bytes = Math.floor((b64Chars * 3) / 4);
  const extra = ceilLog2(Math.max(1, count)) + (bytes > 262144 ? ceilLog2(Math.ceil(bytes / 262144)) : 0);
  return Math.min(16, extra);
}

const BACKOFF_MIN_MS = 1000;
const BACKOFF_MAX_MS = 30000;

/** Close codes after which reconnecting is pointless or harmful. */
const NO_RECONNECT_CODES = new Set([
  4004, // account deleted
  4005, // replaced by a newer connection of the same account (another tab/device)
]);

/** Error carrying the server's error code as its message (UI maps codes to text). */
export class ApiError extends Error {
  constructor(code, status = 0) {
    super(code);
    this.name = 'ApiError';
    this.code = code;
    this.status = status;
  }
}

function checkUsername(u) {
  if (typeof u !== 'string' || !USERNAME_RE.test(u)) throw new ApiError('bad_request', 400);
  return u;
}

/** Uniform random jitter in [0, n) using the CSPRNG (no Math.random). */
function randomBelow(n) {
  const b = randomBytes(4);
  const x = ((b[0] << 24) | (b[1] << 16) | (b[2] << 8) | b[3]) >>> 0;
  return Math.floor((x / 0x100000000) * n);
}

export class ServerApi {
  /**
   * @param {string} baseUrl e.g. 'http://127.0.0.1:8443'
   * @param {{fetch?: Function, WebSocket?: Function}} [impl] overrides (tests)
   */
  constructor(baseUrl, impl = {}) {
    const u = new URL(baseUrl);
    if (u.protocol !== 'http:' && u.protocol !== 'https:') throw new TypeError('serverUrl must be http(s)');
    this.baseUrl = u.origin;
    this.wsUrl = (u.protocol === 'https:' ? 'wss://' : 'ws://') + u.host + '/ws';
    this._fetch = impl.fetch || globalThis.fetch.bind(globalThis);
    this._WebSocket = impl.WebSocket || globalThis.WebSocket;
  }

  async _request(method, path, body) {
    const init = {
      method,
      credentials: 'omit',
      cache: 'no-store',
      referrerPolicy: 'no-referrer',
      redirect: 'error',
      headers: { Accept: 'application/json' },
    };
    if (body !== undefined) {
      init.body = JSON.stringify(body);
      init.headers['Content-Type'] = 'application/json';
    }
    let res;
    try {
      res = await this._fetch(this.baseUrl + path, init);
    } catch {
      throw new ApiError('network', 0);
    }
    let data = null;
    try {
      data = await res.json();
    } catch {
      data = null;
    }
    if (!res.ok) {
      const code = data && typeof data.error === 'string' ? data.error : `http_${res.status}`;
      throw new ApiError(code, res.status);
    }
    if (!data || typeof data !== 'object') throw new ApiError('bad_response', res.status);
    return { status: res.status, data };
  }

  /** GET /api/pow → {challenge, difficulty} */
  async getPow(purpose) {
    if (purpose !== 'register' && purpose !== 'send') throw new TypeError('bad pow purpose');
    const { data } = await this._request('GET', `/api/pow?purpose=${purpose}`);
    if (typeof data.challenge !== 'string' || !Number.isInteger(data.difficulty)) {
      throw new ApiError('bad_response');
    }
    return data;
  }

  async _solve(purpose, onProgress, signal, extraBits = 0) {
    const { challenge, difficulty } = await this.getPow(purpose);
    const nonce = await solvePow(challenge, difficulty + extraBits, {
      signal,
      onProgress: onProgress ? (tries) => onProgress({ stage: 'pow', tries }) : undefined,
    });
    return { challenge, nonce };
  }

  /**
   * POST /api/register; fetches and solves a registration PoW first.
   * Retries once with a fresh challenge if the server rejects the PoW (e.g. it
   * expired because solving took longer than its 5-minute lifetime).
   */
  async register(payload, { onProgress, signal } = {}) {
    for (let attempt = 0; ; attempt++) {
      const pow = await this._solve('register', onProgress, signal);
      if (onProgress) { try { onProgress({ stage: 'register' }); } catch { /* ignore */ } }
      try {
        await this._request('POST', '/api/register', { ...payload, pow });
        return true;
      } catch (err) {
        if (err.code === 'bad_pow' && attempt === 0) continue;
        throw err;
      }
    }
  }

  /** → {username, ik_sig, ik_dh, ik_dh_sig} or null if unknown. */
  async getIdentity(username) {
    checkUsername(username);
    try {
      const { data } = await this._request('GET', `/api/identity/${username}`);
      return data;
    } catch (err) {
      if (err.code === 'not_found') return null;
      throw err;
    }
  }

  /** → full prekey bundle (consumes one OPK on the server) or null if unknown. */
  async getBundle(username) {
    checkUsername(username);
    try {
      const { data } = await this._request('GET', `/api/bundle/${username}`);
      return data;
    } catch (err) {
      if (err.code === 'not_found') return null;
      throw err;
    }
  }

  /**
   * POST /api/send, split into batches the server accepts (≤100 items, bounded
   * body size), each with its own send PoW.
   * @param {{to: string, blob: string}[]} messages  blob = b64u
   * @returns {Promise<{to, ok, error?}[]>} one result per input message, in order.
   *          Batch-level failures (network, HTTP errors) become per-item failures.
   */
  async send(messages) {
    if (!Array.isArray(messages)) throw new TypeError('messages must be an array');
    const batches = [];
    let cur = [];
    let size = 0;
    for (const m of messages) {
      checkUsername(m.to);
      if (typeof m.blob !== 'string') throw new TypeError('blob must be b64u');
      const s = m.blob.length + m.to.length + 32;
      if (cur.length && (cur.length >= SEND_MAX_ITEMS || size + s > SEND_MAX_BATCH_CHARS)) {
        batches.push(cur);
        cur = [];
        size = 0;
      }
      cur.push(m);
      size += s;
    }
    if (cur.length) batches.push(cur);

    const results = [];
    for (const batch of batches) {
      let res = null;
      for (let attempt = 0; attempt < 2 && !res; attempt++) {
        try {
          const pow = await this._solve('send', undefined, undefined,
            sendPowExtraBits(batch.length, batch.reduce((n, m) => n + m.blob.length, 0)));
          const { data } = await this._request('POST', '/api/send', {
            messages: batch.map((m) => ({ to: m.to, blob: m.blob })),
            pow,
          });
          if (!Array.isArray(data.results) || data.results.length !== batch.length) throw new ApiError('bad_response');
          res = data.results.map((r, i) => ({
            to: batch[i].to,
            ok: r && r.ok === true,
            ...(r && r.ok === true ? {} : { error: (r && typeof r.error === 'string') ? r.error : 'failed' }),
          }));
        } catch (err) {
          if (err && err.code === 'bad_pow' && attempt === 0) continue;
          res = batch.map((m) => ({ to: m.to, ok: false, error: (err && err.code) || 'network' }));
        }
      }
      results.push(...res);
    }
    return results;
  }

  /**
   * Open the authenticated receive socket. Reconnects with exponential backoff
   * (1 s … 30 s, randomised jitter) until close() is called.
   *
   * @param {object} o
   * @param {string} o.username
   * @param {(bytes: Uint8Array) => Promise<Uint8Array>} o.sign  Ed25519 with IK_sig
   * @param {(msg: {t:'msg', id, blob}) => void} o.onMessage
   * @param {(connected: boolean) => void} [o.onStatus]
   * @param {(frame: object) => void} [o.onEvent]  ready / opk_count / spk_ok / deleted / error / closed
   * @returns {{ send(obj): boolean, close(): void, readonly connected: boolean }}
   */
  connect({ username, sign, onMessage, onStatus, onEvent }) {
    checkUsername(username);
    const WS = this._WebSocket;
    if (typeof WS !== 'function') throw new Error('WebSocket unavailable');
    const wsUrl = this.wsUrl;
    let ws = null;
    let closed = false;
    let ready = false;
    let attempt = 0;
    let timer = null;

    const safe = (fn, ...args) => {
      if (typeof fn !== 'function') return;
      try { fn(...args); } catch { /* listener errors must not kill the socket */ }
    };

    const setReady = (v) => {
      if (ready === v) return;
      ready = v;
      safe(onStatus, v);
    };

    const schedule = () => {
      if (closed || timer) return;
      const base = Math.min(BACKOFF_MAX_MS, BACKOFF_MIN_MS * 2 ** Math.min(attempt, 10));
      attempt++;
      const delay = Math.floor(base / 2) + randomBelow(Math.ceil(base / 2) + 1);
      timer = setTimeout(() => { timer = null; open(); }, delay);
    };

    const open = () => {
      if (closed) return;
      let sock;
      try {
        sock = new WS(wsUrl);
      } catch {
        schedule();
        return;
      }
      ws = sock;
      let authed = false;
      let authSent = false;

      sock.onmessage = async (ev) => {
        if (closed || ws !== sock) return;
        if (typeof ev.data !== 'string') return; // protocol uses text frames only
        let msg;
        try { msg = JSON.parse(ev.data); } catch { return; }
        if (!msg || typeof msg !== 'object' || typeof msg.t !== 'string') return;

        if (!authed) {
          if (msg.t === 'challenge' && !authSent && typeof msg.nonce === 'string') {
            authSent = true;
            try {
              const nonce = b64uDecode(msg.nonce);
              if (nonce.length !== 32) throw new Error('bad nonce');
              const sig = await sign(concatBytes(AUTH_LABEL, nonce));
              if (closed || ws !== sock) return;
              sock.send(JSON.stringify({ t: 'auth', username, sig: b64uEncode(sig) }));
            } catch {
              try { sock.close(); } catch { /* ignore */ }
            }
          } else if (msg.t === 'ready') {
            authed = true;
            attempt = 0;
            setReady(true);
            safe(onEvent, msg);
          } else if (msg.t === 'error') {
            if (msg.code === 'auth_failed') attempt = Math.max(attempt, 5); // slow down
            safe(onEvent, msg);
          }
          return;
        }
        if (msg.t === 'msg') safe(onMessage, msg);
        else safe(onEvent, msg);
      };
      sock.onerror = () => { /* 'close' follows */ };
      sock.onclose = (ev) => {
        if (ws !== sock) return;
        ws = null;
        setReady(false);
        if (closed) return;
        const code = ev && typeof ev.code === 'number' ? ev.code : 0;
        if (NO_RECONNECT_CODES.has(code)) {
          closed = true;
          safe(onEvent, { t: 'closed', code });
          return;
        }
        schedule();
      };
    };

    open();

    return {
      send(obj) {
        if (closed || !ready || !ws || ws.readyState !== 1) return false;
        try {
          ws.send(JSON.stringify(obj));
          return true;
        } catch {
          return false;
        }
      },
      close() {
        closed = true;
        if (timer) { clearTimeout(timer); timer = null; }
        const s = ws;
        ws = null;
        if (s) {
          s.onmessage = null;
          try { s.close(1000); } catch { /* ignore */ }
        }
        if (ready) { ready = false; safe(onStatus, false); }
      },
      get connected() {
        return ready && !closed;
      },
    };
  }
}
