// Sombra server configuration (SPEC §3.1).
//
// All settings come from environment variables. `startServer(options)` may override
// any of them (tests use port 0, a temp data dir, low PoW bits and rateLimit:false).
//
// Privacy note: TRUST_PROXY only affects which address is used as the (HMAC-hashed,
// in-memory, never persisted) rate-limit key. IPs are NEVER logged under any setting.

import path from 'node:path';

/** Parse an integer env var; fall back to `def` when unset/invalid or out of range. */
function intEnv(env, name, def, min, max) {
  const raw = env[name];
  if (raw === undefined || raw === '') return def;
  if (!/^\d+$/.test(String(raw).trim())) return def;
  const n = Number.parseInt(raw, 10);
  if (!Number.isSafeInteger(n) || n < min || n > max) return def;
  return n;
}

/** Parse an on/off style boolean env var. */
function boolEnv(env, name, def) {
  const raw = env[name];
  if (raw === undefined || raw === '') return def;
  const v = String(raw).trim().toLowerCase();
  if (['1', 'on', 'true', 'yes'].includes(v)) return true;
  if (['0', 'off', 'false', 'no'].includes(v)) return false;
  return def;
}

/**
 * Build the configuration object from an environment map.
 * @param {Record<string,string|undefined>} env
 */
export function loadConfig(env = process.env) {
  const tlsCert = env.TLS_CERT || null;
  const tlsKey = env.TLS_KEY || null;
  return {
    port: intEnv(env, 'PORT', 8443, 0, 65535),
    host: env.HOST || '127.0.0.1',
    dataDir: path.resolve(env.DATA_DIR || './data'),
    // HTTPS (+ HSTS) only when BOTH are set.
    tlsCert: tlsCert && tlsKey ? tlsCert : null,
    tlsKey: tlsCert && tlsKey ? tlsKey : null,
    // PoW difficulties are clamped to a sane range (0..32 leading zero bits).
    // Default raised from SPEC's 18 to 22 bits (BUG-3 / SRV-04): ~4M expected hashes, a few
    // seconds in a browser, 16x the cost of mass registration / username squatting.
    powRegisterBits: intEnv(env, 'POW_REGISTER_BITS', 22, 0, 32),
    powSendBits: intEnv(env, 'POW_SEND_BITS', 10, 0, 32),
    messageTtlDays: intEnv(env, 'MESSAGE_TTL_DAYS', 14, 1, 365),
    trustProxy: boolEnv(env, 'TRUST_PROXY', false),
    rateLimit: boolEnv(env, 'RATE_LIMIT', true),
    // Global cap on queued (undelivered) blob bytes across all recipients (SRV-04).
    queueMaxTotalBytes: intEnv(env, 'QUEUE_MAX_TOTAL_MB', 8192, 1, 16 * 1024 * 1024) * 1024 * 1024,
    // Reject /api/send blobs that are not well-formed sealed envelopes (SPEC §2.7 + §2.6
    // padding buckets). Applied by the `node server/index.js` entry point; library callers
    // (tests) must opt in via startServer({strictEnvelopes:true}) — see index.js.
    strictEnvelopes: boolEnv(env, 'STRICT_ENVELOPES', true),
    debug: env.DEBUG === '1',
  };
}

/** Configuration derived from the current process environment. */
export const config = loadConfig(process.env);

// Fixed protocol limits (SPEC §3.4, §3.6, §3.7). Not configurable on purpose.
export const LIMITS = Object.freeze({
  REGISTER_BODY_BYTES: 256 * 1024,          // 256 KiB
  SEND_BODY_BYTES: 24 * 1024 * 1024,        // 24 MiB total request body
  BLOB_MAX_BYTES: 12 * 1024 * 1024,         // 12 MiB per decoded blob
  MAX_OPKS_PER_REGISTER: 200,
  MAX_OPKS_PER_UPLOAD: 200,
  MAX_OPKS_STORED: 2000,                    // hard cap per user (storage bound)
  MAX_MESSAGES_PER_SEND: 100,
  QUEUE_MAX_MESSAGES: 5000,                 // per recipient
  QUEUE_MAX_BYTES: 256 * 1024 * 1024,       // per recipient
  QUEUE_RESERVED_BYTES: 32 * 1024 * 1024,   // APP-2: fair-share reserve honoured even when the global quota is full
  WS_MAX_PAYLOAD: 1024 * 1024,              // 1 MiB inbound frame limit
  WS_MAX_ACK_IDS: 1000,
  OPK_LOW_WATERMARK: 20,
  POW_TTL_MS: 5 * 60 * 1000,

  // ---- Resource bounds (security fixes SRV-03/06/08/09; not part of the wire protocol) ----
  // Global budget of request-body bytes buffered in memory at once (all requests). A body
  // that would exceed it gets 503 {error:"busy"} and is discarded without buffering.
  BODY_BUDGET_BYTES: 128 * 1024 * 1024,
  // A request body that sends no data for this long is aborted (body slowloris).
  BODY_IDLE_TIMEOUT_MS: 30_000,
  // Whole-request deadline (headers + body). 24 MiB at ~200 KiB/s.
  REQUEST_TIMEOUT_MS: 120_000,
  // Max structural JSON tokens ({ [ , :) in a /api/send body: bounds JSON.parse expansion
  // (a 24 MiB body of "[0,0,0,...]" would otherwise build millions of JS values pre-PoW).
  SEND_MAX_JSON_TOKENS: 8 * 100 + 64,
  // Per-address caps (only when rate limiting is on; with RATE_LIMIT=off every client
  // shares one address, e.g. Tor, so only the global caps apply).
  MAX_INFLIGHT_BODIES_PER_ADDR: 8,
  MAX_CONNECTIONS_PER_ADDR: 256,        // raw TCP sockets (not applied with TRUST_PROXY)
  MAX_UNAUTH_WS_PER_ADDR: 5,
  // Global caps.
  MAX_HTTP_CONNECTIONS: 24_000,         // server.maxConnections (> MAX_WS_CONNECTIONS)
  MAX_WS_CONNECTIONS: 20_000,
  MAX_UNAUTH_WS: 1000,                  // oldest pending (unauthenticated) socket is evicted
  WS_AUTH_TIMEOUT_MS: 5_000,            // SPEC: "within 10 s" — stricter is compliant
  // WebSocket send backpressure: never queue a frame on a socket that already holds data
  // if that would exceed the per-socket high-water mark; global cap across sockets.
  WS_HIGH_WATER: 2 * 1024 * 1024,
  WS_LOW_WATER: 512 * 1024,
  WS_GLOBAL_HIGH_WATER: 256 * 1024 * 1024,
  WS_STALL_TIMEOUT_MS: 45_000,          // buffered data with zero drain progress → terminate
  // Per-target OPK consumption budget for unauthenticated GET /api/bundle (SRV-06). Beyond
  // it the bundle is served with opk:null and NO OPK is consumed.
  BUNDLE_OPKS_PER_TARGET: 50,
  BUNDLE_TARGET_WINDOW_MS: 60 * 60 * 1000,
  BUNDLE_TARGET_MAX_ENTRIES: 100_000,
});
