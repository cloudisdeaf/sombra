// Sombra — client-side proof of work (SPEC §2.10).
//
// hash = SHA-256(utf8("SOMBRA-POW-v1:" + challenge + ":" + nonce)), nonce a
// decimal integer string; valid iff hash has >= difficulty leading zero bits.
//
// WebCrypto's digest is async and far too slow for a tight search loop, so this
// module carries a synchronous pure-JS SHA-256 (FIPS 180-4). The solver also
// caches the "midstate" of the constant prefix so each attempt only hashes the
// final one or two blocks.

import { utf8Encode } from './encoding.js';

const POW_PREFIX = 'SOMBRA-POW-v1:';
const YIELD_EVERY = 20000;
// The solver refuses absurd difficulties (a malicious server could otherwise
// make the client spin forever). Server defaults are 18 (register) / 10 (send).
const MAX_SOLVE_DIFFICULTY = 32;
const NONCE_RE = /^(0|[1-9][0-9]{0,15})$/;

// ---------------------------------------------------------------------------
// Pure-JS SHA-256
// ---------------------------------------------------------------------------

const K = new Int32Array([
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]);
const IV = new Int32Array([
  0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
]);
const W = new Int32Array(64); // message schedule scratch (module-level: no allocation per block)

/** Process one 64-byte block at buf[off..off+64) into state H (Int32Array(8)). */
function compress(H, buf, off) {
  for (let i = 0; i < 16; i++) {
    const j = off + i * 4;
    W[i] = (buf[j] << 24) | (buf[j + 1] << 16) | (buf[j + 2] << 8) | buf[j + 3];
  }
  for (let i = 16; i < 64; i++) {
    const w15 = W[i - 15], w2 = W[i - 2];
    const s0 = ((w15 >>> 7) | (w15 << 25)) ^ ((w15 >>> 18) | (w15 << 14)) ^ (w15 >>> 3);
    const s1 = ((w2 >>> 17) | (w2 << 15)) ^ ((w2 >>> 19) | (w2 << 13)) ^ (w2 >>> 10);
    W[i] = (W[i - 16] + s0 + W[i - 7] + s1) | 0;
  }
  let a = H[0], b = H[1], c = H[2], d = H[3], e = H[4], f = H[5], g = H[6], h = H[7];
  for (let i = 0; i < 64; i++) {
    const S1 = ((e >>> 6) | (e << 26)) ^ ((e >>> 11) | (e << 21)) ^ ((e >>> 25) | (e << 7));
    const ch = (e & f) ^ (~e & g);
    const t1 = (h + S1 + ch + K[i] + W[i]) | 0;
    const S0 = ((a >>> 2) | (a << 30)) ^ ((a >>> 13) | (a << 19)) ^ ((a >>> 22) | (a << 10));
    const maj = (a & b) ^ (a & c) ^ (b & c);
    const t2 = (S0 + maj) | 0;
    h = g; g = f; f = e; e = (d + t1) | 0;
    d = c; c = b; b = a; a = (t1 + t2) | 0;
  }
  H[0] = (H[0] + a) | 0; H[1] = (H[1] + b) | 0; H[2] = (H[2] + c) | 0; H[3] = (H[3] + d) | 0;
  H[4] = (H[4] + e) | 0; H[5] = (H[5] + f) | 0; H[6] = (H[6] + g) | 0; H[7] = (H[7] + h) | 0;
}

/**
 * Finish a hash: `tail[0..tailLen)` are the trailing (< 64) message bytes not yet
 * compressed, `totalLen` the full message length in bytes. `tail` must have room
 * for tailLen + 72 bytes; bytes past tailLen are overwritten.
 */
function finish(H, tail, tailLen, totalLen) {
  tail[tailLen] = 0x80;
  const padded = tailLen + 1 + 8 <= 64 ? 64 : 128;
  tail.fill(0, tailLen + 1, padded - 8);
  const bitsHi = Math.floor(totalLen / 0x20000000); // (totalLen * 8) / 2^32
  const bitsLo = (totalLen * 8) >>> 0;
  tail[padded - 8] = bitsHi >>> 24; tail[padded - 7] = bitsHi >>> 16;
  tail[padded - 6] = bitsHi >>> 8; tail[padded - 5] = bitsHi;
  tail[padded - 4] = bitsLo >>> 24; tail[padded - 3] = bitsLo >>> 16;
  tail[padded - 2] = bitsLo >>> 8; tail[padded - 1] = bitsLo;
  compress(H, tail, 0);
  if (padded === 128) compress(H, tail, 64);
}

function stateToBytes(H) {
  const out = new Uint8Array(32);
  for (let i = 0; i < 8; i++) {
    out[i * 4] = H[i] >>> 24; out[i * 4 + 1] = H[i] >>> 16;
    out[i * 4 + 2] = H[i] >>> 8; out[i * 4 + 3] = H[i];
  }
  return out;
}

/** Synchronous SHA-256 of a Uint8Array (extra export; verified against WebCrypto in tests). */
/**
 * Synchronous HMAC-SHA256 (RFC 2104) on top of sha256Sync. Used by the Double Ratchet
 * chain step (VC-4): it is ~15x cheaper than two WebCrypto importKey+sign round trips,
 * which bounds the CPU an attacker can make a recipient spend on forged headers before
 * authentication. Verified against WebCrypto and RFC 4231 in tests.
 */
export function hmacSha256Sync(key, data) {
  if (!(key instanceof Uint8Array) || !(data instanceof Uint8Array)) throw new TypeError('hmacSha256Sync expects Uint8Arrays');
  const k0 = new Uint8Array(64);
  if (key.length > 64) {
    const kh = sha256Sync(key);
    k0.set(kh);
    kh.fill(0);
  } else {
    k0.set(key);
  }
  const inner = new Uint8Array(64 + data.length);
  const outer = new Uint8Array(64 + 32);
  for (let i = 0; i < 64; i++) {
    inner[i] = k0[i] ^ 0x36;
    outer[i] = k0[i] ^ 0x5c;
  }
  inner.set(data, 64);
  const ih = sha256Sync(inner);
  outer.set(ih, 64);
  const mac = sha256Sync(outer);
  k0.fill(0); inner.fill(0); outer.fill(0); ih.fill(0);
  return mac;
}

export function sha256Sync(data) {
  if (!(data instanceof Uint8Array)) throw new TypeError('sha256Sync input must be a Uint8Array');
  const H = new Int32Array(IV);
  const full = data.length - (data.length % 64);
  for (let off = 0; off < full; off += 64) compress(H, data, off);
  const tail = new Uint8Array(128);
  tail.set(data.subarray(full));
  finish(H, tail, data.length - full, data.length);
  return stateToBytes(H);
}

// ---------------------------------------------------------------------------
// Proof of work
// ---------------------------------------------------------------------------

/** Number of leading zero bits of a byte array. */
export function leadingZeroBits(bytes) {
  if (!(bytes instanceof Uint8Array)) throw new TypeError('leadingZeroBits input must be a Uint8Array');
  let n = 0;
  for (let i = 0; i < bytes.length; i++) {
    if (bytes[i] === 0) { n += 8; continue; }
    return n + Math.clz32(bytes[i]) - 24;
  }
  return n;
}

/** Leading zero bits straight from the hash state words (avoids building bytes in the hot loop). */
function stateLeadingZeroBits(H) {
  let n = 0;
  for (let i = 0; i < 8; i++) {
    if (H[i] === 0) { n += 32; continue; }
    return n + Math.clz32(H[i]);
  }
  return n;
}

function checkDifficulty(d, max) {
  return Number.isInteger(d) && d >= 0 && d <= max;
}

function powMessage(challenge, nonce) {
  return utf8Encode(POW_PREFIX + challenge + ':' + nonce);
}

/** Verify a PoW solution synchronously. Never throws; returns false on malformed input. */
export function verifyPowSync(challenge, nonce, difficulty) {
  try {
    if (typeof challenge !== 'string' || typeof nonce !== 'string') return false;
    if (!NONCE_RE.test(nonce) || !checkDifficulty(difficulty, 256)) return false;
    return leadingZeroBits(sha256Sync(powMessage(challenge, nonce))) >= difficulty;
  } catch {
    return false;
  }
}

function abortError(signal) {
  if (signal.reason !== undefined) return signal.reason;
  const e = new Error('aborted');
  e.name = 'AbortError';
  return e;
}

/**
 * Search for a nonce. Yields to the event loop every ~20000 attempts so the UI
 * stays responsive; reports progress (attempt count) via onProgress and stops
 * when `signal` is aborted (rejects with signal.reason / AbortError).
 * @returns {Promise<string>} decimal nonce
 */
export async function solvePow(challenge, difficulty, { onProgress, signal } = {}) {
  if (typeof challenge !== 'string' || challenge.length === 0 || challenge.length > 4096) {
    throw new TypeError('bad challenge');
  }
  if (!checkDifficulty(difficulty, MAX_SOLVE_DIFFICULTY)) throw new RangeError('difficulty out of range');
  if (signal?.aborted) throw abortError(signal);

  // Midstate: compress all complete 64-byte blocks of the constant prefix once.
  const prefix = utf8Encode(POW_PREFIX + challenge + ':');
  const full = prefix.length - (prefix.length % 64);
  const mid = new Int32Array(IV);
  for (let off = 0; off < full; off += 64) compress(mid, prefix, off);
  const remLen = prefix.length - full;
  // Room for remainder (<64) + nonce digits (<=16) + padding (<=72).
  const tail = new Uint8Array(remLen + 16 + 72 + 64);
  const H = new Int32Array(8);

  for (let nonce = 0; nonce <= Number.MAX_SAFE_INTEGER; nonce++) {
    const digits = String(nonce);
    tail.set(prefix.subarray(full), 0);
    for (let i = 0; i < digits.length; i++) tail[remLen + i] = digits.charCodeAt(i);
    let tLen = remLen + digits.length;
    H.set(mid);
    if (tLen >= 64) { // remainder + digits spilled into a further complete block
      compress(H, tail, 0);
      tail.copyWithin(0, 64, tLen);
      tLen -= 64;
    }
    finish(H, tail, tLen, prefix.length + digits.length);
    if (stateLeadingZeroBits(H) >= difficulty) return digits;

    if (nonce % YIELD_EVERY === YIELD_EVERY - 1) {
      if (typeof onProgress === 'function') {
        try { onProgress(nonce + 1); } catch { /* UI callback errors must not break solving */ }
      }
      await new Promise((r) => setTimeout(r, 0));
      if (signal?.aborted) throw abortError(signal);
    }
  }
  throw new Error('no solution found');
}
