// Sombra — byte / string encoding helpers (SPEC §2.1).
//
// Isomorphic: uses only standard globals (TextEncoder / TextDecoder) so it runs
// unchanged in browsers and in Node 26. No dependencies.

const B64U_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';

// Reverse lookup table: char code -> 6-bit value, or -1 for characters outside
// the base64url alphabet.
const B64U_LOOKUP = (() => {
  const t = new Int16Array(128).fill(-1);
  for (let i = 0; i < B64U_ALPHABET.length; i++) t[B64U_ALPHABET.charCodeAt(i)] = i;
  return t;
})();

// Alphabet as ASCII byte values (for the buffer-based encoder).
const B64U_CODES = Uint8Array.from(B64U_ALPHABET, (c) => c.charCodeAt(0));
// All encoder output bytes are ASCII, for which UTF-8 decoding is the identity.
const asciiDecoder = new TextDecoder('utf-8');

const textEncoder = new TextEncoder();
// fatal: true -> malformed UTF-8 throws instead of silently producing U+FFFD.
const textDecoder = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true });

function assertBytes(x, what = 'argument') {
  if (!(x instanceof Uint8Array)) throw new TypeError(`${what} must be a Uint8Array`);
}

/**
 * Encode bytes as base64url without padding (RFC 4648 §5).
 * @param {Uint8Array} bytes
 * @returns {string}
 */
export function b64uEncode(bytes) {
  assertBytes(bytes, 'b64uEncode input');
  // Write ASCII codes into a byte buffer and decode once: building the string with
  // `+=` creates millions of rope nodes for multi-MiB inputs (files) and spends
  // seconds in the garbage collector.
  const len = bytes.length;
  const out = new Uint8Array(Math.ceil((len * 4) / 3));
  let o = 0;
  let i = 0;
  for (; i + 2 < len; i += 3) {
    const n = (bytes[i] << 16) | (bytes[i + 1] << 8) | bytes[i + 2];
    out[o++] = B64U_CODES[(n >>> 18) & 63];
    out[o++] = B64U_CODES[(n >>> 12) & 63];
    out[o++] = B64U_CODES[(n >>> 6) & 63];
    out[o++] = B64U_CODES[n & 63];
  }
  const rem = len - i;
  if (rem === 1) {
    const n = bytes[i] << 16;
    out[o++] = B64U_CODES[(n >>> 18) & 63];
    out[o++] = B64U_CODES[(n >>> 12) & 63];
  } else if (rem === 2) {
    const n = (bytes[i] << 16) | (bytes[i + 1] << 8);
    out[o++] = B64U_CODES[(n >>> 18) & 63];
    out[o++] = B64U_CODES[(n >>> 12) & 63];
    out[o++] = B64U_CODES[(n >>> 6) & 63];
  }
  return asciiDecoder.decode(out.subarray(0, o));
}

/**
 * Strictly decode base64url without padding.
 * Throws on: non-string input, characters outside the alphabet (including '='
 * padding and whitespace), impossible lengths (len % 4 === 1) and
 * non-canonical encodings (non-zero unused trailing bits). Strictness gives
 * every value exactly one valid encoding, which matters when encodings are
 * compared or used as map keys.
 * @param {string} str
 * @returns {Uint8Array}
 */
export function b64uDecode(str) {
  if (typeof str !== 'string') throw new TypeError('b64uDecode input must be a string');
  const len = str.length;
  if (len % 4 === 1) throw new Error('invalid base64url length');
  const outLen = Math.floor((len * 3) / 4);
  const out = new Uint8Array(outLen);
  const val = (idx) => {
    const c = str.charCodeAt(idx);
    const v = c < 128 ? B64U_LOOKUP[c] : -1;
    if (v < 0) throw new Error('invalid base64url character');
    return v;
  };
  let o = 0;
  let i = 0;
  for (; i + 3 < len; i += 4) {
    const n = (val(i) << 18) | (val(i + 1) << 12) | (val(i + 2) << 6) | val(i + 3);
    out[o++] = (n >>> 16) & 255;
    out[o++] = (n >>> 8) & 255;
    out[o++] = n & 255;
  }
  const rem = len - i;
  if (rem === 2) {
    const a = val(i), b = val(i + 1);
    if (b & 0x0f) throw new Error('non-canonical base64url');
    out[o++] = ((a << 2) | (b >>> 4)) & 255;
  } else if (rem === 3) {
    const a = val(i), b = val(i + 1), c = val(i + 2);
    if (c & 0x03) throw new Error('non-canonical base64url');
    out[o++] = ((a << 2) | (b >>> 4)) & 255;
    out[o++] = ((b << 4) | (c >>> 2)) & 255;
  }
  return out;
}

/** @param {string} str @returns {Uint8Array} */
export function utf8Encode(str) {
  if (typeof str !== 'string') throw new TypeError('utf8Encode input must be a string');
  return textEncoder.encode(str);
}

/** Decode UTF-8, throwing on malformed input. @param {Uint8Array} bytes @returns {string} */
export function utf8Decode(bytes) {
  assertBytes(bytes, 'utf8Decode input');
  return textDecoder.decode(bytes);
}

/** Concatenate Uint8Arrays into a new Uint8Array. */
export function concatBytes(...arrays) {
  let total = 0;
  for (const a of arrays) {
    assertBytes(a, 'concatBytes argument');
    total += a.length;
  }
  const out = new Uint8Array(total);
  let off = 0;
  for (const a of arrays) {
    out.set(a, off);
    off += a.length;
  }
  return out;
}

/** 32-bit unsigned big-endian encoding. Throws if n is not an integer in [0, 2^32). */
export function u32be(n) {
  if (!Number.isInteger(n) || n < 0 || n > 0xffffffff) throw new RangeError('u32be: value out of range');
  const out = new Uint8Array(4);
  out[0] = (n >>> 24) & 255;
  out[1] = (n >>> 16) & 255;
  out[2] = (n >>> 8) & 255;
  out[3] = n & 255;
  return out;
}

/**
 * Compare two byte arrays in time independent of their contents (only the
 * length is allowed to leak). Returns false for non-Uint8Array input.
 */
export function constantTimeEqual(a, b) {
  if (!(a instanceof Uint8Array) || !(b instanceof Uint8Array)) return false;
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

/**
 * Overwrite a byte array with zeros. Best effort only: JS engines may have made
 * copies we cannot reach, but this shortens the lifetime of secrets we own.
 * Silently ignores anything that is not a typed array.
 */
export function zeroize(bytes) {
  if (ArrayBuffer.isView(bytes) && typeof bytes.fill === 'function') {
    try { bytes.fill(0); } catch { /* best effort */ }
  }
}
