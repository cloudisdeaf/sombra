// Sombra — length-hiding padding (SPEC §2.6).
//
// padded = u32be(len) || bytes || zeros, total length rounded up to a bucket:
// 256, 512, 1024, ..., 16384, then the next power of two up to 1 MiB, then the
// next multiple of 1 MiB. This hides the exact size of messages and files from
// anyone who sees ciphertexts (the server, the network).

import { u32be } from './encoding.js';

const MIN_BUCKET = 256;
const MiB = 1024 * 1024;

/** Smallest bucket size >= n (n = 4 + payload length). */
export function bucketSize(n) {
  if (!Number.isInteger(n) || n < 0) throw new RangeError('bad length');
  if (n <= MIN_BUCKET) return MIN_BUCKET;
  if (n <= MiB) {
    let b = MIN_BUCKET;
    while (b < n) b *= 2;
    return b;
  }
  return Math.ceil(n / MiB) * MiB;
}

/** Pad bytes into a bucket-sized buffer. */
export function pad(bytes) {
  if (!(bytes instanceof Uint8Array)) throw new TypeError('pad input must be a Uint8Array');
  if (bytes.length > 0xffffffff - 4) throw new RangeError('pad input too large');
  const out = new Uint8Array(bucketSize(bytes.length + 4)); // zero-filled
  out.set(u32be(bytes.length), 0);
  out.set(bytes, 4);
  return out;
}

/**
 * Remove padding. Strict: throws if the buffer is not exactly the bucket size
 * for the declared length, if the length field exceeds the buffer, or if the
 * padding bytes are not all zero. (Input is normally authenticated already;
 * strictness just guarantees a single valid encoding.)
 * @returns {Uint8Array} a copy of the payload
 */
export function unpad(bytes) {
  if (!(bytes instanceof Uint8Array)) throw new TypeError('unpad input must be a Uint8Array');
  if (bytes.length < MIN_BUCKET) throw new Error('invalid padding');
  const len = ((bytes[0] << 24) | (bytes[1] << 16) | (bytes[2] << 8) | bytes[3]) >>> 0;
  if (len > bytes.length - 4) throw new Error('invalid padding');
  if (bucketSize(len + 4) !== bytes.length) throw new Error('invalid padding');
  let nz = 0;
  for (let i = 4 + len; i < bytes.length; i++) nz |= bytes[i];
  if (nz !== 0) throw new Error('invalid padding');
  return bytes.slice(4, 4 + len);
}
