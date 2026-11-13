// Sombra — safety numbers for out-of-band identity verification (SPEC §2.8).
//
// Per party:
//   fp = utf8("SOMBRA-FP-v1") || ik_sig || ik_dh || utf8(username)
//   h  = SHA-512(fp); then 5200 times: h = SHA-512(h || ik_sig || ik_dh)
//   first 30 bytes -> 6 chunks of 5 bytes -> big-endian 40-bit int mod 100000,
//   zero-padded to 5 digits -> 30 digits.
// Safety number = both 30-digit strings sorted lexicographically and
// concatenated (60 digits), so both parties compute the same value.

import { b64uDecode, utf8Encode, concatBytes } from './encoding.js';
import { sha512 } from './primitives.js';

const FP_LABEL = utf8Encode('SOMBRA-FP-v1');
const ITERATIONS = 5200;

function decode32(str, what) {
  const b = b64uDecode(str);
  if (b.length !== 32) throw new Error(`${what}: expected 32 bytes`);
  return b;
}

async function partyDigits(username, pub) {
  if (typeof username !== 'string' || username.length === 0) throw new TypeError('bad username');
  if (!pub || typeof pub !== 'object') throw new TypeError('bad public identity');
  const ikSig = decode32(pub.ik_sig, 'ik_sig');
  const ikDh = decode32(pub.ik_dh, 'ik_dh');
  const keys = concatBytes(ikSig, ikDh);
  let h = await sha512(concatBytes(FP_LABEL, keys, utf8Encode(username)));
  const buf = new Uint8Array(64 + keys.length);
  buf.set(keys, 64);
  for (let i = 0; i < ITERATIONS; i++) {
    buf.set(h, 0);
    h = await sha512(buf);
  }
  let out = '';
  for (let c = 0; c < 6; c++) {
    // 40-bit big-endian integer: exact in a JS Number (< 2^53).
    let v = 0;
    for (let j = 0; j < 5; j++) v = v * 256 + h[c * 5 + j];
    out += String(v % 100000).padStart(5, '0');
  }
  return out;
}

/**
 * @returns {Promise<string>} 60 digits, no spaces
 */
export async function safetyNumber(localUsername, localPub, remoteUsername, remotePub) {
  const [a, b] = await Promise.all([
    partyDigits(localUsername, localPub),
    partyDigits(remoteUsername, remotePub),
  ]);
  return a < b ? a + b : b + a;
}

/** "123456789..." -> "12345 67890 ..." (groups of 5 separated by single spaces). */
export function formatSafetyNumber(str) {
  if (typeof str !== 'string') throw new TypeError('safety number must be a string');
  return (str.match(/.{1,5}/g) || []).join(' ');
}
