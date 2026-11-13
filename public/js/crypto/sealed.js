// Sombra — sealed sender envelope (SPEC §2.7).
//
// The envelope hides the sender's username from the server: only the recipient
// (holder of the identity DH private key) can open it. The sealed layer does NOT
// authenticate the sender by itself; authentication comes from the inner ratchet
// layer, whose AD binds both parties' identity keys (SPEC §5.3).
//
// blob = 0x01 || eph.pub(32) || AES-256-GCM(key, iv, pad(utf8(JSON{from, inner})), aad = 0x01 || eph.pub || recipientIkDh)

import { b64uEncode, b64uDecode, utf8Encode, utf8Decode, concatBytes, zeroize } from './encoding.js';
import { hkdf, aesGcmEncrypt, aesGcmDecrypt, generateX25519, x25519 } from './primitives.js';
import { pad, unpad } from './padding.js';

const VERSION = 0x01;
const SEALED_INFO = 'SOMBRA-SEALED-v1';
// version(1) + eph(32) + smallest padded plaintext (256) + GCM tag (16)
const MIN_BLOB = 1 + 32 + 256 + 16;

async function deriveKeyIv(shared, ephPub, recipientPub) {
  const okm = await hkdf(shared, concatBytes(ephPub, recipientPub), SEALED_INFO, 44);
  const out = { key: okm.slice(0, 32), iv: okm.slice(32, 44) };
  zeroize(okm);
  return out;
}

/**
 * @param {string} senderUsername
 * @param {Uint8Array} recipientIkDhPub  recipient's X25519 identity public key
 * @param {Uint8Array} innerBytes
 * @returns {Promise<Uint8Array>} blob
 */
export async function seal(senderUsername, recipientIkDhPub, innerBytes) {
  if (typeof senderUsername !== 'string' || senderUsername.length === 0) throw new TypeError('bad sender');
  if (!(recipientIkDhPub instanceof Uint8Array) || recipientIkDhPub.length !== 32) {
    throw new TypeError('recipient key must be 32 bytes');
  }
  if (!(innerBytes instanceof Uint8Array)) throw new TypeError('inner must be a Uint8Array');

  const eph = await generateX25519();
  let key;
  try {
    const shared = await x25519(eph.priv, recipientIkDhPub);
    const kiv = await deriveKeyIv(shared, eph.pub, recipientIkDhPub);
    zeroize(shared);
    key = kiv.key;
    const pt = pad(utf8Encode(JSON.stringify({ from: senderUsername, inner: b64uEncode(innerBytes) })));
    const aad = concatBytes(new Uint8Array([VERSION]), eph.pub, recipientIkDhPub);
    const ct = await aesGcmEncrypt(key, kiv.iv, pt, aad);
    zeroize(pt);
    return concatBytes(new Uint8Array([VERSION]), eph.pub, ct);
  } finally {
    zeroize(eph.priv);
    if (key) zeroize(key);
  }
}

/**
 * @param {{pub: Uint8Array, priv: Uint8Array}} recipientDhKeyPair  own identity DH keypair
 * @param {Uint8Array} blob
 * @returns {Promise<{from: string, inner: Uint8Array}>}  throws Error('unseal failed') on any failure
 */
export async function unseal(recipientDhKeyPair, blob) {
  // A single generic error for every failure mode: no oracle on what went wrong.
  const fail = () => new Error('unseal failed');
  if (!(blob instanceof Uint8Array) || blob.length < MIN_BLOB || blob[0] !== VERSION) throw fail();
  const kp = recipientDhKeyPair;
  if (!kp || !(kp.pub instanceof Uint8Array) || kp.pub.length !== 32 ||
      !(kp.priv instanceof Uint8Array) || kp.priv.length !== 32) {
    throw new TypeError('bad recipient keypair');
  }
  const ephPub = blob.slice(1, 33);
  const ct = blob.subarray(33);
  let key;
  try {
    const shared = await x25519(kp.priv, ephPub);
    const kiv = await deriveKeyIv(shared, ephPub, kp.pub);
    zeroize(shared);
    key = kiv.key;
    const aad = concatBytes(new Uint8Array([VERSION]), ephPub, kp.pub);
    const pt = await aesGcmDecrypt(key, kiv.iv, ct, aad);
    const obj = JSON.parse(utf8Decode(unpad(pt)));
    zeroize(pt);
    if (!obj || typeof obj !== 'object' || typeof obj.from !== 'string' || obj.from.length === 0 ||
        typeof obj.inner !== 'string') {
      throw fail();
    }
    return { from: obj.from, inner: b64uDecode(obj.inner) };
  } catch {
    throw fail();
  } finally {
    if (key) zeroize(key);
  }
}
