// Sombra — cryptographic primitives over WebCrypto (SPEC §2.2).
//
// Isomorphic: only `globalThis.crypto` is used (browser and Node 26).
// All byte values are Uint8Array. Keypairs are { pub: Uint8Array(32), priv: Uint8Array(32) }
// where `priv` is the raw 32-byte X25519 scalar / Ed25519 seed.
//
// Every imported CryptoKey is created non-extractable and is never cached, so a
// key only lives in WebCrypto for the duration of one operation.

import { b64uEncode, b64uDecode, utf8Encode, concatBytes, zeroize } from './encoding.js';

const subtle = globalThis.crypto?.subtle;
if (!subtle) throw new Error('WebCrypto (crypto.subtle) is not available in this environment');

// DER prefix of a PKCS#8 PrivateKeyInfo for X25519 (OID 1.3.101.110) wrapping a
// 32-byte OCTET STRING. Used only by x25519() — see the note there.
const X25519_PKCS8_PREFIX = new Uint8Array([
  0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e, 0x04, 0x22, 0x04, 0x20,
]);

function assertBytes(x, what, len) {
  if (!(x instanceof Uint8Array)) throw new TypeError(`${what} must be a Uint8Array`);
  if (len !== undefined && x.length !== len) throw new RangeError(`${what} must be ${len} bytes`);
}

/** Cryptographically secure random bytes (synchronous). */
export function randomBytes(n) {
  if (!Number.isInteger(n) || n < 0) throw new RangeError('randomBytes: bad length');
  const out = new Uint8Array(n);
  // getRandomValues is limited to 65536 bytes per call.
  for (let off = 0; off < n; off += 65536) {
    globalThis.crypto.getRandomValues(out.subarray(off, Math.min(n, off + 65536)));
  }
  return out;
}

export async function sha256(data) {
  assertBytes(data, 'sha256 input');
  return new Uint8Array(await subtle.digest('SHA-256', data));
}

export async function sha512(data) {
  assertBytes(data, 'sha512 input');
  return new Uint8Array(await subtle.digest('SHA-512', data));
}

export async function hmacSha256(key, data) {
  assertBytes(key, 'hmac key');
  assertBytes(data, 'hmac data');
  if (key.length === 0) throw new RangeError('hmac key must not be empty');
  const k = await subtle.importKey('raw', key, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  return new Uint8Array(await subtle.sign('HMAC', k, data));
}

/**
 * HKDF-SHA256 (RFC 5869).
 * @param {Uint8Array} ikm
 * @param {Uint8Array} salt  may be empty (then treated as HashLen zero bytes by HKDF)
 * @param {Uint8Array|string} info  strings are UTF-8 encoded
 * @param {number} length  output bytes, 1..8160
 */
export async function hkdf(ikm, salt, info, length) {
  assertBytes(ikm, 'hkdf ikm');
  assertBytes(salt, 'hkdf salt');
  const infoBytes = typeof info === 'string' ? utf8Encode(info) : info;
  assertBytes(infoBytes, 'hkdf info');
  if (!Number.isInteger(length) || length < 1 || length > 255 * 32) throw new RangeError('hkdf: bad length');
  const k = await subtle.importKey('raw', ikm, 'HKDF', false, ['deriveBits']);
  const bits = await subtle.deriveBits({ name: 'HKDF', hash: 'SHA-256', salt, info: infoBytes }, k, length * 8);
  return new Uint8Array(bits);
}

async function importAesKey(key32, usage) {
  assertBytes(key32, 'AES key', 32);
  return subtle.importKey('raw', key32, { name: 'AES-GCM' }, false, [usage]);
}

/** AES-256-GCM encrypt; returns ciphertext || 16-byte tag. */
export async function aesGcmEncrypt(key32, iv12, plaintext, aad = new Uint8Array(0)) {
  assertBytes(iv12, 'AES-GCM iv', 12);
  assertBytes(plaintext, 'AES-GCM plaintext');
  assertBytes(aad, 'AES-GCM aad');
  const k = await importAesKey(key32, 'encrypt');
  const ct = await subtle.encrypt({ name: 'AES-GCM', iv: iv12, additionalData: aad, tagLength: 128 }, k, plaintext);
  return new Uint8Array(ct);
}

/** AES-256-GCM decrypt; throws Error('decryption failed') on any authentication failure. */
export async function aesGcmDecrypt(key32, iv12, ciphertext, aad = new Uint8Array(0)) {
  assertBytes(iv12, 'AES-GCM iv', 12);
  assertBytes(ciphertext, 'AES-GCM ciphertext');
  assertBytes(aad, 'AES-GCM aad');
  if (ciphertext.length < 16) throw new Error('decryption failed');
  const k = await importAesKey(key32, 'decrypt');
  try {
    const pt = await subtle.decrypt({ name: 'AES-GCM', iv: iv12, additionalData: aad, tagLength: 128 }, k, ciphertext);
    return new Uint8Array(pt);
  } catch {
    // Uniform error: never reveal why decryption failed.
    throw new Error('decryption failed');
  }
}

export async function pbkdf2Sha256(passwordBytes, salt, iterations, length = 32) {
  assertBytes(passwordBytes, 'pbkdf2 password');
  assertBytes(salt, 'pbkdf2 salt');
  if (!Number.isInteger(iterations) || iterations < 1) throw new RangeError('pbkdf2: bad iteration count');
  if (!Number.isInteger(length) || length < 1 || length > 1024) throw new RangeError('pbkdf2: bad length');
  const k = await subtle.importKey('raw', passwordBytes, 'PBKDF2', false, ['deriveBits']);
  const bits = await subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt, iterations }, k, length * 8);
  return new Uint8Array(bits);
}

async function generateOkp(name, usages) {
  const kp = await subtle.generateKey({ name }, true, usages);
  const jwk = await subtle.exportKey('jwk', kp.privateKey);
  const out = { pub: b64uDecode(jwk.x), priv: b64uDecode(jwk.d) };
  jwk.d = ''; // drop our reference to the encoded secret
  if (out.pub.length !== 32 || out.priv.length !== 32) throw new Error(`${name}: unexpected key size`);
  return out;
}

/** -> { pub: Uint8Array(32), priv: Uint8Array(32) } */
export async function generateX25519() {
  return generateOkp('X25519', ['deriveBits']);
}

/**
 * X25519 Diffie-Hellman. Throws if the shared secret is all zeros (peer sent a
 * low-order point) or on any malformed input.
 *
 * Note on import format: SPEC §2.2 says private keys are imported via JWK
 * {kty:'OKP',crv,x,d}. WebCrypto requires the public `x` member in an OKP
 * private JWK (RFC 8037), but this function's signature only receives the raw
 * private scalar. We therefore import X25519 private keys as PKCS#8, which
 * carries exactly the raw scalar and is supported by all WebCrypto
 * implementations that support X25519. Ed25519 signing (where the public key is
 * available) uses JWK as specified.
 */
export async function x25519(privBytes, pubBytes) {
  assertBytes(privBytes, 'X25519 private key', 32);
  assertBytes(pubBytes, 'X25519 public key', 32);
  const pkcs8 = concatBytes(X25519_PKCS8_PREFIX, privBytes);
  let shared;
  try {
    const priv = await subtle.importKey('pkcs8', pkcs8, { name: 'X25519' }, false, ['deriveBits']);
    const pub = await subtle.importKey('raw', pubBytes, { name: 'X25519' }, false, []);
    shared = new Uint8Array(await subtle.deriveBits({ name: 'X25519', public: pub }, priv, 256));
  } catch {
    // WebCrypto itself rejects all-zero outputs with OperationError on some
    // platforms; normalise every failure into one error.
    throw new Error('x25519 failed');
  } finally {
    zeroize(pkcs8);
  }
  let acc = 0;
  for (let i = 0; i < shared.length; i++) acc |= shared[i];
  if (acc === 0) throw new Error('x25519 failed');
  return shared;
}

/** -> { pub: Uint8Array(32), priv: Uint8Array(32) } (priv = 32-byte seed) */
export async function generateEd25519() {
  return generateOkp('Ed25519', ['sign', 'verify']);
}

/** Ed25519 signature (64 bytes) over `message` with keyPair {pub, priv}. */
export async function ed25519Sign(keyPair, message) {
  if (!keyPair || typeof keyPair !== 'object') throw new TypeError('ed25519Sign: keyPair required');
  assertBytes(keyPair.pub, 'Ed25519 public key', 32);
  assertBytes(keyPair.priv, 'Ed25519 private key', 32);
  assertBytes(message, 'Ed25519 message');
  const jwk = { kty: 'OKP', crv: 'Ed25519', x: b64uEncode(keyPair.pub), d: b64uEncode(keyPair.priv) };
  const k = await subtle.importKey('jwk', jwk, { name: 'Ed25519' }, false, ['sign']);
  jwk.d = '';
  return new Uint8Array(await subtle.sign({ name: 'Ed25519' }, k, message));
}

/** Ed25519 verification. Returns false on any problem; never throws. */
export async function ed25519Verify(pub, message, signature) {
  try {
    if (!(pub instanceof Uint8Array) || pub.length !== 32) return false;
    if (!(message instanceof Uint8Array)) return false;
    if (!(signature instanceof Uint8Array) || signature.length !== 64) return false;
    const k = await subtle.importKey('raw', pub, { name: 'Ed25519' }, false, ['verify']);
    return (await subtle.verify({ name: 'Ed25519' }, k, signature, message)) === true;
  } catch {
    return false;
  }
}
