// Sombra — local encryption at rest (SPEC §2.9).
//
// A passphrase is stretched with PBKDF2-SHA256 (600 000 iterations) into a
// master key, from which two independent subkeys are derived with HKDF:
//   encKey — AES-256-GCM encryption of every stored record
//   macKey — HMAC of record names, so the storage backend never sees names
// The vault metadata ({v, salt, iter, verifier}) is the only thing stored in
// clear; the verifier lets us reject a wrong passphrase without touching data.

import { b64uEncode, b64uDecode, utf8Encode, utf8Decode, concatBytes, zeroize } from './encoding.js';
import { randomBytes, hkdf, hmacSha256, aesGcmEncrypt, aesGcmDecrypt, pbkdf2Sha256 } from './primitives.js';

export const PBKDF2_ITERATIONS = 600000;

const ENC_INFO = 'SOMBRA-VAULT-ENC-v1';
const MAC_INFO = 'SOMBRA-VAULT-MAC-v1';
const VERIFIER_PT = 'SOMBRA-VAULT-OK';
const VERIFIER_AAD = utf8Encode('verifier');
// Upper bound on accepted iteration counts so tampered metadata cannot make
// unlocking hang forever.
const MAX_ITERATIONS = 10_000_000;

function checkIterations(iter) {
  if (!Number.isInteger(iter) || iter < 1 || iter > MAX_ITERATIONS) throw new Error('bad vault iteration count');
}

function checkPassphrase(passphrase) {
  if (typeof passphrase !== 'string' || passphrase.length === 0) throw new TypeError('passphrase must be a non-empty string');
}

async function deriveKeys(passphrase, salt, iter) {
  const pw = utf8Encode(passphrase);
  const master = await pbkdf2Sha256(pw, salt, iter, 32);
  zeroize(pw);
  try {
    const encKey = await hkdf(master, salt, ENC_INFO, 32);
    const macKey = await hkdf(master, salt, MAC_INFO, 32);
    return { encKey, macKey };
  } finally {
    zeroize(master);
  }
}

/** b64u(iv12 || AES-GCM(key, iv, pt, aad)) */
async function sealBytes(key, pt, aad) {
  const iv = randomBytes(12);
  return b64uEncode(concatBytes(iv, await aesGcmEncrypt(key, iv, pt, aad)));
}

async function openBytes(key, str, aad) {
  const raw = b64uDecode(str);
  if (raw.length < 12 + 16) throw new Error('decryption failed');
  return aesGcmDecrypt(key, raw.subarray(0, 12), raw.subarray(12), aad);
}

/**
 * Create a new vault.
 * @param {string} passphrase
 * @param {{iterations?: number}} [options]  iterations override — intended for tests only;
 *        production callers must use the default PBKDF2_ITERATIONS.
 * @returns {Promise<{meta: {v, salt, iter, verifier}, keys: {encKey, macKey}}>}
 */
export async function createVault(passphrase, { iterations = PBKDF2_ITERATIONS } = {}) {
  checkPassphrase(passphrase);
  checkIterations(iterations);
  const salt = randomBytes(16);
  const keys = await deriveKeys(passphrase, salt, iterations);
  const verifier = await sealBytes(keys.encKey, utf8Encode(VERIFIER_PT), VERIFIER_AAD);
  return { meta: { v: 1, salt: b64uEncode(salt), iter: iterations, verifier }, keys };
}

/** Derive keys from passphrase + meta; throws Error('bad passphrase') if wrong. */
export async function unlockVault(passphrase, meta) {
  checkPassphrase(passphrase);
  if (!meta || typeof meta !== 'object' || meta.v !== 1 || typeof meta.verifier !== 'string') {
    throw new Error('bad vault metadata');
  }
  checkIterations(meta.iter);
  const salt = b64uDecode(meta.salt);
  if (salt.length !== 16) throw new Error('bad vault metadata');
  const keys = await deriveKeys(passphrase, salt, meta.iter);
  try {
    const pt = await openBytes(keys.encKey, meta.verifier, VERIFIER_AAD);
    if (utf8Decode(pt) !== VERIFIER_PT) throw new Error('mismatch');
  } catch {
    zeroize(keys.encKey);
    zeroize(keys.macKey);
    throw new Error('bad passphrase');
  }
  return keys;
}

/** Encrypt a JSON-serialisable object bound to its record name (AAD). */
export async function encryptRecord(keys, name, obj) {
  if (typeof name !== 'string') throw new TypeError('record name must be a string');
  const json = JSON.stringify(obj);
  if (json === undefined) throw new TypeError('record is not JSON-serialisable');
  const pt = utf8Encode(json);
  try {
    return await sealBytes(keys.encKey, pt, utf8Encode(name));
  } finally {
    zeroize(pt);
  }
}

/** Decrypt a record; throws if the key, name (AAD) or ciphertext don't match. */
export async function decryptRecord(keys, name, str) {
  if (typeof name !== 'string') throw new TypeError('record name must be a string');
  if (typeof str !== 'string') throw new TypeError('record must be a string');
  const pt = await openBytes(keys.encKey, str, utf8Encode(name));
  try {
    return JSON.parse(utf8Decode(pt));
  } finally {
    zeroize(pt);
  }
}

/** Opaque storage key for a record name: b64u(HMAC(macKey, utf8(name))). */
export async function recordKey(keys, name) {
  if (typeof name !== 'string') throw new TypeError('record name must be a string');
  return b64uEncode(await hmacSha256(keys.macKey, utf8Encode(name)));
}
