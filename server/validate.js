// Strict input validation helpers (SPEC §3.4).
//
// Every helper throws a ValidationError on bad input; the HTTP / WS layers map that
// to 400 {error:"bad_request"} (or a WS error frame). Unknown fields are ignored by
// simply never reading them.

import { createPublicKey, verify as cryptoVerify } from 'node:crypto';

export class ValidationError extends Error {
  constructor(code = 'bad_request') {
    super(code);
    this.code = code;
  }
}

const USERNAME_RE = /^[a-z0-9_]{3,32}$/;
const B64U_RE = /^[A-Za-z0-9_-]*$/;

export function isUsername(v) {
  return typeof v === 'string' && USERNAME_RE.test(v);
}

export function assertUsername(v) {
  if (!isUsername(v)) throw new ValidationError();
  return v;
}

/**
 * CRYPTO-6 / CL-6: names that collide with Object.prototype members in JS clients
 * ('__proto__', 'constructor') — and 'prototype' for good measure. They match the
 * username syntax but can never be registered. Lookups of such names simply 404.
 */
export const RESERVED_USERNAMES = Object.freeze(new Set(['__proto__', 'constructor', 'prototype']));

/** A username that may be registered (syntax + not reserved). */
export function assertNewUsername(v) {
  assertUsername(v);
  if (RESERVED_USERNAMES.has(v)) throw new ValidationError();
  return v;
}

export function isPlainObject(v) {
  return v !== null && typeof v === 'object' && !Array.isArray(v);
}

export function assertObject(v) {
  if (!isPlainObject(v)) throw new ValidationError();
  return v;
}

/**
 * Strict base64url (no padding) decode. Rejects padding, foreign characters, impossible
 * lengths and non-canonical encodings (non-zero trailing bits), so each byte string has
 * exactly one accepted textual form.
 * @param {unknown} str
 * @param {number} [maxBytes] reject before decoding if the result would exceed this
 * @returns {Buffer}
 */
export function b64uDecodeStrict(str, maxBytes = Infinity) {
  if (typeof str !== 'string') throw new ValidationError();
  if (str.length % 4 === 1) throw new ValidationError();
  if (Math.floor((str.length * 3) / 4) > maxBytes) throw new ValidationError();
  if (!B64U_RE.test(str)) throw new ValidationError();
  const buf = Buffer.from(str, 'base64url');
  if (buf.toString('base64url') !== str) throw new ValidationError();
  return buf;
}

/** Encode a Uint8Array/Buffer as base64url without padding (zero-copy view). */
export function b64uEncode(bytes) {
  return Buffer.from(bytes.buffer, bytes.byteOffset, bytes.byteLength).toString('base64url');
}

/** Decode a b64u string that must be exactly `len` bytes. */
export function decodeFixed(str, len) {
  const buf = b64uDecodeStrict(str, len);
  if (buf.length !== len) throw new ValidationError();
  return buf;
}

/** 32-byte public key (Ed25519 or X25519). All-zero keys are rejected outright. */
export function decodeKey(str) {
  const buf = decodeFixed(str, 32);
  if (buf.every((b) => b === 0)) throw new ValidationError();
  return buf;
}

/** 64-byte Ed25519 signature. */
export function decodeSig(str) {
  return decodeFixed(str, 64);
}

/** Prekey id: integer in 0..2^32-1. */
export function isPrekeyId(v) {
  return Number.isInteger(v) && v >= 0 && v <= 0xffffffff;
}

export function assertPrekeyId(v) {
  if (!isPrekeyId(v)) throw new ValidationError();
  return v;
}

/** Validate `{id, pub, sig}` → `{id, pub:Buffer, sig:Buffer}`. */
export function parseSignedPrekey(v) {
  assertObject(v);
  return { id: assertPrekeyId(v.id), pub: decodeKey(v.pub), sig: decodeSig(v.sig) };
}

/**
 * Validate a list of `{id, pub}` one-time prekeys (1..max, unique ids).
 * @returns {{id:number, pub:Buffer}[]}
 */
export function parseOpkList(v, max) {
  if (!Array.isArray(v) || v.length < 1 || v.length > max) throw new ValidationError();
  const seen = new Set();
  return v.map((o) => {
    assertObject(o);
    const id = assertPrekeyId(o.id);
    if (seen.has(id)) throw new ValidationError();
    seen.add(id);
    return { id, pub: decodeKey(o.pub) };
  });
}

/** PoW solution `{challenge, nonce}` — shape only; pow.js does the real verification. */
export function parsePow(v) {
  assertObject(v);
  if (typeof v.challenge !== 'string' || v.challenge.length < 1 || v.challenge.length > 128) {
    throw new ValidationError();
  }
  if (typeof v.nonce !== 'string' || !/^[0-9]{1,20}$/.test(v.nonce)) throw new ValidationError();
  return { challenge: v.challenge, nonce: v.nonce };
}

/** u32 big-endian encoding. */
export function u32be(n) {
  const b = Buffer.alloc(4);
  b.writeUInt32BE(n >>> 0, 0);
  return b;
}

// DER SubjectPublicKeyInfo prefix for a raw 32-byte Ed25519 public key (RFC 8410).
const ED25519_SPKI_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');

/**
 * Verify an Ed25519 signature using node:crypto. Never throws.
 * @param {Uint8Array} pub 32-byte raw public key
 * @param {Uint8Array} message
 * @param {Uint8Array} sig 64-byte signature
 */
export function ed25519Verify(pub, message, sig) {
  try {
    if (pub.length !== 32 || sig.length !== 64) return false;
    const key = createPublicKey({
      key: Buffer.concat([ED25519_SPKI_PREFIX, Buffer.from(pub)]),
      format: 'der',
      type: 'spki',
    });
    return cryptoVerify(null, Buffer.from(message), key, Buffer.from(sig));
  } catch {
    return false;
  }
}

// Domain-separation labels (SPEC §2.3, §3.7).
const LABEL_IKDH = Buffer.from('SOMBRA-IKDH-v1', 'utf8');
const LABEL_SPK = Buffer.from('SOMBRA-SPK-v1', 'utf8');
const LABEL_AUTH = Buffer.from('SOMBRA-AUTH-v1', 'utf8');

/** ik_dh_sig = Ed25519Sign(sig, utf8("SOMBRA-IKDH-v1") || ik_dh) */
export function verifyIkDhSig(ikSig, ikDh, ikDhSig) {
  return ed25519Verify(ikSig, Buffer.concat([LABEL_IKDH, ikDh]), ikDhSig);
}

/** spk.sig = Ed25519Sign(IK_sig, utf8("SOMBRA-SPK-v1") || u32be(id) || spk_pub) */
export function verifySpkSig(ikSig, spk) {
  return ed25519Verify(ikSig, Buffer.concat([LABEL_SPK, u32be(spk.id), spk.pub]), spk.sig);
}

/** WS auth: sig = Ed25519(IK_sig, utf8("SOMBRA-AUTH-v1") || nonce) */
export function verifyAuthSig(ikSig, nonce, sig) {
  return ed25519Verify(ikSig, Buffer.concat([LABEL_AUTH, nonce]), sig);
}

const LABEL_REG = Buffer.from('SOMBRA-REG-v1', 'utf8');

/**
 * CRYPTO-7: registration proof of possession, bound to the username:
 * reg_sig = Ed25519(IK_sig, utf8("SOMBRA-REG-v1") || u8(len(username)) || utf8(username) || ik_dh)
 * Copying someone else's public identity (and its signatures) no longer registers.
 */
export function verifyRegSig(ikSig, username, ikDh, regSig) {
  const name = Buffer.from(username, 'utf8');
  if (name.length > 255) return false;
  return ed25519Verify(ikSig, Buffer.concat([LABEL_REG, Buffer.from([name.length]), name, ikDh]), regSig);
}
