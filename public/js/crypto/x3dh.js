// Sombra — identity keys, prekeys and X3DH key agreement (SPEC §2.3, §2.4).
//
// Based on the Signal X3DH specification, with an explicit Ed25519 identity
// signing key plus a separate X25519 identity DH key whose binding is proven by
// `ik_dh_sig`.

import { b64uEncode, b64uDecode, utf8Encode, concatBytes, u32be, zeroize } from './encoding.js';
import {
  hkdf, generateX25519, x25519, generateEd25519, ed25519Sign, ed25519Verify,
} from './primitives.js';

const IKDH_LABEL = utf8Encode('SOMBRA-IKDH-v1');
const SPK_LABEL = utf8Encode('SOMBRA-SPK-v1');
const AD_LABEL = utf8Encode('SOMBRA-AD-v1');
// CRYPTO-7 (unknown-key-share): with `names` the AD also binds both usernames.
// SPEC change (§2.4), opt-in per call; both peers must use it, and a receiver
// must NOT fall back to v1 (that would re-open the UKS by downgrade):
// AD = utf8("SOMBRA-AD-v2") || IKa_sig || IKa_dh || IKb_sig || IKb_dh
//      || u8(len) || utf8(usernameA) || u8(len) || utf8(usernameB)
const AD_LABEL_V2 = utf8Encode('SOMBRA-AD-v2');
const X3DH_INFO = 'SOMBRA-X3DH-v1';

/** Decode a b64u value that must be exactly `len` bytes; throws otherwise. */
function decodeFixed(str, len, what) {
  const b = b64uDecode(str);
  if (b.length !== len) throw new Error(`${what}: expected ${len} bytes`);
  return b;
}

function isUint32(n) {
  return Number.isInteger(n) && n >= 0 && n <= 0xffffffff;
}

// ---------------------------------------------------------------------------
// Key (de)serialisation helpers (extra exports, not in SPEC — convenience for
// the storage layer; format follows SPEC §2.2 "{ pub: b64u, priv: b64u }").
// ---------------------------------------------------------------------------

/** { pub: Uint8Array, priv: Uint8Array } -> { pub: b64u, priv: b64u } */
export function serializeKeyPair(kp) {
  return { pub: b64uEncode(kp.pub), priv: b64uEncode(kp.priv) };
}

/** { pub: b64u, priv: b64u } -> { pub: Uint8Array(32), priv: Uint8Array(32) } */
export function deserializeKeyPair(obj) {
  if (!obj || typeof obj !== 'object') throw new TypeError('bad serialised keypair');
  return { pub: decodeFixed(obj.pub, 32, 'keypair pub'), priv: decodeFixed(obj.priv, 32, 'keypair priv') };
}

/** {sig, dh} -> {sig: {pub,priv} b64u, dh: {pub,priv} b64u} */
export function serializeIdentity(identity) {
  return { sig: serializeKeyPair(identity.sig), dh: serializeKeyPair(identity.dh) };
}

export function deserializeIdentity(obj) {
  if (!obj || typeof obj !== 'object') throw new TypeError('bad serialised identity');
  return { sig: deserializeKeyPair(obj.sig), dh: deserializeKeyPair(obj.dh) };
}

// ---------------------------------------------------------------------------
// Identity and prekeys (SPEC §2.3)
// ---------------------------------------------------------------------------

/** -> { sig: Ed25519 keypair, dh: X25519 keypair } */
export async function generateIdentity() {
  const [sig, dh] = await Promise.all([generateEd25519(), generateX25519()]);
  return { sig, dh };
}

/** -> { ik_sig, ik_dh, ik_dh_sig } as b64u strings */
export async function publicIdentity(identity) {
  const sig = await ed25519Sign(identity.sig, concatBytes(IKDH_LABEL, identity.dh.pub));
  return {
    ik_sig: b64uEncode(identity.sig.pub),
    ik_dh: b64uEncode(identity.dh.pub),
    ik_dh_sig: b64uEncode(sig),
  };
}

/** Checks that ik_dh is signed by ik_sig. Never throws. */
export async function verifyPublicIdentity(pubId) {
  try {
    if (!pubId || typeof pubId !== 'object') return false;
    const ikSig = decodeFixed(pubId.ik_sig, 32, 'ik_sig');
    const ikDh = decodeFixed(pubId.ik_dh, 32, 'ik_dh');
    const sig = decodeFixed(pubId.ik_dh_sig, 64, 'ik_dh_sig');
    return await ed25519Verify(ikSig, concatBytes(IKDH_LABEL, ikDh), sig);
  } catch {
    return false;
  }
}

/** -> { id, keyPair: {pub,priv}, pub: b64u, sig: b64u } */
export async function generateSignedPrekey(identity, id) {
  if (!isUint32(id)) throw new RangeError('prekey id must be a uint32');
  const keyPair = await generateX25519();
  const sig = await ed25519Sign(identity.sig, concatBytes(SPK_LABEL, u32be(id), keyPair.pub));
  return { id, keyPair, pub: b64uEncode(keyPair.pub), sig: b64uEncode(sig) };
}

/** Verify spk = {id, pub, sig} (b64u) against identity signing key ik_sig (b64u). Never throws. */
export async function verifySignedPrekey(ik_sig_b64u, spk) {
  try {
    if (!spk || typeof spk !== 'object' || !isUint32(spk.id)) return false;
    const ikSig = decodeFixed(ik_sig_b64u, 32, 'ik_sig');
    const pub = decodeFixed(spk.pub, 32, 'spk pub');
    const sig = decodeFixed(spk.sig, 64, 'spk sig');
    return await ed25519Verify(ikSig, concatBytes(SPK_LABEL, u32be(spk.id), pub), sig);
  } catch {
    return false;
  }
}

/** -> [{ id, keyPair, pub: b64u }] with ids startId .. startId+count-1 */
export async function generateOneTimePrekeys(startId, count) {
  if (!isUint32(startId)) throw new RangeError('startId must be a uint32');
  if (!Number.isInteger(count) || count < 0 || startId + count - 1 > 0xffffffff) {
    throw new RangeError('bad prekey count');
  }
  const out = [];
  for (let i = 0; i < count; i++) {
    const keyPair = await generateX25519();
    out.push({ id: startId + i, keyPair, pub: b64uEncode(keyPair.pub) });
  }
  return out;
}

// ---------------------------------------------------------------------------
// X3DH (SPEC §2.4)
// ---------------------------------------------------------------------------

async function deriveSk(dhs) {
  const ikm = concatBytes(new Uint8Array(32).fill(0xff), ...dhs);
  try {
    return await hkdf(ikm, new Uint8Array(32), X3DH_INFO, 32);
  } finally {
    zeroize(ikm);
    for (const d of dhs) zeroize(d);
  }
}

/** Validate the optional { initiator, responder } username binding. */
function checkNames(names) {
  if (names === undefined) return undefined; // legacy v1 AD
  if (!names || typeof names !== 'object') throw new TypeError('names must be { initiator, responder }');
  const out = {};
  for (const role of ['initiator', 'responder']) {
    const v = names[role];
    if (typeof v !== 'string' || v.length === 0) throw new TypeError(`names.${role} must be a non-empty string`);
    const bytes = utf8Encode(v);
    if (bytes.length > 255) throw new RangeError(`names.${role} too long`);
    out[role] = bytes;
  }
  return out;
}

function buildAd(aSig, aDh, bSig, bDh, names) {
  if (!names) return concatBytes(AD_LABEL, aSig, aDh, bSig, bDh);
  return concatBytes(AD_LABEL_V2, aSig, aDh, bSig, bDh,
    Uint8Array.of(names.initiator.length), names.initiator,
    Uint8Array.of(names.responder.length), names.responder);
}

/**
 * Initiator side (Alice) of X3DH against a prekey bundle (b64u strings):
 * { username, ik_sig, ik_dh, ik_dh_sig, spk:{id,pub,sig}, opk:{id,pub}|null }
 * names (optional, CRYPTO-7): { initiator: ownUsername, responder: bundle.username }
 * -> { sk, ad, ek: b64u, spk_id, opk_id: number|null, spkPub: Uint8Array }
 */
export async function x3dhInitiate(identity, bundle, names) {
  if (!bundle || typeof bundle !== 'object' || !bundle.spk || typeof bundle.spk !== 'object') {
    throw new Error('bad bundle');
  }
  const nameBytes = checkNames(names);
  if (nameBytes && bundle.username !== names.responder) throw new Error('bad bundle');
  const okIdentity = await verifyPublicIdentity(bundle);
  const okSpk = okIdentity && await verifySignedPrekey(bundle.ik_sig, bundle.spk);
  if (!okIdentity || !okSpk) throw new Error('bad bundle signature');

  const ikbSig = decodeFixed(bundle.ik_sig, 32, 'ik_sig');
  const ikbDh = decodeFixed(bundle.ik_dh, 32, 'ik_dh');
  const spkPub = decodeFixed(bundle.spk.pub, 32, 'spk pub');
  let opkPub = null;
  let opkId = null;
  if (bundle.opk !== null && bundle.opk !== undefined) {
    if (typeof bundle.opk !== 'object' || !isUint32(bundle.opk.id)) throw new Error('bad bundle');
    opkPub = decodeFixed(bundle.opk.pub, 32, 'opk pub');
    opkId = bundle.opk.id;
  }

  const ek = await generateX25519();
  try {
    const dhs = [
      await x25519(identity.dh.priv, spkPub), // DH1 = DH(IKa, SPKb)
      await x25519(ek.priv, ikbDh),           // DH2 = DH(EKa, IKb)
      await x25519(ek.priv, spkPub),          // DH3 = DH(EKa, SPKb)
    ];
    if (opkPub) dhs.push(await x25519(ek.priv, opkPub)); // DH4 = DH(EKa, OPKb)
    const sk = await deriveSk(dhs);
    const ad = buildAd(identity.sig.pub, identity.dh.pub, ikbSig, ikbDh, nameBytes);
    return { sk, ad, ek: b64uEncode(ek.pub), spk_id: bundle.spk.id, opk_id: opkId, spkPub };
  } finally {
    zeroize(ek.priv); // the ephemeral private key is never needed again
  }
}

/**
 * Responder side (Bob).
 * @param identity        own identity {sig, dh}
 * @param spkKeyPair      own SPK keypair used by the initiator
 * @param opkKeyPair      own OPK keypair, or null if the initiator used none
 * @param initiatorPub    { ik_sig, ik_dh } b64u (caller must already have verified ik_dh_sig)
 * @param ekB64u          initiator's ephemeral public key (b64u)
 * @param names           optional (CRYPTO-7): { initiator: sealed `from`, responder: ownUsername }
 * -> { sk, ad }  (AD bytes identical to the initiator's)
 */
export async function x3dhRespond(identity, spkKeyPair, opkKeyPair, initiatorPub, ekB64u, names) {
  if (!initiatorPub || typeof initiatorPub !== 'object') throw new Error('bad initiator identity');
  const nameBytes = checkNames(names);
  const ikaSig = decodeFixed(initiatorPub.ik_sig, 32, 'ik_sig');
  const ikaDh = decodeFixed(initiatorPub.ik_dh, 32, 'ik_dh');
  const ek = decodeFixed(ekB64u, 32, 'ek');
  const dhs = [
    await x25519(spkKeyPair.priv, ikaDh),    // DH1
    await x25519(identity.dh.priv, ek),      // DH2
    await x25519(spkKeyPair.priv, ek),       // DH3
  ];
  if (opkKeyPair) dhs.push(await x25519(opkKeyPair.priv, ek)); // DH4
  const sk = await deriveSk(dhs);
  const ad = buildAd(ikaSig, ikaDh, identity.sig.pub, identity.dh.pub, nameBytes);
  return { sk, ad };
}
