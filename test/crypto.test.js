// Tests for the Sombra client crypto library (everything except the ratchet,
// which lives in ratchet.test.js). Run: node --test test/crypto.test.js
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import nodeCrypto from 'node:crypto';

import {
  b64uEncode, b64uDecode, utf8Encode, utf8Decode, concatBytes, u32be, constantTimeEqual, zeroize,
} from '../public/js/crypto/encoding.js';
import {
  randomBytes, sha256, sha512, hmacSha256, hkdf, aesGcmEncrypt, aesGcmDecrypt, pbkdf2Sha256,
  generateX25519, x25519, generateEd25519, ed25519Sign, ed25519Verify,
} from '../public/js/crypto/primitives.js';
import {
  generateIdentity, publicIdentity, verifyPublicIdentity, generateSignedPrekey, verifySignedPrekey,
  generateOneTimePrekeys, x3dhInitiate, x3dhRespond, serializeIdentity, deserializeIdentity,
} from '../public/js/crypto/x3dh.js';
import { pad, unpad } from '../public/js/crypto/padding.js';
import { seal, unseal } from '../public/js/crypto/sealed.js';
import { safetyNumber, formatSafetyNumber } from '../public/js/crypto/safety.js';
import {
  PBKDF2_ITERATIONS, createVault, unlockVault, encryptRecord, decryptRecord, recordKey,
} from '../public/js/crypto/vault.js';
import { leadingZeroBits, solvePow, verifyPowSync, sha256Sync } from '../public/js/crypto/pow.js';

const hex = (h) => Uint8Array.from(Buffer.from(h.replace(/\s+/g, ''), 'hex'));
const toHex = (b) => Buffer.from(b).toString('hex');
const TEST_ITER = 1000; // reduced PBKDF2 cost for tests only

// ---------------------------------------------------------------------------
describe('encoding', () => {
  test('b64u round trip for all lengths 0..70 and matches Buffer base64url', () => {
    for (let n = 0; n <= 70; n++) {
      const b = randomBytes(n);
      const s = b64uEncode(b);
      assert.equal(s, Buffer.from(b).toString('base64url'));
      assert.match(s, /^[A-Za-z0-9_-]*$/);
      assert.deepEqual(b64uDecode(s), b);
    }
  });

  test('b64uDecode rejects invalid input', () => {
    for (const bad of ['A', 'AAAAA', 'AA==', 'AA=', 'A+B/', 'ab cd', 'ab\n', 'é', 'AB', 'AAB']) {
      // 'AB' and 'AAB' have non-zero unused trailing bits -> non-canonical
      assert.throws(() => b64uDecode(bad), undefined, `should reject ${JSON.stringify(bad)}`);
    }
    assert.throws(() => b64uDecode(null));
    assert.throws(() => b64uDecode(123));
    assert.deepEqual(b64uDecode(''), new Uint8Array(0));
    assert.deepEqual(b64uDecode('AA'), new Uint8Array([0]));
    assert.deepEqual(b64uDecode('AAA'), new Uint8Array([0, 0]));
    assert.throws(() => b64uEncode('not bytes'));
  });

  test('utf8 round trip and fatal decoding', () => {
    const s = 'Hola, ¿qué tal? 🔒 ñandú';
    assert.equal(utf8Decode(utf8Encode(s)), s);
    assert.throws(() => utf8Decode(new Uint8Array([0xff, 0xfe, 0x80])));
    assert.throws(() => utf8Encode(42));
  });

  test('concatBytes, u32be, constantTimeEqual, zeroize', () => {
    assert.deepEqual(concatBytes(new Uint8Array([1, 2]), new Uint8Array(0), new Uint8Array([3])), new Uint8Array([1, 2, 3]));
    assert.deepEqual(concatBytes(), new Uint8Array(0));
    assert.throws(() => concatBytes([1, 2]));
    assert.deepEqual(u32be(0x01020304), new Uint8Array([1, 2, 3, 4]));
    assert.deepEqual(u32be(0xffffffff), new Uint8Array([255, 255, 255, 255]));
    assert.deepEqual(u32be(0), new Uint8Array(4));
    for (const bad of [-1, 2 ** 32, 1.5, NaN, '1']) assert.throws(() => u32be(bad));
    assert.equal(constantTimeEqual(new Uint8Array([1, 2]), new Uint8Array([1, 2])), true);
    assert.equal(constantTimeEqual(new Uint8Array([1, 2]), new Uint8Array([1, 3])), false);
    assert.equal(constantTimeEqual(new Uint8Array([1, 2]), new Uint8Array([1, 2, 3])), false);
    assert.equal(constantTimeEqual(new Uint8Array(0), new Uint8Array(0)), true);
    assert.equal(constantTimeEqual('ab', 'ab'), false);
    const z = new Uint8Array([9, 9, 9]);
    zeroize(z);
    assert.deepEqual(z, new Uint8Array(3));
    zeroize(null); // must not throw
    zeroize({});
  });
});

// ---------------------------------------------------------------------------
describe('primitives', () => {
  test('randomBytes length and variability', () => {
    assert.equal(randomBytes(0).length, 0);
    assert.equal(randomBytes(100000).length, 100000);
    assert.notDeepEqual(randomBytes(32), randomBytes(32));
  });

  test('sha256 / sha512 / hmac known answers', async () => {
    assert.equal(toHex(await sha256(utf8Encode('abc'))),
      'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');
    assert.equal(toHex(await sha512(utf8Encode('abc'))),
      'ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f');
    // RFC 4231 test case 2
    assert.equal(toHex(await hmacSha256(utf8Encode('Jefe'), utf8Encode('what do ya want for nothing?'))),
      '5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843');
  });

  test('HKDF-SHA256 matches RFC 5869 test case 1', async () => {
    const okm = await hkdf(
      hex('0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b'),
      hex('000102030405060708090a0b0c'),
      hex('f0f1f2f3f4f5f6f7f8f9'),
      42,
    );
    assert.equal(toHex(okm),
      '3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865');
  });

  test('HKDF string info equals utf8 bytes info', async () => {
    const ikm = randomBytes(32), salt = randomBytes(32);
    assert.deepEqual(await hkdf(ikm, salt, 'SOMBRA-TEST', 44), await hkdf(ikm, salt, utf8Encode('SOMBRA-TEST'), 44));
  });

  test('AES-256-GCM round trip and tamper detection', async () => {
    const key = randomBytes(32), iv = randomBytes(12), aad = utf8Encode('aad');
    const pt = utf8Encode('mensaje secreto');
    const ct = await aesGcmEncrypt(key, iv, pt, aad);
    assert.equal(ct.length, pt.length + 16);
    assert.deepEqual(await aesGcmDecrypt(key, iv, ct, aad), pt);

    for (let i = 0; i < ct.length; i++) {
      const t = ct.slice();
      t[i] ^= 0x01;
      await assert.rejects(aesGcmDecrypt(key, iv, t, aad), /decryption failed/);
    }
    await assert.rejects(aesGcmDecrypt(key, iv, ct, utf8Encode('aaD')), /decryption failed/);
    await assert.rejects(aesGcmDecrypt(key, iv, ct), /decryption failed/);
    await assert.rejects(aesGcmDecrypt(randomBytes(32), iv, ct, aad), /decryption failed/);
    await assert.rejects(aesGcmDecrypt(key, randomBytes(12), ct, aad), /decryption failed/);
    await assert.rejects(aesGcmDecrypt(key, iv, ct.subarray(0, 10), aad), /decryption failed/);
    await assert.rejects(aesGcmEncrypt(randomBytes(16), iv, pt));
    await assert.rejects(aesGcmEncrypt(key, randomBytes(16), pt));
  });

  test('PBKDF2-SHA256 matches node:crypto', async () => {
    const pw = utf8Encode('correct horse'), salt = randomBytes(16);
    const ours = await pbkdf2Sha256(pw, salt, 1000, 32);
    const ref = nodeCrypto.pbkdf2Sync(Buffer.from(pw), Buffer.from(salt), 1000, 32, 'sha256');
    assert.equal(toHex(ours), ref.toString('hex'));
  });

  test('X25519 matches RFC 7748 §6.1', async () => {
    const aPriv = hex('77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a');
    const aPub = hex('8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a');
    const bPriv = hex('5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb');
    const bPub = hex('de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f');
    const K = '4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742';
    assert.equal(toHex(await x25519(aPriv, bPub)), K);
    assert.equal(toHex(await x25519(bPriv, aPub)), K);
  });

  test('X25519 generated keys agree; all-zero / low-order outputs rejected', async () => {
    const a = await generateX25519(), b = await generateX25519();
    assert.equal(a.pub.length, 32);
    assert.equal(a.priv.length, 32);
    assert.deepEqual(await x25519(a.priv, b.pub), await x25519(b.priv, a.pub));
    // Low-order points: 0, 1 and the order-8 point -> all-zero shared secret.
    const lowOrder = [
      new Uint8Array(32),
      hex('0100000000000000000000000000000000000000000000000000000000000000'),
      hex('e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800'),
    ];
    for (const p of lowOrder) await assert.rejects(x25519(a.priv, p), /x25519 failed/);
    await assert.rejects(x25519(a.priv, new Uint8Array(31)));
  });

  test('Ed25519 matches RFC 8032 test 1', async () => {
    const kp = {
      priv: hex('9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60'),
      pub: hex('d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a'),
    };
    const expected = 'e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b';
    const sig = await ed25519Sign(kp, new Uint8Array(0));
    assert.equal(toHex(sig), expected);
    assert.equal(await ed25519Verify(kp.pub, new Uint8Array(0), sig), true);
  });

  test('Ed25519 sign/verify, and verify never throws', async () => {
    const kp = await generateEd25519();
    const msg = utf8Encode('hola');
    const sig = await ed25519Sign(kp, msg);
    assert.equal(sig.length, 64);
    assert.equal(await ed25519Verify(kp.pub, msg, sig), true);
    assert.equal(await ed25519Verify(kp.pub, utf8Encode('hola!'), sig), false);
    const bad = sig.slice(); bad[10] ^= 1;
    assert.equal(await ed25519Verify(kp.pub, msg, bad), false);
    assert.equal(await ed25519Verify((await generateEd25519()).pub, msg, sig), false);
    // Malformed inputs -> false, never an exception
    assert.equal(await ed25519Verify(new Uint8Array(31), msg, sig), false);
    assert.equal(await ed25519Verify(kp.pub, msg, sig.subarray(0, 63)), false);
    assert.equal(await ed25519Verify(null, msg, sig), false);
    assert.equal(await ed25519Verify(kp.pub, 'hola', sig), false);
    assert.equal(await ed25519Verify(new Uint8Array(32).fill(0xff), msg, sig), false);
  });
});

// ---------------------------------------------------------------------------
describe('identity & X3DH', () => {
  async function makeBob(withOpk = true) {
    const identity = await generateIdentity();
    const pubId = await publicIdentity(identity);
    const spk = await generateSignedPrekey(identity, 7);
    const [opk] = await generateOneTimePrekeys(100, 1);
    const bundle = {
      username: 'bob', ...pubId,
      spk: { id: spk.id, pub: spk.pub, sig: spk.sig },
      opk: withOpk ? { id: opk.id, pub: opk.pub } : null,
    };
    return { identity, pubId, spk, opk, bundle };
  }

  test('public identity / prekey signatures verify and detect tampering', async () => {
    const { identity, pubId, spk } = await makeBob();
    assert.equal(await verifyPublicIdentity(pubId), true);
    assert.equal(await verifyPublicIdentity({ ...pubId, ik_dh: b64uEncode(randomBytes(32)) }), false);
    assert.equal(await verifyPublicIdentity({ ...pubId, ik_dh_sig: 'garbage' }), false);
    assert.equal(await verifyPublicIdentity(null), false);
    const spkPub = { id: spk.id, pub: spk.pub, sig: spk.sig };
    assert.equal(await verifySignedPrekey(pubId.ik_sig, spkPub), true);
    assert.equal(await verifySignedPrekey(pubId.ik_sig, { ...spkPub, id: 8 }), false);
    assert.equal(await verifySignedPrekey(pubId.ik_sig, { ...spkPub, pub: b64uEncode(randomBytes(32)) }), false);
    assert.equal(await verifySignedPrekey(b64uEncode((await generateEd25519()).pub), spkPub), false);
    assert.equal(await verifySignedPrekey(pubId.ik_sig, { ...spkPub, id: -1 }), false);
    // serialisation round trip
    assert.deepEqual(deserializeIdentity(JSON.parse(JSON.stringify(serializeIdentity(identity)))), identity);
  });

  test('generateOneTimePrekeys produces sequential ids', async () => {
    const opks = await generateOneTimePrekeys(5, 3);
    assert.deepEqual(opks.map((o) => o.id), [5, 6, 7]);
    for (const o of opks) assert.equal(b64uDecode(o.pub).length, 32);
    await assert.rejects(generateOneTimePrekeys(0xffffffff, 2));
  });

  for (const withOpk of [true, false]) {
    test(`initiator and responder agree (${withOpk ? 'with' : 'without'} OPK)`, async () => {
      const alice = await generateIdentity();
      const alicePub = await publicIdentity(alice);
      const bob = await makeBob(withOpk);
      const init = await x3dhInitiate(alice, bob.bundle);
      assert.equal(init.sk.length, 32);
      assert.equal(init.spk_id, 7);
      assert.equal(init.opk_id, withOpk ? 100 : null);
      assert.deepEqual(init.spkPub, bob.spk.keyPair.pub);
      const resp = await x3dhRespond(bob.identity, bob.spk.keyPair, withOpk ? bob.opk.keyPair : null,
        { ik_sig: alicePub.ik_sig, ik_dh: alicePub.ik_dh }, init.ek);
      assert.deepEqual(resp.sk, init.sk);
      assert.deepEqual(resp.ad, init.ad);
      assert.deepEqual(init.ad, concatBytes(utf8Encode('SOMBRA-AD-v1'), alice.sig.pub, alice.dh.pub,
        bob.identity.sig.pub, bob.identity.dh.pub));
      // Responder ignoring/using the wrong OPK must not agree.
      const wrong = await x3dhRespond(bob.identity, bob.spk.keyPair, withOpk ? null : (await generateX25519()),
        { ik_sig: alicePub.ik_sig, ik_dh: alicePub.ik_dh }, init.ek);
      assert.notDeepEqual(wrong.sk, init.sk);
    });
  }

  test('x3dhInitiate rejects bad bundle signatures', async () => {
    const alice = await generateIdentity();
    const bob = await makeBob();
    const otherSpk = await generateSignedPrekey(await generateIdentity(), 7);
    const variants = [
      { ...bob.bundle, ik_dh: b64uEncode((await generateX25519()).pub) },
      { ...bob.bundle, spk: { ...bob.bundle.spk, pub: otherSpk.pub } },
      { ...bob.bundle, spk: { ...bob.bundle.spk, sig: otherSpk.sig } },
      { ...bob.bundle, spk: { ...bob.bundle.spk, id: 8 } },
      { ...bob.bundle, ik_sig: b64uEncode((await generateEd25519()).pub) },
    ];
    for (const v of variants) await assert.rejects(x3dhInitiate(alice, v), /bad bundle signature/);
  });
});

// ---------------------------------------------------------------------------
describe('padding', () => {
  const expected = [
    [0, 256], [1, 256], [252, 256], [253, 512], [508, 512], [509, 1024], [16380, 16384], [16381, 32768],
    [65532, 65536], [65533, 131072], [1048572, 1048576], [1048573, 2097152], [2 * 1048576, 3 * 1048576],
    [5 * 1048576 - 4, 5 * 1048576],
  ];
  test('bucket sizes', () => {
    for (const [len, total] of expected) {
      const p = pad(new Uint8Array(len).fill(0xab));
      assert.equal(p.length, total, `len ${len}`);
      assert.deepEqual(p.subarray(0, 4), u32be(len));
      const u = unpad(p);
      assert.equal(u.length, len);
      assert.ok(u.every((x) => x === 0xab));
    }
  });

  test('round trip of random data', () => {
    for (const n of [0, 5, 300, 5000]) {
      const b = randomBytes(n);
      assert.deepEqual(unpad(pad(b)), b);
    }
  });

  test('unpad errors', () => {
    const good = pad(utf8Encode('hola'));
    assert.throws(() => unpad(new Uint8Array(0)), /invalid padding/);
    assert.throws(() => unpad(good.subarray(0, 255)), /invalid padding/);
    const tooLong = good.slice(); tooLong.set(u32be(253), 0);
    assert.throws(() => unpad(tooLong), /invalid padding/); // would need a 512 bucket
    const huge = good.slice(); huge.set(u32be(0xffffffff), 0);
    assert.throws(() => unpad(huge), /invalid padding/);
    const nonZero = good.slice(); nonZero[200] = 1;
    assert.throws(() => unpad(nonZero), /invalid padding/);
    const wrongBucket = new Uint8Array(512); wrongBucket.set(u32be(4), 0);
    assert.throws(() => unpad(wrongBucket), /invalid padding/);
    assert.throws(() => unpad('x'));
  });
});

// ---------------------------------------------------------------------------
describe('sealed sender', () => {
  test('seal / unseal round trip hides sender and pads', async () => {
    const bob = await generateX25519();
    const inner = randomBytes(1000);
    const blob = await seal('alice', bob.pub, inner);
    assert.equal(blob[0], 0x01);
    assert.equal(blob.length, 1 + 32 + 2048 + 16); // padded JSON (~1.4 KB) -> 2048 bucket
    assert.equal(Buffer.from(blob).includes(Buffer.from('alice')), false);
    const out = await unseal(bob, blob);
    assert.equal(out.from, 'alice');
    assert.deepEqual(out.inner, inner);
    // Two seals of the same content differ (fresh ephemeral key).
    assert.notDeepEqual(await seal('alice', bob.pub, inner), blob);
  });

  test('unseal fails with wrong key or tampered blob', async () => {
    const bob = await generateX25519();
    const eve = await generateX25519();
    const blob = await seal('alice', bob.pub, utf8Encode('hi'));
    await assert.rejects(unseal(eve, blob), /unseal failed/);
    // Right private key but wrong claimed public key -> AAD/salt mismatch.
    await assert.rejects(unseal({ pub: eve.pub, priv: bob.priv }, blob), /unseal failed/);
    for (const i of [0, 1, 20, 40, blob.length - 1]) {
      const t = blob.slice(); t[i] ^= 0x01;
      await assert.rejects(unseal(bob, t), /unseal failed/);
    }
    await assert.rejects(unseal(bob, blob.subarray(0, 100)), /unseal failed/);
    const lowOrder = blob.slice(); lowOrder.fill(0, 1, 33);
    await assert.rejects(unseal(bob, lowOrder), /unseal failed/);
  });
});

// ---------------------------------------------------------------------------
describe('safety numbers', () => {
  test('symmetric, 60 digits, formatting, sensitive to key changes', async () => {
    const a = await publicIdentity(await generateIdentity());
    const b = await publicIdentity(await generateIdentity());
    const n1 = await safetyNumber('alice', a, 'bob', b);
    const n2 = await safetyNumber('bob', b, 'alice', a);
    assert.equal(n1, n2);
    assert.match(n1, /^[0-9]{60}$/);
    const f = formatSafetyNumber(n1);
    assert.match(f, /^([0-9]{5} ){11}[0-9]{5}$/);
    assert.equal(f.replace(/ /g, ''), n1);

    const b2 = await publicIdentity(await generateIdentity());
    assert.notEqual(await safetyNumber('alice', a, 'bob', b2), n1);
    const bDhChanged = { ...b, ik_dh: b64uEncode((await generateX25519()).pub) };
    assert.notEqual(await safetyNumber('alice', a, 'bob', bDhChanged), n1);
    assert.notEqual(await safetyNumber('alice', a, 'bobby', b), n1);
  });

  test('deterministic known structure (each half is the per-party 30 digits)', async () => {
    const a = await publicIdentity(await generateIdentity());
    const b = await publicIdentity(await generateIdentity());
    const c = await publicIdentity(await generateIdentity());
    const ab = await safetyNumber('alice', a, 'bob', b);
    const ac = await safetyNumber('alice', a, 'carol', c);
    const aliceHalf = [ab.slice(0, 30), ab.slice(30)].find((h) => ac.includes(h));
    assert.ok(aliceHalf, 'alice\'s 30 digits must appear in both numbers');
    assert.ok(ab.slice(0, 30) <= ab.slice(30));
  });
});

// ---------------------------------------------------------------------------
describe('vault', () => {
  test('default iteration count is 600000 and is used by default', async () => {
    assert.equal(PBKDF2_ITERATIONS, 600000);
    const { meta } = await createVault('una frase larga de prueba');
    assert.equal(meta.iter, 600000);
  });

  test('create / unlock / wrong passphrase', async () => {
    const { meta, keys } = await createVault('contraseña segura', { iterations: TEST_ITER });
    assert.equal(meta.v, 1);
    assert.equal(meta.iter, TEST_ITER);
    assert.equal(b64uDecode(meta.salt).length, 16);
    assert.ok(JSON.parse(JSON.stringify(meta)));
    const keys2 = await unlockVault('contraseña segura', meta);
    assert.deepEqual(keys2, keys);
    assert.equal(keys.encKey.length, 32);
    assert.notDeepEqual(keys.encKey, keys.macKey);
    await assert.rejects(unlockVault('contraseña segurA', meta), /^Error: bad passphrase$/);
    await assert.rejects(unlockVault('contraseña segura', { ...meta, salt: b64uEncode(randomBytes(16)) }), /bad passphrase/);
    await assert.rejects(createVault(''));
  });

  test('record round trip, aad binding, record keys', async () => {
    const { keys } = await createVault('pw', { iterations: TEST_ITER });
    const obj = { a: 1, b: ['x', 'ñ'], c: { d: null } };
    const enc = await encryptRecord(keys, 'contacts', obj);
    assert.equal(typeof enc, 'string');
    assert.deepEqual(await decryptRecord(keys, 'contacts', enc), obj);
    assert.notEqual(await encryptRecord(keys, 'contacts', obj), enc); // random IV
    // Record encrypted under name A cannot be decrypted as name B (swap attack).
    await assert.rejects(decryptRecord(keys, 'account', enc));
    // Different vault keys
    const { keys: other } = await createVault('pw', { iterations: TEST_ITER });
    await assert.rejects(decryptRecord(other, 'contacts', enc));
    // Tampering
    const raw = b64uDecode(enc); raw[raw.length - 1] ^= 1;
    await assert.rejects(decryptRecord(keys, 'contacts', b64uEncode(raw)));
    // recordKey: deterministic, name-hiding, key-dependent
    const rk = await recordKey(keys, 'session:alice');
    assert.equal(rk, await recordKey(keys, 'session:alice'));
    assert.notEqual(rk, await recordKey(keys, 'session:bob'));
    assert.notEqual(rk, await recordKey(other, 'session:alice'));
    assert.equal(b64uDecode(rk).length, 32);
    assert.ok(!rk.includes('alice'));
  });
});

// ---------------------------------------------------------------------------
describe('proof of work', () => {
  test('pure-JS SHA-256 equals WebCrypto for random inputs of length 0..300', async () => {
    for (let n = 0; n <= 300; n++) {
      const b = randomBytes(n);
      assert.equal(toHex(sha256Sync(b)), toHex(await sha256(b)), `length ${n}`);
    }
    assert.equal(toHex(sha256Sync(new Uint8Array(0))),
      'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855');
  });

  test('leadingZeroBits', () => {
    assert.equal(leadingZeroBits(new Uint8Array([0x80])), 0);
    assert.equal(leadingZeroBits(new Uint8Array([0x01])), 7);
    assert.equal(leadingZeroBits(new Uint8Array([0, 0x40])), 9);
    assert.equal(leadingZeroBits(new Uint8Array([0, 0, 0])), 24);
    assert.equal(leadingZeroBits(new Uint8Array(0)), 0);
  });

  test('solve / verify, cross-checked with WebCrypto', async () => {
    for (const challenge of ['abc', b64uEncode(randomBytes(41)), 'x'.repeat(50), 'y'.repeat(120), 'z'.repeat(45), 'w'.repeat(48)]) {
      const difficulty = 12;
      let progressCalls = 0;
      const nonce = await solvePow(challenge, difficulty, { onProgress: () => { progressCalls++; } });
      assert.match(nonce, /^(0|[1-9][0-9]*)$/);
      assert.equal(verifyPowSync(challenge, nonce, difficulty), true);
      const h = await sha256(utf8Encode(`SOMBRA-POW-v1:${challenge}:${nonce}`));
      assert.ok(leadingZeroBits(h) >= difficulty);
      // The returned nonce is the first solution: every smaller nonce fails
      // (catches midstate/tail bugs in the solver, incl. the spill-over block path
      // exercised by the 45/48-char challenges).
      for (let i = 0; i < Number(nonce); i++) {
        assert.equal(verifyPowSync(challenge, String(i), difficulty), false);
      }
      assert.ok(progressCalls >= 0);
    }
  });

  test('verifyPowSync rejects bad input', async () => {
    const nonce = await solvePow('chal', 8);
    assert.equal(verifyPowSync('chal', nonce, 8), true);
    assert.equal(verifyPowSync('chal2', nonce, 8) && verifyPowSync('chal3', nonce, 8) && verifyPowSync('chal4', nonce, 8), false);
    assert.equal(verifyPowSync('chal', '0' + nonce, 8), false); // leading zero not canonical
    assert.equal(verifyPowSync('chal', '-1', 8), false);
    assert.equal(verifyPowSync('chal', '1e3', 8), false);
    assert.equal(verifyPowSync('chal', 5, 8), false);
    assert.equal(verifyPowSync('chal', nonce, -1), false);
    assert.equal(verifyPowSync('chal', nonce, 1.5), false);
    assert.equal(verifyPowSync(null, nonce, 8), false);
    assert.equal(verifyPowSync('chal', '0', 0), true);
  });

  test('solvePow honours abort signal and rejects absurd difficulty', async () => {
    const ac = new AbortController();
    let progress = 0;
    const p = solvePow('hard', 31, { signal: ac.signal, onProgress: (n) => { progress = n; ac.abort(); } });
    await assert.rejects(p, (e) => e.name === 'AbortError');
    assert.ok(progress >= 20000);
    await assert.rejects(solvePow('x', 40), RangeError);
    await assert.rejects(solvePow('', 4), TypeError);
  });
});
