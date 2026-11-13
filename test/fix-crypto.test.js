// Regression tests for audited crypto findings CRYPTO-2, CRYPTO-7, CRYPTO-8.
// Run: node --test test/fix-crypto.test.js
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';

import { utf8Encode, utf8Decode, concatBytes } from '../public/js/crypto/encoding.js';
import { generateIdentity, publicIdentity, generateSignedPrekey, generateOneTimePrekeys,
  x3dhInitiate, x3dhRespond } from '../public/js/crypto/x3dh.js';
import * as R from '../public/js/crypto/ratchet.js';

const { ratchetInitSender, ratchetInitReceiver, ratchetEncrypt, ratchetDecrypt, MAX_SKIP } = R;
const DAY = 24 * 3600 * 1000;

async function makeUser(username) {
  const identity = await generateIdentity();
  const pub = await publicIdentity(identity);
  const spk = await generateSignedPrekey(identity, 1);
  const [opk] = await generateOneTimePrekeys(1, 1);
  const bundle = { username, ...pub, spk: { id: 1, pub: spk.pub, sig: spk.sig }, opk: { id: opk.id, pub: opk.pub } };
  return { username, identity, pub, spk, opk, bundle };
}

async function newSession() {
  const alice = await makeUser('alice');
  const bob = await makeUser('bob');
  const init = await x3dhInitiate(alice.identity, bob.bundle);
  const resp = await x3dhRespond(bob.identity, bob.spk.keyPair, bob.opk.keyPair, alice.pub, init.ek);
  return {
    ad: init.ad,
    a: await ratchetInitSender(init.sk, init.spkPub),
    b: await ratchetInitReceiver(resp.sk, bob.spk.keyPair),
  };
}

function party(state, ad) {
  return {
    state,
    async send(text, opts) {
      const r = await ratchetEncrypt(this.state, utf8Encode(text), ad, opts);
      this.state = r.state;
      return { header: r.header, ct: r.ciphertext, text };
    },
    async recv(msg, opts) {
      const r = await ratchetDecrypt(this.state, msg.header, msg.ct, ad, opts);
      this.state = r.state;
      return utf8Decode(r.plaintext);
    },
  };
}

async function assertRejectsUnchanged(state, header, ct, ad, re, opts) {
  const snapshot = structuredClone(state);
  await assert.rejects(ratchetDecrypt(state, header, ct, ad, opts), re);
  assert.deepEqual(state, snapshot);
}

describe('CRYPTO-2: no permanent deadlock after > MAX_SKIP lost messages', () => {
  test('new ratchet key with pn gap > MAX_SKIP is accepted (old chain clamped)', async () => {
    const { a, b, ad } = await newSession();
    const A = party(a, ad), B = party(b, ad);
    assert.equal(await B.recv(await A.send('m0')), 'm0');
    const lost = [];
    for (let i = 0; i < MAX_SKIP + 500; i++) lost.push(await A.send(`lost${i}`)); // never delivered
    assert.equal(await A.recv(await B.send('reply')), 'reply'); // Alice DH-ratchets
    const x = await A.send('new chain');
    assert.equal(x.header.pn, MAX_SKIP + 501);
    // Before the fix: 'too many skipped messages' forever (Bob never ratchets).
    assert.equal(await B.recv(x), 'new chain');
    // At most MAX_SKIP keys of the abandoned chain were derived and stored.
    assert.equal(B.state.skipped.length, MAX_SKIP);
    // Early lost messages are still readable if they show up late; those past the clamp are not.
    assert.equal(await B.recv(lost[3]), 'lost3');
    await assertRejectsUnchanged(B.state, lost[lost.length - 1].header, lost[lost.length - 1].ct, ad);
    // Conversation fully recovered in both directions.
    assert.equal(await A.recv(await B.send('b2')), 'b2');
    assert.equal(await B.recv(await A.send('a3')), 'a3');
  });

  test('clamp does not accept forged headers and leaves state untouched', async () => {
    const { a, b, ad } = await newSession();
    const A = party(a, ad), B = party(b, ad);
    assert.equal(await B.recv(await A.send('m0')), 'm0');
    assert.equal(await A.recv(await B.send('reply')), 'reply');
    const x = await A.send('new chain');
    await assertRejectsUnchanged(B.state, { ...x.header, pn: 0xffffffff }, x.ct, ad, /too many skipped/);
    assert.equal(await B.recv(x), 'new chain');
  });

  test('sender-side rekey signal bounds every sending chain below MAX_SKIP', async () => {
    assert.equal(typeof R.ratchetNeedsRekey, 'function');
    assert.ok(Number.isInteger(R.REKEY_AFTER) && R.REKEY_AFTER > 0 && R.REKEY_AFTER < MAX_SKIP);
    const { a, b, ad } = await newSession();
    const A = party(a, ad), B = party(b, ad);
    let last;
    while (!R.ratchetNeedsRekey(A.state)) last = await A.send('x'); // all lost except the last
    assert.equal(A.state.ns, R.REKEY_AFTER);
    assert.equal(last.header.n, R.REKEY_AFTER - 1);
    // The worst-case gap on a rekey-bounded chain is always recoverable.
    assert.equal(await B.recv(last), 'x');
    // After a DH ratchet step the counter resets.
    assert.equal(await A.recv(await B.send('ack')), 'ack');
    assert.equal(R.ratchetNeedsRekey(A.state), false);
    assert.equal(R.ratchetNeedsRekey(B.state), false);
    assert.throws(() => R.ratchetNeedsRekey(null));
  });
});

describe('CRYPTO-8: skipped message keys expire', () => {
  test('skipped keys older than the max age are purged and unusable', async () => {
    const { a, b, ad } = await newSession();
    const A = party(a, ad), B = party(b, ad);
    const t0 = 1_800_000_000_000;
    const withheld = await A.send('withheld');
    const later = await A.send('later');
    assert.equal(await B.recv(later, { now: t0 }), 'later');
    assert.equal(B.state.skipped.length, 1);
    assert.equal(B.state.skipped[0].t, t0);
    // Within the window: still readable (from a copy of the state).
    const r = await ratchetDecrypt(B.state, withheld.header, withheld.ct, ad, { now: t0 + 13 * DAY });
    assert.equal(utf8Decode(r.plaintext), 'withheld');
    // A later message after the window purges the key (forward secrecy restored).
    const after = await A.send('after');
    assert.equal(await B.recv(after, { now: t0 + 15 * DAY }), 'after');
    assert.equal(B.state.skipped.length, 0);
    await assertRejectsUnchanged(B.state, withheld.header, withheld.ct, ad, undefined, { now: t0 + 15 * DAY });
  });

  test('withheld ciphertext is rejected after the window even without other traffic', async () => {
    const { a, b, ad } = await newSession();
    const A = party(a, ad), B = party(b, ad);
    const t0 = 1_800_000_000_000;
    const withheld = await A.send('withheld');
    assert.equal(await B.recv(await A.send('later'), { now: t0 }), 'later');
    await assertRejectsUnchanged(B.state, withheld.header, withheld.ct, ad, undefined, { now: t0 + R.SKIPPED_KEY_MAX_AGE_MS + 1 });
  });

  test('ratchetPurgeSkipped is functional, handles legacy entries and clock skew', async () => {
    const { a, b, ad } = await newSession();
    const A = party(a, ad), B = party(b, ad);
    const t0 = 1_800_000_000_000;
    for (let i = 0; i < 3; i++) await A.send(`l${i}`);
    assert.equal(await B.recv(await A.send('x'), { now: t0 }), 'x');
    const legacy = structuredClone(B.state);
    delete legacy.skipped[0].t;          // pre-fix state: no timestamp
    legacy.skipped[1].t = t0 + 365 * DAY; // future timestamp (clock was wrong)
    const snap = structuredClone(legacy);
    const p = R.ratchetPurgeSkipped(legacy, t0 + DAY);
    assert.deepEqual(legacy, snap); // input not mutated
    assert.equal(p.skipped.length, 3);
    assert.equal(p.skipped[0].t, t0 + DAY); // legacy: clock starts now
    assert.equal(p.skipped[1].t, t0 + DAY); // future clamped to now
    const p2 = R.ratchetPurgeSkipped(p, t0 + DAY + R.SKIPPED_KEY_MAX_AGE_MS + 1);
    assert.equal(p2.skipped.length, 0);
    assert.equal(R.SKIPPED_KEY_MAX_AGE_MS, 14 * DAY);
    assert.throws(() => R.ratchetPurgeSkipped(p, NaN));
  });
});

describe('CRYPTO-7: usernames bound into the X3DH associated data', () => {
  test('a message encrypted for "carlos" (copied identity) does not decrypt at alice', async () => {
    const alice = await makeUser('alice');
    const bob = await makeUser('bob');
    // Attacker registers "carlos" with alice's public identity and prekeys.
    const carlosBundle = { ...alice.bundle, username: 'carlos' };
    const init = await x3dhInitiate(bob.identity, carlosBundle, { initiator: 'bob', responder: 'carlos' });
    const sender = await ratchetInitSender(init.sk, init.spkPub);
    const enc = await ratchetEncrypt(sender, utf8Encode('Carlos: esto es SOLO para ti'), init.ad);
    // Delivered to alice, who binds her own username.
    const resp = await x3dhRespond(alice.identity, alice.spk.keyPair, alice.opk.keyPair, bob.pub, init.ek,
      { initiator: 'bob', responder: 'alice' });
    assert.notDeepEqual(resp.ad, init.ad);
    const recv = await ratchetInitReceiver(resp.sk, alice.spk.keyPair);
    await assert.rejects(ratchetDecrypt(recv, enc.header, enc.ciphertext, resp.ad), /decryption failed/);
  });

  test('re-sealing with a different sender name is rejected; matching names work', async () => {
    const alice = await makeUser('alice');
    const bob = await makeUser('bob');
    const init = await x3dhInitiate(bob.identity, alice.bundle, { initiator: 'bob', responder: 'alice' });
    const enc = await ratchetEncrypt(await ratchetInitSender(init.sk, init.spkPub), utf8Encode('hola'), init.ad);
    const respond = (initiator) => x3dhRespond(alice.identity, alice.spk.keyPair, alice.opk.keyPair, bob.pub, init.ek,
      { initiator, responder: 'alice' });
    const forged = await respond('mallory');
    await assert.rejects(ratchetDecrypt(await ratchetInitReceiver(forged.sk, alice.spk.keyPair), enc.header, enc.ciphertext, forged.ad));
    const ok = await respond('bob');
    assert.deepEqual(ok.ad, init.ad);
    const d = await ratchetDecrypt(await ratchetInitReceiver(ok.sk, alice.spk.keyPair), enc.header, enc.ciphertext, ok.ad);
    assert.equal(utf8Decode(d.plaintext), 'hola');
    // Exact AD layout: label v2 || IKa || IKb || u8 len || name_a || u8 len || name_b
    assert.deepEqual(init.ad, concatBytes(utf8Encode('SOMBRA-AD-v2'), bob.identity.sig.pub, bob.identity.dh.pub,
      alice.identity.sig.pub, alice.identity.dh.pub, Uint8Array.of(3), utf8Encode('bob'), Uint8Array.of(5), utf8Encode('alice')));
  });

  test('bad name bindings are refused', async () => {
    const alice = await makeUser('alice');
    const bob = await makeUser('bob');
    await assert.rejects(x3dhInitiate(bob.identity, alice.bundle, { initiator: 'bob', responder: 'carlos' }), /bad bundle/);
    for (const names of [{ initiator: '', responder: 'alice' }, { initiator: 'bob' }, { initiator: 'x'.repeat(256), responder: 'alice' },
      { initiator: 1, responder: 'alice' }, 'bob', null]) {
      await assert.rejects(x3dhInitiate(bob.identity, alice.bundle, names));
    }
    const init = await x3dhInitiate(bob.identity, alice.bundle, { initiator: 'bob', responder: 'alice' });
    await assert.rejects(x3dhRespond(alice.identity, alice.spk.keyPair, null, bob.pub, init.ek, { initiator: 'bob' }));
  });
});
