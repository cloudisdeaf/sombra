// Tests for the Double Ratchet (public/js/crypto/ratchet.js), driven through a
// real X3DH handshake. Run: node --test test/ratchet.test.js
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';

import { utf8Encode, utf8Decode, b64uEncode, b64uDecode } from '../public/js/crypto/encoding.js';
import { generateIdentity, publicIdentity, generateSignedPrekey, generateOneTimePrekeys,
  x3dhInitiate, x3dhRespond } from '../public/js/crypto/x3dh.js';
import { generateX25519 } from '../public/js/crypto/primitives.js';
import { ratchetInitSender, ratchetInitReceiver, ratchetEncrypt, ratchetDecrypt, MAX_SKIP }
  from '../public/js/crypto/ratchet.js';

/** Full X3DH between Alice and Bob, then ratchet init on both sides. */
async function newSession() {
  const alice = await generateIdentity();
  const bob = await generateIdentity();
  const bobPub = await publicIdentity(bob);
  const spk = await generateSignedPrekey(bob, 1);
  const [opk] = await generateOneTimePrekeys(1, 1);
  const bundle = { username: 'bob', ...bobPub, spk: { id: 1, pub: spk.pub, sig: spk.sig }, opk: { id: opk.id, pub: opk.pub } };
  const init = await x3dhInitiate(alice, bundle);
  const alicePub = await publicIdentity(alice);
  const resp = await x3dhRespond(bob, spk.keyPair, opk.keyPair, alicePub, init.ek);
  return {
    ad: init.ad,
    a: await ratchetInitSender(init.sk, init.spkPub),
    b: await ratchetInitReceiver(resp.sk, spk.keyPair),
  };
}

/** Wrapper that keeps the state in a mutable holder, like a real client would. */
function party(state, ad) {
  return {
    state,
    async send(text) {
      const r = await ratchetEncrypt(this.state, utf8Encode(text), ad);
      this.state = r.state;
      return { header: r.header, ct: r.ciphertext, text };
    },
    async recv(msg) {
      const r = await ratchetDecrypt(this.state, msg.header, msg.ct, ad);
      this.state = r.state;
      return utf8Decode(r.plaintext);
    },
  };
}

/** Assert decryption fails AND the input state is left untouched. */
async function assertRejectsUnchanged(state, header, ct, ad, re) {
  const snapshot = structuredClone(state);
  await assert.rejects(ratchetDecrypt(state, header, ct, ad), re);
  assert.deepEqual(state, snapshot);
}

function shuffle(arr) {
  const a = arr.slice();
  for (let i = a.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1));
    [a[i], a[j]] = [a[j], a[i]];
  }
  return a;
}

describe('double ratchet', () => {
  test('state is plain JSON and initial shapes match the spec', async () => {
    const { a, b } = await newSession();
    for (const s of [a, b]) {
      assert.deepEqual(JSON.parse(JSON.stringify(s)), s);
      assert.equal(s.v, 1);
      assert.equal(s.ns, 0);
      assert.equal(s.nr, 0);
      assert.equal(s.pn, 0);
      assert.deepEqual(s.skipped, []);
    }
    assert.equal(b.cks, null);
    assert.equal(b.dhr, null);
    assert.notEqual(a.cks, null);
  });

  test('responder cannot send before receiving', async () => {
    const { b, ad } = await newSession();
    await assert.rejects(ratchetEncrypt(b, utf8Encode('x'), ad), /cannot send/);
  });

  test('long conversation in both directions with many DH ratchet steps', async () => {
    const { a, b, ad } = await newSession();
    const A = party(a, ad), B = party(b, ad);
    // First message must come from Alice.
    assert.equal(await B.recv(await A.send('hola bob')), 'hola bob');
    let dhSteps = 0;
    let lastSender = 'A';
    for (let i = 0; i < 300; i++) {
      const fromA = Math.random() < 0.5;
      if ((fromA ? 'A' : 'B') !== lastSender) dhSteps++;
      lastSender = fromA ? 'A' : 'B';
      const [S, R] = fromA ? [A, B] : [B, A];
      const text = `msg ${i} ${'ñ'.repeat(i % 17)}`;
      assert.equal(await R.recv(await S.send(text)), text);
    }
    assert.ok(dhSteps > 50, 'expected many direction changes');
    assert.deepEqual(A.state.skipped, []);
    assert.deepEqual(B.state.skipped, []);
  });

  test('header fields and ciphertext are fresh per message', async () => {
    const { a, ad } = await newSession();
    const A = party(a, ad);
    const m0 = await A.send('same'), m1 = await A.send('same');
    assert.equal(m0.header.n, 0);
    assert.equal(m1.header.n, 1);
    assert.equal(m0.header.dh, m1.header.dh);
    assert.equal(b64uDecode(m0.header.dh).length, 32);
    assert.notDeepEqual(m0.ct, m1.ct);
  });

  test('out-of-order delivery within and across chains', async () => {
    const { a, b, ad } = await newSession();
    const A = party(a, ad), B = party(b, ad);
    const chain1 = [];
    for (let i = 0; i < 10; i++) chain1.push(await A.send(`a1-${i}`));
    // Deliver only half now, shuffled.
    const firstHalf = shuffle(chain1.slice(0, 5).concat(chain1.slice(7, 8)));
    for (const m of firstHalf) assert.equal(await B.recv(m), m.text);
    // Bob replies -> Alice ratchets; Alice sends a new chain.
    const r = await B.send('b-reply');
    assert.equal(await A.recv(r), 'b-reply');
    const chain2 = [];
    for (let i = 0; i < 5; i++) chain2.push(await A.send(`a2-${i}`));
    // Chain-2 messages arrive before the stragglers of chain 1 (pn path).
    for (const m of shuffle(chain2)) assert.equal(await B.recv(m), m.text);
    for (const m of shuffle([chain1[5], chain1[6], chain1[8], chain1[9]])) assert.equal(await B.recv(m), m.text);
    assert.deepEqual(B.state.skipped, []);
    // Conversation continues normally.
    assert.equal(await A.recv(await B.send('ok')), 'ok');
  });

  test('lost messages do not break the session', async () => {
    const { a, b, ad } = await newSession();
    const A = party(a, ad), B = party(b, ad);
    for (let round = 0; round < 5; round++) {
      const sent = [];
      for (let i = 0; i < 6; i++) sent.push(await A.send(`a${round}-${i}`));
      // Messages 1, 3 and 4 are lost forever.
      for (const i of [0, 2, 5]) assert.equal(await B.recv(sent[i]), sent[i].text);
      const reply = await B.send(`b${round}`);
      // Bob's reply is sometimes lost too; Bob then sends another.
      if (round % 2 === 0) assert.equal(await A.recv(reply), reply.text);
      else {
        const again = await B.send(`b${round}-again`);
        assert.equal(await A.recv(again), again.text);
      }
    }
    assert.equal(B.state.skipped.length, 15); // 3 lost per round x 5
  });

  test('replays are rejected (each message key used once)', async () => {
    const { a, b, ad } = await newSession();
    const A = party(a, ad), B = party(b, ad);
    const m0 = await A.send('m0'), m1 = await A.send('m1'), m2 = await A.send('m2');
    assert.equal(await B.recv(m0), 'm0');
    await assertRejectsUnchanged(B.state, m0.header, m0.ct, ad); // in-chain replay
    assert.equal(await B.recv(m2), 'm2'); // skips m1
    assert.equal(await B.recv(m1), 'm1'); // from skipped store
    await assertRejectsUnchanged(B.state, m1.header, m1.ct, ad); // replay of skipped key
    await assertRejectsUnchanged(B.state, m2.header, m2.ct, ad);
    // Replay of an old-chain message after a DH ratchet.
    assert.equal(await A.recv(await B.send('x')), 'x');
    assert.equal(await B.recv(await A.send('y')), 'y');
    await assertRejectsUnchanged(B.state, m0.header, m0.ct, ad);
    await assertRejectsUnchanged(B.state, m2.header, m2.ct, ad);
  });

  test('tampered ciphertext, header or AD are rejected without state change', async () => {
    const { a, b, ad } = await newSession();
    const A = party(a, ad), B = party(b, ad);
    assert.equal(await B.recv(await A.send('first')), 'first');
    const m = await A.send('secreto');
    const skip = await A.send('later'); // n=2 -> exercise skip path in tampering too

    for (const i of [0, 3, m.ct.length - 1]) {
      const ct = m.ct.slice(); ct[i] ^= 0x80;
      await assertRejectsUnchanged(B.state, m.header, ct, ad);
    }
    await assertRejectsUnchanged(B.state, m.header, m.ct.subarray(0, m.ct.length - 1), ad);
    await assertRejectsUnchanged(B.state, { ...m.header, n: m.header.n + 1 }, m.ct, ad);
    await assertRejectsUnchanged(B.state, { ...m.header, pn: m.header.pn + 1 }, m.ct, ad);
    const dh = b64uDecode(m.header.dh); dh[5] ^= 1;
    await assertRejectsUnchanged(B.state, { ...m.header, dh: b64uEncode(dh) }, m.ct, ad); // new-DH path
    await assertRejectsUnchanged(B.state, { ...m.header, dh: b64uEncode(new Uint8Array(32)) }, m.ct, ad); // low order
    const badAd = ad.slice(); badAd[ad.length - 1] ^= 1;
    await assertRejectsUnchanged(B.state, m.header, m.ct, badAd);
    await assertRejectsUnchanged(B.state, skip.header, skip.ct, badAd); // would skip n=1 first
    // Malformed headers
    for (const h of [null, {}, { ...m.header, n: -1 }, { ...m.header, n: 1.5 }, { ...m.header, pn: 2 ** 32 },
      { ...m.header, dh: 'AAAA' }, { ...m.header, dh: m.header.dh + '=' }, { ...m.header, n: '1' }]) {
      await assertRejectsUnchanged(B.state, h, m.ct, ad);
    }
    // Wrong-session key: a message for another session.
    const other = await newSession();
    const om = await ratchetEncrypt(other.a, utf8Encode('x'), other.ad);
    await assertRejectsUnchanged(B.state, om.header, om.ciphertext, ad);

    // The untampered messages still decrypt afterwards.
    assert.equal(await B.recv(skip), 'later');
    assert.equal(await B.recv(m), 'secreto');
  });

  test('encrypt and decrypt never mutate their input state', async () => {
    const { a, b, ad } = await newSession();
    const snapA = structuredClone(a), snapB = structuredClone(b);
    const e = await ratchetEncrypt(a, utf8Encode('hi'), ad);
    assert.deepEqual(a, snapA);
    assert.notEqual(e.state, a);
    const d = await ratchetDecrypt(b, e.header, e.ciphertext, ad);
    assert.deepEqual(b, snapB);
    assert.equal(utf8Decode(d.plaintext), 'hi');
    // Same input state can be used again (caller didn't persist): same result.
    const d2 = await ratchetDecrypt(b, e.header, e.ciphertext, ad);
    assert.equal(utf8Decode(d2.plaintext), 'hi');
  });

  test('MAX_SKIP: exactly MAX_SKIP skipped is fine, more is rejected', async () => {
    assert.equal(MAX_SKIP, 1000);
    const { a, b, ad } = await newSession();
    const A = party(a, ad), B = party(b, ad);
    let last;
    for (let i = 0; i <= MAX_SKIP + 1; i++) last = await A.send(`m${i}`);
    // last.n = 1001 -> would need 1001 skipped keys
    await assertRejectsUnchanged(B.state, last.header, last.ct, ad, /too many skipped/);
    // A message at n = 1000 needs exactly 1000 skipped keys: accepted.
    const { a: a2, b: b2, ad: ad2 } = await newSession();
    const A2 = party(a2, ad2), B2 = party(b2, ad2);
    let m1000;
    for (let i = 0; i <= MAX_SKIP; i++) m1000 = await A2.send(`m${i}`);
    assert.equal(m1000.header.n, 1000);
    assert.equal(await B2.recv(m1000), 'm1000');
    assert.equal(B2.state.skipped.length, 1000);
  });

  test('MAX_SKIP also applies to the previous-chain length (pn)', async () => {
    const { a, b, ad } = await newSession();
    const A = party(a, ad), B = party(b, ad);
    assert.equal(await B.recv(await A.send('first')), 'first');
    const r = await B.send('reply');
    // Forge a header claiming a huge previous chain on a fresh DH key: must fail
    // before any work is committed.
    const freshDh = b64uEncode((await generateX25519()).pub);
    await assertRejectsUnchanged(A.state, { ...r.header, dh: freshDh, pn: 5000 }, r.ct, ad);
    // Same with the genuine new DH key but an inflated pn (Alice's receiving
    // chain is null here, so the pn check only matters once a chain exists).
    await assertRejectsUnchanged(A.state, { ...r.header, pn: 5000 }, r.ct, ad);
    assert.equal(await A.recv(r), 'reply');
    // Alice's new chain: header.pn tells Bob how long her previous chain was.
    const x = await A.send('new chain');
    assert.equal(x.header.pn, 1);
    await assertRejectsUnchanged(B.state, { ...x.header, pn: B.state.nr + MAX_SKIP + 1 }, x.ct, ad, /too many skipped/);
    assert.equal(await B.recv(x), 'new chain');
    for (let i = 0; i < MAX_SKIP + 2; i++) await A.send(`lost ${i}`);
    const next = await A.send('after-gap'); // same chain, n = 1002
    await assertRejectsUnchanged(B.state, next.header, next.ct, ad, /too many skipped/);
  });

  test('skipped-key store is capped at 2000, oldest evicted', async () => {
    const { a, b, ad } = await newSession();
    const A = party(a, ad), B = party(b, ad);
    const firstLost = [];
    for (let chain = 0; chain < 3; chain++) {
      let lastMsg;
      for (let i = 0; i <= MAX_SKIP; i++) {
        const m = await A.send(`c${chain}-${i}`);
        if (chain === 0 && i < 3) firstLost.push(m);
        lastMsg = m;
      }
      assert.equal(await B.recv(lastMsg), lastMsg.text); // skips 1000 each chain
      assert.equal(await A.recv(await B.send(`ack${chain}`)), `ack${chain}`);
    }
    assert.equal(B.state.skipped.length, 2000);
    // Oldest keys (chain 0) were evicted -> those messages can no longer be read.
    for (const m of firstLost) await assertRejectsUnchanged(B.state, m.header, m.ct, ad);
  });

  test('state survives JSON round trip mid-conversation (incl. skipped keys)', async () => {
    const { a, b, ad } = await newSession();
    const A = party(a, ad), B = party(b, ad);
    const msgs = [];
    for (let i = 0; i < 6; i++) msgs.push(await A.send(`m${i}`));
    assert.equal(await B.recv(msgs[4]), 'm4'); // skip 0..3
    A.state = JSON.parse(JSON.stringify(A.state));
    B.state = JSON.parse(JSON.stringify(B.state));
    assert.equal(B.state.skipped.length, 4);
    assert.equal(await B.recv(msgs[1]), 'm1');
    assert.equal(await A.recv(await B.send('b')), 'b');
    A.state = JSON.parse(JSON.stringify(A.state));
    B.state = JSON.parse(JSON.stringify(B.state));
    assert.equal(await B.recv(await A.send('c')), 'c');
    assert.equal(await B.recv(msgs[5]), 'm5');
    assert.equal(await B.recv(msgs[0]), 'm0');
    for (let i = 0; i < 20; i++) {
      const [S, R] = i % 3 ? [A, B] : [B, A];
      const text = `t${i}`;
      assert.equal(await R.recv(await S.send(text)), text);
      S.state = JSON.parse(JSON.stringify(S.state));
      R.state = JSON.parse(JSON.stringify(R.state));
    }
  });

  test('rejects invalid state objects', async () => {
    const { a, ad } = await newSession();
    await assert.rejects(ratchetEncrypt(null, utf8Encode('x'), ad));
    await assert.rejects(ratchetEncrypt({ ...a, v: 2 }, utf8Encode('x'), ad));
    await assert.rejects(ratchetEncrypt({ ...a, ns: -1 }, utf8Encode('x'), ad));
    await assert.rejects(ratchetEncrypt(a, 'x', ad));
  });
});
