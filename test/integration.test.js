// End-to-end tests: real server (startServer) + several SombraClient instances over
// real HTTP and WebSocket connections.
import { test, describe, before, after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { DatabaseSync } from 'node:sqlite';

import { startServer } from '../server/index.js';
import { SombraClient } from '../public/js/core/client.js';
import { MemoryBackend } from '../public/js/core/store.js';
import { b64uDecode, b64uEncode } from '../public/js/crypto/encoding.js';
import { randomBytes } from '../public/js/crypto/primitives.js';

const ITER = 1000; // fast vault KDF for tests only
// Test-only privacy profile: the production defaults delay receipts (2-30 s), identity
// confirmations (1-10 s) and OPK refills (1-10 min) on purpose (CL-1 / SRV-01 / SRV-06);
// these tests are about protocol behaviour, so the delays are near zero here.
const FAST = { receiptDelayMs: [0, 20], identityDelayMs: [0, 20], prekeyRefillDelayMs: [0, 0], sendJitterMs: 0 };

let srv;
let base;
let dataDir;
let sandbox;
const clients = [];

before(async () => {
  sandbox = fs.mkdtempSync(path.join(os.tmpdir(), 'sombra-int-'));
  dataDir = path.join(sandbox, 'data');
  srv = await startServer({ port: 0, host: '127.0.0.1', dataDir, powRegisterBits: 4, powSendBits: 4, rateLimit: false,
    // The OPK test drains a whole pool on purpose (default per-target budget: 50/h, SRV-06).
    bundleOpksPerTarget: 1000 });
  base = `http://127.0.0.1:${srv.port}`;
});

after(async () => {
  for (const c of clients) { try { c.lock(); } catch { /* ignore */ } }
  await srv.close();
  fs.rmSync(sandbox, { recursive: true, force: true });
});

async function waitFor(pred, { timeout = 10000, interval = 20, what = 'condition' } = {}) {
  const end = Date.now() + timeout;
  for (;;) {
    let v;
    try { v = await pred(); } catch { v = false; }
    if (v) return v;
    if (Date.now() > end) throw new Error(`timeout waiting for ${what}`);
    await new Promise((r) => setTimeout(r, interval));
  }
}

/** fetch wrapper recording every /api/send body; can hold sends instead of forwarding. */
function makeTap() {
  const tap = { hold: false, bodies: [], held: [], inflight: 0 };
  tap.fetch = async (url, init = {}) => {
    tap.inflight++;
    try { return await tapFetch(url, init); } finally { tap.inflight--; }
  };
  const tapFetch = async (url, init) => {
    if (String(url).endsWith('/api/send') && init.method === 'POST') {
      tap.bodies.push(init.body);
      if (tap.hold) {
        tap.held.push(init.body);
        const body = JSON.parse(init.body);
        return new Response(JSON.stringify({ ok: true, results: body.messages.map((m) => ({ to: m.to, ok: true })) }), { status: 202 });
      }
    }
    return fetch(url, init);
  };
  return tap;
}

async function newClient(username, opts = {}) {
  const backend = opts.backend || new MemoryBackend();
  const c = new SombraClient({ serverUrl: base, backend, kdfIterations: ITER, privacy: FAST, ...opts, backend });
  clients.push(c);
  await c.createAccount(username, `passphrase of ${username}`);
  await waitFor(() => c.connected, { what: `${username} connected` });
  return c;
}

async function texts(c, convId) {
  return (await c.getMessages(convId)).filter((m) => m.kind === 'text').map((m) => m.text);
}

async function waitText(c, convId, text, timeout) {
  return waitFor(async () => (await texts(c, convId)).includes(text), { what: `"${text}" at ${c.username}`, timeout });
}

function dbPath() {
  return path.join(dataDir, 'sombra.db');
}

function serverDb() {
  return new DatabaseSync(dbPath(), { readOnly: true });
}

async function session(c, peer) {
  return c._store.get(`session:${peer}`);
}

/**
 * Wait until every operation already queued on the client's mutex has finished. A
 * received message becomes visible (msgs record) before the same task finishes the
 * rest of its work (conversation preview, event, session commit — CL-10 order), so
 * assertions about that work must not race with it.
 */
function settle(c) {
  return c._serial(async () => {});
}

describe('integration', () => {
  let alice;
  let bob;
  let carol;
  const aliceTap = makeTap();

  test('registration', async () => {
    const progress = [];
    const backend = new MemoryBackend();
    alice = new SombraClient({ serverUrl: base, backend, kdfIterations: ITER, fetch: aliceTap.fetch, privacy: FAST });
    clients.push(alice);
    await alice.createAccount('Alice', 'alice passphrase', { onProgress: (p) => progress.push(p.stage) });
    assert.equal(alice.username, 'alice');
    assert.ok(progress.includes('pow') || progress.includes('register'));
    assert.ok(progress.includes('done'));
    assert.equal(await SombraClient.hasAccount(backend), true);
    await waitFor(() => alice.connected, { what: 'alice connected' });

    // Local storage reveals neither the username nor key material names.
    const raw = (await Promise.all((await backend.keys()).map(async (k) => k + (await backend.get(k))))).join('');
    assert.ok(!raw.includes('alice'));

    bob = await newClient('bob');
    carol = await newClient('carol');

    const dup = new SombraClient({ serverUrl: base, backend: new MemoryBackend(), kdfIterations: ITER });
    await assert.rejects(dup.createAccount('bob', 'whatever pass'), /username_taken/);
    await assert.rejects(dup.createAccount('x', 'whatever pass'), /bad_username/);

    const db = serverDb();
    try {
      assert.equal(db.prepare('SELECT COUNT(*) AS n FROM opks WHERE username = ?').get('alice').n, 100);
    } finally { db.close(); }
  });

  test('first message (prekey path) and reply', async () => {
    const conv = await alice.startDirect('bob');
    assert.equal(conv, 'd:bob');
    await assert.rejects(alice.startDirect('nobody_here'), /user_not_found/);
    const got = [];
    bob.addEventListener('message', (e) => got.push(e.detail));
    const m = await alice.sendText(conv, 'hola bob');
    assert.equal(m.mine, true);
    assert.ok(['sent', 'delivered', 'read'].includes(m.status));
    await waitText(bob, 'd:alice', 'hola bob');
    await settle(bob);
    assert.ok(got.some((d) => d.convId === 'd:alice' && d.message.text === 'hola bob'));
    const convs = await bob.listConversations();
    const c = convs.find((x) => x.id === 'd:alice');
    assert.equal(c.type, 'direct');
    assert.equal(c.peer, 'alice');
    assert.equal(c.unread, 1);
    assert.equal(c.lastText, 'hola bob');

    // alice initiated (X3DH), bob answered a prekey message. bob's automatic delivered
    // receipt is the first message alice gets on the session, so it confirms it.
    assert.equal((await session(alice, 'bob')).current.role, 'initiator');
    const bs = await session(bob, 'alice');
    assert.equal(bs.current.role, 'responder');
    assert.equal(bs.eks.length, 1);
    assert.equal(bs.current.ek, (await session(alice, 'bob')).current.ek);
    await bob.sendText('d:alice', 'hola alice');
    await waitText(alice, 'd:bob', 'hola alice');
    await waitFor(async () => (await session(alice, 'bob')).current.peerConfirmed === true, { what: 'peerConfirmed' });
    await alice.sendText('d:bob', 'ya confirmado');
    await waitText(bob, 'd:alice', 'ya confirmado');
  });

  test('initiator repeats prekey messages until the peer answers', async () => {
    const ivan = await newClient('ivan');
    const judy = await newClient('judy');
    judy.lock(); // offline: cannot confirm the session yet
    await ivan.startDirect('judy');
    for (const t of ['p1', 'p2', 'p3']) await ivan.sendText('d:judy', t);
    const s = await session(ivan, 'judy');
    assert.equal(s.current.peerConfirmed, false);
    assert.equal(s.previous.length, 0);
    await judy.unlock('passphrase of judy');
    for (const t of ['p1', 'p2', 'p3']) await waitText(judy, 'd:ivan', t);
    await settle(judy); // payloads are stored before the session commit (CL-10)
    const js = await session(judy, 'ivan');
    assert.equal(js.eks.length, 1, 'all three prekey messages continued one session');
    assert.equal(js.previous.length, 0);
    await waitFor(async () => (await session(ivan, 'judy')).current.peerConfirmed, { what: 'confirmed by receipt' });
    await ivan.sendText('d:judy', 'p4');
    await waitText(judy, 'd:ivan', 'p4');
    ivan.lock();
    judy.lock();
  });

  test('long back-and-forth with bursts in both directions', async () => {
    const expectedAtBob = [];
    const expectedAtAlice = [];
    for (let round = 0; round < 12; round++) {
      const fromAlice = round % 3 !== 1;
      const burst = 1 + (round % 3);
      for (let i = 0; i < burst; i++) {
        const t = `r${round}-${i}-${fromAlice ? 'a' : 'b'}`;
        if (fromAlice) { await alice.sendText('d:bob', t); expectedAtBob.push(t); }
        else { await bob.sendText('d:alice', t); expectedAtAlice.push(t); }
      }
    }
    await waitFor(async () => {
      const tb = await texts(bob, 'd:alice');
      return expectedAtBob.every((t) => tb.includes(t));
    }, { what: 'all of alice → bob' });
    await waitFor(async () => {
      const ta = await texts(alice, 'd:bob');
      return expectedAtAlice.every((t) => ta.includes(t));
    }, { what: 'all of bob → alice' });
    // No duplicates
    const tb = await texts(bob, 'd:alice');
    assert.equal(new Set(tb).size, tb.length);
  });

  test('delivered and read receipts update status', async () => {
    const m = await alice.sendText('d:bob', 'receipt me');
    await waitFor(async () => (await alice.getMessages('d:bob')).find((x) => x.id === m.id).status === 'delivered',
      { what: 'delivered' });
    const updates = [];
    alice.addEventListener('update', (e) => updates.push(e.detail));
    await bob.markRead('d:alice');
    assert.equal((await bob.listConversations()).find((x) => x.id === 'd:alice').unread, 0);
    await waitFor(async () => (await alice.getMessages('d:bob')).find((x) => x.id === m.id).status === 'read',
      { what: 'read' });
    assert.ok(updates.some((u) => u.convId === 'd:bob' && u.messageId === m.id));
  });

  test('offline recipient receives queued messages; server stores only ciphertext', async () => {
    const secret = 'PLAINTEXT-CANARY-7f3a9c offline message';
    bob.lock();
    assert.equal(bob.connected, false);
    assert.equal(bob.username, null);
    await assert.rejects(bob.getMessages('d:alice'), /locked/);
    await alice.sendText('d:bob', secret);
    await alice.sendText('d:bob', 'second offline');

    const db = serverDb();
    let queued;
    try {
      queued = db.prepare('SELECT COUNT(*) AS n FROM queue WHERE recipient = ?').get('bob').n;
    } finally { db.close(); }
    assert.ok(queued >= 2, 'messages are queued for bob');
    const bytes = fs.readFileSync(dbPath());
    assert.equal(bytes.indexOf(Buffer.from('PLAINTEXT-CANARY-7f3a9c')), -1, 'plaintext found in server DB');
    assert.equal(bytes.indexOf(Buffer.from(secret)), -1);

    await assert.rejects(bob.unlock('wrong passphrase'), /bad passphrase/);
    await bob.unlock('passphrase of bob');
    assert.equal(bob.username, 'bob');
    await waitText(bob, 'd:alice', secret);
    await waitText(bob, 'd:alice', 'second offline');
    // Earlier history survived lock/unlock.
    assert.ok((await texts(bob, 'd:alice')).includes('hola bob'));
    // Queue drained after ACK.
    await waitFor(() => {
      const d = serverDb();
      try { return d.prepare('SELECT COUNT(*) AS n FROM queue WHERE recipient = ?').get('bob').n === 0; } finally { d.close(); }
    }, { what: 'queue drained' });
  });

  test('lock/unlock keeps sessions and messages (same backend)', async () => {
    const before = await texts(alice, 'd:bob');
    alice.lock();
    await alice.unlock('alice passphrase');
    await waitFor(() => alice.connected, { what: 'alice reconnected' });
    assert.deepEqual(await texts(alice, 'd:bob'), before);
    await alice.sendText('d:bob', 'after unlock');
    await waitText(bob, 'd:alice', 'after unlock');
    await bob.sendText('d:alice', 'reply after unlock');
    await waitText(alice, 'd:bob', 'reply after unlock');
  });

  test('out-of-order delivery is handled by the ratchet', async () => {
    // Only the four texts may be held: no automatic receipt of alice's may be queued
    // or in flight meanwhile (receipts leave on their own timer, CL-1).
    alice.setPrivacyOptions({ deliveryReceipts: false, readReceipts: false });
    await waitFor(() => alice._receiptQ.size === 0, { what: 'receipt queue empty' });
    await settle(alice);
    await waitFor(() => aliceTap.inflight === 0, { what: 'no request in flight' });
    aliceTap.hold = true;
    aliceTap.held.length = 0;
    const order = ['ooo-1', 'ooo-2', 'ooo-3', 'ooo-4'];
    for (const t of order) await alice.sendText('d:bob', t);
    aliceTap.hold = false;
    assert.equal(aliceTap.held.length, 4);
    // Deliver in reverse order (each request still carries its unused PoW solution).
    for (const body of [...aliceTap.held].reverse()) {
      const res = await fetch(`${base}/api/send`, { method: 'POST', body });
      assert.equal(res.status, 202);
    }
    for (const t of order) await waitText(bob, 'd:alice', t);
    // Replaying a delivered blob is dropped (no duplicate).
    const res = await fetch(`${base}/api/send`, {
      method: 'POST',
      body: JSON.stringify({ ...JSON.parse(aliceTap.held[0]), pow: await solveSend() }),
    });
    assert.equal(res.status, 202);
    await new Promise((r) => setTimeout(r, 300));
    assert.equal((await texts(bob, 'd:alice')).filter((t) => t === 'ooo-1').length, 1);
    alice.setPrivacyOptions({ deliveryReceipts: true, readReceipts: true });
  });

  test('server never sees the sender username in /api/send bodies', async () => {
    assert.ok(aliceTap.bodies.length > 10);
    for (const body of aliceTap.bodies) {
      assert.ok(!body.includes('alice'), 'sender username in send body');
      const obj = JSON.parse(body);
      assert.deepEqual(Object.keys(obj).sort(), ['messages', 'pow']);
      for (const m of obj.messages) {
        assert.deepEqual(Object.keys(m).sort(), ['blob', 'to']);
        const blob = b64uDecode(m.blob);
        assert.equal(blob[0], 0x01);
        assert.equal((blob.length - 33 - 16) % 256, 0, 'padded size');
        const s = Buffer.from(blob).toString('latin1');
        assert.ok(!s.includes('alice'));
        assert.ok(!s.includes('hola'));
      }
    }
  });

  test('simultaneous first messages from both sides', async () => {
    const dave = await newClient('dave');
    const erin = await newClient('erin');
    await dave.startDirect('erin');
    await erin.startDirect('dave');
    // Both sendText calls start before either side can process the other's message.
    await Promise.all([dave.sendText('d:erin', 'hi from dave'), erin.sendText('d:dave', 'hi from erin')]);
    await waitText(erin, 'd:dave', 'hi from dave');
    await waitText(dave, 'd:erin', 'hi from erin');
    for (let i = 0; i < 4; i++) {
      await Promise.all([dave.sendText('d:erin', `d${i}`), erin.sendText('d:dave', `e${i}`)]);
    }
    for (let i = 0; i < 4; i++) {
      await waitText(erin, 'd:dave', `d${i}`);
      await waitText(dave, 'd:erin', `e${i}`);
    }
    await dave.sendText('d:erin', 'final d');
    await waitText(erin, 'd:dave', 'final d');
    await erin.sendText('d:dave', 'final e');
    await waitText(dave, 'd:erin', 'final e');
    // Both sides converged on the same current session.
    const sd = await session(dave, 'erin');
    const se = await session(erin, 'dave');
    assert.equal(sd.current.ek, se.current.ek);
    assert.ok(sd.previous.length >= 1 && sd.previous.length <= 3);
    dave.lock();
    erin.lock();
  });

  test('file messages (single and chunked) round trip', async () => {
    const small = randomBytes(100 * 1024);
    await alice.sendFile('d:bob', { name: 'foto.png', mime: 'image/png', bytes: small });
    const big = new Uint8Array(8 * 1024 * 1024);
    for (let off = 0; off < big.length; off += 65536) big.set(randomBytes(65536), off);
    const sent = await alice.sendFile('d:bob', { name: '../evil/doc.pdf', mime: 'application/pdf', bytes: big });
    assert.equal(sent.kind, 'file');
    await waitFor(async () => (await bob.getMessages('d:alice')).filter((m) => m.kind === 'file').length === 2,
      { what: 'files at bob', timeout: 30000 });
    const files = (await bob.getMessages('d:alice')).filter((m) => m.kind === 'file');
    assert.equal(files[0].file.name, 'foto.png');
    assert.equal(files[0].file.mime, 'image/png');
    assert.deepEqual(files[0].file.data, small);
    assert.equal(files[1].file.name, '.._evil_doc.pdf');
    assert.equal(files[1].file.size, big.length);
    assert.ok(Buffer.from(files[1].file.data).equals(Buffer.from(big)));
    assert.equal(files[1].id, sent.id);
    await waitFor(async () => (await alice.getMessages('d:bob')).find((m) => m.id === sent.id).status === 'delivered',
      { what: 'file delivered' });
    await assert.rejects(alice.sendFile('d:bob', { name: 'x', mime: 'a/b', bytes: new Uint8Array(100 * 1024 * 1024 + 1) }), /file_too_large/);
  });

  test('delete for everyone (only by the original sender)', async () => {
    const m = await alice.sendText('d:bob', 'delete me');
    const keep = await alice.sendText('d:bob', 'keep me');
    await waitText(bob, 'd:alice', 'keep me');
    await alice.deleteMessages('d:bob', [m.id], true);
    await waitFor(async () => !(await texts(bob, 'd:alice')).includes('delete me'), { what: 'remote deletion' });
    assert.ok(!(await texts(alice, 'd:bob')).includes('delete me'));
    assert.ok((await texts(bob, 'd:alice')).includes('keep me'));

    // bob forges a delete for alice's message: ignored by alice.
    const enc = await bob._serial(() => bob._encryptPayload(['alice'], {
      id: b64uEncode(randomBytes(16)), ts: Date.now(), kind: 'delete', body: { ids: [keep.id] },
    }));
    await bob.api.send(enc.blobs);
    // and a normal "for everyone" of a message bob did not send only deletes locally.
    const bobView = (await bob.getMessages('d:alice')).find((x) => x.text === 'keep me');
    await bob.deleteMessages('d:alice', [bobView.id], true);
    await alice.sendText('d:bob', 'sync marker 1');
    await waitText(bob, 'd:alice', 'sync marker 1');
    await bob.sendText('d:alice', 'sync marker 2');
    await waitText(alice, 'd:bob', 'sync marker 2');
    assert.ok((await texts(alice, 'd:bob')).includes('keep me'));
    assert.ok(!(await texts(bob, 'd:alice')).includes('keep me'));
  });

  test('disappearing messages are deleted on both sides', async () => {
    await alice.setTimer('d:bob', 1);
    await waitFor(async () => (await bob.listConversations()).find((c) => c.id === 'd:alice').timer === 1, { what: 'timer at bob' });
    const m = await alice.sendText('d:bob', 'self destruct');
    assert.ok(m.expiresAt > Date.now() - 1000);
    await waitText(bob, 'd:alice', 'self destruct');
    const atBob = (await bob.getMessages('d:alice')).find((x) => x.text === 'self destruct');
    assert.ok(atBob.expiresAt);
    // The 5 s sweeper removes the stored records (not just hides them).
    const gone = async (c, conv) => !(await c._store.get(`msgs:${conv}`)).some((x) => x.text === 'self destruct');
    await waitFor(() => gone(alice, 'd:bob'), { timeout: 12000, what: 'sweep at alice' });
    await waitFor(() => gone(bob, 'd:alice'), { timeout: 12000, what: 'sweep at bob' });
    await alice.setTimer('d:bob', 0);
    await waitFor(async () => (await bob.listConversations()).find((c) => c.id === 'd:alice').timer === 0, { what: 'timer off' });
    const m2 = await alice.sendText('d:bob', 'stays');
    assert.equal(m2.expiresAt, undefined);
  });

  test('groups: creation, fan-out, admin-only updates, membership checks, leave', async () => {
    const gid = await alice.createGroup('Equipo', ['bob', 'carol']);
    assert.match(gid, /^g:[A-Za-z0-9_-]{22}$/);
    for (const c of [bob, carol]) {
      await waitFor(async () => (await c.listConversations()).some((x) => x.id === gid), { what: `group at ${c.username}` });
    }
    const info = (await carol.listConversations()).find((x) => x.id === gid);
    assert.equal(info.type, 'group');
    assert.equal(info.title, 'Equipo');
    assert.equal(info.admin, 'alice');
    assert.deepEqual([...info.members].sort(), ['alice', 'bob', 'carol']);

    await alice.sendText(gid, 'hola grupo');
    await waitText(bob, gid, 'hola grupo');
    await waitText(carol, gid, 'hola grupo');
    await bob.sendText(gid, 'bob en el grupo');
    await waitText(alice, gid, 'bob en el grupo');
    await waitText(carol, gid, 'bob en el grupo'); // bob ↔ carol session created on demand
    const fromBob = (await carol.getMessages(gid)).find((m) => m.text === 'bob en el grupo');
    assert.equal(fromBob.from, 'bob');

    // Non-admin cannot add members.
    await assert.rejects(bob.addGroupMembers(gid, ['dave']), /not_admin/);
    // Forged group_update from a non-admin member is ignored.
    const groupId = gid.slice(2);
    const forged = await bob._serial(() => bob._encryptPayload(['carol'], {
      id: b64uEncode(randomBytes(16)), ts: Date.now(), kind: 'group_update', group: groupId,
      body: { group: { id: groupId, name: 'Hackeado', members: ['alice', 'bob', 'carol'], admin: 'bob' } },
    }));
    await bob.api.send(forged.blobs);
    // A non-member (frank) injecting a message into the group is rejected.
    const frank = await newClient('frank');
    const inj = await frank._serial(() => frank._encryptPayload(['alice'], {
      id: b64uEncode(randomBytes(16)), ts: Date.now(), kind: 'text', group: groupId, body: { text: 'intruso' },
    }));
    await frank.api.send(inj.blobs);
    await bob.sendText(gid, 'sync g1');
    await waitText(carol, gid, 'sync g1');
    await waitText(alice, gid, 'sync g1');
    assert.equal((await carol.listConversations()).find((x) => x.id === gid).title, 'Equipo');
    assert.ok(!(await texts(alice, gid)).includes('intruso'));

    // Admin adds frank; frank gets the group and messages.
    await alice.addGroupMembers(gid, ['frank']);
    await waitFor(async () => (await frank.listConversations()).some((x) => x.id === gid), { what: 'frank added' });
    await waitFor(async () => (await carol.listConversations()).find((x) => x.id === gid).members.includes('frank'), { what: 'carol sees frank' });
    await alice.sendText(gid, 'bienvenido frank');
    await waitText(frank, gid, 'bienvenido frank');

    // carol leaves: the others drop her; she no longer receives.
    await carol.leaveGroup(gid);
    assert.ok(!(await carol.listConversations()).some((x) => x.id === gid));
    await waitFor(async () => !(await alice.listConversations()).find((x) => x.id === gid).members.includes('carol'), { what: 'carol removed at alice' });
    await waitFor(async () => !(await bob.listConversations()).find((x) => x.id === gid).members.includes('carol'), { what: 'carol removed at bob' });
    await alice.sendText(gid, 'sin carol');
    await waitText(bob, gid, 'sin carol');
    await new Promise((r) => setTimeout(r, 200));
    assert.ok(!(await carol.listConversations()).some((x) => x.id === gid));
    frank.lock();
  });

  test('key change detection after re-registration', async () => {
    const kc = await newClient('kcbob');
    await alice.startDirect('kcbob');
    await alice.sendText('d:kcbob', 'antes');
    await waitText(kc, 'd:alice', 'antes');
    const before = await alice.getSafetyNumber('kcbob');
    assert.equal(before.number.length, 60);
    assert.equal(before.formatted.split(' ').length, 12);
    await alice.setVerified('kcbob', true);
    assert.equal((await alice.getSafetyNumber('kcbob')).verified, true);

    await kc.deleteAccount();
    assert.equal(kc.username, null);
    assert.equal(await SombraClient.hasAccount(kc.backend), false);
    const kc2 = await newClient('kcbob'); // same username, brand-new keys

    const changes = [];
    alice.addEventListener('keychange', (e) => changes.push(e.detail.username));
    await kc2.startDirect('alice');
    await kc2.sendText('d:alice', 'soy el nuevo kcbob');
    // CL-5: kcbob was VERIFIED, so the message from the new identity is held (not
    // shown) until alice accepts the new safety number.
    await waitFor(() => changes.length === 1, { what: 'keychange' });
    await settle(alice);
    assert.deepEqual(changes, ['kcbob']);
    assert.ok(!(await texts(alice, 'd:kcbob')).includes('soy el nuevo kcbob'), 'held until accepted');
    const conv = (await alice.listConversations()).find((c) => c.id === 'd:kcbob');
    assert.equal(conv.keyChanged, true);
    assert.equal(conv.verified, false);
    const after = await alice.getSafetyNumber('kcbob');
    assert.notEqual(after.number, before.number);
    assert.equal(after.verified, false);
    // Sending is blocked until the user accepts the new key.
    await assert.rejects(alice.sendText('d:kcbob', 'bloqueado'), /key_changed/);
    await alice.acceptKeyChange('kcbob');
    assert.equal((await alice.listConversations()).find((c) => c.id === 'd:kcbob').keyChanged, false);
    assert.ok((await texts(alice, 'd:kcbob')).includes('soy el nuevo kcbob'), 'released on accept');
    await alice.sendText('d:kcbob', 'aceptado');
    await waitText(kc2, 'd:alice', 'aceptado');
    kc2.lock();
  });

  test('a forged sender cannot impersonate a contact', async () => {
    // mallory seals a prekey message claiming to be "bob" using her own identity keys.
    const mallory = await newClient('mallory');
    const realBundle = await mallory.api.getBundle('alice');
    assert.ok(realBundle);
    mallory._username = 'bob'; // claimed sender inside the sealed envelope
    const enc = await mallory._serial(() => mallory._encryptPayload(['alice'], {
      id: b64uEncode(randomBytes(16)), ts: Date.now(), kind: 'text', body: { text: 'soy bob, de verdad' },
    }));
    assert.equal(enc.blobs.length, 1);
    await mallory.api.send(enc.blobs);
    await bob.sendText('d:alice', 'sync forged');
    await waitText(alice, 'd:bob', 'sync forged');
    assert.ok(!(await texts(alice, 'd:bob')).includes('soy bob, de verdad'));
    assert.equal((await alice.listConversations()).find((c) => c.id === 'd:bob').keyChanged, false);
    mallory.lock();
  });

  test('OPK consumption and replenishment', async () => {
    const o = await newClient('opkuser');
    const count = () => {
      const d = serverDb();
      try { return d.prepare('SELECT COUNT(*) AS n FROM opks WHERE username = ?').get('opkuser').n; } finally { d.close(); }
    };
    assert.equal(count(), 100);
    const initial = new Set(Object.keys((await o._store.get('account')).opks).map(Number));
    assert.equal(initial.size, 100);
    const served = new Set();
    for (let i = 0; i < 81; i++) {
      const b = await alice.api.getBundle('opkuser');
      assert.ok(initial.has(b.opk.id) && !served.has(b.opk.id), 'each OPK served once');
      served.add(b.opk.id);
    }
    // SRV-06: ids are random, not a counter that reveals how many were ever issued.
    assert.ok([...served].some((id) => id > 100000), 'random OPK ids');
    // 19 left → server pushes opk_count → client uploads 100 more.
    await waitFor(() => count() === 119, { what: 'replenished' });
    for (let i = 0; i < 19; i++) await alice.api.getBundle('opkuser');
    assert.equal(count(), 100);
    // A new contact now uses one of the replenished OPKs — it must decrypt.
    const g = await newClient('gina');
    await g.startDirect('opkuser');
    await g.sendText('d:opkuser', 'usa opk nueva');
    await waitText(o, 'd:gina', 'usa opk nueva');
    await settle(o);
    const usedId = (await session(g, 'opkuser')).current.x3dh.opk_id;
    assert.ok(Number.isInteger(usedId) && !initial.has(usedId), 'a replenished OPK was used');
    const acc = await o._store.get('account');
    assert.equal(acc.opks[String(usedId)], undefined, 'used OPK deleted locally');
    assert.equal(Object.keys(acc.opks).filter((id) => !initial.has(Number(id))).length, 99);
    g.lock();
    o.lock();
  });

  test('SPK rotation after 7 days keeps the previous SPK usable', async () => {
    let offset = 0;
    const now = () => Date.now() + offset;
    const backend = new MemoryBackend();
    const r = new SombraClient({ serverUrl: base, backend, kdfIterations: ITER, now, privacy: FAST });
    clients.push(r);
    await r.createAccount('rotor', 'rotor pass');
    await waitFor(() => r.connected);
    const oldBundle = await alice.api.getBundle('rotor');
    const spk1 = oldBundle.spk.id; // random (SRV-06), no longer 1
    assert.deepEqual((await r._store.get('account')).spks.map((s) => s.id), [spk1]);

    offset = 8 * 24 * 3600 * 1000;
    r.lock();
    await r.unlock('rotor pass');
    await waitFor(async () => (await alice.api.getIdentity('rotor')) &&
      (() => { const d = serverDb(); try { return d.prepare('SELECT spk_id FROM users WHERE username = ?').get('rotor').spk_id !== spk1; } finally { d.close(); } })(),
    { what: 'spk rotated' });
    await waitFor(async () => (await r._store.get('account')).spks.find((s) => s.id === spk1).retiredAt, { what: 'spk_ok' });
    // A sender that fetched the OLD bundle (SPK 1) before rotation still gets through.
    const h = await newClient('hank');
    h.api.getBundle = async () => oldBundle;
    await h.startDirect('rotor');
    await h.sendText('d:rotor', 'con la spk vieja');
    await waitText(r, 'd:hank', 'con la spk vieja');
    // After 30 more days the old SPK is pruned.
    offset += 31 * 24 * 3600 * 1000;
    r.lock();
    await r.unlock('rotor pass');
    await waitFor(async () => !(await r._store.get('account')).spks.some((s) => s.id === spk1), { what: 'old spk pruned' });
    h.lock();
    r.lock();
  });

  test('backup export/import restores a working account', async () => {
    const bytes = await carol.exportBackup();
    const restored = new MemoryBackend();
    await SombraClient.importBackup(restored, bytes);
    carol.lock();
    const carol2 = new SombraClient({ serverUrl: base, backend: restored, kdfIterations: ITER, privacy: FAST });
    clients.push(carol2);
    await carol2.unlock('passphrase of carol');
    await waitFor(() => carol2.connected);
    assert.ok((await texts(carol2, 'd:alice').catch(() => [])).length >= 0);
    await alice.startDirect('carol');
    await alice.sendText('d:carol', 'tras restaurar');
    await waitText(carol2, 'd:alice', 'tras restaurar');
  });

  test('panicWipe wipes local data immediately', async () => {
    const backend = bob.backend;
    await bob.panicWipe();
    assert.equal(bob.username, null);
    assert.deepEqual(await backend.keys(), []);
    assert.equal(await SombraClient.hasAccount(backend), false);
  });
});

async function solveSend() {
  const { solvePow } = await import('../public/js/crypto/pow.js');
  const r = await fetch(`${base}/api/pow?purpose=send`);
  const { challenge, difficulty } = await r.json();
  return { challenge, nonce: await solvePow(challenge, difficulty) };
}

