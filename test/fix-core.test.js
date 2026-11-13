// Regression tests for the CORE (public/js/core) audit fixes: CL-1..CL-12, CRYPTO-1..9
// as wired in the client, SRV-01/02/06 (client side), CRYPTO-7 (server registration
// proof of possession), BUG-2 and the new UI error codes. Each test reproduces the
// audited attack against a real server (startServer, port 0) and real SombraClients.
import { test, describe, before, after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { DatabaseSync } from 'node:sqlite';

import { startServer } from '../server/index.js';
import { loadConfig } from '../server/config.js';
import { sendPowExtraBits, leadingZeroBits, powHash } from '../server/pow.js';
import { sendPowExtraBits as clientExtraBits } from '../public/js/core/api.js';
import { SombraClient } from '../public/js/core/client.js';
import { MemoryBackend } from '../public/js/core/store.js';
import { IdbBackend } from '../public/js/core/idbstore.js';
import { b64uDecode, b64uEncode, utf8Encode, utf8Decode, concatBytes } from '../public/js/crypto/encoding.js';
import { randomBytes, ed25519Sign, generateX25519 } from '../public/js/crypto/primitives.js';
import { seal, unseal } from '../public/js/crypto/sealed.js';
import { generateIdentity, publicIdentity, generateSignedPrekey } from '../public/js/crypto/x3dh.js';
import { solvePow } from '../public/js/crypto/pow.js';
import { pad } from '../public/js/crypto/padding.js';
import { errorText } from '../public/js/ui/errors.js';

const ITER = 1000; // fast vault KDF for tests only
const DAY = 24 * 3600 * 1000;
// Test-only privacy profile (production defaults delay these on purpose, see CL-1 tests).
const FAST = { receiptDelayMs: [0, 20], identityDelayMs: [0, 20], prekeyRefillDelayMs: [0, 0], sendJitterMs: 0 };

let srv;
let base;
let dataDir;
let sandbox;
const clients = [];

before(async () => {
  sandbox = fs.mkdtempSync(path.join(os.tmpdir(), 'sombra-core-'));
  dataDir = path.join(sandbox, 'data');
  srv = await startServer({
    port: 0, host: '127.0.0.1', dataDir, powRegisterBits: 4, powSendBits: 4, rateLimit: false,
    bundleOpksPerTarget: 1000, // the SRV-06 refill test drains a pool on purpose
  });
  base = `http://127.0.0.1:${srv.port}`;
});

after(async () => {
  for (const c of clients) { try { c.lock(); } catch { /* ignore */ } }
  await srv.close();
  fs.rmSync(sandbox, { recursive: true, force: true });
});

// ---------------------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------------------

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function waitFor(pred, { timeout = 10000, interval = 20, what = 'condition' } = {}) {
  const end = Date.now() + timeout;
  for (;;) {
    let v;
    try { v = await pred(); } catch { v = false; }
    if (v) return v;
    if (Date.now() > end) throw new Error(`timeout waiting for ${what}`);
    await sleep(interval);
  }
}

function pass(name) {
  return `passphrase of ${name}`;
}

async function newClient(username, opts = {}) {
  const backend = opts.backend || new MemoryBackend();
  const c = new SombraClient({ serverUrl: base, backend, kdfIterations: ITER, privacy: FAST, ...opts, backend });
  clients.push(c);
  await c.createAccount(username, pass(username));
  await waitFor(() => c.connected, { what: `${username} connected` });
  return c;
}

/** Wait until every operation already queued on the client's mutex has finished. */
function settle(c) {
  return c._serial(async () => {});
}

async function texts(c, convId) {
  return (await c.getMessages(convId)).filter((m) => m.kind === 'text').map((m) => m.text);
}

async function waitText(c, convId, text, timeout) {
  return waitFor(async () => (await texts(c, convId)).includes(text), { what: `"${text}" at ${c.username}`, timeout });
}

function nid() {
  return b64uEncode(randomBytes(16));
}

/** A (possibly malicious) client sends an arbitrary app payload to `to` (array). */
async function rawSend(c, to, payload) {
  const enc = await c._serial(() => c._encryptPayload(to, payload));
  return c._sendControlNow(enc);
}

/** fetch wrapper: logs every request, can hold /api/send POSTs (answered as accepted). */
function makeTap() {
  const tap = { hold: false, log: [], held: [], inflight: 0 };
  tap.fetch = async (url, init = {}) => {
    tap.inflight++;
    try {
      const u = String(url);
      tap.log.push({ t: Date.now(), url: u, method: init.method || 'GET', body: init.body });
      if (u.endsWith('/api/send') && init.method === 'POST' && tap.hold) {
        tap.held.push(init.body);
        const body = JSON.parse(init.body);
        return new Response(JSON.stringify({ ok: true, results: body.messages.map((m) => ({ to: m.to, ok: true })) }), { status: 202 });
      }
      return await fetch(url, init);
    } finally {
      tap.inflight--;
    }
  };
  return tap;
}

async function postBody(body) {
  const r = await fetch(`${base}/api/send`, { method: 'POST', headers: { 'content-type': 'application/json' }, body });
  assert.equal(r.status, 202);
}

/** Record every sealed blob `c` receives (before it is processed). */
function captureIncoming(c) {
  const blobs = [];
  const orig = c._receiveBlob.bind(c);
  c._receiveBlob = (blob) => { blobs.push(blob); return orig(blob); };
  return blobs;
}

async function openBlob(c, blob) {
  const { from, inner } = await unseal(c._identity.dh, b64uDecode(blob));
  return { from, wire: JSON.parse(utf8Decode(inner)) };
}

/** Seal an inner wire message to `toClient` claiming sender `from` (anyone can). */
async function sealAs(from, toClient, wire) {
  return b64uEncode(await seal(from, b64uDecode(toClient._pubId.ik_dh), utf8Encode(JSON.stringify(wire))));
}

async function x25519Pub() {
  return b64uEncode((await generateX25519()).pub);
}

function serverDb() {
  return new DatabaseSync(path.join(dataDir, 'sombra.db'), { readOnly: true });
}

function serverOpkIds(username) {
  const d = serverDb();
  try {
    return d.prepare('SELECT id FROM opks WHERE username = ?').all(username).map((r) => Number(r.id));
  } finally { d.close(); }
}

function identityOf(c) {
  return { username: c.username, ik_sig: c._pubId.ik_sig, ik_dh: c._pubId.ik_dh, ik_dh_sig: c._pubId.ik_dh_sig };
}

/** fetch that answers /api/identity/<name> with `table[name]` when set (malicious server). */
function identityOverride(table) {
  return async (url, init) => {
    const m = /\/api\/identity\/([^/?]+)$/.exec(String(url));
    if (m && table[m[1]]) {
      return new Response(JSON.stringify({ ...table[m[1]], username: m[1] }), { status: 200, headers: { 'content-type': 'application/json' } });
    }
    return fetch(url, init);
  };
}

async function contactOf(c, username) {
  const contacts = await c._store.get('contacts');
  return Object.prototype.hasOwnProperty.call(contacts, username) ? contacts[username] : undefined;
}

/** A complete, validly signed registration payload (without pow). */
async function regPayload(name, { identity, ikDhOverride } = {}) {
  const id = identity || await generateIdentity();
  const pub = await publicIdentity(id);
  let ikDh = pub.ik_dh;
  let ikDhSig = pub.ik_dh_sig;
  if (ikDhOverride) {
    ikDh = ikDhOverride;
    ikDhSig = b64uEncode(await ed25519Sign(id.sig, concatBytes(utf8Encode('SOMBRA-IKDH-v1'), b64uDecode(ikDh))));
  }
  const spk = await generateSignedPrekey(id, 7);
  const n = utf8Encode(name);
  const regMsg = concatBytes(utf8Encode('SOMBRA-REG-v1'), new Uint8Array([n.length]), n, b64uDecode(ikDh));
  return {
    username: name, ik_sig: pub.ik_sig, ik_dh: ikDh, ik_dh_sig: ikDhSig,
    reg_sig: b64uEncode(await ed25519Sign(id.sig, regMsg)),
    spk: { id: spk.id, pub: spk.pub, sig: spk.sig },
    opks: [{ id: 1, pub: await x25519Pub() }],
  };
}

async function registerRaw(payload) {
  const { challenge, difficulty } = await (await fetch(`${base}/api/pow?purpose=register`)).json();
  const nonce = await solvePow(challenge, difficulty);
  const r = await fetch(`${base}/api/register`, {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ ...payload, pow: { challenge, nonce } }),
  });
  let json = null;
  try { json = await r.json(); } catch { /* empty */ }
  return { status: r.status, json };
}

/** Count WebCrypto HMAC/sign calls made while `fn` runs (ratchet chain steps use them). */
// Counts WebCrypto key-derivation work (sign / deriveBits / importKey). Since VC-4 the
// chain step is a synchronous HMAC, so skipped-key derivation itself no longer shows up
// here; the DH ratchet step (X25519 + HKDF) still does, which is what proves that work
// was (or was not) started for a forged header.
async function countSignCalls(fn) {
  const s = globalThis.crypto.subtle;
  const proto = Object.getPrototypeOf(s);
  let n = 0;
  for (const name of ['sign', 'deriveBits', 'importKey']) {
    const orig = proto[name];
    s[name] = function (...a) { n++; return orig.apply(this, a); };
  }
  try { await fn(); } catch { /* expected drops */ } finally { delete s.sign; delete s.deriveBits; delete s.importKey; }
  return n;
}

// ---------------------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------------------

describe('CL-1 / SRV-01: receive path does not reveal the sealed sender', () => {
  test('production defaults delay receipts and identity lookups', () => {
    const d = new SombraClient({ serverUrl: base });
    assert.ok(d._privacy.receiptDelayMs[0] >= 2000, 'receipt delay min');
    assert.ok(d._privacy.receiptDelayMs[1] >= 30000, 'receipt delay max');
    assert.ok(d._privacy.identityDelayMs[0] >= 1000, 'identity delay min');
    assert.equal(d._privacy.deliveryReceipts, true);
  });

  test('no /api/identity or receipt POST right after a delivery; receipts are optional', async () => {
    const DELAY = 1200;
    const tap = makeTap();
    const bob = await newClient('cl1_bob', { fetch: tap.fetch, privacy: { ...FAST, receiptDelayMs: [DELAY, DELAY], identityDelayMs: [DELAY, DELAY] } });
    const alice = await newClient('cl1_alice');
    let deliveredAt = 0;
    const orig = bob._onSocketMessage.bind(bob);
    bob._onSocketMessage = (m, gen) => { if (!deliveredAt) deliveredAt = Date.now(); orig(m, gen); };
    tap.log.length = 0;
    await alice.startDirect('cl1_bob');
    const m = await alice.sendText('d:cl1_bob', 'hola');
    await waitText(bob, 'd:cl1_alice', 'hola');
    await waitFor(async () => (await alice.getMessages('d:cl1_bob')).find((x) => x.id === m.id).status === 'delivered',
      { what: 'delivered receipt' });
    const lookup = tap.log.find((e) => e.url.endsWith('/api/identity/cl1_alice'));
    const send = tap.log.find((e) => e.url.endsWith('/api/send') && e.method === 'POST');
    assert.ok(deliveredAt > 0 && lookup && send);
    // Old behaviour: identity GET ~2 ms and receipt POST ~12 ms after the push.
    assert.ok(lookup.t - deliveredAt >= DELAY - 50, `identity lookup ${lookup.t - deliveredAt} ms after delivery`);
    assert.ok(send.t - deliveredAt >= 2 * DELAY - 100, `receipt ${send.t - deliveredAt} ms after delivery`);

    // Receipts can be switched off entirely.
    bob.setPrivacyOptions({ deliveryReceipts: false, readReceipts: false, receiptDelayMs: [0, 0] });
    tap.log.length = 0;
    await alice.sendText('d:cl1_bob', 'sin acuse');
    await waitText(bob, 'd:cl1_alice', 'sin acuse');
    await bob.markRead('d:cl1_alice');
    await sleep(300);
    assert.equal(tap.log.filter((e) => e.url.endsWith('/api/send')).length, 0, 'no receipt sent');
    alice.lock();
    bob.lock();
  });
});

describe('SRV-02 / CL-8: group fan-out', () => {
  test('one /api/send request per recipient, never the member list in one POST', async () => {
    const tap = makeTap();
    const carol = await newClient('srv2_carol', { fetch: tap.fetch });
    const others = [await newClient('srv2_a'), await newClient('srv2_b'), await newClient('srv2_d')];
    const gid = await carol.createGroup('Fan-out', others.map((c) => c.username));
    for (const c of others) await waitFor(async () => (await c.listConversations()).some((x) => x.id === gid), { what: 'group' });
    await waitFor(() => tap.inflight === 0);
    tap.log.length = 0;
    await carol.sendText(gid, 'a todos');
    const sends = tap.log.filter((e) => e.url.endsWith('/api/send') && e.method === 'POST');
    assert.equal(sends.length, 3);
    const to = sends.map((e) => JSON.parse(e.body).messages);
    assert.ok(to.every((ms) => ms.length === 1), 'one recipient per request');
    assert.deepEqual(to.map((ms) => ms[0].to).sort(), ['srv2_a', 'srv2_b', 'srv2_d']);
    for (const c of others) await waitText(c, gid, 'a todos');
    for (const c of [carol, ...others]) c.lock();
  });
});

describe('CL-2 / CL-11: per-sender message identity', () => {
  test('a group member cannot overwrite or delete another member\'s (chunked) file', async () => {
    const alice = await newClient('cl2_alice');
    const bob = await newClient('cl2_bob');
    const mal = await newClient('cl2_mal');
    const gid = await alice.createGroup('Contratos', ['cl2_bob', 'cl2_mal']);
    const raw = gid.slice(2);
    for (const c of [bob, mal]) await waitFor(async () => (await c.listConversations()).some((x) => x.id === gid), { what: 'group' });
    const big = new Uint8Array(3 * 1024 * 1024 + 10); // two chunks
    for (let off = 0; off < big.length; off += 65536) big.set(randomBytes(Math.min(65536, big.length - off)), off);
    const sent = await alice.sendFile(gid, { name: 'contrato.pdf', mime: 'application/pdf', bytes: big });
    await waitFor(async () => (await bob.getMessages(gid)).some((m) => m.kind === 'file'), { what: 'file at bob', timeout: 30000 });
    await waitFor(async () => (await mal.getMessages(gid)).some((m) => m.kind === 'file'), { what: 'file at mal', timeout: 30000 });

    // mallory reuses the fid (= alice's message id) for her own one-shot file ...
    const evil = utf8Encode('IBAN: ES00 MALLORY');
    await rawSend(mal, ['cl2_bob'], {
      id: sent.id, ts: Date.now(), kind: 'file', group: raw,
      body: { name: 'contrato.pdf', mime: 'application/pdf', size: evil.length, data: b64uEncode(evil) },
    });
    await waitFor(async () => (await bob.getMessages(gid)).filter((m) => m.kind === 'file').length === 2, { what: 'second file' });
    let files = (await bob.getMessages(gid)).filter((m) => m.kind === 'file');
    const fromAlice = files.find((m) => m.from === 'cl2_alice');
    const fromMal = files.find((m) => m.from === 'cl2_mal');
    assert.ok(Buffer.from(fromAlice.file.data).equals(Buffer.from(big)), 'alice\'s bytes intact');
    assert.deepEqual(fromMal.file.data, evil);
    assert.notEqual(fromMal.id, fromAlice.id, 'local ids are unique per conversation');

    // ... then "deletes for everyone" the shared id: only her own message goes.
    await rawSend(mal, ['cl2_bob'], { id: nid(), ts: Date.now(), kind: 'delete', group: raw, body: { ids: [sent.id] } });
    await waitFor(async () => !(await bob.getMessages(gid)).some((m) => m.from === 'cl2_mal' && m.kind === 'file'), { what: 'mal deletion' });
    files = (await bob.getMessages(gid)).filter((m) => m.kind === 'file');
    assert.equal(files.length, 1);
    assert.equal(files[0].from, 'cl2_alice');
    assert.ok(Buffer.from(files[0].file.data).equals(Buffer.from(big)), 'alice\'s bytes survive');
    // alice's own delete still works (matched by her id).
    await alice.deleteMessages(gid, [sent.id], true);
    await waitFor(async () => !(await bob.getMessages(gid)).some((m) => m.kind === 'file'), { what: 'alice deletion' });
    for (const c of [alice, bob, mal]) c.lock();
  });

  test('a member who learns a message id first cannot suppress the genuine message', async () => {
    const tap = makeTap();
    const alice = await newClient('cl11_alice', { fetch: tap.fetch });
    const bob = await newClient('cl11_bob');
    const mal = await newClient('cl11_mal');
    const gid = await alice.createGroup('Dedup', ['cl11_bob', 'cl11_mal']);
    for (const c of [bob, mal]) await waitFor(async () => (await c.listConversations()).some((x) => x.id === gid), { what: 'group' });
    await waitFor(() => tap.inflight === 0);
    tap.hold = true; // the "server" delays alice's message
    const m = await alice.sendText(gid, 'genuino');
    tap.hold = false;
    assert.equal(tap.held.length, 2);
    await rawSend(mal, ['cl11_bob'], { id: m.id, ts: Date.now(), kind: 'text', group: gid.slice(2), body: { text: 'falso' } });
    await waitText(bob, gid, 'falso');
    for (const body of tap.held) await postBody(body);
    await waitText(bob, gid, 'genuino');
    const msgs = (await bob.getMessages(gid)).filter((x) => x.kind === 'text');
    assert.equal(msgs.find((x) => x.text === 'genuino').from, 'cl11_alice');
    assert.equal(msgs.find((x) => x.text === 'falso').from, 'cl11_mal');
    for (const c of [alice, bob, mal]) c.lock();
  });
});

describe('CL-3 / CRYPTO-4: backup restore', () => {
  test('restored state never re-encrypts with used keys; both directions work; OPK pool replaced', async () => {
    const alice = await newClient('cl3_alice');
    const bob = await newClient('cl3_bob');
    const seen = captureIncoming(bob);
    await alice.startDirect('cl3_bob');
    await alice.sendText('d:cl3_bob', 'a1');
    await waitText(bob, 'd:cl3_alice', 'a1');
    await bob.sendText('d:cl3_alice', 'b1');
    await waitText(alice, 'd:cl3_bob', 'b1');
    const backup = await alice.exportBackup();

    await alice.sendText('d:cl3_bob', 'SECRET: attack at dawn!!');
    await waitText(bob, 'd:cl3_alice', 'SECRET: attack at dawn!!');
    await bob.sendText('d:cl3_alice', 'b2');
    await waitText(alice, 'd:cl3_bob', 'b2');
    // OPKs uploaded AFTER the backup: their private keys are not in it.
    await alice._serial(() => alice._replenishOpks());
    await waitFor(() => serverOpkIds('cl3_alice').length >= 150, { what: 'extra OPKs uploaded' });
    alice.lock();

    const restored = new MemoryBackend();
    await SombraClient.importBackup(restored, backup);
    const alice2 = new SombraClient({ serverUrl: base, backend: restored, kdfIterations: ITER, privacy: FAST });
    clients.push(alice2);
    await alice2.unlock(pass('cl3_alice'));
    await waitFor(() => alice2.connected);
    await alice2.sendText('d:cl3_bob', 'hello from restored dev');
    await waitText(bob, 'd:cl3_alice', 'hello from restored dev');
    await bob.sendText('d:cl3_alice', 'b3');
    await waitText(alice2, 'd:cl3_bob', 'b3');

    // No (ratchet key, n) — i.e. no AES-GCM key+IV — was ever used twice by alice.
    const pairs = [];
    for (const blob of seen) {
      const { from, wire } = await openBlob(bob, blob);
      if (from === 'cl3_alice') pairs.push(`${wire.header.dh}|${wire.header.n}`);
    }
    assert.ok(pairs.length >= 3);
    assert.equal(new Set(pairs).size, pairs.length, 'header (dh, n) reused after restore');

    // The server's OPK pool was replaced by keys the restored device holds.
    await waitFor(async () => !(await alice2._store.get('account')).replaceOpks, { what: 'opks_replaced' });
    const local = (await alice2._store.get('account')).opks;
    const ids = serverOpkIds('cl3_alice');
    assert.equal(ids.length, 100);
    assert.ok(ids.every((id) => local[String(id)]), 'every served OPK is decryptable');
    // A brand-new contact (uses one of those OPKs) reaches the restored device.
    const carol = await newClient('cl3_carol');
    await carol.startDirect('cl3_alice');
    await carol.sendText('d:cl3_alice', 'hola restaurada');
    await waitText(alice2, 'd:cl3_carol', 'hola restaurada');
    for (const c of [alice2, bob, carol]) c.lock();
  });
});

describe('CL-4: group-id squatting', () => {
  test('a member cannot "create" a known gid on someone else; the real admin stays in control', async () => {
    const alice = await newClient('cl4_alice');
    const mal = await newClient('cl4_mal');
    const carol = await newClient('cl4_carol');
    const bob = await newClient('cl4_bob');
    const eve = await newClient('cl4_eve');
    const gid = await alice.createGroup('Junta directiva', ['cl4_mal', 'cl4_carol']);
    const raw = gid.slice(2);
    await waitFor(async () => (await mal.listConversations()).some((x) => x.id === gid), { what: 'group at mal' });
    const members = ['cl4_mal', 'cl4_alice', 'cl4_carol', 'cl4_bob', 'cl4_eve'];
    // Squat with a made-up creator binding, and in the legacy (unbound) form.
    await rawSend(mal, ['cl4_bob'], {
      id: nid(), ts: Date.now(), kind: 'group_update', group: raw,
      body: { group: { id: raw, name: 'Junta directiva', members, admin: 'cl4_mal', creator: 'cl4_mal', salt: nid() } },
    });
    await rawSend(mal, ['cl4_bob'], {
      id: nid(), ts: Date.now(), kind: 'group_update', group: raw,
      body: { group: { id: raw, name: 'Junta directiva', members, admin: 'cl4_mal' } },
    });
    await rawSend(mal, ['cl4_bob'], { id: nid(), ts: Date.now(), kind: 'text', body: { text: 'sync4' } });
    await waitText(bob, 'd:cl4_mal', 'sync4');
    await settle(bob);
    assert.ok(!(await bob.listConversations()).some((x) => x.id === gid), 'squatted creation ignored');

    await alice.addGroupMembers(gid, ['cl4_bob']);
    await waitFor(async () => (await bob.listConversations()).some((x) => x.id === gid), { what: 'bob added' });
    const view = (await bob.listConversations()).find((x) => x.id === gid);
    assert.equal(view.admin, 'cl4_alice');
    assert.ok(!view.members.includes('cl4_eve'));
    await bob.sendText(gid, 'confidencial: cifras Q3');
    await waitText(alice, gid, 'confidencial: cifras Q3');
    await waitText(carol, gid, 'confidencial: cifras Q3');
    await sleep(200);
    assert.ok(!(await eve.listConversations()).some((x) => x.id === gid), 'outsider never received it');
    for (const c of [alice, mal, carol, bob, eve]) c.lock();
  });
});

describe('CL-5 / CRYPTO-5: identity changes', () => {
  test('forged prekey with an undecryptable body changes nothing (no lookup, no downgrade)', async () => {
    const table = {};
    const tap = makeTap();
    const lookups = () => tap.log.filter((e) => e.url.endsWith('/api/identity/cl5a_alice')).length;
    const bobFetch = async (url, init) => { tap.log.push({ url: String(url) }); return identityOverride(table)(url, init); };
    const alice = await newClient('cl5a_alice');
    const bob = await newClient('cl5a_bob', { fetch: bobFetch });
    const mal = await newClient('cl5a_mal');
    await bob.startDirect('cl5a_alice');
    await bob.sendText('d:cl5a_alice', 'hola alice');
    await waitText(alice, 'd:cl5a_bob', 'hola alice');
    await alice.sendText('d:cl5a_bob', 'hola bob');
    await waitText(bob, 'd:cl5a_alice', 'hola bob');
    await bob.setVerified('cl5a_alice', true);
    const ekBefore = (await bob._store.get('session:cl5a_alice')).current.ek;

    table.cl5a_alice = identityOf(mal); // the "server" would confirm the attacker identity
    const n0 = lookups();
    const spkId = (await bob._store.get('account')).spks.at(-1).id;
    const wire = {
      v: 1, type: 'prekey',
      x3dh: { ik_sig: mal._pubId.ik_sig, ik_dh: mal._pubId.ik_dh, ik_dh_sig: mal._pubId.ik_dh_sig, ek: await x25519Pub(), spk_id: spkId, opk_id: null },
      header: { dh: await x25519Pub(), pn: 0, n: 0 },
      ct: b64uEncode(randomBytes(80)),
    };
    await mal.api.send([{ to: 'cl5a_bob', blob: await sealAs('cl5a_alice', bob, wire) }]);
    await alice.sendText('d:cl5a_bob', 'genuino 1');
    await waitText(bob, 'd:cl5a_alice', 'genuino 1');
    await settle(bob);
    const conv = (await bob.listConversations()).find((c) => c.id === 'd:cl5a_alice');
    assert.equal(conv.verified, true);
    assert.equal(conv.keyChanged, false);
    assert.equal(lookups(), n0, 'no identity lookup for an unauthenticated message');
    assert.equal((await contactOf(bob, 'cl5a_alice')).ik_sig, alice._pubId.ik_sig);
    assert.equal((await bob._store.get('session:cl5a_alice')).current.ek, ekBefore, 'sessions were not wiped');
    await bob.sendText('d:cl5a_alice', 'sigo funcionando');
    await waitText(alice, 'd:cl5a_bob', 'sigo funcionando');
    for (const c of [alice, bob, mal]) c.lock();
  });

  test('a VERIFIED contact\'s changed identity is held out of the chat until the user accepts it', async () => {
    const table = {};
    const alice = await newClient('cl5_alice');
    const bob = await newClient('cl5_bob', { fetch: identityOverride(table) });
    const mal = await newClient('cl5_mal');
    await bob.startDirect('cl5_alice');
    await bob.sendText('d:cl5_alice', 'hola alice');
    await waitText(alice, 'd:cl5_bob', 'hola alice');
    await bob.setVerified('cl5_alice', true);

    const changes = [];
    bob.addEventListener('keychange', (e) => changes.push(e.detail.username));
    table.cl5_alice = identityOf(mal); // malicious server confirms the attacker's keys
    mal._username = 'cl5_alice';
    await rawSend(mal, ['cl5_bob'], { id: nid(), ts: Date.now(), kind: 'text', body: { text: 'Soy Alice: transfiere 5000 EUR a ES00 MAL' } });
    await waitFor(() => changes.length === 1, { what: 'keychange' });
    await settle(bob);
    assert.ok(!(await texts(bob, 'd:cl5_alice')).some((t) => t.includes('5000 EUR')), 'impersonation shown in a verified chat');
    const sys = (await bob.getMessages('d:cl5_alice')).filter((m) => m.kind === 'system').map((m) => m.text).join('\n');
    assert.match(sys, /retenidos/);
    const conv = (await bob.listConversations()).find((c) => c.id === 'd:cl5_alice');
    assert.equal(conv.keyChanged, true);
    assert.equal(conv.verified, false);
    await assert.rejects(bob.sendText('d:cl5_alice', 'no'), /key_changed/);
    // Only an explicit user decision releases what was held.
    await bob.acceptKeyChange('cl5_alice');
    assert.ok((await texts(bob, 'd:cl5_alice')).some((t) => t.includes('5000 EUR')));
    assert.equal((await contactOf(bob, 'cl5_alice')).hold, false);
    for (const c of [alice, bob, mal]) c.lock();
  });
});

describe('CL-6 / CRYPTO-6: prototype-colliding usernames', () => {
  test('reserved names cannot be registered (client and server)', async () => {
    const c = new SombraClient({ serverUrl: base, backend: new MemoryBackend(), kdfIterations: ITER });
    for (const name of ['__proto__', 'constructor', 'prototype']) {
      await assert.rejects(c.createAccount(name, 'pw'), /bad_username/);
    }
    assert.equal((await registerRaw(await regPayload('constructor'))).status, 400);
    assert.equal((await registerRaw(await regPayload('__proto__'))).status, 400);
    assert.equal((await registerRaw(await regPayload('constructor_ok'))).status, 201);
  });

  test('a peer named __proto__ / constructor (malicious server) is pinned normally, no pollution', async () => {
    const table = {};
    const bob = await newClient('cl6_bob', { fetch: identityOverride(table) });
    let i = 0;
    for (const name of ['__proto__', 'constructor']) {
      const mal = await newClient(`cl6_mal${i++}`);
      table[name] = identityOf(mal);
      mal._username = name;
      const changes = [];
      bob.addEventListener('keychange', (e) => changes.push(e.detail.username));
      await rawSend(mal, ['cl6_bob'], { id: nid(), ts: Date.now(), kind: 'text', body: { text: `hola 1 ${name}` } });
      await rawSend(mal, ['cl6_bob'], { id: nid(), ts: Date.now(), kind: 'text', body: { text: `hola 2 ${name}` } });
      await waitText(bob, `d:${name}`, `hola 2 ${name}`);
      assert.ok((await texts(bob, `d:${name}`)).includes(`hola 1 ${name}`));
      assert.deepEqual(changes, [], 'no spurious key change');
      assert.ok(await contactOf(bob, name), 'pinned as an own property');
      assert.equal((await bob.getSafetyNumber(name)).number.length, 60);
      await bob.setVerified(name, true);
      assert.equal(({}).verified, undefined, 'Object.prototype polluted');
      assert.equal(Object.prototype.keyChanged, undefined);
      assert.equal((await bob.getSafetyNumber(name)).verified, true);
      mal.lock();
    }
    bob.lock();
    await bob.unlock(pass('cl6_bob'));
    assert.ok(await contactOf(bob, '__proto__'), 'persisted across lock/unlock');
    bob.lock();
  });
});

describe('CL-7: storage quotas against strangers', () => {
  test('in-flight chunked files per sender and group creations per creator are bounded', async () => {
    const bob = await newClient('cl7_bob');
    const mal = await newClient('cl7_mal');
    await rawSend(mal, ['cl7_bob'], { id: nid(), ts: Date.now(), kind: 'text', body: { text: 'hola' } });
    await waitText(bob, 'd:cl7_mal', 'hola');
    for (let i = 0; i < 5; i++) {
      const data = randomBytes(10);
      await rawSend(mal, ['cl7_bob'], {
        id: nid(), ts: Date.now(), kind: 'file',
        body: { name: `f${i}`, mime: 'application/octet-stream', size: 20, data: b64uEncode(data), part: { fid: nid(), i: 0, n: 2 } },
      });
    }
    await rawSend(mal, ['cl7_bob'], { id: nid(), ts: Date.now(), kind: 'text', body: { text: 'sync7' } });
    await waitText(bob, 'd:cl7_mal', 'sync7');
    await settle(bob);
    const index = await bob._store.get('fparts');
    assert.equal(Object.values(index).filter((e) => e.from === 'cl7_mal').length, 2, 'in-flight files per sender');

    for (let i = 0; i < 34; i++) await mal.createGroup(`spam ${i}`, ['cl7_bob']);
    await rawSend(mal, ['cl7_bob'], { id: nid(), ts: Date.now(), kind: 'text', body: { text: 'sync7b' } });
    await waitText(bob, 'd:cl7_mal', 'sync7b', 30000);
    await settle(bob);
    const groups = (await bob.listConversations()).filter((c) => c.type === 'group');
    assert.equal(groups.length, 32, 'groups per creator');
    bob.lock();
    mal.lock();
  });
});

describe('CL-9: lock during unlock / account creation', () => {
  test('a lock() while unlock() or createAccount() is in flight wins', async () => {
    const backend = new MemoryBackend();
    const c = new SombraClient({ serverUrl: base, backend, kdfIterations: ITER, privacy: FAST });
    clients.push(c);
    await c.createAccount('cl9_user', 'pw cl9');
    await waitFor(() => c.connected);
    c.lock();
    const p = c.unlock('pw cl9');
    c.lock();
    await assert.rejects(p, /locked/);
    await sleep(100);
    assert.equal(c.unlocked, false);
    assert.equal(c.connected, false);
    assert.equal(c._identity, null);
    await c.unlock('pw cl9'); // still usable afterwards
    await waitFor(() => c.connected);
    c.lock();

    const c2 = new SombraClient({ serverUrl: base, backend: new MemoryBackend(), kdfIterations: ITER, privacy: FAST });
    clients.push(c2);
    const p2 = c2.createAccount('cl9_user2', 'pw');
    c2.lock();
    await assert.rejects(p2, /locked/);
    assert.equal(c2.unlocked, false);
    assert.equal(c2.connected, false);
  });
});

describe('CL-10: ratchet state vs. payload persistence', () => {
  test('a lock between storing the message and committing the ratchet loses nothing', async () => {
    const alice = await newClient('cl10_alice');
    const backend = new MemoryBackend();
    const bob = await newClient('cl10_bob', { backend });
    await alice.startDirect('cl10_bob');
    await alice.sendText('d:cl10_bob', 'm1');
    await waitText(bob, 'd:cl10_alice', 'm1');
    await bob.sendText('d:cl10_alice', 'ok');
    await waitText(alice, 'd:cl10_bob', 'ok');
    await settle(bob);
    const orig = bob._deliverPayload.bind(bob);
    bob._deliverPayload = async (...a) => { await orig(...a); bob.lock(); };
    await alice.sendText('d:cl10_bob', 'm2 (important)');
    await waitFor(() => !bob.unlocked, { what: 'bob locked mid-receive' });

    const bob2 = new SombraClient({ serverUrl: base, backend, kdfIterations: ITER, privacy: FAST });
    clients.push(bob2);
    await bob2.unlock(pass('cl10_bob'));
    await waitText(bob2, 'd:cl10_alice', 'm2 (important)');
    await alice.sendText('d:cl10_bob', 'm3');
    await waitText(bob2, 'd:cl10_alice', 'm3');
    await settle(bob2);
    const got = (await bob2.getMessages('d:cl10_alice')).filter((m) => m.kind === 'text' && !m.mine).map((m) => m.text);
    assert.deepEqual(got, ['m1', 'm2 (important)', 'm3'], 'nothing lost, nothing duplicated');
    await bob2.sendText('d:cl10_alice', 'r2');
    await waitText(alice, 'd:cl10_bob', 'r2');
    alice.lock();
    bob2.lock();
  });
});

describe('CL-12: acceptKeyChange pins what the user was shown', () => {
  test('a key swapped again at accept time is not pinned silently', async () => {
    const table = {};
    const alice = await newClient('cl12_alice');
    const bob = await newClient('cl12_bob', { fetch: identityOverride(table) });
    const m1 = await newClient('cl12_m1');
    const m2 = await newClient('cl12_m2');
    await bob.startDirect('cl12_alice');
    const changes = [];
    bob.addEventListener('keychange', (e) => changes.push(e.detail.username));
    table.cl12_alice = identityOf(m1);
    m1._username = 'cl12_alice';
    await rawSend(m1, ['cl12_bob'], { id: nid(), ts: Date.now(), kind: 'text', body: { text: 'k1' } });
    await waitFor(() => changes.length === 1, { what: 'first key change' });
    await settle(bob);
    const shown = await bob.getSafetyNumber('cl12_alice');
    assert.equal((await contactOf(bob, 'cl12_alice')).ik_sig, m1._pubId.ik_sig);

    table.cl12_alice = identityOf(m2); // swapped between warning and click
    await assert.rejects(bob.acceptKeyChange('cl12_alice'), /key_changed/);
    const c = await contactOf(bob, 'cl12_alice');
    assert.equal(c.ik_sig, m2._pubId.ik_sig);
    assert.equal(c.keyChanged, true, 'still flagged: the new number must be shown again');
    assert.notEqual((await bob.getSafetyNumber('cl12_alice')).number, shown.number);
    await bob.acceptKeyChange('cl12_alice'); // server agrees with what is shown now
    assert.equal((await contactOf(bob, 'cl12_alice')).keyChanged, false);
    for (const x of [alice, bob, m1, m2]) x.lock();
  });
});

describe('CRYPTO-1: unauthenticated work per incoming message', () => {
  test('forged headers over the skip budget are rejected before any key derivation', async () => {
    const alice = await newClient('c1_alice');
    const bob = await newClient('c1_bob');
    await alice.startDirect('c1_bob');
    await alice.sendText('d:c1_bob', 'x');
    await waitText(bob, 'd:c1_alice', 'x');
    await settle(bob);
    const st = (await bob._store.get('session:c1_alice')).current.state;
    const ct = randomBytes(64);
    const forged = async (pn, n) => countSignCalls(() => bob._serial(() => bob._decryptMsg('c1_alice', { dh: forgedDh, pn, n }, ct)));
    const forgedDh = await x25519Pub();
    // Old code: ~2000 chain steps (~116 ms) per blob for pn = n = 1000.
    // Baseline: loading the (encrypted) session record costs a few WebCrypto calls.
    const over1 = await forged(st.nr + 1000, 1000);
    const over2 = await forged(st.nr + 600, 600);
    // Control: within the budget the DH ratchet step runs (X25519 + HKDF + AES).
    const within = await forged(st.nr + 200, 200);
    assert.ok(over1 <= 8 && over2 <= 8, `over-budget headers did ratchet work: ${over1}, ${over2}`);
    assert.ok(within >= Math.max(over1, over2) + 4, `control did no ratchet work: ${within} vs ${over1}`);
    alice.lock();
    bob.lock();
  });

  test('a backlog of forged blobs does not block the user\'s own sends', async () => {
    const alice = await newClient('c1b_alice');
    const bob = await newClient('c1b_bob');
    await alice.startDirect('c1b_bob');
    await alice.sendText('d:c1b_bob', 'x');
    await waitText(bob, 'd:c1b_alice', 'x');
    await settle(bob);
    const st = (await bob._store.get('session:c1b_alice')).current.state;
    for (let i = 0; i < 20; i++) {
      const wire = { v: 1, type: 'msg', header: { dh: await x25519Pub(), pn: st.nr + 400, n: 500 }, ct: b64uEncode(randomBytes(64)) };
      bob._onSocketMessage({ id: nid(), blob: await sealAs('c1b_alice', bob, wire) }, bob._gen);
    }
    await bob.sendText('d:c1b_alice', 'no espero a la cola');
    assert.ok(bob._incoming.length > 0, 'send waited for the whole forged backlog');
    await waitText(alice, 'd:c1b_bob', 'no espero a la cola');
    await waitFor(() => bob._incoming.length === 0, { timeout: 60000, what: 'backlog drained' });
    await alice.sendText('d:c1b_bob', 'sigue vivo');
    await waitText(bob, 'd:c1b_alice', 'sigue vivo');
    alice.lock();
    bob.lock();
  });
});

describe('CRYPTO-2: re-key before a chain can deadlock', () => {
  test('a chain past MAX_SKIP lost messages re-keys (X3DH) instead of dead-locking', async () => {
    const alice = await newClient('c2_alice');
    const bob = await newClient('c2_bob', { privacy: { ...FAST, deliveryReceipts: false, readReceipts: false } });
    const seen = captureIncoming(bob);
    await alice.startDirect('c2_bob');
    await alice.sendText('d:c2_bob', 'x');
    await waitText(bob, 'd:c2_alice', 'x');
    await bob.sendText('d:c2_alice', 'y');
    await waitText(alice, 'd:c2_bob', 'y');
    await settle(alice);
    const setNs = (ns) => alice._serial(async () => {
      const rec = await alice._store.get('session:c2_bob');
      rec.current.state.ns = ns;
      await alice._store.set('session:c2_bob', rec);
      return rec.current.ek;
    });
    // 1200 messages "lost" on the current chain: the old code kept encrypting on it and
    // bob refused every later message forever (n - nr > MAX_SKIP).
    const oldEk = await setNs(1200);
    seen.length = 0;
    await alice.sendText('d:c2_bob', 'tras 1200 perdidos');
    await waitText(bob, 'd:c2_alice', 'tras 1200 perdidos');
    const rec = await alice._store.get('session:c2_bob');
    assert.notEqual(rec.current.ek, oldEk, 'fresh X3DH session');
    assert.ok(rec.previous.some((s) => s.ek === oldEk));
    const types = [];
    for (const b of seen) types.push((await openBlob(bob, b)).wire.type);
    assert.ok(types.includes('prekey'), 're-key starts with a prekey message');
    await bob.sendText('d:c2_alice', 'z');
    await waitText(alice, 'd:c2_bob', 'z');

    // Transient failure of the re-key: the old chain is still used below the hard limit ...
    await settle(alice);
    const realGetBundle = alice.api.getBundle.bind(alice.api);
    alice.api.getBundle = async () => { const e = new Error('network'); e.code = 'network'; throw e; };
    const lose = (k) => alice._serial(async () => { // k real messages the server "drops"
      for (let i = 0; i < k; i++) await alice._encryptFor('c2_bob', pad(utf8Encode('{}')));
    });
    const ek2 = (await alice._store.get('session:c2_bob')).current.ek;
    await lose(600);
    assert.equal((await alice._store.get('session:c2_bob')).current.ek, ek2, 'no re-key possible');
    await alice.sendText('d:c2_bob', 'sin re-key posible');
    await waitText(bob, 'd:c2_alice', 'sin re-key posible');
    // ... but never past it: encryption on that chain stops at REKEY_HARD_LIMIT (900).
    await assert.rejects(lose(400), /network/);
    assert.equal((await alice._store.get('session:c2_bob')).current.state.ns, 900);
    await assert.rejects(alice.sendText('d:c2_bob', 'demasiado largo'), /network/);
    alice.api.getBundle = realGetBundle;
    await alice.sendText('d:c2_bob', 'de nuevo bien');
    await waitText(bob, 'd:c2_alice', 'de nuevo bien');
    alice.lock();
    bob.lock();
  });
});

describe('CRYPTO-3: one unlocked instance per account', () => {
  test('second instance on the same storage is refused; a replaced instance locks itself', async () => {
    const lockName = `sombra-test-${nid()}`;
    const backend = new MemoryBackend({ lockName });
    const c1 = new SombraClient({ serverUrl: base, backend, kdfIterations: ITER, privacy: FAST });
    clients.push(c1);
    await c1.createAccount('c3_user', 'pw c3');
    await waitFor(() => c1.connected);
    const c2 = new SombraClient({ serverUrl: base, backend, kdfIterations: ITER, privacy: FAST });
    clients.push(c2);
    await assert.rejects(c2.unlock('pw c3'), /open_elsewhere/);
    assert.equal(c2.unlocked, false);
    c1.lock();
    await c2.unlock('pw c3');
    await waitFor(() => c2.connected);

    // Another device (a restored copy) authenticates: the server closes c2's socket
    // with 4005 and c2 must stop (it would otherwise keep encrypting from shared state).
    const errors = [];
    c2.addEventListener('error', (e) => errors.push(e.detail.message));
    const other = new MemoryBackend({ lockName: `${lockName}-other` });
    await SombraClient.importBackup(other, await c2.exportBackup());
    const c3 = new SombraClient({ serverUrl: base, backend: other, kdfIterations: ITER, privacy: FAST });
    clients.push(c3);
    await c3.unlock('pw c3');
    await waitFor(() => !c2.unlocked, { what: 'replaced instance locked' });
    assert.ok(errors.includes('replaced'));
    await assert.rejects(c2.sendText('d:nobody', 'x'), /locked/);
    c3.lock();

    // The browser backend always takes part in the lock.
    const hadIdb = 'indexedDB' in globalThis;
    globalThis.indexedDB = globalThis.indexedDB || {};
    try {
      assert.equal(new IdbBackend().lockName, 'sombra-account');
    } finally {
      if (!hadIdb) delete globalThis.indexedDB;
    }
  });
});

describe('CRYPTO-7: identity binding', () => {
  test('server: registration needs a username-bound proof of possession; identity keys are unique', async () => {
    const victim = await newClient('c7_alice');
    const bundle = await victim.api.getBundle('c7_alice');
    // Copying alice's public identity (with its valid signatures) under another name.
    const copy = {
      username: 'c7_carlos', ik_sig: bundle.ik_sig, ik_dh: bundle.ik_dh, ik_dh_sig: bundle.ik_dh_sig,
      spk: bundle.spk, opks: [{ id: 1, pub: await x25519Pub() }],
    };
    let r = await registerRaw(copy);
    assert.equal(r.status, 400, 'no reg_sig');
    const other = await regPayload('c7_carlos');
    r = await registerRaw({ ...copy, reg_sig: other.reg_sig });
    assert.equal(r.status, 400);
    assert.deepEqual(r.json, { error: 'bad_signature' });
    // An identity the attacker DOES own still cannot back two usernames ...
    const id = await generateIdentity();
    assert.equal((await registerRaw(await regPayload('c7_one', { identity: id }))).status, 201);
    r = await registerRaw(await regPayload('c7_two', { identity: id }));
    assert.equal(r.status, 409);
    assert.deepEqual(r.json, { error: 'identity_taken' });
    // ... nor can a fresh ik_sig adopt someone else's ik_dh (it can sign it, not own it).
    r = await registerRaw(await regPayload('c7_three', { ikDhOverride: bundle.ik_dh }));
    assert.equal(r.status, 409);
    assert.deepEqual(r.json, { error: 'identity_taken' });
    // A name-bound proof for another name is useless.
    const p = await regPayload('c7_four');
    assert.equal((await registerRaw({ ...p, username: 'c7_five' })).status, 400);
    assert.equal((await registerRaw(p)).status, 201);
    victim.lock();
  });

  test('client: a message encrypted for "carlos" (served alice\'s keys) does not decrypt at alice', async () => {
    const alice = await newClient('c7b_alice');
    const helper = await newClient('c7b_helper');
    const aliceBundle = await helper.api.getBundle('c7b_alice');
    const rewrite = async (url, init = {}) => {
      if (String(url).endsWith('/api/send') && init.method === 'POST') {
        init = { ...init, body: init.body.replaceAll('"to":"c7b_carlos"', '"to":"c7b_alice"') }; // malicious routing
      }
      return fetch(url, init);
    };
    const bob = await newClient('c7b_bob', { fetch: rewrite });
    const fake = { ...aliceBundle, username: 'c7b_carlos' };
    bob.api.getIdentity = async (u) => (u === 'c7b_carlos' ? { username: u, ik_sig: fake.ik_sig, ik_dh: fake.ik_dh, ik_dh_sig: fake.ik_dh_sig } : null);
    bob.api.getBundle = async (u) => (u === 'c7b_carlos' ? fake : null);
    await bob.startDirect('c7b_carlos');
    await bob.sendText('d:c7b_carlos', 'Carlos: esto es SOLO para ti');
    await helper.startDirect('c7b_alice');
    await helper.sendText('d:c7b_alice', 'sync7b');
    await waitText(alice, 'd:c7b_helper', 'sync7b');
    await sleep(200);
    await settle(alice);
    for (const conv of await alice.listConversations()) {
      assert.ok(!(await texts(alice, conv.id)).some((t) => t.includes('SOLO para ti')), `UKS message shown in ${conv.id}`);
    }
    for (const c of [alice, helper, bob]) c.lock();
  });
});

describe('CRYPTO-8: forward-secrecy hygiene for idle sessions', () => {
  test('skipped keys of idle sessions expire; idle previous sessions are dropped (sweep + unlock)', async () => {
    let off = 0;
    const now = () => Date.now() + off;
    const tap = makeTap();
    const alice = await newClient('c8_alice', { fetch: tap.fetch });
    const backend = new MemoryBackend();
    const bob = await newClient('c8_bob', { now, backend });
    await alice.startDirect('c8_bob');
    await alice.sendText('d:c8_bob', 'base');
    await waitText(bob, 'd:c8_alice', 'base');
    await waitFor(() => tap.inflight === 0);
    tap.hold = true; // a malicious server withholds two ciphertexts
    await alice.sendText('d:c8_bob', 'w1');
    await alice.sendText('d:c8_bob', 'w2');
    tap.hold = false;
    const withheld = tap.held.slice();
    assert.equal(withheld.length, 2);
    await alice.sendText('d:c8_bob', 'w3');
    await waitText(bob, 'd:c8_alice', 'w3');
    await settle(bob);
    let rec = await bob._store.get('session:c8_alice');
    assert.equal(rec.current.state.skipped.length, 2);
    assert.ok(Number.isFinite(rec.current.lastUsed), 'lastUsed recorded on decrypt');

    off = 15 * DAY; // bob stays idle past the server TTL
    await bob._sweep();
    rec = await bob._store.get('session:c8_alice');
    assert.equal(rec.current.state.skipped.length, 0, 'withheld message keys purged');
    for (const body of withheld) await postBody(body);
    await alice.sendText('d:c8_bob', 'w4');
    await waitText(bob, 'd:c8_alice', 'w4');
    await settle(bob);
    const t = await texts(bob, 'd:c8_alice');
    assert.ok(!t.includes('w1') && !t.includes('w2'), 'withheld ciphertexts decrypted after expiry');

    // Previous sessions unused for 30 days are dropped.
    const plant = (ages) => bob._serial(async () => {
      const r = await bob._store.get('session:c8_alice');
      r.previous = ages.map((a) => ({ ...JSON.parse(JSON.stringify(r.current)), ek: nid(), lastUsed: now() - a }));
      await bob._store.set('session:c8_alice', r);
    });
    await plant([31 * DAY, 1 * DAY]);
    bob._lastSessionSweep = 0;
    await bob._sweep();
    rec = await bob._store.get('session:c8_alice');
    assert.equal(rec.previous.length, 1);
    assert.ok(now() - rec.previous[0].lastUsed < 2 * DAY);
    // ... also right after an unlock (no hour-long wait).
    await plant([40 * DAY]);
    bob.lock();
    await bob.unlock(pass('c8_bob'));
    await waitFor(async () => (await bob._store.get('session:c8_alice')).previous.length === 0, { what: 'sweep on unlock' });
    alice.lock();
    bob.lock();
  });
});

describe('CRYPTO-9: non-canonical X25519 encodings', () => {
  test('a replayed prekey message with the ek top bit flipped does not create a second session', async () => {
    const alice = await newClient('c9_alice');
    const bob = await newClient('c9_bob');
    const seen = captureIncoming(bob);
    const realGetBundle = alice.api.getBundle.bind(alice.api);
    alice.api.getBundle = async (u) => ({ ...(await realGetBundle(u)), opk: null }); // X3DH without OPK
    await alice.startDirect('c9_bob');
    await alice.sendText('d:c9_bob', 'uno');
    await waitText(bob, 'd:c9_alice', 'uno');
    await settle(bob);
    const { wire } = await openBlob(bob, seen[0]);
    assert.equal(wire.type, 'prekey');
    assert.equal(wire.x3dh.opk_id, null);
    const ek = b64uDecode(wire.x3dh.ek);
    ek[31] ^= 0x80;
    const replay = { ...wire, x3dh: { ...wire.x3dh, ek: b64uEncode(ek) } };
    const dh = b64uDecode(wire.header.dh);
    dh[31] ^= 0x80;
    const replay2 = { ...wire, header: { ...wire.header, dh: b64uEncode(dh) } };
    for (const w of [replay, replay2]) await alice.api.send([{ to: 'c9_bob', blob: await sealAs('c9_alice', bob, w) }]);
    await alice.sendText('d:c9_bob', 'dos');
    await waitText(bob, 'd:c9_alice', 'dos');
    await settle(bob);
    const rec = await bob._store.get('session:c9_alice');
    assert.equal(rec.eks.length, 1);
    assert.equal(rec.previous.length, 0, 'replay created a second session');
    assert.equal((await texts(bob, 'd:c9_alice')).filter((t) => t === 'uno').length, 1);
    alice.lock();
    bob.lock();
  });
});

describe('BUG-2: group names', () => {
  test('control / bidi / zero-width characters are stripped on create and on receive', async () => {
    const RLO = String.fromCharCode(0x202e);
    const LRI = String.fromCharCode(0x2066);
    const ZW = String.fromCharCode(0x200b);
    const LS = String.fromCharCode(0x2028);
    const bad = new RegExp('[' + [[0x00, 0x1f], [0x7f, 0x9f], [0x200b, 0x200f], [0x2028, 0x202e], [0x2060, 0x2069], [0xfeff, 0xfeff]]
      .map(([a, b]) => String.fromCharCode(a) + '-' + String.fromCharCode(b)).join('') + ']');
    const alice = await newClient('b2_alice');
    const bob = await newClient('b2_bob');
    const gid = await alice.createGroup(`Equipo\n${RLO}olleh${ZW}${LS}`, ['b2_bob']);
    await waitFor(async () => (await bob.listConversations()).some((x) => x.id === gid), { what: 'group at bob' });
    for (const c of [alice, bob]) {
      const title = (await c.listConversations()).find((x) => x.id === gid).title;
      assert.equal(title, 'Equipo olleh');
      assert.ok(!bad.test(title));
    }
    // A raw update from the admin with spoofing characters is cleaned by the receiver.
    const g = (await alice._store.get('groups'))[gid.slice(2)];
    await rawSend(alice, ['b2_bob'], {
      id: nid(), ts: Date.now(), kind: 'group_update', group: g.id,
      body: { group: { id: g.id, name: `${LRI}fdp${RLO}.exe`, members: g.members, admin: g.admin } },
    });
    await waitFor(async () => (await bob.listConversations()).find((x) => x.id === gid).title.includes('fdp'), { what: 'rename' });
    const renamed = (await bob.listConversations()).find((x) => x.id === gid).title;
    assert.ok(!bad.test(renamed), 'bidi characters survived');
    const sys = (await bob.getMessages(gid)).filter((m) => m.kind === 'system').map((m) => m.text);
    assert.ok(sys.every((t) => !bad.test(t)));
    alice.lock();
    bob.lock();
  });
});

describe('SRV-06 (client side): prekey ids and refill timing', () => {
  test('random OPK/SPK ids; low-pool refill waits a random delay (no presence echo)', async () => {
    assert.ok(new SombraClient({ serverUrl: base })._privacy.prekeyRefillDelayMs[0] >= 60000, 'default refill delay');
    const o = await newClient('s6_user', { privacy: { ...FAST, prekeyRefillDelayMs: [3000, 3000] } });
    const ids = serverOpkIds('s6_user');
    assert.equal(ids.length, 100);
    assert.ok(ids.some((id) => id > 100000), 'OPK ids are not a counter');
    const spkId = (await o._store.get('account')).spks[0].id;
    assert.ok(spkId > 1000 || spkId !== 1, 'SPK id is not a counter');
    const fetcher = await newClient('s6_fetcher');
    for (let i = 0; i < 81; i++) await fetcher.api.getBundle('s6_user');
    await sleep(500);
    assert.equal(serverOpkIds('s6_user').length, 19, 'refilled immediately (presence oracle)');
    await waitFor(() => serverOpkIds('s6_user').length === 119, { what: 'delayed refill' });
    o.lock();
    fetcher.lock();
  });
});

describe('SRV-04: send PoW scales with what a request stores', () => {
  test('a 100-message batch needs base+7 bits, one small message only the base', async () => {
    const u = await newClient('s4_user');
    for (const [n, chars] of [[1, 400], [2, 10], [100, 400], [1, 4 * 1024 * 1024], [100, 30 * 1024 * 1024]]) {
      assert.equal(clientExtraBits(n, chars), sendPowExtraBits(n, chars), 'client and server agree');
    }
    assert.equal(sendPowExtraBits(1, 1400), 0);
    assert.equal(sendPowExtraBits(100, 400), 7);
    const post = (messages, pow) => fetch(`${base}/api/send`, {
      method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ messages, pow }),
    });
    const { challenge, difficulty } = await (await fetch(`${base}/api/pow?purpose=send`)).json();
    let weak;
    for (let i = 0; ; i++) {
      const z = leadingZeroBits(powHash(challenge, String(i)));
      if (z >= difficulty && z < difficulty + 7) { weak = String(i); break; }
    }
    const batch = Array.from({ length: 100 }, () => ({ to: 's4_user', blob: 'AAAA' }));
    // Old server: one base-difficulty PoW bought 100 queued messages.
    assert.equal((await post(batch, { challenge, nonce: weak })).status, 403);
    assert.equal((await post(batch.slice(0, 1), { challenge, nonce: weak })).status, 202);
    // The client solves the scaled difficulty transparently.
    const res = await u.api.send(batch.slice(0, 5));
    assert.ok(res.every((r) => r.ok));
    u.lock();
  });
});

describe('BUG-3 / UI error codes', () => {
  test('registration PoW default ≥ 22 bits; new error codes have Spanish text', () => {
    assert.ok(loadConfig({}).powRegisterBits >= 22);
    const generic = errorText(new Error('zz_unknown_zz'));
    for (const code of ['open_elsewhere', 'identity_taken', 'replaced', 'key_changed', 'busy', 'bad_username']) {
      assert.notEqual(errorText(new Error(code)), generic, code);
    }
  });
});

// ---------------------------------------------------------------------------------------
// Post-fix adversarial review (VC-1, VC-2, VC-3, C2)
// ---------------------------------------------------------------------------------------

function queuedFor(username) {
  const d = serverDb();
  try {
    return Number(d.prepare('SELECT COUNT(*) AS n FROM queue WHERE recipient = ?').get(username).n);
  } finally { d.close(); }
}

describe('VC-1: a full quarantine never drops (and ACKs) a genuine first contact', () => {
  test('slots occupied by forged claims → genuine message stays on the server and arrives after they clear', async () => {
    const state = { block: true };
    const victimFetch = async (url, init) => {
      if (/\/api\/identity\//.test(String(url)) && state.block) throw new TypeError('fetch failed');
      return fetch(url, init);
    };
    const victim = await newClient('vc1_victim', { fetch: victimFetch });
    const genuine = await newClient('vc1_real');
    // Three attackers claim to be vc1_real with their own identities (AD v2 binds the
    // claimed name, so the victim authenticates and parks them pending confirmation).
    for (let i = 0; i < 3; i++) {
      const m = await newClient(`vc1_mal${i}`);
      m._username = 'vc1_real';
      await rawSend(m, ['vc1_victim'], { id: nid(), ts: Date.now(), kind: 'text', body: { text: `fake ${i}` } });
    }
    await waitFor(async () => {
      const pend = await victim._store.get('pend:vc1_real');
      return pend && pend.entries.length === 3;
    }, { what: '3 parked forged identities' });
    // The genuine sender's first message arrives while the slots are full.
    await genuine.startDirect('vc1_victim');
    await genuine.sendText('d:vc1_victim', 'hola, soy yo de verdad');
    await sleep(500);
    await settle(victim);
    assert.ok(queuedFor('vc1_victim') >= 1, 'genuine message was ACKed (dropped) instead of kept on the server');
    // Identity lookups work again → forged entries are rejected → resync → delivered.
    state.block = false;
    await waitText(victim, 'd:vc1_real', 'hola, soy yo de verdad', 30000);
    assert.ok(!(await texts(victim, 'd:vc1_real')).some((t) => t.startsWith('fake')), 'forged claim delivered');
  });
});

describe('VC-2: held buffer (CL-5) never silences the verified contact nor drops overflow', () => {
  test('old verified session keeps flowing; overflow stays on the server and arrives after accept', async () => {
    const table = {};
    const alice = await newClient('vc2_alice');
    const bob = await newClient('vc2_bob', { fetch: identityOverride(table) });
    const mal = await newClient('vc2_mal');
    await bob.startDirect('vc2_alice');
    await bob.sendText('d:vc2_alice', 'hola alice');
    await waitText(alice, 'd:vc2_bob', 'hola alice');
    await alice.sendText('d:vc2_bob', 'hola bob');
    await waitText(bob, 'd:vc2_alice', 'hola bob');
    const n0 = (await bob.getSafetyNumber('vc2_alice')).number;
    await bob.setVerified('vc2_alice', true, n0);

    // Malicious server forges a key change and floods 101 payloads through it.
    table.vc2_alice = identityOf(mal);
    mal._username = 'vc2_alice';
    for (let i = 0; i < 101; i++) {
      await rawSend(mal, ['vc2_bob'], { id: nid(), ts: Date.now(), kind: 'text', body: { text: `relleno ${i}` } });
    }
    await waitFor(async () => (await contactOf(bob, 'vc2_alice'))?.hold === true, { what: 'hold', timeout: 20000 });
    // The genuine alice, on the session bound to the VERIFIED identity, is not silenced.
    await alice.sendText('d:vc2_bob', 'sigo siendo yo');
    await waitText(bob, 'd:vc2_alice', 'sigo siendo yo', 20000);
    await waitFor(async () => queuedFor('vc2_bob') >= 1, { what: 'overflow kept on the server', timeout: 20000 });
    const held = await bob._store.get('held:vc2_alice');
    assert.equal(held.payloads.length, 100);
    // The user accepts the shown number → everything, including the overflow, appears.
    const n1 = (await bob.getSafetyNumber('vc2_alice')).number;
    await bob.acceptKeyChange('vc2_alice', n1);
    await waitFor(async () => (await texts(bob, 'd:vc2_alice')).filter((t) => t.startsWith('relleno')).length === 101,
      { what: '101 held+overflow payloads', timeout: 30000 });
  });
});

describe('VC-3: verification is bound to the safety number the user compared', () => {
  test('a key change while comparing makes setVerified / acceptKeyChange fail', async () => {
    const table = {};
    const alice = await newClient('vc3_alice');
    const bob = await newClient('vc3_bob', { fetch: identityOverride(table) });
    const mal = await newClient('vc3_mal');
    await bob.startDirect('vc3_alice');
    await bob.sendText('d:vc3_alice', 'hola');
    await waitText(alice, 'd:vc3_bob', 'hola');
    const shown = (await bob.getSafetyNumber('vc3_alice')).number; // dialog opened
    // ...a forged key change lands while the user compares the digits.
    table.vc3_alice = identityOf(mal);
    mal._username = 'vc3_alice';
    await rawSend(mal, ['vc3_bob'], { id: nid(), ts: Date.now(), kind: 'text', body: { text: 'x' } });
    await waitFor(async () => (await contactOf(bob, 'vc3_alice'))?.keyChanged === true, { what: 'keychange' });
    await assert.rejects(bob.setVerified('vc3_alice', true, shown), /key_changed/);
    await assert.rejects(bob.acceptKeyChange('vc3_alice', shown), /key_changed/);
    const c = await contactOf(bob, 'vc3_alice');
    assert.equal(c.verified, false);
    assert.equal(c.keyChanged, true);
  });
});

describe('C2: queued receipts survive a lock', () => {
  test('read receipt queued right before lock is sent after unlock', async () => {
    const alice = await newClient('c2r_alice');
    const bob = await newClient('c2r_bob', { privacy: { ...FAST, receiptDelayMs: [1500, 1600] } });
    await alice.startDirect('c2r_bob');
    const sent = await alice.sendText('d:c2r_bob', 'léeme');
    await waitText(bob, 'd:c2r_alice', 'léeme');
    await bob.markRead('d:c2r_alice');
    bob.lock(); // inside the random receipt delay
    await sleep(2000);
    const status = async () => (await alice.getMessages('d:c2r_bob')).find((m) => m.id === sent.id)?.status;
    assert.notEqual(await status(), 'read');
    await bob.unlock(pass('c2r_bob'));
    await waitFor(async () => (await status()) === 'read', { what: 'read receipt after unlock', timeout: 15000 });
  });
});
