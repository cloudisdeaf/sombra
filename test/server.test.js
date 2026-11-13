// Server tests (SPEC §3). Self-contained: client-side crypto is generated with Node's
// WebCrypto and PoW is solved locally with node:crypto — nothing from public/js is imported.

import { test, describe, before, after } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createHash, webcrypto } from 'node:crypto';
import { DatabaseSync } from 'node:sqlite';

import { startServer } from '../server/index.js';
import { sendPowExtraBits } from '../server/pow.js';

const { subtle } = webcrypto;
const enc = new TextEncoder();
const b64u = (bytes) => Buffer.from(bytes).toString('base64url');
const unb64u = (s) => new Uint8Array(Buffer.from(s, 'base64url'));
const cat = (...arrs) => new Uint8Array(Buffer.concat(arrs.map((a) => Buffer.from(a))));
const u32be = (n) => { const b = Buffer.alloc(4); b.writeUInt32BE(n); return b; };

// ---------------------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------------------

function leadingZeroBits(bytes) {
  let n = 0;
  for (const b of bytes) {
    if (b === 0) { n += 8; continue; }
    n += Math.clz32(b) - 24;
    break;
  }
  return n;
}

function solvePow(challenge, difficulty) {
  for (let i = 0; ; i++) {
    const h = createHash('sha256').update(`SOMBRA-POW-v1:${challenge}:${i}`).digest();
    if (leadingZeroBits(h) >= difficulty) return String(i);
  }
}

async function genEd25519() {
  const kp = await subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify']);
  const pub = new Uint8Array(await subtle.exportKey('raw', kp.publicKey));
  const sign = async (msg) => new Uint8Array(await subtle.sign({ name: 'Ed25519' }, kp.privateKey, msg));
  return { pub, sign };
}

async function genX25519Pub() {
  const kp = await subtle.generateKey({ name: 'X25519' }, true, ['deriveBits']);
  return new Uint8Array(await subtle.exportKey('raw', kp.publicKey));
}

async function makeSpk(ident, id) {
  const pub = await genX25519Pub();
  const sig = await ident.sig.sign(cat(enc.encode('SOMBRA-SPK-v1'), u32be(id), pub));
  return { id, pub: b64u(pub), sig: b64u(sig) };
}

async function makeOpks(startId, count) {
  const out = [];
  for (let i = 0; i < count; i++) out.push({ id: startId + i, pub: b64u(await genX25519Pub()) });
  return out;
}

/** A fresh identity plus a complete registration payload (without pow). */
async function makeAccount(username, { opkCount = 3 } = {}) {
  const sig = await genEd25519();
  const ikDh = await genX25519Pub();
  const ikDhSig = await sig.sign(cat(enc.encode('SOMBRA-IKDH-v1'), ikDh));
  const ident = { username, sig, ikDh };
  // CRYPTO-7: registration proof of possession bound to the username.
  const regSig = await sig.sign(cat(enc.encode('SOMBRA-REG-v1'), [enc.encode(username).length], enc.encode(username), ikDh));
  ident.payload = {
    username,
    ik_sig: b64u(sig.pub),
    ik_dh: b64u(ikDh),
    ik_dh_sig: b64u(ikDhSig),
    reg_sig: b64u(regSig),
    spk: await makeSpk(ident, 1),
    opks: await makeOpks(100, opkCount),
  };
  return ident;
}

function tmpDir(prefix) {
  return fs.mkdtempSync(path.join(os.tmpdir(), prefix));
}

let usernameCounter = 0;
const uniqueName = (p = 'user') => `${p}_${process.pid % 10000}_${usernameCounter++}`;

// ---------------------------------------------------------------------------------------
// Fixture
// ---------------------------------------------------------------------------------------

let srv, base, port, dataDir, sandbox;

before(async () => {
  // Sandboxed public dir with a "secret" sibling file outside it to aim traversal at.
  sandbox = tmpDir('sombra-test-');
  const pub = path.join(sandbox, 'public');
  fs.mkdirSync(path.join(pub, 'js', 'sub'), { recursive: true });
  fs.writeFileSync(path.join(pub, 'index.html'), '<!doctype html><title>t</title>');
  fs.writeFileSync(path.join(pub, 'js', 'app.js'), 'export {};');
  fs.writeFileSync(path.join(pub, 'js', 'data.bin'), 'x');
  fs.writeFileSync(path.join(pub, '.hidden.js'), 'nope');
  fs.writeFileSync(path.join(sandbox, 'secret.txt'), 'TOP-SECRET');
  dataDir = path.join(sandbox, 'data');

  srv = await startServer({
    port: 0, host: '127.0.0.1', dataDir, publicDir: pub,
    powRegisterBits: 4, powSendBits: 4, rateLimit: false, authTimeoutMs: 1500,
  });
  port = srv.port;
  base = `http://127.0.0.1:${port}`;
});

after(async () => {
  await srv.close();
  fs.rmSync(sandbox, { recursive: true, force: true });
});

async function getPow(purpose) {
  const r = await fetch(`${base}/api/pow?purpose=${purpose}`);
  assert.equal(r.status, 200);
  return r.json();
}

async function solvedPow(purpose, extraBits = 0) {
  const { challenge, difficulty } = await getPow(purpose);
  return { challenge, nonce: solvePow(challenge, difficulty + extraBits) };
}

async function postJson(p, body) {
  const r = await fetch(base + p, {
    method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body),
  });
  let json = null;
  try { json = await r.json(); } catch { /* empty */ }
  return { status: r.status, json, headers: r.headers };
}

async function register(acct, pow) {
  return postJson('/api/register', { ...acct.payload, pow: pow ?? await solvedPow('register') });
}

async function registered(opts) {
  const acct = await makeAccount(uniqueName(), opts);
  const r = await register(acct);
  assert.equal(r.status, 201, JSON.stringify(r.json));
  return acct;
}

async function send(messages) {
  // SRV-04: the send PoW scales with the number of messages and bytes.
  const extra = Array.isArray(messages) && messages.every((m) => m && typeof m.blob === 'string')
    ? sendPowExtraBits(messages.length, messages.reduce((n, m) => n + m.blob.length, 0)) : 0;
  return postJson('/api/send', { messages, pow: await solvedPow('send', extra) });
}

/** Raw HTTP request (no URL normalisation, unlike fetch). */
function rawGet(rawPath) {
  return new Promise((resolve, reject) => {
    const req = http.request({ host: '127.0.0.1', port, path: rawPath, method: 'GET' }, (res) => {
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: Buffer.concat(chunks).toString() }));
    });
    req.on('error', reject);
    req.end();
  });
}

function openDb() {
  return new DatabaseSync(path.join(dataDir, 'sombra.db'), { readOnly: true });
}

function dbGet(sql, ...params) {
  const db = openDb();
  try { return db.prepare(sql).get(...params); } finally { db.close(); }
}

/** Minimal WS test client with a message inbox and awaitable predicates. */
function wsClient() {
  const ws = new WebSocket(`ws://127.0.0.1:${port}/ws`);
  const inbox = [];
  let waiters = [];
  let closeInfo = null;
  const closeWaiters = [];
  const pump = () => {
    waiters = waiters.filter((w) => {
      const i = inbox.findIndex(w.pred);
      if (i === -1) return true;
      clearTimeout(w.timer);
      w.resolve(inbox.splice(i, 1)[0]);
      return false;
    });
  };
  ws.addEventListener('message', (ev) => { inbox.push(JSON.parse(ev.data)); pump(); });
  ws.addEventListener('close', (ev) => {
    closeInfo = { code: ev.code, reason: ev.reason };
    for (const r of closeWaiters) r(closeInfo);
  });
  const opened = new Promise((resolve, reject) => {
    ws.addEventListener('open', resolve, { once: true });
    ws.addEventListener('error', reject, { once: true });
  });
  return {
    ws, inbox, opened,
    next(pred = () => true, timeout = 3000) {
      return new Promise((resolve, reject) => {
        const w = { pred, resolve, timer: setTimeout(() => reject(new Error('timeout waiting for ws message')), timeout) };
        waiters.push(w);
        pump();
      });
    },
    send(obj) { ws.send(typeof obj === 'string' ? obj : JSON.stringify(obj)); },
    closed(timeout = 5000) {
      if (closeInfo) return Promise.resolve(closeInfo);
      return new Promise((resolve, reject) => {
        const t = setTimeout(() => reject(new Error('timeout waiting for close')), timeout);
        closeWaiters.push((i) => { clearTimeout(t); resolve(i); });
      });
    },
    close() { try { ws.close(); } catch { /* ignore */ } },
  };
}

async function connectAs(acct) {
  const c = wsClient();
  const ch = await c.next((m) => m.t === 'challenge');
  const nonce = unb64u(ch.nonce);
  assert.equal(nonce.length, 32);
  const sig = await acct.sig.sign(cat(enc.encode('SOMBRA-AUTH-v1'), nonce));
  c.send({ t: 'auth', username: acct.username, sig: b64u(sig) });
  c.ready = await c.next((m) => m.t === 'ready' || m.t === 'error');
  assert.equal(c.ready.t, 'ready', JSON.stringify(c.ready));
  return c;
}

const randomBlob = (n = 300) => b64u(webcrypto.getRandomValues(new Uint8Array(n)));

// ---------------------------------------------------------------------------------------
// HTTP / static
// ---------------------------------------------------------------------------------------

describe('http & static files', () => {
  const expected = {
    'content-security-policy': "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' blob: data:; media-src 'self' blob:; connect-src 'self'; font-src 'self'; worker-src 'self'; manifest-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
    'referrer-policy': 'no-referrer',
    'x-content-type-options': 'nosniff',
    'x-frame-options': 'DENY',
    'cross-origin-opener-policy': 'same-origin',
    'cross-origin-resource-policy': 'same-origin',
    'cross-origin-embedder-policy': 'require-corp',
    'permissions-policy': 'camera=(), microphone=(), geolocation=(), interest-cohort=(), browsing-topics=()',
  };

  test('security headers on static, API and error responses', async () => {
    for (const p of ['/', '/js/app.js', '/nope.html', '/api/pow?purpose=send', '/api/identity/zz', '/api/unknown']) {
      const r = await rawGet(p);
      for (const [k, v] of Object.entries(expected)) assert.equal(r.headers[k], v, `${k} on ${p}`);
      assert.equal(r.headers['x-powered-by'], undefined);
      assert.equal(r.headers.server, undefined);
      assert.equal(r.headers['set-cookie'], undefined);
      assert.equal(r.headers['strict-transport-security'], undefined, 'no HSTS without TLS');
      if (p.startsWith('/api/')) assert.equal(r.headers['cache-control'], 'no-store');
    }
  });

  test('serves index.html for / and files with explicit MIME types', async () => {
    let r = await rawGet('/');
    assert.equal(r.status, 200);
    assert.equal(r.headers['content-type'], 'text/html; charset=utf-8');
    assert.match(r.body, /doctype/);
    r = await rawGet('/js/app.js');
    assert.equal(r.status, 200);
    assert.equal(r.headers['content-type'], 'text/javascript; charset=utf-8');
    // unknown extension, directory (no listing), dotfile, missing file
    for (const p of ['/js/data.bin', '/js/', '/js', '/js/sub/', '/.hidden.js', '/missing.js']) {
      assert.equal((await rawGet(p)).status, 404, p);
    }
  });

  test('path traversal attempts are blocked', async () => {
    const attempts = [
      '/../secret.txt', '/js/../../secret.txt', '/..%2fsecret.txt', '/%2e%2e/secret.txt',
      '/%2e%2e%2fsecret.txt', '/js/%2e%2e/%2e%2e/secret.txt', '/..\\secret.txt',
      '/js\\..\\..\\secret.txt', '/%5c..%5csecret.txt', '/js/%5c%2e%2e%5c%2e%2e%5csecret.txt',
      '/%252e%252e/secret.txt', '/..%00/secret.txt', '/index.html%00.js', '/C:/Windows/win.ini',
      '/C:%5cWindows%5cwin.ini', '/index.html::$DATA', '/%c0%ae%c0%ae/secret.txt', '//secret.txt',
    ];
    for (const p of attempts) {
      const r = await rawGet(p);
      assert.notEqual(r.status, 200, p);
      assert.ok(!r.body.includes('TOP-SECRET'), p);
      assert.equal(r.headers['x-frame-options'], 'DENY', p);
    }
  });

  test('unknown API route 404 and wrong method 405', async () => {
    assert.equal((await rawGet('/api/nothing')).status, 404);
    assert.equal((await rawGet('/api/register')).status, 405);
    const r = await fetch(`${base}/api/pow?purpose=register`, { method: 'POST' });
    assert.equal(r.status, 405);
  });
});

// ---------------------------------------------------------------------------------------
// PoW & registration
// ---------------------------------------------------------------------------------------

describe('pow & register', () => {
  test('pow endpoint returns challenge + difficulty; bad purpose 400', async () => {
    const p = await getPow('register');
    assert.equal(p.difficulty, 4);
    assert.equal(unb64u(p.challenge).length, 41);
    assert.equal(unb64u(p.challenge)[0], 1);
    assert.equal(unb64u((await getPow('send')).challenge)[0], 2);
    assert.equal((await rawGet('/api/pow?purpose=admin')).status, 400);
    assert.equal((await rawGet('/api/pow')).status, 400);
  });

  test('register success, then duplicate username → 409', async () => {
    const a = await makeAccount(uniqueName('alice'));
    const r = await register(a);
    assert.equal(r.status, 201);
    assert.deepEqual(r.json, { ok: true });
    const dup = await makeAccount(a.username);
    const r2 = await register(dup);
    assert.equal(r2.status, 409);
    assert.deepEqual(r2.json, { error: 'username_taken' });
  });

  test('bad signatures → 400', async () => {
    const a = await makeAccount(uniqueName());
    // ik_dh_sig made by a different key
    const other = await genEd25519();
    const bad1 = { ...a.payload, ik_dh_sig: b64u(await other.sign(cat(enc.encode('SOMBRA-IKDH-v1'), unb64u(a.payload.ik_dh)))) };
    let r = await postJson('/api/register', { ...bad1, pow: await solvedPow('register') });
    assert.equal(r.status, 400);
    // spk signature over a different id
    const spk = { ...a.payload.spk, id: a.payload.spk.id + 1 };
    r = await postJson('/api/register', { ...a.payload, spk, pow: await solvedPow('register') });
    assert.equal(r.status, 400);
    // flipped bit in spk.sig
    const sig = unb64u(a.payload.spk.sig); sig[0] ^= 1;
    r = await postJson('/api/register', { ...a.payload, spk: { ...a.payload.spk, sig: b64u(sig) }, pow: await solvedPow('register') });
    assert.equal(r.status, 400);
    assert.equal((await rawGet(`/api/identity/${a.username}`)).status, 404, 'nothing stored');
  });

  test('bad, reused, wrong-purpose, tampered and malformed PoW → 403', async () => {
    const a = await makeAccount(uniqueName());
    // wrong nonce (find one that does NOT satisfy difficulty)
    const { challenge, difficulty } = await getPow('register');
    let bad = 0;
    while (leadingZeroBits(createHash('sha256').update(`SOMBRA-POW-v1:${challenge}:${bad}`).digest()) >= difficulty) bad++;
    let r = await register(a, { challenge, nonce: String(bad) });
    assert.equal(r.status, 403);
    assert.deepEqual(r.json, { error: 'bad_pow' });

    // wrong purpose: a solved 'send' challenge cannot register
    r = await register(a, await solvedPow('send'));
    assert.equal(r.status, 403);

    // tampered challenge (flip a byte in the expiry; HMAC must fail)
    const good = await solvedPow('register');
    const raw = unb64u(good.challenge); raw[5] ^= 0xff;
    const forged = b64u(raw);
    r = await register(a, { challenge: forged, nonce: solvePow(forged, 4) });
    assert.equal(r.status, 403);

    // challenge from nowhere
    const fake = b64u(webcrypto.getRandomValues(new Uint8Array(41)));
    r = await register(a, { challenge: fake, nonce: solvePow(fake, 4) });
    assert.equal(r.status, 403);

    // valid use, then reuse by a different account
    r = await register(a, good);
    assert.equal(r.status, 201);
    const b = await makeAccount(uniqueName());
    r = await register(b, good);
    assert.equal(r.status, 403);

    // malformed nonce → 400 (type/shape error)
    r = await register(b, { challenge: good.challenge, nonce: 'abc' });
    assert.equal(r.status, 400);
  });

  test('invalid usernames and wrong types → 400', async () => {
    const a = await makeAccount('valid_name');
    for (const username of ['Alice', 'ab', 'a'.repeat(33), 'al ice', 'al-ice', 'ál', '', 42, null, '../x']) {
      const r = await postJson('/api/register', { ...a.payload, username, pow: await solvedPow('register') });
      assert.equal(r.status, 400, String(username));
      assert.deepEqual(r.json, { error: 'bad_request' });
    }
    const variants = [
      { ik_sig: b64u(new Uint8Array(31)) },
      { ik_dh: a.payload.ik_dh + '=' },
      { ik_dh: b64u(new Uint8Array(32)) },               // all-zero key
      { ik_dh_sig: b64u(new Uint8Array(63)) },
      { spk: { ...a.payload.spk, id: -1 } },
      { spk: { ...a.payload.spk, id: 2 ** 32 } },
      { spk: { ...a.payload.spk, id: 1.5 } },
      { opks: [] },
      { opks: await makeOpks(0, 201) },
      { opks: [a.payload.opks[0], a.payload.opks[0]] },  // duplicate ids
      { opks: 'x' },
      { pow: null },
    ];
    for (const v of variants) {
      const r = await postJson('/api/register', { pow: await solvedPow('register'), ...a.payload, ...v });
      assert.equal(r.status, 400, JSON.stringify(Object.keys(v)));
    }
    // non-JSON and non-object bodies
    for (const body of ['not json', '[]', '"str"', 'null']) {
      const r = await fetch(`${base}/api/register`, { method: 'POST', body });
      assert.equal(r.status, 400);
    }
    assert.equal((await rawGet('/api/identity/Alice')).status, 400);
    assert.equal((await rawGet('/api/bundle/a')).status, 400);
  });

  test('oversized bodies → 413 (Content-Length and streamed/chunked)', async () => {
    // Declared Content-Length over the 256 KiB register limit
    const big = JSON.stringify({ pad: 'x'.repeat(300 * 1024) });
    let r = await fetch(`${base}/api/register`, { method: 'POST', body: big });
    assert.equal(r.status, 413);
    assert.deepEqual(await r.json(), { error: 'payload_too_large' });

    // Chunked body without Content-Length: must be counted while streaming
    const status = await new Promise((resolve, reject) => {
      const req = http.request({ host: '127.0.0.1', port, path: '/api/register', method: 'POST',
        headers: { 'transfer-encoding': 'chunked' } }, (res) => { res.resume(); resolve(res.statusCode); });
      req.on('error', (e) => (e.code === 'ECONNRESET' || e.code === 'EPIPE' ? resolve('reset') : reject(e)));
      const chunk = Buffer.alloc(64 * 1024, 0x61);
      let sent = 0;
      const pump = () => {
        while (sent < 2 * 1024 * 1024) {
          sent += chunk.length;
          if (!req.write(chunk)) { req.once('drain', pump); return; }
        }
        req.end();
      };
      pump();
    });
    assert.equal(status, 413);

    // /api/send: 24 MiB total limit
    r = await fetch(`${base}/api/send`, { method: 'POST', body: Buffer.alloc(25 * 1024 * 1024, 0x20) });
    assert.equal(r.status, 413);
  });
});

// ---------------------------------------------------------------------------------------
// Identity & bundles
// ---------------------------------------------------------------------------------------

describe('identity & bundle', () => {
  test('identity endpoint returns the public identity; 404 for unknown', async () => {
    const a = await registered();
    const r = await fetch(`${base}/api/identity/${a.username}`);
    assert.equal(r.status, 200);
    assert.deepEqual(await r.json(), {
      username: a.username, ik_sig: a.payload.ik_sig, ik_dh: a.payload.ik_dh, ik_dh_sig: a.payload.ik_dh_sig,
    });
    const nf = await fetch(`${base}/api/identity/nobody_here`);
    assert.equal(nf.status, 404);
    assert.deepEqual(await nf.json(), { error: 'not_found' });
    assert.equal((await fetch(`${base}/api/bundle/nobody_here`)).status, 404);
  });

  test('bundle consumes each OPK exactly once, then opk:null', async () => {
    const a = await registered({ opkCount: 5 });
    const bundles = await Promise.all(Array.from({ length: 7 }, () =>
      fetch(`${base}/api/bundle/${a.username}`).then((r) => r.json())));
    const opkIds = bundles.filter((b) => b.opk).map((b) => b.opk.id);
    assert.equal(opkIds.length, 5);
    assert.equal(new Set(opkIds).size, 5, 'no OPK handed out twice');
    assert.deepEqual([...opkIds].sort((x, y) => x - y), a.payload.opks.map((o) => o.id));
    assert.equal(bundles.filter((b) => b.opk === null).length, 2);
    for (const b of bundles) {
      assert.equal(b.username, a.username);
      assert.equal(b.ik_sig, a.payload.ik_sig);
      assert.equal(b.ik_dh, a.payload.ik_dh);
      assert.equal(b.ik_dh_sig, a.payload.ik_dh_sig);
      assert.deepEqual(b.spk, a.payload.spk);
      if (b.opk) assert.equal(b.opk.pub, a.payload.opks.find((o) => o.id === b.opk.id).pub);
    }
    assert.equal(dbGet('SELECT COUNT(*) AS n FROM opks WHERE username = ?', a.username).n, 0);
  });

  test('online owner is told opk_count when it drops below 20 after a bundle fetch', async () => {
    const a = await registered({ opkCount: 21 });
    const c = await connectAs(a);
    assert.equal(c.ready.opk_count, 21);
    assert.equal(c.ready.spk_id, 1);
    await fetch(`${base}/api/bundle/${a.username}`);          // 20 left: no push
    await fetch(`${base}/api/bundle/${a.username}`);          // 19 left: push
    const m = await c.next((x) => x.t === 'opk_count');
    assert.equal(m.n, 19);
    c.close();
  });
});

// ---------------------------------------------------------------------------------------
// Messaging over REST + WebSocket
// ---------------------------------------------------------------------------------------

describe('messaging', () => {
  test('send to online user is delivered via WS; unknown recipient per-item not_found', async () => {
    const a = await registered();
    const c = await connectAs(a);
    const blob = randomBlob(500);
    const r = await send([{ to: a.username, blob }, { to: 'ghost_user_x', blob }]);
    assert.equal(r.status, 202);
    assert.deepEqual(r.json, {
      ok: true,
      results: [{ to: a.username, ok: true }, { to: 'ghost_user_x', ok: false, error: 'not_found' }],
    });
    const m = await c.next((x) => x.t === 'msg');
    assert.equal(m.blob, blob);
    assert.match(m.id, /^[A-Za-z0-9_-]{22}$/);
    c.close();
  });

  test('send validation: bad blob / too many messages / bad pow', async () => {
    const a = await registered();
    let r = await send([{ to: a.username, blob: 'not*b64' }]);
    assert.equal(r.status, 400);
    r = await send([{ to: a.username, blob: '' }]);
    assert.equal(r.status, 400);
    r = await send([]);
    assert.equal(r.status, 400);
    r = await send(Array.from({ length: 101 }, () => ({ to: a.username, blob: 'AAAA' })));
    assert.equal(r.status, 400);
    r = await postJson('/api/send', { messages: [{ to: a.username, blob: 'AAAA' }], pow: await solvedPow('register') });
    assert.equal(r.status, 403);
  });

  test('send to offline user is queued and flushed (in order) after auth', async () => {
    const a = await registered();
    const blobs = [randomBlob(100), randomBlob(200), randomBlob(300)];
    for (const blob of blobs) {
      const r = await send([{ to: a.username, blob }]);
      assert.equal(r.json.results[0].ok, true);
    }
    assert.equal(dbGet('SELECT COUNT(*) AS n FROM queue WHERE recipient = ?', a.username).n, 3);
    const row = dbGet('SELECT expires FROM queue WHERE recipient = ?', a.username);
    assert.equal(row.expires % 86400000, 0, 'expiry rounded to UTC day');
    assert.ok(row.expires >= Date.now() + 14 * 86400000);
    assert.ok(row.expires <= Date.now() + 15 * 86400000);

    const c = await connectAs(a);
    const got = [];
    for (let i = 0; i < 3; i++) got.push((await c.next((x) => x.t === 'msg')).blob);
    assert.deepEqual(got, blobs);
    c.close();
  });

  test('per-recipient queue limit (5000 messages) → queue_full', async () => {
    const a = await registered();
    const batch = Array.from({ length: 100 }, () => ({ to: a.username, blob: 'AAAA' }));
    for (let i = 0; i < 50; i++) {
      const r = await send(batch);
      assert.equal(r.status, 202);
      assert.ok(r.json.results.every((x) => x.ok), `batch ${i}`);
    }
    const r = await send([{ to: a.username, blob: 'AAAA' }]);
    assert.deepEqual(r.json.results, [{ to: a.username, ok: false, error: 'queue_full' }]);
    assert.equal(dbGet('SELECT COUNT(*) AS n FROM queue WHERE recipient = ?', a.username).n, 5000);

    // A full queue is flushed completely, once each, after auth.
    const c = await connectAs(a);
    const ids = new Set();
    for (let i = 0; i < 5000; i++) ids.add((await c.next((x) => x.t === 'msg')).id);
    assert.equal(ids.size, 5000);
    await assert.rejects(c.next((x) => x.t === 'msg', 200));
    c.close();
  });

  test('ack deletes only the owner\'s queue entries', async () => {
    const a = await registered();
    const b = await registered();
    const ca = await connectAs(a);
    const cb = await connectAs(b);
    await send([{ to: a.username, blob: randomBlob() }]);
    const m = await ca.next((x) => x.t === 'msg');
    assert.ok(dbGet('SELECT 1 AS x FROM queue WHERE id = ?', m.id), 'stored until ACK');

    // Bob tries to ack Alice's message: nothing happens.
    cb.send({ t: 'ack', ids: [m.id] });
    cb.send({ t: 'upload_opks', opks: await makeOpks(500, 1) }); // round-trip barrier
    await cb.next((x) => x.t === 'opk_count');
    assert.ok(dbGet('SELECT 1 AS x FROM queue WHERE id = ?', m.id), 'still there after foreign ack');

    ca.send({ t: 'ack', ids: [m.id] });
    ca.send({ t: 'upload_opks', opks: await makeOpks(500, 1) });
    await ca.next((x) => x.t === 'opk_count');
    assert.equal(dbGet('SELECT 1 AS x FROM queue WHERE id = ?', m.id), undefined, 'deleted on ack');

    // Malformed ack → error frame, connection stays usable.
    ca.send({ t: 'ack', ids: ['short'] });
    assert.equal((await ca.next((x) => x.t === 'error')).code, 'bad_request');

    // Reconnect: acked message is not redelivered.
    ca.close();
    await ca.closed();
    const ca2 = await connectAs(a);
    await assert.rejects(ca2.next((x) => x.t === 'msg', 300));
    ca2.close();
    cb.close();
  });
});

// ---------------------------------------------------------------------------------------
// WebSocket protocol
// ---------------------------------------------------------------------------------------

describe('websocket protocol', () => {
  test('auth with the wrong key fails with auth_failed + 4003', async () => {
    const a = await registered();
    const mallory = await genEd25519();
    const c = wsClient();
    const ch = await c.next((m) => m.t === 'challenge');
    const sig = await mallory.sign(cat(enc.encode('SOMBRA-AUTH-v1'), unb64u(ch.nonce)));
    c.send({ t: 'auth', username: a.username, sig: b64u(sig) });
    assert.deepEqual(await c.next((m) => m.t === 'error'), { t: 'error', code: 'auth_failed' });
    assert.equal((await c.closed()).code, 4003);
  });

  test('auth for unknown user, or signature over a different nonce, fails', async () => {
    const a = await registered();
    let c = wsClient();
    await c.next((m) => m.t === 'challenge');
    const sig = await a.sig.sign(cat(enc.encode('SOMBRA-AUTH-v1'), new Uint8Array(32)));
    c.send({ t: 'auth', username: a.username, sig: b64u(sig) });
    assert.equal((await c.closed()).code, 4003);

    c = wsClient();
    const ch = await c.next((m) => m.t === 'challenge');
    const s2 = await a.sig.sign(cat(enc.encode('SOMBRA-AUTH-v1'), unb64u(ch.nonce)));
    c.send({ t: 'auth', username: 'nobody_xyz', sig: b64u(s2) });
    assert.equal((await c.closed()).code, 4003);
  });

  test('messages before auth close with 4002', async () => {
    let c = wsClient();
    await c.next((m) => m.t === 'challenge');
    c.send({ t: 'ack', ids: [] });
    assert.equal((await c.closed()).code, 4002);
    c = wsClient();
    await c.next((m) => m.t === 'challenge');
    c.send('garbage{');
    assert.equal((await c.closed()).code, 4002);
  });

  test('auth timeout closes with 4001', async () => {
    const c = wsClient();
    await c.next((m) => m.t === 'challenge');
    const info = await c.closed(5000);
    assert.equal(info.code, 4001);
  });

  test('a second connection replaces the first with 4005', async () => {
    const a = await registered();
    const c1 = await connectAs(a);
    const c2 = await connectAs(a);
    const info = await c1.closed();
    assert.equal(info.code, 4005);
    assert.equal(info.reason, 'replaced');
    // Messages now go to the new connection.
    const blob = randomBlob();
    await send([{ to: a.username, blob }]);
    assert.equal((await c2.next((x) => x.t === 'msg')).blob, blob);
    // A second auth on an authenticated socket is rejected.
    c2.send({ t: 'auth', username: a.username, sig: b64u(new Uint8Array(64)) });
    assert.equal((await c2.next((x) => x.t === 'error')).code, 'bad_request');
    c2.close();
  });

  test('upload_opks stores keys and replies with opk_count', async () => {
    const a = await registered({ opkCount: 2 });
    const c = await connectAs(a);
    assert.equal(c.ready.opk_count, 2);
    c.send({ t: 'upload_opks', opks: await makeOpks(1000, 100) });
    assert.deepEqual(await c.next((x) => x.t === 'opk_count'), { t: 'opk_count', n: 102 });
    assert.equal(dbGet('SELECT COUNT(*) AS n FROM opks WHERE username = ?', a.username).n, 102);
    c.send({ t: 'upload_opks', opks: await makeOpks(2000, 201) });
    assert.equal((await c.next((x) => x.t === 'error')).code, 'bad_request');
    c.send({ t: 'upload_opks', opks: [{ id: 1, pub: 'zz' }] });
    assert.equal((await c.next((x) => x.t === 'error')).code, 'bad_request');
    c.close();
  });

  test('rotate_spk with valid signature is accepted; invalid rejected', async () => {
    const a = await registered();
    const c = await connectAs(a);
    const spk = await makeSpk(a, 2);
    c.send({ t: 'rotate_spk', spk });
    assert.deepEqual(await c.next((x) => x.t === 'spk_ok' || x.t === 'error'), { t: 'spk_ok', id: 2 });
    let bundle = await (await fetch(`${base}/api/bundle/${a.username}`)).json();
    assert.deepEqual(bundle.spk, spk);

    // Signed by someone else
    const other = await makeAccount(uniqueName());
    const forged = await makeSpk(other, 3);
    c.send({ t: 'rotate_spk', spk: forged });
    assert.deepEqual(await c.next((x) => x.t === 'spk_ok' || x.t === 'error'), { t: 'error', code: 'bad_signature' });
    // Valid signature but id changed after signing
    c.send({ t: 'rotate_spk', spk: { ...(await makeSpk(a, 4)), id: 5 } });
    assert.equal((await c.next((x) => x.t === 'spk_ok' || x.t === 'error')).code, 'bad_signature');
    bundle = await (await fetch(`${base}/api/bundle/${a.username}`)).json();
    assert.deepEqual(bundle.spk, spk, 'SPK unchanged after rejected rotations');
    c.close();
  });

  test('delete_account wipes user, OPKs and queue; then closes 4004', async () => {
    const a = await registered({ opkCount: 4 });
    await send([{ to: a.username, blob: randomBlob() }, { to: a.username, blob: randomBlob() }]);
    const c = await connectAs(a);
    await c.next((x) => x.t === 'msg');
    c.send({ t: 'delete_account' });
    assert.deepEqual(await c.next((x) => x.t === 'deleted'), { t: 'deleted' });
    assert.equal((await c.closed()).code, 4004);

    assert.equal(dbGet('SELECT COUNT(*) AS n FROM users WHERE username = ?', a.username).n, 0);
    assert.equal(dbGet('SELECT COUNT(*) AS n FROM opks WHERE username = ?', a.username).n, 0);
    assert.equal(dbGet('SELECT COUNT(*) AS n FROM queue WHERE recipient = ?', a.username).n, 0);
    assert.equal((await fetch(`${base}/api/identity/${a.username}`)).status, 404);
    const r = await send([{ to: a.username, blob: randomBlob() }]);
    assert.deepEqual(r.json.results[0], { to: a.username, ok: false, error: 'not_found' });

    // Username can be re-registered by a new identity; old key cannot log in.
    const again = await makeAccount(a.username);
    assert.equal((await register(again)).status, 201);
    const c2 = wsClient();
    const ch = await c2.next((m) => m.t === 'challenge');
    c2.send({ t: 'auth', username: a.username, sig: b64u(await a.sig.sign(cat(enc.encode('SOMBRA-AUTH-v1'), unb64u(ch.nonce)))) });
    assert.equal((await c2.closed()).code, 4003);
  });

  test('frames over 1 MiB are refused', async () => {
    const a = await registered();
    const c = await connectAs(a);
    c.send('x'.repeat(1024 * 1024 + 10));
    const info = await c.closed();
    assert.equal(info.code, 1009);
  });

  test('upgrade on a path other than /ws is rejected', async () => {
    const ws = new WebSocket(`ws://127.0.0.1:${port}/other`);
    await new Promise((resolve) => { ws.addEventListener('error', resolve); ws.addEventListener('close', resolve); });
    assert.notEqual(ws.readyState, WebSocket.OPEN);
  });
});

describe('database privacy settings', () => {
  test('secure_delete on, journal_mode delete, no timestamp columns', () => {
    // A fresh connection reports per-connection pragma defaults, so check the
    // persistent journal mode and the schema only; secure_delete is asserted via source.
    const db = openDb();
    try {
      assert.equal(db.prepare('PRAGMA journal_mode').get().journal_mode, 'delete');
      const cols = db.prepare("SELECT name FROM pragma_table_info('queue')").all().map((c) => c.name);
      assert.deepEqual(cols, ['id', 'recipient', 'blob', 'expires']);
    } finally { db.close(); }
    const src = fs.readFileSync(new URL('../server/db.js', import.meta.url), 'utf8');
    assert.match(src, /PRAGMA secure_delete = ON;/);
  });
});
