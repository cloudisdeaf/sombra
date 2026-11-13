// Regression tests for the server security fixes (audit round: SRV-03..SRV-10, BUG-3).
// Each test reproduces the audited weakness and fails on the pre-fix server.
// Self-contained like server.test.js (no client code imported).

import { test, describe, before, after } from 'node:test';
import assert from 'node:assert/strict';
import net from 'node:net';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createHash, webcrypto, randomBytes } from 'node:crypto';
import { DatabaseSync } from 'node:sqlite';
import WsClient from 'ws';

const SERVER_DIR = process.env.SOMBRA_SERVER_DIR
  ? new URL(`file:///${process.env.SOMBRA_SERVER_DIR.replace(/\\/g, '/')}/`)
  : new URL('../server/', import.meta.url);
const serverMod = await import(new URL('index.js', SERVER_DIR));
const configMod = await import(new URL('config.js', SERVER_DIR));
const dbMod = await import(new URL('db.js', SERVER_DIR));
const serverPowMod = await import(new URL('pow.js', SERVER_DIR));
const { startServer } = serverMod;

const { subtle } = webcrypto;
const enc = new TextEncoder();
const b64u = (bytes) => Buffer.from(bytes).toString('base64url');
const unb64u = (s) => new Uint8Array(Buffer.from(s, 'base64url'));
const cat = (...arrs) => new Uint8Array(Buffer.concat(arrs.map((a) => Buffer.from(a))));
const u32be = (n) => { const b = Buffer.alloc(4); b.writeUInt32BE(n); return b; };
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// ---------------------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------------------

function solvePow(challenge, difficulty) {
  for (let i = 0; ; i++) {
    const h = createHash('sha256').update(`SOMBRA-POW-v1:${challenge}:${i}`).digest();
    let n = 0;
    for (const b of h) { if (b === 0) { n += 8; continue; } n += Math.clz32(b) - 24; break; }
    if (n >= difficulty) return String(i);
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

async function makeAccount(username, opkCount = 3) {
  const sig = await genEd25519();
  const ikDh = await genX25519Pub();
  const ikDhSig = await sig.sign(cat(enc.encode('SOMBRA-IKDH-v1'), ikDh));
  // CRYPTO-7: registration proof of possession bound to the username.
  const regSig = await sig.sign(cat(enc.encode('SOMBRA-REG-v1'), [enc.encode(username).length], enc.encode(username), ikDh));
  const spkPub = await genX25519Pub();
  const spkSig = await sig.sign(cat(enc.encode('SOMBRA-SPK-v1'), u32be(1), spkPub));
  const opks = [];
  for (let i = 0; i < opkCount; i++) opks.push({ id: 100 + i, pub: b64u(await genX25519Pub()) });
  return {
    username, sig,
    payload: {
      username, ik_sig: b64u(sig.pub), ik_dh: b64u(ikDh), ik_dh_sig: b64u(ikDhSig), reg_sig: b64u(regSig),
      spk: { id: 1, pub: b64u(spkPub), sig: b64u(spkSig) }, opks,
    },
  };
}

let nameCounter = 0;
const uniqueName = (p = 'fx') => `${p}_${process.pid % 10000}_${nameCounter++}`;

/** A started server plus request helpers bound to it. */
async function boot(opts = {}) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sombra-fix-'));
  const pub = path.join(dir, 'public');
  fs.mkdirSync(pub);
  fs.writeFileSync(path.join(pub, 'index.html'), '<!doctype html>');
  const srv = await startServer({
    port: 0, host: '127.0.0.1', dataDir: path.join(dir, 'data'), publicDir: pub,
    powRegisterBits: 4, powSendBits: 4, rateLimit: false, ...opts,
  });
  const base = `http://127.0.0.1:${srv.port}`;
  const h = {
    srv, dir, base, port: srv.port,
    async close() { await srv.close(); fs.rmSync(dir, { recursive: true, force: true }); },
    async pow(purpose, extraBits = 0) {
      const { challenge, difficulty } = await (await fetch(`${base}/api/pow?purpose=${purpose}`)).json();
      return { challenge, nonce: solvePow(challenge, difficulty + extraBits) };
    },
    async post(p, body, headers = {}) {
      const r = await fetch(base + p, {
        method: 'POST', headers: { 'content-type': 'application/json', ...headers },
        body: typeof body === 'string' ? body : JSON.stringify(body),
      });
      let json = null;
      try { json = await r.json(); } catch { /* empty */ }
      return { status: r.status, json };
    },
    async register(acct) {
      const r = await h.post('/api/register', { ...acct.payload, pow: await h.pow('register') });
      assert.equal(r.status, 201, JSON.stringify(r.json));
      return acct;
    },
    async send(messages) {
      // SRV-04: the send PoW scales with the number of messages and bytes.
      const extra = serverPowMod.sendPowExtraBits(messages.length, messages.reduce((n, m) => n + m.blob.length, 0));
      return h.post('/api/send', { messages, pow: await h.pow('send', extra) });
    },
    db() { return new DatabaseSync(path.join(dir, 'data', 'sombra.db'), { readOnly: true }); },
  };
  return h;
}

/** Raw TCP request that sends headers + `bodyPart` and then stalls. */
function rawPartial(port, { method = 'POST', path: p = '/api/send', contentLength, bodyPart = '', headers = {} }) {
  const sock = net.connect(port, '127.0.0.1');
  const st = { sock, closed: false, data: '' };
  sock.on('data', (d) => { st.data += d.toString(); });
  sock.on('error', () => {});
  st.closedP = new Promise((resolve) => sock.on('close', () => { st.closed = true; resolve(); }));
  st.responseP = new Promise((resolve) => {
    const chk = () => { if (/^HTTP\/1\.1 \d{3}/.test(st.data)) resolve(Number(st.data.slice(9, 12))); };
    sock.on('data', chk);
    sock.on('close', () => resolve(st.data ? Number(st.data.slice(9, 12)) : null));
  });
  const extra = Object.entries(headers).map(([k, v]) => `${k}: ${v}\r\n`).join('');
  sock.write(`${method} ${p} HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\n` +
    `Content-Length: ${contentLength}\r\n${extra}\r\n`);
  if (bodyPart) sock.write(bodyPart);
  return st;
}

const within = (p, ms) => Promise.race([p.then((v) => ({ v })), sleep(ms).then(() => 'timeout')]);

/** Open a WebSocket (ws lib) and wait for the challenge or a failure. */
function openWs(port, headers = {}) {
  return new Promise((resolve) => {
    const ws = new WsClient(`ws://127.0.0.1:${port}/ws`, { headers });
    const inbox = [];
    const st = { ws, inbox, closed: false, closeCode: null };
    st.closedP = new Promise((r) => ws.on('close', (code) => { st.closed = true; st.closeCode = code; r(code); }));
    ws.on('message', (d) => inbox.push(JSON.parse(d.toString())));
    ws.on('unexpected-response', (_req, res) => { st.status = res.statusCode; resolve(st); });
    ws.on('error', () => resolve(st));
    ws.once('message', () => { st.open = true; resolve(st); });
  });
}

async function waitFor(pred, ms = 3000) {
  const end = Date.now() + ms;
  while (Date.now() < end) { if (pred()) return true; await sleep(10); }
  return pred();
}

async function authWs(port, acct) {
  const st = await openWs(port);
  assert.ok(st.open, 'socket opened');
  const ch = st.inbox.find((m) => m.t === 'challenge');
  const sig = await acct.sig.sign(cat(enc.encode('SOMBRA-AUTH-v1'), unb64u(ch.nonce)));
  st.ws.send(JSON.stringify({ t: 'auth', username: acct.username, sig: b64u(sig) }));
  assert.ok(await waitFor(() => st.inbox.some((m) => m.t === 'ready')), 'ready');
  return st;
}

/** Spec-conformant sealed envelope shape: 0x01 || eph(32) || ct(bucket) || tag(16). */
const envelope = (ptLen = 256) => {
  const b = randomBytes(1 + 32 + ptLen + 16);
  b[0] = 0x01;
  return b64u(b);
};

// ---------------------------------------------------------------------------------------
// SRV-03: pre-PoW memory DoS
// ---------------------------------------------------------------------------------------

describe('SRV-03 request body memory bounds', () => {
  test('a stalled request body is aborted after the idle timeout', async () => {
    const h = await boot({ bodyIdleTimeoutMs: 300 });
    try {
      const st = rawPartial(h.port, { contentLength: 100000, bodyPart: '{"messages":' });
      const r = await within(st.closedP, 2500);
      assert.notEqual(r, 'timeout', 'server kept a stalled body open (requestTimeout only)');
    } finally { await h.close(); }
  });

  test('global in-flight body budget: excess concurrent bodies get 503 instead of being buffered', async () => {
    const h = await boot({ bodyBudgetBytes: 1024 * 1024, bodyIdleTimeoutMs: 10_000 });
    try {
      const a = rawPartial(h.port, { contentLength: 900 * 1024, bodyPart: 'x'.repeat(800 * 1024) });
      await sleep(150);
      const b = rawPartial(h.port, { contentLength: 900 * 1024, bodyPart: 'x'.repeat(10) });
      const r = await within(b.responseP, 2000);
      assert.notEqual(r, 'timeout', 'second body accepted into memory past the budget');
      assert.equal(r.v, 503);
      a.sock.destroy();
      b.sock.destroy();
      // Budget is released once the holder goes away: a normal request works again.
      await sleep(100);
      const ok = await h.post('/api/send', { messages: [] });
      assert.equal(ok.status, 400);
    } finally { await h.close(); }
  });

  test('per-address cap on concurrently uploading bodies (rate limiting on)', async () => {
    const h = await boot({ rateLimit: true, bodyIdleTimeoutMs: 10_000 });
    try {
      const held = [];
      for (let i = 0; i < 8; i++) held.push(rawPartial(h.port, { contentLength: 1000, bodyPart: '{' }));
      await sleep(200);
      const extra = rawPartial(h.port, { contentLength: 1000, bodyPart: '{' });
      const r = await within(extra.responseP, 2000);
      assert.notEqual(r, 'timeout', '9th concurrent body from one address was accepted');
      assert.equal(r.v, 429);
      for (const s of [...held, extra]) s.sock.destroy();
    } finally { await h.close(); }
  });

  test('budget and per-address slots are released after normal requests (no leak)', async () => {
    const h = await boot({ rateLimit: true, bodyBudgetBytes: 512 * 1024 });
    try {
      const a = await h.register(await makeAccount(uniqueName()));
      for (let i = 0; i < 30; i++) {
        const r = await h.send([{ to: a.username, blob: envelope(64 * 1024) }]);
        assert.equal(r.status, 202, `request ${i}: ${JSON.stringify(r.json)}`);
      }
      for (let i = 0; i < 12; i++) {
        assert.equal((await h.post('/api/send', '{"messages":[]}')).status, 400);
        assert.equal((await h.post('/api/send', '{bad json')).status, 400);
      }
    } finally { await h.close(); }
  });

  test('PoW is verified before blobs are decoded', async () => {
    const h = await boot();
    try {
      const big = 'A'.repeat(4 * 1024 * 1024) + '*'; // invalid b64u, multi-MiB
      const r = await h.post('/api/send', {
        messages: [{ to: 'some_user', blob: big }], pow: { challenge: 'x', nonce: '1' },
      });
      assert.equal(r.status, 403, 'blob was decoded/validated before the PoW');
    } finally { await h.close(); }
  });

  test('JSON bodies with excessive structure are rejected; 100-message batches still work', async () => {
    const h = await boot();
    try {
      const a = await h.register(await makeAccount(uniqueName()));
      const junk = `{"messages":[${'0,'.repeat(200000)}0],"pow":{"challenge":"x","nonce":"1"}}`;
      assert.equal((await h.post('/api/send', junk)).status, 400);
      const batch = Array.from({ length: 100 }, () => ({ to: a.username, blob: envelope() }));
      const r = await h.send(batch);
      assert.equal(r.status, 202);
      assert.ok(r.json.results.every((x) => x.ok));
    } finally { await h.close(); }
  });
});

// ---------------------------------------------------------------------------------------
// SRV-04 + BUG-3: queue flooding / cheap registration
// ---------------------------------------------------------------------------------------

describe('APP-2 global quota is not shared fate', () => {
  test('a flooded sink cannot block delivery to a small queue; oldest sink messages are evicted', async () => {
    const E = 1 + 32 + 256 + 16; // envelope() size
    const h = await boot({ queueMaxTotalBytes: 8 * E, queueReservedBytes: 700 });
    try {
      const sink = await h.register(await makeAccount(uniqueName()));
      const victim = await h.register(await makeAccount(uniqueName()));
      // The attacker fills the whole global quota with a never-draining sink account.
      let r = await h.send(Array.from({ length: 8 }, () => ({ to: sink.username, blob: envelope() })));
      assert.ok(r.json.results.every((x) => x.ok));
      r = await h.send([{ to: sink.username, blob: envelope() }]);
      assert.deepEqual(r.json.results, [{ to: sink.username, ok: false, error: 'queue_full' }]);
      // A recipient under the fair-share reserve still gets messages (sink pays).
      r = await h.send([{ to: victim.username, blob: envelope() }, { to: victim.username, blob: envelope() }]);
      assert.deepEqual(r.json.results.map((x) => x.ok), [true, true]);
      // ...but only up to the reserve: above it the global quota applies again.
      r = await h.send([{ to: victim.username, blob: envelope() }]);
      assert.deepEqual(r.json.results, [{ to: victim.username, ok: false, error: 'queue_full' }]);
      // Exactly two of the sink's oldest messages were evicted; the victim's are intact.
      const s = await authWs(h.port, sink);
      const v = await authWs(h.port, victim);
      await sleep(300);
      assert.equal(s.inbox.filter((m) => m.t === 'msg').length, 6);
      assert.equal(v.inbox.filter((m) => m.t === 'msg').length, 2);
      s.ws.close(); v.ws.close();
    } finally { await h.close(); }
  });
});

describe('SRV-04 queue flooding', () => {
  test('global queue byte quota → queue_full', async () => {
    const h = await boot({ queueMaxTotalBytes: 1000 });
    try {
      const a = await h.register(await makeAccount(uniqueName()));
      const b = await h.register(await makeAccount(uniqueName()));
      let r = await h.send([{ to: a.username, blob: envelope() }, { to: b.username, blob: envelope() }]);
      assert.deepEqual(r.json.results.map((x) => x.ok), [true, true]);
      r = await h.send([{ to: b.username, blob: envelope(512) }]);
      assert.deepEqual(r.json.results, [{ to: b.username, ok: false, error: 'queue_full' }]);
      // Quota is credited back when messages are acknowledged.
      const c = await authWs(h.port, a);
      assert.ok(await waitFor(() => c.inbox.some((m) => m.t === 'msg')));
      const id = c.inbox.find((m) => m.t === 'msg').id;
      c.ws.send(JSON.stringify({ t: 'ack', ids: [id] }));
      await sleep(100);
      r = await h.send([{ to: b.username, blob: envelope() }]);
      assert.equal(r.json.results[0].ok, true);
      c.ws.close();
    } finally { await h.close(); }
  });

  test('strict envelopes: junk / short / mis-padded blobs are rejected, real envelopes accepted', async () => {
    const h = await boot({ strictEnvelopes: true });
    try {
      const a = await h.register(await makeAccount(uniqueName()));
      assert.equal((await h.send([{ to: a.username, blob: 'AAAA' }])).status, 400);
      const wrongVersion = Buffer.from(unb64u(envelope()));
      wrongVersion[0] = 2;
      assert.equal((await h.send([{ to: a.username, blob: b64u(wrongVersion) }])).status, 400);
      assert.equal((await h.send([{ to: a.username, blob: b64u(randomBytes(1 + 32 + 300 + 16)) }])).status, 400);
      for (const pt of [256, 512, 16384, 1024 * 1024, 2 * 1024 * 1024]) {
        const r = await h.send([{ to: a.username, blob: envelope(pt) }]);
        assert.equal(r.status, 202, `bucket ${pt}`);
      }
      assert.equal((await h.send([{ to: a.username, blob: envelope(3 * 1024 * 1024 + 256) }])).status, 400);
    } finally { await h.close(); }
  });

  test('isSealedEnvelope matches SPEC §2.6 buckets', () => {
    const { isSealedEnvelope } = serverMod;
    assert.equal(typeof isSealedEnvelope, 'function');
    const mk = (pt) => { const b = Buffer.alloc(49 + pt); b[0] = 1; return b; };
    assert.equal(isSealedEnvelope(mk(256)), true);
    assert.equal(isSealedEnvelope(mk(255)), false);
    assert.equal(isSealedEnvelope(mk(768)), false);
    assert.equal(isSealedEnvelope(mk(5 * 1024 * 1024)), true);
  });

  test('BUG-3: default registration PoW is at least 22 bits', () => {
    assert.ok(configMod.loadConfig({}).powRegisterBits >= 22);
  });
});

// ---------------------------------------------------------------------------------------
// SRV-05: rate limiter
// ---------------------------------------------------------------------------------------

describe('SRV-05 rate limiter', () => {
  test('compressed IPv6 addresses in one /64 share a bucket (HTTP, trusted proxy)', async () => {
    const h = await boot({ rateLimit: true, trustProxy: true });
    try {
      const statuses = [];
      for (let i = 1; i <= 21; i++) {
        const r = await h.post('/api/register', '{}', { 'x-forwarded-for': `2001:db8::${i.toString(16)}:0:0:1` });
        statuses.push(r.status);
      }
      assert.equal(statuses.slice(0, 20).every((s) => s === 400), true);
      assert.equal(statuses[20], 429, 'per-/64 limit bypassed with compressed addresses');
    } finally { await h.close(); }
  });

  test('addressKeys / expandIPv6 normalise addresses', () => {
    const { addressKeys, expandIPv6 } = serverMod;
    assert.equal(typeof addressKeys, 'function');
    assert.deepEqual(expandIPv6('2001:db8::1'), [0x2001, 0xdb8, 0, 0, 0, 0, 0, 1]);
    assert.deepEqual(expandIPv6('::'), [0, 0, 0, 0, 0, 0, 0, 0]);
    assert.deepEqual(expandIPv6('64:ff9b::1.2.3.4'), [0x64, 0xff9b, 0, 0, 0, 0, 0x102, 0x304]);
    assert.equal(expandIPv6('1.2.3.4'), null);
    assert.equal(expandIPv6('2001:db8:::1'), null);
    assert.equal(addressKeys('2001:db8::5:0:0:1').key, addressKeys('2001:db8:0:0:6::1').key);
    assert.notEqual(addressKeys('2001:db8:0:1::1').key, addressKeys('2001:db8:0:2::1').key);
    assert.equal(addressKeys('2001:db8:0:1::1').agg, addressKeys('2001:db8:0:2::1').agg);
    assert.equal(addressKeys('::ffff:10.1.2.3').key, '10.1.2.3');
    assert.equal(addressKeys('fe80::1%eth0').key, addressKeys('fe80::2').key);
  });

  test('a full bucket map evicts instead of failing closed for new clients', () => {
    const { RateLimiter } = serverMod;
    assert.equal(typeof RateLimiter, 'function');
    const rl = new RateLimiter(true, true, { maxBuckets: 50 });
    const req = (ip) => ({ socket: { remoteAddress: '127.0.0.1' }, headers: { 'x-forwarded-for': ip } });
    for (let i = 0; i < 200; i++) rl.allow(req(`10.0.${i >> 8}.${i & 255}`), 'pow');
    assert.ok(rl.buckets.size <= 50);
    assert.equal(rl.allow(req('192.0.2.77'), 'pow'), true, 'fresh client locked out by a full map');
  });

  test('IPv6 /48 aggregate limits a single /48 that rotates /64s', () => {
    const { RateLimiter } = serverMod;
    const rl = new RateLimiter(true, true, { limits: { register: 2 } });
    const req = (ip) => ({ socket: { remoteAddress: '127.0.0.1' }, headers: { 'x-forwarded-for': ip } });
    let allowed = 0;
    for (let i = 0; i < 200; i++) if (rl.allow(req(`2001:db8:1:${i.toString(16)}::1`), 'register')) allowed++;
    assert.equal(allowed, 2 * 16);
    assert.equal(rl.allow(req('2001:db8:2::1'), 'register'), true, 'other /48 unaffected');
  });
});

// ---------------------------------------------------------------------------------------
// SRV-06: OPK drain via unauthenticated bundle fetches
// ---------------------------------------------------------------------------------------

describe('SRV-06 bundle OPK drain', () => {
  test('per-target OPK budget: beyond it bundles carry opk:null and consume nothing', async () => {
    const h = await boot();
    try {
      const a = await h.register(await makeAccount(uniqueName(), 60));
      let withOpk = 0;
      for (let i = 0; i < 55; i++) {
        const b = await (await fetch(`${h.base}/api/bundle/${a.username}`)).json();
        if (b.opk) withOpk++;
        else assert.equal(b.opk, null);
      }
      assert.equal(withOpk, configMod.LIMITS.BUNDLE_OPKS_PER_TARGET ?? 50);
      const db = h.db();
      try {
        assert.equal(db.prepare('SELECT COUNT(*) AS n FROM opks WHERE username = ?').get(a.username).n, 10);
      } finally { db.close(); }
      // Unknown targets are still 404 (and do not allocate budget entries).
      assert.equal((await fetch(`${h.base}/api/bundle/nobody_zz`)).status, 404);
    } finally { await h.close(); }
  });
});

// ---------------------------------------------------------------------------------------
// SRV-07: DB metadata at rest
// ---------------------------------------------------------------------------------------

describe('SRV-07 database ordering metadata', () => {
  test('queue rowids carry no global arrival order; users/opks are WITHOUT ROWID', async () => {
    const h = await boot();
    try {
      const u = {};
      for (const n of ['zed', 'bob', 'dave', 'erin', 'alice', 'carol']) {
        u[n] = await h.register(await makeAccount(uniqueName(n)));
      }
      await h.send([{ to: u.zed.username, blob: envelope() }]);
      await h.send(['bob', 'dave', 'erin'].map((n) => ({ to: u[n].username, blob: envelope() })));
      await h.send([{ to: u.alice.username, blob: envelope() }]);
      await h.send([{ to: u.carol.username, blob: envelope() }]);
      await h.send([{ to: u.carol.username, blob: envelope() }]);
      const db = h.db();
      try {
        const rows = db.prepare('SELECT rowid AS r, recipient FROM queue ORDER BY rowid').all();
        assert.equal(rows.length, 7);
        const rs = rows.map((x) => Number(x.r));
        const span = rs[rs.length - 1] - rs[0];
        assert.ok(span > 1_000_000, `rowids look sequential: ${rs.join(',')}`);
        // Per-recipient order is still monotonic (flush cursor relies on it).
        const carol = db.prepare('SELECT rowid AS r FROM queue WHERE recipient = ? ORDER BY rowid').all(u.carol.username);
        assert.equal(carol.length, 2);
        for (const t of ['users', 'opks']) {
          const sql = db.prepare("SELECT sql FROM sqlite_master WHERE type='table' AND name=?").get(t).sql;
          assert.match(sql, /WITHOUT ROWID/i, `${t} is a rowid table (rowid = insertion order)`);
        }
        assert.deepEqual(
          db.prepare("SELECT name FROM pragma_table_info('queue')").all().map((c) => c.name),
          ['id', 'recipient', 'blob', 'expires']);
      } finally { db.close(); }
      // Queued messages are still delivered in order.
      const c = await authWs(h.port, u.carol);
      assert.ok(await waitFor(() => c.inbox.filter((m) => m.t === 'msg').length === 2));
      c.ws.close();
    } finally { await h.close(); }
  });

  test('existing rowid tables are migrated in place without data loss', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sombra-mig-'));
    try {
      const old = new DatabaseSync(path.join(dir, 'sombra.db'));
      old.exec(`CREATE TABLE users(username TEXT PRIMARY KEY, ik_sig BLOB NOT NULL, ik_dh BLOB NOT NULL, ik_dh_sig BLOB NOT NULL, spk_id INTEGER NOT NULL, spk_pub BLOB NOT NULL, spk_sig BLOB NOT NULL);
        CREATE TABLE opks(username TEXT NOT NULL, id INTEGER NOT NULL, pub BLOB NOT NULL, PRIMARY KEY(username, id));`);
      const k = Buffer.alloc(32, 1);
      old.prepare('INSERT INTO users VALUES (?,?,?,?,?,?,?)').run('zzz_old', k, k, Buffer.alloc(64), 1, k, Buffer.alloc(64));
      old.prepare('INSERT INTO opks VALUES (?,?,?)').run('zzz_old', 7, k);
      old.close();
      const db = dbMod.openDatabase(dir);
      try {
        assert.equal(db.getUser('zzz_old').username, 'zzz_old');
        assert.equal(db.countOpks('zzz_old'), 1);
        assert.equal(Number(db.takeBundle('zzz_old').opk.id), 7);
        const sql = db.db.prepare("SELECT sql FROM sqlite_master WHERE name='users'").get().sql;
        assert.match(sql, /WITHOUT ROWID/i);
      } finally { db.close(); }
    } finally { fs.rmSync(dir, { recursive: true, force: true }); }
  });

  test('enqueue honours the live connection cursor (minSeq) after the queue empties', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sombra-seq-'));
    try {
      const db = dbMod.openDatabase(dir);
      try {
        const k = Buffer.alloc(32, 1);
        db.createUser({ username: 'rcpt', ikSig: k, ikDh: k, ikDhSig: Buffer.alloc(64), spk: { id: 1, pub: k, sig: Buffer.alloc(64) }, opks: [] });
        const floor = 2 ** 52 + 12345;
        const lim = { maxMessages: 10, maxBytes: 1e6, minSeq: () => floor };
        const r1 = db.enqueue('rcpt', 'a'.repeat(22), Buffer.alloc(10), Date.now() + 1e6, lim);
        assert.ok(r1.seq > floor);
        const r2 = db.enqueue('rcpt', 'b'.repeat(22), Buffer.alloc(10), Date.now() + 1e6, { ...lim, minSeq: () => 0 });
        assert.ok(r2.seq > r1.seq, 'per-recipient seq must stay monotonic');
        assert.ok(Number.isSafeInteger(r2.seq));
      } finally { db.close(); }
    } finally { fs.rmSync(dir, { recursive: true, force: true }); }
  });
});

// ---------------------------------------------------------------------------------------
// SRV-08: unauthenticated WebSocket slots
// ---------------------------------------------------------------------------------------

describe('SRV-08 unauthenticated WebSocket caps', () => {
  test('per-address cap on pending (unauthenticated) sockets', async () => {
    const h = await boot({ rateLimit: true });
    try {
      const socks = [];
      for (let i = 0; i < 5; i++) socks.push(await openWs(h.port));
      assert.ok(socks.every((s) => s.open));
      const sixth = await openWs(h.port);
      assert.ok(!sixth.open, '6th pending socket from one address accepted');
      for (const s of [...socks, sixth]) s.ws.terminate();
    } finally { await h.close(); }
  });

  test('global pending-socket cap evicts the oldest; authenticated sockets are not counted', async () => {
    const h = await boot({ maxUnauthWs: 3, authTimeoutMs: 10_000 });
    try {
      const a = await h.register(await makeAccount(uniqueName()));
      const authed = await authWs(h.port, a);
      const socks = [];
      for (let i = 0; i < 3; i++) socks.push(await openWs(h.port));
      assert.equal(await waitFor(() => socks[0].closed, 300), false);
      socks.push(await openWs(h.port));
      assert.ok(socks[3].open);
      assert.ok(await waitFor(() => socks[0].closed, 2000), 'oldest pending socket not evicted');
      assert.equal(socks[1].closed || socks[2].closed || socks[3].closed, false);
      assert.equal(authed.closed, false);
      for (const s of [...socks, authed]) s.ws.terminate();
    } finally { await h.close(); }
  });

  test('auth timeout default is at most 5 s', () => {
    assert.ok((configMod.LIMITS.WS_AUTH_TIMEOUT_MS ?? 10_000) <= 5000);
  });
});

// ---------------------------------------------------------------------------------------
// SRV-09: slow reader
// ---------------------------------------------------------------------------------------

describe('SRV-09 slow WebSocket reader', () => {
  test('a socket that stops reading is terminated instead of pinning frames in memory', async () => {
    const h = await boot({ stallTimeoutMs: 500, pingIntervalMs: 60_000 });
    try {
      const a = await h.register(await makeAccount(uniqueName()));
      const c = await authWs(h.port, a);
      // Stop reading; TCP window fills. ws' receiver would resume() the socket on 'drain',
      // so pin it paused until the test resumes it.
      const sock = c.ws._socket;
      const realResume = sock.resume;
      sock.resume = function () { return this; };
      sock.pause();
      // Enough volume to exceed what the OS loopback buffers absorb (tens of MiB on Windows).
      for (let i = 0; i < 5; i++) {
        const r = await h.send([1, 2].map(() => ({ to: a.username, blob: b64u(randomBytes(7 * 1024 * 1024)) })));
        assert.equal(r.status, 202);
      }
      await sleep(2500);
      sock.resume = realResume;
      sock.resume();
      const done = await waitFor(() => c.closed, 4000);
      assert.ok(done, `stalled reader was not terminated (got ${c.inbox.filter((m) => m.t === 'msg').length} msgs)`);
    } finally { await h.close(); }
  });

  test('normal delivery of large and many messages still works with backpressure', async () => {
    const h = await boot();
    try {
      const a = await h.register(await makeAccount(uniqueName()));
      const c = await authWs(h.port, a);
      const blobs = [];
      for (let i = 0; i < 3; i++) blobs.push(b64u(randomBytes(3 * 1024 * 1024)));
      for (const blob of blobs) await h.send([{ to: a.username, blob }]);
      const small = Array.from({ length: 50 }, () => ({ to: a.username, blob: envelope() }));
      await h.send(small);
      assert.ok(await waitFor(() => c.inbox.filter((m) => m.t === 'msg').length === 53, 8000));
      assert.deepEqual(c.inbox.filter((m) => m.t === 'msg').slice(0, 3).map((m) => m.blob), blobs);
      c.ws.close();
    } finally { await h.close(); }
  });
});

// ---------------------------------------------------------------------------------------
// SRV-10: cross-site requests
// ---------------------------------------------------------------------------------------

describe('SRV-10 cross-site requests', () => {
  let h;
  before(async () => { h = await boot(); });
  after(async () => { await h.close(); });

  test('cross-site /api/bundle is refused without consuming an OPK', async () => {
    const a = await h.register(await makeAccount(uniqueName(), 3));
    const r = await fetch(`${h.base}/api/bundle/${a.username}`, { headers: { 'sec-fetch-site': 'cross-site' } });
    assert.equal(r.status, 403);
    const db = h.db();
    try {
      assert.equal(db.prepare('SELECT COUNT(*) AS n FROM opks WHERE username = ?').get(a.username).n, 3);
    } finally { db.close(); }
    for (const site of ['same-origin', 'none']) {
      const ok = await fetch(`${h.base}/api/bundle/${a.username}`, { headers: { 'sec-fetch-site': site } });
      assert.equal(ok.status, 200);
    }
    const sendX = await h.post('/api/send', { messages: [] }, { 'sec-fetch-site': 'same-site' });
    assert.equal(sendX.status, 403);
  });

  test('cross-site WebSocket upgrades are refused; same-origin and non-browser allowed', async () => {
    const bad = await openWs(h.port, { 'sec-fetch-site': 'cross-site', origin: 'https://evil.example' });
    assert.ok(!bad.open);
    const badOrigin = await openWs(h.port, { origin: 'https://evil.example' });
    assert.ok(!badOrigin.open);
    const good = await openWs(h.port, { 'sec-fetch-site': 'same-origin', origin: `http://127.0.0.1:${h.port}` });
    assert.ok(good.open);
    const legacy = await openWs(h.port, { origin: `http://127.0.0.1:${h.port}` });
    assert.ok(legacy.open);
    const plain = await openWs(h.port);
    assert.ok(plain.open);
    for (const s of [bad, badOrigin, good, legacy, plain]) s.ws.terminate();
  });
});
