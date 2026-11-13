// Desktop launcher (launcher/app.js): local panel, guards, host/join modes and the
// /api + /ws forwarding — with Tor replaced by a fake SOCKS5 "network" (no tor.exe).
import { test, describe, after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import net from 'node:net';
import http from 'node:http';
import { fileURLToPath } from 'node:url';
import { createLauncher } from '../launcher/app.js';
import { socks5Connect } from '../launcher/socks.js';
import { normalizeOnion } from '../launcher/tor.js';
import { SombraClient } from '../public/js/core/client.js';
import { MemoryBackend } from '../public/js/core/store.js';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const PUBLIC = path.join(ROOT, 'public');
const UI = path.join(ROOT, 'launcher', 'ui');
const ONION_A = `${'a'.repeat(56)}.onion`;
const FAST = { receiptDelayMs: [0, 20], identityDelayMs: [0, 20], prekeyRefillDelayMs: [0, 0], sendJitterMs: 0 };
const cleanups = [];
after(async () => { for (const fn of cleanups.reverse()) await fn().catch(() => {}); });

const tmp = () => fs.mkdtempSync(path.join(os.tmpdir(), 'sombra-launcher-'));
const serverOptions = { powRegisterBits: 4, powSendBits: 4 };

/** A fake SOCKS5 server: CONNECT <onion>:80 is forwarded to 127.0.0.1:<target()>. */
function fakeSocks(port, routes) {
  const srv = net.createServer((c) => {
    let buf = Buffer.alloc(0);
    let stage = 0;
    c.on('error', () => {});
    c.on('data', function onData(d) {
      buf = Buffer.concat([buf, d]);
      if (stage === 0 && buf.length >= 3) { buf = buf.subarray(3); stage = 1; c.write(Buffer.from([5, 0])); }
      if (stage === 1 && buf.length >= 5 && buf.length >= 7 + buf[4]) {
        const host = buf.subarray(5, 5 + buf[4]).toString();
        const rest = buf.subarray(7 + buf[4]);
        c.removeListener('data', onData);
        const target = routes[host];
        if (!target) { c.end(Buffer.from([5, 4, 0, 1, 0, 0, 0, 0, 0, 0])); return; }
        const up = net.connect(target(), '127.0.0.1', () => {
          c.write(Buffer.from([5, 0, 0, 1, 127, 0, 0, 1, 0, 0]));
          if (rest.length) up.write(rest);
          c.pipe(up); up.pipe(c);
        });
        up.on('error', () => c.destroy());
      }
    });
  });
  return new Promise((r) => srv.listen(port, '127.0.0.1', () => r(srv)));
}

/** Fake startTor: host → reports an onion; join → runs the fake SOCKS "network". */
function fakeTorFactory(routes, record = {}) {
  return ({ socksPort, hidden }) => {
    const t = {
      state: 'ready', progress: 100, error: null, socksPort: socksPort || null,
      onChange() {}, stop() { if (t.srv) t.srv.close(); },
      onion: () => Promise.resolve(hidden ? ONION_A : null),
    };
    if (hidden) record.targetPort = hidden.targetPort;
    if (socksPort) fakeSocks(socksPort, routes).then((s) => { t.srv = s; });
    return t;
  };
}

async function get(port, p, headers = {}) {
  return new Promise((resolve, reject) => {
    const r = http.request({ host: '127.0.0.1', port, path: p, headers: { host: `127.0.0.1:${port}`, ...headers } }, (res) => {
      let b = '';
      res.on('data', (c) => { b += c; });
      res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: b }));
    });
    r.on('error', reject);
    r.end();
  });
}
async function post(port, p, body, headers = {}) {
  return new Promise((resolve, reject) => {
    const data = JSON.stringify(body);
    const r = http.request({ host: '127.0.0.1', port, path: p, method: 'POST', headers: { host: `127.0.0.1:${port}`, 'content-type': 'application/json', 'content-length': Buffer.byteLength(data), ...headers } }, (res) => {
      let b = '';
      res.on('data', (c) => { b += c; });
      res.on('end', () => { let j = null; try { j = JSON.parse(b); } catch { /* */ } resolve({ status: res.statusCode, json: j }); });
    });
    r.on('error', reject);
    r.end(data);
  });
}
const waitFor = async (pred, ms = 15000) => {
  const end = Date.now() + ms;
  for (;;) {
    if (await pred()) return;
    if (Date.now() > end) throw new Error('timeout');
    await new Promise((r) => setTimeout(r, 50));
  }
};

describe('launcher helpers', () => {
  test('normalizeOnion accepts pasted variants and rejects junk', () => {
    assert.equal(normalizeOnion(`  HTTP://${ONION_A.toUpperCase()}/ `), ONION_A);
    assert.equal(normalizeOnion(`${ONION_A}:80/x`), ONION_A);
    for (const bad of ['', 'example.com', `${'a'.repeat(16)}.onion`, `${'1'.repeat(56)}.onion`, null]) assert.equal(normalizeOnion(bad), null);
  });

  test('socks5Connect speaks SOCKS5 by domain name and returns a clean stream', async () => {
    const echo = net.createServer((c) => c.pipe(c));
    await new Promise((r) => echo.listen(0, '127.0.0.1', r));
    const socks = await fakeSocks(0, { [ONION_A]: () => echo.address().port });
    cleanups.push(async () => { echo.close(); socks.close(); });
    const s = await socks5Connect({ proxyPort: socks.address().port, host: ONION_A, port: 80 });
    s.write('hola');
    const got = await new Promise((r) => s.once('data', (d) => r(d.toString())));
    assert.equal(got, 'hola');
    s.destroy();
    await assert.rejects(socks5Connect({ proxyPort: socks.address().port, host: `${'b'.repeat(56)}.onion`, port: 80 }), /socks_reply_4/);
  });
});

describe('local panel and guards', () => {
  test('unconfigured: app redirects to the panel; panel is served with CSP', async () => {
    const L = await createLauncher({ homeDir: tmp(), publicDir: PUBLIC, uiDir: UI, port: 0, startTor: fakeTorFactory({}), serverOptions });
    cleanups.push(() => L.close());
    let r = await get(L.port, '/');
    assert.equal(r.status, 302);
    assert.equal(r.headers.location, '/_local/?next=app');
    r = await get(L.port, '/_local/');
    assert.equal(r.status, 200);
    assert.match(r.headers['content-security-policy'], /default-src 'none'/);
    assert.match(r.body, /Unirme a una red/);
    r = await get(L.port, '/_local/status');
    assert.equal(JSON.parse(r.body).mode, null);
  });

  test('DNS rebinding, cross-site requests and traversal are refused', async () => {
    const L = await createLauncher({ homeDir: tmp(), publicDir: PUBLIC, uiDir: UI, port: 0, startTor: fakeTorFactory({}), serverOptions });
    cleanups.push(() => L.close());
    assert.equal((await get(L.port, '/_local/status', { host: 'evil.example:80' })).status, 421);
    assert.equal((await post(L.port, '/_local/setup', { mode: 'host' }, { 'sec-fetch-site': 'cross-site' })).status, 403);
    assert.equal((await post(L.port, '/_local/quit', {}, { origin: 'https://evil.example' })).status, 403);
    assert.equal((await get(L.port, '/api/pow?purpose=send', { 'sec-fetch-site': 'cross-site' })).status, 403);
    for (const p of ['/..%2fpackage.json', '/_local/..%2f..%2fpackage.json', '/css/..%5c..%5cpackage.json', '/index.html.', '/favicon.svg::$DATA']) {
      assert.equal((await get(L.port, p)).status, 404, p);
    }
    assert.equal(L.state.mode, null, 'cross-site setup must not change state');
    assert.equal((await post(L.port, '/_local/setup', { mode: 'join', onion: 'nope.onion' })).status, 400);
  });
});

describe('host + join end to end (fake Tor)', () => {
  test('a friend joins through "Tor", both register and exchange E2E messages', async () => {
    const record = {};
    const hostL = await createLauncher({ homeDir: tmp(), publicDir: PUBLIC, uiDir: UI, port: 0, startTor: fakeTorFactory({}, record), serverOptions });
    cleanups.push(() => hostL.close());
    let r = await post(hostL.port, '/_local/setup', { mode: 'host' });
    assert.equal(r.status, 200);
    assert.equal(r.json.ready, true);
    await waitFor(() => hostL.state.onion === ONION_A);
    assert.ok(record.targetPort, 'Tor was pointed at the hosted server');
    assert.equal((await get(hostL.port, '/')).status, 200);

    const joinL = await createLauncher({ homeDir: tmp(), publicDir: PUBLIC, uiDir: UI, port: 0, startTor: fakeTorFactory({ [ONION_A]: () => record.targetPort }) });
    cleanups.push(() => joinL.close());
    r = await post(joinL.port, '/_local/setup', { mode: 'join', onion: ` http://${ONION_A}/ ` });
    assert.equal(r.status, 200);
    assert.equal(r.json.onion, ONION_A);
    await waitFor(async () => (await get(joinL.port, '/api/pow?purpose=send')).status === 200);

    const mk = async (port, name) => {
      const c = new SombraClient({ serverUrl: `http://127.0.0.1:${port}`, backend: new MemoryBackend(), kdfIterations: 1000, privacy: FAST });
      cleanups.push(async () => c.lock());
      await c.createAccount(name, `frase de ${name} larga`);
      await waitFor(() => c.connected);
      return c;
    };
    const host = await mk(hostL.port, 'anfitrion');
    const friend = await mk(joinL.port, 'amiga');
    await friend.startDirect('anfitrion');
    await friend.sendText('d:anfitrion', 'hola desde Tor');
    await waitFor(async () => (await host.getMessages('d:amiga')).some((m) => m.text === 'hola desde Tor'));
    await host.sendText('d:amiga', 'te leo');
    await waitFor(async () => (await friend.getMessages('d:anfitrion')).some((m) => m.text === 'te leo'));
  });

  test('forwarded requests carry no browser-identifying headers', async () => {
    const seen = [];
    const rec = http.createServer((req, res) => { seen.push(req.headers); res.writeHead(200, { 'content-type': 'application/json' }); res.end('{"ok":true}'); });
    await new Promise((r) => rec.listen(0, '127.0.0.1', r));
    cleanups.push(async () => rec.close());
    const L = await createLauncher({ homeDir: tmp(), publicDir: PUBLIC, uiDir: UI, port: 0, startTor: fakeTorFactory({ [ONION_A]: () => rec.address().port }) });
    cleanups.push(() => L.close());
    await post(L.port, '/_local/setup', { mode: 'join', onion: ONION_A });
    await waitFor(async () => (await get(L.port, '/api/x', {
      'user-agent': 'Mozilla/5.0 Secret', 'accept-language': 'es-ES', cookie: 'a=b', referer: 'http://127.0.0.1/', 'sec-fetch-site': 'same-origin',
      origin: `http://127.0.0.1:${L.port}`,
    })).status === 200);
    const h = seen.at(-1);
    assert.equal(h.host, ONION_A);
    for (const k of ['user-agent', 'accept-language', 'cookie', 'referer', 'origin', 'sec-fetch-site']) assert.equal(h[k], undefined, k);
  });

  test('saved choice is restored on restart; reset forgets it', async () => {
    const home = tmp();
    const routes = { [ONION_A]: () => 1 };
    let L = await createLauncher({ homeDir: home, publicDir: PUBLIC, uiDir: UI, port: 0, startTor: fakeTorFactory(routes) });
    await post(L.port, '/_local/setup', { mode: 'join', onion: ONION_A });
    assert.equal((await post(L.port, '/_local/setup', { mode: 'host' })).status, 409);
    await L.close();
    L = await createLauncher({ homeDir: home, publicDir: PUBLIC, uiDir: UI, port: 0, startTor: fakeTorFactory(routes) });
    cleanups.push(() => L.close());
    assert.equal(L.state.mode, 'join');
    assert.equal(L.state.onion, ONION_A);
    await post(L.port, '/_local/reset', {});
    assert.equal(L.state.mode, null);
    assert.equal(fs.existsSync(path.join(home, 'config.json')), false);
  });
});
