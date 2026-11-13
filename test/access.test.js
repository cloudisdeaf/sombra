// R-1: registration access control (invitation codes, closed registration, local bypass).
import { test, describe, after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import http from 'node:http';
import net from 'node:net';
import { fileURLToPath } from 'node:url';
import { AccessControl, normalizeInvite, formatInvite } from '../server/access.js';
import { createLauncher } from '../launcher/app.js';
import { SombraClient } from '../public/js/core/client.js';
import { MemoryBackend } from '../public/js/core/store.js';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const PUBLIC = path.join(ROOT, 'public');
const UI = path.join(ROOT, 'launcher', 'ui');
const ONION = `${'c'.repeat(56)}.onion`;
const FAST = { receiptDelayMs: [0, 20], identityDelayMs: [0, 20], prekeyRefillDelayMs: [0, 0], sendJitterMs: 0 };
const serverOptions = { powRegisterBits: 4, powSendBits: 4 };
const cleanups = [];
after(async () => { for (const fn of cleanups.reverse()) await fn().catch(() => {}); });
const tmp = () => fs.mkdtempSync(path.join(os.tmpdir(), 'sombra-access-'));

describe('AccessControl', () => {
  test('codes are 20 characters, normalised and formatted', () => {
    const a = new AccessControl({ mode: 'invite' });
    const code = a.createInvite();
    assert.match(code, /^([A-HJ-NP-Z2-9]{4}-){4}[A-HJ-NP-Z2-9]{4}$/);
    assert.equal(normalizeInvite(code.toLowerCase().replace(/-/g, ' ')), code.replace(/-/g, ''));
    assert.equal(formatInvite('ABCDEFGHJKLMNPQRSTUV'), 'ABCD-EFGH-JKLM-NPQR-STUV');
    for (const bad of ['', 'short', 'I'.repeat(20), 'A'.repeat(21), null, 42, 'A'.repeat(100)]) assert.equal(normalizeInvite(bad), null);
  });

  test('invite mode: a valid code works once; unknown, missing and reused codes are refused', () => {
    const a = new AccessControl({ mode: 'invite', localKey: 'k'.repeat(40) });
    const code = a.createInvite();
    assert.equal(a.check({}).error, 'invite_required');
    assert.equal(a.check({ 'x-sombra-local': 'x'.repeat(40) }).error, 'invite_required', 'a guessed local key is not enough');
    assert.equal(a.check({ 'x-sombra-invite': 'ABCD-EFGH-JKLM-NPQR-STUV' }).error, 'invite_required');
    const ok = a.check({ 'x-sombra-invite': code });
    assert.equal(ok.ok, true);
    assert.equal(a.count(), 1, 'not spent until consume()');
    ok.consume();
    assert.equal(a.count(), 0);
    assert.equal(a.check({ 'x-sombra-invite': code }).error, 'invite_required');
  });

  test('closed mode refuses everyone but the local key; open mode refuses nobody', () => {
    const a = new AccessControl({ mode: 'closed', localKey: 'k'.repeat(40) });
    const code = a.createInvite();
    assert.equal(a.check({ 'x-sombra-invite': code }).error, 'registration_closed');
    assert.equal(a.check({ 'x-sombra-local': 'wrong' }).error, 'registration_closed');
    assert.equal(a.check({ 'x-sombra-local': 'k'.repeat(40) }).ok, true);
    a.setMode('open');
    assert.equal(a.check({}).ok, true);
    assert.throws(() => a.setMode('nope'), /bad_mode/);
  });

  test('invitations persist as hashes only, and revoke clears them', () => {
    const dir = tmp();
    const a = new AccessControl({ dir, mode: 'invite' });
    const code = a.createInvite();
    const raw = fs.readFileSync(path.join(dir, 'invites.json'), 'utf8');
    assert.ok(!raw.includes(code.replace(/-/g, '')), 'the code itself is never stored');
    assert.match(raw, /^\["[0-9a-f]{64}"\]$/);
    const b = new AccessControl({ dir, mode: 'invite' });
    assert.equal(b.check({ 'x-sombra-invite': code }).ok, true);
    b.revokeAll();
    assert.equal(new AccessControl({ dir, mode: 'invite' }).count(), 0);
  });
});

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
async function getJson(port, p) {
  return new Promise((resolve, reject) => {
    http.get({ host: '127.0.0.1', port, path: p, headers: { host: `127.0.0.1:${port}` } }, (res) => {
      let b = '';
      res.on('data', (c) => { b += c; });
      res.on('end', () => resolve({ status: res.statusCode, json: JSON.parse(b) }));
    }).on('error', reject);
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

/** Fake SOCKS5 routing the onion to a local port (same idea as launcher.test.js). */
function fakeTor(record) {
  return ({ socksPort, hidden }) => {
    const t = { state: 'ready', progress: 100, error: null, socksPort: socksPort || null, onChange() {}, stop() { if (t.srv) t.srv.close(); }, onion: () => Promise.resolve(hidden ? ONION : null) };
    if (hidden) record.targetPort = hidden.targetPort;
    if (socksPort) {
      t.srv = net.createServer((c) => {
        let buf = Buffer.alloc(0); let stage = 0;
        c.on('error', () => {});
        c.on('data', function onData(d) {
          buf = Buffer.concat([buf, d]);
          if (stage === 0 && buf.length >= 3) { buf = buf.subarray(3); stage = 1; c.write(Buffer.from([5, 0])); }
          if (stage === 1 && buf.length >= 5 && buf.length >= 7 + buf[4]) {
            const rest = buf.subarray(7 + buf[4]);
            c.removeListener('data', onData);
            const up = net.connect(record.targetPort, '127.0.0.1', () => {
              c.write(Buffer.from([5, 0, 0, 1, 127, 0, 0, 1, 0, 0]));
              if (rest.length) up.write(rest);
              c.pipe(up); up.pipe(c);
            });
            up.on('error', () => c.destroy());
          }
        });
      }).listen(socksPort, '127.0.0.1');
    }
    return t;
  };
}

describe('invitation-only network end to end', () => {
  async function setup() {
    const record = {};
    const hostL = await createLauncher({ homeDir: tmp(), publicDir: PUBLIC, uiDir: UI, port: 0, startTor: fakeTor(record), serverOptions });
    cleanups.push(() => hostL.close());
    assert.equal((await post(hostL.port, '/_local/setup', { mode: 'host' })).status, 200);
    await waitFor(() => hostL.state.onion === ONION);
    const guest = async (invite) => {
      const L = await createLauncher({ homeDir: tmp(), publicDir: PUBLIC, uiDir: UI, port: 0, startTor: fakeTor(record) });
      cleanups.push(() => L.close());
      const r = await post(L.port, '/_local/setup', { mode: 'join', onion: ONION, invite });
      assert.equal(r.status, 200);
      await waitFor(async () => (await getJson(L.port, '/api/pow?purpose=send')).status === 200);
      return L;
    };
    const register = async (port, name) => {
      const c = new SombraClient({ serverUrl: `http://127.0.0.1:${port}`, backend: new MemoryBackend(), kdfIterations: 1000, privacy: FAST });
      cleanups.push(async () => c.lock());
      await c.createAccount(name, `frase de ${name} larga`);
      return c;
    };
    return { hostL, guest, register };
  }

  test('host defaults to invitation-only; the host can still create accounts', async () => {
    const { hostL, register } = await setup();
    assert.equal(hostL.state.registration, 'invite');
    await register(hostL.port, 'duena');
  });

  test('no code, wrong code, forged local key: refused', async () => {
    const { hostL, guest, register } = await setup();
    const noCode = await guest('');
    await assert.rejects(register(noCode.port, 'sincodigo'), /invite_required/);
    const wrong = await guest('ABCD-EFGH-JKLM-NPQR-STUV');
    await assert.rejects(register(wrong.port, 'codigomalo'), /invite_required/);
    // A remote client cannot skip the check by sending the header name it does not know the value of.
    const forged = await guest('');
    const r = await post(forged.port, '/api/register', {}, { 'x-sombra-local': 'x', 'sec-fetch-site': 'same-origin' });
    assert.ok(r.status === 403 || r.status === 400);
    assert.equal(hostL.state.invites, 0);
  });

  test('a code works for one account only, and a failed attempt does not burn it', async () => {
    const { hostL, guest, register } = await setup();
    const code = (await post(hostL.port, '/_local/invite', {})).json.code;
    await register(hostL.port, 'tomado'); // takes the name 'tomado' (host, no code needed)
    const g1 = await guest(code);
    await assert.rejects(register(g1.port, 'tomado'), /username_taken/);
    assert.equal(hostL.state.invites, 1, 'a failed registration keeps the code');
    await register(g1.port, 'amiga1');
    assert.equal((await getJson(hostL.port, '/_local/status')).json.invites, 0, 'spent on success');
    const g2 = await guest(code);
    await assert.rejects(register(g2.port, 'amiga2'), /invite_required/);
  });

  test('closed registration refuses even a valid code; reopening and revoking work', async () => {
    const { hostL, guest, register } = await setup();
    const code = (await post(hostL.port, '/_local/invite', {})).json.code;
    assert.equal((await post(hostL.port, '/_local/registration', { mode: 'closed' })).json.registration, 'closed');
    assert.equal((await post(hostL.port, '/_local/invite', {})).status, 409, 'no new codes while closed');
    const g = await guest(code);
    await assert.rejects(register(g.port, 'tarde'), /registration_closed/);
    await register(hostL.port, 'sigue'); // the host's own app is not locked out
    await post(hostL.port, '/_local/registration', { mode: 'invite' });
    await register(g.port, 'ahora');
    const other = (await post(hostL.port, '/_local/invite', {})).json.code;
    assert.equal((await post(hostL.port, '/_local/invites/revoke', {})).json.invites, 0);
    const g2 = await guest(other);
    await assert.rejects(register(g2.port, 'anulada'), /invite_required/);
    assert.equal((await post(hostL.port, '/_local/registration', { mode: 'open' })).status, 400, 'the panel cannot reopen registration to everyone');
  });

  test('panel guards: cross-site calls and a bad code are refused; guests have no invite routes', async () => {
    const { hostL, guest } = await setup();
    for (const p of ['/_local/invite', '/_local/invites/revoke', '/_local/registration']) {
      assert.equal((await post(hostL.port, p, { mode: 'closed' }, { 'sec-fetch-site': 'cross-site' })).status, 403, p);
    }
    const g = await guest('');
    assert.equal((await post(g.port, '/_local/invite', {})).status, 409);
    const L = await createLauncher({ homeDir: tmp(), publicDir: PUBLIC, uiDir: UI, port: 0, startTor: fakeTor({}) });
    cleanups.push(() => L.close());
    assert.equal((await post(L.port, '/_local/setup', { mode: 'join', onion: ONION, invite: 'not a code' })).status, 400);
    assert.equal(L.state.mode, null);
  });

  test('registration mode and codes survive a host restart', async () => {
    const record = {};
    const home = tmp();
    let L = await createLauncher({ homeDir: home, publicDir: PUBLIC, uiDir: UI, port: 0, startTor: fakeTor(record), serverOptions });
    await post(L.port, '/_local/setup', { mode: 'host' });
    await post(L.port, '/_local/invite', {});
    await post(L.port, '/_local/registration', { mode: 'closed' });
    await L.close();
    L = await createLauncher({ homeDir: home, publicDir: PUBLIC, uiDir: UI, port: 0, startTor: fakeTor(record), serverOptions });
    cleanups.push(() => L.close());
    assert.equal(L.state.registration, 'closed');
    assert.equal((await getJson(L.port, '/_local/status')).json.invites, 1);
  });
});

describe('panel script', () => {
  test('launcher/ui/setup.js parses (the browser panel is not covered by the other tests)', async () => {
    const { spawnSync } = await import('node:child_process');
    const r = spawnSync(process.execPath, ['--check', path.join(UI, 'setup.js')], { encoding: 'utf8' });
    assert.equal(r.status, 0, r.stderr);
  });
});
