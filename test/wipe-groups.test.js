// Wipe a chat for everyone, expel a group member, and larger files — against a real server.
import { test, describe, before, after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

import { startServer } from '../server/index.js';
import { SombraClient, MAX_FILE_BYTES } from '../public/js/core/client.js';
import { MemoryBackend } from '../public/js/core/store.js';
import { b64uEncode } from '../public/js/crypto/encoding.js';
import { randomBytes } from '../public/js/crypto/primitives.js';

const FAST = { receiptDelayMs: [0, 20], identityDelayMs: [0, 20], prekeyRefillDelayMs: [0, 0], sendJitterMs: 0 };
let srv; let base; let sandbox;
const clients = [];
let n = 0;

before(async () => {
  sandbox = fs.mkdtempSync(path.join(os.tmpdir(), 'sombra-wipe-'));
  srv = await startServer({ port: 0, host: '127.0.0.1', dataDir: path.join(sandbox, 'data'), powRegisterBits: 4, powSendBits: 4, rateLimit: false, bundleOpksPerTarget: 1000 });
  base = `http://127.0.0.1:${srv.port}`;
});
after(async () => {
  for (const c of clients) { try { c.lock(); } catch { /* ignore */ } }
  await srv.close();
  fs.rmSync(sandbox, { recursive: true, force: true });
});

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
async function waitFor(pred, { timeout = 15000, what = 'condition' } = {}) {
  const end = Date.now() + timeout;
  for (;;) {
    let v; try { v = await pred(); } catch { v = false; }
    if (v) return v;
    if (Date.now() > end) throw new Error(`timeout waiting for ${what}`);
    await sleep(20);
  }
}
async function mk(prefix) {
  const name = `${prefix}${++n}`;
  const c = new SombraClient({ serverUrl: base, backend: new MemoryBackend(), kdfIterations: 1000, privacy: FAST });
  clients.push(c);
  await c.createAccount(name, `frase de ${name} larga`);
  await waitFor(() => c.connected, { what: 'connected' });
  return c;
}
const kinds = async (c, id, kind) => (await c.getMessages(id)).filter((m) => m.kind === kind);
const texts = async (c, id) => (await kinds(c, id, 'text')).map((m) => m.text);
const waitText = (c, id, t) => waitFor(async () => (await texts(c, id)).includes(t), { what: `"${t}"` });
const system = async (c, id) => (await kinds(c, id, 'system')).map((m) => m.text).join('\n');

describe('wipe a chat for everyone', () => {
  test('direct chat: either side can empty it for both, and the chat keeps working', async () => {
    const a = await mk('wa'); const b = await mk('wb');
    const A = a.username; const B = b.username;
    await a.startDirect(B);
    await a.sendText(`d:${B}`, 'hola');
    await waitText(b, `d:${A}`, 'hola');
    await b.sendText(`d:${A}`, 'que tal');
    await waitText(a, `d:${B}`, 'que tal');
    await a.sendFile(`d:${B}`, { name: 'x.txt', mime: 'text/plain', bytes: new TextEncoder().encode('contenido') });
    await waitFor(async () => (await kinds(b, `d:${A}`, 'file')).length === 1, { what: 'file at b' });

    await b.wipeConversation(`d:${A}`); // the receiver of the first message wipes
    await waitFor(async () => (await kinds(a, `d:${B}`, 'text')).length === 0 && (await kinds(a, `d:${B}`, 'file')).length === 0, { what: 'a emptied' });
    assert.equal((await kinds(b, `d:${A}`, 'text')).length, 0);
    assert.equal((await kinds(b, `d:${A}`, 'file')).length, 0);
    assert.match(await system(a, `d:${B}`), new RegExp(`@${B} vació el chat para todos`));
    assert.match(await system(b, `d:${A}`), /Vaciaste el chat para todos/);
    const conv = (await a.listConversations()).find((c) => c.id === `d:${B}`);
    assert.equal(conv.unread, 0);

    await a.sendText(`d:${B}`, 'seguimos');
    await waitText(b, `d:${A}`, 'seguimos');
    assert.ok(!(await texts(b, `d:${A}`)).includes('hola'), 'old messages did not come back');
  });

  test('direct chat: "remove" deletes the conversation on both sides', async () => {
    const a = await mk('ra'); const b = await mk('rb');
    const A = a.username; const B = b.username;
    await a.startDirect(B);
    await a.sendText(`d:${B}`, 'secreto');
    await waitText(b, `d:${A}`, 'secreto');
    await a.wipeConversation(`d:${B}`, { remove: true });
    assert.ok(!(await a.listConversations()).some((c) => c.id === `d:${B}`));
    await waitFor(async () => !(await b.listConversations()).some((c) => c.id === `d:${A}`), { what: 'b lost the chat' });
    await b.startDirect(A); // a fresh chat works
    await b.sendText(`d:${A}`, 'de nuevo');
    await waitText(a, `d:${B}`, 'de nuevo');
  });

  test('group: any member can empty it for all; a non-member cannot', async () => {
    const a = await mk('ga'); const b = await mk('gb'); const c = await mk('gc'); const mal = await mk('gm');
    const gid = await a.createGroup('equipo', [b.username, c.username]);
    await waitFor(async () => (await c.listConversations()).some((x) => x.id === gid), { what: 'c has group' });
    await waitFor(async () => (await b.listConversations()).some((x) => x.id === gid), { what: 'b has group' });
    await a.sendText(gid, 'uno'); await waitText(b, gid, 'uno'); await waitText(c, gid, 'uno');
    await b.sendText(gid, 'dos'); await waitText(a, gid, 'dos'); await waitText(c, gid, 'dos');

    // An outsider claiming the group id is dropped (not a member).
    const forged = await mal._serial(() => mal._encryptPayload([a.username], { id: b64uEncode(randomBytes(16)), ts: Date.now(), kind: 'wipe', group: gid.replace(/^g:/, ''), body: {} }));
    await mal._sendControlNow(forged);
    await a.sendText(gid, 'tres'); await waitText(b, gid, 'tres');
    assert.ok((await texts(a, gid)).includes('uno'), 'outsider could not wipe the group');

    await c.wipeConversation(gid); // not the admin, not the creator
    await waitFor(async () => (await texts(a, gid)).length === 0 && (await texts(b, gid)).length === 0, { what: 'group emptied' });
    assert.match(await system(a, gid), new RegExp(`@${c.username} vació el chat para todos`));
    assert.ok((await a.listConversations()).some((x) => x.id === gid), 'the group itself stays');
    await b.sendText(gid, 'despues');
    await waitText(a, gid, 'despues'); await waitText(c, gid, 'despues');
  });
});

describe('expel a group member', () => {
  test('only the admin can; the expelled member stops receiving; others see the new list', async () => {
    const a = await mk('ea'); const b = await mk('eb'); const c = await mk('ec');
    const gid = await a.createGroup('club', [b.username, c.username]);
    await waitFor(async () => (await c.listConversations()).some((x) => x.id === gid) && (await b.listConversations()).some((x) => x.id === gid), { what: 'group delivered' });
    await assert.rejects(b.removeGroupMember(gid, c.username), /not_admin/);
    await assert.rejects(a.removeGroupMember(gid, a.username), /bad_request/);

    await a.removeGroupMember(gid, c.username);
    await waitFor(async () => !(await b.listConversations()).find((x) => x.id === gid).members.includes(c.username), { what: 'b sees the new list' });
    assert.ok(!(await a.listConversations()).find((x) => x.id === gid).members.includes(c.username));
    await waitFor(async () => /te eliminó del grupo/.test(await system(c, gid)), { what: 'c told' });

    await a.sendText(gid, 'solo para dos');
    await waitText(b, gid, 'solo para dos');
    await sleep(300);
    assert.ok(!(await texts(c, gid)).includes('solo para dos'), 'expelled member no longer receives');
  });
});

describe('larger files', () => {
  test(`the limit is ${MAX_FILE_BYTES / 1024 / 1024} MiB and a 40 MiB file arrives intact`, async () => {
    assert.equal(MAX_FILE_BYTES, 100 * 1024 * 1024);
    const a = await mk('fa'); const b = await mk('fb');
    await a.startDirect(b.username);
    const bytes = new Uint8Array(40 * 1024 * 1024);
    for (let off = 0; off < bytes.length; off += 65536) bytes.set(randomBytes(65536), off);
    await a.sendFile(`d:${b.username}`, { name: 'grande.bin', mime: 'application/octet-stream', bytes });
    const got = await waitFor(async () => (await kinds(b, `d:${a.username}`, 'file'))[0], { timeout: 120000, what: 'big file' });
    assert.equal(got.file.size, bytes.length);
    const data = got.file.data || got.fileBytes;
    if (data) assert.equal(Buffer.compare(Buffer.from(data), Buffer.from(bytes)), 0);
  });
});
