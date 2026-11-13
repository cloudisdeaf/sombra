// Client core unit tests: EncryptedStore, MemoryBackend, backup export/import.
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';

import { MemoryBackend, EncryptedStore, META_KEY } from '../public/js/core/store.js';
import { SombraClient } from '../public/js/core/client.js';
import { ServerApi } from '../public/js/core/api.js';
import { createVault, unlockVault } from '../public/js/crypto/vault.js';
import { utf8Decode, utf8Encode } from '../public/js/crypto/encoding.js';

const ITER = 1000; // fast vault for tests (production default is 600000)

async function rawDump(backend) {
  const out = [];
  for (const k of await backend.keys()) out.push(k, await backend.get(k));
  return out.join('\n');
}

describe('MemoryBackend', () => {
  test('get/set/delete/keys/clear', async () => {
    const b = new MemoryBackend();
    assert.equal(await b.get('x'), undefined);
    await b.set('x', '1');
    await b.set('y', '2');
    assert.equal(await b.get('x'), '1');
    assert.deepEqual((await b.keys()).sort(), ['x', 'y']);
    await b.delete('x');
    assert.equal(await b.get('x'), undefined);
    await b.clear();
    assert.deepEqual(await b.keys(), []);
    await assert.rejects(b.set('z', 5), TypeError);
    await assert.rejects(b.set('', 'v'), TypeError);
  });
});

describe('EncryptedStore', () => {
  test('hides record names and values at rest', async () => {
    const backend = new MemoryBackend();
    const { meta, keys } = await createVault('correct horse battery', { iterations: ITER });
    await backend.set(META_KEY, JSON.stringify(meta));
    const store = new EncryptedStore(backend, keys);
    const secretUser = 'zebra_contact_name';
    const secretText = 'the eagle lands at midnight';
    await store.set(`session:${secretUser}`, { peer: secretUser, note: 'ratchet-state' });
    await store.set(`msgs:d:${secretUser}`, [{ text: secretText, from: secretUser }]);
    await store.set('contacts', { [secretUser]: { ik_sig: 'x' } });

    assert.deepEqual(await store.get(`msgs:d:${secretUser}`), [{ text: secretText, from: secretUser }]);
    assert.deepEqual(await store.get('contacts'), { [secretUser]: { ik_sig: 'x' } });
    assert.equal(await store.get('missing'), undefined);

    const raw = await rawDump(backend);
    for (const needle of [secretUser, secretText, 'session:', 'msgs:', 'contacts', 'ratchet-state', 'eagle']) {
      assert.ok(!raw.includes(needle), `backend leaks "${needle}"`);
    }
    // Only the meta record has a readable key; all other keys are 43-char b64u MACs.
    for (const k of await backend.keys()) {
      if (k === META_KEY) continue;
      assert.match(k, /^[A-Za-z0-9_-]{43}$/);
    }
    // Meta holds no secrets: just v, salt, iter, verifier.
    assert.deepEqual(Object.keys(JSON.parse(await backend.get(META_KEY))).sort(), ['iter', 'salt', 'v', 'verifier']);

    await store.delete('contacts');
    assert.equal(await store.get('contacts'), undefined);
  });

  test('records cannot be swapped between names (AAD binding)', async () => {
    const backend = new MemoryBackend();
    const { keys } = await createVault('pass phrase', { iterations: ITER });
    const store = new EncryptedStore(backend, keys);
    await store.set('a', { v: 1 });
    await store.set('b', { v: 2 });
    const before = new Set(await backend.keys());
    // Find the backend keys and swap the ciphertexts.
    const [ka, kb] = [...before];
    const va = await backend.get(ka);
    await backend.set(ka, await backend.get(kb));
    await backend.set(kb, va);
    await assert.rejects(store.get('a'));
    await assert.rejects(store.get('b'));
  });

  test('wrong passphrase fails; a store with wrong keys cannot read', async () => {
    const backend = new MemoryBackend();
    const { meta, keys } = await createVault('right passphrase', { iterations: ITER });
    const store = new EncryptedStore(backend, keys);
    await store.set('account', { username: 'alice' });
    await assert.rejects(unlockVault('wrong passphrase', meta), /bad passphrase/);
    const other = await createVault('another', { iterations: ITER });
    const store2 = new EncryptedStore(backend, other.keys);
    assert.equal(await store2.get('account'), undefined); // different MAC key → different record key
    const good = await unlockVault('right passphrase', meta);
    assert.deepEqual(await new EncryptedStore(backend, good).get('account'), { username: 'alice' });
  });

  test('close() zeroizes its key copy and rejects further use', async () => {
    const backend = new MemoryBackend();
    const { keys } = await createVault('pp', { iterations: ITER });
    const store = new EncryptedStore(backend, keys);
    await store.set('x', 1);
    store.close();
    assert.equal(store.closed, true);
    await assert.rejects(store.get('x'), /locked/);
    await assert.rejects(store.set('x', 2), /locked/);
    // The caller's key material is untouched (the store copied it).
    assert.ok(keys.encKey.some((b) => b !== 0));
  });
});

describe('ServerApi', () => {
  test('derives ws URL and uses privacy-preserving fetch options', async () => {
    const seen = [];
    const fakeFetch = async (url, init) => {
      seen.push({ url, init });
      return { ok: false, status: 404, json: async () => ({ error: 'not_found' }) };
    };
    const api = new ServerApi('https://example.test:9000/some/path', { fetch: fakeFetch });
    assert.equal(api.wsUrl, 'wss://example.test:9000/ws');
    assert.equal(new ServerApi('http://127.0.0.1:8443').wsUrl, 'ws://127.0.0.1:8443/ws');
    assert.equal(await api.getIdentity('bob_1'), null);
    assert.equal(seen[0].url, 'https://example.test:9000/api/identity/bob_1');
    assert.equal(seen[0].init.credentials, 'omit');
    assert.equal(seen[0].init.cache, 'no-store');
    assert.equal(seen[0].init.referrerPolicy, 'no-referrer');
    await assert.rejects(api.getIdentity('../etc'), /bad_request/);
  });
});

describe('SombraClient backup (offline)', () => {
  /** Build a local-only account directly in a backend (no server needed). */
  async function makeLocalAccount(passphrase) {
    const backend = new MemoryBackend();
    const { meta, keys } = await createVault(passphrase, { iterations: ITER });
    const store = new EncryptedStore(backend, keys);
    await store.set('account', { username: 'local_user' });
    await store.set('msgs:d:friend_name', [{ id: 'x', text: 'very secret backup text' }]);
    await backend.set(META_KEY, JSON.stringify(meta));
    return { backend, keys };
  }

  test('export/import round trip preserves every encrypted record', async () => {
    const { backend, keys } = await makeLocalAccount('backup pass');
    assert.equal(await SombraClient.hasAccount(backend), true);
    assert.equal(await SombraClient.hasAccount(new MemoryBackend()), false);

    // exportBackup only needs an unlocked store; emulate an unlocked client.
    const client = new SombraClient({ serverUrl: 'http://127.0.0.1:1', backend });
    client._store = new EncryptedStore(backend, keys);
    const bytes = await client.exportBackup();
    assert.ok(bytes instanceof Uint8Array);
    const text = utf8Decode(bytes);
    assert.ok(!text.includes('very secret backup text'));
    assert.ok(!text.includes('friend_name'));
    client._store.close();
    client._store = null;

    const restored = new MemoryBackend();
    await restored.set('junk', 'old data');
    await SombraClient.importBackup(restored, bytes);
    assert.equal(await restored.get('junk'), undefined);
    assert.deepEqual((await restored.keys()).sort(), (await backend.keys()).sort());
    const meta = JSON.parse(await restored.get(META_KEY));
    const k2 = await unlockVault('backup pass', meta);
    const s2 = new EncryptedStore(restored, k2);
    assert.deepEqual(await s2.get('msgs:d:friend_name'), [{ id: 'x', text: 'very secret backup text' }]);
    await assert.rejects(unlockVault('nope', meta), /bad passphrase/);
  });

  test('importBackup rejects garbage', async () => {
    const b = new MemoryBackend();
    await b.set('keep', 'me');
    for (const bad of ['', 'not json', '{}', '{"format":"sombra-backup","v":1,"records":{}}',
      '{"format":"sombra-backup","v":1,"records":{"__sombra_meta__":"{}"}}',
      '{"format":"sombra-backup","v":1,"records":{"a":5}}']) {
      await assert.rejects(SombraClient.importBackup(b, utf8Encode(bad)), /bad backup/);
    }
    assert.equal(await b.get('keep'), 'me'); // untouched on failure
  });

  test('unlock with the wrong passphrase throws bad passphrase', async () => {
    const { backend } = await makeLocalAccount('the right one');
    const client = new SombraClient({ serverUrl: 'http://127.0.0.1:1', backend });
    await assert.rejects(client.unlock('the wrong one'), /bad passphrase/);
    assert.equal(client.username, null);
    await assert.rejects(new SombraClient({ serverUrl: 'http://127.0.0.1:1', backend: new MemoryBackend() }).unlock('x'), /no_account/);
  });

  test('panicWipe clears the backend even while locked', async () => {
    const { backend } = await makeLocalAccount('pp');
    const client = new SombraClient({ serverUrl: 'http://127.0.0.1:1', backend });
    await client.panicWipe();
    assert.deepEqual(await backend.keys(), []);
  });
});
