// Sombra — client storage layer (SPEC §4.1).
//
// Two layers:
//   * A *backend* is a dumb async key/value store of strings (MemoryBackend here,
//     IdbBackend in idbstore.js for browsers). It only ever sees opaque keys and
//     opaque ciphertext — plus the vault metadata under META_KEY.
//   * EncryptedStore sits on top of a backend and the vault keys. Record names are
//     replaced by recordKey(keys, name) = b64u(HMAC(macKey, name)) so the backend
//     never learns which records exist (no "session:alice" in the clear), and
//     values are sealed with encryptRecord (AES-256-GCM, AAD = record name, so a
//     ciphertext cannot be moved to another record name undetected).
//
// This module is isomorphic: no DOM, no IndexedDB.

import { encryptRecord, decryptRecord, recordKey } from '../crypto/vault.js';
import { zeroize } from '../crypto/encoding.js';

/** Backend key under which the (non-secret) vault metadata is stored in clear. */
export const META_KEY = '__sombra_meta__';

/** In-memory backend (tests, Node). Same API as IdbBackend. */
export class MemoryBackend {
  /**
   * @param {{lockName?: string}} [opts] lockName: name of the exclusive Web Lock an
   *   unlocked SombraClient holds on this backend (CRYPTO-3). Optional here (tests);
   *   IdbBackend always sets one.
   */
  constructor({ lockName } = {}) {
    /** @type {Map<string, string>} */
    this._map = new Map();
    if (typeof lockName === 'string' && lockName) this.lockName = lockName;
  }

  async get(k) {
    checkKey(k);
    return this._map.has(k) ? this._map.get(k) : undefined;
  }

  async set(k, v) {
    checkKey(k);
    if (typeof v !== 'string') throw new TypeError('backend values must be strings');
    this._map.set(k, v);
  }

  async delete(k) {
    checkKey(k);
    this._map.delete(k);
  }

  async keys() {
    return [...this._map.keys()];
  }

  async clear() {
    this._map.clear();
  }
}

function checkKey(k) {
  if (typeof k !== 'string' || k.length === 0) throw new TypeError('backend keys must be non-empty strings');
}

/**
 * Encrypted, name-hiding record store.
 *
 * The constructor copies the vault keys; close() zeroizes the copy and makes every
 * further call throw Error('locked'). Every method re-checks the closed flag after
 * each await and before touching the keys again, so a lock() racing with an
 * in-flight write can never cause a record to be encrypted with zeroized keys.
 */
export class EncryptedStore {
  /**
   * @param {{get,set,delete,keys,clear}} backend
   * @param {{encKey: Uint8Array, macKey: Uint8Array}} vaultKeys
   */
  constructor(backend, vaultKeys) {
    if (!backend || typeof backend.get !== 'function' || typeof backend.set !== 'function') {
      throw new TypeError('bad backend');
    }
    if (!vaultKeys || !(vaultKeys.encKey instanceof Uint8Array) || !(vaultKeys.macKey instanceof Uint8Array)) {
      throw new TypeError('bad vault keys');
    }
    this.backend = backend;
    this._keys = { encKey: vaultKeys.encKey.slice(), macKey: vaultKeys.macKey.slice() };
    this._closed = false;
  }

  get closed() {
    return this._closed;
  }

  _check() {
    if (this._closed) throw new Error('locked');
  }

  /** @returns {Promise<object|undefined>} */
  async get(name) {
    this._check();
    const k = await recordKey(this._keys, name);
    this._check();
    const v = await this.backend.get(k);
    if (v === undefined || v === null) return undefined;
    this._check();
    return decryptRecord(this._keys, name, v);
  }

  async set(name, obj) {
    this._check();
    const k = await recordKey(this._keys, name);
    this._check();
    const v = await encryptRecord(this._keys, name, obj);
    this._check();
    await this.backend.set(k, v);
  }

  async delete(name) {
    this._check();
    const k = await recordKey(this._keys, name);
    this._check();
    await this.backend.delete(k);
  }

  /** Drop and zeroize the keys; the store is unusable afterwards. */
  close() {
    if (this._closed) return;
    this._closed = true;
    zeroize(this._keys.encKey);
    zeroize(this._keys.macKey);
    this._keys = null;
  }
}
