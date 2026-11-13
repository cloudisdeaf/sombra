// Sombra — IndexedDB backend (browser only; SPEC §4.2).
//
// Same API as MemoryBackend: async get/set/delete/keys/clear over string keys and
// string values. Database `sombra`, object store `kv` (out-of-line keys). Every
// value written here is already opaque (EncryptedStore ciphertext) except the vault
// metadata under META_KEY.

const DB_NAME = 'sombra';
const STORE = 'kv';
const DB_VERSION = 1;

function promisify(req) {
  return new Promise((resolve, reject) => {
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error || new Error('indexeddb error'));
  });
}

export class IdbBackend {
  constructor() {
    if (typeof indexedDB === 'undefined' || !indexedDB) throw new Error('IndexedDB unavailable');
    this._dbp = null;
    // CRYPTO-3: every tab of this origin shares this database, so they share this Web
    // Lock name: only one tab at a time may hold the account unlocked (two instances
    // would read-modify-write the same ratchet state and reuse AES-GCM key+IV pairs).
    this.lockName = 'sombra-account';
  }

  _open() {
    if (this._dbp) return this._dbp;
    this._dbp = new Promise((resolve, reject) => {
      const req = indexedDB.open(DB_NAME, DB_VERSION);
      req.onupgradeneeded = () => {
        const db = req.result;
        if (!db.objectStoreNames.contains(STORE)) db.createObjectStore(STORE);
      };
      req.onsuccess = () => {
        const db = req.result;
        // Another tab upgrading/deleting the DB: close so we don't block it, reopen lazily.
        db.onversionchange = () => { db.close(); this._dbp = null; };
        resolve(db);
      };
      req.onerror = () => { this._dbp = null; reject(req.error || new Error('indexeddb open failed')); };
      req.onblocked = () => { /* wait: resolves once the other connection closes */ };
    });
    return this._dbp;
  }

  async _tx(mode, fn) {
    const db = await this._open();
    return new Promise((resolve, reject) => {
      const tx = db.transaction(STORE, mode);
      const store = tx.objectStore(STORE);
      let result;
      Promise.resolve(fn(store)).then((r) => { result = r; }, reject);
      tx.oncomplete = () => resolve(result);
      tx.onerror = () => reject(tx.error || new Error('indexeddb transaction failed'));
      tx.onabort = () => reject(tx.error || new Error('indexeddb transaction aborted'));
    });
  }

  async get(k) {
    checkKey(k);
    const v = await this._tx('readonly', (s) => promisify(s.get(k)));
    return v === undefined || v === null ? undefined : v;
  }

  async set(k, v) {
    checkKey(k);
    if (typeof v !== 'string') throw new TypeError('backend values must be strings');
    await this._tx('readwrite', (s) => promisify(s.put(v, k)));
  }

  async delete(k) {
    checkKey(k);
    await this._tx('readwrite', (s) => promisify(s.delete(k)));
  }

  async keys() {
    const ks = await this._tx('readonly', (s) => promisify(s.getAllKeys()));
    return ks.filter((k) => typeof k === 'string');
  }

  async clear() {
    await this._tx('readwrite', (s) => promisify(s.clear()));
  }
}

function checkKey(k) {
  if (typeof k !== 'string' || k.length === 0) throw new TypeError('backend keys must be non-empty strings');
}
