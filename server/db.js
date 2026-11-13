// node:sqlite storage layer (SPEC §3.8, §3.2).
//
// Privacy properties:
//  - No timestamps except the coarse per-message expiry (rounded UP to the next UTC day).
//  - secure_delete=ON so deleted rows (ACKed messages, consumed OPKs, deleted accounts)
//    are overwritten with zeros, and journal_mode=DELETE so no WAL file keeps old pages.
//    Residual risk (documented, not fixable in-process): the rollback journal of each
//    transaction is unlinked, not wiped, so page pre-images may remain in free filesystem
//    blocks. Operators should keep DATA_DIR on full-disk encryption or tmpfs.
//  - temp_store=MEMORY so SQLite never spills temporary data to disk.
//  - Usernames, keys and opaque sealed blobs are the only things stored.
//  - No insertion order at rest (SRV-07):
//      * users and opks are WITHOUT ROWID tables (clustered by primary key), so their
//        physical/rowid order no longer equals registration / upload order. This deviates
//        from the literal SPEC §3.8 DDL only by the "WITHOUT ROWID" suffix; columns and
//        semantics are unchanged.
//      * queue rowids are NOT a global counter: each recipient's rows form an independent
//        random walk (random 52-bit start, random positive gaps). Rowids are still strictly
//        increasing per recipient (the WebSocket flush cursor needs that), but they reveal
//        nothing about arrival order across recipients, nor which rows came in one batch.

import fs from 'node:fs';
import path from 'node:path';
import { randomInt } from 'node:crypto';
import { DatabaseSync } from 'node:sqlite';

const DAY_MS = 24 * 60 * 60 * 1000;

/** Round a timestamp up to the next UTC midnight (exact midnight stays as is). */
export function roundUpToUtcDay(ms) {
  return Math.ceil(ms / DAY_MS) * DAY_MS;
}

const USERS_DDL = 'CREATE TABLE IF NOT EXISTS users(username TEXT PRIMARY KEY, ik_sig BLOB NOT NULL, ik_dh BLOB NOT NULL, ik_dh_sig BLOB NOT NULL, spk_id INTEGER NOT NULL, spk_pub BLOB NOT NULL, spk_sig BLOB NOT NULL) WITHOUT ROWID;';
const OPKS_DDL = 'CREATE TABLE IF NOT EXISTS opks(username TEXT NOT NULL, id INTEGER NOT NULL, pub BLOB NOT NULL, PRIMARY KEY(username, id)) WITHOUT ROWID;';
const QUEUE_DDL = `
CREATE TABLE IF NOT EXISTS queue(id TEXT PRIMARY KEY, recipient TEXT NOT NULL, blob BLOB NOT NULL, expires INTEGER NOT NULL);
CREATE INDEX IF NOT EXISTS queue_recipient ON queue(recipient);
`;

// Queue rowid random walk parameters. Start in [1, 2^52), gaps in [1, 2^20]: a recipient
// would need ~2^32 messages to approach 2^53, so rowids always stay exact JS numbers.
const SEQ_START_BITS = 52;
const SEQ_MAX_GAP = 2 ** 20;
const SEQ_LIMIT = Number.MAX_SAFE_INTEGER - SEQ_MAX_GAP;

function randomSeqStart() {
  // randomInt is limited to 48-bit ranges: combine two 26-bit draws.
  const hi = randomInt(0, 2 ** (SEQ_START_BITS - 26));
  const lo = randomInt(0, 2 ** 26);
  return hi * 2 ** 26 + lo + 1;
}

function isConstraintError(err) {
  return !!err && (err.code === 'ERR_SQLITE_ERROR') &&
    /constraint|UNIQUE|PRIMARY KEY/i.test(String(err.message));
}

export class SombraDb {
  /** @param {string} dataDir */
  constructor(dataDir) {
    fs.mkdirSync(dataDir, { recursive: true, mode: 0o700 });
    this.file = path.join(dataDir, 'sombra.db');
    this.db = new DatabaseSync(this.file);
    this.db.exec('PRAGMA secure_delete = ON;');
    this.db.exec('PRAGMA journal_mode = DELETE;');
    this.db.exec('PRAGMA synchronous = FULL;');
    this.db.exec('PRAGMA temp_store = MEMORY;');
    this.migrateToWithoutRowid('users', USERS_DDL,
      'username, ik_sig, ik_dh, ik_dh_sig, spk_id, spk_pub, spk_sig', 'username');
    this.migrateToWithoutRowid('opks', OPKS_DDL, 'username, id, pub', 'username, id');
    this.db.exec(USERS_DDL);
    this.db.exec(OPKS_DDL);
    this.db.exec(QUEUE_DDL);
    // CRYPTO-7: identity keys are looked up on registration (one identity per username).
    // Plain (non-UNIQUE) indexes so a pre-existing database that already holds a copied
    // identity still opens; uniqueness is enforced by createUser() for new registrations.
    this.db.exec("CREATE INDEX IF NOT EXISTS users_ik_sig ON users(ik_sig);");
    this.db.exec("CREATE INDEX IF NOT EXISTS users_ik_dh ON users(ik_dh);");
    try { fs.chmodSync(this.file, 0o600); } catch { /* best effort (no-op on Windows) */ }

    const p = (sql) => this.db.prepare(sql);
    this.s = {
      insertUser: p('INSERT INTO users(username, ik_sig, ik_dh, ik_dh_sig, spk_id, spk_pub, spk_sig) VALUES (?, ?, ?, ?, ?, ?, ?)'),
      userExists: p('SELECT 1 AS x FROM users WHERE username = ?'),
      identityUsed: p('SELECT 1 AS x FROM users WHERE ik_sig = ? OR ik_dh = ? OR ik_sig = ? OR ik_dh = ? LIMIT 1'),
      getUser: p('SELECT username, ik_sig, ik_dh, ik_dh_sig, spk_id, spk_pub, spk_sig FROM users WHERE username = ?'),
      updateSpk: p('UPDATE users SET spk_id = ?, spk_pub = ?, spk_sig = ? WHERE username = ?'),
      deleteUser: p('DELETE FROM users WHERE username = ?'),
      upsertOpk: p('INSERT OR REPLACE INTO opks(username, id, pub) VALUES (?, ?, ?)'),
      countOpks: p('SELECT COUNT(*) AS n FROM opks WHERE username = ?'),
      takeOpk: p('DELETE FROM opks WHERE username = ? AND id = (SELECT id FROM opks WHERE username = ? ORDER BY id LIMIT 1) RETURNING id, pub'),
      deleteOpks: p('DELETE FROM opks WHERE username = ?'),
      queueStats: p('SELECT COUNT(*) AS n, COALESCE(SUM(length(blob)), 0) AS bytes FROM queue WHERE recipient = ?'),
      queueTotals: p('SELECT COUNT(*) AS n, COALESCE(SUM(length(blob)), 0) AS bytes FROM queue'),
      maxSeq: p('SELECT MAX(rowid) AS m FROM queue WHERE recipient = ?'),
      enqueue: p('INSERT INTO queue(rowid, id, recipient, blob, expires) VALUES (?, ?, ?, ?, ?)'),
      queuedAfter: p('SELECT rowid AS seq, id, blob FROM queue WHERE recipient = ? AND rowid > ? AND expires > ? ORDER BY rowid LIMIT ?'),
      ack: p('DELETE FROM queue WHERE id = ? AND recipient = ? RETURNING length(blob) AS len'),
      deleteQueue: p('DELETE FROM queue WHERE recipient = ? RETURNING length(blob) AS len'),
      purge: p('DELETE FROM queue WHERE expires <= ?'),
      // APP-2 (fair-share eviction): only used when the global quota is exhausted.
      largestQueue: p('SELECT recipient, SUM(length(blob)) AS bytes FROM queue GROUP BY recipient ORDER BY bytes DESC LIMIT 1'),
      evictOldest: p('DELETE FROM queue WHERE rowid = (SELECT MIN(rowid) FROM queue WHERE recipient = ?) RETURNING length(blob) AS len'),
    };

    // Global queue totals, kept in memory so the global quota check is O(1) per message.
    this.refreshTotals();
  }

  /**
   * One-time migration of a pre-existing rowid table to WITHOUT ROWID (same columns),
   * copying rows in primary-key order so the new layout carries no insertion order.
   */
  migrateToWithoutRowid(table, ddl, cols, orderBy) {
    const row = this.db.prepare("SELECT sql FROM sqlite_master WHERE type = 'table' AND name = ?").get(table);
    if (!row || /WITHOUT\s+ROWID/i.test(row.sql)) return;
    const tmp = `${table}__new`;
    this.tx(() => {
      this.db.exec(`DROP TABLE IF EXISTS ${tmp};`);
      this.db.exec(ddl.replace(`IF NOT EXISTS ${table}(`, `${tmp}(`));
      this.db.exec(`INSERT INTO ${tmp}(${cols}) SELECT ${cols} FROM ${table} ORDER BY ${orderBy};`);
      this.db.exec(`DROP TABLE ${table};`); // secure_delete zeroes the freed pages
      this.db.exec(`ALTER TABLE ${tmp} RENAME TO ${table};`);
    });
  }

  refreshTotals() {
    const t = this.s.queueTotals.get();
    this.totalCount = Number(t.n);
    this.totalBytes = Number(t.bytes);
  }

  /** Run `fn` inside an IMMEDIATE transaction; rolls back on any throw. */
  tx(fn) {
    this.db.exec('BEGIN IMMEDIATE');
    try {
      const r = fn();
      this.db.exec('COMMIT');
      return r;
    } catch (err) {
      try { this.db.exec('ROLLBACK'); } catch { /* ignore */ }
      throw err;
    }
  }

  /**
   * Create a user with its SPK and initial OPKs atomically.
   * @returns {true|'username_taken'|'identity_taken'} identity_taken (CRYPTO-7): the
   *   ik_sig or ik_dh is already registered (to another username). Both 32-byte keys are
   *   checked against both columns, so a key cannot be reused in the other role either.
   */
  createUser({ username, ikSig, ikDh, ikDhSig, spk, opks }) {
    return this.tx(() => {
      if (this.s.userExists.get(username)) return 'username_taken';
      if (this.s.identityUsed.get(ikSig, ikSig, ikDh, ikDh)) return 'identity_taken';
      this.s.insertUser.run(username, ikSig, ikDh, ikDhSig, spk.id, spk.pub, spk.sig);
      for (const o of opks) this.s.upsertOpk.run(username, o.id, o.pub);
      return true;
    });
  }

  getUser(username) {
    return this.s.getUser.get(username) ?? null;
  }

  userExists(username) {
    return !!this.s.userExists.get(username);
  }

  countOpks(username) {
    return this.s.countOpks.get(username).n;
  }

  /**
   * Atomically fetch the user and consume (delete) exactly one OPK — or none when
   * `consume` is false (per-target OPK budget exhausted, see index.js apiBundle).
   * @returns {null | {user, opk: {id, pub}|null, remaining:number}}
   */
  takeBundle(username, consume = true) {
    return this.tx(() => {
      const user = this.s.getUser.get(username);
      if (!user) return null;
      const opk = consume ? (this.s.takeOpk.get(username, username) ?? null) : null;
      const remaining = this.s.countOpks.get(username).n;
      return { user, opk, remaining };
    });
  }

  /**
   * Store additional OPKs (replacing same ids: the owning client is authoritative).
   * @returns {number|null} new count, or null if the per-user cap would be exceeded
   */
  addOpks(username, opks, maxStored) {
    return this.tx(() => {
      const before = this.s.countOpks.get(username).n;
      if (before + opks.length > maxStored) return null;
      for (const o of opks) this.s.upsertOpk.run(username, o.id, o.pub);
      return this.s.countOpks.get(username).n;
    });
  }

  /**
   * Replace ALL stored OPKs of a user with a fresh batch (CL-3 / CRYPTO-4: after a backup
   * restore the client no longer holds the private keys of OPKs uploaded after the
   * backup; serving them would make first messages undecryptable).
   * @returns {number} new count
   */
  replaceOpks(username, opks) {
    return this.tx(() => {
      this.s.deleteOpks.run(username);
      for (const o of opks) this.s.upsertOpk.run(username, o.id, o.pub);
      return this.s.countOpks.get(username).n;
    });
  }

  updateSpk(username, spk) {
    this.s.updateSpk.run(spk.id, spk.pub, spk.sig, username);
  }

  /** Insert one queue row with a fresh per-recipient sequence number (> floor). */
  insertQueued(recipient, id, blob, expires, floor) {
    const m = this.s.maxSeq.get(recipient).m;
    let base = Math.max(m === null || m === undefined ? 0 : Number(m), floor);
    if (base === 0) base = randomSeqStart();
    for (let attempt = 0; attempt < 8; attempt++) {
      const seq = base + randomInt(1, SEQ_MAX_GAP + 1);
      if (seq > SEQ_LIMIT) throw new Error('queue sequence space exhausted');
      try {
        this.s.enqueue.run(seq, id, recipient, blob, expires);
        return seq;
      } catch (err) {
        // Astronomically unlikely rowid collision with another recipient's row: redraw.
        if (!isConstraintError(err)) throw err;
      }
    }
    throw new Error('queue rowid allocation failed');
  }

  /**
   * Queue a batch of sealed blobs in ONE transaction (one fsync per /api/send request),
   * honouring the per-recipient limits and the global quota.
   * @param {{recipient:string, id:string, blob:Uint8Array}[]} items
   * @param {number} expires
   * @param {{maxMessages:number, maxBytes:number, maxTotalBytes?:number,
   *          minSeq?:(recipient:string)=>number}} limits
   *   minSeq: lower bound for the recipient's next sequence number (the live connection's
   *   flush cursor), so a message queued after the recipient's queue emptied can never get
   *   a seq below what that connection has already paged past.
   * @returns {({ok:true, seq:number} | {ok:false, error:'not_found'|'queue_full'})[]}
   */
  enqueueBatch(items, expires, { maxMessages, maxBytes, maxTotalBytes = Infinity, minSeq, reservedBytes = 0 }) {
    let addCount = 0;
    let addBytes = 0;
    let evCount = 0;
    let evBytes = 0;
    const out = this.tx(() => {
      /** @type {Map<string, {n:number, bytes:number} | null>} */
      const stats = new Map();
      const statOf = (r) => {
        if (!stats.has(r)) {
          stats.set(r, this.s.userExists.get(r) ? { ...this.s.queueStats.get(r) } : null);
        }
        return stats.get(r);
      };
      const used = () => this.totalBytes + addBytes - evBytes;
      /**
       * APP-2: the global quota must not be shared fate. When it is exhausted, a recipient
       * whose own queue is still under the fair-share reserve gets room by evicting the
       * OLDEST messages of the currently largest queue (which, under a flooding attack,
       * is one of the attacker's never-draining sink accounts). Recipients already above
       * the reserve are refused as before. Victims must themselves be above the reserve,
       * so eviction can never push a small queue out.
       */
      const makeRoom = (recipient, need) => {
        while (used() + need > maxTotalBytes) {
          const big = this.s.largestQueue.get();
          if (!big || big.recipient === recipient || Number(big.bytes) <= reservedBytes) return false;
          const r = this.s.evictOldest.get(big.recipient);
          if (!r) return false;
          evCount += 1;
          evBytes += Number(r.len);
          const vs = stats.get(big.recipient);
          if (vs) { vs.n -= 1; vs.bytes -= Number(r.len); }
        }
        return true;
      };
      return items.map(({ recipient, id, blob }) => {
        const st = statOf(recipient);
        if (!st) return { ok: false, error: 'not_found' };
        if (st.n + 1 > maxMessages || st.bytes + blob.length > maxBytes) {
          return { ok: false, error: 'queue_full' };
        }
        if (used() + blob.length > maxTotalBytes &&
            !(st.bytes + blob.length <= reservedBytes && makeRoom(recipient, blob.length))) {
          return { ok: false, error: 'queue_full' };
        }
        const floor = minSeq ? Number(minSeq(recipient)) || 0 : 0;
        const seq = this.insertQueued(recipient, id, blob, expires, floor);
        st.n += 1;
        st.bytes += blob.length;
        addCount += 1;
        addBytes += blob.length;
        return { ok: true, seq };
      });
    });
    // Only after a successful COMMIT.
    this.totalCount += addCount - evCount;
    this.totalBytes += addBytes - evBytes;
    return out;
  }

  /** Queue a single blob (see enqueueBatch). */
  enqueue(recipient, id, blob, expires, limits) {
    return this.enqueueBatch([{ recipient, id, blob }], expires, limits)[0];
  }

  /** Next batch of unexpired queued messages for `recipient` with rowid > afterSeq. */
  queuedAfter(recipient, afterSeq, now, limit = 64) {
    return this.s.queuedAfter.all(recipient, afterSeq, now, limit);
  }

  /** Delete queue entries by id, only those owned by `recipient`. Returns deleted count. */
  ack(recipient, ids) {
    let bytes = 0;
    const n = this.tx(() => {
      let c = 0;
      for (const id of ids) {
        const r = this.s.ack.get(id, recipient);
        if (r) { c += 1; bytes += Number(r.len); }
      }
      return c;
    });
    this.totalCount -= n;
    this.totalBytes -= bytes;
    return n;
  }

  /** Remove a user and everything associated with it. */
  deleteUser(username) {
    const rows = this.tx(() => {
      const r = this.s.deleteQueue.all(username);
      this.s.deleteOpks.run(username);
      this.s.deleteUser.run(username);
      return r;
    });
    this.totalCount -= rows.length;
    for (const r of rows) this.totalBytes -= Number(r.len);
  }

  /** Delete expired queue entries. Returns number deleted. */
  purgeExpired(now) {
    const n = Number(this.s.purge.run(now).changes);
    this.refreshTotals();
    return n;
  }

  close() {
    try { this.db.close(); } catch { /* already closed */ }
  }
}

export function openDatabase(dataDir) {
  return new SombraDb(dataDir);
}
