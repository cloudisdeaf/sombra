// Registration access control (security review R-1).
//
// Who may create an account on this server:
//   'open'    anyone who can reach it (the default for library use and the plain server).
//   'invite'  only holders of a single-use invitation code, or the local launcher.
//   'closed'  nobody new, except the local launcher.
//
// The code is shown once to the operator, travels to the guest out of band, and the guest's
// launcher attaches it to POST /api/register as `X-Sombra-Invite`. Only SHA-256 hashes are
// stored (no timestamps, no codes), in <dataDir>/invites.json. The operator's own app reaches
// the server through the launcher proxy, which adds `X-Sombra-Local: <random per-run key>`;
// remote clients cannot know that key, so they cannot skip the check.

import fs from 'node:fs';
import path from 'node:path';
import { createHash, randomInt, timingSafeEqual } from 'node:crypto';

export const REGISTRATION_MODES = Object.freeze(['open', 'invite', 'closed']);

// No I, O, 0, 1: easy to read out loud and to type from a message.
const ALPHABET = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
const CODE_LEN = 20; // 20 x 5 bits = 100 bits
const CODE_RE = /^[A-HJ-NP-Z2-9]{20}$/;
const MAX_INVITES = 100;

/** Normalise what a person typed ("abcd-efgh …") to the canonical 20 characters, or null. */
export function normalizeInvite(input) {
  if (typeof input !== 'string' || input.length > 64) return null;
  const s = input.toUpperCase().replace(/[\s-]/g, '');
  return CODE_RE.test(s) ? s : null;
}

/** "ABCDEFGHJKLMNPQRSTUV" → "ABCD-EFGH-JKLM-NPQR-STUV". */
export function formatInvite(code) {
  return code.match(/.{4}/g).join('-');
}

const sha = (s) => createHash('sha256').update(s).digest();

export class AccessControl {
  /**
   * @param {{dir?: string|null, mode?: string, localKey?: string|null}} [o]
   */
  constructor({ dir = null, mode = 'open', localKey = null } = {}) {
    this.file = dir ? path.join(dir, 'invites.json') : null;
    this.localHash = localKey ? sha(String(localKey)) : null;
    this._mode = REGISTRATION_MODES.includes(mode) ? mode : 'open';
    /** @type {Set<string>} hex SHA-256 of each outstanding code */
    this.invites = new Set();
    this._load();
  }

  get mode() { return this._mode; }

  setMode(mode) {
    if (!REGISTRATION_MODES.includes(mode)) throw new TypeError('bad_mode');
    this._mode = mode;
  }

  count() { return this.invites.size; }

  /** Create a single-use invitation. Returns the code in display form. */
  createInvite() {
    if (this.invites.size >= MAX_INVITES) throw new Error('too_many_invites');
    let code = '';
    for (let i = 0; i < CODE_LEN; i++) code += ALPHABET[randomInt(ALPHABET.length)];
    this.invites.add(sha(code).toString('hex'));
    this._save();
    return formatInvite(code);
  }

  revokeAll() {
    this.invites.clear();
    this._save();
  }

  /**
   * Decide whether a registration request may proceed.
   * @returns {{ok: true, consume: () => void} | {ok: false, error: string}}
   */
  check(headers) {
    const local = headers['x-sombra-local'];
    if (this.localHash && typeof local === 'string' && local.length <= 256 &&
        timingSafeEqual(sha(local), this.localHash)) {
      return { ok: true, consume: () => {} };
    }
    if (this._mode === 'open') return { ok: true, consume: () => {} };
    if (this._mode === 'closed') return { ok: false, error: 'registration_closed' };
    const raw = headers['x-sombra-invite'];
    const code = typeof raw === 'string' ? normalizeInvite(raw) : null;
    const h = code ? sha(code).toString('hex') : null;
    if (!h || !this.invites.has(h)) return { ok: false, error: 'invite_required' };
    return {
      ok: true,
      consume: () => { if (this.invites.delete(h)) this._save(); },
    };
  }

  _load() {
    if (!this.file) return;
    try {
      const list = JSON.parse(fs.readFileSync(this.file, 'utf8'));
      if (Array.isArray(list)) {
        for (const h of list) if (typeof h === 'string' && /^[0-9a-f]{64}$/.test(h)) this.invites.add(h);
      }
    } catch { /* no file yet, or unreadable: start with none */ }
  }

  _save() {
    if (!this.file) return;
    const tmp = `${this.file}.tmp`;
    fs.writeFileSync(tmp, JSON.stringify([...this.invites]), { mode: 0o600 });
    fs.renameSync(tmp, this.file);
  }
}
