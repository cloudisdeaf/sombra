// Sombra UI — non-sensitive per-device UI preferences in localStorage.
// Only settings live here (never keys, usernames or message data). Every access is wrapped
// because storage may be unavailable (private mode, blocked site data).

const PREFIX = 'sombra.ui.';

export const AUTOLOCK_CHOICES = [1, 2, 5, 10, 15, 30, 60];
const DEFAULTS = {
  autoLockMinutes: 10,
  lockOnHidden: false,
  hidePreviews: false,
  // C3: E2E receipts can be turned off (stronger protection against timing correlation).
  deliveryReceipts: true,
  readReceipts: true,
};

function read(key) {
  try {
    const raw = globalThis.localStorage?.getItem(PREFIX + key);
    return raw === null || raw === undefined ? undefined : JSON.parse(raw);
  } catch {
    return undefined;
  }
}

function write(key, value) {
  try {
    globalThis.localStorage?.setItem(PREFIX + key, JSON.stringify(value));
  } catch {
    /* storage unavailable: preference lasts for this session only */
  }
}

const memory = {};

export function getPref(key) {
  if (key in memory) return memory[key];
  const v = read(key);
  const def = DEFAULTS[key];
  if (v === undefined || typeof v !== typeof def) return def;
  if (key === 'autoLockMinutes' && !AUTOLOCK_CHOICES.includes(v)) return def;
  return v;
}

export function setPref(key, value) {
  memory[key] = value;
  write(key, value);
}

/** Remove all UI preferences (used on panic wipe / account deletion). */
export function clearPrefs() {
  for (const k of Object.keys(memory)) delete memory[k];
  try {
    const ls = globalThis.localStorage;
    if (!ls) return;
    const doomed = [];
    for (let i = 0; i < ls.length; i++) {
      const k = ls.key(i);
      if (k && k.startsWith(PREFIX)) doomed.push(k);
    }
    for (const k of doomed) ls.removeItem(k);
  } catch {
    /* ignore */
  }
}
