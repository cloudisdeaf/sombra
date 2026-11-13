// Sombra UI — pure formatting helpers (no DOM). Safe to import from Node for tests.

export const USERNAME_RE = /^[a-z0-9_]{3,32}$/;
export const MAX_FILE_BYTES = 100 * 1024 * 1024; // keep equal to the core limit
export const MAX_TEXT_CHARS = 20000;
export const MIN_PASSPHRASE = 10;
export const AVATAR_COLORS = 8;

const LOCALE = 'es-ES';
const fmtTime = new Intl.DateTimeFormat(LOCALE, { hour: '2-digit', minute: '2-digit' });
const fmtWeekday = new Intl.DateTimeFormat(LOCALE, { weekday: 'short' });
const fmtShortDate = new Intl.DateTimeFormat(LOCALE, { day: '2-digit', month: '2-digit', year: '2-digit' });
const fmtDayMonth = new Intl.DateTimeFormat(LOCALE, { day: 'numeric', month: 'long' });
const fmtFullDate = new Intl.DateTimeFormat(LOCALE, { day: 'numeric', month: 'long', year: 'numeric' });
const fmtDateTime = new Intl.DateTimeFormat(LOCALE, { dateStyle: 'full', timeStyle: 'short' });

/** Normalise user-typed username: trim, drop a leading "@", lowercase. */
export function normalizeUsername(str) {
  return String(str ?? '').trim().replace(/^@+/, '').toLowerCase();
}

export function isValidUsername(str) {
  return USERNAME_RE.test(str);
}

/** Explain what is wrong with a (normalised) username, or '' if valid. */
export function usernameProblem(u) {
  if (!u) return 'Escribe un nombre de usuario.';
  if (u.length < 3) return 'Mínimo 3 caracteres.';
  if (u.length > 32) return 'Máximo 32 caracteres.';
  if (!USERNAME_RE.test(u)) return 'Solo letras minúsculas a–z, números y guion bajo (_).';
  return '';
}

function startOfDay(ts) {
  const d = new Date(ts);
  d.setHours(0, 0, 0, 0);
  return d.getTime();
}

function validTs(ts) {
  return typeof ts === 'number' && Number.isFinite(ts) && ts > 0;
}

/** "14:05" */
export function timeOf(ts) {
  return validTs(ts) ? fmtTime.format(ts) : '';
}

/** Conversation-list timestamp: time today, weekday this week, short date otherwise. */
export function listTime(ts, now = Date.now()) {
  if (!validTs(ts)) return '';
  const today = startOfDay(now);
  if (ts >= today) return fmtTime.format(ts);
  if (ts >= today - 6 * 86400000) return fmtWeekday.format(ts);
  return fmtShortDate.format(ts);
}

/** Local calendar-day key used to group messages. */
export function dayKey(ts) {
  if (!validTs(ts)) return 'unknown';
  const d = new Date(ts);
  return `${d.getFullYear()}-${d.getMonth() + 1}-${d.getDate()}`;
}

/** Date separator label: "Hoy", "Ayer", "3 de marzo", "3 de marzo de 2024". */
export function dayLabel(ts, now = Date.now()) {
  if (!validTs(ts)) return '';
  const today = startOfDay(now);
  const day = startOfDay(ts);
  if (day === today) return 'Hoy';
  // Use calendar arithmetic, not 86400000, so DST changes do not break "Ayer".
  const y = new Date(today);
  y.setDate(y.getDate() - 1);
  if (day === y.getTime()) return 'Ayer';
  if (new Date(ts).getFullYear() === new Date(now).getFullYear()) return fmtDayMonth.format(ts);
  return fmtFullDate.format(ts);
}

export function fullDateTime(ts) {
  return validTs(ts) ? fmtDateTime.format(ts) : '';
}

/** Human readable size in Spanish units. */
export function formatSize(n) {
  const v = Number(n);
  if (!Number.isFinite(v) || v < 0) return '';
  if (v < 1024) return `${v} B`;
  const units = ['KB', 'MB', 'GB'];
  let x = v / 1024;
  let i = 0;
  while (x >= 1024 && i < units.length - 1) {
    x /= 1024;
    i += 1;
  }
  return `${x.toLocaleString(LOCALE, { maximumFractionDigits: x < 10 ? 1 : 0 })} ${units[i]}`;
}

/** Up to two upper-case initials for an avatar. Unicode-safe. */
export function initials(title) {
  const t = String(title ?? '').trim();
  if (!t) return '?';
  const parts = t.split(/[\s_.\-]+/u).filter(Boolean);
  const first = (p) => Array.from(p)[0] ?? '';
  // Prefer letters/digits so "Equipo <b>" gives "EB", not "E<"; symbol-only names
  // (e.g. emoji) fall back to their first characters.
  const words = parts.map((p) => Array.from(p).filter((c) => /[\p{L}\p{N}]/u.test(c))).filter((w) => w.length);
  let out;
  if (words.length >= 2) out = words[0][0] + words[1][0];
  else if (words.length === 1) out = words[0].slice(0, 2).join('');
  else if (parts.length >= 2) out = first(parts[0]) + first(parts[1]);
  else out = Array.from(parts[0] ?? t).slice(0, 2).join('');
  return out.toLocaleUpperCase(LOCALE) || '?';
}

/** Deterministic colour bucket (0..AVATAR_COLORS-1) from a string, FNV-1a 32-bit. */
export function colorIndex(str) {
  let hsh = 0x811c9dc5;
  const t = String(str ?? '');
  for (let i = 0; i < t.length; i++) {
    hsh ^= t.charCodeAt(i);
    hsh = Math.imul(hsh, 0x01000193) >>> 0;
  }
  return hsh % AVATAR_COLORS;
}

/** Disappearing-message timer options (SPEC §6). */
export const TIMER_OPTIONS = [
  { seconds: 0, label: 'Desactivado', short: '' },
  { seconds: 30, label: '30 segundos', short: '30 s' },
  { seconds: 300, label: '5 minutos', short: '5 min' },
  { seconds: 3600, label: '1 hora', short: '1 h' },
  { seconds: 86400, label: '1 día', short: '1 d' },
  { seconds: 604800, label: '1 semana', short: '1 sem' },
];

export function timerLabel(seconds) {
  const n = Number(seconds) || 0;
  const opt = TIMER_OPTIONS.find((o) => o.seconds === n);
  if (opt) return opt.label;
  if (n < 60) return `${n} segundos`;
  if (n < 3600) return `${Math.round(n / 60)} minutos`;
  if (n < 86400) return `${Math.round(n / 3600)} horas`;
  return `${Math.round(n / 86400)} días`;
}

export function timerShort(seconds) {
  const n = Number(seconds) || 0;
  if (!n) return '';
  const opt = TIMER_OPTIONS.find((o) => o.seconds === n);
  if (opt) return opt.short;
  if (n < 60) return `${n} s`;
  if (n < 3600) return `${Math.round(n / 60)} min`;
  if (n < 86400) return `${Math.round(n / 3600)} h`;
  return `${Math.round(n / 86400)} d`;
}

/** Remaining time until `expiresAt`, compact ("4 min"). */
export function remaining(expiresAt, now = Date.now()) {
  const ms = Number(expiresAt) - now;
  if (!Number.isFinite(ms)) return '';
  if (ms <= 0) return '0 s';
  const sec = Math.ceil(ms / 1000);
  if (sec < 60) return `${sec} s`;
  if (sec < 3600) return `${Math.ceil(sec / 60)} min`;
  if (sec < 86400) return `${Math.ceil(sec / 3600)} h`;
  return `${Math.ceil(sec / 86400)} d`;
}

// C0/C1 controls and line/paragraph separators (become spaces) ...
const DISPLAY_CTRL_RE = /[\u0000-\u001f\u007f-\u009f\u2028\u2029]/g;
// ... and ALM, LRM/RLM, LRE/RLE/PDF/LRO/RLO, LRI/RLI/FSI/PDI (removed).
const DISPLAY_BIDI_RE = /[\u061c\u200e\u200f\u202a-\u202e\u2066-\u2069]/g;

/**
 * Clean peer-controlled one-line text (group titles, list previews, system notices) for display:
 * removes control and bidi embedding/override/isolate characters (so a name such as
 * "Equipo <RLO>olleh" cannot render reversed or reorder the surrounding UI text), collapses
 * whitespace and caps the length. Plain RTL scripts (Arabic, Hebrew) need none of these
 * characters and render unchanged.
 */
export function cleanDisplayText(str, max = 200) {
  let s = String(str ?? '').replace(DISPLAY_BIDI_RE, '').replace(DISPLAY_CTRL_RE, ' ').replace(/\s+/g, ' ').trim();
  if (s.length > max) s = `${s.slice(0, max - 1)}…`;
  return s;
}

/**
 * Make a received filename safe for the `download` attribute and display:
 * strip path components, control/bidi-override characters and reserved characters,
 * collapse whitespace, cap the length. Never returns an empty string.
 */
export function sanitizeFilename(name, fallback = 'archivo') {
  let n = String(name ?? '');
  n = n.replace(/^.*[\\/]/, ''); // drop any path
  // Control chars, bidi overrides/isolates (filename spoofing such as "gpj.exe"), reserved chars.
  n = n.replace(/[\u0000-\u001f\u007f-\u009f\u200e\u200f\u202a-\u202e\u2066-\u2069<>:"|?*]/gu, '');
  n = n.replace(/\s+/g, ' ').trim();
  n = n.replace(/^\.+/, ''); // no hidden / dot-only names
  if (n.length > 120) {
    const dot = n.lastIndexOf('.');
    const ext = dot > 0 && n.length - dot <= 10 ? n.slice(dot) : '';
    n = n.slice(0, 120 - ext.length) + ext;
  }
  return n || fallback;
}

/**
 * Detect a raster image type from magic bytes. Returns a MIME type or null.
 * We only render inline images whose bytes really are PNG/JPEG/GIF/WebP/BMP/AVIF —
 * never SVG (scriptable) and never trust the sender-declared MIME type.
 */
export function sniffImageMime(bytes) {
  if (!(bytes instanceof Uint8Array) || bytes.length < 12) return null;
  const b = bytes;
  if (b[0] === 0x89 && b[1] === 0x50 && b[2] === 0x4e && b[3] === 0x47 && b[4] === 0x0d && b[5] === 0x0a) return 'image/png';
  if (b[0] === 0xff && b[1] === 0xd8 && b[2] === 0xff) return 'image/jpeg';
  if (b[0] === 0x47 && b[1] === 0x49 && b[2] === 0x46 && b[3] === 0x38) return 'image/gif';
  if (b[0] === 0x52 && b[1] === 0x49 && b[2] === 0x46 && b[3] === 0x46 &&
      b[8] === 0x57 && b[9] === 0x45 && b[10] === 0x42 && b[11] === 0x50) return 'image/webp';
  if (b[0] === 0x42 && b[1] === 0x4d) return 'image/bmp';
  if (b[4] === 0x66 && b[5] === 0x74 && b[6] === 0x79 && b[7] === 0x70 &&
      b[8] === 0x61 && b[9] === 0x76 && b[10] === 0x69 && (b[11] === 0x66 || b[11] === 0x73)) return 'image/avif';
  return null;
}

/** Group a 60-digit safety number into 12 blocks of 5 digits. */
export function safetyGroups(str) {
  const digits = String(str ?? '').replace(/\D/g, '');
  const out = [];
  for (let i = 0; i < digits.length; i += 5) out.push(digits.slice(i, i + 5));
  return out;
}

/** "3 miembros" */
export function membersLabel(n) {
  const k = Number(n) || 0;
  return k === 1 ? '1 miembro' : `${k} miembros`;
}

/** Date stamp for backup filenames (YYYYMMDD, local). */
export function dateStamp(d = new Date()) {
  const p = (x) => String(x).padStart(2, '0');
  return `${d.getFullYear()}${p(d.getMonth() + 1)}${p(d.getDate())}`;
}
