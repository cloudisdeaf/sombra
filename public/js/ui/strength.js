// Sombra UI — passphrase strength estimator (pure, no DOM).
//
// A deliberately conservative entropy estimate: charset-size × length, then penalties for
// repeats, sequences, keyboard walks, common passwords and containing the username.
// It is a UX hint, not a guarantee; the vault adds PBKDF2 (600 000 iterations) on top.

import { MIN_PASSPHRASE } from './format.js';

const COMMON = [
  'password', 'contraseña', 'contrasena', 'qwerty', 'asdf', 'zxcv', '123456', '654321', 'abc123',
  'iloveyou', 'teamo', 'admin', 'welcome', 'bienvenido', 'letmein', 'dragon', 'monkey', 'sombra',
  'secreto', 'secret', 'clave', 'hola', 'futbol', 'football', 'princesa', 'princess', 'barcelona',
  'madrid', 'mexico', 'argentina', 'master', 'shadow', 'superman', 'batman', 'passw0rd', 'p4ssw0rd',
  'telegram', 'signal', 'whatsapp', '000000', '111111', '121212', 'qazwsx', 'trustno1',
];

const SEQUENCES = ['abcdefghijklmnopqrstuvwxyz', '0123456789', 'qwertyuiop', 'asdfghjkl', 'zxcvbnm', 'qwertzuiop'];

function charsetSize(p) {
  let n = 0;
  if (/[a-z]/.test(p)) n += 26;
  if (/[A-Z]/.test(p)) n += 26;
  if (/[0-9]/.test(p)) n += 10;
  if (/[ !-\/:-@\[-`{-~]/.test(p)) n += 33;
  if (/[^\x00-\x7f]/.test(p)) n += 60; // accented letters, ñ, emoji…
  return Math.max(n, 1);
}

/** Count characters that are part of runs of ≥3 sequential chars (forward or backward). */
function sequentialChars(lower) {
  let count = 0;
  for (const seq of SEQUENCES) {
    const rev = [...seq].reverse().join('');
    for (const s of [seq, rev]) {
      for (let len = s.length; len >= 3; len--) {
        for (let i = 0; i + len <= s.length; i++) {
          const sub = s.slice(i, i + len);
          if (lower.includes(sub)) {
            count += len;
            lower = lower.split(sub).join('\u0000');
          }
        }
      }
    }
  }
  return count;
}

/**
 * @param {string} pass
 * @param {string} [username]
 * @returns {{score: 0|1|2|3|4, bits: number, label: string, hint: string, acceptable: boolean}}
 */
export function estimateStrength(pass, username = '') {
  const p = String(pass ?? '');
  const chars = Array.from(p);
  if (chars.length === 0) {
    return { score: 0, bits: 0, label: '', hint: `Mínimo ${MIN_PASSPHRASE} caracteres. Mejor varias palabras al azar.`, acceptable: false };
  }
  const lower = p.toLowerCase();

  // Effective length: collapse repeated characters ("aaaa" counts ~1.5).
  let effective = 0;
  for (let i = 0; i < chars.length; i++) effective += chars[i] === chars[i - 1] ? 0.25 : 1;
  const uniq = new Set(chars).size;
  effective = Math.min(effective, uniq * 3);
  effective -= sequentialChars(lower) * 0.7;

  let common = false;
  for (const w of COMMON) {
    if (lower.includes(w)) {
      effective -= Math.max(0, w.length - 1);
      common = true;
    }
  }
  const u = String(username ?? '').toLowerCase();
  if (u.length >= 3 && lower.includes(u)) effective -= u.length - 1;

  // Word-based passphrases (spaces/dashes separating ≥4 words) get a small bonus: they are
  // usually random-ish and long.
  const words = p.split(/[\s\-_.]+/).filter((w) => w.length >= 3);
  let bits = Math.max(0, effective) * Math.log2(charsetSize(p));
  if (words.length >= 4) bits += 8;
  bits = Math.round(bits);

  let score;
  if (bits < 28) score = 0;
  else if (bits < 40) score = 1;
  else if (bits < 56) score = 2;
  else if (bits < 72) score = 3;
  else score = 4;

  if (chars.length < MIN_PASSPHRASE) score = Math.min(score, 1);
  if (common) score = Math.min(score, 1);

  const labels = ['Muy débil', 'Débil', 'Aceptable', 'Fuerte', 'Muy fuerte'];
  let hint = '';
  if (chars.length < MIN_PASSPHRASE) hint = `Mínimo ${MIN_PASSPHRASE} caracteres.`;
  else if (common) hint = 'Contiene palabras o patrones muy comunes.';
  else if (score < 2) hint = 'Añade más palabras o caracteres variados.';
  else if (score < 4) hint = 'Bien. Una frase más larga es aún más segura.';
  else hint = 'Excelente.';

  return {
    score,
    bits,
    label: labels[score],
    hint,
    // Policy: SPEC minimum length plus "not trivially guessable" (score ≥ 1).
    acceptable: chars.length >= MIN_PASSPHRASE && score >= 1,
  };
}
