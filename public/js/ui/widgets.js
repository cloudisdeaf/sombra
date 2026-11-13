// Sombra UI — small reusable DOM widgets.

import { h, on, uid } from './dom.js';
import { icon } from './icons.js';
import { colorIndex, initials } from './format.js';

/** Circular avatar with initials and a deterministic colour derived from `seed`. */
export function avatar(title, seed, { size = 'md', group = false } = {}) {
  const el = h('span', { class: ['avatar', `avatar-${size}`, `av-c${colorIndex(seed ?? title)}`], 'aria-hidden': 'true' });
  if (group && !title) el.append(icon('users'));
  else el.append(document.createTextNode(initials(title)));
  return el;
}

/** Labelled text input. Returns { wrap, input, hint, setHint(text, kind) }. */
export function field({ label, type = 'text', name, placeholder = '', autocomplete = 'off', maxlength, hint = '', attrs = {} }) {
  const id = uid('f');
  const hintId = `${id}-hint`;
  const input = h('input', {
    id, name, type, class: 'input', placeholder, autocomplete, maxlength,
    spellcheck: 'false', autocapitalize: 'none', autocorrect: 'off', 'aria-describedby': hintId, ...attrs,
  });
  const hintEl = h('p', { id: hintId, class: 'field-hint' }, hint);
  const wrap = h('div', { class: 'field' }, h('label', { class: 'field-label', for: id }, label), input, hintEl);
  const setHint = (text, kind = '') => {
    hintEl.textContent = text;
    hintEl.className = ['field-hint', kind && `hint-${kind}`].filter(Boolean).join(' ');
    if (kind === 'error') input.setAttribute('aria-invalid', 'true');
    else input.removeAttribute('aria-invalid');
  };
  return { wrap, input, hint: hintEl, setHint };
}

/** Password field with a show/hide toggle. */
export function passwordField(opts) {
  const f = field({ ...opts, type: 'password' });
  const toggle = h('button', { type: 'button', class: 'icon-btn field-eye', 'aria-label': 'Mostrar frase', 'aria-pressed': 'false' }, icon('eye'));
  on(toggle, 'click', () => {
    const show = f.input.type === 'password';
    f.input.type = show ? 'text' : 'password';
    toggle.setAttribute('aria-pressed', String(show));
    toggle.setAttribute('aria-label', show ? 'Ocultar frase' : 'Mostrar frase');
    toggle.replaceChildren(icon(show ? 'eyeOff' : 'eye'));
  });
  const row = h('div', { class: 'input-row' });
  f.input.replaceWith(row);
  row.append(f.input, toggle);
  return { ...f, toggle };
}

/** Labelled checkbox. */
export function checkbox(label, checked = false, description = '') {
  const id = uid('cb');
  const input = h('input', { id, type: 'checkbox', class: 'checkbox', checked });
  const wrap = h('label', { class: 'check-row', for: id }, input,
    h('span', { class: 'check-text' }, h('span', null, label), description ? h('span', { class: 'check-desc' }, description) : null));
  return { wrap, input };
}

/** Indeterminate / determinate progress bar. */
export function progressBar(labelText = '') {
  const fill = h('div', { class: 'progress-fill' });
  const bar = h('div', { class: 'progress indeterminate', role: 'progressbar', 'aria-label': labelText || 'Progreso' }, fill);
  const set = (fraction) => {
    if (typeof fraction === 'number' && Number.isFinite(fraction)) {
      const pct = Math.max(0, Math.min(100, Math.round(fraction * 100)));
      bar.classList.remove('indeterminate');
      bar.setAttribute('aria-valuenow', String(pct));
      bar.setAttribute('aria-valuemin', '0');
      bar.setAttribute('aria-valuemax', '100');
      fill.style.width = `${pct}%`; // CSSOM, allowed by CSP
    } else {
      bar.classList.add('indeterminate');
      bar.removeAttribute('aria-valuenow');
      fill.style.removeProperty('width');
    }
  };
  return { bar, set };
}

/** Username chip-list editor used by group dialogs. */
export function chip(text, onRemove) {
  const rm = h('button', { type: 'button', class: 'chip-x', 'aria-label': `Quitar @${text}` }, icon('x'));
  on(rm, 'click', onRemove);
  return h('span', { class: 'chip' }, h('span', null, `@${text}`), rm);
}
