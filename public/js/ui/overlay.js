// Sombra UI — modal dialogs (native <dialog>), popup menus and toasts.
// Native <dialog>.showModal() gives us the top layer, inert background, focus containment
// and Escape handling for free; we add consistent structure and busy states.

import { h, on, uid } from './dom.js';
import { icon } from './icons.js';
import { errorText } from './errors.js';

const openDialogs = new Set();
let openMenuState = null;

/**
 * Open a modal dialog.
 * @param {object} o
 * @param {string} o.title
 * @param {Node|Node[]} [o.body]
 * @param {Array<{label:string, kind?:'primary'|'danger'|'ghost', icon?:string,
 *   onClick?: () => (boolean|void|Promise<boolean|void>), close?: boolean}>} [o.actions]
 *   onClick returning `false` keeps the dialog open. Thrown errors are shown inline.
 * @param {string} [o.size] 'wide' | 'narrow'
 * @param {() => void} [o.onClose]
 * @param {HTMLElement} [o.initialFocus]
 * @returns {{dialog: HTMLDialogElement, close: () => void, setError: (t:string)=>void, body: HTMLElement}}
 */
export function openDialog({ title, body, actions = [], size = '', onClose, initialFocus, dismissable = true }) {
  const titleId = uid('dlg-title');
  const errorEl = h('p', { class: 'dialog-error', role: 'alert', hidden: true });
  const bodyEl = h('div', { class: 'dialog-body' }, body);
  const closeBtn = h('button', { type: 'button', class: 'icon-btn dialog-close', 'aria-label': 'Cerrar' }, icon('x'));
  const footer = h('div', { class: 'dialog-actions' });
  const dialog = h('dialog', { class: ['dialog', size && `dialog-${size}`], 'aria-labelledby': titleId },
    h('div', { class: 'dialog-head' }, h('h2', { id: titleId, class: 'dialog-title' }, title), dismissable ? closeBtn : null),
    bodyEl, errorEl, actions.length ? footer : null);

  let closed = false;
  const close = () => {
    if (closed) return;
    closed = true;
    openDialogs.delete(api);
    if (dialog.open) dialog.close();
    dialog.remove();
    if (onClose) {
      try { onClose(); } catch { /* ignore */ }
    }
  };
  const setError = (text) => {
    errorEl.textContent = text || '';
    errorEl.hidden = !text;
  };
  const api = { dialog, close, setError, body: bodyEl };

  const buttons = actions.map((a) => {
    const btn = h('button', { type: 'button', class: ['btn', `btn-${a.kind || 'ghost'}`] }, a.icon ? icon(a.icon) : null, a.label);
    on(btn, 'click', async () => {
      setError('');
      if (!a.onClick) { close(); return; }
      const all = footer.querySelectorAll('button');
      all.forEach((b) => { b.disabled = true; });
      btn.classList.add('busy');
      try {
        const res = await a.onClick(api);
        if (res !== false && a.close !== false) close();
      } catch (err) {
        setError(errorText(err));
      } finally {
        btn.classList.remove('busy');
        all.forEach((b) => { b.disabled = false; });
      }
    });
    return btn;
  });
  footer.append(...buttons);

  on(closeBtn, 'click', close);
  on(dialog, 'cancel', (e) => {
    e.preventDefault();
    if (dismissable) close();
  });
  // Click on the backdrop (the dialog element itself, outside its box) closes.
  on(dialog, 'mousedown', (e) => {
    if (!dismissable || e.target !== dialog) return;
    const r = dialog.getBoundingClientRect();
    const inside = e.clientX >= r.left && e.clientX <= r.right && e.clientY >= r.top && e.clientY <= r.bottom;
    if (!inside) close();
  });

  document.body.append(dialog);
  openDialogs.add(api);
  dialog.showModal();
  const focusTarget = initialFocus || bodyEl.querySelector('input, select, textarea') || buttons[buttons.length - 1] || closeBtn;
  if (focusTarget) focusTarget.focus();
  return api;
}

/** Close every open dialog and menu (used when locking). */
export function closeAllOverlays() {
  for (const d of [...openDialogs]) d.close();
  closeMenu();
}

/**
 * Promise-based confirmation.
 * If `typed` is given, the user must type it exactly to enable the confirm button.
 */
export function confirmDialog({ title, message, confirmLabel = 'Aceptar', danger = false, typed = null, details = null }) {
  return new Promise((resolve) => {
    let result = false;
    const parts = [];
    for (const para of [].concat(message || [])) parts.push(h('p', null, para));
    if (details) parts.push(details);
    let input = null;
    if (typed) {
      const id = uid('typed');
      input = h('input', { id, class: 'input', type: 'text', autocomplete: 'off', spellcheck: 'false', autocapitalize: 'none' });
      parts.push(h('label', { class: 'field-label', for: id }, 'Escribe ', h('strong', { class: 'mono' }, typed), ' para confirmar'), input);
    }
    const dlg = openDialog({
      title,
      body: parts,
      size: 'narrow',
      onClose: () => resolve(result),
      actions: [
        { label: 'Cancelar', kind: 'ghost' },
        {
          label: confirmLabel,
          kind: danger ? 'danger' : 'primary',
          onClick: () => {
            if (typed && input.value.trim() !== typed) throw new Error('confirm_mismatch');
            result = true;
          },
        },
      ],
      initialFocus: input || undefined,
    });
    if (typed) {
      const confirmBtn = dlg.dialog.querySelector('.dialog-actions .btn:last-child');
      const sync = () => { confirmBtn.disabled = input.value.trim() !== typed; };
      on(input, 'input', sync);
      on(input, 'keydown', (e) => { if (e.key === 'Enter' && !confirmBtn.disabled) confirmBtn.click(); });
      sync();
    }
  });
}

// ---------------------------------------------------------------- popup menus

/**
 * Open a popup menu.
 * @param {object} o
 * @param {HTMLElement} [o.anchor] element to position next to (and to return focus to)
 * @param {number} [o.x] / [o.y] viewport coordinates (context menus)
 * @param {string} o.label accessible name
 * @param {Array<{label:string, icon?:string, danger?:boolean, checked?:boolean, disabled?:boolean, onSelect:()=>void}>} o.items
 */
export function openMenu({ anchor, x, y, label, items, returnFocus }) {
  closeMenu();
  const radio = items.some((i) => typeof i.checked === 'boolean');
  const menu = h('div', { class: 'menu', role: 'menu', 'aria-label': label, tabindex: '-1' });
  const buttons = items.map((item) => {
    const b = h('button', {
      type: 'button',
      class: ['menu-item', item.danger && 'danger'],
      role: radio ? 'menuitemradio' : 'menuitem',
      'aria-checked': radio ? String(Boolean(item.checked)) : undefined,
      tabindex: '-1',
      disabled: Boolean(item.disabled),
    }, item.icon ? icon(item.icon) : (radio ? h('span', { class: 'menu-radio', 'aria-hidden': 'true' }) : null), h('span', null, item.label));
    on(b, 'click', () => {
      closeMenu();
      try { item.onSelect(); } catch { /* handlers report their own errors */ }
    });
    return b;
  });
  menu.append(...buttons);
  const scrim = h('div', { class: 'menu-scrim' });
  on(scrim, 'mousedown', (e) => { e.preventDefault(); closeMenu(); });
  on(scrim, 'touchstart', (e) => { e.preventDefault(); closeMenu(); }, { passive: false });
  on(scrim, 'contextmenu', (e) => { e.preventDefault(); closeMenu(); });

  const enabled = () => buttons.filter((b) => !b.disabled);
  on(menu, 'keydown', (e) => {
    const list = enabled();
    const idx = list.indexOf(document.activeElement);
    if (e.key === 'ArrowDown') { e.preventDefault(); list[(idx + 1) % list.length]?.focus(); }
    else if (e.key === 'ArrowUp') { e.preventDefault(); list[(idx - 1 + list.length) % list.length]?.focus(); }
    else if (e.key === 'Home') { e.preventDefault(); list[0]?.focus(); }
    else if (e.key === 'End') { e.preventDefault(); list[list.length - 1]?.focus(); }
    else if (e.key === 'Escape' || e.key === 'Tab') { e.preventDefault(); closeMenu(); }
  });

  // Menus must live inside an open modal dialog to be interactive when one is open.
  const host = [...openDialogs].pop()?.dialog || document.body;
  host.append(scrim, menu);

  // Position (CSSOM — permitted by CSP, unlike style="" attributes).
  const vw = window.innerWidth;
  const vh = window.innerHeight;
  const mr = menu.getBoundingClientRect();
  let left;
  let top;
  if (anchor && x === undefined) {
    const ar = anchor.getBoundingClientRect();
    left = ar.right - mr.width;
    top = ar.bottom + 4;
    if (top + mr.height > vh - 8) top = ar.top - mr.height - 4;
  } else {
    left = x;
    top = y;
    if (left + mr.width > vw - 8) left = x - mr.width;
    if (top + mr.height > vh - 8) top = y - mr.height;
  }
  left = Math.max(8, Math.min(left, vw - mr.width - 8));
  top = Math.max(8, Math.min(top, vh - mr.height - 8));
  menu.style.left = `${Math.round(left)}px`;
  menu.style.top = `${Math.round(top)}px`;
  menu.classList.add('open');

  openMenuState = { menu, scrim, returnTo: returnFocus || anchor || document.activeElement };
  if (anchor) anchor.setAttribute('aria-expanded', 'true');
  openMenuState.anchor = anchor;
  const first = enabled().find((b) => b.getAttribute('aria-checked') === 'true') || enabled()[0];
  (first || menu).focus();
}

export function closeMenu() {
  if (!openMenuState) return;
  const { menu, scrim, returnTo, anchor } = openMenuState;
  openMenuState = null;
  menu.remove();
  scrim.remove();
  if (anchor) anchor.setAttribute('aria-expanded', 'false');
  if (returnTo && typeof returnTo.focus === 'function' && returnTo.isConnected) returnTo.focus();
}

export function isMenuOpen() {
  return Boolean(openMenuState);
}

// ---------------------------------------------------------------- toasts

/**
 * Transient status message. Contains UI text only — never message content.
 * @param {string} text
 * @param {'info'|'success'|'warn'|'error'} [kind]
 */
export function toast(text, kind = 'info', ms = 4000) {
  let region = document.getElementById('toasts');
  if (!region) {
    region = h('div', { id: 'toasts', class: 'toasts', role: 'status', 'aria-live': 'polite' });
    document.body.append(region);
  }
  const iconName = kind === 'error' ? 'alertCircle' : kind === 'warn' ? 'alert' : kind === 'success' ? 'check' : 'info';
  const el = h('div', { class: ['toast', `toast-${kind}`] }, icon(iconName), h('span', null, text));
  // If a modal dialog is open, render inside it so the toast is not hidden behind the top layer.
  const host = [...openDialogs].pop()?.dialog;
  if (host) {
    let local = host.querySelector('.toasts-local');
    if (!local) {
      local = h('div', { class: 'toasts toasts-local', role: 'status', 'aria-live': 'polite' });
      host.append(local);
    }
    local.append(el);
  } else {
    region.append(el);
  }
  const t = setTimeout(() => el.remove(), ms);
  on(el, 'click', () => { clearTimeout(t); el.remove(); });
}

/** Remove all toasts (used on lock). */
export function clearToasts() {
  document.querySelectorAll('.toast').forEach((t) => t.remove());
}
