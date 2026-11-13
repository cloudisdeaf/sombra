// Sombra UI — sidebar: account header, search / new chat, conversation list.

import { h, on, clear } from './dom.js';
import { icon } from './icons.js';
import { avatar } from './widgets.js';
import { listTime, normalizeUsername, isValidUsername, timerLabel, fullDateTime } from './format.js';
import { getPref } from './prefs.js';

function iconButton(name, label, cls = '') {
  return h('button', { type: 'button', class: ['icon-btn', cls], 'aria-label': label, title: label }, icon(name));
}

export function createSidebar(app) {
  const statusDot = h('span', { class: 'status-dot', 'aria-hidden': 'true' });
  const statusText = h('span', { class: 'status-text' }, 'Conectando…');
  const status = h('span', { class: 'conn-status', role: 'status' }, statusDot, statusText);

  const newChatBtn = iconButton('edit', 'Nuevo chat');
  const newGroupBtn = iconButton('users', 'Nuevo grupo');
  const settingsBtn = iconButton('settings', 'Ajustes');
  const lockBtn = iconButton('lock', 'Bloquear ahora (Ctrl+Mayús+L)');

  const me = app.me || '';
  const header = h('header', { class: 'side-header' },
    h('div', { class: 'me' }, avatar(me, me, { size: 'sm' }),
      h('div', { class: 'me-text' }, h('span', { class: 'me-name' }, `@${me}`), status)),
    h('div', { class: 'side-actions' }, newChatBtn, newGroupBtn, settingsBtn, lockBtn));

  const search = h('input', {
    type: 'search', class: 'search-input', placeholder: 'Buscar o escribir @usuario',
    'aria-label': 'Buscar chats o iniciar un chat con un nombre de usuario',
    autocomplete: 'off', spellcheck: 'false', autocapitalize: 'none', maxlength: 64,
  });
  const searchBox = h('div', { class: 'search' }, icon('search', { cls: 'search-icon' }), search);

  const list = h('ul', { class: 'conv-list', 'aria-label': 'Chats' });
  const empty = h('div', { class: 'conv-empty', hidden: true });
  const scroller = h('nav', { class: 'conv-scroll', 'aria-label': 'Conversaciones' }, list, empty);

  const el = h('aside', { class: 'sidebar' }, header, searchBox, scroller);

  let convs = [];
  let activeId = null;

  on(newChatBtn, 'click', () => app.showNewChat());
  on(newGroupBtn, 'click', () => app.showNewGroup());
  on(settingsBtn, 'click', () => app.showSettings());
  on(lockBtn, 'click', () => app.lock());

  on(search, 'input', () => render());
  on(search, 'keydown', (e) => {
    if (e.key === 'Escape' && search.value) {
      e.preventDefault();
      search.value = '';
      render();
    } else if (e.key === 'Enter') {
      e.preventDefault();
      const firstBtn = list.querySelector('button');
      if (firstBtn) firstBtn.click();
    } else if (e.key === 'ArrowDown') {
      const firstBtn = list.querySelector('button');
      if (firstBtn) { e.preventDefault(); firstBtn.focus(); }
    }
  });
  // Arrow-key navigation within the list.
  on(list, 'keydown', (e) => {
    if (e.key !== 'ArrowDown' && e.key !== 'ArrowUp') return;
    const btns = [...list.querySelectorAll('button')];
    const i = btns.indexOf(document.activeElement);
    if (i < 0) return;
    e.preventDefault();
    if (e.key === 'ArrowDown') btns[Math.min(btns.length - 1, i + 1)].focus();
    else if (i === 0) search.focus();
    else btns[i - 1].focus();
  });

  function convItem(c) {
    const hide = getPref('hidePreviews');
    const isGroup = c.type === 'group';
    const titleRow = h('span', { class: 'conv-title' }, h('span', { class: 'conv-name', dir: 'auto' }, c.title || c.peer || '—'));
    if (c.verified) titleRow.append(icon('shieldCheck', { cls: 'ind ind-verified', label: 'Verificado' }));
    if (c.keyChanged) titleRow.append(icon('alert', { cls: 'ind ind-warn', label: 'Clave de seguridad cambiada' }));
    if (c.timer) titleRow.append(icon('clock', { cls: 'ind', label: `Mensajes temporales: ${timerLabel(c.timer)}` }));

    let last;
    if (!c.lastText && !c.lastTs) last = isGroup ? 'Grupo creado' : 'Sin mensajes';
    else if (hide) last = 'Mensaje cifrado';
    else last = c.lastText || '';
    const unread = Number(c.unread) || 0;

    const btn = h('button', {
      type: 'button',
      class: ['conv', c.id === activeId && 'active', unread > 0 && 'has-unread'],
      dataset: { id: c.id },
      'aria-current': c.id === activeId ? 'true' : undefined,
    },
      avatar(c.title || c.peer, c.peer || c.id, { group: isGroup }),
      h('span', { class: 'conv-main' },
        h('span', { class: 'conv-top' }, titleRow,
          h('time', { class: 'conv-time', title: fullDateTime(c.lastTs) }, listTime(c.lastTs))),
        h('span', { class: 'conv-bottom' },
          h('span', { class: ['conv-last', hide && 'muted-preview'], dir: 'auto' },
            isGroup ? icon('users', { cls: 'conv-kind' }) : icon('lock', { cls: 'conv-kind' }),
            h('span', null, last)),
          unread > 0 ? h('span', { class: 'badge', 'aria-label': `${unread} sin leer` }, unread > 999 ? '999+' : String(unread)) : null)));
    on(btn, 'click', () => app.openConversation(c.id));
    return h('li', null, btn);
  }

  function render() {
    const raw = search.value.trim();
    const q = raw.toLowerCase().replace(/^@+/, '');
    const filtered = (q
      ? convs.filter((c) => String(c.title || '').toLowerCase().includes(q) || String(c.peer || '').includes(q))
      : convs.slice()).sort((a, b) => (Number(b.lastTs) || 0) - (Number(a.lastTs) || 0));

    // Preserve keyboard focus across re-renders.
    const focusedId = document.activeElement && list.contains(document.activeElement)
      ? document.activeElement.dataset.id : null;

    clear(list);
    const candidate = normalizeUsername(raw);
    if (raw && isValidUsername(candidate) && candidate !== app.me &&
        !convs.some((c) => c.type === 'direct' && c.peer === candidate)) {
      const start = h('button', { type: 'button', class: 'conv conv-start', dataset: { id: '__start__' } },
        h('span', { class: 'avatar avatar-md av-accent', 'aria-hidden': 'true' }, icon('edit')),
        h('span', { class: 'conv-main' },
          h('span', { class: 'conv-top' }, h('span', { class: 'conv-title' }, `Iniciar chat con @${candidate}`)),
          h('span', { class: 'conv-bottom' }, h('span', { class: 'conv-last' }, 'Buscar este nombre de usuario en el servidor'))));
      on(start, 'click', async () => {
        start.disabled = true;
        const ok = await app.startChatWith(candidate);
        start.disabled = false;
        if (ok) { search.value = ''; render(); }
      });
      list.append(h('li', null, start));
    }
    for (const c of filtered) list.append(convItem(c));

    if (!list.firstChild) {
      empty.hidden = false;
      clear(empty).append(
        icon('chat', { cls: 'empty-icon' }),
        h('p', null, q ? 'No hay chats que coincidan.' : 'Aún no tienes chats.'),
        h('p', { class: 'muted' }, q
          ? 'Escribe un nombre de usuario válido (3–32 caracteres: a–z, 0–9, _) para iniciar un chat.'
          : 'Escribe el @usuario de alguien en el buscador o pulsa el lápiz para iniciar un chat cifrado.'));
    } else {
      empty.hidden = true;
    }
    if (focusedId) {
      const again = [...list.querySelectorAll('button')].find((b) => b.dataset.id === focusedId);
      if (again) again.focus();
    }
  }

  return {
    el,
    render(next) {
      convs = Array.isArray(next) ? next : [];
      render();
    },
    setActive(id) {
      activeId = id;
      for (const b of list.querySelectorAll('button.conv')) {
        const act = b.dataset.id === id;
        b.classList.toggle('active', act);
        if (act) b.setAttribute('aria-current', 'true');
        else b.removeAttribute('aria-current');
      }
    },
    setStatus(connected) {
      el.classList.toggle('online', Boolean(connected));
      statusText.textContent = connected ? 'Conectado' : 'Conectando…';
    },
    focusSearch() {
      search.focus();
    },
  };
}
