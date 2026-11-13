// Sombra UI — chat pane: header, key-change banner, message list, composer.

import { h, on, clear } from './dom.js';
import { icon } from './icons.js';
import { avatar } from './widgets.js';
import {
  dayKey, dayLabel, timeOf, fullDateTime, formatSize, colorIndex, sniffImageMime, sanitizeFilename,
  TIMER_OPTIONS, timerLabel, timerShort, membersLabel, remaining, MAX_TEXT_CHARS, cleanDisplayText,
} from './format.js';
import { openMenu, confirmDialog, toast, isMenuOpen } from './overlay.js';
import { errorText } from './errors.js';
import { BlobUrlCache, downloadBytes } from './files.js';

const LONG_PRESS_MS = 500;
const STICK_THRESHOLD_PX = 96;
// Max composer messages waiting (queued + in flight) before Enter is refused (bounded memory/work).
const MAX_QUEUED_SENDS = 20;
const SUPPORTS_FIELD_SIZING = typeof CSS !== 'undefined' && CSS.supports && CSS.supports('field-sizing', 'content');

function iconButton(name, label, cls = '') {
  return h('button', { type: 'button', class: ['icon-btn', cls], 'aria-label': label, title: label }, icon(name));
}

/**
 * Keyed DOM reconciliation: reuse nodes whose (key, sig) did not change, insert/move others,
 * remove leftovers. Unchanged nodes are never re-created, so screen readers watching the log
 * only hear genuinely new messages, and scroll position stays stable.
 */
function reconcile(container, items, cache) {
  const next = new Map();
  let ref = container.firstChild;
  for (const it of items) {
    let entry = cache.get(it.key);
    if (!entry || entry.sig !== it.sig) entry = { sig: it.sig, el: it.build() };
    next.set(it.key, entry);
    if (entry.el === ref) ref = ref.nextSibling;
    else container.insertBefore(entry.el, ref);
  }
  while (ref) {
    const n = ref.nextSibling;
    ref.remove();
    ref = n;
  }
  return next;
}

export function createChatView(app) {
  // ------------------------------------------------------------ structure
  const emptyState = h('div', { class: 'chat-empty' },
    h('div', { class: 'chat-empty-card' },
      icon('lock', { cls: 'empty-icon' }),
      h('h2', null, 'Tus mensajes están cifrados de extremo a extremo'),
      h('p', { class: 'muted' }, 'Selecciona un chat o empieza uno nuevo buscando un @usuario. Ni el servidor ni nadie más puede leerlos.')));

  const backBtn = iconButton('back', 'Volver a la lista de chats', 'back-btn');
  const headAvatar = h('span', { class: 'head-avatar' });
  const headTitle = h('span', { class: 'head-title', dir: 'auto' });
  const headSub = h('span', { class: 'head-sub' });
  const titleBtn = h('button', { type: 'button', class: 'head-info' }, headAvatar,
    h('span', { class: 'head-text' }, headTitle, headSub));
  const safetyBtn = iconButton('shield', 'Número de seguridad');
  const timerBadge = h('span', { class: 'timer-badge' });
  const timerBtn = h('button', { type: 'button', class: 'icon-btn timer-btn', 'aria-haspopup': 'menu', 'aria-expanded': 'false' }, icon('clock'), timerBadge);
  const moreBtn = h('button', { type: 'button', class: 'icon-btn', 'aria-label': 'Más opciones', title: 'Más opciones', 'aria-haspopup': 'menu', 'aria-expanded': 'false' }, icon('more'));
  const header = h('header', { class: 'chat-header' }, backBtn, titleBtn,
    h('div', { class: 'chat-actions' }, safetyBtn, timerBtn, moreBtn));

  const bannerSlot = h('div', { class: 'banner-slot' });
  const msgList = h('div', { class: 'messages-inner' });
  const scroller = h('div', {
    class: 'messages', tabindex: '0', role: 'log', 'aria-live': 'polite', 'aria-relevant': 'additions',
    'aria-label': 'Mensajes. Usa las flechas para recorrerlos y Intro para ver opciones.',
  }, msgList);

  const fileInput = h('input', { type: 'file', class: 'visually-hidden', tabindex: '-1', 'aria-hidden': 'true' });
  const attachBtn = iconButton('paperclip', 'Adjuntar archivo (máx. 100 MiB)', 'attach-btn');
  const textarea = h('textarea', {
    class: 'composer-input', rows: 1, placeholder: 'Mensaje cifrado…', 'aria-label': 'Escribe un mensaje',
    maxlength: MAX_TEXT_CHARS, dir: 'auto', autocomplete: 'off',
    // Privacy: browser "enhanced" spellcheck services may upload typed text.
    spellcheck: 'false', enterkeyhint: 'send',
  });
  const sendBtn = h('button', { type: 'submit', class: 'icon-btn send-btn', 'aria-label': 'Enviar', title: 'Enviar (Intro)', disabled: true }, icon('send'));
  const composerNote = h('p', { class: 'composer-note', hidden: true });
  const queueNote = h('p', { class: 'composer-queue', role: 'status', 'aria-live': 'polite', hidden: true });
  const composer = h('form', { class: 'composer', autocomplete: 'off' },
    composerNote, queueNote, h('div', { class: 'composer-row' }, attachBtn, textarea, sendBtn), fileInput);

  const inner = h('div', { class: 'chat-inner', hidden: true }, header, bannerSlot, scroller, composer);
  const dropHint = h('div', { class: 'drop-hint', hidden: true }, icon('upload'), h('span', null, 'Suelta el archivo para enviarlo cifrado'));
  const el = h('section', { class: 'chat', 'aria-label': 'Conversación' }, emptyState, inner, dropHint);

  // ------------------------------------------------------------ state
  let conv = null;
  let messages = [];
  let byId = new Map();
  let nodeCache = new Map();
  const blobs = new BlobUrlCache();
  let stickBottom = true;
  let loading = null;
  let loadAgain = false;
  let expiryTimer = null;
  // Composer send queue (BUG-1): one global promise chain, so network phases never overlap
  // (core serialises state mutations but not the network phase -> parallel sends could reorder).
  let sendChain = Promise.resolve();
  let pendingSends = []; // jobs queued or in flight: { id, gen, text, cancelled }

  const isOpen = () => Boolean(conv);
  const convId = () => (conv ? conv.id : null);
  const isGroup = () => Boolean(conv && conv.type === 'group');
  const isAdmin = () => Boolean(conv && conv.admin && conv.admin === app.me);

  // ------------------------------------------------------------ header
  function renderHeader() {
    clear(headAvatar).append(avatar(conv.title || conv.peer, conv.peer || conv.id, { group: isGroup() }));
    headTitle.textContent = conv.title || conv.peer || '';
    clear(headSub);
    if (isGroup()) {
      const n = Array.isArray(conv.members) ? conv.members.length : 0;
      headSub.append(icon('users', { cls: 'sub-icon' }), membersLabel(n));
      titleBtn.setAttribute('aria-label', `${conv.title}, ${membersLabel(n)}. Ver información del grupo`);
      safetyBtn.setAttribute('aria-label', 'Verificar miembros del grupo');
      safetyBtn.title = 'Verificar miembros del grupo';
      clear(safetyBtn).append(icon('shield'));
      safetyBtn.classList.remove('verified');
    } else {
      // Long text on wide screens, short one on narrow screens (CSS swaps them; BUG-4).
      if (conv.verified) {
        headSub.append(icon('shieldCheck', { cls: 'sub-icon ok' }),
          h('span', { class: 'sub-long' }, 'Verificado · cifrado de extremo a extremo'),
          h('span', { class: 'sub-short' }, 'Verificado'));
      } else {
        headSub.append(icon('lock', { cls: 'sub-icon' }),
          h('span', { class: 'sub-long' }, 'Cifrado de extremo a extremo · sin verificar'),
          h('span', { class: 'sub-short' }, 'Sin verificar'));
      }
      titleBtn.setAttribute('aria-label', `@${conv.peer}. Ver número de seguridad`);
      safetyBtn.setAttribute('aria-label', conv.verified ? 'Número de seguridad (verificado)' : 'Verificar número de seguridad');
      safetyBtn.title = safetyBtn.getAttribute('aria-label');
      clear(safetyBtn).append(icon(conv.verified ? 'shieldCheck' : 'shield'));
      safetyBtn.classList.toggle('verified', Boolean(conv.verified));
    }
    const t = Number(conv.timer) || 0;
    timerBadge.textContent = timerShort(t);
    timerBtn.classList.toggle('active', t > 0);
    const tl = `Mensajes temporales: ${timerLabel(t)}`;
    timerBtn.setAttribute('aria-label', tl);
    timerBtn.title = tl;
    renderBanner();
  }

  function renderBanner() {
    clear(bannerSlot);
    const blocked = Boolean(conv && conv.type === 'direct' && conv.keyChanged);
    setComposerBlocked(blocked ? 'El número de seguridad ha cambiado. Revísalo y acéptalo para seguir escribiendo.' : '');
    if (!blocked) return;
    const peer = conv.peer;
    const viewBtn = h('button', { type: 'button', class: 'btn btn-small btn-ghost' }, icon('shield'), 'Ver número de seguridad');
    const acceptBtn = h('button', { type: 'button', class: 'btn btn-small btn-warn' }, 'Aceptar');
    on(viewBtn, 'click', () => app.showSafety(peer));
    on(acceptBtn, 'click', async () => {
      acceptBtn.disabled = true;
      try {
        await app.client.acceptKeyChange(peer);
        toast(`Nueva clave de @${peer} aceptada. Verifícala cuando puedas.`, 'success');
        await app.refreshConversations();
      } catch (err) {
        toast(errorText(err), 'error');
      } finally {
        acceptBtn.disabled = false;
      }
    });
    bannerSlot.append(h('div', { class: 'banner banner-warn', role: 'alert' },
      icon('alert', { cls: 'banner-icon' }),
      h('div', { class: 'banner-text' },
        h('strong', null, `El número de seguridad de @${peer} ha cambiado.`),
        h('span', null, ' Puede que haya reinstalado Sombra o cambiado de dispositivo, o que alguien intente interceptar la conversación. Compruébalo con esa persona por otro canal antes de continuar.')),
      h('div', { class: 'banner-actions' }, viewBtn, acceptBtn)));
  }

  function setComposerBlocked(reason) {
    const blocked = Boolean(reason);
    textarea.disabled = blocked;
    attachBtn.disabled = blocked;
    composerNote.hidden = !blocked;
    composerNote.textContent = reason || '';
    updateSendState();
  }

  on(backBtn, 'click', () => app.closeConversation());
  on(titleBtn, 'click', () => {
    if (!conv) return;
    if (isGroup()) app.showGroupInfo(conv.id);
    else app.showSafety(conv.peer);
  });
  on(safetyBtn, 'click', () => {
    if (!conv) return;
    if (isGroup()) app.showGroupInfo(conv.id);
    else app.showSafety(conv.peer);
  });
  on(timerBtn, 'click', () => {
    if (!conv) return;
    const current = Number(conv.timer) || 0;
    const id = conv.id;
    openMenu({
      anchor: timerBtn,
      label: 'Mensajes temporales',
      items: TIMER_OPTIONS.map((o) => ({
        label: o.label,
        checked: o.seconds === current,
        onSelect: async () => {
          if (o.seconds === current) return;
          try {
            await app.client.setTimer(id, o.seconds);
            toast(o.seconds ? `Mensajes temporales: ${o.label}` : 'Mensajes temporales desactivados', 'success');
            await app.refreshConversations();
            requestLoad();
          } catch (err) {
            toast(errorText(err), 'error');
          }
        },
      })),
    });
  });
  on(moreBtn, 'click', () => {
    if (!conv) return;
    const c = conv;
    const canDeleteConv = typeof app.client.deleteConversation === 'function';
    const items = [];
    if (c.type === 'group') {
      items.push({ label: 'Información del grupo', icon: 'info', onSelect: () => app.showGroupInfo(c.id) });
      if (isAdmin()) items.push({ label: 'Añadir miembros', icon: 'userPlus', onSelect: () => app.showAddMembers(c.id) });
    } else {
      items.push({ label: 'Número de seguridad', icon: 'shield', onSelect: () => app.showSafety(c.peer) });
    }
    items.push({ label: canDeleteConv ? 'Eliminar chat (solo aquí)' : 'Vaciar chat (solo aquí)', icon: 'trash', danger: true, onSelect: () => deleteChat(c) });
    items.push({ label: 'Vaciar chat para todos', icon: 'trash', danger: true, onSelect: () => wipeForAll(c, false) });
    if (c.type === 'direct') items.push({ label: 'Eliminar chat para todos', icon: 'trash', danger: true, onSelect: () => wipeForAll(c, true) });
    if (c.type === 'group') items.push({ label: 'Salir del grupo', icon: 'logout', danger: true, onSelect: () => app.leaveGroup(c.id) });
    openMenu({ anchor: moreBtn, label: 'Opciones del chat', items });
  });

  async function wipeForAll(c, remove) {
    const ok = await confirmDialog({
      title: remove ? 'Eliminar chat para todos' : 'Vaciar chat para todos',
      message: [
        remove
          ? 'Se borrarán todos los mensajes y archivos de este chat en tu dispositivo y se pedirá a la otra persona que también elimine el chat.'
          : 'Se borrarán todos los mensajes y archivos de este chat en tu dispositivo y se pedirá a los demás participantes que hagan lo mismo.',
        'No se puede garantizar: quien tenga una versión modificada o antigua de la app, o ya haya hecho capturas o copias, conservará el contenido. Si alguien está desconectado, se le aplicará al conectarse.',
      ],
      confirmLabel: remove ? 'Eliminar para todos' : 'Vaciar para todos',
      danger: true,
    });
    if (!ok) return;
    try {
      await app.client.wipeConversation(c.id, { remove });
      if (remove) app.closeConversation(); else requestLoad();
      await app.refreshConversations();
    } catch (err) {
      toast(errorText(err), 'error');
    }
  }

  async function deleteChat(c) {
    // SPEC §4.4 has no deleteConversation(); we feature-detect it and otherwise clear every
    // message of the conversation from this device (deleteMessages(..., forEveryone=false)).
    const canDeleteConv = typeof app.client.deleteConversation === 'function';
    const ok = await confirmDialog({
      title: canDeleteConv ? 'Eliminar chat' : 'Vaciar chat',
      message: canDeleteConv
        ? 'Se eliminará este chat y todos sus mensajes de este dispositivo. Los demás participantes conservarán su copia.'
        : 'Se eliminarán todos los mensajes de este chat en este dispositivo. Los demás participantes conservarán su copia.',
      confirmLabel: canDeleteConv ? 'Eliminar' : 'Vaciar',
      danger: true,
    });
    if (!ok) return;
    try {
      if (canDeleteConv) {
        await app.client.deleteConversation(c.id);
        app.closeConversation();
      } else {
        const all = await app.client.getMessages(c.id);
        const ids = all.map((m) => m.id);
        if (ids.length) await app.client.deleteMessages(c.id, ids, false);
        requestLoad();
      }
      await app.refreshConversations();
    } catch (err) {
      toast(errorText(err), 'error');
    }
  }

  // ------------------------------------------------------------ messages
  function ticks(m) {
    switch (m.status) {
      case 'sending': return icon('clock', { cls: 'tick tick-sending', label: 'Enviando' });
      case 'sent': return icon('check', { cls: 'tick', label: 'Enviado' });
      case 'delivered': return icon('checks', { cls: 'tick', label: 'Entregado' });
      case 'read': return icon('checks', { cls: 'tick tick-read', label: 'Leído' });
      case 'failed': return icon('alertCircle', { cls: 'tick tick-failed', label: 'No enviado' });
      default: return null;
    }
  }

  function buildFileContent(m) {
    const f = m.file || {};
    const data = f.data instanceof Uint8Array ? f.data : null;
    const name = sanitizeFilename(f.name);
    const imgMime = data ? sniffImageMime(data) : null;
    if (imgMime) {
      const url = blobs.get(m.id, data, imgMime);
      const img = h('img', { class: 'msg-image', src: url, alt: `Imagen: ${name}`, decoding: 'async', loading: 'lazy', draggable: 'false' });
      on(img, 'load', () => { if (stickBottom) scrollToBottom(); }, { once: true });
      return h('button', { type: 'button', class: 'image-btn', dataset: { action: 'open-image' }, 'aria-label': `Ver imagen ${name}` }, img);
    }
    return h('button', { type: 'button', class: 'file-chip', dataset: { action: 'download' }, 'aria-label': `Descargar ${name}, ${formatSize(f.size ?? (data ? data.length : 0))}` },
      h('span', { class: 'file-icon' }, icon('file')),
      h('span', { class: 'file-meta' },
        h('span', { class: 'file-name', dir: 'auto' }, name),
        h('span', { class: 'file-size' }, data ? formatSize(f.size ?? data.length) : 'Archivo no disponible')),
      icon('download', { cls: 'file-dl' }));
  }

  function buildMessage(m, { showSender, tail }) {
    if (m.kind === 'system') {
      // System notices embed peer-controlled names (e.g. group titles): no bidi overrides.
      return h('div', { class: 'msg-system', dataset: { id: m.id } }, h('span', { dir: 'auto' }, cleanDisplayText(m.text, 400)));
    }
    const isImage = m.kind === 'file' && m.file && m.file.data instanceof Uint8Array && sniffImageMime(m.file.data);
    const bubble = h('div', {
      class: ['bubble', isImage && 'bubble-media', m.kind === 'file' && !isImage && 'bubble-file',
        m.expiresAt && 'has-timer', m.status === 'failed' && 'bubble-failed'],
      tabindex: '-1',
      dataset: { id: m.id },
    });
    bubble.append(h('span', { class: 'visually-hidden' }, m.mine ? 'Tú: ' : `@${m.from}: `));
    if (showSender) bubble.append(h('div', { class: ['sender', `nc${colorIndex(m.from)}`], dir: 'auto' }, `@${m.from}`));
    if (m.kind === 'file') bubble.append(buildFileContent(m));
    else bubble.append(h('div', { class: 'text', dir: 'auto' }, m.text || ''));

    const meta = h('span', { class: 'meta' });
    if (m.expiresAt) {
      meta.append(icon('clock', { cls: 'meta-timer', label: `Desaparece en ${remaining(m.expiresAt)}` }));
    }
    meta.append(h('time', { title: fullDateTime(m.ts) }, timeOf(m.ts)));
    if (m.mine) {
      const t = ticks(m);
      if (t) meta.append(t);
    }
    bubble.append(meta);

    const row = h('div', { class: ['msg-row', m.mine ? 'out' : 'in', tail && 'tail'], dataset: { id: m.id } }, bubble);
    if (m.mine && m.status === 'failed') {
      row.append(h('button', { type: 'button', class: 'retry-hint', dataset: { action: 'retry' } },
        icon('retry'), 'No enviado · pulsa para reintentar'));
    }
    return row;
  }

  function daySeparator(ts) {
    return h('div', { class: 'day-sep', role: 'separator' }, h('span', null, dayLabel(ts)));
  }

  function renderMessages(forceBottom = false) {
    const now = Date.now();
    const visible = messages.filter((m) => !(m.expiresAt && m.expiresAt <= now));
    const group = isGroup();
    const items = [];
    let prevDay = null;
    let prevFrom = null;
    for (let i = 0; i < visible.length; i++) {
      const m = visible[i];
      const dk = dayKey(m.ts);
      if (dk !== prevDay) {
        const label = dayLabel(m.ts, now);
        items.push({ key: `day:${dk}`, sig: label, build: () => daySeparator(m.ts) });
        prevDay = dk;
        prevFrom = null;
      }
      if (m.kind === 'system') {
        items.push({ key: `m:${m.id}`, sig: `sys|${m.text}`, build: () => buildMessage(m, {}) });
        prevFrom = null;
        continue;
      }
      const next = visible[i + 1];
      const firstOfRun = prevFrom !== m.from;
      const tail = !next || next.kind === 'system' || next.from !== m.from || dayKey(next.ts) !== dk;
      const showSender = group && !m.mine && firstOfRun;
      const sig = [m.status, showSender ? 1 : 0, tail ? 1 : 0, m.expiresAt || 0].join('|');
      items.push({ key: `m:${m.id}`, sig, build: () => buildMessage(m, { showSender, tail }) });
      prevFrom = m.from;
    }

    const wasAtBottom = stickBottom;
    nodeCache = reconcile(msgList, items, nodeCache);
    // Revoke image URLs of messages that are gone.
    blobs.retain(new Set(visible.map((m) => m.id)));

    if (!visible.length) {
      msgList.append(h('div', { class: 'msg-system msg-intro' },
        h('span', null, isGroup()
          ? 'Grupo cifrado de extremo a extremo. Cada mensaje se cifra por separado para cada miembro.'
          : 'Los mensajes de este chat están cifrados de extremo a extremo. Verifica el número de seguridad para descartar intermediarios.')));
      nodeCache.clear();
    }
    if (forceBottom || wasAtBottom) scrollToBottom();
    scheduleExpiry(visible);
  }

  function scrollToBottom() {
    scroller.scrollTop = scroller.scrollHeight;
    stickBottom = true;
  }

  on(scroller, 'scroll', () => {
    stickBottom = scroller.scrollHeight - scroller.scrollTop - scroller.clientHeight < STICK_THRESHOLD_PX;
  }, { passive: true });

  /** Re-render when the next disappearing message is due (the client sweeper deletes it too). */
  function scheduleExpiry(visible) {
    clearTimeout(expiryTimer);
    expiryTimer = null;
    let soonest = Infinity;
    for (const m of visible) if (m.expiresAt && m.expiresAt < soonest) soonest = m.expiresAt;
    if (soonest === Infinity) return;
    const delay = Math.max(250, Math.min(soonest - Date.now() + 50, 60000));
    expiryTimer = setTimeout(() => { if (conv) renderMessages(); }, delay);
  }

  /** Load messages for the open conversation; coalesces concurrent requests. */
  function requestLoad(forceBottom = false) {
    if (!conv) return Promise.resolve();
    if (loading) {
      loadAgain = true;
      if (forceBottom) stickBottom = true;
      return loading;
    }
    const id = conv.id;
    const gen = app.gen;
    loading = (async () => {
      try {
        do {
          loadAgain = false;
          const list = await app.client.getMessages(id);
          if (!conv || conv.id !== id || gen !== app.gen) return;
          messages = Array.isArray(list) ? list : [];
          byId = new Map(messages.map((m) => [m.id, m]));
          renderMessages(forceBottom);
          forceBottom = false;
        } while (loadAgain && conv && conv.id === id && gen === app.gen);
      } catch (err) {
        if (gen === app.gen) toast(errorText(err, 'No se pudieron cargar los mensajes.'), 'error');
      } finally {
        loading = null;
      }
    })();
    return loading;
  }

  // ------------------------------------------------------------ message interactions
  function messageFromEvent(e) {
    const row = e.target.closest && e.target.closest('.msg-row');
    if (!row || !msgList.contains(row)) return null;
    return byId.get(row.dataset.id) || null;
  }

  function messageMenu(m, x, y, anchor) {
    if (!m || m.kind === 'system') return;
    const id = conv.id;
    const items = [];
    if (m.kind === 'text' && m.text) {
      items.push({
        label: 'Copiar texto', icon: 'copy', onSelect: async () => {
          try { await navigator.clipboard.writeText(m.text); toast('Texto copiado.', 'success', 2000); }
          catch { toast('No se pudo copiar.', 'error'); }
        },
      });
    }
    if (m.kind === 'file' && m.file && m.file.data instanceof Uint8Array) {
      items.push({ label: 'Descargar', icon: 'download', onSelect: () => downloadBytes(m.file.data, m.file.name) });
    }
    if (m.mine && m.status === 'failed') items.push({ label: 'Reintentar envío', icon: 'retry', onSelect: () => retry(m) });
    items.push({ label: 'Eliminar para mí', icon: 'trash', danger: true, onSelect: () => deleteMsg(id, m, false) });
    if (m.mine && m.status !== 'failed' && m.status !== 'sending') {
      items.push({ label: 'Eliminar para todos', icon: 'trash', danger: true, onSelect: () => deleteMsg(id, m, true) });
    }
    openMenu({ x, y, anchor: x === undefined ? anchor : undefined, label: 'Opciones del mensaje', items, returnFocus: anchor });
  }

  async function deleteMsg(id, m, forEveryone) {
    if (forEveryone) {
      const ok = await confirmDialog({
        title: 'Eliminar para todos',
        message: 'El mensaje se eliminará de este dispositivo y se pedirá a los demás participantes que lo eliminen. No se puede garantizar si alguien modificó su aplicación o ya lo copió.',
        confirmLabel: 'Eliminar',
        danger: true,
      });
      if (!ok) return;
    }
    try {
      await app.client.deleteMessages(id, [m.id], forEveryone);
      requestLoad();
      app.refreshConversations();
    } catch (err) {
      toast(errorText(err), 'error');
    }
  }

  async function retry(m) {
    if (!conv) return;
    const id = conv.id;
    try {
      let resent = false;
      if (m.kind === 'text') {
        await app.client.sendText(id, m.text);
        resent = true;
      } else if (m.kind === 'file' && m.file && m.file.data instanceof Uint8Array) {
        await app.client.sendFile(id, { name: m.file.name, mime: m.file.mime, bytes: m.file.data });
        resent = true;
      }
      // Drop the failed copy only once a replacement message exists (send did not throw).
      if (resent) await app.client.deleteMessages(id, [m.id], false);
    } catch (err) {
      toast(errorText(err, 'No se pudo reenviar el mensaje.'), 'error');
    } finally {
      requestLoad(true);
      app.refreshConversations();
    }
  }

  on(msgList, 'click', (e) => {
    const actionEl = e.target.closest && e.target.closest('[data-action]');
    if (!actionEl) return;
    const m = messageFromEvent(e);
    if (!m) return;
    const action = actionEl.dataset.action;
    if (action === 'download' && m.file && m.file.data instanceof Uint8Array) downloadBytes(m.file.data, m.file.name);
    else if (action === 'open-image') {
      const url = blobs.peek(m.id);
      if (url) app.showImage({ url, name: m.file.name, bytes: m.file.data, onDownload: () => downloadBytes(m.file.data, m.file.name) });
    } else if (action === 'retry') retry(m);
  });

  let suppressContextUntil = 0;
  on(msgList, 'contextmenu', (e) => {
    const m = messageFromEvent(e);
    if (!m || m.kind === 'system') return;
    e.preventDefault();
    if (Date.now() < suppressContextUntil) return;
    const bubble = e.target.closest('.msg-row').querySelector('.bubble');
    messageMenu(m, e.clientX, e.clientY, bubble);
  });

  // Long-press for touch devices (iOS Safari does not fire contextmenu).
  let pressTimer = null;
  let pressStart = null;
  const cancelPress = () => { clearTimeout(pressTimer); pressTimer = null; pressStart = null; };
  on(msgList, 'pointerdown', (e) => {
    if (e.pointerType !== 'touch') return;
    const m = messageFromEvent(e);
    if (!m || m.kind === 'system') return;
    pressStart = { x: e.clientX, y: e.clientY };
    const bubble = e.target.closest('.msg-row').querySelector('.bubble');
    pressTimer = setTimeout(() => {
      pressTimer = null;
      suppressContextUntil = Date.now() + 800;
      bubble.classList.add('pressed');
      setTimeout(() => bubble.classList.remove('pressed'), 200);
      messageMenu(m, pressStart.x, pressStart.y, bubble);
    }, LONG_PRESS_MS);
  });
  on(msgList, 'pointermove', (e) => {
    if (pressStart && Math.hypot(e.clientX - pressStart.x, e.clientY - pressStart.y) > 10) cancelPress();
  });
  on(msgList, 'pointerup', cancelPress);
  on(msgList, 'pointercancel', cancelPress);

  // Keyboard navigation: arrows move between bubbles, Enter/ContextMenu/Shift+F10 open the menu.
  on(scroller, 'keydown', (e) => {
    if (isMenuOpen()) return;
    const bubbles = [...msgList.querySelectorAll('.bubble')];
    if (!bubbles.length) return;
    const idx = bubbles.indexOf(document.activeElement);
    if (e.key === 'ArrowUp' || e.key === 'ArrowDown') {
      e.preventDefault();
      let next;
      if (idx < 0) next = bubbles[bubbles.length - 1];
      else next = bubbles[Math.max(0, Math.min(bubbles.length - 1, idx + (e.key === 'ArrowUp' ? -1 : 1)))];
      next.focus();
      next.scrollIntoView({ block: 'nearest' });
    } else if (idx >= 0 && (e.key === 'Enter' || e.key === 'ContextMenu' || (e.key === 'F10' && e.shiftKey))) {
      e.preventDefault();
      const b = bubbles[idx];
      const r = b.getBoundingClientRect();
      messageMenu(byId.get(b.dataset.id), r.left + 16, r.bottom - 4, b);
    } else if (e.key === 'Escape') {
      e.preventDefault();
      if (!textarea.disabled) textarea.focus();
    }
  });

  // ------------------------------------------------------------ composer
  function autoGrow() {
    if (SUPPORTS_FIELD_SIZING) return;
    textarea.style.height = 'auto'; // CSSOM (CSP-safe)
    textarea.style.height = `${Math.min(textarea.scrollHeight, 200)}px`;
  }

  function updateSendState() {
    sendBtn.disabled = textarea.disabled || textarea.value.trim().length === 0;
    // Visible feedback for queued/in-flight messages of the open conversation.
    const n = conv ? pendingSends.filter((j) => !j.cancelled && j.id === conv.id).length : 0;
    sendBtn.classList.toggle('is-sending', n > 0);
    queueNote.hidden = n === 0;
    queueNote.textContent = n === 0 ? '' : n === 1 ? 'Enviando…' : `Enviando… (${n} mensajes en cola)`;
  }

  on(textarea, 'input', () => {
    autoGrow();
    updateSendState();
    if (conv) app.drafts.set(conv.id, textarea.value);
  });
  on(textarea, 'keydown', (e) => {
    if (e.key === 'Enter' && !e.shiftKey && !e.isComposing && e.keyCode !== 229) {
      e.preventDefault();
      sendCurrent();
    } else if (e.key === 'Escape' && app.isNarrow()) {
      // no-op on desktop; on mobile Escape behaves like "back"
      e.preventDefault();
      app.closeConversation();
    }
  });
  on(composer, 'submit', (e) => {
    e.preventDefault();
    sendCurrent();
  });

  /**
   * Accept the composer text and queue it (BUG-1: Enter used to be silently ignored while a
   * previous send was in flight). Sends run strictly one after another (no overlapping network
   * phases, so delivery order is preserved). A job captures the conversation id and the app
   * generation; a lock (generation bump / destroy) cancels every job that has not started.
   */
  function sendCurrent() {
    if (!conv || textarea.disabled) return;
    const text = textarea.value.trim();
    if (!text) return;
    if (text.length > MAX_TEXT_CHARS) {
      toast(`El mensaje supera ${MAX_TEXT_CHARS.toLocaleString('es-ES')} caracteres.`, 'error');
      return;
    }
    if (pendingSends.length >= MAX_QUEUED_SENDS) {
      toast('Espera a que se envíen los mensajes anteriores.', 'warn');
      return;
    }
    const job = { id: conv.id, gen: app.gen, text, cancelled: false };
    pendingSends.push(job);
    textarea.value = '';
    app.drafts.delete(job.id);
    autoGrow();
    updateSendState();
    stickBottom = true;
    sendChain = sendChain.then(() => runSend(job), () => runSend(job));
  }

  const jobLive = (job) => !job.cancelled && job.gen === app.gen;

  /** Put unsent texts back (before whatever the user typed meanwhile) so nothing is lost. */
  function restoreTexts(id, texts) {
    if (!texts.length) return;
    const restored = texts.join('\n');
    if (conv && conv.id === id) {
      textarea.value = textarea.value ? `${restored}\n${textarea.value}` : restored;
      app.drafts.set(id, textarea.value);
      autoGrow();
    } else {
      const d = app.drafts.get(id) || '';
      app.drafts.set(id, d ? `${restored}\n${d}` : restored);
    }
  }

  async function runSend(job) {
    try {
      if (!jobLive(job)) return;
      try {
        await app.client.sendText(job.id, job.text);
      } catch (err) {
        if (!jobLive(job)) return; // locked meanwhile: never resurrect plaintext
        // Stop this conversation's queue: do not auto-send later messages out of order or
        // after a condition the user must see first (e.g. key_changed). Give them back.
        const rest = pendingSends.filter((j) => j !== job && j.id === job.id && jobLive(j));
        for (const j of rest) j.cancelled = true;
        restoreTexts(job.id, [job.text, ...rest.map((j) => j.text)]);
        toast(errorText(err, 'No se pudo enviar el mensaje.'), 'error');
      }
    } catch {
      // never break the chain
    } finally {
      pendingSends = pendingSends.filter((j) => j !== job && !j.cancelled);
      if (job.gen === app.gen) {
        updateSendState();
        if (conv && conv.id === job.id) {
          requestLoad(true);
          if (!textarea.disabled && !pendingSends.length) textarea.focus();
        }
        app.refreshConversations();
      }
    }
  }

  function cancelPendingSends() {
    for (const j of pendingSends) j.cancelled = true;
    pendingSends = [];
  }

  on(attachBtn, 'click', () => fileInput.click());
  on(fileInput, 'change', () => {
    const f = fileInput.files && fileInput.files[0];
    fileInput.value = '';
    if (f && conv) app.confirmSendFile(conv.id, f);
  });
  on(textarea, 'paste', (e) => {
    if (!conv || !e.clipboardData) return;
    const files = [...(e.clipboardData.files || [])];
    const img = files.find((f) => f.type && f.type.startsWith('image/'));
    if (img) {
      e.preventDefault();
      app.confirmSendFile(conv.id, img, { pasted: true });
    }
  });

  // Drag & drop a file onto the chat pane.
  let dragDepth = 0;
  const hasFiles = (e) => e.dataTransfer && [...(e.dataTransfer.types || [])].includes('Files');
  on(el, 'dragenter', (e) => {
    if (!conv || !hasFiles(e) || textarea.disabled) return;
    e.preventDefault();
    dragDepth += 1;
    dropHint.hidden = false;
  });
  on(el, 'dragover', (e) => { if (conv && hasFiles(e)) e.preventDefault(); });
  on(el, 'dragleave', () => {
    dragDepth = Math.max(0, dragDepth - 1);
    if (!dragDepth) dropHint.hidden = true;
  });
  on(el, 'drop', (e) => {
    dragDepth = 0;
    dropHint.hidden = true;
    if (!conv || !hasFiles(e)) return;
    e.preventDefault();
    if (textarea.disabled) return;
    const f = e.dataTransfer.files && e.dataTransfer.files[0];
    if (f) app.confirmSendFile(conv.id, f);
  });

  // ------------------------------------------------------------ public API
  function resetMessages() {
    clearTimeout(expiryTimer);
    expiryTimer = null;
    clear(msgList);
    nodeCache = new Map();
    messages = [];
    byId = new Map();
    blobs.revokeAll();
  }

  return {
    el,
    isOpen,
    convId,
    async open(c) {
      const switching = !conv || conv.id !== c.id;
      if (conv && switching) app.drafts.set(conv.id, textarea.value);
      conv = c;
      emptyState.hidden = true;
      inner.hidden = false;
      if (switching) {
        resetMessages();
        textarea.value = app.drafts.get(c.id) || '';
        autoGrow();
        stickBottom = true;
      }
      renderHeader();
      updateSendState();
      await requestLoad(true);
      if (switching && !textarea.disabled && !app.isNarrow()) textarea.focus();
    },
    /** Update header/banner from a refreshed conversation record. */
    updateConv(c) {
      if (!conv || conv.id !== c.id) return;
      const groupChanged = c.type === 'group' && JSON.stringify(c.members) !== JSON.stringify(conv.members);
      conv = c;
      renderHeader();
      if (groupChanged) renderMessages();
    },
    reload: () => requestLoad(),
    close() {
      if (conv) app.drafts.set(conv.id, textarea.value);
      conv = null;
      resetMessages();
      textarea.value = '';
      inner.hidden = true;
      emptyState.hidden = false;
    },
    /** Drop all decrypted content from the DOM and revoke blob URLs (lock / wipe). */
    destroy() {
      cancelPendingSends();
      conv = null;
      resetMessages();
      textarea.value = '';
      clear(el);
    },
  };
}
