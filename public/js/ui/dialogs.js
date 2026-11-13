// Sombra UI — modal dialogs: safety number, new chat, groups, settings, file send, image viewer.

import { h, on, clear, uid } from './dom.js';
import { icon } from './icons.js';
import { avatar, field, checkbox, chip } from './widgets.js';
import { openDialog, confirmDialog, toast } from './overlay.js';
import { errorText, errorUsername, UiError } from './errors.js';
import {
  normalizeUsername, usernameProblem, safetyGroups, formatSize, sniffImageMime, sanitizeFilename,
  MAX_FILE_BYTES, membersLabel, dateStamp,
} from './format.js';
import { downloadBytes } from './files.js';
import { getPref, setPref, AUTOLOCK_CHOICES } from './prefs.js';
import { formatSafetyNumber } from '../crypto/safety.js';

// SPEC §3.6: one /api/send batch carries at most 100 messages and a group message is a pairwise
// fan-out in a single batch, so a group can have at most 100 members besides ourselves.
export const MAX_GROUP_OTHERS = 100;
const MAX_GROUP_NAME = 64;

// ------------------------------------------------------------------ safety number

export async function showSafety(app, username) {
  let info;
  try {
    info = await app.client.getSafetyNumber(username);
  } catch (err) {
    toast(errorText(err, 'No se pudo calcular el número de seguridad.'), 'error');
    return;
  }
  const conv = app.convs.find((c) => c.type === 'direct' && c.peer === username);
  const keyChanged = Boolean(conv && conv.keyChanged);
  const formatted = info.formatted || formatSafetyNumber(info.number);
  const groups = safetyGroups(info.number || formatted);

  const grid = h('div', { class: 'safety-grid', role: 'group', 'aria-label': `Número de seguridad: ${formatted}` },
    groups.map((g) => h('span', { class: 'safety-cell', 'aria-hidden': 'true' }, g)));
  const statusEl = h('p', { class: ['safety-status', info.verified ? 'ok' : 'muted'] },
    icon(info.verified ? 'shieldCheck' : 'shield'),
    h('span', null, info.verified ? `Has verificado a @${username}.` : `@${username} aún no está verificado.`));

  const body = [
    h('div', { class: 'safety-peer' }, avatar(username, username, { size: 'lg' }), h('strong', null, `@${username}`)),
    keyChanged ? h('p', { class: 'note warn' }, icon('alert'),
      h('span', null, 'La clave de este contacto ha cambiado recientemente. Vuelve a comparar el número antes de confiar en la conversación.')) : null,
    h('p', { class: 'muted' }, `Compara estos 60 dígitos con los que ve @${username} en su dispositivo, en persona o por otro canal de confianza (p. ej. una llamada). Si coinciden, nadie puede estar interceptando vuestra conversación.`),
    grid,
    statusEl,
  ];

  const actions = [
    {
      label: 'Copiar', kind: 'ghost', icon: 'copy', close: false, onClick: async () => {
        try { await navigator.clipboard.writeText(formatted); toast('Número copiado.', 'success', 2000); }
        catch { toast('No se pudo copiar.', 'error'); }
      },
    },
  ];
  if (keyChanged) {
    actions.push({
      label: 'Aceptar nueva clave', kind: 'warn', onClick: async () => {
        // VC-3: bind the acceptance to the number shown in this dialog.
        try {
          await app.client.acceptKeyChange(username, info.number);
        } catch (err) {
          toast(errorText(err), 'error');
          return;
        }
        toast(`Nueva clave de @${username} aceptada.`, 'success');
        await app.refreshConversations();
      },
    });
  }
  actions.push({
    label: info.verified ? 'Quitar verificación' : 'Marcar como verificado',
    kind: info.verified ? 'ghost' : 'primary',
    icon: info.verified ? null : 'shieldCheck',
    onClick: async () => {
      // VC-3: bind "verified" to the number the user actually compared.
      try {
        await app.client.setVerified(username, !info.verified, info.number);
      } catch (err) {
        toast(errorText(err), 'error');
        return;
      }
      toast(info.verified ? `@${username} ya no está marcado como verificado.` : `@${username} marcado como verificado.`, 'success');
      await app.refreshConversations();
    },
  });
  openDialog({ title: 'Número de seguridad', body, actions });
}

// ------------------------------------------------------------------ new chat

export function showNewChat(app) {
  const f = field({ label: 'Nombre de usuario', placeholder: '@usuario', maxlength: 33, hint: 'El chat se cifra de extremo a extremo desde el primer mensaje.' });
  const form = h('form', { novalidate: true }, f.wrap);
  const dlg = openDialog({
    title: 'Nuevo chat',
    size: 'narrow',
    body: form,
    actions: [
      { label: 'Cancelar', kind: 'ghost' },
      {
        label: 'Iniciar chat', kind: 'primary', onClick: async () => {
          const u = normalizeUsername(f.input.value);
          const problem = usernameProblem(u);
          if (problem) { f.setHint(problem, 'error'); f.input.focus(); return false; }
          if (u === app.me) { f.setHint('Ese eres tú.', 'error'); return false; }
          const ok = await app.startChatWith(u, { silent: true });
          if (!ok) { f.setHint('No existe ningún usuario con ese nombre.', 'error'); return false; }
          return true;
        },
      },
    ],
  });
  on(form, 'submit', (e) => {
    e.preventDefault();
    dlg.dialog.querySelector('.dialog-actions .btn-primary').click();
  });
}

// ------------------------------------------------------------------ groups

/** Username picker: contact checkboxes + free-form @username entry with chips. */
function memberPicker(app, { exclude = new Set() } = {}) {
  const selected = new Set();
  const chips = h('div', { class: 'chips', 'aria-live': 'polite' });
  const add = field({ label: 'Añadir por nombre de usuario', placeholder: '@usuario', maxlength: 33 });
  const addBtn = h('button', { type: 'button', class: 'btn btn-ghost btn-small' }, icon('plus'), 'Añadir');
  const addRow = h('div', { class: 'input-row' });
  add.input.replaceWith(addRow);
  addRow.append(add.input, addBtn);

  const contacts = app.convs
    .filter((c) => c.type === 'direct' && c.peer && !exclude.has(c.peer) && c.peer !== app.me)
    .map((c) => c.peer)
    .sort();
  const boxes = new Map();
  const contactList = h('div', { class: 'contact-pick', role: 'group', 'aria-label': 'Contactos' });
  for (const u of contacts) {
    const cb = checkbox(`@${u}`);
    cb.wrap.prepend(avatar(u, u, { size: 'sm' }));
    on(cb.input, 'change', () => {
      if (cb.input.checked) selected.add(u);
      else selected.delete(u);
      renderChips();
    });
    boxes.set(u, cb.input);
    contactList.append(cb.wrap);
  }

  function renderChips() {
    clear(chips);
    for (const u of selected) {
      chips.append(chip(u, () => {
        selected.delete(u);
        const box = boxes.get(u);
        if (box) box.checked = false;
        renderChips();
      }));
    }
    if (!selected.size) chips.append(h('span', { class: 'muted' }, 'Nadie seleccionado todavía.'));
  }

  const tryAdd = () => {
    const u = normalizeUsername(add.input.value);
    const problem = usernameProblem(u);
    if (problem) { add.setHint(problem, 'error'); return; }
    if (u === app.me) { add.setHint('Ya formas parte del grupo.', 'error'); return; }
    if (exclude.has(u)) { add.setHint(`@${u} ya es miembro.`, 'error'); return; }
    if (selected.size >= MAX_GROUP_OTHERS) { add.setHint(`Máximo ${MAX_GROUP_OTHERS} miembros.`, 'error'); return; }
    selected.add(u);
    const box = boxes.get(u);
    if (box) box.checked = true;
    add.input.value = '';
    add.setHint('');
    renderChips();
  };
  on(addBtn, 'click', tryAdd);
  on(add.input, 'keydown', (e) => {
    if (e.key === 'Enter' || e.key === ',' || e.key === ' ') {
      e.preventDefault();
      tryAdd();
    }
  });
  renderChips();

  const el = h('div', { class: 'member-picker' },
    contacts.length ? h('p', { class: 'field-label' }, 'Contactos') : null,
    contacts.length ? contactList : null,
    add.wrap,
    h('p', { class: 'field-label' }, 'Seleccionados'),
    chips);
  return {
    el,
    selected: () => [...selected],
    flushInput: () => { if (add.input.value.trim()) tryAdd(); },
    markMissing: (u) => add.setHint(`No existe ningún usuario @${u}.`, 'error'),
  };
}

export function showNewGroup(app) {
  const name = field({ label: 'Nombre del grupo', maxlength: MAX_GROUP_NAME, hint: 'Solo lo verán los miembros: viaja cifrado.' });
  name.input.setAttribute('autocomplete', 'off');
  const picker = memberPicker(app);
  openDialog({
    title: 'Nuevo grupo',
    body: [name.wrap, picker.el],
    actions: [
      { label: 'Cancelar', kind: 'ghost' },
      {
        label: 'Crear grupo', kind: 'primary', icon: 'users', onClick: async () => {
          picker.flushInput();
          const title = name.input.value.trim();
          if (!title) { name.setHint('Ponle un nombre al grupo.', 'error'); name.input.focus(); return false; }
          const members = picker.selected();
          if (!members.length) throw new UiError('Añade al menos un miembro.');
          try {
            const convId = await app.client.createGroup(title, members);
            await app.refreshConversations();
            if (convId) await app.openConversation(convId);
            toast('Grupo creado.', 'success');
            return true;
          } catch (err) {
            const missing = errorUsername(err);
            if (missing) picker.markMissing(missing);
            throw err;
          }
        },
      },
    ],
  });
}

export function showAddMembers(app, convId) {
  const conv = app.convs.find((c) => c.id === convId);
  if (!conv) return;
  const current = new Set(Array.isArray(conv.members) ? conv.members : []);
  const picker = memberPicker(app, { exclude: current });
  openDialog({
    title: `Añadir a «${conv.title}»`,
    body: [h('p', { class: 'muted' }, 'Los nuevos miembros solo podrán leer los mensajes enviados a partir de ahora.'), picker.el],
    actions: [
      { label: 'Cancelar', kind: 'ghost' },
      {
        label: 'Añadir', kind: 'primary', icon: 'userPlus', onClick: async () => {
          picker.flushInput();
          const members = picker.selected();
          if (!members.length) throw new UiError('Añade al menos un miembro.');
          if (current.size - 1 + members.length > MAX_GROUP_OTHERS) throw new UiError(`Un grupo admite como máximo ${MAX_GROUP_OTHERS + 1} miembros.`);
          try {
            await app.client.addGroupMembers(convId, members);
          } catch (err) {
            const missing = errorUsername(err);
            if (missing) picker.markMissing(missing);
            throw err;
          }
          toast('Miembros añadidos.', 'success');
          await app.refreshConversations();
          return true;
        },
      },
    ],
  });
}

export function showGroupInfo(app, convId) {
  const conv = app.convs.find((c) => c.id === convId);
  if (!conv) return;
  const members = (Array.isArray(conv.members) ? conv.members.slice() : []).sort((a, b) => {
    if (a === conv.admin) return -1;
    if (b === conv.admin) return 1;
    return a.localeCompare(b);
  });
  let dlg = null;
  const list = h('ul', { class: 'member-list', 'aria-label': 'Miembros' });
  for (const u of members) {
    const tags = h('span', { class: 'member-tags' });
    if (u === app.me) tags.append(h('span', { class: 'tag' }, 'tú'));
    if (u === conv.admin) tags.append(h('span', { class: 'tag tag-accent' }, 'administrador'));
    const row = h('li', { class: 'member' }, avatar(u, u, { size: 'sm' }), h('span', { class: 'member-name' }, `@${u}`), tags);
    if (u !== app.me) {
      const btn = h('button', { type: 'button', class: 'btn btn-small btn-ghost', 'aria-label': `Número de seguridad de @${u}` }, icon('shield'), 'Verificar');
      on(btn, 'click', () => { dlg.close(); app.showSafety(u); });
      row.append(btn);
      if (conv.admin === app.me) {
        const kick = h('button', { type: 'button', class: 'btn btn-small btn-ghost', 'aria-label': `Eliminar a @${u} del grupo` }, icon('logout'), 'Expulsar');
        on(kick, 'click', async () => {
          const ok = await confirmDialog({ title: 'Expulsar del grupo', message: `@${u} dejará de recibir los mensajes del grupo. Conservará lo que ya recibió.`, confirmLabel: 'Expulsar', danger: true });
          if (!ok) return;
          try {
            await app.client.removeGroupMember(convId, u);
            toast(`@${u} ya no está en el grupo.`, 'success');
            await app.refreshConversations();
            dlg.close();
            app.showGroupInfo(convId);
          } catch (err) { toast(errorText(err), 'error'); }
        });
        row.append(kick);
      }
    }
    list.append(row);
  }
  const actions = [];
  if (conv.admin === app.me) {
    actions.push({ label: 'Añadir miembros', kind: 'ghost', icon: 'userPlus', onClick: () => { setTimeout(() => app.showAddMembers(convId), 0); } });
  }
  actions.push({ label: 'Salir del grupo', kind: 'danger', icon: 'logout', onClick: () => { setTimeout(() => app.leaveGroup(convId), 0); } });
  dlg = openDialog({
    title: conv.title || 'Grupo',
    body: [
      h('div', { class: 'safety-peer' }, avatar(conv.title, conv.id, { size: 'lg', group: true }),
        h('strong', { dir: 'auto' }, conv.title), h('span', { class: 'muted' }, membersLabel(members.length))),
      h('p', { class: 'muted' }, 'Cada mensaje del grupo se cifra por separado para cada miembro. Verifica a los miembros para descartar intermediarios.'),
      list,
    ],
    actions,
  });
}

// ------------------------------------------------------------------ files

/** Confirm (with preview) and send a file. */
export async function confirmSendFile(app, convId, file, { pasted = false } = {}) {
  if (!file) return;
  if (file.size > MAX_FILE_BYTES) {
    toast(`El archivo ocupa ${formatSize(file.size)}; el máximo es ${formatSize(MAX_FILE_BYTES)}.`, 'error', 6000);
    return;
  }
  if (file.size === 0) {
    toast('El archivo está vacío.', 'error');
    return;
  }
  let bytes;
  try {
    bytes = new Uint8Array(await file.arrayBuffer());
  } catch {
    toast('No se pudo leer el archivo.', 'error');
    return;
  }
  const imgMime = sniffImageMime(bytes);
  let name = sanitizeFilename(file.name, imgMime ? 'imagen' : 'archivo');
  if (pasted && imgMime) name = `imagen-${dateStamp()}.${imgMime.split('/')[1].replace('jpeg', 'jpg')}`;
  const mime = (typeof file.type === 'string' && /^[\w.+-]+\/[\w.+-]+$/.test(file.type)) ? file.type : 'application/octet-stream';

  let previewUrl = null;
  const body = [];
  if (imgMime) {
    previewUrl = URL.createObjectURL(new Blob([bytes], { type: imgMime }));
    body.push(h('div', { class: 'send-preview' }, h('img', { src: previewUrl, alt: `Vista previa de ${name}` })));
  } else {
    body.push(h('div', { class: 'file-chip static' }, h('span', { class: 'file-icon' }, icon('file')),
      h('span', { class: 'file-meta' }, h('span', { class: 'file-name', dir: 'auto' }, name), h('span', { class: 'file-size' }, formatSize(bytes.length)))));
  }
  if (imgMime) body.push(h('p', { class: 'muted' }, `${name} · ${formatSize(bytes.length)}`));
  body.push(h('p', { class: 'note' }, icon('lock'), h('span', null, 'Se cifrará de extremo a extremo antes de salir de este dispositivo. Ojo: las fotos pueden contener metadatos (ubicación, modelo de cámara) dentro del propio archivo.')));

  openDialog({
    title: imgMime ? 'Enviar imagen' : 'Enviar archivo',
    size: 'narrow',
    body,
    onClose: () => { if (previewUrl) URL.revokeObjectURL(previewUrl); },
    actions: [
      { label: 'Cancelar', kind: 'ghost' },
      {
        label: 'Enviar', kind: 'primary', icon: 'send', onClick: async () => {
          await app.client.sendFile(convId, { name, mime: imgMime || mime, bytes });
          app.chat?.reload();
          app.refreshConversations();
        },
      },
    ],
  });
}

/** Full-size image viewer. The blob URL belongs to the chat view cache (revoked there). */
export function showImage(app, { url, name, onDownload }) {
  const safeName = sanitizeFilename(name, 'imagen');
  openDialog({
    title: safeName,
    size: 'wide',
    body: h('div', { class: 'viewer' }, h('img', { src: url, alt: safeName })),
    actions: [
      { label: 'Descargar', kind: 'ghost', icon: 'download', close: false, onClick: () => onDownload() },
      { label: 'Cerrar', kind: 'primary' },
    ],
  });
}

// ------------------------------------------------------------------ settings

export function showSettings(app) {
  // Account
  const account = h('section', { class: 'settings-section' },
    h('h3', null, 'Cuenta'),
    h('div', { class: 'safety-peer row' }, avatar(app.me, app.me, { size: 'md' }),
      h('div', null, h('strong', null, `@${app.me}`),
        h('p', { class: 'muted small' }, app.connected ? 'Conectado al servidor' : 'Sin conexión con el servidor'))));

  // Security
  const selId = uid('autolock');
  const sel = h('select', { id: selId, class: 'input select' },
    AUTOLOCK_CHOICES.map((m) => h('option', { value: String(m), selected: m === getPref('autoLockMinutes') },
      m === 1 ? '1 minuto' : `${m} minutos`)));
  on(sel, 'change', () => {
    setPref('autoLockMinutes', Number(sel.value));
    app.autolock.poke();
    toast('Bloqueo automático actualizado.', 'success', 2000);
  });
  const hiddenCb = checkbox('Bloquear al ocultar la ventana', getPref('lockOnHidden'), 'Se bloquea al cambiar de pestaña, minimizar o bloquear el móvil.');
  on(hiddenCb.input, 'change', () => setPref('lockOnHidden', hiddenCb.input.checked));
  const previewCb = checkbox('Ocultar vista previa de mensajes', getPref('hidePreviews'), 'La lista de chats no mostrará el texto del último mensaje.');
  on(previewCb.input, 'change', () => {
    setPref('hidePreviews', previewCb.input.checked);
    app.refreshConversations();
  });
  // C3: receipts are sent after a random delay, but each one is still a request from this
  // device to the sender; turning them off removes that timing signal entirely.
  const applyReceipts = () => app.client?.setPrivacyOptions?.({
    deliveryReceipts: getPref('deliveryReceipts'), readReceipts: getPref('readReceipts'),
  });
  const deliveredCb = checkbox('Enviar confirmaciones de entrega', getPref('deliveryReceipts'), 'Desactívalo para que el servidor no pueda relacionar tus respuestas automáticas con quien te escribe.');
  on(deliveredCb.input, 'change', () => { setPref('deliveryReceipts', deliveredCb.input.checked); applyReceipts(); });
  const readCb = checkbox('Enviar confirmaciones de lectura', getPref('readReceipts'), 'Si lo desactivas, tus contactos no verán el doble check azul.');
  on(readCb.input, 'change', () => { setPref('readReceipts', readCb.input.checked); applyReceipts(); });
  const lockBtn = h('button', { type: 'button', class: 'btn btn-ghost' }, icon('lock'), 'Bloquear ahora');
  on(lockBtn, 'click', () => app.lock());
  const security = h('section', { class: 'settings-section' },
    h('h3', null, 'Seguridad'),
    h('div', { class: 'field' }, h('label', { class: 'field-label', for: selId }, 'Bloqueo automático por inactividad'), sel),
    hiddenCb.wrap, previewCb.wrap, deliveredCb.wrap, readCb.wrap,
    h('div', { class: 'btn-row' }, lockBtn),
    h('p', { class: 'muted small' }, 'Atajo: Ctrl+Mayús+L bloquea al instante.'));

  // Backup
  const exportBtn = h('button', { type: 'button', class: 'btn btn-ghost' }, icon('download'), 'Exportar copia cifrada');
  on(exportBtn, 'click', async () => {
    exportBtn.disabled = true;
    try {
      const bytes = await app.client.exportBackup();
      downloadBytes(bytes, `sombra-copia-${dateStamp()}.json`);
      toast('Copia exportada. Guárdala en un lugar seguro.', 'success');
    } catch (err) {
      toast(errorText(err, 'No se pudo exportar la copia.'), 'error');
    } finally {
      exportBtn.disabled = false;
    }
  });
  const backup = h('section', { class: 'settings-section' },
    h('h3', null, 'Copia de seguridad'),
    h('p', { class: 'muted small' }, 'El archivo contiene tus claves y mensajes cifrados con tu frase de acceso. Sin la frase no sirve de nada; con ella, da acceso total a la cuenta: guárdalo en un lugar seguro. Restaurarlo en otro dispositivo mueve la cuenta (no la uses en dos a la vez).'),
    h('div', { class: 'btn-row' }, exportBtn));

  // Danger zone
  const delBtn = h('button', { type: 'button', class: 'btn btn-danger' }, icon('trash'), 'Eliminar cuenta');
  const panicBtn = h('button', { type: 'button', class: 'btn btn-danger-ghost' }, icon('zap'), 'Borrado de pánico');
  on(delBtn, 'click', () => app.deleteAccount());
  on(panicBtn, 'click', () => app.panic());
  const danger = h('section', { class: 'settings-section danger-zone' },
    h('h3', null, 'Zona peligrosa'),
    h('p', { class: 'muted small' }, 'Eliminar cuenta: borra tu usuario, tus claves públicas y los mensajes pendientes del servidor, y todo lo guardado en este dispositivo. Borrado de pánico: elimina al instante todos los datos locales, sin conexión con el servidor.'),
    h('div', { class: 'btn-row' }, delBtn, panicBtn));

  // How Sombra protects you
  const points = [
    ['lock', 'Cifrado de extremo a extremo', 'Protocolo tipo Signal (X3DH + Double Ratchet): solo los participantes pueden leer los mensajes y cada mensaje usa una clave nueva, así que robar una clave no descifra el pasado ni el futuro.'],
    ['eyeOff', 'Remitente sellado', 'El servidor solo ve un sobre cifrado para el destinatario: no sabe quién envía cada mensaje.'],
    ['key', 'Cuenta anónima', 'Sin teléfono, sin correo y sin contraseña en el servidor. Tu identidad es un par de claves generado en este dispositivo.'],
    ['shield', 'Sin rastro en el servidor', 'No guarda IPs, ni horas, ni registros. Los mensajes se borran al entregarse (o a los 14 días) y su tamaño se oculta con relleno.'],
    ['lock', 'Almacén local cifrado', 'Todo lo guardado aquí se cifra con tu frase de acceso (PBKDF2 600 000 iteraciones + AES-256-GCM).'],
    ['shieldCheck', 'Números de seguridad', 'Compáralos en persona para asegurarte de que nadie se interpone. Sombra te avisa si la clave de un contacto cambia.'],
    ['alert', 'Límites honestos', 'Para ocultar tu IP al servidor usa Tor o una VPN. Nada protege un dispositivo comprometido; los mensajes temporales no impiden capturas de pantalla.'],
  ];
  const about = h('section', { class: 'settings-section' },
    h('h3', null, 'Cómo te protege Sombra'),
    h('ul', { class: 'about-list' }, points.map(([ic, title, text]) =>
      h('li', null, icon(ic, { cls: 'about-icon' }), h('div', null, h('strong', null, title), h('p', { class: 'muted small' }, text))))));

  // Network (only when running inside the Sombra desktop app: its local panel answers).
  const network = h('section', { class: 'settings-section', hidden: true },
    h('h3', null, 'Red'));
  fetch('/_local/status', { cache: 'no-store', credentials: 'omit' })
    .then((r) => (r.ok ? r.json() : null))
    .then((st) => {
      if (!st || !st.mode) return;
      const text = st.mode === 'host'
        ? 'Tu ordenador es el punto de encuentro de tu red. En el panel tienes la dirección para invitar a tus amigos.'
        : 'Estás conectado por Tor a la red de un amigo.';
      network.append(
        h('p', { class: 'muted small' }, text),
        h('div', { class: 'btn-row' }, h('a', { class: 'btn btn-ghost', href: '/_local/' }, icon('shield'), 'Abrir panel de red')));
      network.hidden = false;
    })
    .catch(() => {});

  openDialog({
    title: 'Ajustes',
    body: [account, network, security, backup, danger, about],
    actions: [{ label: 'Cerrar', kind: 'primary' }],
    initialFocus: sel,
  });
}

/** Typed confirmation and account deletion. Returns true if deleted. */
export async function confirmDeleteAccount(app) {
  return confirmDialog({
    title: 'Eliminar cuenta',
    message: [
      'Se borrará tu cuenta del servidor y todos los datos de este dispositivo. Nadie podrá volver a escribirte a este nombre de usuario con tus claves actuales.',
      'Esta acción no se puede deshacer.',
    ],
    confirmLabel: 'Eliminar para siempre',
    danger: true,
    typed: app.me,
  });
}

export async function confirmPanic() {
  return confirmDialog({
    title: 'Borrado de pánico',
    message: 'Se eliminarán inmediatamente todas las claves, chats y mensajes de este dispositivo. La cuenta del servidor no se toca, pero sin las claves quedará inutilizable.',
    confirmLabel: 'Borrar ahora',
    danger: true,
  });
}
