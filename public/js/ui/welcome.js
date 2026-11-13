// Sombra UI — welcome screens: create account, unlock vault, import backup.

import { h, on, replaceChildren } from './dom.js';
import { icon, logo } from './icons.js';
import { field, passwordField, checkbox, progressBar } from './widgets.js';
import { normalizeUsername, usernameProblem, MIN_PASSPHRASE } from './format.js';
import { estimateStrength } from './strength.js';
import { errorText } from './errors.js';
import { confirmDialog, toast } from './overlay.js';

const MAX_BACKUP_BYTES = 1024 * 1024 * 1024; // 1 GiB sanity cap for reading a backup file

function shell(...content) {
  return h('main', { class: 'welcome' },
    h('div', { class: 'welcome-card' },
      h('div', { class: 'brand' }, logo(), h('h1', { class: 'brand-name' }, 'Sombra'),
        h('p', { class: 'brand-tag' }, 'Mensajería cifrada de extremo a extremo. Sin teléfono, sin correo, sin rastro.')),
      ...content),
    h('p', { class: 'welcome-foot' }, icon('lock'), ' Tus claves se generan y se guardan cifradas solo en este dispositivo.'));
}

/**
 * Describe a createAccount() progress callback value.
 * SPEC §4.4 does not define the shape of onProgress's argument, so accept the plausible
 * forms: a number (fraction 0..1 or attempt counter), a stage string, or an object with
 * {stage|phase|step, progress|fraction, tries|iterations|attempts|hashes}.
 */
export function describeProgress(p) {
  const STAGES = {
    keys: 'Generando claves de identidad…',
    identity: 'Generando claves de identidad…',
    prekeys: 'Generando claves de un solo uso…',
    pow: 'Resolviendo la prueba de trabajo anti-spam…',
    register: 'Registrando el nombre de usuario…',
    registering: 'Registrando el nombre de usuario…',
    vault: 'Cifrando el almacén local…',
    store: 'Cifrando el almacén local…',
    save: 'Cifrando el almacén local…',
    connect: 'Conectando con el servidor…',
    done: 'Listo.',
  };
  let stage = null;
  let fraction = null;
  let tries = null;
  if (typeof p === 'number') {
    if (p >= 0 && p <= 1) fraction = p;
    else tries = p;
  } else if (typeof p === 'string') {
    stage = p;
  } else if (p && typeof p === 'object') {
    stage = p.stage ?? p.phase ?? p.step ?? null;
    const f = p.progress ?? p.fraction ?? p.ratio;
    if (typeof f === 'number' && f >= 0 && f <= 1) fraction = f;
    const t = p.tries ?? p.iterations ?? p.attempts ?? p.hashes ?? p.nonce ?? p.count;
    if (typeof t === 'number' || (typeof t === 'string' && /^\d+$/.test(t))) tries = Number(t);
  }
  let text = (stage && STAGES[String(stage).toLowerCase()]) || (tries !== null ? STAGES.pow : 'Creando tu cuenta…');
  if (tries !== null) text += ` (${tries.toLocaleString('es-ES')} intentos)`;
  return { text, fraction };
}

/** Create-account / import screen for a device with no account. */
export function renderWelcome(app, { tab = 'create' } = {}) {
  const tabs = h('div', { class: 'tabs', role: 'tablist', 'aria-label': 'Opciones de inicio' });
  const createTab = h('button', { type: 'button', role: 'tab', class: 'tab', id: 'tab-create', 'aria-controls': 'panel-create' }, 'Crear cuenta');
  const importTab = h('button', { type: 'button', role: 'tab', class: 'tab', id: 'tab-import', 'aria-controls': 'panel-import' }, 'Restaurar copia');
  tabs.append(createTab, importTab);

  const createPanel = h('section', { id: 'panel-create', role: 'tabpanel', 'aria-labelledby': 'tab-create', class: 'tab-panel' }, buildCreateForm(app));
  const importPanel = h('section', { id: 'panel-import', role: 'tabpanel', 'aria-labelledby': 'tab-import', class: 'tab-panel' }, buildImportForm(app));

  const select = (which, focus = false) => {
    const isCreate = which === 'create';
    createTab.setAttribute('aria-selected', String(isCreate));
    importTab.setAttribute('aria-selected', String(!isCreate));
    createTab.tabIndex = isCreate ? 0 : -1;
    importTab.tabIndex = isCreate ? -1 : 0;
    createPanel.hidden = !isCreate;
    importPanel.hidden = isCreate;
    if (focus) (isCreate ? createTab : importTab).focus();
  };
  on(createTab, 'click', () => select('create'));
  on(importTab, 'click', () => select('import'));
  on(tabs, 'keydown', (e) => {
    if (e.key === 'ArrowRight' || e.key === 'ArrowLeft') {
      e.preventDefault();
      select(createTab.getAttribute('aria-selected') === 'true' ? 'import' : 'create', true);
    }
  });
  select(tab);

  replaceChildren(app.root, shell(tabs, createPanel, importPanel));
  const first = createPanel.querySelector('input');
  if (tab === 'create' && first) first.focus();
}

function buildCreateForm(app) {
  const user = field({
    label: 'Nombre de usuario',
    name: 'username',
    placeholder: 'p. ej. luna_77',
    maxlength: 32,
    hint: '3–32 caracteres: a–z, 0–9 y _. Es lo único que verán los demás; no uses tu nombre real si no quieres.',
  });
  const pass = passwordField({
    label: 'Frase de acceso',
    name: 'passphrase',
    autocomplete: 'new-password',
    hint: `Mínimo ${MIN_PASSPHRASE} caracteres. Usa varias palabras al azar. Nunca sale de este dispositivo.`,
  });
  const meterFill = h('div', { class: 'meter-fill' });
  const meterLabel = h('span', { class: 'meter-label' });
  const meter = h('div', { class: 'meter', 'data-score': '0', 'aria-hidden': 'true' }, meterFill);
  const meterRow = h('div', { class: 'meter-row', 'aria-live': 'polite' }, meter, meterLabel);
  pass.wrap.insertBefore(meterRow, pass.hint);

  const pass2 = passwordField({ label: 'Repite la frase de acceso', name: 'passphrase2', autocomplete: 'new-password' });
  const ack = checkbox('Entiendo que si olvido mi frase de acceso no hay forma de recuperar la cuenta.');
  const submit = h('button', { type: 'submit', class: 'btn btn-primary btn-block' }, 'Crear cuenta');
  const status = h('div', { class: 'progress-box', hidden: true, 'aria-live': 'polite' });
  const progressText = h('p', { class: 'progress-text' });
  const prog = progressBar('Progreso de creación de la cuenta');
  status.append(progressText, prog.bar);
  const formError = h('p', { class: 'form-error', role: 'alert', hidden: true });

  const form = h('form', { class: 'form', novalidate: true, autocomplete: 'off' },
    user.wrap, pass.wrap, pass2.wrap, ack.wrap, formError, submit, status);

  let userTouched = false;
  const validateUser = () => {
    const raw = user.input.value;
    const u = normalizeUsername(raw);
    if (u !== raw) {
      // Keep the field canonical (lowercase, no "@") while typing.
      const pos = user.input.selectionStart;
      user.input.value = u;
      try { user.input.setSelectionRange(pos, pos); } catch { /* ignore */ }
    }
    const problem = usernameProblem(u);
    if (problem && (userTouched || u.length > 0)) user.setHint(problem, u.length ? 'error' : '');
    else if (!problem) user.setHint(`Te encontrarán como @${u}`, 'ok');
    return !problem;
  };
  const updateMeter = () => {
    const st = estimateStrength(pass.input.value, normalizeUsername(user.input.value));
    meter.dataset.score = String(pass.input.value ? st.score + 1 : 0);
    meterLabel.textContent = pass.input.value ? `${st.label} · ${st.hint}` : '';
    return st;
  };
  const validateMatch = () => {
    if (!pass2.input.value) { pass2.setHint(''); return false; }
    const ok = pass2.input.value === pass.input.value;
    pass2.setHint(ok ? 'Coinciden.' : 'Las frases no coinciden.', ok ? 'ok' : 'error');
    return ok;
  };
  on(user.input, 'input', validateUser);
  on(user.input, 'blur', () => { userTouched = true; validateUser(); });
  on(pass.input, 'input', () => { updateMeter(); if (pass2.input.value) validateMatch(); });
  on(pass2.input, 'input', validateMatch);

  const setBusy = (busy) => {
    for (const el of form.querySelectorAll('input, button')) el.disabled = busy;
    status.hidden = !busy;
    submit.classList.toggle('busy', busy);
  };
  const showError = (text) => {
    formError.textContent = text || '';
    formError.hidden = !text;
  };

  on(form, 'submit', async (e) => {
    e.preventDefault();
    showError('');
    userTouched = true;
    const okUser = validateUser();
    const st = updateMeter();
    const okMatch = validateMatch();
    if (!okUser) { user.input.focus(); return; }
    if (!st.acceptable) {
      showError(pass.input.value.length < MIN_PASSPHRASE
        ? `La frase de acceso debe tener al menos ${MIN_PASSPHRASE} caracteres.`
        : 'La frase de acceso es demasiado fácil de adivinar.');
      pass.input.focus();
      return;
    }
    if (!okMatch) { showError('Las frases de acceso no coinciden.'); pass2.input.focus(); return; }
    if (!ack.input.checked) { showError('Confirma que entiendes que la frase no se puede recuperar.'); ack.input.focus(); return; }

    const username = normalizeUsername(user.input.value);
    const passphrase = pass.input.value;
    setBusy(true);
    progressText.textContent = 'Generando claves de identidad…';
    prog.set(null);
    try {
      await app.client.createAccount(username, passphrase, {
        onProgress: (p) => {
          const d = describeProgress(p);
          progressText.textContent = d.text;
          prog.set(d.fraction);
        },
      });
      // Do not leave the passphrase sitting in the DOM.
      pass.input.value = '';
      pass2.input.value = '';
      await app.enterMain();
    } catch (err) {
      setBusy(false);
      const msg = errorText(err, 'No se pudo crear la cuenta. Comprueba la conexión e inténtalo de nuevo.');
      showError(msg);
      if (String(err && err.message).includes('username_taken')) {
        user.setHint('Ese nombre ya está en uso.', 'error');
        user.input.focus();
      }
    }
  });
  return form;
}

function buildImportForm(app) {
  const fileInput = h('input', { type: 'file', id: 'backup-file', class: 'file-input', accept: '.json,.sombra,application/json,application/octet-stream' });
  const fileLabel = h('label', { for: 'backup-file', class: 'btn btn-ghost btn-block file-pick' }, icon('upload'), h('span', null, 'Elegir archivo de copia…'));
  const fileName = h('p', { class: 'field-hint' }, 'Ningún archivo seleccionado.');
  const submit = h('button', { type: 'submit', class: 'btn btn-primary btn-block', disabled: true }, 'Restaurar');
  const formError = h('p', { class: 'form-error', role: 'alert', hidden: true });
  const form = h('form', { class: 'form', novalidate: true },
    h('p', { class: 'muted' }, 'Restaura una copia cifrada exportada desde Ajustes. Después necesitarás la frase de acceso de esa cuenta.'),
    h('p', { class: 'note warn' }, icon('alert'),
      h('span', null, 'No uses la misma cuenta en dos dispositivos a la vez: las sesiones cifradas se desincronizarían. Restaura solo para mover la cuenta a este dispositivo.')),
    fileInput, fileLabel, fileName, formError, submit);

  on(fileInput, 'change', () => {
    const f = fileInput.files && fileInput.files[0];
    fileName.textContent = f ? `${f.name}` : 'Ningún archivo seleccionado.';
    submit.disabled = !f;
  });

  on(form, 'submit', async (e) => {
    e.preventDefault();
    formError.hidden = true;
    const f = fileInput.files && fileInput.files[0];
    if (!f) return;
    if (f.size > MAX_BACKUP_BYTES) {
      formError.textContent = 'El archivo es demasiado grande para ser una copia de Sombra.';
      formError.hidden = false;
      return;
    }
    submit.disabled = true;
    submit.classList.add('busy');
    try {
      const bytes = new Uint8Array(await f.arrayBuffer());
      const { SombraClient } = app.modules;
      if (await SombraClient.hasAccount(app.backend)) {
        const ok = await confirmDialog({
          title: 'Sustituir datos',
          message: 'Ya hay datos de Sombra en este dispositivo. Se sustituirán por la copia.',
          confirmLabel: 'Sustituir',
          danger: true,
        });
        if (!ok) return;
      }
      // Never overwrite the vault under a tab that has it unlocked ('open_elsewhere').
      try {
        await app.withAccountLock(() => SombraClient.importBackup(app.backend, bytes));
      } finally {
        bytes.fill(0);
      }
      toast('Copia restaurada. Introduce tu frase de acceso.', 'success');
      await app.showUnlock();
    } catch (err) {
      formError.textContent = errorText(err, 'El archivo de copia de seguridad no es válido.');
      formError.hidden = false;
    } finally {
      submit.disabled = false;
      submit.classList.remove('busy');
    }
  });
  return form;
}

/** Unlock screen for a device that already holds an encrypted vault. */
export function renderUnlock(app, { reason = '' } = {}) {
  // The username is stored inside the encrypted vault, so the device cannot show it before
  // unlocking. Asking for it works like a normal sign-in (and lets a password manager fill
  // both fields); it is checked against the account once the passphrase has opened it.
  const user = field({
    label: 'Usuario',
    name: 'username',
    placeholder: '@tu_usuario',
    maxlength: 33,
    autocomplete: 'username',
  });
  const pass = passwordField({ label: 'Frase de acceso', name: 'passphrase', autocomplete: 'current-password' });
  const submit = h('button', { type: 'submit', class: 'btn btn-primary btn-block' }, icon('lock'), h('span', null, 'Desbloquear'));
  const formError = h('p', { class: 'form-error', role: 'alert', hidden: true });
  const busyText = h('p', { class: 'progress-text', hidden: true, 'aria-live': 'polite' }, 'Derivando la clave del almacén…');
  const wipeBtn = h('button', { type: 'button', class: 'link-btn danger' }, 'Borrar todos los datos de este dispositivo');
  const form = h('form', { class: 'form', novalidate: true },
    reason ? h('p', { class: 'note' }, icon('info'), h('span', null, reason)) : null,
    user.wrap, pass.wrap, formError, submit, busyText);

  let failures = 0;
  on(form, 'submit', async (e) => {
    e.preventDefault();
    formError.hidden = true;
    const passphrase = pass.input.value;
    const typedUser = normalizeUsername(user.input.value);
    if (!typedUser) { user.input.focus(); return; }
    if (!passphrase) { pass.input.focus(); return; }
    submit.disabled = true;
    user.input.disabled = true;
    pass.input.disabled = true;
    busyText.hidden = false;
    submit.classList.add('busy');
    try {
      await app.client.unlock(passphrase);
      if (app.client.username !== typedUser) {
        // Opened with the right passphrase but another name: refuse, and do not say which was wrong.
        app.client.lock();
        throw new Error('bad_login');
      }
      pass.input.value = '';
      await app.enterMain();
    } catch (err) {
      failures += 1;
      // Small growing UI delay after repeated failures (PBKDF2 already makes guessing slow).
      if (failures > 3) await new Promise((r) => setTimeout(r, Math.min(10000, 1000 * (failures - 3))));
      formError.textContent = errorText(err, 'No se pudo desbloquear.');
      formError.hidden = false;
      submit.disabled = false;
      user.input.disabled = false;
      pass.input.disabled = false;
      busyText.hidden = true;
      submit.classList.remove('busy');
      pass.input.select();
      pass.input.focus();
    }
  });

  on(wipeBtn, 'click', async () => {
    const ok = await confirmDialog({
      title: 'Borrar este dispositivo',
      message: [
        'Se eliminarán de forma irreversible las claves, los chats y los mensajes guardados en este dispositivo.',
        'La cuenta seguirá registrada en el servidor, pero sin las claves nadie podrá usarla.',
      ],
      confirmLabel: 'Borrar todo',
      danger: true,
      typed: 'BORRAR',
    });
    if (ok) await app.wipeLocal();
  });

  replaceChildren(app.root, shell(
    h('h2', { class: 'welcome-title' }, 'Desbloquear Sombra'),
    form,
    h('div', { class: 'welcome-links' }, wipeBtn)));
  user.input.focus();
}
