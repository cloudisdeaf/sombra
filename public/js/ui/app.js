// Sombra UI — entry point and controller.
//
// The UI talks only to SombraClient (core/client.js) and IdbBackend (core/idbstore.js) as
// specified in SPEC §4.2 / §4.4. All DOM is built with ui/dom.js (no HTML parsing anywhere).
//
// Lifecycle:   boot → (welcome | unlock) → main → (lock → unlock → main) | (wipe → welcome)
// A generation counter (`gen`) is bumped on every lock/wipe so late async results from a
// previous session can never render decrypted data after the app was locked.

import { SombraClient } from '../core/client.js';
import { IdbBackend } from '../core/idbstore.js';
import { h, replaceChildren } from './dom.js';
import { icon, logo } from './icons.js';
import { renderWelcome, renderUnlock } from './welcome.js';
import { createSidebar } from './chatlist.js';
import { createChatView } from './chatview.js';
import {
  showSafety, showNewChat, showNewGroup, showAddMembers, showGroupInfo, showSettings, showImage,
  confirmSendFile, confirmDeleteAccount, confirmPanic,
} from './dialogs.js';
import { closeAllOverlays, clearToasts, confirmDialog, toast } from './overlay.js';
import { errorText } from './errors.js';
import { normalizeUsername, usernameProblem, cleanDisplayText } from './format.js';
import { getPref, clearPrefs } from './prefs.js';
import { createAutoLock } from './autolock.js';

const NARROW_QUERY = '(max-width: 760px)';
const APP_TITLE = 'Sombra';

/**
 * Wrap an async function so that concurrent calls collapse: while a run is in flight, further
 * calls schedule exactly one follow-up run and share its promise.
 */
function coalesce(fn) {
  let running = null;
  let queued = null;
  const run = () => {
    if (running) {
      if (!queued) {
        queued = running.then(() => {
          queued = null;
          return run();
        });
      }
      return queued;
    }
    running = (async () => {
      try {
        await fn();
      } catch {
        /* reported by fn itself */
      } finally {
        running = null;
      }
    })();
    return running;
  };
  return run;
}

class App {
  constructor(root) {
    this.root = root;
    this.backend = null;
    this.client = null;
    this.modules = { SombraClient };
    this.gen = 0;
    this.view = 'boot';
    this.me = '';
    this.convs = [];
    this.currentId = null;
    this.drafts = new Map();
    this.connected = false;
    this.sidebar = null;
    this.chat = null;
    this.layout = null;
    this.listenerAbort = null;
    this.narrowMql = window.matchMedia(NARROW_QUERY);
    this.autolock = createAutoLock({ onIdle: () => this.lock('Sombra se bloqueó por inactividad.') });

    this.refreshConversations = coalesce(() => this.doRefreshConversations());
    this.markReadNow = coalesce(() => this.doMarkRead());

    // Other tabs of this profile: a local wipe in one tab must lock the others (else an
    // unlocked tab keeps running and writes its state back into the wiped database).
    this.tabs = null;
    try {
      if (typeof BroadcastChannel === 'function') {
        this.tabs = new BroadcastChannel('sombra-tabs');
        this.tabs.onmessage = (e) => { if (e && e.data === 'wipe') this.onWipedElsewhere(); };
      }
    } catch {
      this.tabs = null;
    }
  }

  // ------------------------------------------------------------------ boot
  async start() {
    this.installGlobalHandlers();
    try {
      this.backend = new IdbBackend();
    } catch {
      this.fatal('Este navegador no permite el almacenamiento local cifrado (IndexedDB). Desactiva el modo privado estricto o usa otro navegador.');
      return;
    }
    this.newClient();
    let has = false;
    try {
      has = await SombraClient.hasAccount(this.backend);
    } catch {
      this.fatal('No se pudo abrir el almacenamiento local. Comprueba que el navegador permite guardar datos de este sitio.');
      return;
    }
    if (has) await this.showUnlock();
    else this.showWelcome();
  }

  /** Create a fresh SombraClient and (re)bind its events; old listeners are detached. */
  newClient() {
    if (this.listenerAbort) this.listenerAbort.abort();
    const ac = new AbortController();
    this.listenerAbort = ac;
    const client = new SombraClient({ serverUrl: location.origin, backend: this.backend });
    // C3: user-controlled receipt privacy (Ajustes › Seguridad).
    client.setPrivacyOptions({ deliveryReceipts: getPref('deliveryReceipts'), readReceipts: getPref('readReceipts') });
    const opts = { signal: ac.signal };
    const detail = (e) => (e && e.detail) || {};
    client.addEventListener('message', (e) => this.onMessage(detail(e)), opts);
    client.addEventListener('update', (e) => this.onUpdate(detail(e)), opts);
    client.addEventListener('conversations', () => this.onConversations(), opts);
    client.addEventListener('status', (e) => this.onStatus(detail(e)), opts);
    client.addEventListener('keychange', (e) => this.onKeyChange(detail(e)), opts);
    client.addEventListener('error', (e) => this.onClientError(detail(e)), opts);
    this.client = client;
  }

  installGlobalHandlers() {
    document.addEventListener('visibilitychange', () => {
      if (document.visibilityState === 'hidden') {
        if (this.view === 'main' && getPref('lockOnHidden')) this.lock('Sombra se bloqueó al ocultar la ventana.');
      } else if (this.view === 'main') {
        // Timers are throttled in background tabs: re-check idle time before showing anything.
        if (!this.autolock.check()) this.maybeMarkRead();
      }
    });
    window.addEventListener('focus', () => {
      if (this.view === 'main' && !this.autolock.check()) this.maybeMarkRead();
    });
    document.addEventListener('keydown', (e) => {
      if (this.view !== 'main') return;
      const key = e.key.toLowerCase();
      if ((e.ctrlKey || e.metaKey) && e.shiftKey && key === 'l') {
        e.preventDefault();
        this.lock();
      } else if ((e.ctrlKey || e.metaKey) && !e.shiftKey && key === 'k') {
        e.preventDefault();
        if (this.isNarrow()) this.closeConversation();
        this.sidebar?.focusSearch();
      }
    });
    const onNarrowChange = () => {
      if (this.layout) this.layout.classList.toggle('narrow', this.isNarrow());
    };
    if (this.narrowMql.addEventListener) this.narrowMql.addEventListener('change', onNarrowChange);
  }

  isNarrow() {
    return this.narrowMql.matches;
  }

  fatal(text) {
    this.view = 'fatal';
    replaceChildren(this.root, h('main', { class: 'welcome' },
      h('div', { class: 'welcome-card' }, h('div', { class: 'brand' }, logo(), h('h1', { class: 'brand-name' }, APP_TITLE)),
        h('p', { class: 'note warn' }, icon('alert'), h('span', null, text)))));
  }

  // ------------------------------------------------------------------ screens
  showWelcome(opts) {
    this.view = 'welcome';
    document.title = APP_TITLE;
    renderWelcome(this, opts);
  }

  async showUnlock(opts) {
    this.view = 'locked';
    document.title = APP_TITLE;
    renderUnlock(this, opts);
  }

  async enterMain() {
    this.gen += 1;
    this.view = 'main';
    this.me = this.client.username || '';
    this.convs = [];
    this.currentId = null;
    this.connected = Boolean(this.client.connected);
    this.sidebar = createSidebar(this);
    this.chat = createChatView(this);
    this.layout = h('div', { class: ['layout', this.isNarrow() && 'narrow'] }, this.sidebar.el, this.chat.el);
    replaceChildren(this.root, this.layout);
    this.sidebar.setStatus(this.connected);
    this.sidebar.render([]);
    this.autolock.start();
    await this.refreshConversations();
    if (this.view === 'main') this.sidebar.focusSearch();
  }

  // ------------------------------------------------------------------ data
  async doRefreshConversations() {
    if (this.view !== 'main') return;
    const gen = this.gen;
    let convs;
    try {
      convs = await this.client.listConversations();
    } catch (err) {
      if (gen === this.gen) toast(errorText(err, 'No se pudieron cargar los chats.'), 'error');
      return;
    }
    if (gen !== this.gen || this.view !== 'main') return;
    // Titles (group names) and previews are peer-controlled: strip bidi overrides / controls
    // once here so every view (list, header, dialogs) shows the same, spoof-free text.
    this.convs = (Array.isArray(convs) ? convs : []).map((c) => ({
      ...c,
      title: cleanDisplayText(c.title, 64),
      lastText: cleanDisplayText(c.lastText),
    }));
    this.sidebar.render(this.convs);
    this.sidebar.setActive(this.currentId);
    if (this.currentId) {
      const c = this.convs.find((x) => x.id === this.currentId);
      if (c) this.chat.updateConv(c);
      else this.closeConversation();
    }
    this.updateTitle();
  }

  updateTitle() {
    const total = this.convs.reduce((n, c) => n + (Number(c.unread) || 0), 0);
    // Generic badge only — never message content or sender names in the title.
    document.title = total > 0 ? `(${total > 99 ? '99+' : total}) ${APP_TITLE}` : APP_TITLE;
  }

  canMarkRead() {
    return this.view === 'main' && this.currentId && document.visibilityState === 'visible' &&
      (!this.isNarrow() || this.layout.classList.contains('chat-open'));
  }

  maybeMarkRead() {
    if (this.canMarkRead()) this.markReadNow();
  }

  async doMarkRead() {
    if (!this.canMarkRead()) return;
    const id = this.currentId;
    const gen = this.gen;
    try {
      await this.client.markRead(id);
    } catch {
      return; // receipts are best effort
    }
    if (gen === this.gen) this.refreshConversations();
  }

  // ------------------------------------------------------------------ client events
  onMessage({ convId, message }) {
    if (this.view !== 'main') return;
    this.refreshConversations();
    if (convId && convId === this.currentId) {
      this.chat.reload();
      if (!message || !message.mine) this.maybeMarkRead();
    }
  }

  onUpdate({ convId }) {
    if (this.view !== 'main') return;
    this.refreshConversations();
    if (this.currentId && (!convId || convId === this.currentId)) this.chat.reload();
  }

  onConversations() {
    if (this.view !== 'main') return;
    this.refreshConversations();
  }

  onStatus({ connected }) {
    this.connected = Boolean(connected);
    if (this.view === 'main' && this.sidebar) this.sidebar.setStatus(this.connected);
  }

  onKeyChange({ username }) {
    if (this.view !== 'main') return;
    const u = typeof username === 'string' ? username : '';
    toast(u ? `El número de seguridad de @${u} ha cambiado. Verifícalo.` : 'El número de seguridad de un contacto ha cambiado.', 'warn', 8000);
    this.refreshConversations();
  }

  onClientError({ message }) {
    if (this.view !== 'main') return;
    toast(errorText(message, 'Error de comunicación con el servidor.'), 'error');
  }

  // ------------------------------------------------------------------ navigation
  async openConversation(id) {
    if (this.view !== 'main' || !id) return;
    let conv = this.convs.find((c) => c.id === id);
    if (!conv) {
      await this.refreshConversations();
      conv = this.convs.find((c) => c.id === id);
      if (!conv) return;
    }
    this.currentId = id;
    this.sidebar.setActive(id);
    this.layout.classList.add('chat-open');
    await this.chat.open(conv);
    this.maybeMarkRead();
  }

  closeConversation() {
    if (this.view !== 'main') return;
    const prev = this.currentId;
    this.currentId = null;
    this.chat.close();
    this.layout.classList.remove('chat-open');
    this.sidebar.setActive(null);
    // Return focus to the list item we came from (mobile back button).
    if (prev) {
      const btn = [...this.sidebar.el.querySelectorAll('button.conv')].find((b) => b.dataset.id === prev);
      if (btn) btn.focus();
    }
  }

  /** Start (or open) a direct chat. Returns true on success. */
  async startChatWith(raw, { silent = false } = {}) {
    const u = normalizeUsername(raw);
    const problem = usernameProblem(u);
    if (problem) {
      if (!silent) toast(problem, 'error');
      return false;
    }
    if (u === this.me) {
      if (!silent) toast('No puedes iniciar un chat contigo.', 'error');
      return false;
    }
    try {
      const convId = await this.client.startDirect(u);
      await this.refreshConversations();
      await this.openConversation(convId || `d:${u}`);
      return true;
    } catch (err) {
      if (!silent || !String(err && err.message).includes('not_found')) {
        toast(errorText(err, 'No se pudo iniciar el chat.'), 'error');
      }
      return false;
    }
  }

  async leaveGroup(convId) {
    const conv = this.convs.find((c) => c.id === convId);
    const ok = await confirmDialog({
      title: 'Salir del grupo',
      message: `Dejarás de recibir los mensajes de «${conv ? conv.title : 'este grupo'}». Se avisará a los demás miembros.`,
      confirmLabel: 'Salir',
      danger: true,
    });
    if (!ok) return;
    try {
      await this.client.leaveGroup(convId);
      if (this.currentId === convId) this.closeConversation();
      toast('Has salido del grupo.', 'success');
      await this.refreshConversations();
    } catch (err) {
      toast(errorText(err), 'error');
    }
  }

  // ------------------------------------------------------------------ dialogs
  showSafety(username) { return showSafety(this, username); }
  showNewChat() { return showNewChat(this); }
  showNewGroup() { return showNewGroup(this); }
  showAddMembers(convId) { return showAddMembers(this, convId); }
  showGroupInfo(convId) { return showGroupInfo(this, convId); }
  showSettings() { return showSettings(this); }
  showImage(opts) { return showImage(this, opts); }
  confirmSendFile(convId, file, opts) { return confirmSendFile(this, convId, file, opts); }

  // ------------------------------------------------------------------ lock / wipe
  /** Tear down every piece of decrypted state held by the UI. */
  teardownMain() {
    this.gen += 1;
    // Leave 'main' first: client.lock()/panicWipe() emit events synchronously after this and
    // every handler is gated on view === 'main' (the sidebar/chat no longer exist).
    this.view = 'teardown';
    closeAllOverlays();
    clearToasts();
    this.autolock.stop();
    if (this.chat) this.chat.destroy();
    this.chat = null;
    this.sidebar = null;
    this.layout = null;
    this.convs = [];
    this.currentId = null;
    this.drafts.clear();
    replaceChildren(this.root);
    document.title = APP_TITLE;
  }

  lock(reason = '') {
    if (this.view !== 'main') return;
    this.teardownMain();
    try {
      this.client.lock();
    } catch {
      /* already locked */
    }
    this.showUnlock({ reason });
  }

  /**
   * Run `fn` while holding the account Web Lock (the one an unlocked SombraClient holds,
   * CRYPTO-3), so no other tab of this profile is unlocked and writing meanwhile.
   * wait=false: throw 'open_elsewhere' when another tab holds it.
   * wait=true: wait up to `timeoutMs`, then run `fn` anyway (a panic wipe is never blocked).
   */
  async withAccountLock(fn, { wait = false, timeoutMs = 3000 } = {}) {
    const name = this.backend && typeof this.backend.lockName === 'string' ? this.backend.lockName : '';
    const locks = navigator.locks;
    if (!name || !locks || typeof locks.request !== 'function') return fn();
    if (!wait) {
      let ran = false;
      let result;
      await locks.request(name, { mode: 'exclusive', ifAvailable: true }, async (lock) => {
        if (!lock) return;
        ran = true;
        result = await fn();
      });
      if (!ran) throw new Error('open_elsewhere');
      return result;
    }
    const ac = new AbortController();
    const timer = setTimeout(() => ac.abort(), timeoutMs);
    let granted = false;
    try {
      return await locks.request(name, { mode: 'exclusive', signal: ac.signal }, () => {
        granted = true;
        clearTimeout(timer);
        return fn();
      });
    } catch (err) {
      if (!granted) return fn(); // timed out (other tab unresponsive): proceed anyway
      throw err;
    } finally {
      clearTimeout(timer);
    }
  }

  /** Another tab of this profile wiped the local data: drop everything here too. */
  onWipedElsewhere() {
    if (this.view !== 'main' && this.view !== 'locked') return;
    if (this.view === 'main') this.teardownMain();
    else closeAllOverlays();
    try { this.client.lock(); } catch { /* ignore */ } // releases the account Web Lock
    this.me = '';
    this.newClient();
    this.showWelcome();
    toast('Los datos locales se borraron desde otra pestaña.', 'info', 7000);
  }

  /** Local wipe (panic). Works from the unlock screen too. */
  async wipeLocal() {
    if (this.view === 'main') this.teardownMain();
    else closeAllOverlays();
    // Release our own account lock, tell other tabs to lock (releasing theirs), then
    // clear while holding the lock so no unlocked tab can write the data back.
    try { this.client.lock(); } catch { /* ignore */ }
    try { if (this.tabs) this.tabs.postMessage('wipe'); } catch { /* ignore */ }
    await this.withAccountLock(async () => {
      try {
        await this.client.panicWipe();
      } catch {
        // Locked clients may refuse; wipe the backend directly as a fallback.
        try { await this.backend.clear(); } catch { /* nothing more we can do */ }
      }
    }, { wait: true });
    try { this.client.lock(); } catch { /* ignore */ }
    clearPrefs();
    this.me = '';
    this.newClient();
    this.showWelcome();
    toast('Todos los datos locales se han borrado.', 'success');
  }

  async panic() {
    if (await confirmPanic()) await this.wipeLocal();
  }

  async deleteAccount() {
    if (!(await confirmDeleteAccount(this))) return;
    try {
      await this.client.deleteAccount();
    } catch (err) {
      toast(errorText(err, 'No se pudo eliminar la cuenta del servidor. Comprueba la conexión.'), 'error', 7000);
      return;
    }
    this.teardownMain();
    try { await this.backend.clear(); } catch { /* client already wiped */ }
    clearPrefs();
    this.me = '';
    this.newClient();
    this.showWelcome();
    toast('Cuenta eliminada.', 'success');
  }
}

// ------------------------------------------------------------------ start
const root = document.getElementById('app');
const app = new App(root);
app.start().catch(() => app.fatal('No se pudo iniciar Sombra.'));
