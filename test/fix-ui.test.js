// UI regression tests (audit round): composer send queue (BUG-1) and narrow-screen
// header subtitle / sticky day separator (BUG-4).
//
// The UI modules need a DOM; this file installs a tiny fake DOM on globalThis that
// implements only what chatview.js / dom.js / icons.js / widgets.js / overlay.js touch
// while building the view and sending messages. No real HTML parsing is involved.
import { test, describe, before } from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';

// ------------------------------------------------------------------ fake DOM
class FakeNode {
  constructor() { this.parentNode = null; this.childNodes = []; }
  get firstChild() { return this.childNodes[0] || null; }
  get nextSibling() {
    if (!this.parentNode) return null;
    const sib = this.parentNode.childNodes;
    return sib[sib.indexOf(this) + 1] || null;
  }
  _adopt(n) {
    if (typeof n === 'string') n = new FakeText(n);
    if (n.parentNode) n.parentNode.removeChild(n);
    n.parentNode = this;
    return n;
  }
  append(...nodes) { for (const n of nodes) this.childNodes.push(this._adopt(n)); }
  appendChild(n) { this.append(n); return n; }
  insertBefore(n, ref) {
    if (!ref) return this.appendChild(n);
    n = this._adopt(n);
    this.childNodes.splice(this.childNodes.indexOf(ref), 0, n);
    return n;
  }
  removeChild(n) {
    const i = this.childNodes.indexOf(n);
    if (i >= 0) this.childNodes.splice(i, 1);
    n.parentNode = null;
    return n;
  }
  remove() { if (this.parentNode) this.parentNode.removeChild(this); }
  contains(n) {
    for (let x = n; x; x = x.parentNode) if (x === this) return true;
    return false;
  }
  get textContent() { return this.childNodes.map((c) => c.textContent).join(''); }
  set textContent(v) {
    for (const c of this.childNodes) c.parentNode = null;
    this.childNodes = [];
    if (v !== '' && v !== null && v !== undefined) this.append(String(v));
  }
}
class FakeText extends FakeNode {
  constructor(t) { super(); this.data = String(t); }
  get textContent() { return this.data; }
  set textContent(v) { this.data = String(v); }
}
class FakeElement extends FakeNode {
  constructor(tag) {
    super();
    this.tagName = String(tag).toUpperCase();
    this.attrs = new Map();
    this.dataset = {};
    this.style = {};
    this.listeners = new Map();
    this.hidden = false;
    this.disabled = false;
    this.value = '';
    this.className = '';
    this.scrollTop = 0;
    this.scrollHeight = 0;
    this.clientHeight = 0;
    const self = this;
    this.classList = {
      _set() { return new Set(self.className.split(/\s+/).filter(Boolean)); },
      contains(c) { return this._set().has(c); },
      add(...cs) { const s = this._set(); cs.forEach((c) => s.add(c)); self.className = [...s].join(' '); },
      remove(...cs) { const s = this._set(); cs.forEach((c) => s.delete(c)); self.className = [...s].join(' '); },
      toggle(c, force) {
        const want = force === undefined ? !this.contains(c) : Boolean(force);
        if (want) this.add(c); else this.remove(c);
        return want;
      },
    };
  }
  setAttribute(k, v) { this.attrs.set(k, String(v)); }
  getAttribute(k) { return this.attrs.has(k) ? this.attrs.get(k) : null; }
  removeAttribute(k) { this.attrs.delete(k); }
  hasAttribute(k) { return this.attrs.has(k); }
  addEventListener(type, fn) {
    if (!this.listeners.has(type)) this.listeners.set(type, []);
    this.listeners.get(type).push(fn);
  }
  removeEventListener(type, fn) {
    const l = this.listeners.get(type) || [];
    const i = l.indexOf(fn);
    if (i >= 0) l.splice(i, 1);
  }
  dispatch(type, extra = {}) {
    const ev = { type, target: this, defaultPrevented: false, preventDefault() { this.defaultPrevented = true; }, stopPropagation() {}, ...extra };
    for (const fn of [...(this.listeners.get(type) || [])]) fn(ev);
    return ev;
  }
  focus() { globalThis.document.activeElement = this; }
  blur() {}
  click() { this.dispatch('click'); }
  closest() { return null; }
  querySelector() { return null; }
  querySelectorAll() { return []; }
  getBoundingClientRect() { return { left: 0, top: 0, right: 0, bottom: 0, width: 0, height: 0 }; }
  /** All descendant elements (depth-first) matching a predicate. */
  findAll(pred, out = []) {
    for (const c of this.childNodes) {
      if (c instanceof FakeElement) {
        if (pred(c)) out.push(c);
        c.findAll(pred, out);
      }
    }
    return out;
  }
}

function installFakeDom() {
  const body = new FakeElement('body');
  globalThis.Node = FakeNode;
  globalThis.document = {
    body,
    activeElement: body,
    createElement: (t) => new FakeElement(t),
    createElementNS: (_ns, t) => new FakeElement(t),
    createTextNode: (t) => new FakeText(t),
    getElementById: () => null,
    querySelectorAll: () => [],
  };
  globalThis.window = { innerWidth: 1280, innerHeight: 800 };
}

const tick = () => new Promise((r) => setImmediate(r));
async function settle(n = 10) { for (let i = 0; i < n; i++) await tick(); }

function deferred() {
  let resolve, reject;
  const promise = new Promise((res, rej) => { resolve = res; reject = rej; });
  return { promise, resolve, reject };
}

let createChatView;
before(async () => {
  installFakeDom();
  ({ createChatView } = await import('../public/js/ui/chatview.js'));
});

/** Fake app whose client.sendText calls are recorded and resolved manually. */
function makeApp() {
  const calls = [];
  const app = {
    me: 'alice',
    gen: 0,
    drafts: new Map(),
    isNarrow: () => false,
    refreshConversations: async () => {},
    closeConversation() {},
    showSafety() {},
    showGroupInfo() {},
    confirmSendFile() {},
    client: {
      getMessages: async () => [],
      sendText(convId, text) {
        const d = deferred();
        calls.push({ convId, text, ...d });
        return d.promise;
      },
      deleteMessages: async () => {},
    },
  };
  return { app, calls };
}

const DIRECT = { id: 'c1', type: 'direct', peer: 'bob', title: 'bob', verified: true, keyChanged: false, timer: 0 };

function parts(view) {
  const textarea = view.el.findAll((e) => e.tagName === 'TEXTAREA')[0];
  const sendBtn = view.el.findAll((e) => e.classList.contains('send-btn'))[0];
  const headSub = view.el.findAll((e) => e.classList.contains('head-sub'))[0];
  return { textarea, sendBtn, headSub };
}

function typeAndEnter(textarea, text) {
  textarea.value = text;
  textarea.dispatch('input');
  return textarea.dispatch('keydown', { key: 'Enter', shiftKey: false, isComposing: false, keyCode: 13 });
}

// ------------------------------------------------------------------ BUG-1
describe('BUG-1: composer sends while a previous send is in flight', () => {
  test('second Enter is queued (not dropped) and sent strictly after the first', async () => {
    const { app, calls } = makeApp();
    const view = createChatView(app);
    await view.open({ ...DIRECT });
    const { textarea } = parts(view);

    typeAndEnter(textarea, 'mensaje A');
    await settle();
    assert.equal(calls.length, 1);
    assert.equal(calls[0].text, 'mensaje A');

    typeAndEnter(textarea, 'mensaje B');
    await settle();
    // B was accepted: the composer is cleared (previously B silently stayed there unsent).
    assert.equal(textarea.value, '', 'second message must be accepted by the composer');
    // No parallel network phase: B waits for A.
    assert.equal(calls.length, 1, 'B must not be sent concurrently with A');

    calls[0].resolve({ id: 'm1' });
    await settle();
    assert.equal(calls.length, 2, 'B is sent once A completes');
    assert.deepEqual(calls.map((c) => [c.convId, c.text]), [['c1', 'mensaje A'], ['c1', 'mensaje B']]);
    calls[1].resolve({ id: 'm2' });
    await settle();
  });

  test('a failed send stops the queue and returns every unsent text to the composer, in order', async () => {
    const { app, calls } = makeApp();
    const view = createChatView(app);
    await view.open({ ...DIRECT });
    const { textarea } = parts(view);

    typeAndEnter(textarea, 'uno');
    await settle();
    typeAndEnter(textarea, 'dos');
    typeAndEnter(textarea, 'tres');
    await settle();
    assert.equal(calls.length, 1);

    // e.g. key_changed thrown by the core: later messages must NOT go out automatically.
    calls[0].reject(new Error('key_changed'));
    await settle();
    assert.equal(calls.length, 1, 'queued messages must not be sent after a failure');
    assert.equal(textarea.value, 'uno\ndos\ntres');
  });

  test('lock (destroy + generation bump) drops queued plaintext and never sends it', async () => {
    const { app, calls } = makeApp();
    const view = createChatView(app);
    await view.open({ ...DIRECT });
    const { textarea } = parts(view);

    typeAndEnter(textarea, 'antes del bloqueo');
    await settle();
    typeAndEnter(textarea, 'en cola');
    await settle();
    assert.equal(calls.length, 1);

    app.gen += 1; // as App.lock() does
    view.destroy();
    app.drafts.clear();
    calls[0].reject(new Error('locked'));
    await settle();
    assert.equal(calls.length, 1, 'queued message must not be sent after lock');
    assert.equal(app.drafts.size, 0, 'no plaintext may be resurrected into drafts after lock');
    assert.equal(textarea.value, '');
  });

  test('queue is bounded; overflow keeps the text in the composer', async () => {
    const { app, calls } = makeApp();
    const view = createChatView(app);
    await view.open({ ...DIRECT });
    const { textarea } = parts(view);
    let accepted = 0;
    for (let i = 0; i < 100; i++) {
      typeAndEnter(textarea, `m${i}`);
      if (textarea.value === '') accepted += 1;
      else break;
    }
    assert.ok(accepted >= 2 && accepted < 100, `bounded queue (accepted ${accepted})`);
    assert.equal(textarea.value, `m${accepted}`, 'overflowing text stays in the composer');
    await settle();
    assert.equal(calls.length, 1);
    // Drain.
    for (let i = 0; i < accepted; i++) {
      calls[i].resolve({});
      await settle();
    }
    assert.equal(calls.length, accepted);
    assert.deepEqual(calls.map((c) => c.text), Array.from({ length: accepted }, (_, i) => `m${i}`));
  });

  test('messages queued for another conversation keep their own conversation id', async () => {
    const { app, calls } = makeApp();
    const view = createChatView(app);
    await view.open({ ...DIRECT });
    const { textarea } = parts(view);
    typeAndEnter(textarea, 'para c1');
    await settle();
    await view.open({ ...DIRECT, id: 'c2', peer: 'carol', title: 'carol' });
    typeAndEnter(textarea, 'para c2');
    await settle();
    calls[0].resolve({});
    await settle();
    assert.deepEqual(calls.map((c) => [c.convId, c.text]), [['c1', 'para c1'], ['c2', 'para c2']]);
    calls[1].resolve({});
    await settle();
  });
});

// ------------------------------------------------------------------ BUG-4
describe('BUG-4: narrow header subtitle and sticky day separator', () => {
  test('direct-chat subtitle has a short variant ("Verificado" / "Sin verificar")', async () => {
    const { app } = makeApp();
    const view = createChatView(app);
    await view.open({ ...DIRECT });
    let { headSub } = parts(view);
    let short = headSub.findAll((e) => e.classList.contains('sub-short'));
    let long = headSub.findAll((e) => e.classList.contains('sub-long'));
    assert.equal(short.length, 1);
    assert.equal(short[0].textContent, 'Verificado');
    assert.equal(long.length, 1);

    view.updateConv({ ...DIRECT, verified: false });
    ({ headSub } = parts(view));
    short = headSub.findAll((e) => e.classList.contains('sub-short'));
    assert.equal(short[0].textContent, 'Sin verificar');
  });

  test('CSS: narrow screens show only the short subtitle; day pill is opaque and layered', async () => {
    const css = await readFile(new URL('../public/css/app.css', import.meta.url), 'utf8');
    // Default: short hidden.
    assert.match(css, /\.head-sub \.sub-short\s*\{[^}]*display:\s*none/);
    // Narrow media block swaps them.
    const narrow = css.slice(css.indexOf('@media (max-width: 760px)'));
    assert.match(narrow, /\.head-sub \.sub-long\s*\{[^}]*display:\s*none/);
    assert.match(narrow, /\.head-sub \.sub-short\s*\{[^}]*display:\s*inline/);
    // Day pill: solid background (no rgba translucency) and above bubbles.
    const pill = css.match(/\.day-sep span\s*\{([^}]*)\}/)[1];
    assert.doesNotMatch(pill, /background:\s*rgba\(/);
    assert.match(pill, /background:\s*var\(--panel\)/);
    const sep = css.match(/\.day-sep\s*\{([^}]*)\}/)[1];
    assert.match(sep, /z-index:\s*[2-9]/);
  });
});
