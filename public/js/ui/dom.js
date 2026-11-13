// Sombra UI — minimal, safe DOM construction helpers.
//
// SECURITY: this module is the ONLY way the UI builds DOM. It never parses HTML:
//   * text is always inserted as Text nodes (document.createTextNode / textContent);
//   * attribute names starting with "on" (inline event handlers) are refused;
//   * "style", "srcdoc", "innerHTML"/"outerHTML" are refused (CSP forbids inline style
//     attributes and we never want markup injection sinks);
//   * URL-bearing attributes (href, src, action, formaction, xlink:href) are validated:
//     only same-origin http(s) URLs, relative URLs, "#" fragments and blob: URLs created
//     by this origin are accepted. javascript:, data:, etc. are rejected.
// Event listeners are attached explicitly with on() / addEventListener.

const SVG_NS = 'http://www.w3.org/2000/svg';

const FORBIDDEN_ATTRS = new Set(['style', 'srcdoc', 'innerhtml', 'outerhtml']);
const URL_ATTRS = new Set(['href', 'src', 'action', 'formaction', 'xlink:href', 'poster']);
// Attributes that are better set as DOM properties (they reflect live state).
const PROP_ATTRS = new Set(['value', 'checked', 'selected', 'disabled', 'indeterminate', 'multiple']);

/** Throws if `url` is not safe to use in an href/src. Returns the original string. */
export function safeUrl(url) {
  const s = String(url);
  if (s.startsWith('#')) return s;
  let parsed;
  try {
    parsed = new URL(s, globalThis.location ? globalThis.location.href : 'http://localhost/');
  } catch {
    throw new Error('unsafe url');
  }
  if (parsed.protocol === 'blob:') {
    // blob:<origin>/<uuid> — only accept blobs minted by our own origin.
    if (globalThis.location && !s.startsWith('blob:' + globalThis.location.origin + '/')) {
      throw new Error('unsafe url');
    }
    return s;
  }
  if (parsed.protocol === 'http:' || parsed.protocol === 'https:') {
    if (globalThis.location && parsed.origin !== globalThis.location.origin) {
      throw new Error('unsafe url');
    }
    return s;
  }
  throw new Error('unsafe url');
}

function checkAttrName(name) {
  const lower = String(name).toLowerCase();
  if (lower.startsWith('on')) throw new Error(`refusing inline event handler attribute "${name}"`);
  if (FORBIDDEN_ATTRS.has(lower)) throw new Error(`refusing attribute "${name}"`);
  return lower;
}

function applyAttrs(el, attrs, isSvg) {
  if (!attrs) return;
  for (const [name, value] of Object.entries(attrs)) {
    if (value === undefined || value === null || value === false) continue;
    const lower = checkAttrName(name);
    if (lower === 'class') {
      const cls = Array.isArray(value) ? value.filter(Boolean).join(' ') : String(value);
      if (isSvg) el.setAttribute('class', cls);
      else el.className = cls;
    } else if (lower === 'text') {
      el.textContent = String(value);
    } else if (lower === 'dataset') {
      for (const [k, v] of Object.entries(value)) {
        if (v !== undefined && v !== null) el.dataset[k] = String(v);
      }
    } else if (!isSvg && PROP_ATTRS.has(lower)) {
      el[lower] = value;
    } else {
      const str = value === true ? '' : String(value);
      el.setAttribute(name, URL_ATTRS.has(lower) ? safeUrl(str) : str);
    }
  }
}

function appendChildren(el, children) {
  for (const child of children) {
    if (child === undefined || child === null || child === false || child === true) continue;
    if (Array.isArray(child)) {
      appendChildren(el, child);
    } else if (child instanceof Node) {
      el.append(child);
    } else {
      el.append(document.createTextNode(String(child)));
    }
  }
}

/**
 * Create an HTML element.
 *   h('button', { class: 'btn', type: 'button', 'aria-label': 'Enviar' }, 'Texto', otherNode)
 * Strings/numbers become Text nodes; arrays are flattened; null/false are skipped.
 */
export function h(tag, attrs, ...children) {
  const el = document.createElement(tag);
  applyAttrs(el, attrs, false);
  appendChildren(el, children);
  return el;
}

/** Create an SVG element (static icons only). */
export function s(tag, attrs, ...children) {
  const el = document.createElementNS(SVG_NS, tag);
  applyAttrs(el, attrs, true);
  appendChildren(el, children);
  return el;
}

/** Remove every child of `el`. */
export function clear(el) {
  while (el.firstChild) el.removeChild(el.firstChild);
  return el;
}

/** Replace all children of `el` with `children`. */
export function replaceChildren(el, ...children) {
  clear(el);
  appendChildren(el, children);
  return el;
}

/** addEventListener shorthand that returns the element (for chaining inside h()). */
export function on(el, type, handler, options) {
  el.addEventListener(type, handler, options);
  return el;
}

/** Set a boolean attribute present/absent. */
export function toggleAttr(el, name, present) {
  checkAttrName(name);
  if (present) el.setAttribute(name, '');
  else el.removeAttribute(name);
}

let idCounter = 0;
/** Unique id for label/aria wiring. */
export function uid(prefix = 'u') {
  idCounter += 1;
  return `${prefix}-${idCounter}`;
}
