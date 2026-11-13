// Sombra desktop launcher: a local front server on 127.0.0.1 that
//  - serves the web app from THIS installation (never from the friend's server, so the
//    person hosting the network cannot ship you modified JavaScript),
//  - serves a small setup panel under /_local/,
//  - forwards /api/* and /ws to the network backend:
//      host mode → the Sombra server running here (published as a Tor onion service),
//      join mode → a friend's onion service, through the local Tor SOCKS port.
// Forwarded requests carry no browser headers (no User-Agent, Origin, Referer, cookies,
// Accept-Language…), so the host learns nothing about your browser.
import http from 'node:http';
import net from 'node:net';
import fs from 'node:fs';
import path from 'node:path';
import { socks5Connect } from './socks.js';
import { startTor as defaultStartTor, normalizeOnion, freePort } from './tor.js';
import { startServer as defaultStartServer } from '../server/index.js';

export const DEFAULT_PORT = 47321;

const SECURITY_HEADERS = {
  'Content-Security-Policy': "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' blob: data:; media-src 'self' blob:; connect-src 'self'; font-src 'self'; worker-src 'self'; manifest-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
  'Referrer-Policy': 'no-referrer',
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'DENY',
  'Cross-Origin-Opener-Policy': 'same-origin',
  'Cross-Origin-Resource-Policy': 'same-origin',
  'Cross-Origin-Embedder-Policy': 'require-corp',
  'Permissions-Policy': 'camera=(), microphone=(), geolocation=(), interest-cohort=(), browsing-topics=()',
};

const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.png': 'image/png',
  '.ico': 'image/x-icon',
  '.json': 'application/json; charset=utf-8',
  '.webmanifest': 'application/manifest+json; charset=utf-8',
  '.txt': 'text/plain; charset=utf-8',
};

// Request headers forwarded to the network backend (everything else is dropped).
const FWD_REQ = ['content-type', 'content-length', 'accept'];
const FWD_WS = ['sec-websocket-key', 'sec-websocket-version', 'sec-websocket-extensions', 'sec-websocket-protocol'];
const HOP = new Set(['connection', 'keep-alive', 'proxy-connection', 'transfer-encoding', 'upgrade', 'te', 'trailer']);

function sendJson(res, status, obj) {
  const body = Buffer.from(JSON.stringify(obj));
  res.writeHead(status, { ...SECURITY_HEADERS, 'Content-Type': 'application/json; charset=utf-8', 'Content-Length': body.length, 'Cache-Control': 'no-store' });
  res.end(body);
}

/** Resolve a URL path inside `root` or return null (no traversal, no odd characters). */
function safeFile(root, urlPath) {
  let p;
  try { p = decodeURIComponent(urlPath); } catch { return null; }
  if (/[\\\0:]/.test(p) || p.split('/').some((seg) => seg === '..' || seg === '.' || /[. ]$/.test(seg) && seg !== '')) return null;
  const full = path.resolve(root, '.' + p);
  const rootR = path.resolve(root);
  if (full !== rootR && !full.startsWith(rootR + path.sep)) return null;
  return full;
}

function readBodyJson(req, limit = 4096) {
  return new Promise((resolve, reject) => {
    let size = 0;
    const chunks = [];
    req.on('data', (c) => {
      size += c.length;
      if (size > limit) { reject(new Error('too_large')); req.destroy(); return; }
      chunks.push(c);
    });
    req.on('end', () => {
      try { resolve(JSON.parse(Buffer.concat(chunks).toString('utf8') || '{}')); } catch { reject(new Error('bad_json')); }
    });
    req.on('error', reject);
  });
}

/**
 * @param {object} o
 * @param {string} o.homeDir     per-user data folder (config, server DB, Tor state)
 * @param {string} o.publicDir   the web app (public/)
 * @param {string} o.uiDir       the setup panel (launcher/ui/)
 * @param {string} [o.torPath]   tor.exe
 * @param {number} [o.port]      front port (stable: the browser keeps your account per origin)
 * @param {Function} [o.startTor] / [o.startServer]  injectable for tests
 * @param {object} [o.serverOptions] extra options for the hosted server (tests)
 * @param {Function} [o.onQuit]
 */
export async function createLauncher(o) {
  const port = o.port ?? DEFAULT_PORT;
  const startTor = o.startTor || defaultStartTor;
  const startServer = o.startServer || defaultStartServer;
  const configPath = path.join(o.homeDir, 'config.json');
  fs.mkdirSync(o.homeDir, { recursive: true });

  const state = {
    mode: null,          // 'host' | 'join'
    onion: null,
    ready: false,        // network backend usable
    tor: { state: 'off', progress: 0, error: null },
    version: o.version || 'dev',
    downloadUrl: o.downloadUrl || 'https://github.com/',
  };
  let backendConnect = null; // () => Promise<net.Socket>
  let backendHost = null;    // Host header sent to the backend
  let hosted = null;         // { port, close } of the hosted server
  let tor = null;

  const readConfig = () => {
    try {
      const c = JSON.parse(fs.readFileSync(configPath, 'utf8'));
      if (c && c.mode === 'host') return { mode: 'host' };
      if (c && c.mode === 'join' && normalizeOnion(c.onion)) return { mode: 'join', onion: normalizeOnion(c.onion) };
    } catch { /* none yet */ }
    return null;
  };
  const writeConfig = (c) => fs.writeFileSync(configPath, JSON.stringify(c));

  const watchTor = (t) => {
    const sync = () => {
      state.tor = { state: t.state, progress: t.progress, error: t.error };
      if (state.mode === 'join') state.ready = t.state === 'ready';
    };
    t.onChange(sync);
    sync();
  };

  async function activate(cfg) {
    state.mode = cfg.mode;
    if (cfg.mode === 'host') {
      hosted = await startServer({
        port: 0, host: '127.0.0.1',
        dataDir: path.join(o.homeDir, 'server'),
        publicDir: o.publicDir,
        rateLimit: false, // every Tor client arrives from 127.0.0.1; PoW is the spam control
        ...(o.serverOptions || {}),
      });
      const target = hosted.port;
      backendConnect = () => new Promise((resolve, reject) => {
        const s = net.connect(target, '127.0.0.1');
        s.once('connect', () => { s.removeListener('error', reject); resolve(s); });
        s.once('error', reject);
      });
      backendHost = `127.0.0.1:${target}`;
      state.ready = true; // usable locally right away; friends can reach it once Tor is up
      if (o.torPath || o.startTor) {
        tor = startTor({ torPath: o.torPath, dataDir: path.join(o.homeDir, 'tor-host'), hidden: { dir: path.join(o.homeDir, 'onion-service'), targetPort: target } });
        watchTor(tor);
        tor.onion().then((h) => { state.onion = h; }).catch(() => {});
      }
    } else {
      if (!o.torPath && !o.startTor) throw new Error('no_tor');
      state.onion = cfg.onion;
      const socksPort = await freePort();
      tor = startTor({ torPath: o.torPath, dataDir: path.join(o.homeDir, 'tor-join'), socksPort });
      watchTor(tor);
      backendConnect = () => socks5Connect({ proxyPort: tor.socksPort, host: cfg.onion, port: 80 });
      backendHost = cfg.onion;
    }
  }

  async function deactivate() {
    if (tor) { tor.stop(); tor = null; }
    if (hosted) { await hosted.close(); hosted = null; }
    backendConnect = null;
    backendHost = null;
    Object.assign(state, { mode: null, onion: null, ready: false, tor: { state: 'off', progress: 0, error: null } });
  }

  // ------------------------------------------------------------------ request guards

  const allowedHosts = new Set([`127.0.0.1:${port}`, `localhost:${port}`]);
  const allowedOrigins = new Set([`http://127.0.0.1:${port}`, `http://localhost:${port}`]);
  /** DNS rebinding: only our own host names. */
  const hostOk = (req) => allowedHosts.has(String(req.headers.host || '').toLowerCase());
  /** Cross-site requests from other web pages are refused (CSRF on the local panel / proxy). */
  const sameSite = (req) => {
    const site = req.headers['sec-fetch-site'];
    if (site !== undefined && site !== 'same-origin' && site !== 'none') return false;
    const origin = req.headers.origin;
    return origin === undefined || allowedOrigins.has(String(origin).toLowerCase());
  };

  // ------------------------------------------------------------------ handlers

  function serveStatic(res, root, urlPath, fallbackIndex) {
    const rel = urlPath === '/' || urlPath === '' ? `/${fallbackIndex}` : urlPath;
    const file = safeFile(root, rel);
    if (!file) { res.writeHead(404, SECURITY_HEADERS); res.end(); return; }
    fs.stat(file, (err, st) => {
      if (err || !st.isFile()) { res.writeHead(404, SECURITY_HEADERS); res.end(); return; }
      const type = MIME[path.extname(file).toLowerCase()];
      if (!type) { res.writeHead(404, SECURITY_HEADERS); res.end(); return; }
      res.writeHead(200, { ...SECURITY_HEADERS, 'Content-Type': type, 'Content-Length': st.size, 'Cache-Control': 'no-cache' });
      fs.createReadStream(file).pipe(res);
    });
  }

  function proxyHttp(req, res) {
    if (!backendConnect || !state.ready) { sendJson(res, 503, { error: 'offline' }); return; }
    const headers = { host: backendHost };
    for (const h of FWD_REQ) if (req.headers[h] !== undefined) headers[h] = req.headers[h];
    if (req.headers['transfer-encoding'] !== undefined && headers['content-length'] === undefined) headers['transfer-encoding'] = 'chunked';
    const connect = backendConnect;
    const preq = http.request({
      method: req.method,
      path: req.url,
      headers,
      createConnection: (_opts, cb) => { connect().then((s) => cb(null, s), (e) => cb(e)); },
    });
    preq.setTimeout(180000, () => preq.destroy(new Error('timeout')));
    preq.on('response', (pres) => {
      const out = {};
      for (const [k, v] of Object.entries(pres.headers)) if (!HOP.has(k)) out[k] = v;
      res.writeHead(pres.statusCode || 502, out);
      pres.pipe(res);
    });
    preq.on('error', () => {
      if (!res.headersSent) sendJson(res, 502, { error: 'network' });
      else res.destroy();
    });
    req.pipe(preq);
  }

  async function handleLocal(req, res, p) {
    if (p === '/_local/ping' && req.method === 'GET') { sendJson(res, 200, { sombra: true }); return; }
    if (p === '/_local/status' && req.method === 'GET') { sendJson(res, 200, state); return; }
    if (req.method === 'POST') {
      let body;
      try { body = await readBodyJson(req); } catch { sendJson(res, 400, { error: 'bad_request' }); return; }
      if (p === '/_local/setup') {
        if (state.mode) { sendJson(res, 409, { error: 'already_configured' }); return; }
        let cfg = null;
        if (body.mode === 'host') cfg = { mode: 'host' };
        else if (body.mode === 'join') {
          const onion = normalizeOnion(body.onion);
          if (!onion) { sendJson(res, 400, { error: 'bad_address' }); return; }
          cfg = { mode: 'join', onion };
        }
        if (!cfg) { sendJson(res, 400, { error: 'bad_request' }); return; }
        try {
          await activate(cfg);
          writeConfig(cfg);
        } catch {
          await deactivate().catch(() => {});
          sendJson(res, 500, { error: 'start_failed' });
          return;
        }
        sendJson(res, 200, state);
        return;
      }
      if (p === '/_local/reset') {
        // Forget the network choice (the hosted server data and onion key stay on disk).
        await deactivate();
        try { fs.unlinkSync(configPath); } catch { /* none */ }
        sendJson(res, 200, state);
        return;
      }
      if (p === '/_local/quit') {
        sendJson(res, 200, { ok: true });
        setTimeout(() => { if (o.onQuit) o.onQuit(); }, 100);
        return;
      }
    }
    if (req.method === 'GET') { serveStatic(res, o.uiDir, p.slice('/_local'.length) || '/', 'setup.html'); return; }
    sendJson(res, 405, { error: 'method' });
  }

  const server = http.createServer((req, res) => {
    const url = String(req.url || '/');
    const p = url.split('?')[0];
    if (!hostOk(req)) { res.writeHead(421, SECURITY_HEADERS); res.end(); return; }
    const sensitive = p.startsWith('/api/') || p.startsWith('/_local/') || req.method !== 'GET';
    if (sensitive && !sameSite(req)) { sendJson(res, 403, { error: 'cross_site' }); return; }
    if (p.startsWith('/api/')) { proxyHttp(req, res); return; }
    if (p === '/_local' || p.startsWith('/_local/')) {
      handleLocal(req, res, p === '/_local' ? '/_local/' : p).catch(() => { if (!res.headersSent) sendJson(res, 500, { error: 'internal' }); });
      return;
    }
    if (req.method !== 'GET' && req.method !== 'HEAD') { sendJson(res, 405, { error: 'method' }); return; }
    if ((p === '/' || p === '/index.html') && !state.ready) {
      res.writeHead(302, { ...SECURITY_HEADERS, Location: '/_local/?next=app', 'Cache-Control': 'no-store' });
      res.end();
      return;
    }
    serveStatic(res, o.publicDir, p, 'index.html');
  });

  server.on('upgrade', (req, socket, head) => {
    const p = String(req.url || '').split('?')[0];
    if (p !== '/ws' || !hostOk(req) || !sameSite(req) || !backendConnect || !state.ready) {
      socket.end('HTTP/1.1 403 Forbidden\r\nConnection: close\r\nContent-Length: 0\r\n\r\n');
      return;
    }
    socket.on('error', () => {});
    backendConnect().then((up) => {
      up.on('error', () => socket.destroy());
      socket.on('close', () => up.destroy());
      up.on('close', () => socket.destroy());
      let reqHead = `GET /ws HTTP/1.1\r\nHost: ${backendHost}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n`;
      for (const h of FWD_WS) {
        const v = req.headers[h];
        if (typeof v === 'string' && !/[\r\n]/.test(v)) reqHead += `${h}: ${v}\r\n`;
      }
      up.write(reqHead + '\r\n');
      if (head && head.length) up.write(head);
      socket.pipe(up);
      up.pipe(socket);
    }, () => socket.destroy());
  });

  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(port, '127.0.0.1', () => { server.removeListener('error', reject); resolve(); });
  });
  const actualPort = server.address().port;
  if (actualPort !== port) {
    // port 0 in tests: re-key the allow-lists to the real port
    allowedHosts.clear(); allowedOrigins.clear();
    allowedHosts.add(`127.0.0.1:${actualPort}`); allowedHosts.add(`localhost:${actualPort}`);
    allowedOrigins.add(`http://127.0.0.1:${actualPort}`); allowedOrigins.add(`http://localhost:${actualPort}`);
  }

  const saved = readConfig();
  if (saved) await activate(saved).catch(() => deactivate());

  return {
    port: actualPort,
    url: `http://127.0.0.1:${actualPort}/`,
    state,
    async close() {
      await deactivate().catch(() => {});
      await new Promise((r) => { server.close(() => r()); server.closeAllConnections?.(); });
    },
  };
}
