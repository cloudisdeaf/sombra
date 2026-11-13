// Runs the bundled Tor (tor.exe) as a child process.
//   host mode: publishes a v3 onion service that points to the local Sombra server.
//   join mode: opens a local SOCKS port used to reach a friend's onion service.
// Tor exits by itself if this process dies (__OwningControllerProcess).
import { spawn } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import net from 'node:net';

export const ONION_RE = /^[a-z2-7]{56}\.onion$/;

/** Accepts "http://xxxx.onion/", " XXXX.onion " … → "xxxx.onion" or null. */
export function normalizeOnion(input) {
  let s = String(input ?? '').trim().toLowerCase();
  s = s.replace(/^[a-z]+:\/\//, '');
  s = s.split('/')[0].split(':')[0];
  return ONION_RE.test(s) ? s : null;
}

/** A free TCP port on 127.0.0.1 (best effort). */
export function freePort() {
  return new Promise((resolve, reject) => {
    const srv = net.createServer();
    srv.unref();
    srv.on('error', reject);
    srv.listen(0, '127.0.0.1', () => {
      const { port } = srv.address();
      srv.close(() => resolve(port));
    });
  });
}

/**
 * @param {{torPath: string, dataDir: string, socksPort?: number,
 *          hidden?: {dir: string, targetPort: number}}} o
 * @returns {{state: string, progress: number, error: string|null, socksPort: number|null,
 *            onion: () => Promise<string>, stop: () => void, onChange: (fn) => void}}
 */
export function startTor({ torPath, dataDir, socksPort = 0, hidden = null }) {
  fs.mkdirSync(dataDir, { recursive: true });
  const torrc = path.join(dataDir, 'torrc');
  if (!fs.existsSync(torrc)) fs.writeFileSync(torrc, '');
  const args = [
    '-f', torrc, '--defaults-torrc', torrc, '--ignore-missing-torrc',
    '--DataDirectory', dataDir,
    '--Log', 'notice stdout',
    '--SocksPort', socksPort ? `127.0.0.1:${socksPort}` : '0',
    '--ClientOnly', '1',
    '--AvoidDiskWrites', '1',
    '--GeoIPFile', '', '--GeoIPv6File', '',
    '--__OwningControllerProcess', String(process.pid),
  ];
  if (hidden) {
    fs.mkdirSync(hidden.dir, { recursive: true });
    args.push('--HiddenServiceDir', hidden.dir, '--HiddenServicePort', `80 127.0.0.1:${hidden.targetPort}`);
  }
  const listeners = new Set();
  const t = {
    state: 'starting',
    progress: 0,
    error: null,
    socksPort: socksPort || null,
    onChange(fn) { listeners.add(fn); },
    stop() {
      stopped = true;
      try { proc.kill(); } catch { /* already gone */ }
    },
    onion: () => onionPromise,
  };
  const emit = () => { for (const fn of listeners) { try { fn(t); } catch { /* ignore */ } } };
  let stopped = false;
  const proc = spawn(torPath, args, { windowsHide: true, stdio: ['ignore', 'pipe', 'pipe'] });
  let tail = '';
  proc.stdout.setEncoding('utf8');
  proc.stdout.on('data', (chunk) => {
    tail = (tail + chunk).slice(-4096);
    for (const m of chunk.matchAll(/Bootstrapped (\d{1,3})%/g)) {
      t.progress = Math.min(100, Number(m[1]));
      if (t.progress >= 100) t.state = 'ready';
      emit();
    }
  });
  proc.stderr.resume();
  proc.on('error', () => { t.state = 'error'; t.error = 'tor_failed_to_start'; emit(); });
  proc.on('exit', () => {
    if (!stopped && t.state !== 'error') {
      t.state = 'error';
      t.error = /Address already in use|Could not bind/i.test(tail) ? 'tor_port_busy' : 'tor_exited';
      emit();
    }
  });
  const onionPromise = hidden
    ? new Promise((resolve, reject) => {
      const file = path.join(hidden.dir, 'hostname');
      const tick = () => {
        if (t.state === 'error') { reject(new Error(t.error)); return; }
        try {
          const h = fs.readFileSync(file, 'utf8').trim();
          if (ONION_RE.test(h)) { resolve(h); return; }
        } catch { /* not yet */ }
        setTimeout(tick, 300);
      };
      tick();
    })
    : Promise.resolve(null);
  onionPromise.catch(() => {});
  return t;
}
