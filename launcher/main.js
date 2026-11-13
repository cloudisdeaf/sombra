// Entry point of Sombra.exe (and of `npm run app` during development).
//
//   Sombra-Setup.exe            first run: installs itself for the current user
//                               (%LOCALAPPDATA%\Programs\Sombra), adds Start menu and
//                               desktop shortcuts, then starts the installed copy.
//   Sombra.exe                  starts the local launcher and opens the browser.
//   Sombra.exe --uninstall      removes the program (asks before deleting data).
//   Sombra.exe --portable       runs from where it is, without installing.
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import http from 'node:http';
import { spawn, spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { createLauncher, DEFAULT_PORT } from './app.js';

// Set by build/sea-loader.cjs when running from the packaged Sombra.exe.
const BOOT = globalThis.__SOMBRA_BOOT__ || null;
const IN_SEA = !!BOOT;
const VERSION = BOOT ? BOOT.version : 'dev';
const DOWNLOAD_URL = BOOT ? BOOT.downloadUrl : 'https://github.com/';
const IS_WIN = process.platform === 'win32';
const args = new Set(process.argv.slice(2));

// SOMBRA_SANDBOX=<dir> redirects everything the installer touches (program folder, data,
// shortcuts, registry key) and answers dialogs automatically, so the install / update /
// uninstall flow can be tested without touching the real installation.
const SANDBOX = process.env.SOMBRA_SANDBOX ? path.resolve(process.env.SOMBRA_SANDBOX) : null;
const PORT = Number(process.env.SOMBRA_PORT) || DEFAULT_PORT;

const localAppData = SANDBOX
  ? path.join(SANDBOX, 'local')
  : (process.env.LOCALAPPDATA || path.join(os.homedir(), 'AppData', 'Local'));
const HOME = process.env.SOMBRA_HOME || path.join(localAppData, 'Sombra');
const INSTALL_DIR = path.join(localAppData, 'Programs', 'Sombra');
const INSTALLED_EXE = path.join(INSTALL_DIR, 'Sombra.exe');

// The packaged .exe has no console window: keep a tiny error log (never message data,
// never addresses or usernames — only launcher failures).
function logError(err) {
  try {
    fs.mkdirSync(HOME, { recursive: true });
    fs.appendFileSync(path.join(HOME, 'launcher-error.log'), `[${new Date().toISOString()}] ${err && err.stack ? err.stack : String(err)}\n`);
  } catch { /* ignore */ }
}
if (IN_SEA) {
  for (const k of ['log', 'info', 'warn', 'error', 'debug']) console[k] = () => {};
}
process.on('uncaughtException', (e) => { logError(e); });
process.on('unhandledRejection', (e) => { logError(e); });

/** Native Windows message box (PowerShell). Text goes through env vars: no injection. */
function messageBox(text, { buttons = 'OK', icon = 'Information' } = {}) {
  if (SANDBOX) {
    try {
      fs.mkdirSync(SANDBOX, { recursive: true });
      fs.appendFileSync(path.join(SANDBOX, 'messages.log'), `[${buttons}] ${text}\n`);
    } catch { /* ignore */ }
    return buttons === 'YesNo' ? 'Yes' : 'OK';
  }
  if (!IS_WIN) return 'OK';
  const script = 'Add-Type -AssemblyName System.Windows.Forms;' +
    '[System.Windows.Forms.MessageBox]::Show($env:SOMBRA_MSG, "Sombra", $env:SOMBRA_BTN, $env:SOMBRA_ICON)';
  const r = spawnSync('powershell.exe', ['-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-Command', script], {
    env: { ...process.env, SOMBRA_MSG: text, SOMBRA_BTN: buttons, SOMBRA_ICON: icon },
    windowsHide: true, encoding: 'utf8',
  });
  return String(r.stdout || '').trim();
}

function openBrowser(url) {
  if (IS_WIN) spawn('rundll32.exe', ['url.dll,FileProtocolHandler', url], { detached: true, stdio: 'ignore', windowsHide: true }).unref();
  else if (process.platform === 'darwin') spawn('open', [url], { detached: true, stdio: 'ignore' }).unref();
  else spawn('xdg-open', [url], { detached: true, stdio: 'ignore' }).unref();
}

function ping(port) {
  return new Promise((resolve) => {
    const r = http.get({ host: '127.0.0.1', port, path: '/_local/ping', headers: { host: `127.0.0.1:${port}` }, timeout: 1500 }, (res) => {
      let b = '';
      res.on('data', (c) => { b += c; });
      res.on('end', () => { try { resolve(JSON.parse(b).sombra === true); } catch { resolve(false); } });
    });
    r.on('error', () => resolve(false));
    r.on('timeout', () => { r.destroy(); resolve(false); });
  });
}

// ------------------------------------------------------------------ install / uninstall (Windows)

function ps(script, env = {}) {
  return spawnSync('powershell.exe', ['-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-Command', script], {
    env: { ...process.env, ...env }, windowsHide: true, encoding: 'utf8',
  });
}

function shortcutPaths() {
  const appData = SANDBOX ? path.join(SANDBOX, 'roaming') : (process.env.APPDATA || path.join(os.homedir(), 'AppData', 'Roaming'));
  const desktop = SANDBOX
    ? path.join(SANDBOX, 'desktop')
    : ((ps('[Environment]::GetFolderPath("Desktop")').stdout || '').trim() || path.join(os.homedir(), 'Desktop'));
  return [
    path.join(appData, 'Microsoft', 'Windows', 'Start Menu', 'Programs', 'Sombra.lnk'),
    path.join(desktop, 'Sombra.lnk'),
  ];
}

const UNINSTALL_KEY = SANDBOX
  ? 'HKCU\\Software\\SombraSandbox\\Uninstall'
  : 'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\Sombra';

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

/** Version recorded by the previous installation, or null (first install). */
function installedVersion() {
  const r = spawnSync('reg.exe', ['query', UNINSTALL_KEY, '/v', 'DisplayVersion'], { windowsHide: true, encoding: 'utf8' });
  const m = /DisplayVersion\s+REG_SZ\s+(\S+)/.exec(String(r.stdout || ''));
  return r.status === 0 && m ? m[1] : null;
}

/** Ask a running Sombra to quit and wait until it has stopped answering. */
async function quitRunning(port) {
  await new Promise((resolve) => {
    const r = http.request({ host: '127.0.0.1', port, path: '/_local/quit', method: 'POST', headers: { host: `127.0.0.1:${port}`, 'content-type': 'application/json' } }, () => resolve());
    r.on('error', resolve);
    r.end('{}');
  });
  for (let i = 0; i < 40 && await ping(port); i++) await sleep(250);
  await sleep(500); // let the process release its files
  return !(await ping(port));
}

async function install() {
  const previous = installedVersion();
  if (await ping(PORT)) {
    const ok = messageBox(
      `Sombra está abierto${previous ? ` (versión ${previous})` : ''}. Para instalar la versión ${VERSION} hay que cerrarlo, y se abrirá de nuevo al terminar.\n\n` +
      'Si tu ordenador hace de anfitrión de una red, tus amigos se desconectarán unos segundos. Tus cuentas, chats y red se conservan.\n\n¿Continuar?',
      { buttons: 'YesNo', icon: 'Question' }) === 'Yes';
    if (!ok) return;
    if (!(await quitRunning(PORT))) {
      messageBox('No se pudo cerrar la versión abierta de Sombra. Ciérrala desde su panel («Cerrar Sombra») y vuelve a ejecutar el instalador.', { icon: 'Error' });
      return;
    }
  }
  fs.mkdirSync(INSTALL_DIR, { recursive: true });
  // Replace the old program. Windows may keep the old exe locked for a moment after it exits.
  let copied = false;
  for (let i = 0; i < 20 && !copied; i++) {
    try { fs.copyFileSync(process.execPath, INSTALLED_EXE); copied = true; } catch (err) {
      if (!err || !['EBUSY', 'EPERM', 'EACCES'].includes(err.code)) throw err;
      await sleep(500);
    }
  }
  if (!copied) {
    messageBox('No se pudo reemplazar la versión anterior de Sombra: algún programa la tiene en uso. Cierra Sombra por completo y vuelve a ejecutar el instalador.', { icon: 'Error' });
    return;
  }
  for (const lnk of shortcutPaths()) {
    fs.mkdirSync(path.dirname(lnk), { recursive: true });
    ps('$s=(New-Object -ComObject WScript.Shell).CreateShortcut($env:SOMBRA_LNK);$s.TargetPath=$env:SOMBRA_EXE;$s.WorkingDirectory=$env:SOMBRA_DIR;$s.IconLocation=$env:SOMBRA_EXE+",0";$s.Description="Sombra";$s.Save()',
      { SOMBRA_LNK: lnk, SOMBRA_EXE: INSTALLED_EXE, SOMBRA_DIR: INSTALL_DIR });
  }
  const reg = (name, type, value) => spawnSync('reg.exe', ['add', UNINSTALL_KEY, '/v', name, '/t', type, '/d', value, '/f'], { windowsHide: true });
  reg('DisplayName', 'REG_SZ', 'Sombra');
  reg('DisplayVersion', 'REG_SZ', VERSION);
  reg('Publisher', 'REG_SZ', 'Sombra');
  reg('DisplayIcon', 'REG_SZ', INSTALLED_EXE);
  reg('InstallLocation', 'REG_SZ', INSTALL_DIR);
  reg('UninstallString', 'REG_SZ', `"${INSTALLED_EXE}" --uninstall`);
  reg('NoModify', 'REG_DWORD', '1');
  reg('NoRepair', 'REG_DWORD', '1');
  if (previous && previous !== VERSION) {
    messageBox(`Sombra se ha actualizado de la versión ${previous} a la ${VERSION}. La versión anterior se ha desinstalado; tus cuentas y chats siguen donde estaban.`);
  }
  if (!SANDBOX) spawn(INSTALLED_EXE, [], { detached: true, stdio: 'ignore', cwd: INSTALL_DIR }).unref();
}

async function uninstall() {
  if (messageBox('¿Desinstalar Sombra de este ordenador?', { buttons: 'YesNo', icon: 'Question' }) !== 'Yes') return;
  if (await ping(PORT)) await quitRunning(PORT);
  for (const lnk of shortcutPaths()) { try { fs.unlinkSync(lnk); } catch { /* none */ } }
  spawnSync('reg.exe', ['delete', UNINSTALL_KEY, '/f'], { windowsHide: true });
  const wipe = messageBox(
    '¿Borrar también los datos de Sombra de este ordenador?\n\n' +
    'Incluye la red que hayas creado (su dirección .onion y los mensajes pendientes de entrega). ' +
    'Tu cuenta y tus chats viven en el navegador: bórralos desde Sombra › Ajustes antes de desinstalar si quieres eliminarlos.',
    { buttons: 'YesNo', icon: 'Warning' });
  // The running exe cannot delete itself: a detached cmd removes the folder a moment later.
  const targets = [INSTALL_DIR, ...(wipe === 'Yes' ? [HOME] : [])];
  const cmd = `ping -n 3 127.0.0.1 >nul & ${targets.map((t) => `rmdir /s /q "${t}"`).join(' & ')}`;
  spawn('cmd.exe', ['/d', '/c', cmd], { detached: true, stdio: 'ignore', windowsHide: true }).unref();
  messageBox('Sombra se ha desinstalado.');
}

// ------------------------------------------------------------------ assets

/** Web app, panel and Tor: next to this file (packaged) or in the repository (dev). */
function findAssets() {
  const here = path.dirname(fileURLToPath(import.meta.url));
  const root = path.resolve(here, '..');
  const tor = [process.env.SOMBRA_TOR, path.join(root, 'tor', 'tor.exe'), path.join(root, 'build', 'vendor', 'tor', 'tor.exe')]
    .find((p) => p && fs.existsSync(p)) || null;
  return { publicDir: path.join(root, 'public'), uiDir: path.join(here, 'ui'), torPath: tor };
}

// ------------------------------------------------------------------ main

async function main() {
  if (args.has('--uninstall')) { await uninstall(); return; }
  if (IN_SEA && IS_WIN && !args.has('--portable') &&
      path.resolve(process.execPath).toLowerCase() !== INSTALLED_EXE.toLowerCase()) {
    await install();
    return;
  }
  const port = PORT;
  const url = `http://127.0.0.1:${port}/`;
  if (await ping(port)) { // already running: just show it
    if (!args.has('--no-browser')) openBrowser(url);
    return;
  }
  const assets = findAssets();
  if (process.env.SOMBRA_NO_TOR === '1') assets.torPath = null;
  let launcher;
  try {
    launcher = await createLauncher({
      homeDir: HOME, port, version: VERSION, downloadUrl: DOWNLOAD_URL, ...assets,
      onQuit: async () => { await launcher.close().catch(() => {}); process.exit(0); },
    });
  } catch (err) {
    logError(err);
    messageBox(err && err.code === 'EADDRINUSE'
      ? `El puerto ${port} está ocupado por otro programa. Ciérralo y vuelve a abrir Sombra.`
      : 'Sombra no se pudo iniciar.', { icon: 'Error' });
    process.exit(1);
  }
  if (!assets.torPath && !IN_SEA) process.stdout.write('Tor no encontrado: solo funcionará en modo local (ver build/build.mjs).\n');
  if (!IN_SEA) process.stdout.write(`Sombra: ${url}\n`);
  if (!args.has('--no-browser')) openBrowser(url);
}

main().catch((e) => { logError(e); process.exit(1); });
