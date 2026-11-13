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

const localAppData = process.env.LOCALAPPDATA || path.join(os.homedir(), 'AppData', 'Local');
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
  const appData = process.env.APPDATA || path.join(os.homedir(), 'AppData', 'Roaming');
  const desktop = (ps('[Environment]::GetFolderPath("Desktop")').stdout || '').trim() || path.join(os.homedir(), 'Desktop');
  return [
    path.join(appData, 'Microsoft', 'Windows', 'Start Menu', 'Programs', 'Sombra.lnk'),
    path.join(desktop, 'Sombra.lnk'),
  ];
}

const UNINSTALL_KEY = 'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\Sombra';

async function install() {
  if (await ping(DEFAULT_PORT)) {
    messageBox('Sombra ya está abierto. Ciérralo desde su panel («Cerrar Sombra») y vuelve a ejecutar el instalador.');
    return;
  }
  fs.mkdirSync(INSTALL_DIR, { recursive: true });
  fs.copyFileSync(process.execPath, INSTALLED_EXE);
  for (const lnk of shortcutPaths()) {
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
  spawn(INSTALLED_EXE, [], { detached: true, stdio: 'ignore', cwd: INSTALL_DIR }).unref();
}

async function uninstall() {
  if (messageBox('¿Desinstalar Sombra de este ordenador?', { buttons: 'YesNo', icon: 'Question' }) !== 'Yes') return;
  if (await ping(DEFAULT_PORT)) {
    await new Promise((resolve) => {
      const r = http.request({ host: '127.0.0.1', port: DEFAULT_PORT, path: '/_local/quit', method: 'POST', headers: { host: `127.0.0.1:${DEFAULT_PORT}`, 'content-type': 'application/json' } }, () => resolve());
      r.on('error', resolve);
      r.end('{}');
    });
    await new Promise((r) => setTimeout(r, 1500));
  }
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
  const port = Number(process.env.SOMBRA_PORT) || DEFAULT_PORT;
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
