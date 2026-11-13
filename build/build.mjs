// Builds dist/Sombra-Setup.exe (Windows x64) — one self-installing executable that
// contains Node.js, the Sombra server + web app, the local panel and Tor.
//
//   npm install
//   npm run build
//
// Set your download link (shown in the invitation your friends receive) in package.json:
//   "sombra": { "downloadUrl": "https://github.com/<you>/sombra/releases/latest" }
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import * as ResEdit from 'resedit';
import { ico } from './icon.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const OUT = path.join(ROOT, 'build', 'out');
const VENDOR = path.join(ROOT, 'build', 'vendor');
const DIST = path.join(ROOT, 'dist');
const pkg = JSON.parse(fs.readFileSync(path.join(ROOT, 'package.json'), 'utf8'));
const VERSION = pkg.version;
const DOWNLOAD_URL = process.env.SOMBRA_DOWNLOAD_URL || (pkg.sombra && pkg.sombra.downloadUrl) || 'https://github.com/';

// Tor Expert Bundle — pinned. The signature of this exact file was checked against the
// Tor Browser Developers signing key (EF6E 286D DA85 EA2A 4BA7 DE68 4E2C 6E87 9329 8290).
// To update: download the new .tar.gz and .asc, verify with gpg, then update both lines.
const TOR = {
  url: 'https://archive.torproject.org/tor-package-archive/torbrowser/16.0.1/tor-expert-bundle-windows-x86_64-16.0.1.tar.gz',
  sha256: '9eed3c3ff1fe43df034ce360196c9ec95472560d77ff55614d0cd5120edea27b',
};

const step = (m) => process.stdout.write(`• ${m}\n`);

async function vendorTor() {
  const torExe = path.join(VENDOR, 'tor', 'tor.exe');
  if (fs.existsSync(torExe)) return;
  step('Descargando Tor (Expert Bundle)…');
  const res = await fetch(TOR.url);
  if (!res.ok) throw new Error(`Tor download failed: HTTP ${res.status}`);
  const buf = Buffer.from(await res.arrayBuffer());
  const got = crypto.createHash('sha256').update(buf).digest('hex');
  if (got !== TOR.sha256) throw new Error(`Tor checksum mismatch: ${got}`);
  const tmp = path.join(VENDOR, 'tmp');
  fs.rmSync(tmp, { recursive: true, force: true });
  fs.mkdirSync(tmp, { recursive: true });
  fs.writeFileSync(path.join(tmp, 'tor.tar.gz'), buf);
  const r = spawnSync('tar', ['-xzf', 'tor.tar.gz'], { cwd: tmp, stdio: 'inherit' });
  if (r.status !== 0) throw new Error('tar failed');
  fs.mkdirSync(path.join(VENDOR, 'tor', 'licenses'), { recursive: true });
  fs.copyFileSync(path.join(tmp, 'tor', 'tor.exe'), torExe);
  for (const f of fs.readdirSync(path.join(tmp, 'docs'))) {
    if (f.endsWith('.txt')) fs.copyFileSync(path.join(tmp, 'docs', f), path.join(VENDOR, 'tor', 'licenses', f));
  }
  fs.rmSync(tmp, { recursive: true, force: true });
}

/** The loader is the SEA main script; the app itself ships as plain source files. */
function writeLoader(build) {
  step('Preparando el cargador…');
  const tpl = fs.readFileSync(path.join(ROOT, 'build', 'sea-loader.cjs'), 'utf8');
  const out = tpl
    .split('__SOMBRA_VERSION__').join(VERSION)
    .split('__SOMBRA_BUILD__').join(build)
    .split('__SOMBRA_DOWNLOAD_URL__').join([...DOWNLOAD_URL].filter((ch) => ![39, 92, 10, 13].includes(ch.charCodeAt(0))).join(''));
  const file = path.join(OUT, 'loader.cjs');
  fs.writeFileSync(file, out);
  return file;
}

function walk(dir, prefix, out) {
  for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, e.name);
    const key = `${prefix}/${e.name}`;
    if (e.isDirectory()) walk(full, key, out);
    else if (e.isFile()) out[key] = full;
  }
  return out;
}

function baseExecutable() {
  step('Preparando el ejecutable base (icono y versión)…');
  const base = path.join(OUT, 'base.exe');
  const exe = ResEdit.NtExecutable.from(fs.readFileSync(process.execPath), { ignoreCert: true });
  const res = ResEdit.NtExecutableResource.from(exe);
  const iconFile = ResEdit.Data.IconFile.from(ico());
  const groups = ResEdit.Resource.IconGroupEntry.fromEntries(res.entries);
  const targets = groups.length ? groups.map((g) => [g.id, g.lang]) : [[1, 1033]];
  for (const [id, lang] of targets) {
    ResEdit.Resource.IconGroupEntry.replaceIconsForResource(res.entries, id, lang, iconFile.icons.map((i) => i.data));
  }
  const vi = ResEdit.Resource.VersionInfo.fromEntries(res.entries)[0] || ResEdit.Resource.VersionInfo.createEmpty();
  const [a, b, c] = VERSION.split('.').map((n) => Number(n) || 0);
  vi.setFileVersion(a, b, c, 0, 1033);
  vi.setProductVersion(a, b, c, 0, 1033);
  const langs = vi.getAllLanguagesForStringValues();
  for (const l of (langs.length ? langs : [{ lang: 1033, codepage: 1200 }])) {
    vi.setStringValues(l, {
      ProductName: 'Sombra', FileDescription: 'Sombra', InternalName: 'Sombra',
      OriginalFilename: 'Sombra.exe', CompanyName: 'Sombra', LegalCopyright: '',
      FileVersion: VERSION, ProductVersion: VERSION,
    });
  }
  vi.outputToResourceEntries(res.entries);
  res.outputResource(exe);
  fs.writeFileSync(base, Buffer.from(exe.generate()));
  return base;
}

/** Mark the PE as a Windows GUI application: no console window pops up. */
function setGuiSubsystem(file) {
  const buf = fs.readFileSync(file);
  const pe = buf.readUInt32LE(0x3c);
  if (buf.toString('latin1', pe, pe + 4) !== 'PE\0\0') throw new Error('not a PE file');
  buf.writeUInt16LE(2, pe + 24 + 68); // IMAGE_SUBSYSTEM_WINDOWS_GUI
  fs.writeFileSync(file, buf);
}

async function main() {
  if (process.platform !== 'win32') throw new Error('El instalador se construye en Windows (x64).');
  fs.rmSync(OUT, { recursive: true, force: true });
  fs.mkdirSync(OUT, { recursive: true });
  fs.mkdirSync(DIST, { recursive: true });
  await vendorTor();
  const base = baseExecutable();

  // Embedded files = the unmodified source tree (auditable after extraction).
  const assets = {};
  for (const f of fs.readdirSync(path.join(ROOT, 'launcher'))) {
    if (f.endsWith('.js')) assets[`launcher/${f}`] = path.join(ROOT, 'launcher', f);
  }
  walk(path.join(ROOT, 'launcher', 'ui'), 'launcher/ui', assets);
  for (const f of fs.readdirSync(path.join(ROOT, 'server'))) {
    if (f.endsWith('.js')) assets[`server/${f}`] = path.join(ROOT, 'server', f);
  }
  walk(path.join(ROOT, 'public'), 'public', assets);
  walk(path.join(ROOT, 'node_modules', 'ws'), 'node_modules/ws', assets);
  walk(path.join(VENDOR, 'tor'), 'tor', assets);
  const appPkg = path.join(OUT, 'package.json');
  fs.writeFileSync(appPkg, JSON.stringify({ name: 'sombra-app', version: VERSION, private: true, type: 'module' }));
  assets['package.json'] = appPkg;
  // Build id = hash of everything embedded: a rebuilt exe always re-extracts.
  const h = crypto.createHash('sha256');
  for (const k of Object.keys(assets).sort()) { h.update(k); h.update(fs.readFileSync(assets[k])); }
  const loader = writeLoader(h.digest('hex').slice(0, 12));
  const output = path.join(OUT, 'Sombra.exe');
  const seaConfig = {
    main: loader,
    output,
    executable: base,
    disableExperimentalSEAWarning: true,
    useCodeCache: false,
    useSnapshot: false,
    assets,
  };
  fs.writeFileSync(path.join(OUT, 'sea.json'), JSON.stringify(seaConfig, null, 2));
  step(`Generando el ejecutable (${Object.keys(assets).length} recursos)…`);
  const r = spawnSync(process.execPath, ['--build-sea', path.join(OUT, 'sea.json')], { stdio: 'inherit' });
  if (r.status !== 0) throw new Error('node --build-sea failed');
  setGuiSubsystem(output);

  const final = path.join(DIST, 'Sombra-Setup.exe');
  fs.copyFileSync(output, final);
  const sum = crypto.createHash('sha256').update(fs.readFileSync(final)).digest('hex');
  fs.writeFileSync(`${final}.sha256`, `${sum}  Sombra-Setup.exe\n`);
  fs.rmSync(path.join(OUT, 'base.exe'), { force: true });
  step(`Listo: dist/Sombra-Setup.exe (${(fs.statSync(final).size / 1048576).toFixed(0)} MB)`);
  step(`SHA-256: ${sum}`);
}

main().catch((e) => { process.stderr.write(`\n✗ ${e.message}\n`); process.exit(1); });
