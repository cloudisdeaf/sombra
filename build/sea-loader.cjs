// Entry of the single-executable (SEA) build. Node's SEA can only run one CommonJS file,
// so this loader extracts the embedded, unmodified source tree (launcher, server, web app,
// ws, Tor) to %LOCALAPPDATA%\Sombra\app\<version>-<hash>\ once, then loads the launcher
// from there. Placeholders are filled in by build/build.mjs.
'use strict';
const sea = require('node:sea');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const { createRequire } = require('node:module');

const VERSION = '__SOMBRA_VERSION__';
const BUILD = '__SOMBRA_BUILD__';
const DOWNLOAD_URL = '__SOMBRA_DOWNLOAD_URL__';

const localAppData = process.env.LOCALAPPDATA || path.join(os.homedir(), 'AppData', 'Local');
const home = process.env.SOMBRA_HOME || path.join(localAppData, 'Sombra');
const appsDir = path.join(home, 'app');
const root = path.join(appsDir, `${VERSION}-${BUILD}`);
const marker = path.join(root, '.complete');

if (!fs.existsSync(marker)) {
  fs.rmSync(root, { recursive: true, force: true });
  for (const key of sea.getAssetKeys()) {
    const dest = path.join(root, ...key.split('/'));
    if (!dest.startsWith(root + path.sep)) continue;
    fs.mkdirSync(path.dirname(dest), { recursive: true });
    fs.writeFileSync(dest, Buffer.from(sea.getAsset(key)));
  }
  fs.writeFileSync(marker, BUILD);
}
try { // old versions (only code; accounts, onion keys and server data live elsewhere)
  for (const d of fs.readdirSync(appsDir)) {
    if (d !== path.basename(root)) fs.rmSync(path.join(appsDir, d), { recursive: true, force: true });
  }
} catch { /* in use: removed next time */ }

globalThis.__SOMBRA_BOOT__ = { version: VERSION, downloadUrl: DOWNLOAD_URL, appRoot: root, home };
createRequire(path.join(root, 'loader.cjs'))('./launcher/main.js');
