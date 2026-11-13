// Sombra local panel: choose / show the network. Talks only to the local launcher.
const $ = (id) => document.getElementById(id);
const show = (id) => { for (const s of ['choose', 'connecting', 'ready']) $(s).hidden = s !== id; };
const goApp = new URLSearchParams(location.search).get('next') === 'app';
let last = null;
let busy = false;

function toast(text) {
  const t = $('toast');
  t.textContent = text;
  t.hidden = false;
  clearTimeout(toast.timer);
  toast.timer = setTimeout(() => { t.hidden = true; }, 2200);
}

async function api(path, body) {
  const r = await fetch(path, body === undefined
    ? { cache: 'no-store' }
    : { method: 'POST', cache: 'no-store', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
  let data = null;
  try { data = await r.json(); } catch { /* empty */ }
  if (!r.ok) throw new Error((data && data.error) || 'error');
  return data;
}

const TOR_ERRORS = {
  tor_failed_to_start: 'No se pudo iniciar Tor. Puede que un antivirus lo esté bloqueando.',
  tor_exited: 'Tor se ha cerrado inesperadamente.',
  tor_port_busy: 'Tor no puede abrir su puerto. Cierra otras copias de Sombra o Tor e inténtalo de nuevo.',
};

function render(s) {
  last = s;
  // Never contacts anyone by itself: the link just opens the releases page.
  if (s.version && s.version !== 'dev') $('verLink').textContent = `Versión ${s.version} · buscar actualizaciones`;
  if (typeof s.downloadUrl === 'string' && /^https:\/\//.test(s.downloadUrl)) $('verLink').href = s.downloadUrl;
  $('resetBtn').hidden = !s.mode;
  if (!s.mode) { show('choose'); return; }
  if (s.mode === 'join' && !s.ready) {
    show('connecting');
    $('connTitle').textContent = 'Conectando por Tor…';
    $('barFill').style.width = `${Math.max(4, s.tor.progress || 0)}%`;
    $('connText').textContent = `${s.tor.progress || 0}% · la primera vez puede tardar un minuto.`;
    const e = s.tor.state === 'error' ? (TOR_ERRORS[s.tor.error] || 'Error de Tor.') : '';
    $('torErr').textContent = e;
    $('torErr').hidden = !e;
    return;
  }
  if (goApp && s.ready) { location.replace('/'); return; }
  show('ready');
  $('hostBox').hidden = s.mode !== 'host';
  $('joinBox').hidden = s.mode !== 'join';
  if (s.mode === 'join') {
    $('readyTitle').textContent = 'Conectado';
    $('joinAddr').textContent = s.onion || '';
    return;
  }
  $('readyTitle').textContent = 'Tu red está activa';
  const addr = s.onion || '';
  $('addr').textContent = addr || (s.tor.state === 'off' ? 'Tor no está disponible en esta instalación.' : 'Preparando dirección…');
  const closed = s.registration === 'closed';
  $('copyInvite').disabled = !addr || closed;
  $('copyAddr').disabled = !addr;
  $('revokeBtn').disabled = !s.invites;
  $('regBtn').textContent = closed ? 'Abrir el registro con invitaciones' : 'Cerrar el registro';
  $('inviteNote').textContent = closed
    ? 'Registro cerrado: nadie nuevo puede crear cuenta, ni con código. Tus amigos que ya tienen cuenta siguen conectados.'
    : (s.invites ? `Invitaciones sin usar: ${s.invites}. Cada código sirve una sola vez.` : 'No hay invitaciones sin usar. Crea una por cada amigo.');
  let note = 'Tus amigos podrán conectar unos segundos después de que Tor termine de arrancar.';
  if (s.tor.state === 'ready') note = 'Tor está conectado: tu red es accesible mientras Sombra siga abierto.';
  else if (s.tor.state === 'error') note = TOR_ERRORS[s.tor.error] || 'Error de Tor: tus amigos no pueden conectar ahora.';
  else if (s.tor.state === 'off') note = 'Sin Tor solo puedes usar Sombra en este ordenador.';
  else note = `Tor arrancando… ${s.tor.progress || 0}%`;
  $('hostNote').textContent = note;
}

async function refresh() {
  try { render(await api('/_local/status')); } catch { /* launcher closed */ }
}

async function copy(text, okMsg) {
  try {
    await navigator.clipboard.writeText(text);
    toast(okMsg);
  } catch {
    toast('No se pudo copiar.');
  }
}

$('joinForm').addEventListener('submit', async (ev) => {
  ev.preventDefault();
  if (busy) return;
  busy = true;
  $('joinErr').hidden = true;
  try {
    render(await api('/_local/setup', { mode: 'join', onion: $('onion').value, invite: $('invite').value }));
  } catch (err) {
    $('joinErr').textContent = err.message === 'bad_address'
      ? 'Esa dirección no parece válida. Debe terminar en .onion y tener 56 caracteres antes.'
      : err.message === 'bad_invite'
        ? 'El código de invitación no es válido. Son 20 letras y números, por ejemplo XXXX-XXXX-XXXX-XXXX-XXXX.'
        : 'No se pudo iniciar la conexión.';
    $('joinErr').hidden = false;
  } finally { busy = false; }
});

$('hostBtn').addEventListener('click', async () => {
  if (busy) return;
  busy = true;
  try { render(await api('/_local/setup', { mode: 'host' })); } catch { toast('No se pudo crear la red.'); } finally { busy = false; }
});

$('copyAddr').addEventListener('click', () => { if (last && last.onion) copy(last.onion, 'Dirección copiada'); });
$('copyInvite').addEventListener('click', async () => {
  if (!last || !last.onion || busy) return;
  busy = true;
  try {
    const r = await api('/_local/invite', {});
    render(r);
    $('inviteCode').textContent = r.code;
    $('inviteCode').hidden = false;
    const text = [
      'Te invito a mi red privada de Sombra (mensajes cifrados de extremo a extremo, por Tor).',
      '',
      `1. Descarga Sombra: ${r.downloadUrl}`,
      '2. Ábrelo y elige «Unirme a una red».',
      `3. Pega esta dirección: ${r.onion}`,
      `4. Pega este código (sirve una sola vez): ${r.code}`,
      '5. Crea tu usuario y escríbeme.',
    ].join('\n');
    await copy(text, 'Invitación creada y copiada');
  } catch (err) {
    toast(err.message === 'registration_closed' ? 'El registro está cerrado.' : 'No se pudo crear la invitación.');
  } finally { busy = false; }
});

$('revokeBtn').addEventListener('click', async () => {
  if (!confirm('¿Anular todas las invitaciones sin usar? Los códigos que ya hayas enviado dejarán de funcionar.')) return;
  try { render(await api('/_local/invites/revoke', {})); $('inviteCode').hidden = true; toast('Invitaciones anuladas'); } catch { toast('No se pudo anular.'); }
});

$('regBtn').addEventListener('click', async () => {
  if (!last) return;
  try { render(await api('/_local/registration', { mode: last.registration === 'closed' ? 'invite' : 'closed' })); } catch { toast('No se pudo cambiar.'); }
});

$('resetBtn').addEventListener('click', async () => {
  if (!confirm('¿Cambiar de red? Tu cuenta en esta red sigue guardada en este navegador, pero dejarás de estar conectado hasta que vuelvas a elegirla.')) return;
  try { render(await api('/_local/reset', {})); } catch { toast('No se pudo cambiar.'); }
});

$('quitBtn').addEventListener('click', async () => {
  if (last && last.mode === 'host' && !confirm('Si cierras Sombra, tus amigos no podrán enviarse mensajes por tu red hasta que lo vuelvas a abrir. ¿Cerrar?')) return;
  try { await api('/_local/quit', {}); } catch { /* already closing */ }
  document.body.textContent = '';
  const p = document.createElement('p');
  p.className = 'wrap muted';
  p.textContent = 'Sombra se ha cerrado. Puedes cerrar esta pestaña.';
  document.body.append(p);
});

refresh();
setInterval(refresh, 1000);
