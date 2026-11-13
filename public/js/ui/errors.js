// Sombra UI — map client/server error codes to Spanish user-facing text.
// Never echoes arbitrary error text verbatim when it might contain internal details;
// unknown errors get a generic message.

const MESSAGES = [
  ['username_taken', 'Ese nombre de usuario ya está en uso. Prueba con otro.'],
  ['identity_taken', 'Estas claves de identidad ya están registradas para otro usuario. Vuelve a intentarlo.'],
  ['bad_username', 'Nombre de usuario no válido: de 3 a 32 letras minúsculas, números o guiones bajos.'],
  ['account_exists', 'Ya hay una cuenta en este dispositivo.'],
  ['open_elsewhere', 'Sombra ya está abierto en otra pestaña o ventana. Ciérrala o bloquéala y vuelve a intentarlo.'],
  ['replaced', 'Esta cuenta se abrió en otra pestaña o dispositivo. Esta sesión se ha bloqueado.'],
  ['key_changed', 'El número de seguridad de un contacto ha cambiado. Compruébalo y acéptalo antes de enviar.'],
  ['cannot_message_self', 'No puedes enviarte mensajes a ti mismo.'],
  ['payload_too_large', 'El mensaje es demasiado grande para el servidor.'],
  ['busy', 'El servidor está ocupado. Inténtalo de nuevo en unos segundos.'],
  ['forbidden', 'El servidor rechazó la solicitud.'],
  ['bad passphrase', 'Frase de acceso incorrecta.'],
  ['bad_passphrase', 'Frase de acceso incorrecta.'],
  ['user_not_found', 'No existe ningún usuario con ese nombre.'],
  ['not_found', 'No existe ningún usuario con ese nombre.'],
  ['bad_pow', 'La prueba de trabajo no fue aceptada. Vuelve a intentarlo.'],
  ['queue_full', 'El buzón del destinatario está lleno. Inténtalo más tarde.'],
  ['rate_limited', 'Demasiadas solicitudes. Espera un momento y vuelve a intentarlo.'],
  ['too_many', 'Demasiadas solicitudes. Espera un momento y vuelve a intentarlo.'],
  ['bad_request', 'Solicitud no válida.'],
  ['bad bundle signature', 'Las claves del contacto no tienen una firma válida. No se ha enviado nada.'],
  ['auth_failed', 'El servidor rechazó la autenticación de esta cuenta.'],
  ['file_too_large', 'El archivo supera el máximo de 8 MiB.'],
  ['too large', 'El archivo supera el máximo de 8 MiB.'],
  ['not_admin', 'Solo el administrador del grupo puede hacer esto.'],
  ['not_member', 'No eres miembro de este grupo.'],
  ['locked', 'La aplicación está bloqueada.'],
  ['no account', 'No hay ninguna cuenta en este dispositivo.'],
  ['no_account', 'No hay ninguna cuenta en este dispositivo.'],
  ['bad backup', 'El archivo de copia de seguridad no es válido.'],
  ['bad_backup', 'El archivo de copia de seguridad no es válido.'],
  ['invalid backup', 'El archivo de copia de seguridad no es válido.'],
  ['failed to fetch', 'No se pudo conectar con el servidor.'],
  ['networkerror', 'No se pudo conectar con el servidor.'],
  ['network', 'No se pudo conectar con el servidor.'],
  ['load failed', 'No se pudo conectar con el servidor.'],
  ['quota', 'No queda espacio de almacenamiento en este dispositivo.'],
];

/** An error whose message is already user-facing Spanish text (shown verbatim). */
export class UiError extends Error {}

/** Spanish text for an Error / string / {error} value. */
export function errorText(err, fallback = 'Algo salió mal. Inténtalo de nuevo.') {
  if (err instanceof UiError) return err.message;
  let raw = '';
  if (typeof err === 'string') raw = err;
  else if (err && typeof err.message === 'string') raw = err.message;
  else if (err && typeof err.error === 'string') raw = err.error;
  if (err && typeof err.code === 'string') raw = `${raw} ${err.code}`;
  const lower = raw.toLowerCase();
  for (const [needle, text] of MESSAGES) {
    if (lower.includes(needle)) return text;
  }
  if (err && err.name === 'QuotaExceededError') return 'No queda espacio de almacenamiento en este dispositivo.';
  return fallback;
}

/** Extract a username mentioned in an error (e.g. "user_not_found: bob"), if any. */
export function errorUsername(err) {
  const raw = err && typeof err.message === 'string' ? err.message : '';
  const m = /user_not_found[:\s]+@?([a-z0-9_]{3,32})/.exec(raw);
  return m ? m[1] : null;
}
