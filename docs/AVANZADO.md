# Sombra — guía avanzada (servidor propio)

> Esta guía es para quien quiere desplegar el servidor por su cuenta (VPS, Tor a mano, HTTPS).
> Para el uso normal con la app de escritorio, mira el [README](../README.md).

Sombra es una mensajería de estilo Telegram con **cifrado de extremo a extremo**, pensada
para quien quiere montar **su propio servidor privado** y dejar el menor rastro posible.

- Las cuentas son solo un **nombre de usuario**: no hay teléfono, correo ni contraseña en el
  servidor. Tu identidad es un par de claves generado en tu navegador.
- Los mensajes usan el protocolo de Signal (**X3DH + Double Ratchet**). El servidor solo
  transporta sobres cifrados y no puede leerlos.
- **Remitente sellado** (*sealed sender*): el sobre no dice quién lo envía. El servidor solo
  sabe a quién va dirigido.
- El servidor está diseñado para guardar lo mínimo. No escribe registros (ni IPs, ni nombres,
  ni rutas, ni horas). Borra cada mensaje al confirmarse su entrega, o como muy tarde a los
  14 días.

> Lee [SECURITY.md](../SECURITY.md) antes de confiar en Sombra para algo serio. Allí está, sin
> adornos, lo que Sombra protege, lo que el servidor **sí** puede ver y lo que no se puede
> resolver desde una aplicación web.
> El protocolo exacto está en [SPEC.md](../SPEC.md).

---

## Funciones

- Chats 1:1 y **grupos** de hasta 100 miembros. Los mensajes de grupo se cifran por separado
  para cada miembro (*fan-out* por parejas).
- Texto (hasta 65 536 caracteres) y **archivos** de hasta 100 MiB. Las imágenes se ven dentro
  del chat. Los archivos de más de 3 MiB se envían en fragmentos.
- Confirmaciones de **entregado** y **leído**. Viajan cifradas de extremo a extremo y se
  envían con un retraso aleatorio para no delatar al remitente.
- **Mensajes temporales**: 30 s, 5 min, 1 h, 1 día o 1 semana, por conversación.
- **Borrar para todos**: solo puedes borrar tus propios mensajes.
- **Números de seguridad** de 60 dígitos para verificar a cada contacto en persona. Si la
  clave de un contacto cambia, Sombra muestra un aviso y bloquea el envío hasta que lo
  revises.
- **Almacén local cifrado**: todo lo guardado en el navegador (IndexedDB) se cifra con tu
  frase de acceso (PBKDF2-SHA256 de 600 000 iteraciones + AES-256-GCM). Los nombres de los
  registros también están ocultos.
- **Bloqueo automático** por inactividad (de 1 a 60 min; 10 por defecto), bloqueo al ocultar
  la ventana, bloqueo manual (Ctrl+Mayús+L) y opción para ocultar las vistas previas.
- **Copia de seguridad cifrada** exportable y restaurable.
- **Borrado de pánico**: elimina al instante todos los datos locales. **Eliminar cuenta**:
  borra además la cuenta del servidor.
- Prueba de trabajo (*proof of work*) anti-spam para registrarse y para enviar. No hay
  CAPTCHA ni terceros.
- Interfaz en español, tema oscuro y diseño adaptable a móvil. Sin dependencias de terceros
  en el cliente, sin CDN y sin compilación.

## Requisitos

| Componente | Requisito |
|---|---|
| Servidor | **Node.js 26** (usa `node:sqlite` y WebCrypto con Ed25519/X25519). Única dependencia: `ws`. |
| Cliente | Navegador reciente con X25519 y Ed25519 en WebCrypto, IndexedDB y JavaScript activado: Firefox, Chromium/Chrome, Safari o una versión actual de **Tor Browser**. |
| Contexto seguro | WebCrypto solo funciona en un **contexto seguro**: `https://`, `http://127.0.0.1`/`localhost` o una dirección **`.onion` en Tor Browser**. Con `http://` sobre una IP de red local o un dominio, la aplicación **no funciona**. |

## Instalación y arranque

```sh
git clone <tu-copia-del-repositorio> sombra
cd sombra
npm install          # instala solo 'ws'
npm start            # = node server/index.js
```

Por defecto escucha en `http://127.0.0.1:8443` y guarda los datos en `./data/sombra.db`.
Abre esa dirección en el navegador del mismo equipo para probar.

Lo único que imprime al arrancar es `Sombra listening on http://127.0.0.1:8443`. Si algo
falla, imprime solo `internal error`, sin datos de la petición; con `DEBUG=1` añade también
la traza.

### Variables de entorno

Todas son opcionales. Un valor que no se pueda interpretar o que esté fuera de rango se
**ignora en silencio** y se usa el valor por defecto.

| Variable | Por defecto | Descripción |
|---|---|---|
| `PORT` | `8443` | Puerto TCP (0–65535). |
| `HOST` | `127.0.0.1` | Dirección de escucha. Déjala en `127.0.0.1` detrás de Tor o de un proxy inverso. |
| `DATA_DIR` | `./data` | Carpeta de la base de datos (relativa al directorio actual). Se crea con permisos 0700, y el archivo con 0600. |
| `TLS_CERT` / `TLS_KEY` | *(vacío)* | Rutas a un certificado y una clave PEM. Hay que dar **las dos**: entonces sirve HTTPS (TLS ≥ 1.2) y envía `Strict-Transport-Security`. |
| `POW_REGISTER_BITS` | `22` | Dificultad de la prueba de trabajo para registrarse (0–32 bits). Con 22 bits son unos segundos en un navegador. |
| `POW_SEND_BITS` | `10` | Dificultad de la prueba de trabajo de cada petición de envío (0–32 bits). |
| `MESSAGE_TTL_DAYS` | `14` | Días que un mensaje no entregado espera en el servidor (1–365). La caducidad se redondea **hacia arriba** al siguiente día UTC. Se recomienda **no subirlo de 14**: el cliente descarta a los 14 días las claves de mensajes saltados y a los 30 días las prekeys firmadas antiguas, así que los mensajes más viejos ya no se podrían descifrar. |
| `RATE_LIMIT` | `on` | Límite de peticiones por dirección, guardado en memoria y con la dirección pasada por HMAC. Usa **`off` con Tor** (ver más abajo). |
| `TRUST_PROXY` | `off` | Si está en `on`, usa la **última** entrada de `X-Forwarded-For` como dirección para el límite de peticiones. Actívalo **solo** detrás de un proxy inverso que reescriba esa cabecera. Nunca afecta a los registros, porque Sombra no registra IPs. |
| `QUEUE_MAX_TOTAL_MB` | `8192` | Límite global de bytes en cola (mensajes sin entregar) de todos los usuarios. Al superarlo, los envíos reciben `queue_full`. |
| `STRICT_ENVELOPES` | `on` | Rechaza los blobs que no tienen forma de sobre sellado válido: versión, tamaño mínimo y tamaño de relleno. |
| `DEBUG` | *(vacío)* | Con `1`, muestra la traza de los errores internos. No muestra datos de la petición. |

Límites fijos (no configurables): 100 mensajes y 24 MiB por petición de envío, 12 MiB por
sobre, y 5000 mensajes o 256 MiB en cola por destinatario. La lista completa está en
[SPEC.md §3.9](../SPEC.md).

---

## Despliegue recomendado: servicio *onion* de Tor

Como servicio *onion* (v3), ni el operador ni un observador de la red ven la IP de los
usuarios, y el servidor no necesita dominio, certificado ni puertos abiertos.

1. Arranca Sombra solo en local y **sin límite por dirección**:

   ```sh
   HOST=127.0.0.1 PORT=8443 RATE_LIMIT=off DATA_DIR=/var/lib/sombra npm start
   ```

   **Por qué `RATE_LIMIT=off`:** todas las conexiones que llegan a través de Tor salen del
   propio demonio `tor`, es decir, de `127.0.0.1`. Con el límite activado, todos los usuarios
   compartirían un único contador, y un abusador bloquearía a todos los demás. Con `off`
   siguen activos los topes **globales** (memoria de peticiones, sockets sin autenticar,
   cola). La protección por cliente pasa a hacerla Tor (paso 2). **No** actives
   `TRUST_PROXY`.

2. Añade a `torrc` (normalmente `/etc/tor/torrc`):

   ```
   HiddenServiceDir /var/lib/tor/sombra/
   HiddenServicePort 80 127.0.0.1:8443
   # Defensas contra abuso (tor >= 0.4.8):
   HiddenServicePoWDefensesEnabled 1
   HiddenServiceMaxStreams 100
   HiddenServiceMaxStreamsCloseCircuit 1
   ```

   Reinicia Tor (`systemctl restart tor`). La dirección `.onion` queda en
   `/var/lib/tor/sombra/hostname`. Haz una copia segura de esa carpeta: contiene la clave
   privada del servicio.

3. Los usuarios entran con **Tor Browser** a `http://<dirección>.onion`. Tor Browser trata
   las direcciones `.onion` como contexto seguro, así que WebCrypto funciona sin HTTPS. El
   nivel de seguridad **«El más seguro»** (*Safest*) desactiva JavaScript, y Sombra lo
   necesita.

4. **Importante en Tor Browser:** el navegador borra todos los datos de los sitios al
   cerrarse. Sin copia de seguridad, las claves y los chats se pierden al cerrarlo. Tienes
   dos opciones:
   - tratar la cuenta como **efímera**;
   - **exportar una copia cifrada** antes de cerrar y restaurarla al volver. Lee antes lo que
     implica restaurar copias (sección [Copia de seguridad](#copia-de-seguridad)).

Recomendaciones para el servidor:

- Pon `DATA_DIR` en un disco con **cifrado completo** o en `tmpfs`. SQLite pone a cero lo que
  borra (`secure_delete`), pero el *journal* de cada transacción se desvincula sin
  sobrescribirse y puede quedar en bloques libres del sistema de archivos.
- No añadas nada que registre conexiones.

## Alternativa: HTTPS en Internet

Si no usas Tor, el operador y cualquier observador de la red ven la **IP** de cada usuario.
Ver [SECURITY.md](../SECURITY.md).

**Opción A: TLS directo en Sombra**

```sh
HOST=0.0.0.0 PORT=443 TLS_CERT=/ruta/fullchain.pem TLS_KEY=/ruta/privkey.pem npm start
```

Así no hay proxy intermedio que pueda registrar nada. Para escuchar en el puerto 443 hacen
falta los permisos correspondientes; por ejemplo, `setcap cap_net_bind_service=+ep` sobre el
binario de `node`, o una redirección de puertos.

**Opción B: proxy inverso sin registros**

Sombra escucha en `127.0.0.1:8443` en HTTP plano y el proxy termina TLS. Arráncalo con
`TRUST_PROXY=on` para que el límite de peticiones distinga clientes. En este modo Sombra no
envía HSTS: añádelo en el proxy.

Caddy (`Caddyfile`). Caddy no escribe registros de acceso salvo que pongas la directiva
`log`, y el bloque global de abajo descarta también el resto de registros:

```
{
	log default {
		output discard
	}
}

chat.example.org {
	header {
		Strict-Transport-Security "max-age=63072000; includeSubDomains"
		-Server
	}
	reverse_proxy 127.0.0.1:8443
}
```

nginx:

```nginx
server {
    listen 443 ssl;
    server_name chat.example.org;
    ssl_certificate     /ruta/fullchain.pem;
    ssl_certificate_key /ruta/privkey.pem;

    access_log off;               # sin registro de accesos
    error_log  /dev/null crit;    # sin registro de errores con IPs
    server_tokens off;
    client_max_body_size 25m;     # /api/send acepta hasta 24 MiB

    add_header Strict-Transport-Security "max-age=63072000; includeSubDomains" always;

    location /ws {
        proxy_pass http://127.0.0.1:8443;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $remote_addr;
        proxy_read_timeout 120s;
    }
    location / {
        proxy_pass http://127.0.0.1:8443;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $remote_addr;
        proxy_request_buffering off;
    }
}
```

Usa un proxy que controles tú. Una CDN o un proxy de terceros vería IPs y tiempos, y podría
alterar el JavaScript que se sirve.

---

## Cómo se usa

### Crear la cuenta

1. Abre la dirección de tu servidor y elige **Crear cuenta**.
2. Elige un **nombre de usuario**: de 3 a 32 caracteres, solo `a–z`, `0–9` y `_`. Es lo
   único que el servidor sabe de ti.
3. Elige una **frase de acceso** de al menos 10 caracteres. Es preferible una frase larga de
   5 palabras o más al azar. Protege el almacén local. **Nunca sale del dispositivo y no se
   puede recuperar.**
4. El navegador genera tus claves y resuelve la prueba de trabajo (unos segundos), y la
   cuenta queda registrada.

### Compartir tu nombre de usuario

Sombra no tiene agenda ni búsqueda de contactos. Pasa tu nombre de usuario **por otro canal**
(en persona, en papel...). Para escribir a alguien, pulsa **Nuevo chat** y escribe su nombre
de usuario.

### Verificar los números de seguridad

La primera vez que hablas con alguien, Sombra confía en las claves que entrega el servidor
(*trust on first use*). Un servidor malicioso podría sustituirlas en ese primer contacto.
Para descartarlo:

1. Abre el chat y pulsa el escudo (**Número de seguridad**).
2. Comparad los **60 dígitos** (12 grupos de 5) **en persona** o por un canal en el que os
   reconozcáis, como una llamada de voz.
3. Si coinciden, pulsa **Marcar como verificado**.

Si más adelante la clave de un contacto cambia (ha reinstalado, o alguien se hace pasar por
él), verás el aviso *«El número de seguridad de @usuario ha cambiado»*, también en los grupos
que compartís, y el envío queda bloqueado. **Vuelve a comparar los números** antes de pulsar
**Aceptar**.

### Mensajes temporales

En el menú del chat, elige el temporizador: desactivado, 30 s, 5 min, 1 h, 1 día o 1 semana.
Se aplica a los mensajes enviados desde ese momento. Cada lado los borra pasado el plazo: el
remitente lo cuenta desde el envío y el destinatario desde la recepción.

Limitaciones: el borrado solo se ejecuta mientras la aplicación está **desbloqueada**. Además,
nada impide que el otro haga capturas de pantalla o fotos.

### Copia de seguridad

- **Ajustes → Exportar copia cifrada** descarga un archivo `.json` con todos los registros ya
  cifrados con tu frase de acceso. Sin la frase no sirve de nada; con ella, da acceso total a
  la cuenta.
- Para restaurar, ve a la pantalla inicial, pestaña **Restaurar copia**, y desbloquea con la
  frase de esa copia.
- Al restaurar, Sombra **no reutiliza** las sesiones cifradas de la copia para enviar: con
  cada contacto abre una sesión nueva y rota la prekey firmada. Así evita reutilizar claves
  de mensaje.
- **No tengas la misma cuenta abierta en dos dispositivos o pestañas a la vez.** Si otra
  instancia se conecta, la primera se bloquea sola. Los mensajes enviados después de la copia
  no estarán en ella.

### Bloqueo, borrado de pánico y eliminar cuenta

- **Bloquear** (candado, Ctrl+Mayús+L o por inactividad) cierra la conexión y borra de la
  memoria las claves y los mensajes descifrados.
- **Borrado de pánico** (en Ajustes o en la pantalla de desbloqueo) elimina **al instante**
  todos los datos de Sombra de este navegador, sin conectar con el servidor. La cuenta del
  servidor sigue existiendo, pero queda inservible sin las claves.
- **Eliminar cuenta** borra del servidor tu usuario, tus claves públicas y tus mensajes
  pendientes, y después hace el borrado local.

---

## Pruebas

```sh
npm test             # = node --test test/
```

Las pruebas usan el *test runner* integrado de Node 26. Arrancan servidores reales en un
puerto aleatorio, con una carpeta de datos temporal y una prueba de trabajo de baja
dificultad. Cubren:

- las primitivas criptográficas y el *ratchet*;
- el servidor (API, WebSocket, cabeceras, validación, límites);
- el almacén cifrado;
- la integración cliente-servidor de extremo a extremo;
- las regresiones de las correcciones de la auditoría: `test/fix-*.test.js`.

## Estructura

```
server/   servidor HTTP(S) + WebSocket + SQLite (index.js, db.js, pow.js, validate.js, config.js)
public/   cliente web: index.html, css/, js/crypto (criptografía), js/core (protocolo), js/ui (interfaz)
test/     pruebas (node --test)
SPEC.md   especificación técnica del protocolo
SECURITY.md  modelo de amenazas, metadatos visibles, limitaciones y estado de la auditoría
```
