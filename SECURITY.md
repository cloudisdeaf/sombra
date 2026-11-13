# Seguridad de Sombra

Este documento explica:

- qué protege Sombra y frente a quién;
- qué diseño criptográfico usa;
- qué metadatos **sigue viendo el servidor**;
- qué limitaciones no se pueden resolver desde una aplicación web;
- en qué estado están los hallazgos de la auditoría.

Está escrito para que decidas con datos, no para tranquilizarte. El detalle del protocolo
está en [SPEC.md](SPEC.md).

---

## 1. Modelo de amenazas

### Qué protege

| Propiedad | Alcance |
|---|---|
| **Confidencialidad del contenido** | El texto, los archivos (y sus nombres), las confirmaciones, los borrados, los temporizadores y los datos de los grupos (nombre, miembros, administrador) viajan cifrados de extremo a extremo. El servidor nunca tiene las claves. |
| **Remitente oculto al servidor** | Cada sobre se cifra para la clave de identidad del destinatario y el remitente va **dentro**. El envío (`POST /api/send`) no está autenticado y va por un camino distinto del WebSocket con el que recibes. Ver los límites en §3. |
| **Autenticación del remitente** | La capa *ratchet* liga en sus datos asociados (AD v2) las claves de identidad **y los nombres de usuario** de las dos partes. Un mensaje no se acepta si el `from` sellado no coincide con la sesión. |
| **Secreto hacia delante** (*forward secrecy*) | Cada mensaje usa una clave nueva (Double Ratchet). Robar el estado actual no descifra mensajes ya recibidos y borrados. Las claves de mensajes saltados caducan a los 14 días. |
| **Seguridad post-compromiso** | Tras un robo **pasivo** del estado de una sesión, el siguiente intercambio de claves Diffie-Hellman (un ida y vuelta de mensajes) vuelve a dejar fuera al atacante. Si envías 500 mensajes seguidos sin recibir respuesta, la sesión se renueva con un X3DH nuevo. |
| **Cifrado en reposo** | Todo lo que hay en IndexedDB va cifrado con AES-256-GCM, con una clave derivada de tu frase de acceso. Los nombres de los registros son HMAC, así que no se ve qué chats existen. Solo están en claro la sal, el número de iteraciones y un verificador. |
| **Servidor mínimo** | No hay registros, ni cookies, ni analítica, ni peticiones a terceros. Las claves de cuenta son públicas. Los mensajes son sobres opacos que se borran al confirmarse la entrega o al caducar, y solo llevan una caducidad redondeada al día. |

### Adversarios considerados

- **Observador de red** (tu proveedor, una Wi-Fi pública, un Estado). Con HTTPS no ve el
  contenido, pero sí tu IP, la del servidor, cuándo te conectas y el volumen de tráfico. Con
  Tor ve que usas Tor, pero no con quién hablas.
- **Servidor malicioso o comprometido**: el operador, alguien que lo ha atacado o quien lo
  confisque.
  - **No puede** leer mensajes ni falsificarlos en nombre de un contacto ya establecido.
  - **Sí puede**:
    - ver los metadatos de §3;
    - retener, retrasar o descartar mensajes;
    - impedir el servicio;
    - **suplantar claves en el primer contacto** si no verificáis los números de seguridad;
    - **servir JavaScript modificado** (§4.1). Esto es lo más grave.
- **Contactos maliciosos**: otro usuario o un miembro de un grupo. No pueden suplantar a
  otros miembros, ni sobrescribir sus archivos, ni secuestrar un grupo, ni llenar sin límite
  tu almacenamiento. Las correcciones están en §5.
- **Incautación del dispositivo**:
  - **Bloqueado**: el atacante tiene que adivinar tu frase de acceso. El ataque es
    **offline**, contra PBKDF2 de 600 000 iteraciones: una frase débil cae.
  - **Desbloqueado** (o con malware): lo ve todo. Ninguna aplicación lo evita.

### Fuera de alcance

Sombra no oculta **que** usas Sombra. Tampoco resiste a un dispositivo comprometido (malware,
teclado espía, extensiones del navegador) ni al análisis de tráfico de un adversario global.
Y no protege de lo que el otro haga con tus mensajes.

---

## 2. Diseño criptográfico (resumen)

Todo se hace con WebCrypto en el navegador. No hay código criptográfico de terceros.

| Pieza | Primitivas |
|---|---|
| Identidad | Ed25519 (`IK_sig`, para firmar) + X25519 (`IK_dh`). `ik_dh_sig = Ed25519(IK_sig, "SOMBRA-IKDH-v1" ‖ ik_dh)`. |
| Registro (v2) | `reg_sig = Ed25519(IK_sig, "SOMBRA-REG-v1" ‖ u8(len) ‖ username ‖ ik_dh)` demuestra que quien registra tiene las claves. El servidor rechaza claves de identidad ya registradas (`409 identity_taken`). |
| Prekeys | SPK X25519 firmada (`"SOMBRA-SPK-v1" ‖ u32be(id) ‖ pub`), que se rota cada 7 días; las antiguas se guardan 30 días. Lotes de 100 OPK X25519 de un solo uso. |
| Acuerdo inicial | X3DH: `SK = HKDF-SHA256(0xFF×32 ‖ DH1 ‖ DH2 ‖ DH3 [‖ DH4], sal 0×32, "SOMBRA-X3DH-v1")`. |
| Datos asociados (v2) | `AD = "SOMBRA-AD-v2" ‖ IKa_sig ‖ IKa_dh ‖ IKb_sig ‖ IKb_dh ‖ u8(len) ‖ userA ‖ u8(len) ‖ userB`. Evita el *unknown-key-share*. |
| Mensajes | Double Ratchet de Signal sin cifrado de cabeceras: `KDF_RK` = HKDF-SHA256, `KDF_CK` = HMAC-SHA256 (0x01/0x02), clave+IV = HKDF(mk, "SOMBRA-MK-v1", 44), AES-256-GCM con `aad = AD ‖ cabecera`. Máximo 1000 claves saltadas por paso y 2000 guardadas; caducan a los 14 días. Se renueva con X3DH tras 500 envíos sin respuesta. |
| Remitente sellado | Una X25519 efímera por sobre contra `IK_dh` del destinatario. Clave e IV con HKDF-SHA256 ("SOMBRA-SEALED-v1"). AES-256-GCM sobre `pad({from, inner})`. |
| Relleno | `u32be(len) ‖ datos ‖ ceros`, redondeado a 256 B, 512 B... hasta 16 KiB, luego a la siguiente potencia de 2 hasta 1 MiB, y luego a múltiplos de 1 MiB. |
| Números de seguridad | 5200 iteraciones de SHA-512 sobre `"SOMBRA-FP-v1" ‖ ik_sig ‖ ik_dh ‖ username`. 30 dígitos por parte; 60 en total. |
| Almacén local | PBKDF2-SHA256 (600 000 iteraciones, sal de 16 B) → HKDF → `encKey` (AES-256-GCM, AAD = nombre del registro) y `macKey` (HMAC-SHA256 de los nombres de registro). |
| Grupos (v2) | Los mensajes de grupo se cifran por parejas con cada miembro. `gid = SHA-256("SOMBRA-GID-v1" ‖ u8(len) ‖ creador ‖ sal16)[0..16)`: el identificador queda ligado al creador. |
| Anti-spam | Prueba de trabajo SHA-256 con reto HMAC del servidor de un solo uso que caduca a los 5 min. 22 bits para registrarse y 10 bits por envío. |
| Autenticación del WebSocket | `Ed25519(IK_sig, "SOMBRA-AUTH-v1" ‖ nonce32)`. Un único intento por conexión. |

---

## 3. Metadatos que el servidor **sí** puede ver

El servidor no **guarda** casi nada, pero en cada momento **ve** lo siguiente. Un operador
malicioso puede modificar el código para registrarlo.

1. **El destinatario de cada mensaje.** Cada `POST /api/send` lleva en claro el `to`
   (nombre de usuario). También ve cuántos mensajes recibe cada cuenta y cuándo.
2. **La IP de cada petición**, salvo con Tor. Incluye el WebSocket autenticado, de modo que
   sabe que la IP X es la cuenta `alicia`.
3. **Cuándo estás en línea.** El WebSocket está autenticado con tu nombre: conexión,
   desconexión y confirmaciones (ACK) de entrega.
4. **Correlación temporal.** Si un sobre se entrega a `bea` y poco después llega un envío
   anónimo dirigido a `alicia`, desde la misma IP o conexión, es probable que `bea` responda a
   `alicia`.
   - Mitigaciones actuales:
     - las confirmaciones de entrega y lectura se agrupan y se envían con un **retraso
       aleatorio de 2 a 30 s** (desactivables en Ajustes);
     - la comprobación de identidad de un remitente nuevo se hace **1–10 s después** y
       fuera del camino de recepción;
     - cada sobre de un mensaje de grupo va en **su propia petición**, en orden aleatorio y
       con hasta 250 ms de separación.
   - Riesgo residual: son retrasos cortos, así que la correlación estadística sigue siendo
     posible.
   - La API del cliente (`setPrivacyOptions`) permite desactivar las confirmaciones o
     alargar los retrasos, pero **la interfaz aún no lo ofrece**.
5. **Tamaño aproximado.** Se ve el *bucket* de relleno: un texto corto (≤ 256 B) se distingue
   de una imagen. Un archivo grande se ve como varios sobres de unos 9 MiB. Un mensaje de
   grupo produce una ráfaga de N envíos casi simultáneos, lo que deja ver el tamaño del grupo
   aproximado.
6. **Consultas de claves.**
   - `GET /api/identity/<usuario>` (al abrir un chat o comprobar un remitente) y
     `GET /api/bundle/<usuario>` (al iniciar sesión cifrada) muestran **a quién consultas**.
   - Cualquiera, sin cuenta, puede comprobar si un nombre de usuario existe.
   - Los identificadores de las prekeys son **secuenciales**. Revelan aproximadamente cuántas
     sesiones se han iniciado contigo y la antigüedad de la cuenta.
   - La reposición de OPK al conectarse puede delatar cuándo estás en línea. Está limitado a
     50 OPK consumibles por destinatario y hora, pero no eliminado.
7. **La conexión HTTP reutilizada** (*keep-alive*, 5 s) puede ligar entre sí varios envíos de
   un mismo cliente.
8. **En disco**: las claves públicas, los OPK pendientes y los sobres en cola con su día de
   caducidad. Desde la v2 no hay orden de inserción reconstruible. La cola cifra el remitente
   solo con la clave de identidad **a largo plazo** del destinatario: si alguien guarda los
   sobres y años después roba esa clave, descubre **quién** los envió, pero no su contenido.

**Recomendación:** si los metadatos importan, despliega el servidor como **servicio onion** y
usa **Tor Browser** (ver README). Así el servidor no ve IPs, y la correlación temporal solo
liga cuentas entre sí, no a personas.

---

## 4. Limitaciones conocidas

1. **El código se entrega por web.** El navegador descarga el JavaScript del propio servidor
   en cada visita (`Cache-Control: no-cache`). Un operador malicioso, o quien comprometa el
   servidor, puede servir una versión con puerta trasera que robe claves y mensajes. CSP,
   SRI y el cifrado de extremo a extremo no protegen de esto.
   - **Mitigación:** autoaloja Sombra en una máquina que controles. Si usas un servidor
     ajeno, compara los archivos servidos con los del repositorio, por ejemplo
     `curl -s https://servidor/js/core/client.js | sha256sum` frente a
     `sha256sum public/js/core/client.js`.
   - No hay fijación de versiones (*pinning*) ni cliente instalable independiente del
     servidor.
2. **Un solo dispositivo.** No hay multidispositivo. Abrir la cuenta en otra pestaña o equipo
   bloquea la primera instancia (cierre 4005).
   - El cerrojo exclusivo entre pestañas (Web Locks) está implementado en el núcleo, pero el
     almacén de IndexedDB todavía no lo activa. Queda un margen entre que la segunda pestaña
     desbloquea y que el servidor desconecta a la primera.
   - **No uses la misma cuenta en dos sitios a la vez.**
3. **Confianza en el primer uso** (TOFU). Hasta que verifiques el número de seguridad en
   persona, un servidor malicioso puede sustituir las claves en el **primer** contacto y hacer
   de intermediario. Después, cualquier cambio de clave muestra un aviso y bloquea el envío.
   Aun así, los mensajes que lleguen con la identidad nueva **se muestran** antes de que la
   aceptes.
4. **No hay Argon2.** WebCrypto no ofrece funciones de derivación resistentes a memoria. Se
   usa PBKDF2-SHA256 con 600 000 iteraciones, que es barato de atacar con GPU. Usa una
   **frase larga**: 5 o más palabras al azar. No se puede cambiar la frase de acceso de un
   almacén existente.
5. **Forense en el navegador.**
   - Mientras la aplicación está desbloqueada, los mensajes descifrados y las claves están en
     la memoria del proceso; pueden acabar en el archivo de intercambio o de hibernación, o en
     volcados de memoria.
   - JavaScript no garantiza el borrado de memoria. Sombra pone a cero los búferes que puede,
     pero no las cadenas de texto.
   - IndexedDB (LevelDB o SQLite según el navegador) puede conservar versiones antiguas de
     los registros hasta que se compacta. Siguen cifradas, **con la misma clave**: con tu
     frase, un análisis forense puede recuperar mensajes temporales ya «borrados».
6. **Remanencia en SSD.** Borrar en SSD, eMMC o sistemas de archivos con copia en escritura
   no sobrescribe los datos físicos. Usa **cifrado de disco completo** en tus dispositivos y
   en el servidor (`DATA_DIR`).
7. **Capturas de pantalla.** Los mensajes temporales no impiden capturas, fotos ni copias del
   otro lado. Además, solo se borran mientras la aplicación del receptor está desbloqueada.
8. **Análisis de tráfico sin Tor.** Sin Tor, el operador y la red ven tu IP y tus horarios
   (§3). Con Tor, un adversario capaz de observar a la vez tu entrada a la red Tor y el
   servidor puede correlacionar tiempos.
9. **Tor Browser borra los datos al cerrarse.** O mantienes la cuenta solo durante la sesión,
   o exportas una copia cada vez. Al restaurar una copia, cada sesión se renueva. Los OPK
   subidos después de la copia no se pueden usar, y los primeros mensajes que alguien te
   envíe con ellos se perderán.
10. **Disponibilidad.** Un servidor malicioso puede descartar mensajes sin que lo notes: el
    mensaje quedará como «enviado» y nunca como «entregado». Un atacante con muchas pruebas
    de trabajo puede llenar el buzón de un usuario desconectado (`queue_full`, hasta 5000
    mensajes o 256 MiB por destinatario).
11. **Sin cifrado de cabeceras en el ratchet.** Esto no expone nada al servidor, porque las
    cabeceras viajan dentro del sobre sellado. Pero quien consiga la clave de identidad del
    destinatario y haya guardado los sobres ve los contadores de mensajes.

### App de escritorio (`Sombra-Setup.exe`)

- **El código lo ejecuta cada uno desde su propia instalación.** El lanzador sirve la app
  desde `127.0.0.1:47321` y solo reenvía `/api` y `/ws` a la red. Quien aloja la red no
  puede mandarte JavaScript modificado; esto cierra, para quien usa el `.exe`, la
  limitación 1. A cambio tienes que confiar en el propio `.exe`: compara su SHA-256 con el
  publicado en la *release*. No está firmado con un certificado de código.
- **Las peticiones reenviadas no llevan cabeceras del navegador**: ni User-Agent, ni
  idioma, ni Origin, ni Referer, ni cookies. Al anfitrión solo le llega lo mismo que vería
  un cliente genérico.
- **Quien crea la red es el servidor**, así que ve los metadatos de §3: destinatarios,
  horas, tamaños por tramos y presencia. No ve IPs, porque todo llega por Tor. Por eso
  mismo el limitador por dirección está apagado y el freno contra el spam es la prueba de
  trabajo.
- **La dirección `.onion` es la llave de entrada**: quien la conozca puede registrarse en
  tu red. Compártela solo con tus amigos. Su clave privada está en
  `%LOCALAPPDATA%\Sombra\onion-service`. Quien la robe puede hacerse pasar por la red,
  pero no leer mensajes ni suplantar a nadie (cifrado de extremo a extremo y números de
  seguridad).
- **El panel local rechaza peticiones de otras webs**: comprueba Host para evitar
  *DNS rebinding*, y Origin y `Sec-Fetch-Site` para evitar CSRF. No protege frente a otros
  programas maliciosos del mismo ordenador, que quedan fuera del modelo de amenazas.
- **Tu cuenta vive en el navegador**, ligada a `http://127.0.0.1:47321`. Si cambias de
  navegador o borras sus datos, restaura tu copia de seguridad.
- Las pruebas automáticas cubren el lanzador con un Tor simulado (SOCKS5 falso). Tor
  real (`tor.exe`) se ejecuta tal cual lo publica The Tor Project.

---

## 5. Auditoría y estado de los hallazgos

En noviembre de 2026 se hizo una auditoría interna: criptografía, cliente, servidor y prueba
de navegador de extremo a extremo, con pruebas de concepto reales.
Tras las correcciones, una segunda revisión adversarial del código final encontró los
hallazgos APP-*, VC-*, C2, C3, UI-1 y SRV-12, también corregidos, cada uno con una prueba
de regresión que falla con el código anterior.

El estado de cada hallazgo se ha determinado leyendo el código actual y sus pruebas:

- **Corregido (test)**: arreglado y con prueba de regresión.
- **Corregido (código)**: arreglado en el código, sin prueba específica.
- **Mitigado**: reducido, con un riesgo residual documentado.
- **Parcial**: solo una parte del arreglo está hecha.
- **Pendiente de verificación**: el cambio está en curso o no se ha podido confirmar.

| Id | Severidad | Descripción | Estado |
|---|---|---|---|
| SRV-01 | Crítica | Las confirmaciones de entrega inmediatas permitían al servidor ligar el WebSocket autenticado del receptor con su envío anónimo, y así descubrir al remitente sellado. | Mitigado (test): confirmaciones agrupadas con retraso aleatorio de 2 a 30 s, cada una en su propia petición, guardadas cifradas para que un bloqueo no las pierda (C2) y desactivables en Ajustes › Seguridad (C3). Queda correlación temporal residual (§3). |
| SRV-02 | Crítica | El *fan-out* de grupo en un solo `/api/send` revelaba la lista de miembros, y el remitente era el miembro que faltaba. | Mitigado: una petición por destinatario, en orden aleatorio y con hasta 250 ms de separación. Queda la ráfaga desde la misma IP sin Tor. |
| SRV-03 | Alta | Cuerpos de hasta 24 MiB se guardaban en memoria antes de comprobar la prueba de trabajo (DoS de memoria sin autenticar). | Corregido (test): presupuesto global de 128 MiB, corte tras 30 s sin datos, máximo 8 cuerpos simultáneos por dirección, límite de tokens JSON y prueba de trabajo antes de decodificar los blobs. |
| SRV-04 | Alta | Se podía llenar la cola de un usuario desconectado con muy poco coste; no había cuota global. | Corregido (test): la prueba de trabajo de envío crece con el número de mensajes y los bytes de cada petición, cuota global con reserva justa por destinatario (APP-2), sobres estrictos y registro de 22 bits. Residual: llenar el buzón de una víctima concreta sigue costando solo prueba de trabajo. |
| SRV-05 | Alta | El limitador de peticiones fallaba cerrado al llenarse y agrupaba mal IPv6 /64. | Corregido (test): normalización IPv6, agregado /48, y desaloja la entrada más antigua en vez de bloquear. |
| SRV-06 | Media | `/api/bundle` sin coste: vaciaba los OPK, servía de oráculo de presencia y los identificadores secuenciales revelaban el historial. | Mitigado (test): presupuesto de OPK por destinatario y hora (al agotarse, `opk:null` sin consumir) e identificadores de prekey aleatorios de 32 bits. Residual: `/api/bundle` no exige prueba de trabajo. |
| SRV-07 | Media | Los `rowid` de la base de datos revelaban el orden global de llegada, los lotes y el orden de registro. | Corregido (test): tablas `WITHOUT ROWID` y `rowid` de cola en paseo aleatorio por destinatario. El residuo del *journal* está documentado (usar cifrado de disco o tmpfs). |
| SRV-08 | Media | Los sockets sin autenticar podían ocupar todas las plazas. | Corregido (test) con `RATE_LIMIT=on`: máximo 5 por dirección, 1000 en total desalojando el más antiguo, y 5 s para autenticarse. Con Tor solo aplican los topes globales: usa las defensas de Tor (README). |
| SRV-09 | Media | Un lector lento autenticado podía retener unos 24 MiB de memoria por conexión. | Corregido (test): contrapresión de 2 MiB por socket y 256 MiB en total, y se termina la conexión si se atasca 45 s. |
| SRV-10 | Baja | Sin comprobación de origen: páginas de terceros podían consumir OPK y plazas desde los navegadores de sus visitantes. | Corregido (test): `Sec-Fetch-Site` y `Origin` se comprueban en `/api/*` y en `/ws`. |
| SRV-11 | Info | Faltaban README y SECURITY con instrucciones de Tor y metadatos. | Corregido: este documento y el README. |
| CL-1 | Crítica | La consulta de identidad y la confirmación inmediata desde el receptor delataban al remitente sellado. | Mitigado (test): la identidad se comprueba más tarde (1–10 s) y fuera del camino de recepción, y las confirmaciones se envían con retraso (SRV-01). |
| CL-2 | Alta | Un miembro del grupo podía sobrescribir o borrar el archivo de otro reutilizando su `fid`. | Corregido (código): eliminación de duplicados por (remitente, id), id local nuevo si hay colisión y registros de archivo únicos. |
| CL-3 | Alta | Restaurar una copia rebobinaba el *ratchet*: se reutilizaban clave e IV de AES-GCM. | Corregido (código): «época» de cuenta; las sesiones restauradas nunca cifran y se inicia X3DH nuevo. Residual: los OPK posteriores a la copia se pierden. |
| CL-4 | Alta | Un miembro sin privilegios podía «crear» el gid de otro grupo en la vista de una víctima (secuestro). | Corregido (código): el gid está ligado al creador (hash con sal) y se verifica; solo el creador puede añadir miembros. |
| CL-5 | Media | Un servidor malicioso podía inyectar mensajes en nombre de un contacto verificado. | Corregido (test): si cambia la identidad de un contacto VERIFICADO, todo lo autenticado por la identidad nueva queda retenido hasta que el usuario acepte el número de seguridad; lo que llega por la sesión de la identidad verificada se sigue mostrando (VC-2). |
| CL-6 | Media | El usuario `__proto__` rompía la fijación de identidad y contaminaba `Object.prototype`. | Corregido (código): diccionarios sin prototipo y búsquedas con `hasOwnProperty`. |
| CL-7 | Media | Un desconocido podía llenar el almacenamiento de la víctima sin límite (fragmentos, grupos). | Parcial: cuotas de 2 archivos en curso por remitente, 32 MiB de fragmentos, 32 grupos por creador y 512 en total; cuarentena acotada de remitentes nuevos; se descarta el contenido de grupos borrados. El historial sigue siendo un único registro por conversación. |
| CL-8 | Media | Los envíos de grupo revelaban miembros y remitente (lote único). | Mitigado: igual que SRV-02. |
| CL-9 | Baja | Un `lock()` durante `unlock()` se ignoraba. | Corregido (código): se comprueba la generación tras cada `await`. |
| CL-10 | Baja | Guardar el *ratchet* antes que el mensaje podía perder el mensaje. | Corregido (código): primero se aplica el mensaje y después se guarda el estado; los duplicados se descartan. |
| CL-11 | Baja | La eliminación de duplicados por id sin remitente permitía suprimir mensajes ajenos en grupos. | Corregido (código): clave `remitente\|id`. |
| CL-12 | Baja | `acceptKeyChange` fijaba lo que devolviera el servidor en ese instante (TOCTOU). | Corregido (código): fija la identidad mostrada; si el servidor cambia otra vez, es un nuevo aviso. |
| CRYPTO-1 | Alta | Cabeceras falsificadas obligaban a derivar miles de claves antes de autenticar, bloqueando el cliente. | Mitigado (test): coste estimado antes de descifrar (máx. 1000 saltos; 100 en sesiones previas y en sesiones nuevas), HMAC síncrono en el avance de cadena (VC-4, unos 15 ms en el peor caso) y la cola de entrada cede el turno entre mensajes. No hay presupuesto de fallos por remitente. |
| CRYPTO-2 | Media | Bloqueo permanente de la sesión tras perderse más de 1000 mensajes. | Corregido (test): en una cadena abandonada se guardan como mucho 1000 claves y el *ratchet* continúa; se renueva con X3DH tras 500 envíos. |
| CRYPTO-3 | Media | Dos pestañas sobre el mismo IndexedDB reutilizaban clave e IV y perdían mensajes. | Corregido (test + e2e): Web Lock exclusivo `sombra-account` mientras la cuenta está desbloqueada (`open_elsewhere` en la segunda pestaña) y la instancia sustituida (4005) se bloquea sola. |
| CRYPTO-4 | Media | Restaurar una copia dejaba todas las sesiones muertas o reutilizando claves. | Corregido (código): igual que CL-3, con rotación inmediata de la SPK. |
| CRYPTO-5 | Media | El cambio de identidad (des-verificar, borrar sesiones) se aplicaba antes de autenticar el mensaje. | Corregido (código): nada cambia hasta que X3DH y AEAD tienen éxito y el servidor lo confirma. |
| CRYPTO-6 | Baja | Los nombres `__proto__` y `constructor` colisionaban con `Object.prototype`. | Corregido (código): igual que CL-6. |
| CRYPTO-7 | Baja | *Unknown-key-share*: los nombres no estaban en el AD y el servidor aceptaba claves copiadas. | Corregido (test): AD v2 con ambos nombres; el registro exige `reg_sig` (prueba de posesión ligada al nombre) y el servidor rechaza claves de identidad ya usadas (`identity_taken`). |
| CRYPTO-8 | Baja | Las claves saltadas y las sesiones previas se guardaban indefinidamente. | Corregido (test): las claves saltadas caducan a los 14 días; barrido al desbloquear y cada hora sobre todas las sesiones; las sesiones previas sin uso en 30 días se eliminan. |
| CRYPTO-9 | Info | Codificaciones X25519 no canónicas burlaban la protección contra repetición basada en `ek`. | Corregido (código): solo se aceptan codificaciones canónicas para `ek`, `ik_dh` y la `dh` de la cabecera. |
| FIX-1 | Info | Error de JavaScript no capturado al bloquear o al hacer borrado de pánico. | Corregido (e2e). |
| FIX-2 | Info | Los nombres de grupo admitían caracteres de control bidireccional (suplantación tipo RLO, U+202E). | Corregido (e2e): limpieza en la interfaz. |
| FIX-3 | Info | En móvil, un nombre largo sacaba de la pantalla los botones de bloquear y ajustes. | Corregido (e2e). |
| BUG-1 | Baja | Intro se ignoraba sin avisar mientras se enviaba el mensaje anterior. | Corregido (test): cola de envío ordenada de hasta 20 mensajes. |
| BUG-2 | Baja | El núcleo no limpiaba los caracteres de control y bidi de los nombres de grupo. | Corregido (código): `cleanGroupName` y `sanitizeFileName` en el núcleo. |
| BUG-3 | Info | La prueba de trabajo de registro de 18 bits era demasiado barata. | Corregido (test): 22 bits por defecto. |
| BUG-4 | Info | Detalles visuales: separador de día, subtítulo en móvil. | Corregido (test). |
| APP-1 | Alta | El reparto de grupo con una petición por miembro (SRV-02) chocaba con los límites por dirección: en un grupo de 100 fallaban los mensajes tras unos 11. | Corregido (test): 4 envíos simultáneos como máximo, con reintentos y espera exponencial ante `rate_limited`/`busy`; límites por dirección ampliados (la prueba de trabajo es el control de coste real). |
| APP-2 | Media | La cuota global de cola era de destino compartido: llenarla con cuentas sumidero bloqueaba la entrega a todos los usuarios desconectados. | Corregido (test): con la cuota global llena, un destinatario por debajo de la reserva justa (32 MiB) recibe espacio desalojando los mensajes más antiguos de la cola más grande. |
| VC-1 | Media | Con la cuarentena de remitentes nuevos llena, el mensaje se descartaba y se confirmaba: un desconocido podía hacer desaparecer el primer mensaje de un contacto real. | Corregido (test): ya no se confirma; el servidor lo conserva y lo reentrega (`resync`) cuando la cuarentena se libera. |
| VC-2 | Media | El búfer de retenidos (CL-5) descartaba y confirmaba a partir de 100 mensajes, incluidos los autenticados por la sesión verificada. | Corregido (test): la sesión de la identidad verificada no se retiene; el desbordamiento queda en el servidor y llega tras aceptar. |
| VC-3 | Baja | «Marcar como verificado» no estaba ligado al número comparado: un cambio de clave durante la comparación se verificaba. | Corregido (test): `setVerified` y `acceptKeyChange` reciben el número mostrado y fallan con `key_changed` si no coincide. |
| VC-4 | Media | El trabajo previo a autenticar era de unos 2000 HMAC (≈62 ms) por mensaje falsificado. | Corregido (test): HMAC-SHA256 síncrono verificado con RFC 4231 y WebCrypto; tope de 100 saltos al crear una sesión. |
| C2 | Media | Las confirmaciones retrasadas vivían solo en memoria: bloquear dentro del retraso las perdía para siempre. | Corregido (test): cola cifrada en el almacén, rearmada con un retraso nuevo al desbloquear. |
| C3 | Baja | No había forma de desactivar las confirmaciones desde la aplicación. | Corregido (e2e): interruptores en Ajustes › Seguridad. |
| UI-1 | Media | Borrar o restaurar desde una segunda pestaña dejaba la primera desbloqueada escribiendo en una base borrada o sustituida. | Corregido (e2e): aviso entre pestañas (BroadcastChannel) y borrado/restauración bajo el Web Lock de la cuenta. |
| SRV-12 | Baja | Tras un 413 con longitud declarada, el servidor destruía el socket después de responder y el cliente reutilizaba una conexión muerta (`ECONNRESET`). | Corregido (test): se drena exactamente la longitud declarada. |

### Cómo informar de un problema

Si encuentras una vulnerabilidad, no la publiques en un *issue* abierto. Contacta en privado
con quien mantenga tu copia o tu despliegue. Incluye los pasos para reproducirla y, si
puedes, una prueba de concepto contra `startServer({ port: 0 })`.
