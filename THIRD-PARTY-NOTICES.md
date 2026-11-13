# Componentes de terceros

`Sombra-Setup.exe` incluye estos componentes, cada uno bajo su propia licencia:

| Componente | Uso | Licencia |
|---|---|---|
| [Node.js](https://nodejs.org) 26 | Motor de ejecución del programa | MIT (y licencias de sus dependencias: OpenSSL, V8, libuv…) |
| [Tor](https://www.torproject.org) 0.4.x (Tor Expert Bundle 16.0.1) | Conexión anónima y servicio *onion* | BSD de 3 cláusulas; incluye OpenSSL, libevent y zlib |
| [ws](https://github.com/websockets/ws) 8 | Servidor WebSocket | MIT |

Los textos completos de las licencias de Tor y de sus bibliotecas se copian dentro de la
instalación, en `%LOCALAPPDATA%\Sombra\app\<versión>\tor\licenses\`. La licencia de ws se
encuentra en `node_modules/ws/LICENSE`, y la de Node.js en
<https://github.com/nodejs/node/blob/main/LICENSE>.

Tor se descarga del archivo oficial de The Tor Project durante `npm run build`. Antes de
usarse, su SHA-256 se compara con el valor fijado en `build/build.mjs`. La firma de ese
archivo se verificó con la clave de firma de Tor Browser:
`EF6E 286D DA85 EA2A 4BA7 DE68 4E2C 6E87 9329 8290`.

Este proyecto no está afiliado a The Tor Project ni a la OpenJS Foundation.
