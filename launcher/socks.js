// Minimal SOCKS5 client (RFC 1928, no auth, CONNECT by domain name) used to reach a
// friend's .onion service through the local Tor process. The hostname is resolved by Tor
// (ATYP 3), never by the local DNS resolver, so no DNS leak.
import net from 'node:net';

/**
 * @param {{proxyHost?: string, proxyPort: number, host: string, port: number, timeoutMs?: number}} o
 * @returns {Promise<net.Socket>} a socket connected end-to-end to host:port
 */
export function socks5Connect({ proxyHost = '127.0.0.1', proxyPort, host, port, timeoutMs = 120000 }) {
  return new Promise((resolve, reject) => {
    const hostBuf = Buffer.from(String(host), 'ascii');
    if (!hostBuf.length || hostBuf.length > 255 || !Number.isInteger(port) || port < 1 || port > 65535) {
      reject(new Error('socks_bad_target'));
      return;
    }
    const s = net.connect(proxyPort, proxyHost);
    let stage = 0;
    let buf = Buffer.alloc(0);
    let done = false;
    const fail = (err) => {
      if (done) return;
      done = true;
      s.destroy();
      reject(err instanceof Error ? err : new Error(String(err)));
    };
    s.setTimeout(timeoutMs, () => fail(new Error('socks_timeout')));
    s.once('error', fail);
    s.once('close', () => fail(new Error('socks_closed')));
    s.once('connect', () => s.write(Buffer.from([0x05, 0x01, 0x00])));
    const onData = (chunk) => {
      buf = Buffer.concat([buf, chunk]);
      if (buf.length > 1024) return fail(new Error('socks_protocol'));
      if (stage === 0) {
        if (buf.length < 2) return undefined;
        if (buf[0] !== 0x05 || buf[1] !== 0x00) return fail(new Error('socks_auth'));
        buf = buf.subarray(2);
        stage = 1;
        s.write(Buffer.concat([
          Buffer.from([0x05, 0x01, 0x00, 0x03, hostBuf.length]),
          hostBuf,
          Buffer.from([port >> 8, port & 0xff]),
        ]));
      }
      if (stage === 1) {
        if (buf.length < 5) return undefined;
        if (buf[0] !== 0x05) return fail(new Error('socks_protocol'));
        if (buf[1] !== 0x00) return fail(new Error(`socks_reply_${buf[1]}`));
        const atyp = buf[3];
        const len = atyp === 0x01 ? 10 : atyp === 0x04 ? 22 : atyp === 0x03 ? 7 + buf[4] : -1;
        if (len < 0) return fail(new Error('socks_protocol'));
        if (buf.length < len) return undefined;
        const rest = buf.subarray(len);
        done = true;
        s.removeListener('data', onData);
        s.removeListener('error', fail);
        s.removeAllListeners('close');
        s.setTimeout(0);
        if (rest.length) s.unshift(rest);
        resolve(s);
      }
      return undefined;
    };
    s.on('data', onData);
  });
}
