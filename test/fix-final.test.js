// Regression tests for the residual issues found by the post-fix adversarial review
// (APP-1, VC-1..VC-4, C2). Server-side APP-2 lives in fix-server.test.js.
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { SombraClient } from '../public/js/core/client.js';
import { MemoryBackend } from '../public/js/core/store.js';

describe('APP-1 group fan-out under server limits', () => {
  test('bounded concurrency; transient rate_limited/busy refusals are retried, not failed', async () => {
    const c = new SombraClient({ serverUrl: 'http://127.0.0.1:1', backend: new MemoryBackend() });
    c.setPrivacyOptions?.({ sendJitterMs: 0 });
    c._store = {}; // pretend unlocked (only `unlocked` is consulted by _sendSplit)
    let inflight = 0;
    let peak = 0;
    const attempts = new Map();
    c.api = {
      async send([m]) {
        inflight++;
        peak = Math.max(peak, inflight);
        await new Promise((r) => setTimeout(r, 5));
        inflight--;
        const n = (attempts.get(m.to) || 0) + 1;
        attempts.set(m.to, n);
        const idx = Number(m.to.slice(1));
        if (idx % 10 === 0 && n === 1) return [{ to: m.to, ok: false, error: idx % 20 === 0 ? 'busy' : 'rate_limited' }];
        if (idx === 7) return [{ to: m.to, ok: false, error: 'not_found' }]; // permanent: no retry
        return [{ to: m.to, ok: true }];
      },
    };
    const blobs = Array.from({ length: 99 }, (_, i) => ({ to: `u${i}`, blob: 'x' }));
    const res = await c._sendSplit(blobs);
    assert.equal(res.length, 99);
    assert.ok(peak <= 4, `peak concurrency ${peak}`);
    for (let i = 0; i < 99; i++) {
      assert.equal(res[i].to, `u${i}`);
      assert.equal(res[i].ok, i !== 7, `u${i}`);
    }
    assert.equal(attempts.get('u7'), 1);
    assert.equal(attempts.get('u10'), 2);
    assert.equal(attempts.get('u20'), 2);
  });
});

describe('VC-4 synchronous HMAC in the ratchet chain step', () => {
  test('hmacSha256Sync matches RFC 4231 and WebCrypto for many key/data lengths', async () => {
    const { hmacSha256Sync } = await import('../public/js/crypto/pow.js');
    const hex = (u) => Buffer.from(u).toString('hex');
    // RFC 4231 test case 2
    assert.equal(hex(hmacSha256Sync(new TextEncoder().encode('Jefe'), new TextEncoder().encode('what do ya want for nothing?'))),
      '5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843');
    // RFC 4231 test case 6 (key longer than the block size)
    assert.equal(hex(hmacSha256Sync(new Uint8Array(131).fill(0xaa), new TextEncoder().encode('Test Using Larger Than Block-Size Key - Hash Key First'))),
      '60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54');
    for (const kl of [0, 1, 31, 32, 33, 63, 64, 65, 130]) {
      for (const dl of [0, 1, 55, 56, 63, 64, 65, 119, 120, 300]) {
        const k = crypto.getRandomValues(new Uint8Array(kl));
        const d = crypto.getRandomValues(new Uint8Array(dl));
        const ref = kl === 0
          ? null // WebCrypto refuses empty HMAC keys
          : new Uint8Array(await crypto.subtle.sign('HMAC', await crypto.subtle.importKey('raw', k, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']), d));
        if (ref) assert.equal(hex(hmacSha256Sync(k, d)), hex(ref), `kl=${kl} dl=${dl}`);
      }
    }
  });

  test('worst-case pre-authentication work per forged header is small', async () => {
    const { ratchetInitSender, ratchetInitReceiver, ratchetEncrypt, ratchetDecrypt } = await import('../public/js/crypto/ratchet.js');
    const { generateX25519, randomBytes } = await import('../public/js/crypto/primitives.js');
    const sk = randomBytes(32);
    const bob = await generateX25519();
    let a = await ratchetInitSender(sk, bob.pub);
    let b = await ratchetInitReceiver(sk, bob);
    const ad = new Uint8Array(8);
    const m = await ratchetEncrypt(a, new Uint8Array(4), ad);
    b = (await ratchetDecrypt(b, m.header, m.ciphertext, ad)).state;
    // Forged header on the current chain asking for the maximum (1000) skips.
    const forged = { ...m.header, n: 1001 };
    const t0 = performance.now();
    await assert.rejects(ratchetDecrypt(b, forged, m.ciphertext, ad));
    const ms = performance.now() - t0;
    assert.ok(ms < 40, `forged 1000-skip header cost ${ms.toFixed(1)} ms`);
  });
});
