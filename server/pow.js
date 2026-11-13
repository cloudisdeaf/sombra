// Proof-of-work challenges (SPEC §3.5).
//
// Challenges are stateless and self-authenticating:
//   challenge = b64u( purpose(1) || u64be(expiryMs) || random16 || HMAC-SHA256(secret, previous 25 bytes)[0..16) )
// so issuing one costs no server memory. Only *redeemed* challenges are remembered (in
// memory, until they expire) to enforce single use. The HMAC secret is random per process,
// so a restart invalidates every outstanding challenge — acceptable, and better for privacy
// than persisting anything.
//
// Client solution: SHA-256(utf8("SOMBRA-POW-v1:" + challenge + ":" + nonce)) must have
// >= difficulty leading zero bits; nonce is a decimal integer string.

import { createHash, createHmac, randomBytes, timingSafeEqual } from 'node:crypto';

export const PURPOSES = Object.freeze({ register: 1, send: 2 });

/** Smallest k with 2^k >= x (x >= 1), integer arithmetic only. */
function ceilLog2(x) {
  let k = 0;
  while (2 ** k < x) k++;
  return k;
}

/**
 * SRV-04: extra leading-zero bits a /api/send solution needs on top of the challenge's
 * base difficulty, so the cost scales with what a request stores: +ceil(log2(messages))
 * and +ceil(log2(bytes / 256 KiB)) beyond 256 KiB (bytes estimated from the b64u length,
 * known before anything is decoded). One small message: +0. Capped at 16.
 * Must stay identical in public/js/core/api.js.
 */
export function sendPowExtraBits(count, b64Chars) {
  const bytes = Math.floor((b64Chars * 3) / 4);
  const extra = ceilLog2(Math.max(1, count)) + (bytes > 262144 ? ceilLog2(Math.ceil(bytes / 262144)) : 0);
  return Math.min(16, extra);
}


const CHALLENGE_BYTES = 1 + 8 + 16 + 16; // 41
const MAC_INPUT_BYTES = 25;

/** Number of leading zero bits of a byte array. */
export function leadingZeroBits(bytes) {
  let n = 0;
  for (const b of bytes) {
    if (b === 0) { n += 8; continue; }
    n += Math.clz32(b) - 24;
    break;
  }
  return n;
}

/** SHA-256 PoW hash as defined by SPEC §2.10. */
export function powHash(challenge, nonce) {
  return createHash('sha256').update(`SOMBRA-POW-v1:${challenge}:${nonce}`, 'utf8').digest();
}

export class PowManager {
  /**
   * @param {{registerBits:number, sendBits:number, ttlMs?:number, now?:()=>number}} opts
   */
  constructor({ registerBits, sendBits, ttlMs = 5 * 60 * 1000, now = Date.now }) {
    this.difficulty = { register: registerBits, send: sendBits };
    this.ttlMs = ttlMs;
    this.now = now;
    this.secret = randomBytes(32);
    /** @type {Map<string, number>} redeemed challenge -> expiryMs */
    this.used = new Map();
  }

  /** Issue a fresh challenge for `purpose` ('register' | 'send'). */
  issue(purpose) {
    const p = PURPOSES[purpose];
    if (!p) throw new Error('bad purpose');
    const head = Buffer.alloc(MAC_INPUT_BYTES);
    head[0] = p;
    head.writeBigUInt64BE(BigInt(this.now() + this.ttlMs), 1);
    randomBytes(16).copy(head, 9);
    const mac = createHmac('sha256', this.secret).update(head).digest().subarray(0, 16);
    return {
      challenge: Buffer.concat([head, mac]).toString('base64url'),
      difficulty: this.difficulty[purpose],
    };
  }

  /**
   * Verify (and on success consume) a solution. Returns true only if the challenge is
   * authentic, bound to `purpose`, unexpired, never redeemed before, and the hash meets
   * the current difficulty (+ extraBits, see sendPowExtraBits). Failed attempts do not
   * consume the challenge.
   */
  verify(purpose, challenge, nonce, extraBits = 0) {
    const p = PURPOSES[purpose];
    if (!p || typeof challenge !== 'string' || typeof nonce !== 'string') return false;
    if (!/^[0-9]{1,20}$/.test(nonce)) return false;
    if (!/^[A-Za-z0-9_-]+$/.test(challenge) || challenge.length > 64) return false;
    const raw = Buffer.from(challenge, 'base64url');
    if (raw.length !== CHALLENGE_BYTES || raw.toString('base64url') !== challenge) return false;

    const head = raw.subarray(0, MAC_INPUT_BYTES);
    const mac = raw.subarray(MAC_INPUT_BYTES);
    const expected = createHmac('sha256', this.secret).update(head).digest().subarray(0, 16);
    if (!timingSafeEqual(mac, expected)) return false;

    if (head[0] !== p) return false;
    const expiry = Number(head.readBigUInt64BE(1));
    if (!(expiry > this.now())) return false;
    if (this.used.has(challenge)) return false;

    const extra = Number.isInteger(extraBits) && extraBits > 0 ? Math.min(16, extraBits) : 0;
    if (leadingZeroBits(powHash(challenge, nonce)) < this.difficulty[purpose] + extra) return false;

    this.used.set(challenge, expiry);
    return true;
  }

  /** Forget redeemed challenges that have expired (they can no longer verify anyway). */
  prune() {
    const now = this.now();
    for (const [c, exp] of this.used) if (exp <= now) this.used.delete(c);
  }
}
