# Sombra — Technical Specification (authoritative, protocol v2)

Sombra is a Telegram-style messenger with end-to-end encryption modelled on the Signal
protocol (X3DH + Double Ratchet). It has sealed sender, metadata minimisation and
username-only anonymous accounts (no phone, no email, no password on the server).

**Every module MUST follow this document exactly.** Modules are built in parallel by
different people and must interoperate. If something is ambiguous, choose the most secure
option and document it in a comment.

> **About v2.** This revision describes the protocol **as implemented** after the November
> 2026 security audit (finding ids such as `CRYPTO-7`, `CL-4` and `SRV-06` are listed in
> [SECURITY.md](SECURITY.md) §5).
> - Sections changed relative to the original design carry the marker **(v2)**.
> - v2 is **not wire-compatible** with v1 for new sessions, because the X3DH associated data
>   changed (§2.4). All clients of a deployment must be upgraded together.
> - Appendix A summarises every change.

## 0. Ground rules

- Runtime: Node.js 26 (server and tests) and modern browsers (client). ES modules everywhere
  (`"type": "module"`).
- Client: **vanilla JS, no framework, no build step, no third-party code, no CDN**.
  - All crypto goes through WebCrypto (`globalThis.crypto.subtle`): X25519, Ed25519, HKDF,
    HMAC, AES-256-GCM, PBKDF2 and SHA-256/512.
  - Code under `public/js/crypto/` and `public/js/core/` must be **isomorphic**: it runs
    unchanged in the browser and in Node 26. That means no DOM, no `window` and no IndexedDB,
    except in `core/idbstore.js`.
  - The client needs a secure context (HTTPS, localhost, or `.onion` in Tor Browser).
- Server: Node 26. The only dependency is `ws` (WebSocket). Storage uses the built-in
  `node:sqlite` (`DatabaseSync`).
- Binary data in JSON is always **base64url without padding** ("b64u"). Decoding is
  **strict and canonical**: it rejects padding, foreign characters and non-zero trailing
  bits, on both client and server.
- All byte arrays in JS are `Uint8Array`.
- UI language: **Spanish**. Code and comments: English.
- Tests: `node --test test/` (built-in test runner, `node:assert/strict`).

## 1. Repository layout

```
sombra/
  package.json            {"type":"module","scripts":{"start":"node server/index.js","test":"node --test test/"},"dependencies":{"ws":"^8.18.0"}}
  SPEC.md  README.md  SECURITY.md
  server/
    index.js      HTTP(S) server: static files, security headers, REST API, WebSocket
    db.js         node:sqlite storage layer
    pow.js        proof-of-work challenge issue/verify
    validate.js   input validation helpers
    config.js     configuration from env vars + fixed LIMITS
  public/
    index.html
    css/app.css
    js/
      crypto/  encoding.js primitives.js x3dh.js ratchet.js sealed.js padding.js safety.js vault.js pow.js
      core/    store.js idbstore.js api.js client.js
      ui/      app.js chatlist.js chatview.js dialogs.js welcome.js overlay.js widgets.js dom.js
               format.js errors.js prefs.js autolock.js strength.js files.js icons.js
  test/
    crypto.test.js  ratchet.test.js  server.test.js  core.test.js  integration.test.js
    fix-crypto.test.js  fix-server.test.js  fix-ui.test.js      (audit regressions, v2)
```

## 2. Crypto library (`public/js/crypto/`)

### 2.1 encoding.js
```js
export function b64uEncode(bytes) -> string           // base64url, no padding
export function b64uDecode(str) -> Uint8Array          // throws on invalid OR non-canonical input
export function utf8Encode(str) -> Uint8Array
export function utf8Decode(bytes) -> string
export function concatBytes(...arrays) -> Uint8Array
export function u32be(n) -> Uint8Array(4)
export function constantTimeEqual(a, b) -> boolean
export function zeroize(bytes)                          // fill(0), best effort
```

### 2.2 primitives.js (all async unless noted; all return Uint8Array)
```js
export function randomBytes(n)                                   // sync
export async function sha256(data)
export async function sha512(data)
export async function hmacSha256(key, data)
export async function hkdf(ikm, salt, info /*Uint8Array|string*/, length)   // HKDF-SHA256
export async function aesGcmEncrypt(key32, iv12, plaintext, aad = new Uint8Array(0))
export async function aesGcmDecrypt(key32, iv12, ciphertext, aad = new Uint8Array(0))  // throws on auth failure
export async function pbkdf2Sha256(passwordBytes, salt, iterations, length = 32)
export async function generateX25519()        // -> { pub: Uint8Array(32), priv: Uint8Array(32) }
export async function x25519(privBytes, pubBytes)   // -> 32-byte shared secret; MUST throw if result is all-zero
export async function generateEd25519()       // -> { pub: Uint8Array(32), priv: Uint8Array(32) }
export async function ed25519Sign(keyPair /*{pub,priv}*/, message)   // -> 64-byte signature
export async function ed25519Verify(pub, message, signature)        // -> boolean (never throws)
```
Keypair representation everywhere: `{ pub: Uint8Array(32), priv: Uint8Array(32) }`, where
`priv` is the raw 32-byte private scalar or seed.

- Ed25519 private keys are imported into WebCrypto as JWK `{kty:'OKP',crv,x,d}`.
- X25519 private keys are imported as **PKCS#8**: the raw scalar behind a fixed DER prefix.
  A private OKP JWK must carry `x`, and `x25519()` only receives the scalar.
- Every imported CryptoKey is non-extractable and is never cached.

Serialised (stored) keypairs use `{ pub: b64u, priv: b64u }`.

### 2.3 Identity (v2)
An identity is `{ sig: Ed25519 keypair, dh: X25519 keypair }`.

- Public identity: `{ ik_sig, ik_dh, ik_dh_sig }`, where
  `ik_dh_sig = Ed25519Sign(sig, utf8("SOMBRA-IKDH-v1") || ik_dh)`.
- Signed prekey (SPK): `{ id: uint32, pub, sig }`, where
  `sig = Ed25519Sign(IK_sig, utf8("SOMBRA-SPK-v1") || u32be(id) || spk_pub)`.
- One-time prekey (OPK): `{ id: uint32, pub }`.

**Registration signature (v2, CRYPTO-7).** Proves possession of the identity key and binds
it to the username:
`reg_sig = Ed25519Sign(IK_sig, utf8("SOMBRA-REG-v1") || u8(len(username)) || utf8(username) || ik_dh)`.

Domain-separation labels in use: `SOMBRA-IKDH-v1`, `SOMBRA-SPK-v1`, `SOMBRA-REG-v1`,
`SOMBRA-AUTH-v1`, `SOMBRA-X3DH-v1`, `SOMBRA-AD-v2`, `SOMBRA-RK-v1`, `SOMBRA-MK-v1`,
`SOMBRA-SEALED-v1`, `SOMBRA-FP-v1`, `SOMBRA-VAULT-ENC-v1`, `SOMBRA-VAULT-MAC-v1`,
`SOMBRA-POW-v1`, `SOMBRA-GID-v1`.

Prekey bundle (from the server, b64u strings):
`{ username, ik_sig, ik_dh, ik_dh_sig, spk: {id, pub, sig}, opk: {id, pub} | null }`

Helpers in x3dh.js:
```js
export async function generateIdentity()                       // -> {sig, dh}
export async function publicIdentity(identity)                 // -> {ik_sig, ik_dh, ik_dh_sig} (b64u)
export async function verifyPublicIdentity(pubId)              // -> boolean (checks ik_dh_sig)
export async function generateSignedPrekey(identity, id)       // -> {id, keyPair, pub: b64u, sig: b64u}
export async function verifySignedPrekey(ik_sig_b64u, spk)     // -> boolean
export async function generateOneTimePrekeys(startId, count)   // -> [{id, keyPair, pub: b64u}]
export function serializeKeyPair / deserializeKeyPair / serializeIdentity / deserializeIdentity
```

### 2.4 X3DH (x3dh.js) (v2)
```js
export async function x3dhInitiate(identity, bundle, names /*{initiator, responder}*/)
  // verifies ik_dh_sig and spk.sig (throws Error('bad bundle signature') on failure)
  // with names: requires bundle.username === names.responder (else Error('bad bundle'))
  // EK = generateX25519()
  // DH1 = X25519(IKa_dh, SPKb) DH2 = X25519(EKa, IKb_dh) DH3 = X25519(EKa, SPKb) DH4 = X25519(EKa, OPKb) if opk
  // SK = HKDF(ikm = 0xFF*32 || DH1 || DH2 || DH3 [|| DH4], salt = 32 zero bytes, info "SOMBRA-X3DH-v1", 32)
  // -> { sk, ad, ek: b64u(EK_pub), spk_id, opk_id /*number|null*/, spkPub: Uint8Array }
export async function x3dhRespond(identity, spkKeyPair, opkKeyPair /*or null*/, initiatorPub /*{ik_sig, ik_dh} b64u*/, ekB64u, names)
  // -> { sk, ad }  (AD built with initiator first, responder second: identical bytes to the initiator's AD)
```
**Associated data v2 (CRYPTO-7, unknown-key-share).** Both usernames are bound into the AD:
```
AD = utf8("SOMBRA-AD-v2") || IKa_sig || IKa_dh || IKb_sig || IKb_dh
     || u8(len(userA)) || utf8(userA) || u8(len(userB)) || utf8(userB)
```
- A is the initiator and B the responder. Each name is a non-empty string of at most
  255 UTF-8 bytes. `null` and other non-object `names` values are rejected.
- The client **always** passes names:
  - as initiator: `{initiator: ownUsername, responder: peer}`;
  - as responder: `{initiator: sealedFrom, responder: ownUsername}`.
  This binds the sealed `from` into every message's AAD.
- Calling without `names` (`undefined`) still produces the legacy v1 AD
  (`"SOMBRA-AD-v1" || IKa_sig || IKa_dh || IKb_sig || IKb_dh`). That form exists only for the
  library's own tests. A client MUST NOT fall back to v1, because doing so would re-open the
  unknown-key-share by downgrade.
- Sessions already stored keep the `ad` they were created with.

### 2.5 Double Ratchet (ratchet.js) (v2)
Signal spec, no header encryption.

- `KDF_RK(rk, dhOut)`: `HKDF(ikm=dhOut, salt=rk, info "SOMBRA-RK-v1", 64)`, giving
  `rk' = [0..32)` and `ck = [32..64)`.
- `KDF_CK(ck)`: `mk = HMAC(ck, 0x01)`, `ck' = HMAC(ck, 0x02)`.
- Message key expansion: `HKDF(mk, salt=32 zero bytes, info "SOMBRA-MK-v1", 44)`, giving the
  AES key `[0..32)` and the IV `[32..44)`.
- Header: `{ dh: b64u(32), pn: uint32, n: uint32 }`. Header bytes are
  `dh(32) || u32be(pn) || u32be(n)`.
- Ciphertext = AES-256-GCM(key, iv, plaintext, aad = AD || headerBytes).
- **State** is a plain JSON-serialisable object:
  `{ v:1, rk, dhs:{pub,priv}, dhr|null, cks|null, ckr|null, ns, nr, pn, skipped:[{dh, n, mk, t}] }`.
- **Functional API.** Never mutate the input state; return a new state. Callers persist the
  new state only on success, so a failed decryption leaves the stored state untouched.

Limits and v2 rules:

| Constant | Value | Rule |
|---|---|---|
| `MAX_SKIP` | 1000 | Same-chain gap `n - nr > MAX_SKIP` → throw `too many skipped messages`. |
| pn clamp **(v2, CRYPTO-2)** | — | On a **new** peer ratchet key, the abandoned chain is skipped up to `pn`, but a gap `> MAX_SKIP` is **clamped**: only the first `MAX_SKIP` keys are stored and the DH ratchet proceeds, instead of throwing. `pn` is in the AAD, so a forged `pn` costs bounded work and the cloned state is discarded. If the clamp fired and decryption then fails, the error is `too many skipped messages`. |
| `MAX_SKIPPED_TOTAL` | 2000 | Stored skipped keys; the oldest are evicted. |
| `SKIPPED_KEY_MAX_AGE_MS` **(v2, CRYPTO-8)** | 14 days | Every skipped entry stores its creation time `t` (ms). Entries older than this are purged at the start of every `ratchetEncrypt`/`ratchetDecrypt` and by `ratchetPurgeSkipped`. Legacy entries without `t` start their clock at `now`, and a future `t` is clamped to `now`. |
| `REKEY_AFTER` **(v2, CRYPTO-2)** | 500 | `ratchetNeedsRekey(state)` is true when `cks !== null && ns >= 500`, i.e. 500 sends with no DH ratchet step since. The caller MUST start a fresh X3DH session instead of encrypting on this one (§5.4). No sending chain can then accumulate a loss gap the receiver refuses. |

```js
export const MAX_SKIP, MAX_SKIPPED_TOTAL, REKEY_AFTER, SKIPPED_KEY_MAX_AGE_MS
export async function ratchetInitSender(sk, remoteRatchetPub /*Uint8Array = SPKb*/) -> state
export async function ratchetInitReceiver(sk, ownRatchetKeyPair /*SPKb keypair*/) -> state
export async function ratchetEncrypt(state, plaintext, ad, opts /*{now?}*/) -> { state, header, ciphertext }
export async function ratchetDecrypt(state, header, ciphertext, ad, opts /*{now?}*/) -> { state, plaintext }   // throws on failure
export function ratchetNeedsRekey(state) -> boolean                                   // (v2)
export function ratchetPurgeSkipped(state, now = Date.now(), maxAgeMs = SKIPPED_KEY_MAX_AGE_MS) -> state   // (v2)
```
Header `dh` is strictly decoded, so it has a single canonical string.

### 2.6 Padding (padding.js)
`pad(bytes)` produces `u32be(len) || bytes || zeros`, with the total length rounded up to a
bucket: 256, 512, 1024, 2048, 4096, 8192, 16384, then the next power of two up to 1 MiB, then
the next multiple of 1 MiB.

`unpad(bytes)` is strict. It throws unless:
- the buffer is exactly the bucket size for the declared length;
- the length fits in the buffer;
- every padding byte is zero.
```js
export function bucketSize(n) ; export function pad(bytes) ; export function unpad(bytes)
```

### 2.7 Sealed sender (sealed.js)
Hides the sender from the server. The outer envelope is the only thing the server sees.
```js
export async function seal(senderUsername, recipientIkDhPub /*Uint8Array*/, innerBytes) -> Uint8Array blob
  // eph = generateX25519(); s = X25519(eph.priv, recipientIkDh)
  // okm = HKDF(s, salt = eph.pub || recipientIkDh, info "SOMBRA-SEALED-v1", 44) -> key[0..32) iv[32..44)
  // pt = pad(utf8(JSON.stringify({ from: senderUsername, inner: b64u(innerBytes) })))
  // blob = 0x01 || eph.pub(32) || AES-GCM(key, iv, pt, aad = 0x01 || eph.pub || recipientIkDh)
export async function unseal(recipientDhKeyPair, blob) -> { from: string, inner: Uint8Array }
  // throws Error('unseal failed') on ANY failure (single error, no oracle); minimum blob 1+32+256+16 bytes
```
- The sealed layer itself does not authenticate the sender. Authentication comes from the
  inner ratchet layer, whose AD v2 binds both identity keys **and both usernames** (§2.4).
- The sealed layer uses the recipient's **long-term** `IK_dh`, so it has no forward secrecy.
  A later compromise of `IK_dh` reveals the sender of recorded envelopes, but not their
  content.

### 2.8 Safety numbers (safety.js)
For each party:
- `fp = utf8("SOMBRA-FP-v1") || ik_sig || ik_dh || utf8(username)`;
- start with `h = SHA-512(fp)`, then iterate `h = SHA-512(h || ik_sig || ik_dh)` 5200 times;
- take the first 30 bytes as 6 chunks of 5 bytes. Each chunk is read as a big-endian 40-bit
  integer, reduced mod 100000 and zero-padded to 5 digits, giving 30 digits.

The safety number is the two 30-digit strings sorted lexicographically and concatenated
(60 digits). It is displayed in 12 groups of 5.
```js
export async function safetyNumber(localUsername, localPub /*{ik_sig, ik_dh} b64u*/, remoteUsername, remotePub) -> string (60 digits, no spaces)
export function formatSafetyNumber(str) -> string  // "12345 67890 ..."
```

### 2.9 Vault (vault.js): local encryption at rest
```js
export const PBKDF2_ITERATIONS = 600000
export async function createVault(passphrase, { iterations } = {}) -> { meta, keys }   // iterations override: tests only
  // salt = 16 random bytes; master = PBKDF2-SHA256(utf8(passphrase), salt, iter, 32)
  // encKey = HKDF(master, salt, "SOMBRA-VAULT-ENC-v1", 32); macKey = HKDF(master, salt, "SOMBRA-VAULT-MAC-v1", 32)
  // verifier = b64u(iv12 || AES-GCM(encKey, iv, utf8("SOMBRA-VAULT-OK"), aad utf8("verifier")))
  // meta = { v: 1, salt: b64u, iter, verifier }   keys = { encKey, macKey }
export async function unlockVault(passphrase, meta) -> keys      // throws Error('bad passphrase'); iter must be 1..10 000 000
export async function encryptRecord(keys, name, obj) -> string   // b64u(iv12 || AES-GCM(encKey, iv, utf8(JSON), aad = utf8(name)))
export async function decryptRecord(keys, name, str) -> obj
export async function recordKey(keys, name) -> string            // b64u(HMAC(macKey, utf8(name))): hides record names at rest
```
After `importBackup()`, `meta` may also carry `restored: 1` (§5.7).

### 2.10 Proof of work (pow.js), client side
- `hash = SHA-256(utf8("SOMBRA-POW-v1:" + challenge + ":" + nonce))`, where `nonce` is a
  decimal integer string.
- A solution is valid if `hash` has at least `difficulty` leading zero bits.
- The module includes a **synchronous pure-JS SHA-256** (exported as `sha256Sync`) with a
  precomputed midstate for the constant prefix.
```js
export function sha256Sync(bytes) -> Uint8Array
export function leadingZeroBits(bytes) -> number
export async function solvePow(challenge, difficulty, { onProgress, signal } = {}) -> string nonce
   // yields to the event loop every ~20000 iterations
export function verifyPowSync(challenge, nonce, difficulty) -> boolean
```

## 3. Server

### 3.1 config.js (env vars) (v2)
Invalid or out-of-range values fall back to the default silently.

| Var | Default | Notes |
|---|---|---|
| `PORT` | 8443 | 0..65535 |
| `HOST` | `127.0.0.1` | |
| `DATA_DIR` | `./data` | resolved against cwd; dir 0700, `sombra.db` 0600 |
| `TLS_CERT`, `TLS_KEY` | — | paths; HTTPS (TLS ≥ 1.2) + HSTS only if **both** are set |
| `POW_REGISTER_BITS` | **22** (v2; was 18) | 0..32 (BUG-3) |
| `POW_SEND_BITS` | 10 | 0..32 |
| `MESSAGE_TTL_DAYS` | 14 | 1..365 |
| `TRUST_PROXY` | off | rate-limit key = **last** `X-Forwarded-For` entry; never used for logging |
| `RATE_LIMIT` | on | `off` for Tor (all clients appear as 127.0.0.1) |
| `QUEUE_MAX_TOTAL_MB` | 8192 | **(v2)** global cap on queued blob bytes (SRV-04) |
| `STRICT_ENVELOPES` | on | **(v2)** sealed-envelope validation of `/api/send` blobs (§3.4) |
| `DEBUG` | — | `1` → print stack traces of internal errors (never request data) |

The `LIMITS` object holds the fixed protocol and resource limits (§3.9).

### 3.2 Privacy rules (hard requirements) (v2)
- **No logging** of IPs, usernames, user agents, request paths or timings. The only output is
  the startup line and generic error messages (`console.error('internal error')`, plus the
  stack trace only if `DEBUG=1`).
- No cookies, no sessions, no analytics, no third-party requests. Responses carry no `Date`,
  `Server` or `X-Powered-By` header.
- The DB stores no timestamps except a coarse message expiry, rounded **up to the next UTC
  day**.
- SQLite pragmas: `secure_delete = ON; journal_mode = DELETE; synchronous = FULL; temp_store = MEMORY`.
- **(v2, SRV-07) No insertion order at rest.**
  - `users` and `opks` are `WITHOUT ROWID` tables. Pre-existing rowid tables are migrated in
    place, copying rows in primary-key order.
  - Queue rowids are **not** a global counter. Each recipient's rows form an independent
    random walk: a random 52-bit start, then random gaps of 1..2^20. They are strictly
    increasing per recipient, which the flush cursor needs, but reveal nothing about arrival
    order across recipients or batch membership.
  - Residual risk: the rollback journal is unlinked, not wiped. Operators must keep
    `DATA_DIR` on full-disk encryption or tmpfs.
- Delivered messages are deleted immediately on ACK. Expired messages are purged at startup
  and then hourly.
- Rate limiting (if on) uses in-memory maps keyed by `HMAC(randomSecretGeneratedAtStartup, …)`.
  Nothing is persisted, and buckets expire after 10 min (§3.9).

### 3.3 HTTP security headers (every response) (v2)
```
Content-Security-Policy: default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' blob: data:; media-src 'self' blob:; connect-src 'self'; font-src 'self'; worker-src 'self'; manifest-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'
Referrer-Policy: no-referrer
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
Cross-Origin-Opener-Policy: same-origin
Cross-Origin-Resource-Policy: same-origin
Cross-Origin-Embedder-Policy: require-corp
Permissions-Policy: camera=(), microphone=(), geolocation=(), interest-cohort=(), browsing-topics=()
Strict-Transport-Security: max-age=63072000; includeSubDomains   (only when TLS)
Cache-Control: no-store                                           (API responses)
Cache-Control: no-cache                                           (static files: always revalidate, so client fixes reach users)
```
Static files rules:
- Served from `public/` only, with `index.html` for `/` and an explicit MIME map. Unknown
  extensions get 404.
- Each path segment must match `^[A-Za-z0-9_][A-Za-z0-9._-]{0,127}$`, with at most 16
  segments. This rules out dotfiles, `..`, `\`, `:` and `%`.
- Symlinks are resolved and re-checked against the public root. There is no directory
  listing.
- Methods: GET and HEAD only (anything else → 405).

`index.html` repeats the CSP (except `frame-ancestors`) in a `<meta>` tag.

### 3.4 Validation (v2)
- Username: `^[a-z0-9_]{3,32}$`. The client lowercases and strips a leading `@` first.
- Keys: strict b64u decoding to exactly 32 bytes. All-zero keys are rejected. Signatures are
  exactly 64 bytes.
- Prekey ids: integers 0..2^32-1. OPK lists contain unique ids.
- Body limits: register 256 KiB; send 24 MiB total; a single blob is ≤ 12 MiB decoded.
- **(v2, SRV-03)** A `/api/send` body may contain at most `8·100+64` structural JSON bytes
  (`{ [ , :`), checked before `JSON.parse`.
- **(v2, SRV-04) Envelope validation** (`STRICT_ENVELOPES`): a blob must look like a sealed
  envelope (§2.7):
  - `blob[0] == 0x01`;
  - `length ≥ 1+32+256+16`;
  - `length - 49` is a padding bucket (a power of two ≤ 1 MiB, or a multiple of 1 MiB).

  The `node server/index.js` entry point enables this by default. Library callers of
  `startServer()` must pass `strictEnvelopes: true`.
- Unknown fields are ignored. Wrong types → 400 `{error:"bad_request"}`.

### 3.5 Proof of work (server/pow.js)
- `GET /api/pow?purpose=register|send` → `{ challenge, difficulty }`.
- `challenge = b64u( purposeByte(1=register,2=send) || u64be(expiryMs) || random16 || HMAC-SHA256(secret, previous 25 bytes)[0..16) )`.
  Expiry is now + 5 min, and `secret` is random at startup.
- Verification steps:
  1. decode canonically;
  2. check the HMAC (timing-safe);
  3. check the purpose;
  4. check the expiry;
  5. check the hash's leading zeros;
  6. check that the challenge has not been redeemed before. Redeemed challenges are kept in
     an in-memory set, pruned after expiry.
- Each challenge is single-use. Failed attempts do not consume it.

### 3.6 REST API (JSON in/out, all errors `{error: code}`) (v2)
**Cross-site refusal (v2, SRV-10).** Every `/api/*` request whose `Sec-Fetch-Site` header is
present and is neither `same-origin` nor `none` gets **403 `{error:"forbidden"}`** before any
state change (no OPK is consumed).

| Method | Path | Body / result |
|---|---|---|
| GET | `/api/pow?purpose=` | → `{challenge, difficulty}` |
| POST | `/api/register` | **(v2)** body `{username, ik_sig, ik_dh, ik_dh_sig, reg_sig, spk:{id,pub,sig}, opks:[{id,pub}] (1..200), pow:{challenge, nonce}}`. Order of checks: PoW (403 `bad_pow`), then signatures with node:crypto Ed25519 (`ik_dh_sig`, `spk.sig`, `reg_sig` per §2.3; failure → 400 `bad_signature`), then 409 `{error:"username_taken"}`, and **409 `{error:"identity_taken"}`** if `ik_sig` or `ik_dh` is already registered to any user. Success → 201 `{ok:true}`. |
| GET | `/api/identity/:username` | → `{username, ik_sig, ik_dh, ik_dh_sig}` or 404 `{error:"not_found"}` |
| GET | `/api/bundle/:username` | → full prekey bundle; atomically consumes (deletes) the lowest-id OPK. 404 if unknown. **(v2, SRV-06) Per-target OPK budget:** at most 50 OPKs per target username per hour may be consumed through this endpoint (in-memory, keyed by HMAC(secret, username), ≤ 100 000 entries, oldest window evicted). Beyond the budget, the bundle is returned with `opk:null` and **nothing is consumed**, which looks the same as an empty pool. |
| POST | `/api/send` | `{messages:[{to, blob}] (1..100), pow:{challenge, nonce}}`, **unauthenticated** (sealed sender). → 202 `{ok:true, results:[{to, ok:boolean, error?}]}`. Unknown recipient → per-item `{ok:false,error:"not_found"}`; full queue (per recipient or global) → `"queue_full"`. All items are stored in **one** transaction, then pushed over WS to recipients that are online. |

Order of checks for `/api/send` **(v2, SRV-03)**:
1. rate limit;
2. per-address body slot;
3. streamed body read against the global memory budget;
4. JSON-token bound;
5. `JSON.parse`;
6. cheap shape checks (`to`, blob string length);
7. **PoW verification**;
8. only then, b64u decoding of the blobs and the envelope check.

Other error responses:

| Status | Code | When |
|---|---|---|
| 405 | `method_not_allowed` | wrong method |
| 404 | `not_found` | unknown `/api` path |
| 413 | `payload_too_large` | body over the limit; the remainder is discarded unbuffered |
| 429 | `rate_limited` | rate limit hit |
| 503 | `busy` | global body budget exhausted |
| 500 | `internal` | unexpected error |

Queue limits: 5000 messages or 256 MiB per recipient, plus `QUEUE_MAX_TOTAL_MB` globally.
Expiry = `roundUpToUtcDay(now + MESSAGE_TTL_DAYS)`.

### 3.7 WebSocket `/ws` (JSON text frames, max frame 1 MiB, no compression) (v2)
```
S→C {t:"challenge", nonce: b64u(32 random)}
C→S {t:"auth", username, sig}     sig = Ed25519(IK_sig, utf8("SOMBRA-AUTH-v1") || nonce)
S→C {t:"ready", opk_count, spk_id}            (or {t:"error", code:"auth_failed"} + close 4003)
S→C {t:"msg", id, blob}                       id = random b64u(16) server queue id; queued messages flushed after ready (paged by per-recipient seq)
C→S {t:"ack", ids:[...]}                      1..1000 ids, each /^[A-Za-z0-9_-]{22}$/; server deletes only entries owned by this user
C→S {t:"upload_opks", opks:[{id,pub}] (≤200)} → S→C {t:"opk_count", n}  |  {t:"error", code:"too_many_opks"} if > 2000 would be stored
C→S {t:"rotate_spk", spk:{id,pub,sig}}        server verifies sig → S→C {t:"spk_ok", id}  |  {t:"error", code:"bad_signature"}
C→S {t:"delete_account"}                      server deletes user, opks, queue → {t:"deleted"} then close 4004
S→C {t:"opk_count", n}                         also pushed whenever count < 20 after a bundle fetch
S→C {t:"error", code}                          bad_request | internal | too_many_opks | bad_signature | auth_failed
```
Close codes:

| Code | Meaning |
|---|---|
| 4001 | auth timeout |
| 4002 | any frame other than `auth` before authentication |
| 4003 | auth failed |
| 4004 | account deleted |
| 4005 | replaced: a new successful auth for the same user closes the previous connection |
| 1001 | server shutdown |

Connection rules:
- **(v2)** Auth must arrive within **5 s** (stricter than v1's 10 s, SRV-08). There is one
  auth attempt per connection.
- **(v2, SRV-10)** An upgrade is refused with 403 when `Sec-Fetch-Site` is cross-site. When
  that header is absent and `TRUST_PROXY` is off, the `Origin` host must match `Host`.
  Non-browser clients without `Origin` are allowed.
- **(v2, SRV-08)** Caps on sockets:
  - at most 5 unauthenticated sockets per address (only with rate limiting on);
  - at most 1000 unauthenticated sockets globally — the **oldest pending socket is evicted**
    rather than refusing new ones;
  - at most 20 000 sockets in total; the next upgrade gets 503.
- **(v2, SRV-09) Backpressure:**
  - a `msg` frame is written to a socket that already holds data only if its buffer stays
    ≤ 2 MiB;
  - the total of unwritten frame bytes across all sockets stays ≤ 256 MiB;
  - a socket whose buffer makes no drain progress for 45 s is terminated.
- The server pings every 30 s and terminates dead connections.

### 3.8 DB schema (server/db.js) (v2)
```sql
CREATE TABLE IF NOT EXISTS users(username TEXT PRIMARY KEY, ik_sig BLOB NOT NULL, ik_dh BLOB NOT NULL, ik_dh_sig BLOB NOT NULL, spk_id INTEGER NOT NULL, spk_pub BLOB NOT NULL, spk_sig BLOB NOT NULL) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS opks(username TEXT NOT NULL, id INTEGER NOT NULL, pub BLOB NOT NULL, PRIMARY KEY(username, id)) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS queue(id TEXT PRIMARY KEY, recipient TEXT NOT NULL, blob BLOB NOT NULL, expires INTEGER NOT NULL);   -- rowid = per-recipient random walk (§3.2)
CREATE INDEX IF NOT EXISTS queue_recipient ON queue(recipient);
```
`reg_sig` is verified at registration and is not stored.

`server/index.js` exports `isSealedEnvelope`, `expandIPv6`, `addressKeys`, `RateLimiter` and:
```js
export async function startServer(options) -> { port, close() }
// options override config: {port, host, dataDir, powRegisterBits, powSendBits, rateLimit, messageTtlDays,
//   tlsCert, tlsKey, trustProxy, debug, queueMaxTotalBytes, strictEnvelopes}
// test hooks: {publicDir, authTimeoutMs, pingIntervalMs, bodyBudgetBytes, bodyIdleTimeoutMs, maxUnauthWs,
//   maxUnauthWsPerAddr, stallTimeoutMs, wsHighWater, bundleOpksPerTarget}
```
It auto-starts only when run directly (`import.meta.url === pathToFileURL(process.argv[1]).href`).
Tests use `port: 0`, a temp `dataDir`, low PoW bits (e.g. 4) and `rateLimit:false`.

### 3.9 Resource limits (v2)
These limits are not part of the wire protocol. They bound abuse (SRV-03/04/05/06/08/09).

| Limit | Value |
|---|---|
| Rate limit per 10-min window per address (IPv4, or IPv6 /64) | pow 1500, register 20, send 1200, identity 1200, bundle 300, ws 300, static 5000 |
| IPv6 /48 aggregate | 16 × the per-/64 limit (checked first) |
| Bucket map | ≤ 200 000 buckets. When full, the **oldest window is evicted** (never fail closed). IPv6 is expanded before grouping; IPv4-mapped IPv6 is treated as IPv4. |
| Global in-memory request bodies | 128 MiB (over budget → 503 `busy`) |
| Body idle timeout / whole-request timeout / header timeout / keep-alive | 30 s / 120 s / 20 s / 5 s |
| Concurrent uploading bodies per address | 8 (rate limiting on only) |
| Raw TCP connections per address | 256 (rate limiting on and no trusted proxy) |
| `server.maxConnections` | 24 000 |
| WS: unauth per address / unauth global / total | 5 / 1000 (evict oldest) / 20 000 |
| WS backpressure per socket / global / stall timeout | 2 MiB / 256 MiB / 45 s |
| OPKs stored per user | 2000 |
| Bundle OPK budget per target | 50 per hour |
| Queue per recipient / global | 5000 msgs or 256 MiB / `QUEUE_MAX_TOTAL_MB` |

With `RATE_LIMIT=off` (Tor), the per-address limits are disabled and only the global caps
apply.

## 4. Client core (`public/js/core/`)

### 4.1 store.js
```js
export class MemoryBackend { async get(k) async set(k, v /*string*/) async delete(k) async keys() async clear() }
export class EncryptedStore {
  constructor(backend, vaultKeys)           // copies the keys
  async get(name) -> object | undefined     // backend key = recordKey(keys, name); value = encryptRecord(...)
  async set(name, obj)
  async delete(name)
  close()                                   // zeroizes its key copy; further calls throw Error('locked')
  get closed
}
export const META_KEY = '__sombra_meta__'   // stored in clear in the backend: vault meta only (salt, iter, verifier[, restored])
```
`EncryptedStore` re-checks `closed` after every `await`, so a lock racing a write never
encrypts with zeroized keys.

### 4.2 idbstore.js
Browser only. `export class IdbBackend` has the same API as MemoryBackend (IndexedDB database
`sombra`, store `kv`).

A backend MAY expose `lockName: string`. The client then holds an exclusive Web Lock under
that name for the unlocked lifetime (§5.8). *Status: `IdbBackend` does not declare it yet.*

### 4.3 api.js (v2)
```js
export const USERNAME_RE = /^[a-z0-9_]{3,32}$/
export class ApiError extends Error { code; status }
export class ServerApi {
  constructor(baseUrl, { fetch, WebSocket } = {})   // ws URL derived (http→ws, https→wss) + '/ws'
  async getPow(purpose) ; async register(payload /*without pow*/, {onProgress, signal}) /* fetches+solves pow; retries once on bad_pow */
  async getIdentity(username) /* null if 404 */ ; async getBundle(username) /* null if 404 */
  async send(messages /*[{to, blob: b64u}]*/) -> results   // splits into ≤100 items / ≤20 MiB batches, each with its own send PoW
  connect({ username, sign /*async (bytes)->Uint8Array*/, onMessage, onStatus, onEvent }) -> { send(obj) -> boolean, close(), connected }
     // auto-reconnect with exponential backoff (1 s..30 s) + CSPRNG jitter until close();
     // NO reconnect after close 4004 (deleted) or 4005 (replaced): emits onEvent({t:'closed', code})
}
```
Requests use `fetch` with `credentials:'omit'`, `cache:'no-store'`,
`referrerPolicy:'no-referrer'` and `redirect:'error'`. Send requests use a **separate** code
path from the authenticated socket. In v2 the client calls `send()` with **one message per
call** (§5.4), so each envelope travels in its own HTTP request with its own PoW.

### 4.4 client.js: `SombraClient`, the only API the UI uses (v2)
```js
export const MAX_FILE_BYTES = 8 * 1024 * 1024
export class SombraClient extends EventTarget {
  constructor({ serverUrl, backend, kdfIterations /*tests*/, fetch, WebSocket, now /*tests*/, privacy })
  static async hasAccount(backend) -> boolean
  setPrivacyOptions({ deliveryReceipts, readReceipts, receiptDelayMs:[min,max], identityDelayMs:[min,max], sendJitterMs })   // (v2)
  async createAccount(username, passphrase, { onProgress } = {})  // keys, register (PoW), vault, connect
  async unlock(passphrase)            // throws Error('bad passphrase') | Error('open_elsewhere') (v2) | Error('locked') if lock() ran meanwhile (v2)
  lock()                              // close socket, drop + zeroize keys/state, release account lock
  get username ; get connected ; get unlocked
  async listConversations() -> [{ id, type:'direct'|'group', title, peer?, members?, admin?, left?, lastText, lastTs, unread, timer, verified, keyChanged }]
  async getMessages(convId) -> [{ id, convId, from, mine, ts, kind:'text'|'file'|'system', text?, file?: {name, mime, size, data /*Uint8Array*/}, status:'sending'|'sent'|'delivered'|'read'|'failed', expiresAt?, keyChanged? }]
  async startDirect(username) -> convId           // throws Error('user_not_found: <u>') | Error('cannot_message_self')
  async deleteConversation(convId)                // local only
  async sendText(convId, text) -> message         // ≤ 65 536 chars
  async sendFile(convId, { name, mime, bytes })   // ≤ 8 MiB; > 3 MiB is chunked (§5.2)
  async markRead(convId)                          // queues E2E read receipts (delayed, §5.2)
  async deleteMessages(convId, ids, forEveryone)
  async setTimer(convId, seconds)                 // disappearing messages, 0 = off, ≤ 365 d
  async createGroup(name, usernames) -> convId
  async addGroupMembers(convId, usernames) ; async leaveGroup(convId)
  async getSafetyNumber(username) -> { number, formatted, verified, keyChanged }
  async setVerified(username, verified)           // verified=true also clears keyChanged
  async acceptKeyChange(username)                 // pins the identity the user was shown (CL-12)
  async exportBackup() -> Uint8Array              // utf8(JSON {format:'sombra-backup', v:1, records})
  static async importBackup(backend, bytes)       // §5.7
  async deleteAccount()               // server (WS delete_account, 15 s timeout) + local wipe
  async panicWipe()                   // lock() + backend.clear(), immediate, works while locked
  // events (CustomEvent, detail): 'message' {convId, message} ; 'update' {convId, messageId?} ;
  //   'conversations' {} ; 'status' {connected} ; 'keychange' {username} ; 'error' {message}
  //   error messages include 'replaced' (another instance took over → this one locked) and 'auth_failed'
}
```
Conversation ids: direct `d:<username>`, group `g:<gid>`.

Concurrency:
- Every mutation of persistent state runs inside `_serial()`, a promise-chain mutex bound to
  an unlock *generation*. Operations queued before a `lock()` fail with `Error('locked')`.
- **(v2, CL-9)** `unlock()` and `createAccount()` capture the generation. If `lock()` runs
  during the KDF, the pending activation is abandoned and its keys are zeroized.

## 5. Messaging protocol

### 5.1 Ratchet wire message (bytes = utf8(JSON)), inside the sealed envelope
```json
{ "v":1, "type":"prekey"|"msg",
  "x3dh": { "ik_sig","ik_dh","ik_dh_sig","ek","spk_id","opk_id" },   // only when type=="prekey"
  "header": {"dh","pn","n"}, "ct": "b64u" }
```
- The initiator sends `type:"prekey"` on **every** message until it receives the first
  message from the peer on that session (`peerConfirmed`). After that it sends `type:"msg"`.
- **(v2, CRYPTO-9)** Receivers accept only **canonical** X25519 encodings for `header.dh`,
  `x3dh.ek` and `x3dh.ik_dh`:
  - b64u round trip;
  - top bit of byte 31 clear;
  - `u < 2^255-19`.

### 5.2 Application payload (ratchet plaintext = pad(utf8(JSON))) (v2)
```json
{ "id":"b64u(16 random)", "ts": 1731400000000, "kind": "...", "body": {...},
  "group": "gid" (optional), "expire": seconds (optional, 1..31536000) }
```
Kinds:

| Kind | Body | Notes |
|---|---|---|
| `text` | `{text}` | 1..65 536 chars |
| `file` | `{name, mime, size, data:b64u[, part:{fid, i, n}]}` | Files > 3 MiB are sent as `n` = 2..64 chunk payloads, each with its own `id`, a shared `fid` (= the sender's message id) and ≤ 3 MiB of data. Name and MIME are sanitised on receipt. |
| `receipt` | `{ids:[...] (≤1000), status:"delivered"\|"read"}` | |
| `delete` | `{ids:[...] (≤1000)}` | |
| `timer` | `{seconds}` | |
| `group_update` | `{group:{id, name, members:[...], admin, creator, salt}}` | **(v2, CL-4)** `creator`, `salt`: see §5.6 |
| `group_leave` | `{}` | |

Unknown kinds are ignored.

- **Receipts (v2, CL-1/SRV-01).** Receiving a stored `text` or `file` queues a `delivered`
  receipt (never for receipts themselves). `markRead` queues `read` receipts.
  - Receipts are **never sent from the receive path**. They are coalesced per
    `(recipient, group, status)` and flushed after an independent uniformly random delay
    (default **2–30 s**; persisted encrypted across lock, C2).
  - Each flush is encrypted inside `_serial()` and sent in its own request(s).
  - `setPrivacyOptions` can disable either kind or change the delay. The UI does not expose
    this yet.
- **Dedup (v2, CL-2/CL-11).** The dedup key is `<from>|<id>`, not the bare id.
  - `seen:<convId>` keeps the last 2000 keys.
  - A stored message from the same sender with the same id is a duplicate, even after `seen`
    eviction.
  - If the id collides with another sender's message (or our own), the incoming message gets
    a fresh local id and keeps the sender's id as `rid`. Receipts and deletions use `rid`.
    File data is stored per local id, so nobody can overwrite or delete another member's
    file.
- Clock skew: `ts` is informational only and is clamped to ≤ now on receipt.

### 5.3 Receiving algorithm (v2)
Incoming `msg` frames go into a bounded in-memory queue (≤ 10 000; overflow is not ACKed, so
the server redelivers). A pump processes **one message per `_serial()` turn and yields** to
the event loop between messages (CRYPTO-1).

1. `unseal` with the own identity DH key → `{from, inner}`. Require
   `from ∈ USERNAME_RE`, `from ≠ self`, `v == 1`, a well-formed header and a canonical
   `header.dh`.

2. **Cost pre-screen (CRYPTO-1).** For every candidate session, estimate the skipped-key
   derivations `ratchetDecrypt` would do **before** authenticating:
   - 0 for a skipped-key hit;
   - `n - nr` on the same chain;
   - `(pn - nr) + n` plus one DH step for a new ratchet key.

   Then:
   - Candidates costing more than `MAX_SKIP` (1000) are never tried.
   - **Previous** sessions are tried only if they cost ≤ 100.
   - Candidates are tried cheapest first (a DH step weighs 64).
   - For a fresh prekey session, `header.n > 1000` → drop.

3. If `type:"prekey"`:
   1. Validate `x3dh`, check canonical `ek` and `ik_dh`, and verify `ik_dh_sig`. The claimed
      identity is *trusted* only if it equals the pinned contact for `from`.
   2. If an existing responder session (current or previous) has the same `ek` and identity,
      decrypt with it.
   3. **Untrusted identity** (first contact, or different from the pinned contact,
      CL-1/CRYPTO-5/CL-5): look for a parked session with that `ek` in `pend:<from>` and
      decrypt with it.
   4. Replay guard: an `ek` already answered (`session.eks`, or a parked `eks`) → drop.
   5. Quarantine bounds for untrusted senders: ≤ 64 senders, ≤ 3 claimed identities per
      sender.
   6. Run `x3dhRespond` with the SPK named by `spk_id` (the current SPK or one kept for
      30 days) and the OPK named by `opk_id`, using **AD v2 names**
      `{initiator: from, responder: self}`. Then `ratchetInitReceiver` and `ratchetDecrypt`.
      Any failure → drop.
   7. **Trusted:** insert the new session as current, pushing the old current into
      `previous` (max 3). Exception (simultaneous initiation): if the current session is an
      unconfirmed initiator session for the same identity with a smaller `ek`, it stays
      current. Then remember `ek` and delete the used OPK.
   8. **Untrusted:** **nothing about the contact changes.** The new session and the decoded
      payload are parked together in `pend:<from>` (≤ 100 payloads, ≤ 16 MiB). The used OPK
      is deleted, and a deferred confirmation is scheduled (step 7).

4. If `type:"msg"`: try the candidates from step 2. The first one that decrypts wins.

5. **Apply before commit (CL-10).** The payload is applied (§5.2) **before** the advanced
   ratchet state is persisted. An interruption in between leaves the message un-ACKed; on
   redelivery the old state decrypts it again and the `(from, id)` dedup drops the
   duplicate. A session that decrypts a message from the peer gets `peerConfirmed=true`.

6. Failure at any step → drop silently (no oracle), but still ACK.
   - Exceptions: transient errors, or the client was locked meanwhile. Then nothing is ACKed.
   - The ACK is sent only after the payload and state are persisted.

7. **Deferred identity confirmation (v2, CL-1/CRYPTO-5).** The client calls
   `GET /api/identity/<from>` **outside the mutex**, after a uniformly random delay (default
   1–10 s). On network errors it retries with backoff (2 s·2^attempt, ≤ 300 s); parked
   entries older than 7 days are then dropped.
   - If the server's identity matches a parked claim:
     - first contact → pin it;
     - different from the pinned contact → record a key change (§5.5);
     - then apply the parked payloads in order and move the parked sessions in.
   - Otherwise, everything parked for `from` is discarded, and its `eks` are remembered as a
     replay guard.

8. **Group messages:**
   - Accept only if `from` is in the group's member list.
   - Accept `group_update` only from the group admin.
   - For an unknown gid, accept only a *creation* that passes §5.6.
   - Drop content for a group the user has left.
   - Drop `text`/`file` for a group whose conversation was deleted locally (CL-7).

**Key change recording.** Applied only after authentication + server confirmation, or when
`/api/bundle` / `/api/identity` serve different keys for a known contact:
- update the pinned keys and set `verified=false`, `keyChanged=true`;
- add the system message *«El número de seguridad de @u ha cambiado.»* to the direct chat
  **and every shared group**;
- emit `keychange`.

Old sessions are **not** destroyed (CL-5). Sending to that user throws `key_changed` until
`setVerified(u, true)` or `acceptKeyChange(u)`.
- `acceptKeyChange` pins the identity stored in the contact. If the server now serves yet
  another identity, it records a new key change and throws `key_changed` (CL-12).
- It drops the sessions not bound to the accepted identity.
- Incoming messages stored while `keyChanged` carry `keyChanged: true`.

### 5.4 Sending (v2)
- **Direct:**
  1. Ensure a session. A new one is created (fetch bundle → `x3dhInitiate` with AD v2 names →
     `ratchetInitSender`) when there is no current session, or when the current session:
     - is bound to another identity than the contact;
     - belongs to an older account epoch (§5.7);
     - has no sending chain;
     - **`ratchetNeedsRekey`** is true (500 sends without a DH step, CRYPTO-2).
  2. Encrypt and **persist the advanced ratchet before** the ciphertext reaches the network.
  3. Wrap in the wire message, `seal(ownUsername, peer.ik_dh, inner)`, then `api.send`.
- A new session never reuses `previous`. The old current is pushed there for in-flight
  messages. Each rekey consumes one of the peer's OPKs.
- If the bundle's identity differs from the pinned contact → record a key change and throw
  `key_changed`.
- **Group (v2, CL-8/SRV-02):** pairwise fan-out to every member except self.
  - Each envelope is posted in **its own `/api/send` request** (own PoW), in **random order**,
    with an independent random delay of 0–250 ms (`sendJitterMs`) before each request after
    the first.
  - The server therefore never sees one request listing the member set.
- Content sends: the message is first stored as `sending`, then encrypted per recipient,
  then sent outside the mutex. The final status is `sent` if any recipient succeeded, else
  `failed`. Recipients that failed are removed from `to`.
- Prekey maintenance:
  - after `ready`, or `opk_count` with `n < 20` → generate and upload 100 new OPKs (private
    keys persisted first; ≤ 2000 kept locally; ids sequential from 1);
  - rotate the SPK every 7 days (checked on `ready` and in the sweeper); an unconfirmed
    rotation is re-sent on `ready`;
  - keep replaced SPKs 30 days after their `retiredAt`.
- Disappearing messages: each message carries `expire`. Both sides delete it `expire` seconds
  after send (sender) or receipt (receiver).
  - A sweeper runs every 5 s **while unlocked**. It also drops incomplete file chunks older
    than 24 h.
  - `getMessages` never returns expired messages.

### 5.5 Local storage records (all through EncryptedStore) (v2)
| Record | Content |
|---|---|
| `account` | `{username, identity(serialised), spks:[{id, keyPair, pub, sig, created, retiredAt?}], opks:{id: keyPair}, nextOpkId, nextSpkId, lastSpkRotation, epoch?}` |
| `contacts` | `{username: {ik_sig, ik_dh, verified, keyChanged, firstSeen}}` |
| `session:<username>` | `{current, previous:[≤3], eks:[≤200 answered ek]}`. Each session is `{role:'initiator'\|'responder', ek, ad, ik_sig, ik_dh, peerConfirmed, x3dh? (initiator), created, epoch, state}`. |
| `pend:<username>` (v2) | `{entries:[{ik, sessions:[≤4], eks, payloads:[≤100], bytes(≤16 MiB), created}]}`: unconfirmed identities (§5.3). |
| `pendidx` (v2) | `[username]`: senders with a `pend:` record (≤ 64). |
| `convs` | `{convId: {id, type, peer? \| group?, title, timer, unread, lastText, lastTs, nextExpiry?, created}}` |
| `msgs:<convId>` | `[message]`. Local messages also hold `to`, `rcpt`, `rid`, `expire`, `expiresAt`, `readSent`, `keyChanged`. |
| `file:<convId>:<localId>` | `{data: b64u}`: file bytes, outside the message list |
| `fparts` / `fpart:<convId>\|<from>\|<fid>:<i>` (v2) | Index of, and data for, incomplete chunked files. Quotas: ≤ 2 in flight per sender, ≤ 32 MiB reserved in total, 24 h TTL. |
| `groups` | `{gid: {id, name, members, admin, creator, salt, left}}` |
| `seen:<convId>` | `[<from>\|<id>]` (≤ 2000) |

All username- or id-keyed dictionaries are **null-prototype** objects with own-property
lookups (CRYPTO-6/CL-6). A username such as `__proto__` is just data.

### 5.6 Groups (v2)
- **Group id bound to the creator (CL-4):**
  `gid = b64u(SHA-256(utf8("SOMBRA-GID-v1") || u8(len(creator)) || utf8(creator) || salt16)[0..16))`.
- `group_update.group` carries `{id, name, members, admin, creator, salt}`.
- An update for an **unknown** gid is accepted only as a creation:
  - `admin == creator == from`;
  - the receiver is a member;
  - `salt` is 16 bytes;
  - `groupIdFor(from, salt) == gid`.
- Creation spam is bounded: ≤ 32 active groups per creator, ≤ 512 groups in total.
- Updates for a known gid are accepted only from the current admin. The binding
  (`creator`, `salt`) is kept from the stored group.
- Only the **creator**, while admin, can add members, because newcomers verify the binding.
  There is no member-removal API. An admin-sent `group_update` with a shorter member list
  removes members.
- `group_leave` removes the sender. If the admin leaves, the new admin is `members[0]`
  (deterministic, so no coordination is needed). The leaver forgets the group and its
  history locally.
- Names are cleaned on create and on receipt (BUG-2): C0/C1 controls, bidi
  marks/overrides/isolates, U+2028/2029, zero-width characters and BOM are replaced, and
  whitespace is collapsed. The result is ≤ 64 code points and must not be empty.
- File names are cleaned in the same way, with `/` and `\` replaced, up to 255 code points.
- ≤ 100 members per group.

### 5.7 Backup and restore (v2)
- `exportBackup()` returns `utf8(JSON {format:'sombra-backup', v:1, records:{backendKey: value}})`.
  The records are already encrypted, and the vault meta is included.
- `importBackup(backend, bytes)` validates the format and the meta, then clears the backend
  and writes every record (meta last). The meta is stored with **`restored: 1`**.
- **First unlock after a restore (CL-3/CRYPTO-4):**
  1. `account.epoch` is incremented;
  2. `lastSpkRotation = 0`, so the SPK rotates on the next `ready`;
  3. the account is saved;
  4. only then is the meta rewritten without `restored`.
- Every session created under an older epoch may still **decrypt**, but never **encrypts**.
  The next send to each peer starts a fresh X3DH session. This prevents (dh, n), and hence
  AES-GCM key+IV, reuse.
- Residual: OPKs uploaded after the backup was taken have no private key locally, so prekey
  messages using them fail. A backup must never be live on two devices.

### 5.8 Single live instance (v2, CRYPTO-3)
- If the backend exposes `lockName` and `navigator.locks` exists, `unlock()` and
  `createAccount()` request an exclusive Web Lock (`ifAvailable`) and hold it until `lock()`.
  If it is taken, they throw `Error('open_elsewhere')`.
- Independently, a WS close **4005 (replaced)** makes the client call `lock()` and emit
  `error {message:'replaced'}`. The API layer does not reconnect after 4004 or 4005.

## 6. UI (`public/index.html`, `public/css/app.css`, `public/js/ui/*.js`) (v2)
- **Layout.** Telegram-like:
  - sidebar: search / new chat by username, new group, and the conversation list with last
    message preview, time and unread badge;
  - main pane: header with name, lock icon and verify button; message bubbles with time and
    ticks (✓ sent, ✓✓ delivered, blue ✓✓ read); composer with file attach, Enter to send and
    Shift+Enter for a newline;
  - responsive: on mobile, a single pane with a back button. Flexible grid tracks use
    `minmax(0, 1fr)` (FIX-3). The direct-chat subtitle has a short variant on narrow screens
    (BUG-4).
- **Screens:**
  - welcome: create account (username + passphrase ×2, min 10 chars, strength hint, PoW
    progress), unlock, and restore backup;
  - main;
  - settings modal: export backup, auto-lock minutes (1, 2, 5, 10, 15, 30, 60; default 10),
    lock when hidden, hide previews, lock now, delete account, panic wipe, and "how Sombra
    protects you";
  - safety-number modal: 60 digits in 12 groups, «Marcar como verificado», «Aceptar nueva
    clave» on key change;
  - group creation modal;
  - disappearing timer menu: off, 30 s, 5 min, 1 h, 1 d, 1 w.
- **Composer queue (v2, BUG-1).** Sends are queued on one global promise chain, so they never
  overlap and order is kept. At most 20 can be queued or in flight; beyond that Enter is
  refused with a toast and the text stays in the composer. On failure, the queued texts for
  that conversation return to the composer. On lock, pending jobs are cancelled.
- **Security rules:**
  - never use `innerHTML`, `insertAdjacentHTML` or `outerHTML` with dynamic data (build the
    DOM with `createElement` + `textContent`);
  - no inline scripts, no inline event handlers and no `style=""` attributes in markup (CSP);
  - `blob:` URLs for images and downloads are revoked after use; SVG is offered as a download
    (`application/octet-stream`), not rendered;
  - no OS notifications; the tab title shows only the unread count;
  - auto-lock on idle (wall-clock based, re-checked on focus and visibility changes), a
    manual lock button and Ctrl+Shift+L;
  - key-change warning banner that blocks the composer;
  - dark theme by default.
- **(v2, FIX-2)** Peer-controlled titles, previews and system lines pass through
  `cleanDisplayText()`, which removes controls and bidi characters.
- UI preferences (never keys, usernames or message data) live in `localStorage` under
  `sombra.ui.*` and are cleared on panic wipe.
- Entry point: `<script type="module" src="js/ui/app.js">`;
  `new SombraClient({serverUrl: location.origin, backend: new IdbBackend()})`.

## Appendix A. Changes v1 → v2

| Area | Change | Findings |
|---|---|---|
| X3DH | AD v2 binds both usernames; no v1 fallback | CRYPTO-7 |
| Registration | `reg_sig` over `SOMBRA-REG-v1 ‖ u8(len) ‖ username ‖ ik_dh`; `409 identity_taken` for reused identity keys | CRYPTO-7 |
| Ratchet | pn-gap clamp; rekey after 500 one-way sends; skipped keys carry `t` and expire after 14 days | CRYPTO-2, CRYPTO-8 |
| Receive path | cost pre-screen (≤ 1000 derivations, previous sessions ≤ 100); yielding pump; canonical X25519 checks | CRYPTO-1, CRYPTO-9 |
| Identity | authenticate before any contact change; parked `pend:` sessions; deferred, delayed `/api/identity`; old sessions kept; warnings in groups; `acceptKeyChange` pins what was shown | CRYPTO-5, CL-1, CL-5, CL-12 |
| Receipts | coalesced, random delay, optional; never in the receive path | CL-1, SRV-01 |
| Group fan-out | one request per envelope, shuffled, jittered | CL-8, SRV-02 |
| Groups | gid bound to the creator; creation checks; quotas | CL-4, CL-7 |
| Dedup / files | `(from, id)` dedup; local ids unique per conversation; `rid` | CL-2, CL-11 |
| Persistence order | payload applied before ratchet commit; ACK after both | CL-10 |
| Lock races | generation checks in unlock/createAccount; 4005 → lock; optional Web Lock | CL-9, CRYPTO-3 |
| Backup | `restored` flag → epoch bump, no encryption from restored sessions, immediate SPK rotation | CL-3, CRYPTO-4 |
| Dictionaries | null-prototype maps, own-property lookups | CRYPTO-6, CL-6 |
| Storage quotas | chunked-file and group-creation quotas; drop content of deleted groups | CL-7 |
| Server memory | global body budget, idle timeout, per-address in-flight cap, JSON token bound, PoW before blob decode | SRV-03 |
| Server queue | envelope validation, global queue quota, register PoW 22 bits | SRV-04, BUG-3 |
| Rate limiting | IPv6 expansion, /48 aggregate, evict-oldest | SRV-05 |
| Bundles | per-target OPK budget (50/h) | SRV-06 |
| DB at rest | `WITHOUT ROWID`; per-recipient random-walk queue rowids | SRV-07 |
| WebSocket | unauth caps with eviction, 5 s auth, backpressure + stall timeout | SRV-08, SRV-09 |
| Cross-site | `Sec-Fetch-Site` / `Origin` refusal on `/api/*` and `/ws` | SRV-10 |
| Names | control/bidi stripping of group and file names (core + UI) | BUG-2, FIX-2 |
| UI | ordered composer queue; mobile layout; subtitle/day-pill fixes | BUG-1, BUG-4, FIX-1, FIX-3 |

## 8. Post-review amendments (v2.1)

- **`resync` (C→S, WebSocket).** `{t:"resync"}` asks the server to rewind the connection's
  flush cursor and re-send every un-ACKed queued message. The server honours at most one per
  10 s per connection; the client waits ≥ 11 s between requests. Clients send it after a
  bounded local buffer (prekey quarantine, held payloads) frees space: when those buffers are
  full the message is **not ACKed** (it stays queued) instead of being dropped (VC-1, VC-2).
- **Held payloads (CL-5/VC-2).** A contact record on hold keeps `heldPrevIk` (the identity
  the user had verified). Payloads authenticated by a session bound to `heldPrevIk` are
  delivered normally; only traffic from the new identity is held.
- **Verification binding (VC-3).** `setVerified(u, true, expectedNumber)` and
  `acceptKeyChange(u, expectedNumber)` throw `key_changed` if the pinned identity no longer
  yields the safety number the user compared.
- **Chain step (VC-4).** `KDF_CK` uses a synchronous HMAC-SHA256 (same output as §2.5).
  A prekey message that would create a new session is dropped before any key derivation if
  `header.n > 100`.
- **Queue fair share (APP-2).** When the global queue quota is exhausted, a recipient whose
  queue is below `QUEUE_RESERVED_BYTES` (32 MiB) gets room by evicting the oldest messages
  of the largest queue (which must itself be above the reserve).
- **Group fan-out (APP-1).** At most 4 concurrent `/api/send` requests per logical message;
  `rate_limited`, `busy` and network errors are retried with exponential backoff (≤ 6 tries).
