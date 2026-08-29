# Secure P2P Transport for z23 — protocol reference

This is the protocol contract for the Noise-encrypted transport
(`lib/net/src/noise_transport.c`, `lib/noise/src/noise_handshake.c`), which is
implemented and armed as INITIATOR in `lib/net/src/net.c` / torn down in
`lib/net/src/connman.c`, default OFF pending rollout (see [`os/A4-noise-transport-p1.md`](./os/A4-noise-transport-p1.md)
for rollout status). No consensus code is touched by this transport; the
parity firewall below is the invariant that keeps it that way.

## 1. Overview & goals

z23 P2P links are today plaintext, unauthenticated TCP. The v1 message
checksum (`nChecksum` in `struct msg_header`, first 4 bytes of double-SHA256 of
the payload, `lib/net/include/net/protocol.h`) detects corruption, not tampering
— it is unkeyed and forgeable by anyone on-path. This document specifies an
opt-in, authenticated, forward-secret transport ("Noise") that wraps the byte
stream between two consenting z23 peers while leaving message semantics,
the v1 wire format, and consensus behavior byte-for-byte unchanged.

Goals:
- Confidentiality + cryptographic integrity of the whole P2P byte stream between
  two Noise-capable peers (closes the documented plaintext gaps: ZMSG off-chain
  channel, ZMarket `zfile*` messages, `inv`/`tx`/`block`/`addr` reconnaissance).
- Forward secrecy: session keys derived from per-session ephemeral X25519 keys;
  compromise of long-term state does not expose past sessions.
- Mutual implicit authentication via persistent static X25519 identities
  (Noise-style), with TOFU pinning in addrman for MITM detection on reconnect.
- Zero new external dependencies — reuse only in-tree C23 crypto.
- Provable consensus parity and unconditional `zclassicd` interoperability.

Non-goal note up front: this is defense-in-depth for clearnet links. The
embedded Tor onion service (`lib/net/src/onion_service.c`,
`lib/net/src/tor_integration.c`) remains the stronger anti-fingerprinting /
network-anonymity control; Noise does not replace it.

## 2. Non-goals & the parity firewall

Non-goals:
- No traffic-analysis resistance beyond what Tor already gives (no mandatory
  ellswift encoding, no garbage/decoy padding in v1 — deferred to an optional
  Phase, §12). We are adding confidentiality/integrity to an already-versioned
  protocol between consenting peers, not evading DPI on the open internet.
- No PKI, no certificates, no signing. The tree has **no X25519/Ed25519 signing
  primitive** (`lib/crypto/include/crypto/ed25519.h` is verify-only), so
  authentication MUST be by DH (Noise implicit auth), never by signature.
- No metadata protection (packet timing/size/graph) against a global observer.
- No protection against malicious-but-authenticated peers (bad blocks, spam,
  bad tips) — that stays the job of consensus validation and peer scoring.

The parity firewall (inviolable — see `docs/CONSENSUS_PARITY_DOCTRINE.md`):
the transport layer sits strictly BELOW `net_message_read_header` /
`net_message_read_data` and ABOVE the raw socket. It transforms bytes only. The
plaintext handed to `p2p_node_receive_bytes` after decryption is byte-identical
to what a v1 peer would have sent raw; the ciphertext is produced from the exact
24-byte `struct msg_header` + payload that `p2p_node_end_message` already
assembles. Message command strings, `nMessageSize`, checksum semantics, the
`g_msg_dispatch` table (`lib/net/src/msgprocessor.c`), the eight reducer stages,
script/Groth16/PHGR13/Equihash verification — none of them can observe whether a
byte arrived plaintext or decrypted. Two honest nodes reaching different tips
because one used v1 and one used Noise is therefore structurally impossible: no
validity logic inspects transport mode.

Things that WOULD break parity and are forbidden:
- Any consensus/relay-acceptance decision conditioned on transport mode.
- Changing `msg_header`, `MESSAGE_START_SIZE`, `pchMessageStart` (network
  magic — chain selection), `MAX_SIZE`/`MAX_PROTOCOL_MESSAGE_LENGTH`, or
  `PROTOCOL_VERSION`/`MIN_PEER_PROTO_VERSION` for v1 connections.
- Using the AEAD tag as a substitute for the v1 double-SHA256 checksum on the
  plaintext v1 path.
- Treating "peer completed a Noise handshake" as a substitute for
  `peer_scoring_record` / `PEER_OFFENCE_PROTOCOL_VIOLATION` checks
  (`lib/net/src/msg_version.c`).

## 3. Protocol spec — Noise_XX_25519_ChaChaPoly_SHA256

Chosen handshake: **Noise_XX** (mutual static transmission, mutual implicit
auth, full forward secrecy, works with ZERO pre-shared knowledge — matches
"dial an IP from addrman"). Pattern: `-> e` / `<- e, ee, s, es` / `-> s, se`
(1.5 RTT).

Suite hash = SHA-256 (the zero-new-crypto choice: `hmac_sha256_*` is already
complete and tested; a Noise suite cannot mix a BLAKE2s transcript hash with a
SHA-256 HKDF, so the whole suite is SHA-256). BLAKE2s-suite HMAC is deferred
(§12) and unnecessary — the KDF runs a handful of times per session.

Why not the alternatives (dialer usually does NOT know the responder's
static on a cold dial): Noise_IK/WireGuard is 1-RTT but REQUIRES the dialer
to already hold the responder's static, so it fails cold dial — **kept as an
opt-in fast-reconnect** once a peer's static is TOFU-pinned in addrman
(saves 0.5 RTT; needs an anti-replay window on msg1). Noise_XK has the same
cold-dial problem. BIP324's unauthenticated AKE fits Bitcoin's lack of peer
identity; z23 defines a persistent static identity, so discarding
auth would be strictly worse — we borrow BIP324's transport ideas (length
obfuscation, dropping redundant magic+checksum, garbage-tolerant detection)
on top of an authenticated Noise core, but only in later phases.

After a successful XX handshake, TOFU-pin the peer's static key in addrman. A
pinned static that later changes is flagged (KCI / MITM-on-reconnect anchor).

### Noise SymmetricState, instantiated on in-tree calls

State: `ck[32]` (chaining key), `h[32]` (transcript hash), running AEAD key
`k[32]`, 64-bit counter `n`.

Init:
```
h  = SHA256("Noise_XX_25519_ChaChaPoly_SHA256")
ck = h
MixHash(prologue)   // §5: network magic(4) ‖ transport_version(1) ‖ suite_id ‖ init_addr ‖ resp_addr
```

MixHash(data): `h = SHA256(h ‖ data)`.

MixKey(dh[32]): `(ck, temp_k) = HKDF2(ck /*salt*/, dh /*ikm*/); k = temp_k; n = 0`.

HKDF2(salt, ikm) — RFC 5869 extract-then-expand on HMAC-SHA256
(`hmac_sha256_init/_write/_finalize`):
```
prk = HMAC(salt, ikm)
o1  = HMAC(prk, 0x01)
o2  = HMAC(prk, o1 ‖ 0x02)
return (o1, o2)
```

EncryptAndHash(pt) → ct: `ct = chacha20poly1305_encrypt(pt, aad=h, nonce96(n), k); MixHash(ct); n++`.
DecryptAndHash(ct) → pt: MixHash(ct) FIRST (Noise order), then
`chacha20poly1305_decrypt(ct, aad=h, nonce96(n), k)`; tag failure aborts the
handshake (constant-time compare, `chacha20poly1305.c`).

`nonce96(n)` = `4×0x00 ‖ LE64(n)` (Noise ChaChaPoly layout) → the `nonce[12]`
argument.

Split() → transport keys:
```
(k_c2s, k_s2c) = HKDF2(ck, "")   // empty ikm
initiator: send=k_c2s recv=k_s2c ; responder: send=k_s2c recv=k_c2s
n_send = n_recv = 0
memory_cleanse(ck); memory_cleanse(k); memory_cleanse(all e/s scalars)  // support/cleanse.h
```

Two independent directional keys, two independent 64-bit counters. No key or
nonce is ever shared across directions.

### Per-step in-tree call sequence

Static identity (once, persisted 0600 at `{datadir}/v2_identity.key`):
```c
zcl_random_secret_bytes(s_priv, 32, "v2_identity");   // random_secret.h:41
curve25519_scalarmult_base(s_pub, s_priv);            // curve25519.h:18
```
Ephemeral (per session, both sides):
```c
zcl_random_secret_bytes(e_priv, 32, "handshake-eph");
curve25519_scalarmult_base(e_pub, e_priv);
```
msg1 `-> e`: send e_pub; MixHash(e_pub).
msg2 `<- e, ee, s, es` (responder computes, initiator mirrors):
send e_pubR; MixHash(e_pubR);
`dh(ee)=scalarmult(e_privR,e_pubI)`; check_nonzero; MixKey(ee);
`ct_s = EncryptAndHash(s_pubR)`; send;
`dh(es)=scalarmult(s_privR,e_pubI)`; check_nonzero; MixKey(es);
`ct_p = EncryptAndHash(payload2)`; send.
msg3 `-> s, se` (initiator computes, responder mirrors):
`ct_s = EncryptAndHash(s_pubI)`; send;
`dh(se)=scalarmult(s_privI,e_pubR)`; check_nonzero; MixKey(se);
`ct_p = EncryptAndHash(payload3)`; send.
Then Split(); transport frames begin.

`dh(out, sk, pk)` = `curve25519_scalarmult(out, sk, pk)` **plus the mandatory
all-zero reject wrapper** (§9 primitive #1) — the in-tree `scalarmult` returns
`true` even for low-order inputs that yield an all-zero shared secret
(`lib/crypto/src/curve25519.c`, no RFC-7748 §6.1 check).

## 4. Record / framing layer

Phase-1 framing (first cut — msgprocessor untouched): after Split(), the
transport wraps the ENTIRE existing 24-byte `struct msg_header` + payload as the
AEAD plaintext of one logical message. Because that plaintext is byte-identical
to today's wire message, `msgprocessor.c` / `net_message_read_*` semantics are
provably unchanged.

Wire frame:
```
[ 3-byte LE length L ] [ AEAD ciphertext, L bytes = inner_len + 16 tag ]
```
- `L` counts ciphertext incl. tag. 3 bytes ⇒ 16 MiB max ≥ `MAX_SIZE`.
- `chacha20poly1305_encrypt(inner, inner_len, aad, nonce96(n_send), send_key, ct)`,
  `aad = LE(epoch) ‖ 3-byte length` — binds length + rekey epoch into the tag,
  so truncation or epoch-splice fails auth.
- `n_send++` per frame; receiver enforces the exact next counter (TCP is
  in-order; any repeat or gap is a hard drop).

The 2048-byte MAC-scratch cap (`chacha20poly1305.c:270`) is the one hard
constraint on frame size. With a 32-byte AAD the one-shot AEAD caps plaintext at
≈2000 bytes/call, but blocks reach 2 MiB (`MAX_PROTOCOL_MESSAGE_LENGTH`,
`lib/net/include/net/net.h`). Two options:
- **v1 chunking (no new crypto):** split any inner message > `FRAME_MAX`
  (set `FRAME_MAX = 1536` plaintext, safely under 2048 − AAD) into N sequenced
  frames with a 1-byte `CONT`/`FINAL` inner flag; the receiver reassembles the
  full `msg_header`+payload before handing it to `net_message_read_header`. Cost
  ~1.3% overhead + more AEAD calls.
- **Noise streaming AEAD (recommended, one small refactor):** add
  `poly1305_init/update/final` + a streaming `chacha20poly1305` (the block
  function `chacha20_block` and `poly1305_mac` already exist to build on) so a
  full ~2 MiB message is one frame and the chunking logic disappears.

Cap decrypted inner length at `MAX_PROTOCOL_MESSAGE_LENGTH` BEFORE allocating
the recv buffer, and route the encrypted path through the existing
`net_recv_total_bytes_cap()` budget so it inherits the same process-wide memory
ceiling and cannot be a memory-DoS vector.

## 5. Net integration seams (file:line, verified)

Two byte-stream seams, both BELOW the message layer and cleanly separable from
socket I/O. Insert transport transforms here and nowhere else.

WRITE seam — `lib/net/src/net.c`:
- A message is assembled plaintext into the `_Thread_local` staging buffer
  `tls_msg_stream` by `p2p_node_begin_message` (`net.c:647`) /
  `p2p_node_end_message` (`net.c:668`). Note: "tls" = thread-local storage
  (`_Thread_local struct byte_stream tls_msg_stream`, `net.c:644`), NOT
  transport security — there is no existing TLS.
- The finished frame `buf = tls_msg_stream.data`, `total = tls_msg_stream.size`
  becomes a queued segment at **`net.c:707`**: `send_segment_create(buf, total)`.
- **Encrypt at `net.c:707`, immediately before `send_segment_create`** — when
  `node->transport` is established, transform `buf[0..total)` into one
  length-prefixed AEAD packet and build the segment from the ciphertext. Do NOT
  encrypt inside `socket_send_data` (`net.c` ~734): that function partial-drains
  via `node->send_offset` and would split an AEAD packet mid-tag.
  `socket_send_data` stays a pure byte-pump, zero change.

READ seam — `lib/net/src/connman.c`:
- Raw bytes read at **`connman.c:1332`** (`recv(target_fd, buf, recv_cap,
  MSG_DONTWAIT)`) and handed to the framing accumulator
  `p2p_node_receive_bytes(node, buf, n, cm->manager.message_start)` at
  **`connman.c:1334`**.
- **Decrypt between `connman.c:1332` and `:1334`.** For an established Noise peer,
  feed `buf[0..n)` to `noise_transport_decrypt()`, which appends to a
  transport-owned ciphertext accumulator (needed because `recv` returns
  arbitrary counts — a packet may span recvs, exactly like the existing v1
  accumulator inside `p2p_node_receive_bytes`, `net.c:430`), peels complete AEAD
  packets, and emits zero-or-more decrypted v1 frames; then call the unchanged
  `p2p_node_receive_bytes()` on the plaintext. For a v1 peer
  (`node->transport == NULL`) the call is unchanged.

Per-connection state — add exactly ONE field to `struct p2p_node`
(`lib/net/include/net/net.h`, near the end of the struct):
```c
struct noise_transport *transport;   /* NULL = plaintext v1 (zclassicd) peer */
```
`p2p_node_create` (`net.c:291`) uses `zcl_calloc`, so this zero-inits to NULL
(v1) with no init edit. Add a teardown in `p2p_node_free`.

Everything else lives in a NEW translation unit `lib/net/src/noise_transport.c` +
`include/net/noise_transport.h`, holding:
```c
struct noise_transport {
  enum noise_hs_state state;      // NOISE_DETECT/NOISE_KEY_SENT/NOISE_KEY_RECV/NOISE_ESTABLISHED/NOISE_FAILED
  bool     is_initiator;
  uint8_t  eph_priv[32], eph_pub[32], peer_pub[32];
  uint8_t  send_key[32], recv_key[32];
  uint64_t send_seq, recv_seq;
  uint32_t epoch_send, epoch_recv;
  /* Noise ck[32], h[32], k[32], n during handshake */
  /* ciphertext recv accumulator (buffer + len) for partial packets */
};
```
Static identity lives on `struct net_manager` (`net.h`): add
`uint8_t identity_priv[32], identity_pub[32];`, loaded once in `connman_start()`
right where the magic/local-services are set (`connman.c` ~1828-1831) from
`{datadir}/v2_identity.key` (datadir is on the connman config, `connman.h`),
generated on first boot and persisted 0600.

Total edited call sites (all thin):
1. `net.h` — 1 field on `struct p2p_node`; identity fields on `struct net_manager`.
2. `net.c:707` — encrypt-before-`send_segment_create` when established.
3. `connman.c:1332-1334` — detect/handshake/decrypt before `p2p_node_receive_bytes`.
4. `net.c` ~914 (after `p2p_node_create` in `connect_node`) + ~1521 (after create
   in `accept_connection`) — `noise_transport_begin(node, nm)` setting
   `is_initiator = !inbound`.
5. `connman.c` ~1828-1831 — load/generate identity into `nm`.
6. Outbound gating — read addrman `nServices` (already learned at
   `msg_version.c:228`); expose a lookup.

Unchanged: `socket_send_data` (`net.c` ~734), `p2p_node_receive_bytes`
(`net.c:430`), the `enum peer_state` machine and `peer_set_state_checked`
(`event.h`), the `g_msg_dispatch` table and every handler (`msgprocessor.c`).
~2 struct fields + 4 call-site edits + 1 new TU.

## 6. Negotiation & zclassicd interop

Capability signal: reuse the existing service-bit pattern. `NODE_ZCL23 =
(1<<10)` (`fast_sync.h:27`) is the zcl23-vs-zclassicd discriminator, advertised
in `msg_version_build` (`ver->services = NODE_NETWORK | NODE_ZCL23`,
`msg_version.c:244`), learned into addrman at `msg_version.c:228`, set on the
peer at `msg_version.c:393`. Add a dedicated Noise bit (mirroring `NODE_BOOTSTRAP =
(1<<24)`, `protocol.h:25`), e.g. `NODE_NOISE_TRANSPORT`, advertised the same way.

Because the plaintext capability bit alone is downgrade-strippable, negotiation
uses a BIP324-style pre-`version` handshake gated so zclassicd never sees it.
Transport handshake state lives in `struct noise_transport`, NOT in
`enum peer_state`, so the validated message-layer transitions are untouched.

Initiator = outbound (`connect_node`, `net.c` ~886/914):
1. If addrman `nServices(addr) & NODE_ZCL23` (or a pinned "Noise-seen" flag) →
   allocate `node->transport`, `is_initiator = true`; queue our 32-byte
   ephemeral X25519 pubkey as the first raw segment; state `NOISE_KEY_SENT`.
   Else `transport = NULL` → existing plaintext path (any zclassicd or
   unknown-service peer stays v1 — zero interop risk).
2. On first recv: read peer ephemeral pubkey → run the Noise XX handshake (§3).
   The very first application message is already `push_version`
   (`msgprocessor.c` ~1765, guarded by `!node->inbound && send_bytes == 0`), so
   it now flows encrypted with no ordering change.

Responder = inbound (`accept_connection`, `net.c` ~1462/1521): allocate
`node->transport`, `is_initiator = false`, state `NOISE_DETECT`. On the first recv
peek 4 bytes:
- `== message_start` (the fixed network magic on the manager,
  `MESSAGE_START_SIZE`, set `connman.c` ~1828) → a v1 zclassicd peer: free
  `node->transport`, feed bytes to the plaintext path. This is the ONLY drop to
  plaintext and it requires the peer to literally speak v1 magic.
- else → a Noise initiator: consume its ephemeral pubkey, run XX, state
  `NOISE_ESTABLISHED`.

zclassicd interop is preserved by construction: zclassicd never gets the Noise
bit, never sends the pre-magic ephemeral key, and always matches the 4-byte
magic
peek → it stays on the untouched v1 path. A zcl23↔zclassicd connection is
bit-for-bit identical to today.

Downgrade resistance:
- Transcript binding: session keys derive from the DH outputs mixed with `h`
  over ALL handshake bytes (§3 prologue + MixHash chain). Any MITM tamper yields
  divergent keys → the first AEAD frame fails auth → disconnect. There is no
  unauthenticated negotiation field to strip.
- Inbound plaintext/Noise fork is a fixed-constant compare against the 4-byte
  magic; a Noise ephemeral pubkey colliding with the magic is ~2⁻³² (initiator
  re-rolls).
- Residual first-contact gap: outbound Noise is gated on addrman-advertised
  `NODE_ZCL23`, learned from unauthenticated gossip — a MITM controlling that
  gossip could clear the bit to force v1. Mitigate with (i) a persistent
  "Noise-seen" pin per address (HSTS-style: never downgrade a peer previously
  reached on Noise) and (ii) the static-identity TOFU pin. This is the same
  ephemeral-only first-contact limit BIP324 acknowledges; note it, don't
  over-engineer the MVP.

## 7. Key management (static identity, memory-locking, zeroization)

- Static identity: 32-byte X25519 seed at `{datadir}/v2_identity.key`, 0600,
  generated on first boot via `zcl_random_secret_bytes(priv, 32, "v2_identity")`
  and `curve25519_scalarmult_base(pub, priv)`. Loaded once into
  `struct net_manager` in `connman_start()`.
- Ephemeral keys: fresh per session via `zcl_random_secret_bytes(...,
  "handshake-eph")` — the CSPRNG rejects all-zero output (guards the
  urandom-open-fails → key=0 class).
- Zeroization: `memory_cleanse` (`lib/support/include/support/cleanse.h`) all
  ephemeral scalars, `ck`, `k`, and DH outputs at Split() and on handshake
  abort; cleanse transport keys in `p2p_node_free`.
- Memory-locking: consider `mlock` on the static-key buffer and the
  `struct noise_transport` key material to keep secrets out of swap (open
  question §13 — confirm the platform posture and existing `mlock` usage before
  adopting).
- Rekey / forward ratchet: rekey a direction after 2²⁰ frames OR 1 GiB on that
  key, whichever first, independently per direction. REKEY =
  `k_next = first32(chacha20poly1305_encrypt(k, nonce96(2^64-1), aad="",
  32×0x00))`; `n = 0; epoch++`. `epoch` is in the transport AAD (§4) so a
  pre-rekey frame can never be replayed post-rekey. Compromise of the current
  key does not expose pre-rekey traffic.

## 8. Threat model (vs Tor)

Baseline: many zcl23↔zcl23 links are clearnet TCP, plaintext, unauthenticated;
the v1 checksum is unkeyed (forgeable on-path). Tor (opt-in `-tor`, requires the
real `vendor/tor` build) already gives confidentiality + endpoint auth (the
.onion IS the destination key) + network anonymity for links routed over it.

What Noise adds for clearnet (non-Tor) links:
- Defeats PASSIVE eavesdropping completely — every `inv`/`tx`/`block`/`addr`/
  `zmsg`/`zfile*` becomes ciphertext to an on-path observer.
- Cryptographic (keyed) integrity — an on-path tamperer without the session key
  cannot forge an accepted payload; tamper surfaces as an AEAD auth failure →
  disconnect, not a silent corruption warning.
- ACTIVE MITM: fully defeated on RECONNECT via the addrman static-key TOFU pin;
  on FIRST contact an attacker who terminates both handshake legs independently
  can still relay (no out-of-band identity) — the honest residual, same as
  BIP324. Do not oversell as full MITM resistance until pinning ships.
- Removes a cheap passive eclipse-assist recon channel (peer graph / versions /
  heights readable in plaintext today).

What Noise does NOT protect against (must not be oversold):
- Metadata to a global observer (packet timing/size/graph) — only Tor's circuit
  routing addresses this, and only for onion-routed links.
- Malicious-but-authenticated peers (bad blocks/tips/spam) — consensus
  validation + `peer_scoring_record` still own this.
- Consensus attacks (51%/selfish-mining/reorgs) — orthogonal; Noise lives below the
  dispatch/reducer boundary and has zero bearing on chain selection.
- Endpoint compromise (keys/wallet/binary) — protects data in transit between
  two honest endpoints only.

## 9. Consensus-parity confirmation

Grounded in code:
- Consensus validity is defined by the eight reducer stages reading `progress.kv`
  (`docs/HOW_THE_NODE_WORKS.md`), driven by `reducer_frontier.c` — they consume
  already-deserialized, already-stored block/tx data, never live socket bytes.
- `g_msg_dispatch` (`msgprocessor.c`) keys purely on the 12-byte command string
  parsed from `struct msg_header` and hands handlers a `struct byte_stream *`
  payload; `net_message_read_data` (`net.c`) strips framing before any handler
  runs. The transport layer sits strictly below `net_message_read_header` /
  `net_message_read_data`.
- Keys/nonces/session state are never derived from and never feed into
  block/tx validity, script eval, Equihash, or Sapling/Sprout proofs.
- The v1 path (`msg_header`, `pchMessageStart` check, checksum) is byte-identical
  to today for any `transport == NULL` peer → zclassicd parity holds
  unconditionally.

Required-now hardening (does not affect parity): the all-zero DH-output reject
wrapper around `curve25519_scalarmult` (the base function never checks —
`lib/crypto/src/curve25519.c`).

## 10. Missing primitives to write in C (no external deps)

1. **All-zero DH-output reject wrapper** around `curve25519_scalarmult` —
   REQUIRED. ~5 lines, constant-time OR-accumulate of the 32 output bytes,
   reject if zero (RFC 7748 §6.1).
2. **RFC-5869 HKDF (2/3-output) on HMAC-SHA256** — ~20 lines over the complete
   `hmac_sha256_init/_write/_finalize`. No new hash primitive needed for the
   SHA-256 suite.
3. **Streaming AEAD** (`poly1305_init/update/final` + streaming
   `chacha20poly1305`) — RECOMMENDED, lifts the 2048-byte MAC-scratch cap so a
   ~2 MiB block is one frame. ~120 lines built on the existing `chacha20_block`
   and `poly1305_mac`. If deferred, use v1 chunking (§4) which needs no new
   crypto.
4. **Infrastructure** (not crypto): persistent static-key load/save at
   `{datadir}/v2_identity.key` (0600); the `NODE_NOISE_TRANSPORT` service bit;
   `struct noise_transport` + `noise_transport.c`.

Already present with verified signatures: X25519 ECDH, ChaCha20-Poly1305 AEAD,
HMAC-SHA256, hardened CSPRNG, constant-time compare, `memory_cleanse`.

Deferred / not needed for v1: HMAC-BLAKE2s (only if switching to the BLAKE2s
suite — profiling will not justify it); length obfuscation + magic/checksum
field-dropping (Phase, §12).

## 11. Staged implementation plan

Each phase is independently landable and copy-proven on a datadir COPY before
any live deploy (`CLAUDE.md` Tenacity doctrine). `test_parallel` green is the
regression FLOOR, not a liveness proof. Phase 1 touches NO live connection path.

**Phase 0 — Static-key + Noise handshake primitives (pure library, no net edits).**
Add primitive #1 (all-zero DH reject), #2 (HKDF-SHA256), the Noise
SymmetricState routines (MixHash/MixKey/Encrypt/DecryptAndHash/Split), and the
`v2_identity.key` load/save. NO edit to net.c/connman.c/msgprocessor.c.
Gate: unit tests only — Noise_XX known-answer vectors (interop against a
reference Noise_XX_25519_ChaChaPoly_SHA256 test vector), HKDF2/HKDF3 RFC-5869
vectors, all-zero DH reject fires on a low-order point, `memory_cleanse` after
Split. Copy-prove: N/A (no datadir touched). `test_parallel` green with the new
TU compiled in. This is the small, first, independently-landable slice.

**Phase 1 — Transport session over the byte-stream seam, capability-gated OFF by
default.** Add `struct noise_transport`, `noise_transport.c`, the one `p2p_node` field,
the identity fields on `net_manager`, the encrypt-at-`net.c:707` and
decrypt-at-`connman.c:1332` seams, `noise_transport_begin` at the two create sites.
Framing = Phase-1 whole-header+payload wrap with v1 chunking (`FRAME_MAX=1536`)
— no new AEAD crypto. Negotiation bit defined but DEFAULT-DISABLED.
Gate: test matrix cases 1 (Noise↔Noise byte-identity round-trip — the actual proof of
correctness), 4 (tamper/AEAD reject → disconnect + score), 5 (handshake-DoS
bound). Copy-prove: run two nodes on datadir COPIES with the bit forced on;
assert both reach the same H* and identical tip hash vs a v1-only control run.
`test_parallel` green with the bit default-off (case 6).

**Phase 2 — Enable negotiation + zclassicd interop + downgrade handling.** Wire
the addrman `nServices`/`NODE_ZCL23` outbound gate + the inbound 4-byte-magic
plaintext/Noise peek + the persistent "Noise-seen" HSTS pin. Bit still opt-in via flag.
Gate: matrix cases 2 (Noise zcl23 ↔ v1 zclassicd plaintext fallback, diff vs golden
v1 capture for byte-identity), 3 (downgrade-attack rejection — both sub-cases:
graceful fallback to a real v1 peer vs hard-fail-closed on a stripped-bit real
Noise peer). Copy-prove: a zcl23 COPY syncing from the live local `zclassicd`
oracle (`~/.zclassic`, RPC 8232) with Noise enabled — proves interop is untouched
and H* still climbs. `test_parallel` green.

**Phase 3 — Streaming AEAD (remove the 2 KiB cap) + TOFU static-key pin.** Add
primitive #3 (streaming ChaCha20-Poly1305) → one frame per message, delete the
chunking path. Add addrman static-key TOFU pinning + the Noise_IK
fast-reconnect + pinned-static-changed MITM flag.
Gate: matrix case 1 re-run with a full 2 MiB block in a single frame; a new
"pinned static changed → flagged" test; IK fast-reconnect round-trip.
Copy-prove: two-node COPY soak passing real ~2 MiB blocks. `test_parallel` green.

**Phase 4 (optional, deferred) — BIP324-style obfuscation.** Length obfuscation
(XOR keystream from a `len_key` from Split, FSChaCha20 rekey) + optional
magic/checksum field-dropping behind an inner-format variant + optional
WireGuard cookie under load. Gate: matrix cases 1/4 re-run; a passive-observer
test asserting frame lengths are not readable. Owner-gated; not required for v1.

## 12. Interop / test matrix

All cases run against datadir COPIES, never the live node. Fixture template =
`lib/test/src/test_net_handshake_adversarial.c` (real `socketpair()` fd feeding
`p2p_node`, driving `process_version` / `msg_process_messages` with fixed-epoch
timestamps, no wall-clock reads); flood/DoS sibling =
`lib/test/src/test_net_msg_dos.c`.

| # | Case | Proven | Fixture | Phase gate |
|---|------|--------|---------|-----------|
| 1 | Noise↔Noise full encrypted round-trip | handshake completes, keys match, `version`/`verack`/`inv`/`tx`/`block`/`zmsg` round-trip byte-identical to the v1 plaintext path | two `p2p_node` over `socketpair()` both advertising the Noise bit; assert decrypted payload == parallel v1 control | P1 |
| 2 | Noise zcl23 ↔ v1 zclassicd plaintext fallback | a peer without the Noise bit stays pure v1, header/checksum/dispatch identical | fixture peer omitting the bit (like `msg_version_classify_peer` at `msg_version.c:389-393`); diff vs a golden v1 capture | P2 |
| 3 | Downgrade-attack rejection | stripped/flipped bit on a real Noise peer either detected+disconnected (bound negotiation) or hard-fail-closed when Noise is required; graceful v1 fallback is NOT a regression | two sub-cases: forced bit-strip vs no-prior-expectation fallback | P2 |
| 4 | MITM / tamper detection | one flipped bit (header/ciphertext/tag) → AEAD reject, connection torn down + scored, no half-decrypted state | reuse `chacha20poly1305_decrypt` tag-mismatch path; assert `peer_scoring_record` like `msg_version.c:309-314` | P1 |
| 5 | Handshake-DoS bound | garbage/partial/slow-loris handshakes cannot exhaust memory/CPU beyond a v1 flood; incomplete sockets reaped on a byte/time budget | extend `test_net_msg_dos.c`; assert bounded allocation + concurrent legit service + reaping | P1 |
| 6 | Parity/regression floor | `test_parallel` green with Noise compiled in but the bit default-off | full `test_parallel` on a build with the bit disabled (additive, like `NODE_ZCL23` fast-sync today) — necessary not sufficient; case 1 is the real correctness proof | every phase |

## 13. Open questions for the owner

1. Authentication scope for v1: ship ephemeral-only Noise_XX first (passive-safe,
   first-contact MITM residual), or block Phase 1 on the addrman static-key TOFU
   pin (Phase 3) to close active-MITM-on-reconnect before any deploy?
2. Suite choice: SHA-256 (zero new crypto, recommended) vs a later BLAKE2s
   switch — accept SHA-256 permanently?
3. Streaming AEAD now (Phase 3) vs shipping v1 chunking first — is the ~1.3%
   overhead + extra AEAD calls acceptable for an interim release?
4. Interaction with Tor: should Noise be auto-disabled for onion-routed peers
   (Tor already authenticates the endpoint) or layered anyway as defense-in-depth?
5. Memory-locking posture: adopt `mlock` on static-key + session-key buffers?
   Confirm existing platform `mlock` usage/limits first.
6. Service-bit allocation: confirm a free bit for `NODE_NOISE_TRANSPORT` (mirror
   `NODE_BOOTSTRAP = 1<<24`) that does not collide with any zclassicd-observed
   bit.
7. Downgrade policy default: HSTS-style "never downgrade a Noise-seen peer" — opt-in
   or default-on once Phase 2 lands?
