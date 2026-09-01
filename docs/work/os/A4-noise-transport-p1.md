# OS-A4 — Noise P1: the encrypted transport on the P2P byte stream

This is the implementation contract for `docs/work/secure-transport-design.md`'s
Phase-1 slice. Re-grep the anchor tokens (`send_segment_create(buf, total)`,
`recv(target_fd`) before editing — lines rot.

Built on `core/modules/noise/noise_handshake.{c,h}` (Noise_XX/_NK driver) and
`core/modules/noise/session_transport.{c,h}` (record layer: 3-byte-length ChaCha20-
Poly1305 frames, per-direction counters, epoch-in-AAD rekey), over
`core/modules/crypto/{x25519_safe,hkdf_sha256,chacha20poly1305,curve25519,hmac_sha256}`.
The transport is implemented and armed as INITIATOR in `core/modules/net/src/net.c`
(decrypted/torn down in `core/modules/net/src/connman.c`), default OFF pending
rollout.

## 0. The one structural invariant (why parity holds)

The transport transforms bytes ONLY, strictly BELOW `net_message_read_*` and
ABOVE the socket. A peer with `node->transport == NULL` (every zclassicd peer,
and every zcl23 peer until it negotiates) takes the EXACT current code path with
zero added branches on the hot bytes — the encrypt/decrypt calls are the taken
side of a single `if (node->transport)`. The plaintext handed to
`p2p_node_receive_bytes` after decrypt is byte-identical to what a v1 peer sent
raw, and the ciphertext is produced from the exact `struct msg_header` + payload
`p2p_node_end_message` already assembled. No consensus/relay/dispatch code can
observe transport mode. This is the load-bearing claim the byte-parity test (§7)
proves and the whole design rests on.

## 1. New translation unit — `core/modules/net/src/noise_transport.c` + `include/net/noise_transport.h`

All new logic lives here. It is a thin driver over Phase-0. `core/modules/net` already
lists `session` transitively via LIB_MODULES (both are in `Makefile:169-170`); add
`-Icognition/modules/session/include` reach is automatic (LIB_INCLUDES foreach). `noise_transport.c`
is picked up by the `core/modules/net/src/*.c` wildcard (`Makefile:173-174`) — no Makefile
source edit.

### 1.1 Public header `core/modules/net/include/net/noise_transport.h`

```c
/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * noise_transport — per-connection Noise_XX handshake driver + record wrapper that
 * sits between p2p_node's message framing and the raw socket. Plaintext peers
 * (transport==NULL) never reach this TU. See docs/work/secure-transport-design.md
 * and docs/work/os/A4-noise-transport-p1.md. */
#ifndef ZCL_NET_NOISE_TRANSPORT_H
#define ZCL_NET_NOISE_TRANSPORT_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "noise/noise_handshake.h"
#include "noise/session_transport.h"

struct p2p_node;
struct net_manager;

enum noise_hs_state {
    NOISE_DETECT = 0,      /* inbound: awaiting first 4 bytes (magic vs eph pubkey) */
    NOISE_KEY_SENT,        /* outbound: our msg1 (`-> e`) queued, awaiting `<- e,ee,s,es` */
    NOISE_KEY_RECV,        /* responder consumed msg1, msg2 queued, awaiting `-> s,se` */
    NOISE_ESTABLISHED,     /* Split() done; session_transport live */
    NOISE_FAILED,          /* abort: caller must drop the peer */
};

struct noise_transport {
    enum noise_hs_state state;
    bool is_initiator;
    struct noise_handshake hs;          /* live only DETECT..pre-ESTABLISHED */
    struct session_transport rec;       /* live only once ESTABLISHED */
    uint8_t peer_static[32]; bool have_peer_static; /* XX-learned; TOFU pin (Phase 2) */
    /* ciphertext recv accumulator: a session frame may span recv() boundaries */
    uint8_t  acc[SESSION_FRAME_MAX_WIRE];
    size_t   acc_len;
    uint64_t hs_started_us;             /* for the p99 bench + DoS reaping */
};

/* Allocate + arm a transport on `node`. is_initiator = !node->inbound.
 * Loads nothing global; uses nm->identity_priv. Sets node->transport.
 * Returns false (and leaves transport NULL = plaintext) only on OOM. */
bool noise_transport_begin(struct p2p_node *node, struct net_manager *nm);

/* WRITE seam. Seal one already-assembled v1 message (header+payload,
 * buf[0..total)) into >=1 session records appended to *out (heap, caller frees).
 * Splits at SESSION_MAX_PAYLOAD so a >1535B message becomes N DATA records; the
 * receiver's v1 accumulator reassembles them transparently. Returns false ->
 * node->transport->state=NOISE_FAILED, caller drops peer. */
bool noise_transport_seal(struct noise_transport *t, const uint8_t *buf, size_t total,
                       uint8_t **out, size_t *out_len);

/* READ seam. Feed raw recv bytes in[0..n). Drives the handshake while state <
 * NOISE_ESTABLISHED (queuing reply bytes to *hs_reply for the caller to send), and
 * once ESTABLISHED peels complete records, decrypts DATA channel bytes into
 * *plaintext (heap, caller frees, may be 0 bytes if a record is still partial).
 * Returns false on any AEAD/turn/DoS-budget failure -> caller drops peer. */
bool noise_transport_feed(struct noise_transport *t,
                       const uint8_t *in, size_t n,
                       uint8_t **hs_reply, size_t *hs_reply_len,
                       uint8_t **plaintext, size_t *plaintext_len);

/* Inbound-only first-bytes classifier: peek up to 4 bytes; returns true if they
 * equal the network magic (=> a v1 zclassicd peer; caller frees transport and
 * uses plaintext path). Only consulted in NOISE_DETECT. */
bool noise_transport_is_plaintext_magic(const uint8_t *first, size_t n,
                                     const unsigned char magic[4]);

void noise_transport_free(struct noise_transport *t);   /* cleanse + free */

/* Diagnostics: fill an object for one peer (mode/state/counters). */
struct json_value;
bool noise_transport_dump_peer(struct json_value *out, const struct noise_transport *t);
#endif
```

### 1.2 Implementation notes (noise_transport.c)

- **Handshake driver:** wrap `noise_hs_init(&t->hs, noise_pattern_xx(), is_initiator,
  prologue, prologue_len, nm->identity_priv, NULL)`. Prologue = `magic(4) ‖
  version_byte(1) ‖ suite_id`; MUST be byte-identical on both sides (§5 design).
  Drive with `noise_hs_write_message` / `noise_hs_read_message`; on
  `noise_hs_done` call `noise_hs_split(&t->hs, send_key, recv_key)` then
  `session_transport_init(&t->rec, send_key, recv_key)`, `memory_cleanse` the
  keys, set `NOISE_ESTABLISHED`, capture `noise_hs_remote_static` into `peer_static`.
- **Record wrapping (seal):** loop over `buf` in `SESSION_MAX_PAYLOAD`-byte
  slices, each `session_transport_encrypt(&t->rec, SESSION_CH_DATA, slice, len,
  frame, &flen)`, append `frame` to the growth buffer. NO CONT/FINAL flag needed
  — the receiver concatenates decrypted plaintext straight into the existing v1
  byte accumulator (`p2p_node_receive_bytes`, `net.c:431`), which already
  reassembles `msg_header`+payload across arbitrary boundaries. This is the whole
  reason chunking is invisible above the seam.
- **Record peeling (feed):** append `in` to `t->acc`; while `acc_len >= 3` and a
  full frame (`3 + le24(acc[0..3])`) is buffered, `session_transport_decrypt`
  it, require `channel == SESSION_CH_DATA`, append the plaintext to the caller's
  output, memmove the remainder down. `session_transport_decrypt` already
  fails-closed on tamper/replay/reorder (counter bound into nonce) — a false
  return is a hard drop.
- **DoS budget (Phase-1 case 5):** cap `acc_len` at `SESSION_FRAME_MAX_WIRE`
  (a longer un-decryptable frame is malformed → fail); cap pre-ESTABLISHED
  wall-time via `hs_started_us` (reap on a fixed budget in the connman idle
  sweep, mirroring existing prehandshake reaping).

## 2. Struct fields (the only edits to `net.h`)

`core/modules/net/include/net/net.h` — `struct p2p_node` ends at **:329**. Add before it:
```c
    struct noise_transport *transport;   /* NULL = plaintext v1 path (zclassicd) */
```
`p2p_node_create` uses `zcl_calloc` (`net.c:296`) → zero-inits to NULL, no init
edit. `struct net_manager` ends at **:410**; add before it:
```c
    uint8_t identity_priv[32], identity_pub[32];  /* persistent Noise static id */
    bool    noise_enabled;                           /* -noisetransport flag; default OFF in P1 */
```
Add `#include "net/noise_transport.h"` fwd via `struct noise_transport;` already
forward-declared — keep net.h free of the session includes (the pointer is opaque
here; the TU that touches it includes noise_transport.h).

## 3. WRITE seam — `core/modules/net/src/net.c:708`

Current (inside `p2p_node_end_message`, holding `node->cs_send`):
```c
708:    struct send_segment *seg = send_segment_create(buf, total);
```
Replace with the guarded form — plaintext path is the UNCHANGED else:
```c
    struct send_segment *seg;
    if (node->transport && node->transport->state == NOISE_ESTABLISHED) {
        uint8_t *ct = NULL; size_t ct_len = 0;
        if (!noise_transport_seal(node->transport, buf, total, &ct, &ct_len)) {
            stream_free(&tls_msg_stream); tls_msg_active = false;
            node->disconnect = true;
            zcl_mutex_unlock(&node->cs_send);
            LOG_FAIL("net", "Noise seal failed node id=%d", (int)node->id);
        }
        seg = send_segment_create(ct, ct_len);
        zcl_free(ct);
    } else {
        seg = send_segment_create(buf, total);   /* byte-identical v1 path */
    }
```
Do NOT touch `socket_send_data` (`net.c:735`): it partial-drains via
`send_offset` and must stay a pure byte-pump — sealing there would split an AEAD
tag. Pre-ESTABLISHED handshake bytes for the initiator are queued at
`noise_transport_begin` time (§5), not here.

## 4. READ seam — `core/modules/net/src/connman.c:1392`

Current (holding `node->cs_recv`, locked at :1369):
```c
1392:  ssize_t n = recv(target_fd, buf, recv_cap, MSG_DONTWAIT);
1393:  if (n > 0) {
1394:      if (!p2p_node_receive_bytes(node, buf, (unsigned int)n,
1395:                                  cm->manager.message_start)) {
```
Insert decrypt between :1392 and :1394. Plaintext path (`transport==NULL`) is
untouched:
```c
    ssize_t n = recv(target_fd, buf, recv_cap, MSG_DONTWAIT);
    if (n > 0) {
        const char *plain = buf; unsigned int plain_n = (unsigned int)n;
        uint8_t *dec = NULL, *hs_reply = NULL; size_t dec_len = 0, hs_len = 0;
        if (node->transport) {
            if (!noise_transport_feed(node->transport, (const uint8_t *)buf, (size_t)n,
                                   &hs_reply, &hs_len, &dec, &dec_len)) {
                connman_note_addnode_prehandshake_disconnect(cm, node, "noise-transport");
                node->disconnect = true; zcl_free(dec); zcl_free(hs_reply);
                goto after_recv;   /* new label just before the score/last_recv block */
            }
            if (hs_len) noise_queue_raw(node, hs_reply, hs_len); /* thin: send_segment on raw bytes */
            zcl_free(hs_reply);
            plain = (const char *)dec; plain_n = (unsigned int)dec_len;
        }
        if (plain_n && !p2p_node_receive_bytes(node, plain, plain_n,
                                               cm->manager.message_start)) {
            connman_note_addnode_prehandshake_disconnect(cm, node, "message-parse");
            node->disconnect = true;
        }
        zcl_free(dec);
after_recv: ;
        p2p_node_score_framing_offence(&cm->manager, node);
        node->last_recv = GetTime();
        node->recv_bytes += (uint64_t)n;   /* raw wire bytes, unchanged accounting */
        ...
```
`noise_queue_raw` = a 3-line helper appending a `send_segment_create` of raw
(un-sealed) handshake bytes to `node->send_*` under `cs_send`; needed because the
handshake messages precede any `session_transport` and must go out verbatim.

## 5. Handshake arming at the two create sites + identity load

- **Outbound initiator** — `connect_node`, after `p2p_node_create` at **net.c:915**
  (node is `inbound=false`). Gate on the addrman hint:
  ```c
  if (nm->noise_enabled && addrman_services_has(nm, &addr_connect->svc, NODE_NOISE_TRANSPORT))
      noise_transport_begin(node, nm);   /* is_initiator=true; queues msg1 `-> e` raw */
  ```
  `noise_transport_begin` for an initiator immediately produces msg1 via
  `noise_hs_write_message` and queues it raw (same `v2_queue_raw`), state
  `NOISE_KEY_SENT`. The first application message is already `push_version`
  (`msg_version.c:382`, outbound branch) → it now flows sealed with no ordering
  change.
- **Inbound responder** — `accept_connection`, after `p2p_node_create` at
  **net.c:1561** (`inbound=true`). Arm in `NOISE_DETECT` only when the flag is on:
  ```c
  if (nm->noise_enabled) noise_transport_begin(node, nm);  /* is_initiator=false, NOISE_DETECT */
  ```
  In `NOISE_DETECT`, `noise_transport_feed` first calls
  `noise_transport_is_plaintext_magic(in, n, nm->message_start)`: if the first 4
  bytes equal the network magic → free the transport, set `transport=NULL`, and
  replay the buffered bytes through the plaintext path (this is the ONLY drop to
  plaintext and it requires the peer to literally speak v1 magic — zclassicd
  always does). Else consume the peer ephemeral, run XX, queue msg2.
- **Identity** — load/generate `{datadir}/v2_identity.key` (0600) into
  `nm->identity_{priv,pub}` once in `connman_start` where the magic is set
  (`connman.c:1890`, `memcpy(cm->manager.message_start, params->pchMessageStart…)`;
  `connman_start` body at `:1903`). Generate on first boot via
  `zcl_random_secret_bytes(priv,32,"v2_identity")` +
  `curve25519_scalarmult_base(pub,priv)` (`curve25519.h`).

## 6. Negotiation in the version exchange (service bit)

- Add `NODE_NOISE_TRANSPORT = (1 << 25)` to the service-flags enum in
  `core/modules/net/include/net/protocol.h` (adjacent to `NODE_BOOTSTRAP = (1<<24)`,
  **protocol.h:25**; free — used bits are 0,2,10,24). Open question §9(1):
  confirm zclassicd ignores 1<<25 (it is in the zcl23-reserved high range, same
  family as the working NODE_BOOTSTRAP).
- Advertise it in `msg_version_build` beside the existing services OR at
  **msg_version.c:244** (`ver->services = NODE_NETWORK | NODE_ZCL23;`) →
  `| (nm->noise_enabled ? NODE_NOISE_TRANSPORT : 0)`. It is learned into addrman at the
  existing `learned.nServices = ver->services` (**msg_version.c:229**) and set on
  the peer at **msg_version.c:344** (`node->services = ver.services`). The bit is
  only a HINT for OUTBOUND gating; the authoritative INBOUND discriminator is the
  4-byte magic peek (§5), which no gossip can strip. Downgrade note: a MITM
  clearing the bit forces v1 (documented residual, same as BIP324); the HSTS
  "Noise-seen" pin closes it in Phase 2, out of scope here.

Default OFF: `nm->noise_enabled` is false unless `-noisetransport` is passed (add to the
argv loop next to existing net flags). Phase-1 lands dark — the byte-parity floor
(§7 case 6) is `test_parallel` green with the bit compiled but off.

## 7. Acceptance — the gates that prove it

All four are required by the plan's A4 bar (`think-more-about-our-keen-crown.md`
OS-A4). Tests are the load-bearing proofs; the parity claim is structural.

1. **Differential byte-parity test** — NEW `tests/harness/src/test_noise_transport_parity.c`
   (auto-collected, `Makefile:491-492`; add its group to the counts). Two
   sub-assertions: (a) with `noise_enabled=false`, drive a `p2p_node` over a
   `socketpair()` (fixture template `test_net_handshake_adversarial.c`) and assert
   the exact bytes `p2p_node_end_message` queues for `version`/`verack`/`inv`/`tx`/
   `block` are BYTE-IDENTICAL to a captured golden (the transport==NULL path is
   literally unchanged). (b) with `noise_enabled=true` on both ends, assert the
   plaintext delivered to `p2p_node_receive_bytes` after decrypt EQUALS the (a)
   golden plaintext for the same messages — proving the seam is transparent.
2. **Noise handshake KAT** — extend `tests/harness/src/test_noise_transport.c` (its
   header notes no canonical XX vector was in-tree). Pin a DETERMINISTIC transcript:
   fixed prologue + fixed statics + `noise_hs_set_ephemeral` with fixed scalars on
   both sides → assert exact `msg1/msg2/msg3` bytes AND the two Split() transport
   keys against hex goldens committed in the test. This is the regression KAT
   (self-generated golden; `x25519_safe` + HKDF beneath are already RFC-5869
   KAT-pinned in `test_hkdf`).
3. **Per-peer dumpstate transport field** — add a `transport` subsystem:
   `bool net_transport_dump_state_json(struct json_value*, const char*)` (walk
   `nm->nodes`, per peer emit `{id, mode: "plaintext"|"noise_xx", state,
   send_frames, recv_frames}` + top-line `plaintext_peers`/`noise_peers` counts —
   plaintext peers NAMED and COUNTED). Register ONE row in
   `engine/controllers/include/controllers/diagnostics_dumpers.def` mirroring the
   `DIAG_LOCAL("sandbox", …)` row (**:62**):
   `DIAG_LOCAL("transport", net_transport_dump_state_json, "per-peer P2P transport: plaintext vs noise_xx, handshake state, frame counters; names+counts plaintext peers")`.
   Update the native diagnostics registry assertion if it pins the list (per
   CLAUDE.md "Adding state introspection" step 4).
4. **Handshake p99 bench receipt** — NEW `bench-noise-handshake` Makefile target
   modeled on `bench-crypto-verify` (**Makefile:2680**: node binary run with a
   `-bench-noise-handshake` flag, `ZCL_BENCH_COMMIT="$(BUILD_COMMIT)"`). Run N=1000
   full XX handshakes over `socketpair()`, append `commit,p50_us,p99_us` to
   `docs/bench-history.csv`, and FAIL if p99 exceeds the budget (propose 2 ms p99
   on the dev lane — two X25519 base + three scalarmults + a few HKDF/AEAD calls;
   set the exact number from the first measured run, then ratchet shrink-only).

Optional belt-and-suspenders lint gate `check-noise-plaintext-seam-guarded` (grep):
assert `net.c:708` and `connman.c:1392±2` keep an unconditional `transport==NULL`
else-branch (catches a future edit that accidentally makes the plaintext path
conditional). WARN→HARD once stable; the byte-parity test is the real proof.

## 8. Consensus parity confirmation (transport is NON-consensus)

Confirmed from code: `g_msg_dispatch` keys purely on the 12-byte
command string from `struct msg_header`; `net_message_read_data` strips framing
before any handler; the eight reducer stages read stored block/tx data via
`reducer_frontier.c`, never live socket bytes; keys/nonces never feed block/tx
validity, script eval, Equihash, or Sapling/Sprout proofs. No block or tx byte on
the wire changes meaning — the same `msg_header`+payload is what gets sealed and
what gets delivered. `check-consensus-parity` (E13) is untouched; no golden
consensus value moves. The transport==NULL path is bit-for-bit today's wire, so
zclassicd interop is preserved by construction (case 2/6). Copy-prove before any
live enable: two nodes on datadir COPIES with `-noisetransport` forced on must reach
identical H*/tip-hash vs a v1-only control (design §11 Phase-1 copy-prove) — this
recipe lands the code dark; the enable is a separate owner-gated step.

## 9. Open questions (carry to owner / Phase 2, do NOT block P1)

1. Confirm `NODE_NOISE_TRANSPORT = 1<<25` collides with no zclassicd-observed bit.
2. Ship ephemeral-only XX in P1 (first-contact MITM residual accepted, same as
   BIP324) vs block on the addrman static-key TOFU pin — pin is Phase 3, keep P1
   passive-safe only.
3. Streaming AEAD (one frame per 2 MiB block) is Phase 3; P1 uses the Phase-0
   `session_transport` 1536-byte chunking (invisible above the seam) — accept the
   ~1.3% overhead for the interim.
4. Suite is permanently SHA-256 (zero new crypto) — confirm.
5. mlock on `identity_priv` + session keys — confirm platform posture first.
