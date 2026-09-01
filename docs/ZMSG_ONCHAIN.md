# ZMSG On-Chain Channel — Sapling-memo agent messages

The on-chain ZMSG channel carries agent-to-agent messages inside the 512-byte
**encrypted Sapling memo** field of a shielded transaction output. Consensus
treats the memo as opaque free-form bytes, so this format changes **no**
consensus predicate, tx-validity rule, or serialization — it is a pure
application-layer overlay (same discipline as ZNAM/ZSLP OP_RETURN payloads).

Two ZMSG channels exist (see `core/modules/net/include/net/zmsg.h`):

- **P2P** (`ZMSG_CHANNEL_P2P`) — instant, free, plaintext-on-wire, between
  connected nodes. Default.
- **On-chain** (`ZMSG_CHANNEL_ONCHAIN`) — permanent, shielded, paid a dust-tier
  amount. Documented here.

## Wire format (v1)

The message rides in the 512-byte memo with a fixed 38-byte header. The
reply-to field is always physically present (all-zero when unused) so decoding
needs no variable-offset arithmetic. All integers are little-endian.

| Offset | Size | Field         | Notes                                                   |
|-------:|-----:|---------------|---------------------------------------------------------|
| 0      | 1    | `magic0`      | `0x5A` (`'Z'`)                                           |
| 1      | 1    | `magic1`      | `0x4D` (`'M'`)                                           |
| 2      | 1    | `version`     | `0x01` (`ZMSG_MEMO_VERSION`)                             |
| 3      | 1    | `flags`       | bit0 = `HAS_REPLY_TO`; bits 1–7 reserved (must be 0)     |
| 4      | 2    | `payload_len` | count of UTF-8 payload bytes, `<= 474`                  |
| 6      | 32   | `reply_to`    | parent `msg_id`; all-zero when `HAS_REPLY_TO` is clear   |
| 38     | N    | `payload`     | UTF-8 message body (`N = payload_len`)                   |
| 38+N   | …    | padding       | `0xF6` filler to 512 bytes (standard Sapling memo pad)   |

- Header length = **38 bytes**. Max payload = `512 − 38` = **474 bytes**
  (`ZMSG_MEMO_MAX_PAYLOAD`).
- The payload is UTF-8 text; it is **not** NUL-terminated on the wire —
  `payload_len` is authoritative.

### Decode is strict

`zmsg_memo_decode()` returns `false` (rejecting the memo) when any of:

- `magic0`/`magic1` do not match (the common, benign case — every non-ZMSG
  shielded note passes through the decoder),
- `version != 0x01`,
- any reserved `flags` bit is set (`flags & ~ZMSG_MEMO_FLAGS_KNOWN`),
- `payload_len > 474` (would run past the memo).

A non-ZMSG memo is expected and returns `false` quietly (no log spam).

## Codec API (`core/modules/net/src/zmsg.c`)

```c
bool zmsg_memo_encode(uint8_t out[512], const uint8_t *payload,
                      size_t payload_len, const uint8_t reply_to[32]);
bool zmsg_memo_decode(const uint8_t memo[512], struct zmsg_memo *out);
```

Unit + negative tests (bad magic, bad version, reserved flag, over-long
payload, round-trip, reply-to) live in the fast pool: `tests/harness/src/test_protocols.c`.

## Send path

`msg_send` gained channel selection (P2P stays the default):

```
msg_send recipient "message" [channel] [from_address] [reply_to]
  channel "onchain": recipient = zs1... address; from_address = funding z/t
  address (required); reply_to = 64-hex parent msg_id (optional).
```

The on-chain path (`msg_send_onchain` in
`contexts/messaging/controllers/src/messaging_controller.c`):

1. **Fails closed** if `sapling_params_loaded()` is false (prover not READY),
   if the recipient is not a `zs1…` address, if `from_address` is missing, or
   if the message is empty / exceeds 474 bytes.
2. Encodes the memo with `zmsg_memo_encode`, hex-encodes the 512 bytes, and
   **composes `z_sendmany`** — `["<from>", [{"address":"<zs1>","amount":1000,`
   `"memo_hex":"<hex>"}]]` — reusing the existing shielded send machinery
   (coin selection, Sapling output proof, binding signature, relay). It does
   **not** duplicate proof construction.
3. `z_sendmany` learned a `memo_hex` recipient key (binary-safe memo) alongside
   the existing UTF-8 `memo` key.
4. On success it stores the outbound message (`channel=onchain`) with the
   broadcast txid.

> **Prover gate:** shielded send is native C23 and becomes available only after
> the SHA-512-pinned parameters load and an in-process Spend + Output + binding
> bundle is accepted by the independent consensus verifier. Failure remains a
> typed refusal; no Rust toolchain or runtime is involved.

## Receive path

When the wallet decrypts an incoming Sapling note
(`engine/jobs/src/tip_finalize_post_step.c`, right after
`node_db_sync_sapling_note`), it calls
`zmsg_ingest_onchain_note(ndb, note->memo, note->txid)`
(`contexts/messaging/models/src/zmsg.c`). If the memo parses as a ZMSG it is stored as an
**inbound** message with:

- `channel = onchain`, `direction = inbound`, `txid` stamped,
- `msg_id = SHA3(txid ‖ memo)` — **deterministic**, so a re-scan / reorg
  re-ingest maps to the same id and both stores (in-memory + SQLite
  `INSERT OR IGNORE` on the `msg_id` primary key) dedup it.

`msg_inbox` / `msg_read` then show it exactly like a P2P message.

## End-to-end test

`tests/harness/src/test_simnet_zmsg_onchain.c` (params-gated group
`simnet_zmsg_onchain`) proves the full round-trip in the deterministic
simulator: a `t→z` output built with the real Sapling prover carrying a ZMSG
memo, decrypted by the recipient, parsed, ingested, and surfaced in the store.
The params-free legs (encode/decode + store ingest + negatives) run
unconditionally; the real-prover leg reports `UNOBSERVED` when
`~/.zcash-params` is
absent.
