# Software Anchoring (ZANC)

Anchor a software/package digest into the ZClassic chain and later verify a
file against that immutable record. This is a parity-safe overlay — a standard
OP_RETURN output, no new opcodes, no consensus change (same pattern as ZNAM/
ZSLP). The chain's proof-of-work history timestamps the digest; anyone can
recompute the digest and find the block that committed it.

## Trust model — what it proves

An anchor is a transaction whose first output is an `OP_RETURN` carrying a
digest. Once that transaction is buried under work, the fact "this exact
digest existed at or before block height *h*" is as hard to forge as rewriting
the chain from *h* forward.

Verification is mechanical and local:

1. Recompute the file's digest (SHA-256 and/or SHA3-256).
2. Look it up in the `zanc_anchors` projection.
3. If found at height *h*, report `txid`, *h*, and confirmations
   (`H* − h + 1`, where `H*` is the node's provable tip).

The `zanc_anchors` table is a **projection** — rebuilt by re-scanning block
bodies, never authoritative. The authority is the confirmed OP_RETURN in chain
history; the table is only an index over it. Delete it and it rebuilds.

## What it does NOT prove

- **Not authorship.** Anchoring is permissionless: anyone can anchor any
  digest, including someone else's. An anchor proves *existence at a height*,
  not *who* published it and not that they are entitled to. Binding a digest to
  an identity needs a signing layer — future work is to bind an anchor to a
  ZNAM name (the name owner signs the anchoring tx's first input, exactly as
  ZNAM mutations are owner-authorized in `apply_znam`), so "package X@1.2 was
  released by name `acme`" becomes checkable. That layer does not exist yet.
- **Not integrity of the content behind the digest.** It commits the 32-byte
  digest, not the bytes. You must recompute the digest from the real file; the
  chain only tells you *when that digest first appeared*.
- **Not first-publication ordering across forks below finality.** Trust the
  anchor only once it has meaningful confirmations.

## Payload layout

First `OP_RETURN` output, Bitcoin script PUSH fields after `0x6a`:

| Field     | Bytes | Value                                   |
|-----------|-------|-----------------------------------------|
| lokad     | 4     | `"ZANC"` (`0x5a414e43`)                 |
| version   | 1     | `1`                                     |
| hash_type | 1     | `1` = SHA2-256, `2` = SHA3-256          |
| digest    | 32    | the anchored digest                     |
| label     | 0..32 | optional UTF-8 label (`name@version`)   |

No trailing bytes are permitted after the label push. The parser
(`contexts/commons/modules/zanc/src/zanc.c`, `zanc_parse`) is strict: it rejects bad lengths, an
unknown version, an unsupported hash-type byte, an oversize or non-UTF-8
label, and any trailing data.

## Where it lives

- Codec: `contexts/commons/modules/zanc/` (`zanc_parse`, `zanc_build_anchor`, `zanc_label_valid`).
- Projection table + model: `zanc_anchors` (schema v30 in
  `engine/models/src/database_migrate_features.c`); model in
  `contexts/commons/models/src/zanc.c`.
- Ingestion seam: `contexts/explorer/models/src/explorer_index.c` — `index_op_return`
  dispatches to `apply_zanc`, alongside ZSLP and ZNAM, on each tx's first
  OP_RETURN.
- Commands: `engine/controllers/src/anchor_controller.c`.

## Commands

- `anchor_publish {"file":path | "digest":hex, "hash_type":"sha3"|"sha2",
  "label":"name@version"}` — build the ZANC OP_RETURN. With a wallet loaded it
  composes and broadcasts a tx carrying it (via the same base-tx compose path
  as ZNAM register); with no wallet it returns `op_return_hex` for manual
  inclusion. `hash_type` defaults to `sha3`.
- `anchor_verify {"file":path | "digest":hex [, "hash_type":...]}` — recompute
  the file's SHA-256 and SHA3-256 (or take a digest), look each up, and report
  `anchored` with `txid`/`height`/`confirmations` per match.
- `anchor_list [{"limit":N}]` — recent anchors, newest first (`limit` ≤ 100).
- `anchor_self` — digest the running binary (`/proc/self/exe`) with both
  SHA-256 and SHA3-256 and report whether it is anchored on-chain.
