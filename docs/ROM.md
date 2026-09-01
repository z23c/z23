# ROM — the L0-L3 trust machine

Every trust claim z23 makes reduces to four layers. This page is the
map of what each layer guarantees, what it does NOT guarantee, and how to
read its live state in one call: `z23 dumpstate rom`.

Cross-references: `docs/CONSENSUS_PARITY_DOCTRINE.md` (why headers are the
only PoW-bound commitment), `docs/HANDOFF.md` (current live state — this
page carries none), `docs/HOW_THE_NODE_WORKS.md` (the reducer/projection
mental model L2 and L3 sit inside).

## The four layers

| Layer | What it is | What it guarantees | What it does NOT guarantee |
|---|---|---|---|
| **L0 — ROM** | The compiled-in SHA3 UTXO checkpoint (`get_sha3_utxo_checkpoint()`, `core/chainparams/src/checkpoints.c`): a height, a block hash, a SHA3-256 digest over the canonical-order transparent UTXO set at that height, a UTXO count, and a total supply. | A single, irreversible floor a node can verify its own fold against without trusting any peer. `reducer_frontier_floor()` never lets H* fall below this height on mainnet. | It does not commit shielded (Sapling/Sprout) state or nullifiers — see "What ZClassic headers commit" below. It is a fact about ONE height, not a live sync state. |
| **L1 — sealed history** | The immutable, hash-committed segment store for finalized block bodies (`engine/modules/storage/chain_segment`, `<datadir>/segments`). | Any segment present is byte-identical to what was originally sealed (whole-segment + per-block SHA3, checked on open). | It does not by itself prove the bodies were consensus-valid — validation happens once, during fold; the segment store only proves the bytes were not altered afterward. An empty/absent segment store is not an error — reads fall through to `blk*.dat`. |
| **L2 — delta fold** | The 8-stage reducer (`header_admit` → `tip_finalize`) folding block bodies forward from L0/L1 into durable state, tracked in `consensus.db`. H\* = the deepest height with a provably-consistent, contiguous `ok=1` prefix across every stage log (`engine/reducer/jobs/src/reducer_frontier.c`). | `[0, H*]` is provably consistent: every stage's success log agrees, hashes match across stages, and the coins frontier does not contradict it. H* never rewinds below the L0 floor (except mid-refold, which reports 0 by design — see `reducer_frontier_floor()`). | `[H*+1, ...)` may have a hole, a failed row, or a hash split — that is the definition of H*, not a defect in this doc. H* is a computed floor, not "how far P2P has downloaded." |
| **L3 — live tip** | The currently active, validated chain tip (`active_chain_tip()`) and the height this node advertises to external consumers (`reducer_frontier_external_tip_height()`). | The active tip is the head of a chain whose ancestors passed PoW, script, and (background) proof validation as they were folded. | The active/external tip can sit AHEAD of H* mid-fold or right after a reorg — it is the pipeline's leading edge, not the provable floor. It is never used as a substitute for H* in reconciliation logic. |

## What ZClassic headers commit — and what they don't

A recurring failure mode is treating a peer-provided or borrowed artifact as
consensus-bound because its *hash* matches a validated header. Headers commit
far less than that:

| Field | Committed by | Notes |
|---|---|---|
| Header chain (PoW) | The Equihash solution in the header itself; parameters are height-selected (see [`EQUIHASH_PARAMS.md`](EQUIHASH_PARAMS.md)) | The one thing a header alone proves: this chain cost real work. |
| Transaction bytes | `hashMerkleRoot` in the header | Committed, but only reachable by downloading and verifying the block body. |
| Sapling note-commitment frontier | `hashFinalSaplingRoot` in the header | Committed, but only as a root — the shielded notes/nullifiers behind it are not. |
| Nullifiers (Sprout + Sapling) | **Not committed** — ROM/checkpoint-only | A borrowed nullifier set cannot be authenticated from the header chain; only the compiled L0 checkpoint or a locally-folded L2 state can. |
| Sprout commitment state | **Not committed** — ROM/checkpoint-only | Same as above. |
| Transparent UTXO set | **Not committed** — ROM/checkpoint-only | ZClassic headers carry no UTXO-set root. Only L0's SHA3 checkpoint or a locally-folded L2 state authenticates it. |

`z23 dumpstate rom` publishes this table as machine-readable data
(`commitments`) alongside the live checkpoint, so an agent can check the
doctrine programmatically instead of re-reading this prose.

## Reading `dumpstate rom`

```
$ z23 dumpstate rom
```

returns one JSON object with four sections:

- **`checkpoint`** — the compiled L0 constants: `height`, `block_hash`,
  `sha3_hash` (both 64-char hex), `utxo_count`, `total_supply_zatoshi`.
- **`commitments`** — the header-commitment enumeration above, one string
  value per field (`pow` / `merkle` / `header` / `not_committed_rom_only`).
- **`layers`** — one sub-object per layer:
  - `l0_rom` — `height` (mirrors `checkpoint.height`).
  - `l1_sealed_history` — the `chain_segments` dump: `status`,
    `segment_count`, covered height range (when non-empty), `manifest_root`.
  - `l2_delta_fold` — `floor` (the L0 anchor floor), `hstar` (the cached
    provable tip), `published` (whether H\* has been computed at least once
    this run).
  - `l3_live_tip` — `has_main_state`, `active_tip` (the validated chain
    tip height, `-1` if no node state is wired — e.g. from a bare tool
    invocation), `external_tip` (the height advertised to peers/RPC).
- **`projections`** — cursors for the two cheaply-readable auxiliary
  structures:
  - `mmb` — `initialized`, `leaves`, `mountains` (Merkle Mountain Belt —
    FlyClient evidence, not a consensus commitment; see
    `docs/HOW_THE_NODE_WORKS.md`).
  - `utxo_root_ladder` — `rung_count`, `stride`, `highest_rung_height`,
    `dense_height` (the compiled golden-height UTXO-root cross-checks,
    `core/modules/chain/include/chain/utxo_root_ladder.h`).

Every field is either a compiled-in constant or a cheap read through an
existing public accessor (no new state, no writes, no O(chain) work) — see
`engine/controllers/src/diagnostics_registry_rom.c`. This subsystem is a
**projection**: it is derived from L0-L3, rebuildable from scratch, and
carries no authority of its own over consensus.

For the live H\* / sync-gap numbers this doc deliberately omits, use
`z23 status` or `z23 dumpstate reducer_frontier`; current
canonical state lives in `docs/HANDOFF.md`.
