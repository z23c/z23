# ADR-0010: File-size raises for the consensus snapshot export/install IO

- **Status:** Accepted 2026-08-27.
- **Deciders:** Project maintainer.
- **Related:** [`0009-swap-money-shape-guard-file-size-raise.md`](./0009-swap-money-shape-guard-file-size-raise.md),
  `config/src/consensus_state_snapshot_export.c`,
  `config/src/consensus_state_snapshot_install_activate.c`.

---

## Context

The E1 file-size ceiling (`tools/scripts/check_file_size_ceiling.sh`, 800-line
ceiling for `app/`+`config/src/`) ratchets: growth above a recorded baseline
(or a first crossing of the ceiling) costs an explicit record.

The native macOS port landing in `3fd1feb5e` / `bdb40e89c` touched the
consensus-state snapshot IO pair as part of the platform work and left the
enforced tier red for every subsequent tree:

- `config/src/consensus_state_snapshot_export.c` **800 → 801** — crosses the
  ceiling by one line and has no baseline entry yet, so it reads as a NEW
  oversized file rather than a grandfathered one.
- `config/src/consensus_state_snapshot_install_activate.c`
  **1169 → 1172** — grows past its recorded baseline.

Neither delta is carried by a heal commit on the landing branch: the raise
surfaced only when the next independent push ran the gate's sandboxed
self-tests (`make_lint_gates_shard_06` / `_07`, which replay the checker
against a copy of the tree), so the landing author's own receipt never saw
it. This ADR records the raises against their true provenance so the ratchet
heal does not silently adopt the growth as if it were intentional design
debt incurred here.

## Decision

1. Record `config/src/consensus_state_snapshot_export.c` at its current line
   count (its first baseline entry — pinning the crossing, not accepting
   further drift).
2. Raise the enforced-tier baseline for
   `config/src/consensus_state_snapshot_install_activate.c` from 1169 to its
   current line count (recorded in
   `tools/scripts/file_size_ceiling_baseline.txt`).

## Consequences

- The enforced tier heals without touching the platform commits' content or
  rewriting history.
- Both files still ratchet: any further growth costs another explicit raise,
  and both carry an obvious split seam (export writer vs install/activate
  phases) that shrinking under the ceiling would let the records shrink into.
- The WARN-tier drift-count acceptance landed alongside this ADR
  (`src/main_cli_modes.c` +1 in the same port) rides its own valve —
  `file_size_ceiling_lib_drift_count.txt` — with this document as the
  reviewed provenance.
