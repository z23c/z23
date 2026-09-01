# ADR-0010: File-size raises for the consensus snapshot export/install IO

> **Superseded by the 2026-08-29 file-size policy change.** E1 no longer
> fails a build at 800 lines, so a raise like this one no longer needs an
> ADR. The policy is now three bands — an advisory 800-line target, an
> allowed 801..1500 buffer, and a hard 1500-line limit — implemented in
> [`tools/file_size_policy.c`](../../tools/file_size_policy.c). Every file
> named below is inside the allowed buffer or carried in the shrink-only
> legacy baseline. Kept for the record of what was decided and why.

- **Status:** Superseded 2026-08-27 by line-count reductions during integration.
- **Deciders:** Project maintainer.
- **Related:** [`0009-swap-money-shape-guard-file-size-raise.md`](./0009-swap-money-shape-guard-file-size-raise.md),
  `engine/composition/src/consensus_state_snapshot_export.c`,
  `engine/composition/src/consensus_state_snapshot_install_activate.c`.

---

## Context

The E1 file-size ceiling (then an 800-line hard
ceiling for `app/`+`engine/composition/src/`) ratchets: growth above a recorded baseline
(or a first crossing of the ceiling) costs an explicit record.

The native macOS port landing in `3fd1feb5e` / `bdb40e89c` touched the
consensus-state snapshot IO pair as part of the platform work and left the
enforced tier red for every subsequent tree:

- `engine/composition/src/consensus_state_snapshot_export.c` **800 → 801** — crosses the
  ceiling by one line and has no baseline entry yet, so it reads as a NEW
  oversized file rather than a grandfathered one.
- `engine/composition/src/consensus_state_snapshot_install_activate.c`
  **1169 → 1172** — grows past its recorded baseline.

Neither delta is carried by a heal commit on the landing branch: the raise
surfaced only when the next independent push ran the gate's sandboxed
self-tests (`make_lint_gates_shard_06` / `_07`, which replay the checker
against a copy of the tree), so the landing author's own receipt never saw
it. This ADR records the raises against their true provenance so the ratchet
heal does not silently adopt the growth as if it were intentional design
debt incurred here.

## Decision

1. Record `engine/composition/src/consensus_state_snapshot_export.c` at its current line
   count (its first baseline entry — pinning the crossing, not accepting
   further drift).
2. Raise the enforced-tier baseline for
   `engine/composition/src/consensus_state_snapshot_install_activate.c` from 1169 to its
   current line count (recorded in
   `tools/lint/file_size_policy_baseline.txt`).

## Consequences

- The enforced tier heals without touching the platform commits' content or
  rewriting history.
- Both files still ratchet: any further growth costs another explicit raise,
  and both carry an obvious split seam (export writer vs install/activate
  phases) that shrinking under the ceiling would let the records shrink into.
- The WARN-tier drift-count acceptance landed alongside this ADR
  (`engine/entry/main_cli_modes.c` +1 in the same port) rode its own valve — a
  drift-count ratchet file that the 2026-08-29 policy change deleted, with
  this document as the reviewed provenance at the time.

## Integrated resolution

The release-hardening integration removed the new line from the exporter,
reduced the installer to its prior 1,169-line ceiling, and reduced
`engine/entry/main_cli_modes.c` to its prior baseline. The enforced baseline is 1,169
and the WARN-tier drift-count ceiling is 22; the now-800-line exporter needs
no exception entry. No size ceiling was raised in the integrated release.
