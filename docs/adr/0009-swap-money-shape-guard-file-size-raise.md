# ADR-0009: File-size baseline raise for the atomic-swap money-shape guard

- **Status:** Accepted 2026-08-27.
- **Deciders:** Project maintainer.
- **Related:** [`0006-always-sync-spine-file-size-raises.md`](./0006-always-sync-spine-file-size-raises.md),
  [`0008-seed-floor-declaration-file-size-raises.md`](./0008-seed-floor-declaration-file-size-raises.md),
  `app/controllers/src/swap_controller.c` (the guarded controller).

---

## Context

The E1 file-size ceiling (`tools/scripts/check_file_size_ceiling.sh`, 800-line
ceiling for `app/`+`config/src/`) ratchets: growth above a recorded baseline
costs an explicit raise.

The swap RPC controllers (`swap_initiate` / `swap_participate`) parsed their
`amount` argument as a bare double straight off the JSON wire and persisted
`(int64_t)(amount * 100000000.0)` unchecked. Every corrupting shape the wire
can deliver became a stored money contract: zero (the parser's absent-argument
sentinel), negatives, NaN (UB on the cast), infinities (also UB), and
magnitudes that overflow `int64_t` once scaled.

The fix is an exported pure gate, `swap_amount_to_zat()`, refusing all of
those shapes before any address decodes or state persists, pinned by seven
refusal/conversion edges in the vault-read lane. It costs **26 net lines**:

- `app/controllers/src/swap_controller.c` **1027 → 1053** — the gate
  implementation at top of the build path, with its rationale comment placed
  where the unchecked cast used to live.
- (`swap_controller.h` +9 and `test_vault_read.c` +27 do not count against
  this file's enforced ceiling.)

Compressing onto the old baseline would mean either dropping the
failure-analysis comment next to the guard or weakening the refusal set
(e.g. letting NaN through as a "zero") — both strictly worse than 26 lines
of size debt on a money-handling controller whose split seam does not exist
yet (settlement helpers are already a separate service; the remaining bulk is
nine cohesive RPC handlers).

## Decision

Raise the enforced-tier baseline for `app/controllers/src/swap_controller.c`
to its current line count (recorded in
`tools/scripts/file_size_ceiling_baseline.txt`).

## Consequences

- The money-shape fix lands through a clean E1 gate.
- The ceiling still ratchets: the file may not grow further without another
  explicit raise, and splitting out the settlement-facing helpers remains the
  standing reward path — shrinking under the ceiling lets the record shrink.
