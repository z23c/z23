# ADR-0008: File-size baseline raises for the external-seed floor declaration

> **Superseded by the 2026-08-29 file-size policy change.** E1 no longer
> fails a build at 800 lines, so a raise like this one no longer needs an
> ADR. The policy is now three bands — an advisory 800-line target, an
> allowed 801..1500 buffer, and a hard 1500-line limit — implemented in
> [`tools/file_size_policy.c`](../../tools/file_size_policy.c). Every file
> named below is inside the allowed buffer or carried in the shrink-only
> legacy baseline. Kept for the record of what was decided and why.

- **Status:** Accepted 2026-08-01.
- **Deciders:** Project maintainer.
- **Related:** [`0006-always-sync-spine-file-size-raises.md`](./0006-always-sync-spine-file-size-raises.md),
  [`FORWARD_PLAN.md`](../work/FORWARD_PLAN.md) hardening backlog item 11,
  `app/services/src/bg_validation_service.c` (the walk-extent consumer).

---

## Context

The E1 file-size ceiling (then an 800-line hard
ceiling for `app/`+`config/src/`) ratchets: the enforced-tier baseline "can
only shrink, never grow, and growing it costs an ADR."

The anchor replay-canary FAILed twice on the bg-validation walk extent.
First (`budget_exceeded`, 5400 s): a fresh walk always started at genesis,
and the Equihash-serial per-block walk needs ~19 h for 3.2M blocks. The first
fix (4c8f4a208) started the walk at the durable trusted base — but the rerun
FAILed in 306 s: `tip_finalize_anchor` keeps RAISING
`REDUCER_TRUSTED_BASE_HEIGHT_KEY` toward tip as anchors finalize, so by
bg-validation start it sat at ~tip and the walk verified zero blocks.

The settled fix is a new `REDUCER_SEED_FLOOR_HEIGHT_KEY` (progress_meta,
8-byte LE, write-once/absent-guarded), declared only by a genuine
external-seed path and never advanced. The declaration must be co-located
with the seed writes so no future seed path can forget it — and both seed
sites already sit exactly at their recorded size baselines:

- **`app/services/src/block_index_loader_rebuild.c` 840 → 853 (+13)** —
  the cold-import wedge heal declares the floor right after the successful
  `tip_finalize_stage_seed_anchor(H, …)`, with the same
  `progress_store_tx_lock()` discipline as the neighboring H* self-check
  and an advisory-only failure path (the heal never fails over the marker).
- **`config/src/consensus_state_snapshot_install_activate.c` 1158 → 1169
  (+11)** — the bundle install declares the floor in the same activation
  transaction that stamps the provenance markers, right after clearing the
  stale trusted-base declaration.

Both additions are ~70% rationale comment, matching the surrounding house
style for consensus-adjacent boot/recovery code. Compressing them to fit
the old baselines would mean either stripping the failure-analysis context
the next maintainer needs, or moving the declaration away from the seed
write it belongs to — both strictly worse than +13/+11 lines of size debt.

## Decision

Raise the enforced-tier baseline for these two files to their current line
counts (recorded in `tools/lint/file_size_policy_baseline.txt`).

## Consequences

- The seed-floor fix lands with a clean `make lint` gate.
- The ceiling still ratchets: neither file may grow further without another
  explicit baseline raise, and every other `app/` file stays under 800.
- If either file is ever split along its seams (the standing cleanup debt
  from ADR-0006 applies to `block_index_loader_rebuild.c` too), the
  baseline line shrinks back, which the gate rewards.
