# ADR-0006: File-size baseline raises for the always-sync spine core

> **Superseded by the 2026-08-29 file-size policy change.** E1 no longer
> fails a build at 800 lines, so a raise like this one no longer needs an
> ADR. The policy is now three bands — an advisory 800-line target, an
> allowed 801..1500 buffer, and a hard 1500-line limit — implemented in
> [`tools/file_size_policy.c`](../../tools/file_size_policy.c). Every file
> named below is inside the allowed buffer or carried in the shrink-only
> legacy baseline. Kept for the record of what was decided and why.

- **Status:** Accepted 2026-07-16.
- **Deciders:** Project maintainer.
- **Related:** [`self-verified-tip-plan.md`](../work/self-verified-tip-plan.md),
  [`fail-safe-architecture.md`](../work/fail-safe-architecture.md),
  [`HANDOFF.md`](../HANDOFF.md), the approved always-sync spine plan
  (`remember-this-software-must-snappy-fog`).

---

## Context

The E1 file-size ceiling (then an 800-line hard
ceiling for `app/`+`engine/composition/src/`) is a beauty ratchet whose baseline "can only
shrink, never grow, and growing it costs an ADR." The always-sync spine's
Wave-1 core (Pillars 0 + 2) legitimately grew three enforced-tier files past
their recorded baselines:

- **`engine/services/src/block_index_loader.c` 844 → 949** — Pillar 0's
  `promote_best_header_after_load()`: on a full-index boot it promotes the
  max-chainwork header into the active-chain window and seats it via
  `chain_set_active_tip`, so `active_chain_tip()` is never NULL and the
  getheaders locator anchors at the frontier instead of genesis. This is the
  linchpin fix that lets the node escape the ~160-header wedge.
- **`engine/services/src/sticky_escalator.c` 873 → 1104** — Pillar 2 made the
  three stub recovery rungs (resnapshot, self_mint_refold, rebootstrap) real,
  in-process, self-derived remedies driven by `stage_rederive_range`, plus the
  reconcile alignment to the landed primitive signature.
- **`engine/services/src/header_sync_service.c` → 812 (new over-ceiling)** —
  Pillar 0's `best_header_fallback` locator path: when `active_chain_tip()` is
  NULL, build the getheaders locator from `pindex_best_header`, never genesis.
- **`engine/composition/src/boot.c` 4070 → 4071 (+1)** — Track B's one-line call-site change
  passing the derived coins-best `hash_found` flag into
  `boot_crashonly_clear_reindex_request_if_covered` so a hash-verified coins-best
  at the reindex anchor is treated as covered (no destructive wipe). `boot.c` is
  an existing monster far over the ceiling; splitting it is separate tracked debt.

Splitting these files is worthwhile cleanup, but each is consensus-adjacent
boot/recovery code where a hasty shape split risks introducing a liveness bug —
strictly worse than the size debt. It is also off the critical path to the
current #1 mission (fold a datadir all the way to the network tip).

## Decision

Raise the enforced-tier baseline for these three files to their current line
counts (recorded in `tools/lint/file_size_policy_baseline.txt`). Track the
cohesion-preserving split of each as follow-up cleanup debt, to be done
deliberately with full build + `test-parallel` verification — not as a rushed
mid-mission refactor.

## Consequences

- The always-sync spine integration branch has a clean `make lint` gate.
- The ceiling still ratchets: these three files may not grow further without
  another explicit baseline raise, and every other `app/` file stays under 800.
- The split remains owed; when done it shrinks these baseline lines back toward
  the ceiling, which the gate rewards (a shrink lets the baseline line drop).
