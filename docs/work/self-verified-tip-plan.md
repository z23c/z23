# The Self-Verified Tip Plan — sovereignty hardening (open items)

> **Live sovereignty (`G-SOV`) is proven via the checkpoint-content
> consensus-bundle install path** (`docs/work/sovereign-cutover-runbook.md`,
> `engine/composition/src/consensus_state_snapshot_install_checkpoint_authority.c`), which
> proves the same G-SOV predicate (coins reproduce the compiled SHA3
> checkpoint + Sapling frontier roots to the validated header) a different
> way than the from-anchor refold sequence below. That from-anchor sequence
> is NOT done: `REDUCER_FRONTIER_TRUSTED_ANCHOR` is still a hardcoded
> `3056758` (`engine/reducer/jobs/include/jobs/reducer_frontier.h`, not self-derived —
> re-grep the exact line before editing, it drifts), `-refold-from-anchor` is
> still an explicit opt-in flag, not the cold-start default (`engine/entry/main.c`,
> `engine/composition/src/boot.c` — re-grep the exact line before editing), and the
> borrowed-seed loader is not deleted. This file is retained as the **design
> reference** for the `G-SOV` predicate (the live sovereignty gate,
> `engine/controllers/src/sovereignty_controller.c`) and for the still-open
> hardening items below. Read `docs/HANDOFF.md` for current live status, not
> this file.

> **One metric: T = time-to-self-verified-tip.** Wall-clock from a cold or
> stalled start until `(tip, utxo)` is backed by PoW + the node's *own* fold,
> with **zero borrowed trust**. *Fast*, *secure*, and *never-stuck* are three
> readings of the same T.

This is the canonical statement of the **sovereign cure** design that
[`FRAMEWORK.md`](../FRAMEWORK.md) §0 names. It is the same design referenced
by [`FORWARD_PLAN.md`](./FORWARD_PLAN.md) #1 (sovereign cure) and
[`never-stuck-plan.md`](./never-stuck-plan.md).

---

## The problem — borrowed state vs. re-derived state

The Prime Directive (`FRAMEWORK.md` §0): *keep `(tip, utxo)` equal to the
network's best valid chain — or name, precisely, the one input it is
missing.*

The node holds every block body on disk and a locally pinned checkpoint (the
baked SHA3 checkpoint @3,056,758, `core/chainparams/src/checkpoints.c`). The
checkpoint is not a ZClassic-header state commitment; sovereignty comes from
reproducing it from validated bodies. The remaining defect: some paths still
read conclusions off persisted `*_log.ok` cursors and a *borrowed* `coins_kv`
copy minted by `zclassicd` (`engine/services/src/utxo_recovery_restore.c:369`)
instead of re-deriving from the evidence, because re-deriving is currently
too slow to be the default reflex everywhere.

**The standing property to reach:** every served fact is a re-derivation,
never a frozen row or a borrowed copy — the failure mode `FRAMEWORK.md` §0
names as "a second write path," "authoritative chain state in RAM," or a
"self-healer that could lie."

---

## Crosscutting rules (every item below)

- **Copy-prove, never live-first.** Every item is proven on a datadir *copy*.
- **Gate on H\* CLIMB, not "booted w/o FATAL."** Real signal:
  `reducer_frontier_provable_tip_cached()` climbing past the target wedge,
  with `coins_applied_height == H* + 1` (no rowless/stamped span).
- **Sovereignty is the 3-part `G-SOV` gate, not tip-reachability** — a node
  can climb H\* to the network tip on a *stamped borrowed* `coins_kv` and
  pass a naive gate while still resting on borrowed trust.
- **Parity replay only where a predicate changes.** The items below change
  state/derivation/perf, not consensus predicates → no fork expected. The one
  predicate in flight (coinbase-maturity default-off, `utxo_apply_delta.c:60`)
  stays walled off; flipping it needs a full-history replay (h=478544 lesson).

---

## Current baseline

- The sapling-tree rebuild resolves its endpoint from coins-applied state
  (`engine/controllers/src/sync_controller_sapling_tree.c:46-71`: caps
  `chain_tip` to `coins_best = coins_applied_height − 1`), so a copy boots
  without the pre-fold sapling FATAL. Minting (`-mint-anchor`,
  `engine/composition/src/boot_mint_anchor.c:62`) is also live — see
  [`refold-fold-rate-bottlenecks.md`](./refold-fold-rate-bottlenecks.md).
- A transient `internal_error` is retriable, not terminal, on both the
  script-validate and proof-validate paths: the heal deletes the stale
  `script_validate_log`/`proof_validate_log` rows in the same transaction,
  rewinds downstream cursors, and leaves genuine invalid verdicts terminal.
  Guarded by `make t ONLY=reducer_frontier_reconcile_light` and
  `test_stage_repair`.

---

## Open item 1 — make re-reading cheap (the measured speed root) · PARTIAL

- **The move:** the dominant refold cost is the per-block ~3.1M-node
  `pprev`-walk in `active_chain_fill_window`
  (`core/modules/validation/src/chainstate.c:350-391`, via
  `reducer_extend_window_to_candidate`), ~76% of refold CPU (measured —
  `docs/work/refold-fold-rate-bottlenecks.md`). Build a **refold-gated** fast
  path: under refold, fill the window from coins state / a cached pointer;
  under normal boot, keep the conservative iteration so the boot path stays
  byte-identical (no hot-loop indirection; clear ownership). The `coins_ram`
  overlay (`-fold-inram`) is the vehicle, **but its cross-thread reader UAF
  must be fixed first.**
- **Gate:** (1) fold-rate up; (2) H\* CLIMB; (3) normal boot **byte-identical**
  (`coins.db` checksum vs HEAD).
- **False-green & stronger gate:** rate can tick up from smaller batches
  while the walk still burns ~76%. Quantitative gate:
  `active_chain_fill_window` CPU fraction **drops below 40%** on a
  flamegraph. Profile before claiming done.

## Open item 2 — self-derive the anchor, then delete the borrow · PARTIAL ~80%

- **Three unlock changes, then the deletion:**
  1. **Self-derive the anchor** — fold genesis→3,056,758 vs the baked
     checkpoint (`engine/composition/src/boot_mint_anchor.c:152-186`); replace the
     hardcoded `REDUCER_FRONTIER_TRUSTED_ANCHOR=3056758`
     (`engine/reducer/jobs/include/jobs/reducer_frontier.h`, re-grep before editing —
     the line drifts) with the self-derived value at its call sites
     (`engine/reducer/jobs/src/reducer_frontier.c`).
  2. **Flip the default** — make `-refold-from-anchor` the default cold
     start (today needs a CLI flag, `engine/entry/main.c`; default boot imports the
     borrowed seed via `utxo_recovery_import_ldb`, `engine/composition/src/boot.c` —
     re-grep both before editing).
  3. **Delete the borrow** — remove the `coins_kv` seed copy
     (`utxo_recovery_restore.c:369`) and the ~9k-LOC carve in dependency
     order (see [`ladder-carve-audit.md`](./ladder-carve-audit.md) for the
     per-file consumer graph and phasing).
- **9-caller caution:** `tip_finalize_stage_seed_anchor` has 9 production
  callers. KEEP the consensus-critical ones
  (`engine/reducer/services/src/reducer_ingest_service.c` live fold; the from-anchor
  `boot_refold_staged.c`; `snapshot_apply.c`); DELETE cold-import ones
  (`block_index_loader_rebuild.c`, `reindex_epilogue.c`) after the cure
  ships. Classify each caller before cutting — deleting a KEEP caller trips
  a live predicate.
- **Gate:** a **FRESH** datadir (no `~/.zclassic`) folds genesis→tip,
  reproduces the SHA3 root + 1,354,769 UTXOs; copy-prove `G-SOV`; *then*
  delete. `test_self_folded_anchor` **exists** —
  `tests/harness/src/test_self_folded_anchor.c`, registered in the canonical catalog
  as `ZCL_TEST_GROUP(self_folded_anchor)`, so it really runs. Extend it rather than writing it.
  <!-- claim: file-present tests/harness/src/test_self_folded_anchor.c # written; do not re-create -->
  <!-- claim: symbol-present self_folded_anchor tools/dev/test_group_catalog.def # registered, so it actually runs -->
- **False-green traps:**
  - *Borrowed-seed no-op:* `-load-verify-boot` no-ops on a stamped
    `coins_kv` (`coins_kv_is_proven_authority()==true`). Defeat: `G-SOV`
    part 3 — assert a from-anchor reset ran
    (`coins_kv_contains_refold_marker()`).
  - *Baked-checkpoint byte-match:* the fresh test can pass by reading the
    *compiled* checkpoint. Defeat: a `_no_binary_checkpoint` variant — null
    the compiled checkpoint, fold from bodies, recompute SHA3, assert it
    equals the original (bodies are the authority, not the binary).
  - Don't delete behind a default-false flag (it lingers). Delete outright +
    add a fail-loud lint gate:
    `grep 'utxo_recovery_import_ldb\|coins_kv_seed_from_node_db\|COINS_KV_MIGRATION_COMPLETE_KEY' --include=*.c → exit 2 on any match`.

## Open item 3 — lock-in (weld the lid) · PARTIAL

- **(a) Kill the forgeable XOR feed — HALF-DONE.** The MMB leaf already
  reads the real persisted `boundary_root`
  (`engine/controllers/src/blockchain_controller.c:189`), but
  `rpc_blockchain_maybe_commit` still writes the O(1) `xor_accumulator` into
  the commitment MMR (`:285`) — a forgeable, never-set-verified value.
  **First confirm whether that commitment MMR is consensus-critical or
  RPC-export-only** — that decides enforce-vs-delete.
- **(b) Fix the 7 fail-silent lint gates + a meta-gate** (feed each gate
  empty input → assert exit 2). Extends the existing self-test pattern
  (`test_make_lint_gates.c`, `FRAMEWORK.md` §5). Re-audit
  `check_one_write_path`, `check_stage_log_reorg_unsafe_ratchet`,
  `check_projections_pure` **before** the item-2 deletions, so a hollow gate
  can't let a forbidden pattern back in via a renamed symbol. Doc:
  [`lint-gate-hollowness-audit.md`](./lint-gate-hollowness-audit.md).
- **(c) Delete confirmed-dead scaffolding** —
  `core/modules/validation/src/verify_queue.c:130` is `additive_unwired` (no
  non-test callers) + the other confirmed-dead paths.
- **(d) CI invariant:** no path advances `coins_applied_height` without the
  co-committed log row (`tip_finalize_log` vs `utxo_apply_log` continuity —
  the one-write-path gate of `FRAMEWORK.md` §5, made specific to the
  cursor).
- **Gate:** `make ci` green; deletions do not regress `G-SOV` H\* CLIMB.

---

## Sequencing

Open items proceed **1 → 2 → 3**: item 1 makes item 2's from-anchor refold
fast enough to be the default reflex. Item 2 is the prize — flips T from ∞
(borrowed) to finite (sovereign), deletes ~9k LOC. Item 3 welds the lid so a
refactor can't quietly re-borrow.

## `G-SOV` — the composite sovereignty gate (every item uses it)

A boot is *self-verified-sovereign* iff **all three** hold:

1. `H* ≥ anchor` **and** `H*` climbs past the target wedge height (forward
   progress, not just a floor);
2. `coins_applied_height == H* + 1` — continuous log coverage, no
   NULL/stamped span (`tip_finalize_log` vs `utxo_apply_log` contiguity);
3. `coins_kv_is_proven_authority() == false`, **or** (`== true` **and**
   `coins_kv_contains_refold_marker()` — a single kernel-store key
   (`COINS_KV_SELF_FOLDED_KEY`, `progress.kv` pre-flip / `consensus.db`
   after the item-2/3 kernel-store flip, `docs/HANDOFF.md` §0-LATEST)
   proving a from-anchor reset ran). This separates self-derived from
   borrowed-and-stamped.

`G-SOV` is the quantitative Prime Directive: `health = network_tip −
log_head`, plus the predicate that `log_head` rests on the node's own fold,
not a borrow.

---

## End state

A node that, cold-started with only its own self-derived state,
reconstructs full state from evidence in bounded time (item 1: cheap
re-read; item 2: self-derived file); never records a missing-evidence
report on evidence already on disk (shipped, symmetric across script +
proof); and cannot be fooled by a forged index card (item 3: XOR feed gone,
borrowed copy deleted, lint gates that actually fire). T is finite, and
every reading of it — fast, secure, never-stuck — is the same number.

This is `FRAMEWORK.md` §0 made true: the UTXO trust root stops being
borrowed, the fold becomes pure from genesis, and the silent halt stays
unrepresentable.
