# From-genesis refold: fold-rate bottlenecks + fix plan

> **Superseded as a description of the current live-sync scheduler
> (2026-09-05, see [`../zrc/0011-fast-sync-over-the-peer-link.md`](../zrc/0011-fast-sync-over-the-peer-link.md)).**
> The "#2 — scheduler ceiling" section below describes a flat
> 2s-tick/100-batch staged-sync scheduler with no catch-up override; that
> scheduler shape no longer matches the tree. Live catchup is now gated by
> `catchup_cadence_active()` (`engine/jobs/include/jobs/catchup_cadence.h`,
> `engine/jobs/src/catchup_cadence.c`), which widens the per-stage drain
> batch and shortens the per-child tick period while a node is genuinely
> behind a connected peer's tip. This document's from-genesis `-refold-staged`
> analysis (the split-brain root cause and bottleneck #1) is unaffected and
> still applies to that offline fold mode; only the "#2" live-scheduler
> ceiling claim is stale. Verify against code before relying; specifics rot.

## The split-brain root cause

`-refold-staged` resets the 8 staged cursors + coins_kv to genesis, but does
NOT reset `pindex_best_header` — it stays pinned at the imported old tip
because `header_admit` advances it forward-only
(`engine/jobs/src/header_admit_stage.c:420-429`). So every staged step extends the
active-chain window to a target far above the fold frontier.

## Ranked bottlenecks (dominant first)

### #1 — per-block full-height `pprev` walk (CPU/cache-bound)
`tip_finalize` no longer retracts the active-chain coverage window during a
refold — `active_chain_move_window_tip` is gated on `!refold_in_progress()`
(`engine/jobs/src/tip_finalize_stage.c:586`), so the first window-fill pass is
the only full walk and every later extend is an O(1) no-op. (An earlier
attempt to route this through `active_chain_extend_window_have_data` was
rejected — that primitive had an unbounded scan and a heap-overflow defect on
forked chains; do not resurrect it.)

### #2 — scheduler ceiling: 1 thread, 2s period, batch 100 → ~50 blk/s
All 8 stages run on ONE supervisor thread (`platform/modules/util/src/supervisor.c:323-340`);
each `on_tick` fires only when `now-last_tick >= period_secs(=2)*1e6`
(`engine/supervisors/src/staged_sync_supervisor.c:249`), draining a batch (tail
stages capped 100). Sequential gating (`utxo_apply` idle when `next_h >=
proof_validate`, `utxo_apply_stage.c:302`) makes the slowest tail stage the rate.
Once #1 lands, 100/2s = 50 blk/s is the next ceiling → still ~17h to checkpoint.

FIX (#2): during refold, lower the tail-stage period to sub-second and/or raise
the tail batch (100→~2000). Compile-time consts in `engine/jobs/include/jobs/*_stage.h`
today; thread a refold-gated override. Needs batched commits (io-speedups) so a
big batch is one fsync, not 2000.

### #3 — utxo_mirror_sync full wipe+reinsert every 5s (O(n), goes quadratic)
`utxo_mirror_sync_run_once` early-returns during a refold
(`engine/services/src/utxo_mirror_sync_service.c:446`) instead of doing a full
`DELETE FROM utxos` + per-row reinsert on every 5s tick; the mirror rebuilds
once, after the fold completes.

### #4 — `utxo_apply_sums_through` O(height) scan/block (latent, O(height²))
`tip_finalize` step calls `SUM(...) FROM utxo_apply_log WHERE height<=? AND ok=1`
per block (`tip_finalize_stage.c:451` → `tip_finalize_log_store.c:73`). Only when
a `live_utxo_count_after` counter is wired (NULL skips). Maintain a running total
incrementally instead.

## Non-factors (ruled out)
- Per-block fsync: with io-speedups it's 1 COMMIT/100-block drain; CPU is 76%
  (busy), not blocked on disk. Real but secondary.
- Watchdog / condition_engine / observer / activation lock contention: those
  paths take neither `progress_store_tx_lock` nor coins_kv; ruled out for a
  peerless refold.

## io-speedups reorg bug — fixed, watch for regression
The batch-aware cursor writers (`cursor_txn_begin/commit/rollback`,
`STAGE_CURSOR_SP` savepoint in `core/modules/sync/src/stage.c`) are guarded by focused
regression coverage in `test_stage.c` (group `stage`, "batch-cursor" checks).
`stage_set_cursor` (`core/modules/sync/src/stage.c:510`) and
`stage_set_named_cursor_if_behind` (`:551`) do an unconditional `BEGIN IMMEDIATE`.
Inside an open batch (the reorg-rewind path `tip_finalize_stage.c:286` calls
set_cursor) SQLite rejects the nested BEGIN → "cannot start a transaction within
a transaction" (test_reducer_ingest_e2e reorg case). Make both batch-aware
(SAVEPOINT/RELEASE/ROLLBACK-TO when `stage_batch_active()`), mirroring
`stage_run_once` (`:413`).

## Order of work
1. Fix the io-speedups reorg bug (unblocks the test suite + batched commits).
2. #1 window bound (the 380x win). Re-measure.
3. #3 mirror gate. #2 batch/period. Re-measure to a feasible rate.
4. Then run the correctness proof to the checkpoint.
