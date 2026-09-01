/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Reducer-ingest service — private cross-TU seam.
 *
 * The reducer-ingest path (reducer_is_authoritative / reducer_kick /
 * reducer_ingest_block and their staged-drain helpers) lives in
 * reducer_ingest_service.c; the activation FSM half lives in
 * chain_activation_service.c. The PUBLIC reducer entry points keep
 * their declarations in services/chain_activation_service.h (unchanged for
 * every caller); this header only re-exports the ONE helper the activation
 * FSM half still needs across the TU boundary:
 *
 *   reducer_drain_to_convergence() — the non-locking staged-Job drain.
 *   activation_request_connect() (the FSM half, in
 *   chain_activation_service.c) calls it directly while already holding
 *   ctl->mutex; the locking reducer_kick / reducer_ingest_block entry points
 *   (in reducer_ingest_service.c) take that same mutex and would deadlock if
 *   used there. Both TUs include this header for the shared forward decl. */

#ifndef ZCL_REDUCER_INGEST_SERVICE_H
#define ZCL_REDUCER_INGEST_SERVICE_H

#include <stdint.h>

/* Runtime tip_finalize anchor re-seed wrapper (2 call sites in
 * reducer_ingest_block). tip_finalize_stage_seed_anchor() is best-effort and
 * idempotent by design (INSERT-OR-IGNORE; see the call-site comments), but its
 * result used to be discarded via (void) — so a runtime re-seed that keeps
 * failing (a silent-stall SEED) left no trace. This wrapper LOG_WARNs + counts
 * the failure with the caller's `why` context WITHOUT changing the deliberately
 * non-fatal control flow: a failed re-seed must not abort the in-flight ingest,
 * so this is LOG_WARN (continue), never LOG_FAIL (return). `why` names which
 * call site fired, for log attribution. Non-static so the test TU can drive it
 * directly. */
void reducer_ingest_try_seed_anchor(int height, const uint8_t hash[32],
                                    const char *why);

/* Monotonic count of runtime seed-anchor re-seed failures since process start
 * (for observability / the reducer_ingest_e2e test). */
uint64_t reducer_ingest_seed_anchor_reseed_failure_count(void);

/* Loop the eight stage step bodies to convergence within a bounded latency
 * budget. The CALLER must hold the chain_activation_controller mutex — this
 * helper does NOT lock. Returns the total number of stage advances. */
int reducer_drain_to_convergence(void);

/* Same staged-Job drain, but with NO latency budget: loop until a no-advance
 * pass (convergence) or the round hard cap. The CALLER must hold the
 * chain_activation_controller mutex — this helper does NOT lock. Used only by
 * the -mint-anchor tight driver (via reducer_kick_unbudgeted) so the
 * genesis..anchor fold drains back-to-back instead of in 2s slices. Returns
 * the total number of stage advances. */
int reducer_drain_to_convergence_unbudgeted(void);

/* ── Batched block-body fdatasync scoping (reducer_body_fsync.c) ─────────
 * Bracket a reducer drive so the per-block block-file fdatasync
 * (write_block_to_disk in reducer_persist_ingested_body_locked) is deferred to
 * the stage drain-batch boundary instead of firing once per block. enter()
 * registers the stage_batch_end pre-commit hook once (fdatasync every deferred
 * body BEFORE the stage cursor / *_log rows that reference it commit) and turns
 * on disk_block_io deferred mode; exit() does a final flush and leaves deferred
 * mode so unrelated write_block_to_disk callers keep their immediate sync. Call
 * Scopes are nestable: the async catch-up worker opens one outer scope around
 * its body batch while each individual reducer submission retains its existing
 * inner scope. Only the outermost exit flushes and disables deferred mode.
 * The stage pre-commit hook preserves the body-before-cursor durability order
 * if another reducer stage commits while the outer scope is open. */
void reducer_enter_batched_body_sync(void);
void reducer_exit_batched_body_sync(void);

/* Timing snapshot for the batched pre-commit durability flush (drive+fsync
 * telemetry gap 2): last_flush_us is the most recent single flush's
 * wall-clock duration; flush_us_ewma is its exponential moving average
 * (alpha = 1/16, integer arithmetic, same shape as
 * platform/modules/util/src/stage.c's step_us_ewma). Either output pointer may be NULL.
 * Lock-free atomic reads, no allocation — safe from the reducer_drive
 * dumpstate / batch_fsync_slow condition thread while a drive runs. Both
 * read 0 before the first batch commit is ever observed. */
void reducer_body_fsync_timing_snapshot(int64_t *last_flush_us,
                                        int64_t *flush_us_ewma);

/* Running totals beside the EWMA above: how many pre-commit durability
 * flushes have run and their summed wall time. A flush is the fold's ONE
 * remaining fsync/journal-barrier point per committed batch, so `count` is
 * literally the number of durability barriers paid — the number behind claims
 * of the form "at tip we pay N barriers per block" (divide the delta by the
 * blocks folded over the same interval). The EWMA alone cannot answer that:
 * it smooths one duration and counts nothing. Monotonic; difference two
 * snapshots for an interval. Either output pointer may be NULL. Lock-free
 * atomic reads, no allocation. */
void reducer_body_fsync_totals_snapshot(uint64_t *flush_count,
                                        uint64_t *flush_us_total);

/* Live batching-state snapshot. `depth` is the global nest count and
 * `event_log_deferred` proves the CURRENT singleton handle is actually armed
 * (not merely that an outer scope once entered before the handle existed).
 * Either output pointer may be NULL. */
void reducer_body_fsync_scope_snapshot(unsigned *depth,
                                       bool *event_log_deferred);

#ifdef ZCL_TESTING
/* Force an artificial delay (microseconds) at the top of the next and every
 * subsequent precommit flush, so a test can prove the timing/EWMA/condition
 * wiring fires on a genuine slow flush without a real contended disk. 0
 * (the default) restores the real (fast) precommit path. */
void reducer_body_fsync_test_set_inject_delay_us(int64_t us);
/* Zero the timing atomics + the injected delay. */
void reducer_body_fsync_test_reset(void);
/* Invoke the precommit flush directly (bypasses needing a real open
 * stage_batch/DB — see the .c file for why this is safe). Returns the same
 * veto verdict the real stage_batch_end() hook would receive. */
bool reducer_body_fsync_test_trigger_precommit(void);
#endif

#endif /* ZCL_REDUCER_INGEST_SERVICE_H */
