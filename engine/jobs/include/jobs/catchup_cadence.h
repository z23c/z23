/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * catchup_cadence — the live-sync catch-up drain-batch override.
 *
 * The supervisor drives each of the eight reducer stages once per tick
 * (period_secs=2, staged_sync_supervisor.c) with a per-stage batch cap. The
 * four tail stages (script_validate, proof_validate, utxo_apply,
 * tip_finalize — see their *_BATCH_PER_TICK macros) are capped at 100, so an
 * ordinary node that fell behind (bodies already on disk, nothing to fetch
 * over P2P, purely reducer-bound) is hard-floored at 100/2s = ~50 blk/s no
 * matter how fast the disk/CPU actually are. This override lifts that floor
 * to 2000/1s ONLY while the node is genuinely far behind the
 * network tip, without touching the shared 2s tick period (the supervisor is
 * single-threaded and shared across many domains — shortening the period
 * would starve everything else, unlike refold_cadence's period override,
 * which only ever applies during an OFFLINE from-genesis/from-anchor fold
 * with no live peers/other domains to starve).
 *
 * GAP MEASUREMENT — reuses, with ZERO new lock surface, the exact primitives
 * engine/conditions/src/sync_rate_below_floor.c already uses for the same
 * gap computation:
 *   - network tip:  connman_max_peer_height(sync_monitor_connman())
 *   - log head:     tip_finalize_stage_cursor() (lock-free atomic read —
 *                    see "Threading" in platform/modules/util/include/util/stage.h)
 * Neither touches progress_store, coins_kv, or any lock the reducer drive
 * holds (LOCK-ORDER LAW, feedback_reducer_drive_lock_order_law.md) — this
 * module reads the same two already-safe accessors and adds no new ones.
 *
 * SAFETY — the override is GATED on catchup_cadence_active(): true ONLY
 * when peers are connected AND the gap (network_tip - log_head) is at least
 * ZCL_CATCHUP_GAP_THRESHOLD (default 500). On a NORMAL live node at/near tip,
 * or with no peers, this is false, so catchup_cadence_drain_batch() returns
 * its argument UNCHANGED and the live hot path is BYTE-FOR-BYTE unchanged.
 * This is the load-bearing safety property, pinned by test_catchup_cadence:
 * normal mode MUST stay batch=<stage default>.
 *
 * Widening the per-drain batch only widens the commit window of the
 * existing per-batch SAVEPOINT/BEGIN IMMEDIATE (one COMMIT per 2000 instead
 * of per 100); correctness is unchanged and a crash resumes idempotently
 * from the last durable cursor, same as always. The bounded risk is one
 * run_due_ticks() pass taking longer wall-clock while active. The 2000-block
 * value is measured rather than projected: over a fixed 360-second budget on
 * a frozen corpus it processed 36,810 blocks vs. 29,000 for the 500-block
 * value (+26.9%), with the slowest observed
 * utxo_apply subphase taking 8.485s. Fan-out stages (validate_headers) stay
 * bounded by stage_effective_batch: their catch-up step count scales only
 * with the catch-up Equihash pool width actually in force
 * (validate_headers_stage_catchup_step_cap, max VH_CATCHUP_STEP_MULT x), so
 * per-tick wall time stays bounded; the full 2000-block window applies only
 * to stages whose step_once performs one block of work.
 *
 * TICK-PERIOD OVERRIDE — catchup_cadence_tick_period_us() — shortens the
 * PER-CHILD tick period for the eight staged-sync children ONLY, from the
 * shared 2s default down to 1s (clamped [1000,2000] ms), while
 * catchup_cadence_active() holds. This looked unsafe in an earlier revision
 * of this comment ("shortening the period would starve everything else")
 * but that concern was about lowering the GLOBAL supervisor sweep wake
 * (g_tick_ms, supervisor_request_min_tick_ms() in platform/modules/util/src/supervisor.c
 * — monotonic-DOWN-only, NEVER touched by this module). A per-child
 * `period_us` is a completely different knob (platform/modules/util/src/supervisor.c's
 * sweep: `period_window_us = period_us > 0 ? period_us : period_secs *
 * 1000000`) — it only changes how often THIS child's on_tick is marked due;
 * every other supervisor child keeps its own period untouched. The sweep's
 * default wake (g_tick_ms) is already 1000ms, i.e. >= our 1s floor, so a
 * 1s-2s per-child period needs no change to the global wake at all — unlike
 * refold_cadence's 250ms period, which genuinely does need
 * supervisor_request_min_tick_ms() to fire on time. Doubling the per-child
 * tick rate roughly doubles catch-up throughput on top of the drain-batch
 * widening above (2 * ~250 blk/s ceiling -> ~500 blk/s), still gated
 * entirely on catchup_cadence_active() so a normal at-tip node is
 * byte-for-byte unchanged (period_us resets to 0 the instant the cadence
 * deactivates — see staged_sync_supervisor.c's staged_stage_tick).
 *
 * TUNABLE (only while active):
 *   ZCL_CATCHUP_GAP_THRESHOLD  blocks   default  500   clamp [1,100000000]
 *   ZCL_CATCHUP_DRAIN_BATCH    blocks   default 2000   clamp [1,1000000]
 *   ZCL_CATCHUP_TICK_MS        ms       default  1000  clamp [1000,2000]
 */

#ifndef ZCL_JOBS_CATCHUP_CADENCE_H
#define ZCL_JOBS_CATCHUP_CADENCE_H

#include <stdbool.h>
#include <stdint.h>

/* Accelerated-cadence defaults (used when active + the env var is unset).
 * 2000 is the measured C3 throughput winner documented above. */
#define CATCHUP_CADENCE_DEFAULT_DRAIN_BATCH 2000
#define CATCHUP_CADENCE_DEFAULT_GAP_THRESHOLD 500
#define CATCHUP_CADENCE_DEFAULT_TICK_MS 1000

/* True iff the node has connected peers AND is at least
 * ZCL_CATCHUP_GAP_THRESHOLD blocks behind the max peer-reported height.
 * Cheap: connman_max_peer_height() + one lock-free atomic cursor read, the
 * same two calls sync_rate_below_floor.c already makes every poll. False on
 * a normal at-tip live node or a node with no peers -> every accessor below
 * is inert. */
bool catchup_cadence_active(void);

/* Per-stage drain batch. Returns `normal_batch` UNCHANGED when inactive;
 * when active, returns ZCL_CATCHUP_DRAIN_BATCH (default 2000, clamped). */
int catchup_cadence_drain_batch(int normal_batch);

/* Per-child supervisor tick period in microseconds. Returns 0 when inactive
 * (=> the caller uses its normal period_secs, unchanged); when active,
 * returns ZCL_CATCHUP_TICK_MS * 1000 (default 1000ms, clamped [1000,2000]).
 * See the TICK-PERIOD OVERRIDE section above for why this is safe without
 * touching the global supervisor min-tick. */
int64_t catchup_cadence_tick_period_us(void);

#ifdef ZCL_TESTING
/* Force the log_head (tip_finalize) cursor reader to return `v` instead of
 * calling the real tip_finalize_stage_cursor() — same override shape as
 * sync_rate_below_floor_test_set_log_head_override(), so a unit test does
 * not need a real progress_store-backed tip_finalize_stage_init(). -1 = use
 * the real reader. Peers/network-tip are driven with a real (test-populated)
 * struct connman via sync_monitor_set_context(), same as
 * test_sync_rate_below_floor.c. */
void catchup_cadence_test_set_log_head_override(int64_t v);

/* Reset all test-only state (the log_head override) back to "use the real
 * reader". */
void catchup_cadence_test_reset(void);
#endif

#endif /* ZCL_JOBS_CATCHUP_CADENCE_H */
