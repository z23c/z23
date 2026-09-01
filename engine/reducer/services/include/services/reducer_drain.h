/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * reducer_drain — cross-TU seam for the drain-core advance-or-blocker
 * contract (engine/services/src/reducer_drain.c).
 *
 * The drain core drives the eight staged-Job step bodies round by round. A
 * healthy stage that reports advances has, by the stage-runner contract
 * (platform/modules/util/src/stage.c), moved its own cursor forward — JOB_ADVANCED persists
 * a strictly-greater cursor or the runner rolls the step back to JOB_FATAL. The
 * advance-or-blocker reconciliation makes the DIVERGENCE a named fact: a stage
 * that reports advances>0 while its own in-memory cursor stays frozen for
 * `spin_k` consecutive rounds registers a TRANSIENT blocker rather than burning
 * CPU as invisible "steps taken". It is observational — it never stops the
 * drain (the drive-age watchdog + the round budget own termination).
 *
 * Two consumers cross the TU boundary:
 *   - the `reducer_drive` dumpstate (engine/conditions/src/reducer_drive_watchdog.c)
 *     reads the per-stage spin counters via reducer_drain_spin_snapshot();
 *   - the regression harness (tests/harness/src/test_reducer_step_drain_harness.c)
 *     drives the reconciliation predicate directly via
 *     reducer_drain_spin_observe() with a synthetic advance-without-cursor-move
 *     stub. */

#ifndef ZCL_SERVICES_REDUCER_DRAIN_H
#define ZCL_SERVICES_REDUCER_DRAIN_H

#include <stdbool.h>
#include <stdint.h>

struct chain_activation_controller;

/* The eight staged-Job reducer stages, in pipeline order. */
#define REDUCER_DRAIN_NUM_STAGES 8

/* Compile-time default for the consecutive-round spin threshold K; override at
 * runtime with the env var ZCL_STAGE_SPIN_ROUNDS. */
#define ZCL_STAGE_SPIN_ROUNDS_DEFAULT 8

/* Per-stage spin snapshot entry (feeds the reducer_drive dumpstate). `name`
 * aliases a static string literal owned by reducer_drain.c. */
struct reducer_stage_spin_entry {
    const char *name;
    uint32_t rounds_frozen;    /* consecutive advance-yet-frozen rounds */
    uint64_t steps_reported;   /* steps the stage reported across that streak */
};

/* Copy the per-stage spin counters into `out` (capacity `max`). Lock-free
 * atomic reads, no allocation — safe to call from the dump/RPC thread while a
 * drive runs. Returns the number of entries written (min(max, NUM_STAGES)). */
int reducer_drain_spin_snapshot(struct reducer_stage_spin_entry *out, int max);

/* Reconcile ONE stage's reported advance against its own cursor movement for a
 * single drain round (the advance-or-blocker predicate the drain core applies
 * to each stage each round):
 *   - cursor_after != cursor_before  -> real forward progress: reset the
 *     stage's streak and clear any standing "stage_spin_<name>" blocker.
 *   - advance <= 0 (idle/converged)  -> not a spin: reset the streak; a
 *     standing blocker persists until real cursor movement clears it.
 *   - advance > 0 && cursor frozen   -> the spin signal: increment the streak;
 *     at `spin_k` consecutive rounds register the TRANSIENT blocker
 *     "stage_spin_<name>" (owner "reducer_drain") naming the stage, the round
 *     count, the steps reported, and the frozen cursor height.
 * Never stops the drain. Exposed so the regression harness can drive the exact
 * predicate with a synthetic stub stage. */
void reducer_drain_spin_observe(int stage_idx, const char *stage_name,
                                int advance, uint64_t cursor_before,
                                uint64_t cursor_after, int spin_k);

#ifdef ZCL_TESTING
/* Zero every per-stage spin counter and clear any stage_spin_* blocker. */
void reducer_drain_spin_reset_for_testing(void);
#endif

/* Drain-exit telemetry snapshot (drive+fsync telemetry gap 1): deconflates
 * "the drain converged" (genuinely no more work) from "the drain hit the
 * budget ceiling" (wall-clock budget elapsed, or the round hard_cap was
 * exhausted without converging) — see the counters' doc comment in
 * reducer_drain.c for exactly what does and does not count toward each
 * total. Consumed by the reducer_drive dumpstate
 * (engine/conditions/src/reducer_drive_watchdog.c). Lock-free atomic reads, no
 * allocation. */
struct reducer_drain_exit_stats {
    uint64_t exit_converged_total;
    uint64_t exit_budget_total;
    int64_t  last_round_advances;  /* adv count of the last round run */
    int64_t  last_elapsed_us;      /* wall-clock time of the last drain call */
    int64_t  last_stage_us[REDUCER_DRAIN_NUM_STAGES];
    /* CUMULATIVE per-stage accounting. last_stage_us above describes ONLY the
     * most recent round and is overwritten every round, so it cannot answer
     * "where does a fold round's time go" — a sample almost always lands on a
     * converged (all-idle) round and reads as zeros. These four are monotonic
     * since process start, so any two samples give an exact interval share:
     *   stage_us_total  — microseconds spent inside that stage's drain entry
     *   stage_calls     — times the stage's drain entry was invoked (== rounds)
     *   stage_advances  — steps the stage reported as advancing, summed
     *   rounds_total    — drain rounds run (one round = one pass over all eight)
     * Wall-clock share of stage i over an interval is
     * d(stage_us_total[i]) / sum_j d(stage_us_total[j]); microseconds per
     * advancing block is d(stage_us_total[i]) / d(stage_advances[i]). */
    uint64_t rounds_total;
    uint64_t stage_us_total[REDUCER_DRAIN_NUM_STAGES];
    uint64_t stage_calls[REDUCER_DRAIN_NUM_STAGES];
    uint64_t stage_advances[REDUCER_DRAIN_NUM_STAGES];
};
void reducer_drain_exit_stats_snapshot(struct reducer_drain_exit_stats *out);

/* Pipeline-order name of drain stage `idx`, or NULL when out of range. The one
 * authority for the stage names (reducer_drain.c's g_drain_stages table); the
 * reducer_drive dumpstate reads it instead of keeping a second hand-maintained
 * copy that could silently drift out of order. */
const char *reducer_drain_stage_name(int idx);

/* Exact steady-tip shape where the runtime may publish the same fully-applied
 * local authority that a clean restart already restores. This deliberately
 * closes ONE normal lookahead edge only; it can never jump a lagging H*, bless
 * a different best-header hash, or publish coins that are not co-committed
 * through the candidate height. */
struct reducer_at_tip_authority_observation {
    int32_t hstar;
    int32_t active_height;
    int32_t best_header_height;
    int32_t coins_applied_height;
    uint64_t tip_finalize_cursor;
    bool active_hash_matches_best;
    bool coins_applied_found;
    bool utxo_apply_succeeded;
    bool normal_lookahead_missing;
    bool block_failed;
};

/* Pure predicate shared by the live reducer and its regression harness. */
bool reducer_at_tip_authority_ready(
    const struct reducer_at_tip_authority_observation *obs);

/* Re-evaluate and, only for the exact observation above, publish the fully
 * applied at-tip authority. Safe from a supervisor tick: acquires the chain
 * activation controller mutex internally. */
void reducer_publish_fully_applied_at_tip(
    struct chain_activation_controller *ctl);

#ifdef ZCL_TESTING
/* Zero every drain-exit counter (test isolation only — process-global). */
void reducer_drain_exit_stats_reset_for_testing(void);
#endif

#endif /* ZCL_SERVICES_REDUCER_DRAIN_H */
