/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Reducer drain core — the bounded round loop that drives the eight staged-Job
 * step bodies to convergence, plus the two public kick entry points
 * (reducer_kick for the supervisor/FSM path, reducer_kick_unbudgeted for the
 * dedicated -mint-anchor driver). Split out of reducer_ingest_service.c (which
 * keeps the synchronous block-intake path) so each file holds one seam.
 *
 * LIVELOCK GUARD: reducer_kick_unbudgeted must never run with NO wall-clock
 * budget and NO frontier-progress check — one call could drain
 * hard_cap(64) * ZCL_REFOLD_DRAIN_BATCH(2000) = 128k blocks back-to-back —
 * HOURS under the fsync-bound fold rate — starving the boot_mint_anchor drive
 * loop (which logs progress and runs the stall detector BETWEEN kicks) of
 * control: the forbidden quiet spin. Two bounds close it:
 *   (1) converge_on_frontier_stall — a round that advances upstream stages but
 *       not the utxo_apply frontier returns immediately (a walled fold hands
 *       control back so the driver fails closed with a named blocker);
 *   (2) a generous wall-clock budget (ZCL_MINT_KICK_BUDGET_MS, default 3000)
 *       checked at ROUND boundaries only, so the per-batch fsync cadence (the
 *       fold's throughput lever) is untouched.
 * Guarded by tests/harness/src/test_reducer_step_drain_harness.c
 * (test_mint_fold_livelock). */

// one-result-type-ok:reducer-drive-counts
/* The reducer entry points return advance-counts; a failure surfaces via the
 * stage FATAL latch + EV_OPERATOR_NEEDED, not a return-value reason (same
 * rationale as reducer_ingest_service.c). */

#include "services/chain_activation_service.h"
#include "services/reducer_ingest_service.h"
#include "services/reducer_drain.h"

#include "event/event.h"
#include "core/utiltime.h"
#include "util/blocker.h"
#include "util/hw_bench.h"
#include "util/hw_profile.h"  /* hw_profile_drain_batch_effective (K3 lever) */
#include "util/log_macros.h"
#include "util/reducer_drive_guard.h"
#include "util/stage.h"
#include "util/thread_registry.h"  /* thread_registry_shutdown_requested */

#include "jobs/header_admit_stage.h"
#include "jobs/validate_headers_stage.h"
#include "jobs/body_fetch_stage.h"
#include "jobs/body_persist_stage.h"
#include "jobs/script_validate_stage.h"
#include "jobs/proof_validate_stage.h"
#include "jobs/utxo_apply_stage.h"
#include "jobs/tip_finalize_stage.h"
#include "jobs/refold_cadence.h"   /* refold_cadence_drain_batch (mint/refold) */
#include "jobs/catchup_cadence.h"  /* peer-gap-gated live-sync batch */
#include "jobs/reducer_frontier.h" /* reducer_frontier_provable_tip_cached (H* gate) */
#include "storage/coins_kv.h"
#include "storage/progress_store.h"
#include "validation/chainstate.h" /* active_chain_tip (regtest at-tip publish) */
#include "chain/chain.h"           /* BLOCK_FAILED_MASK */
#include "chain/chainparams.h"     /* struct chain_params (fMineBlocksOnDemand) */

#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>    /* snprintf */
#include <stdlib.h>   /* getenv, strtoll */
#include <string.h>   /* memset */

bool reducer_at_tip_authority_ready(
    const struct reducer_at_tip_authority_observation *obs)
{
    if (!obs || obs->hstar < 0 || obs->active_height < 0 ||
        obs->active_height == INT32_MAX)
        return false;

    /* Close exactly the ordinary H* -> applied-head edge. Every other shape
     * remains with the existing lookahead/failure machinery: no multi-height
     * authority jump, no header-tip lag, and no failed or foreign candidate. */
    return !obs->block_failed && obs->active_hash_matches_best &&
           obs->best_header_height == obs->active_height &&
           obs->hstar + 1 == obs->active_height &&
           obs->coins_applied_found &&
           obs->coins_applied_height == obs->active_height + 1 &&
           obs->tip_finalize_cursor == (uint64_t)obs->active_height &&
           obs->utxo_apply_succeeded && obs->normal_lookahead_missing;
}

/* Clamped env int; `def` when unset/empty/unparsable (mirrors
 * refold_cadence.c's cadence_env_int — local so this TU owns no cross-TU
 * dependency for one knob). */
static int64_t env_int_default(const char *name, int64_t def, int64_t lo,
                               int64_t hi)
{
    const char *v = getenv(name);
    if (!v || !v[0])
        return def;
    char *end = NULL;
    long long n = strtoll(v, &end, 10);
    if (end == v)
        return def;
    if (n < lo) n = lo;
    if (n > hi) n = hi;
    return (int64_t)n;
}

/* ── The eight staged-Job stages, in pipeline order ──────────────────────
 * One descriptor per stage: the bounded drain entry point (returns the count
 * of advancing steps) and the cheap in-memory cursor reader (a lock-free
 * stage_cursor(g_stage) read — NOT the SQL stage_cursor table, per the
 * hot-path rule). Both the drain loop and the advance-or-blocker
 * reconciliation walk this one table so their stage indices never diverge. */
struct drain_stage_desc {
    const char *name;
    int      (*drain)(int max_steps);
    uint64_t (*cursor)(void);
};

static const struct drain_stage_desc g_drain_stages[REDUCER_DRAIN_NUM_STAGES] = {
    { "header_admit",     header_admit_stage_drain,     header_admit_stage_cursor },
    { "validate_headers", validate_headers_stage_drain, validate_headers_stage_cursor },
    { "body_fetch",       body_fetch_stage_drain,       body_fetch_stage_cursor },
    { "body_persist",     body_persist_stage_drain,     body_persist_stage_cursor },
    { "script_validate",  script_validate_stage_drain,  script_validate_stage_cursor },
    { "proof_validate",   proof_validate_stage_drain,   proof_validate_stage_cursor },
    { "utxo_apply",       utxo_apply_stage_drain,       utxo_apply_stage_cursor },
    { "tip_finalize",     tip_finalize_stage_drain,     tip_finalize_stage_cursor },
};

/* Index of the utxo_apply stage in g_drain_stages — the fold's real
 * forward-progress metric (the converge_on_frontier_stall break reads it). */
#define REDUCER_DRAIN_UTXO_APPLY_IDX 6

/* ── Advance-or-blocker reconciliation state ─────────────────────────────
 * Per-stage consecutive rounds where the stage reported advances>0 but its own
 * cursor did NOT move, plus the steps it reported across that streak, plus a
 * flag tracking whether a "stage_spin_<name>" blocker is currently set for the
 * stage. Written only from reducer_drain_core, which every entry point reaches
 * while holding chain_activation_controller::mutex, so the writer is
 * single-threaded; the reducer_drive dumpstate reads them from another thread,
 * hence atomics. */
static _Atomic uint32_t g_spin_rounds_frozen[REDUCER_DRAIN_NUM_STAGES];
static _Atomic uint64_t g_spin_steps_reported[REDUCER_DRAIN_NUM_STAGES];
static _Atomic bool     g_spin_blocker_active[REDUCER_DRAIN_NUM_STAGES];

/* Consecutive-round spin threshold K (compile-time default, env override). */
static int reducer_stage_spin_rounds(void)
{
    return (int)env_int_default("ZCL_STAGE_SPIN_ROUNDS",
                                ZCL_STAGE_SPIN_ROUNDS_DEFAULT, 1, 1000000);
}

/* Build the "stage_spin_<name>" blocker id into `buf` (>= BLOCKER_ID_MAX). */
/* blocker-id: stage_spin_* */
static void reducer_spin_blocker_id(char *buf, size_t buflen, const char *name)
{
    snprintf(buf, buflen, "stage_spin_%s", name ? name : "unknown");
}

void reducer_drain_spin_observe(int stage_idx, const char *stage_name,
                                int advance, uint64_t cursor_before,
                                uint64_t cursor_after, int spin_k)
{
    if (stage_idx < 0 || stage_idx >= REDUCER_DRAIN_NUM_STAGES || !stage_name)
        return;
    if (spin_k < 1)
        spin_k = 1;

    /* Real forward progress: the spin (if any) is resolved. Reset the streak
     * and clear the standing blocker exactly once on the movement edge. */
    if (cursor_after != cursor_before) {
        atomic_store(&g_spin_rounds_frozen[stage_idx], 0u);
        atomic_store(&g_spin_steps_reported[stage_idx], 0u);
        if (atomic_exchange(&g_spin_blocker_active[stage_idx], false)) {
            char id[BLOCKER_ID_MAX];
            reducer_spin_blocker_id(id, sizeof(id), stage_name);
            blocker_clear(id);
        }
        return;
    }

    /* No advance reported and the cursor is frozen: idle / converged, not a
     * spin. Break the consecutive-round streak (re-arming needs K again). A
     * blocker that was already standing stays until real cursor movement clears
     * it — the named "no forward progress" fact is still true. */
    if (advance <= 0) {
        atomic_store(&g_spin_rounds_frozen[stage_idx], 0u);
        atomic_store(&g_spin_steps_reported[stage_idx], 0u);
        return;
    }

    /* advance > 0 AND the stage's own cursor did not move — the spin signal. */
    uint32_t rounds =
        atomic_fetch_add(&g_spin_rounds_frozen[stage_idx], 1u) + 1u;
    uint64_t steps = atomic_fetch_add(&g_spin_steps_reported[stage_idx],
                                      (uint64_t)advance) + (uint64_t)advance;
    if ((int)rounds < spin_k)
        return;

    char id[BLOCKER_ID_MAX];
    reducer_spin_blocker_id(id, sizeof(id), stage_name);
    char reason[BLOCKER_REASON_MAX];
    snprintf(reason, sizeof(reason),
             "stage=%s reported advance for %u consecutive drain rounds "
             "(steps_reported=%llu) but its cursor is frozen at height %llu — "
             "steps-reported and durable-cursor-moved diverged; observational, "
             "clears when the cursor advances",
             stage_name, rounds, (unsigned long long)steps,
             (unsigned long long)cursor_after);

    struct blocker_record r;
    if (blocker_init(&r, id, "reducer_drain", BLOCKER_TRANSIENT, reason)) {
        (void)blocker_set(&r);
        atomic_store(&g_spin_blocker_active[stage_idx], true);
    }
}

int reducer_drain_spin_snapshot(struct reducer_stage_spin_entry *out, int max)
{
    if (!out || max <= 0)
        return 0;
    int n = max < REDUCER_DRAIN_NUM_STAGES ? max : REDUCER_DRAIN_NUM_STAGES;
    for (int i = 0; i < n; i++) {
        out[i].name = g_drain_stages[i].name;
        out[i].rounds_frozen = atomic_load(&g_spin_rounds_frozen[i]);
        out[i].steps_reported = atomic_load(&g_spin_steps_reported[i]);
    }
    return n;
}

#ifdef ZCL_TESTING
void reducer_drain_spin_reset_for_testing(void)
{
    for (int i = 0; i < REDUCER_DRAIN_NUM_STAGES; i++) {
        atomic_store(&g_spin_rounds_frozen[i], 0u);
        atomic_store(&g_spin_steps_reported[i], 0u);
        if (atomic_exchange(&g_spin_blocker_active[i], false)) {
            char id[BLOCKER_ID_MAX];
            reducer_spin_blocker_id(id, sizeof(id), g_drain_stages[i].name);
            blocker_clear(id);
        }
    }
}
#endif

/* ── Drain-exit telemetry (drive+fsync telemetry gap 1) ──────────────────
 * reducer_drain_core's round loop can stop for several reasons, but only
 * TWO of them mean the same thing an operator diagnosing an IO/throughput
 * regression cares about:
 *   - drain_exit_converged_total: a round found genuinely NO more work
 *     (adv == 0) — the fold is caught up, full stop.
 *   - drain_exit_budget_total: the wall-clock budget elapsed, OR the round
 *     hard_cap was exhausted without ever converging — the fold still had
 *     (or may have had) work left but ran out of allotted time/rounds. A
 *     rising rate of this counter with a falling drain_last_round_advances
 *     is the "we are not keeping up" signal this telemetry exists to make
 *     visible.
 * The other two exits (a thread_registry_shutdown_requested() abort, and
 * the mint-only converge_on_frontier_stall break) are deliberately left out
 * of BOTH counters: shutdown is a clean deliberate stop, not a throughput
 * fact, and a frontier-walled stop already has its own dedicated signal
 * (the mint_fold.frontier_walled blocker, engine/composition/src/boot_mint_anchor.c) —
 * folding it into "converged" would mask a genuinely walled fold as healthy
 * convergence, and folding it into "budget" would misdiagnose a wall as an
 * IO/throughput stall.
 * Written only from reducer_drain_core (single-writer: every entry point
 * reaches it while holding chain_activation_controller::mutex); read from
 * the reducer_drive dumpstate thread, hence atomics. */
static _Atomic uint64_t g_drain_exit_converged_total;
static _Atomic uint64_t g_drain_exit_budget_total;
static _Atomic int64_t  g_drain_last_round_advances;
static _Atomic int64_t  g_drain_last_elapsed_us;
static _Atomic int64_t  g_drain_last_stage_us[REDUCER_DRAIN_NUM_STAGES];

/* CUMULATIVE per-stage accounting (see struct reducer_drain_exit_stats). The
 * last-round array above answers nothing about where a fold round's time goes:
 * it is overwritten every round, so an observer sampling on a timer nearly
 * always catches a converged all-idle round and reads zeros. These are
 * monotonic, so the difference between two samples is an exact interval
 * measurement. Same single-writer/atomic contract as the counters above. */
static _Atomic uint64_t g_drain_rounds_total;
static _Atomic uint64_t g_drain_stage_us_total[REDUCER_DRAIN_NUM_STAGES];
static _Atomic uint64_t g_drain_stage_calls[REDUCER_DRAIN_NUM_STAGES];
static _Atomic uint64_t g_drain_stage_advances[REDUCER_DRAIN_NUM_STAGES];

const char *reducer_drain_stage_name(int idx)
{
    if (idx < 0 || idx >= REDUCER_DRAIN_NUM_STAGES)
        return NULL;
    return g_drain_stages[idx].name;
}

void reducer_drain_exit_stats_snapshot(struct reducer_drain_exit_stats *out)
{
    if (!out)
        return;
    out->exit_converged_total = atomic_load(&g_drain_exit_converged_total);
    out->exit_budget_total    = atomic_load(&g_drain_exit_budget_total);
    out->last_round_advances  = atomic_load(&g_drain_last_round_advances);
    out->last_elapsed_us      = atomic_load(&g_drain_last_elapsed_us);
    out->rounds_total         = atomic_load(&g_drain_rounds_total);
    for (int i = 0; i < REDUCER_DRAIN_NUM_STAGES; i++) {
        out->last_stage_us[i]  = atomic_load(&g_drain_last_stage_us[i]);
        out->stage_us_total[i] = atomic_load(&g_drain_stage_us_total[i]);
        out->stage_calls[i]    = atomic_load(&g_drain_stage_calls[i]);
        out->stage_advances[i] = atomic_load(&g_drain_stage_advances[i]);
    }
}

#ifdef ZCL_TESTING
void reducer_drain_exit_stats_reset_for_testing(void)
{
    atomic_store(&g_drain_exit_converged_total, 0u);
    atomic_store(&g_drain_exit_budget_total, 0u);
    atomic_store(&g_drain_last_round_advances, 0);
    atomic_store(&g_drain_last_elapsed_us, 0);
    atomic_store(&g_drain_rounds_total, 0u);
    for (int i = 0; i < REDUCER_DRAIN_NUM_STAGES; i++) {
        atomic_store(&g_drain_last_stage_us[i], 0);
        atomic_store(&g_drain_stage_us_total[i], 0u);
        atomic_store(&g_drain_stage_calls[i], 0u);
        atomic_store(&g_drain_stage_advances[i], 0u);
    }
}
#endif

/* Drain the eight stage step bodies once, in pipeline order — the SAME
 * *_stage_drain functions the per-stage supervisor children tick
 * (staged_sync_supervisor.c). One pass; caller loops to convergence. Fills
 * `adv_per_stage` (length REDUCER_DRAIN_NUM_STAGES) with each stage's own
 * advance count so the caller can reconcile per-stage advance vs cursor
 * movement; returns the total across all stages. */
static int reducer_drain_all_stages(int max_steps_per_stage,
                                    int *adv_per_stage)
{
    int total = 0;
    atomic_fetch_add(&g_drain_rounds_total, 1u);
    for (int i = 0; i < REDUCER_DRAIN_NUM_STAGES; i++) {
        int64_t started_us = GetTimeMicros();
        int a = g_drain_stages[i].drain(max_steps_per_stage);
        int64_t elapsed_us = GetTimeMicros() - started_us;
        atomic_store(&g_drain_last_stage_us[i], elapsed_us);
        /* CUMULATIVE alongside the overwritten last-round value — three
         * relaxed adds on a path that just spent its time inside a stage
         * drain (block validation + a SQLite batch), so the cost is noise. */
        atomic_fetch_add(&g_drain_stage_us_total[i],
                         elapsed_us > 0 ? (uint64_t)elapsed_us : 0u);
        atomic_fetch_add(&g_drain_stage_calls[i], 1u);
        if (a > 0)
            atomic_fetch_add(&g_drain_stage_advances[i], (uint64_t)a);
        if (adv_per_stage)
            adv_per_stage[i] = a;
        total += a;
    }
    return total;
}

/* Shared drain core. `budget_us <= 0` means NO latency budget: keep draining
 * until convergence (a no-advance pass) or the round hard cap, whichever first.
 * The supervisor/FSM path passes a 2s budget so it yields its 2s stage ticks.
 * `per_stage_batch` sets how many blocks each stage folds under ONE batch
 * transaction (one COMMIT / fsync / ext4 journal barrier per stage per round —
 * see STAGE_DRAIN_IMPL). A larger batch drops the fsync cadence, the genesis
 * fold's dominant wait (jbd2_log_wait_commit). Full validation is identical
 * for any batch size — only the commit cadence and latency differ, never WHAT
 * a stage checks.
 *
 * `converge_on_frontier_stall` (the -mint-anchor unbudgeted path ONLY): break
 * the moment a round advances SOME stage but NOT the utxo_apply frontier (the
 * fold's real forward-progress metric). Without it, a fold walled at a low
 * height keeps `adv > 0` every round while header_admit/validate_headers grind
 * the whole upstream backlog toward the mint ceiling inside ONE call — a
 * silent multi-hour mint livelock. A healthy fold
 * advances the frontier every round (the stages run in pipeline order within a
 * round), so this fires only when the frontier is genuinely walled. */
static int reducer_drain_core(int64_t budget_us, int hard_cap,
                              int per_stage_batch,
                              bool converge_on_frontier_stall)
{
    int64_t   start_us        = GetTimeMicros();
    uint64_t  fatal_gen0      = stage_fatal_generation();
    int       total           = 0;
    int       last_adv        = 0;
    const int spin_k          = reducer_stage_spin_rounds();
    /* Exit-reason bucket for the drain-exit telemetry above. Defaults to
     * DRAIN_EXIT_BUDGET so the round hard_cap being exhausted WITHOUT any
     * explicit break (the loop condition `round < hard_cap` simply going
     * false) still lands in the "ran out of allotted capacity" bucket —
     * the correct classification, not an omission. */
    enum { DRAIN_EXIT_BUDGET = 0, DRAIN_EXIT_CONVERGED, DRAIN_EXIT_SHUTDOWN,
          DRAIN_EXIT_FRONTIER_STALL } exit_reason = DRAIN_EXIT_BUDGET;
    if (per_stage_batch <= 0) per_stage_batch = 100;
    for (int round = 0; round < hard_cap; round++) {
        /* On shutdown, return at this round boundary (a safe, committed point —
         * each stage's batch has already COMMITted) so the P2P message thread's
         * reducer activation exits promptly and connman_join succeeds instead of
         * timing out and detaching the thread under the frees that follow. The
         * fold is resumable, so stopping mid-drain loses no state. */
        if (thread_registry_shutdown_requested()) {
            exit_reason = DRAIN_EXIT_SHUTDOWN;
            break;
        }
        /* Snapshot every stage's cursor at the round boundary (cheap in-memory
         * reads). Each stage only ever moves its OWN cursor, so a round-boundary
         * before/after diff is correctly attributed per stage even though the
         * eight drains run back-to-back inside the round. */
        uint64_t cur_before[REDUCER_DRAIN_NUM_STAGES];
        for (int i = 0; i < REDUCER_DRAIN_NUM_STAGES; i++)
            cur_before[i] = g_drain_stages[i].cursor();
        uint64_t frontier_before =
            converge_on_frontier_stall
                ? cur_before[REDUCER_DRAIN_UTXO_APPLY_IDX] : 0;

        int adv_per_stage[REDUCER_DRAIN_NUM_STAGES] = {0};
        int adv = reducer_drain_all_stages(per_stage_batch, adv_per_stage);
        total += adv;
        last_adv = adv;

        /* Advance-or-blocker contract: reconcile each stage's REPORTED advance
         * against its own cursor movement. A stage that reports advances while
         * its cursor stays frozen for K consecutive rounds is named as a
         * "stage_spin_<name>" blocker (observational — this never breaks the
         * drain; the drive-age watchdog and the round budget own termination).
         * The per-stage own-cursor predicate is robust to the legitimate
         * feed-downstream case: a stage that reports advance moves its OWN
         * cursor (stage-runner contract), so reporting advance while a
         * DOWNSTREAM cursor moves instead cannot mislabel it. */
        for (int i = 0; i < REDUCER_DRAIN_NUM_STAGES; i++) {
            uint64_t cur_after = g_drain_stages[i].cursor();
            reducer_drain_spin_observe(i, g_drain_stages[i].name,
                                       adv_per_stage[i], cur_before[i],
                                       cur_after, spin_k);
        }

        if (adv == 0) {
            exit_reason = DRAIN_EXIT_CONVERGED;
            break;
        }
        /* Frontier-stall convergence (mint drive only): return NOW so the
         * boot_mint_anchor drive loop re-reads the frontier, logs, and runs
         * its stall detector instead of spinning the upstream backlog. */
        if (converge_on_frontier_stall &&
            g_drain_stages[REDUCER_DRAIN_UTXO_APPLY_IDX].cursor() ==
                frontier_before) {
            exit_reason = DRAIN_EXIT_FRONTIER_STALL;
            break;
        }
        if (budget_us > 0 && GetTimeMicros() - start_us > budget_us) {
            exit_reason = DRAIN_EXIT_BUDGET;
            break;
        }
    }
    /* Page the operator on a FATAL latched during this drain regardless of
     * which exit fired — convergence (adv==0) OR the budget timeout. A stage
     * can return JOB_FATAL every pass while another keeps advancing, so
     * total>0 and the loop exits on the budget, not on adv==0; gating the page
     * on the adv==0 break alone let that masked-FATAL recur unpaged. */
    {
        char st[STAGE_NAME_MAX] = {0}, why[128] = {0};
        if (stage_fatal_generation() != fatal_gen0 &&
            stage_last_fatal(st, sizeof(st), why, sizeof(why)))
            event_emitf(EV_OPERATOR_NEEDED, 0,
                        "condition=reducer_stage_fatal stage=%s reason=%s",
                        st, why);
    }

    /* Drain-exit telemetry (see the counters' doc comment above): record the
     * outcome of THIS drain call. Shutdown and frontier-stall exits update
     * neither total — see the doc comment for why. */
    atomic_store(&g_drain_last_round_advances, (int64_t)last_adv);
    atomic_store(&g_drain_last_elapsed_us, GetTimeMicros() - start_us);
    if (exit_reason == DRAIN_EXIT_CONVERGED)
        atomic_fetch_add(&g_drain_exit_converged_total, 1u);
    else if (exit_reason == DRAIN_EXIT_BUDGET)
        atomic_fetch_add(&g_drain_exit_budget_total, 1u);

    return total;
}

int reducer_drain_to_convergence(void)
{
    const int64_t drain_budget_us = 2000 * 1000; /* 2s, same as legacy */
    const int     drain_hard_cap  = 4096;
    /* legacy cadence (100) is the topology/no-measurement fallback;
     * hw_bench_batch_size scales it UP when boot-time measurement found a
     * slower-than-baseline fsync, so the per-batch fsync/journal-commit
     * count drops on slow storage — never below 100, see hw_bench.h. This
     * call is safe under the caller's mutex (reducer_kick) and on the live
     * block-ingest path: hw_bench_batch_size() is a plain atomic-load read,
     * never a probe — the measurement itself runs once at boot
     * (boot_datadir_lock_acquire calls hw_bench_init() right after the
     * datadir lock is acquired, before the reducer can ever run), never
     * lazily from here. */
    /* The block-swarm/message path reaches this synchronous kick directly,
     * not only the staged-sync supervisor children. Apply the SAME peer-gap-
     * gated catch-up batch policy here so block arrival cannot silently fall
     * back to the hardware baseline while the node is far behind. Inactive at
     * or near tip: catchup_cadence_drain_batch returns its argument unchanged. */
    const int per_stage_batch =
        catchup_cadence_drain_batch(hw_bench_batch_size(100));
    return reducer_drain_core(drain_budget_us, drain_hard_cap, per_stage_batch,
                              /*converge_on_frontier_stall=*/false);
}

int reducer_drain_to_convergence_unbudgeted(void)
{
    /* Drain back-to-back, NOT in 2s slices like the supervisor path — but with
     * a GENEROUS wall-clock budget so the call still returns periodically to
     * the -mint-anchor drive loop (progress logging + the stall detector run
     * BETWEEN kicks; see the file header for the livelock this closes). The
     * budget is checked only at ROUND boundaries (committed points), so the
     * per-batch fsync cadence — the fold's throughput lever — is untouched. */
    const int64_t budget_ms =
        env_int_default("ZCL_MINT_KICK_BUDGET_MS", 3000, 100, 600000);
    const int drain_hard_cap   = 64;   /* backstop cap; budget returns first */
    /* Per-stage batch: one COMMIT/fsync per this many blocks/stage. Reached
     * ONLY via reducer_kick_unbudgeted (the -mint-anchor driver), where the
     * mint fold ceiling is set, so refold_cadence_active() is true and the
     * accelerated ZCL_REFOLD_DRAIN_BATCH default (2000) applies; 1000 is the
     * fallback if this path is ever reached with the gate inactive. K3 lever:
     * when -derive-drain-batch is on, that 1000 fallback floor scales with
     * measured RAM/cores (default OFF ⇒ literal 1000, unchanged). */
    const int per_stage_batch  =
        refold_cadence_drain_batch(hw_profile_drain_batch_effective(1000));
    return reducer_drain_core(/*budget_us=*/budget_ms * 1000, drain_hard_cap,
                              per_stage_batch,
                              /*converge_on_frontier_stall=*/true);
}

/* A clean restart already restores a fully-applied coins-best tip as local
 * authority without waiting for another block. Keep a continuously-running
 * node equivalent, but only at the exact normal-lookahead edge: active tip ==
 * best header, UTXO apply and its co-committed frontier cover that tip, H* is
 * exactly one behind, and tip_finalize says the only missing fact is a
 * successor. This never promotes during catch-up or across a reject/hole. */
static void reducer_publish_fully_applied_at_tip_locked(
    struct chain_activation_controller *ctl)
{
    if (!ctl || !ctl->ms || !ctl->params ||
        ctl->params->fMineBlocksOnDemand)
        return;

    struct block_index *tip = active_chain_tip(&ctl->ms->chain_active);
    struct block_index *best = ctl->ms->pindex_best_header;
    if (!tip || !best || !tip->phashBlock || !best->phashBlock)
        return;

    sqlite3 *db = progress_store_db();
    int32_t applied = -1;
    bool applied_found = false;
    bool applied_ok = db && coins_kv_get_applied_height(
        db, &applied, &applied_found);
    const char *blocked = tip_finalize_stage_last_blocked_reason();

    struct reducer_at_tip_authority_observation obs = {
        .hstar = reducer_frontier_provable_tip_cached(),
        .active_height = tip->nHeight,
        .best_header_height = best->nHeight,
        .coins_applied_height = applied,
        .tip_finalize_cursor = tip_finalize_stage_cursor(),
        .active_hash_matches_best =
            memcmp(tip->phashBlock->data, best->phashBlock->data, 32) == 0,
        .coins_applied_found = applied_ok && applied_found,
        .utxo_apply_succeeded =
            utxo_apply_stage_succeeded_at(tip->nHeight),
        .normal_lookahead_missing =
            blocked && strcmp(blocked, "lookahead_tip_missing") == 0,
        .block_failed = (tip->nStatus & BLOCK_FAILED_MASK) != 0,
    };
    if (!reducer_at_tip_authority_ready(&obs))
        return;

    LOG_INFO("reducer",
             "[reducer] publishing fully-applied at-tip authority h=%d "
             "(continuous equivalent of clean-restart restore)",
             tip->nHeight);
    tip_finalize_stage_set_authoritative_tip(tip->nHeight,
                                             tip->phashBlock->data);
}

void reducer_publish_fully_applied_at_tip(
    struct chain_activation_controller *ctl)
{
    if (!ctl)
        return;
    zcl_mutex_lock(&ctl->mutex);
    reducer_publish_fully_applied_at_tip_locked(ctl);
    zcl_mutex_unlock(&ctl->mutex);
}

int reducer_kick(struct chain_activation_controller *ctl)
{
    if (!ctl)
        return 0;
    zcl_mutex_lock(&ctl->mutex);
    /* The normal network/FSM kick emits the same block/header events as the
     * unbudgeted mint drive. Give it the same crash-ordered batch boundary;
     * the depth-counted scope makes this a no-op when an ingest caller already
     * owns the outer scope. */
    reducer_drive_enter_labeled("reducer_kick");
    reducer_enter_batched_body_sync();
    int advanced = reducer_drain_to_convergence();
    reducer_exit_batched_body_sync();
    reducer_drive_exit();

    /* Regtest on-demand at-tip publish (the P2P-FOLLOWER counterpart to the
     * self-mined publish in reducer_ingest_block). On a fMineBlocksOnDemand
     * node the last block at the tip has NO successor to witness its
     * canonicity, so tip_finalize's one-block lookahead can never finalize it
     * — the miner works around this by publishing its just-mined tip via the
     * trusted-tip authority inline, but a follower folds received blocks
     * through this async drive and would otherwise leave H* (getblockcount)
     * one block below the applied active tip forever (proven: follower reaches
     * active tip N but getblockcount stalls at N-1). Once the drive has
     * converged, if the active tip is fully applied (utxo_apply succeeded) yet
     * tip_finalize has not published it, publish it here — the same
     * self-authority the miner uses, no successor required. Gated on
     * fMineBlocksOnDemand (true ONLY for regtest): on main/testnet this whole
     * branch is skipped. */
    if (ctl->params && ctl->params->fMineBlocksOnDemand && ctl->ms) {
        struct block_index *tip = active_chain_tip(&ctl->ms->chain_active);
        /* Gate on the PROVABLE tip (H*) trailing the applied active tip, NOT
         * the finalize cursor: step_finalize can advance the served-tip cursor
         * to N while the tip_finalize_LOG still lacks a counted row at N (its
         * one-block-lookahead never wrote N's finalized row without a
         * successor), so H* / getblockcount sit at N-1. set_authoritative_tip
         * writes the authority anchor row at N (ensure_authority_anchor_row runs
         * even when cursor==N) and republishes H*, lifting the provable tip to
         * the applied tip. Idempotent once H* == N (this branch no longer
         * fires). */
        if (tip && tip->phashBlock &&
            !(tip->nStatus & BLOCK_FAILED_MASK) &&
            utxo_apply_stage_succeeded_at(tip->nHeight) &&
            reducer_frontier_provable_tip_cached() < tip->nHeight)
            tip_finalize_stage_set_authoritative_tip(tip->nHeight,
                                                     tip->phashBlock->data);
    }

    reducer_publish_fully_applied_at_tip_locked(ctl);

    zcl_mutex_unlock(&ctl->mutex);
    return advanced;
}

int reducer_kick_unbudgeted(struct chain_activation_controller *ctl)
{
    if (!ctl)
        return 0;
    /* The dedicated -mint-anchor driver's tight drain: same locking + drive
     * marking as reducer_kick, but the inner drain is budgeted in seconds (not
     * 2s slices) and converges on a frontier stall. Held under ctl->mutex for
     * the whole drain — the same serialization point the supervisor takes — so
     * no concurrent supervisor drain races the active-chain window. Full
     * validation is unchanged. */
    zcl_mutex_lock(&ctl->mutex);
    reducer_drive_enter();
    reducer_enter_batched_body_sync();
    int advanced = reducer_drain_to_convergence_unbudgeted();
    reducer_exit_batched_body_sync();
    reducer_drive_exit();
    zcl_mutex_unlock(&ctl->mutex);
    return advanced;
}
