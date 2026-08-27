/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Staged-sync supervisor children. Owns liveness contracts for the
 * authoritative eight-stage reducer pipeline in the chain domain.
 *
 * staged_sync_supervisor_register() registers them in pipeline order:
 *   header_admit → validate_headers → body_fetch → body_persist →
 *   script_validate → proof_validate → utxo_apply → tip_finalize.
 *
 * Every stage shares one wiring (period=2s, the 30-min progress-quiet
 * window, the chain domain, idempotent registration, the register-failure
 * WARN) and differs only by its symbol names, batch size, and stall
 * message. That common wiring is expressed once: the stages live in a
 * single `struct staged_stage_desc` table in pipeline order, and one
 * generic tick/stall/register helper reads a desc. The only genuinely
 * per-stage code — the on_stall LOG_WARN bodies and the init-failure
 * message — stays as tiny named functions/strings the table points at. */

#include "supervisors/staged_sync_supervisor.h"
#include "services/chain_activation_service.h"
#include "services/reducer_drain.h"
#include "services/reducer_ingest_service.h"
#include "util/blocker.h"
#include "util/log_macros.h"
#include "util/reducer_drive_guard.h"
#include "supervisors/domains.h"
#include "storage/progress_store.h"
#include "validation/main_logic.h"

#include "platform/time_compat.h"  /* platform_time_monotonic_us */
#include "util/supervisor.h"
#include "jobs/refold_cadence.h"   /* accelerated drain batch + tick, mint/refold only */
#include "jobs/catchup_cadence.h"  /* accelerated drain batch, live catch-up only */
#include "jobs/header_admit_stage.h"
#include "jobs/validate_headers_stage.h"
#include "jobs/body_fetch_stage.h"
#include "jobs/body_persist_stage.h"
#include "jobs/script_validate_stage.h"
#include "jobs/proof_validate_stage.h"
#include "jobs/utxo_apply_stage.h"
#include "jobs/tip_finalize_stage.h"

#include <stdatomic.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>   /* getenv, strtol */
#include <string.h>

/* Generous progress-quiet window shared by all eight stages:
 * 1800s (30 min) of IDLE before emitting a progress warning.
 * Stages legitimately idle for long stretches when the live chain is
 * waiting on input, so this is intentionally longer than the 900s
 * COORD_ESC_QUIET_US escalation window in chain_supervisor.c. */
#define STAGED_STAGE_QUIET_US ((int64_t)1800 * 1000 * 1000)

/* Stall-escalation policy (task: consecutive-quiet-window escalation).
 * Default M=2, i.e. 2 * STAGED_STAGE_QUIET_US = 60 min of continuously
 * frozen progress before staged_stage_tick names a typed
 * "stage_stalled_<name>" blocker (see staged_stage_stall_escalation_apply
 * below). Env override for operator tuning and tests. */
#define STAGE_STALL_ESCALATE_WINDOWS_DEFAULT 2

static int staged_stage_escalate_windows(void)
{
    const char *v = getenv("ZCL_STAGE_STALL_ESCALATE_WINDOWS");
    if (!v || !v[0])
        return STAGE_STALL_ESCALATE_WINDOWS_DEFAULT;
    char *end = NULL;
    long n = strtol(v, &end, 10);
    if (end == v || n < 1)
        return STAGE_STALL_ESCALATE_WINDOWS_DEFAULT;
    if (n > 1000000) n = 1000000;
    return (int)n;
}

/* One stage of the eight-stage reducer pipeline. The function pointers
 * match the stage Job ABI exactly: init(struct main_state*)->bool,
 * drain(int max_steps)->int, cursor(void)->uint64_t. `log_stall` is the
 * one genuinely per-stage piece — the cursor/counter LOG_WARN body.
 *
 * The mutable runtime fields (contract / id / ms) live in the desc so a
 * single generic tick/stall handler can recover its stage from the
 * contract's `ctx` pointer (set once at register time, never mutated). */
struct staged_stage_desc {
    /* immutable wiring */
    const char *name;               /* supervisor child name */
    const char *init_fail_msg;      /* WARN text when init() returns false */
    bool      (*init)(struct main_state *ms);
    int       (*drain)(int max_steps);
    uint64_t  (*cursor)(void);
    int         batch;              /* max steps drained per tick */
    /* Per-step fan-out: how many units of consensus work one step_once of this
     * stage verifies. 1 for every stage except validate_headers, whose
     * step_once verifies up to VH_BATCH_SIZE Equihash solutions per step. Used
     * by stage_effective_batch() so an accelerated catch-up batch does not
     * multiply by this factor inside ONE commit held under
     * progress_store_tx_lock (which would stall every other supervised child
     * — incl. the dumpstate/status front door — each sweep) beyond what the
     * stage's catch-up-scaled worker pool can absorb in the same wall time. */
    int         per_step_fanout;
    void      (*log_stall)(void);   /* per-stage stall LOG_WARN body */
    /* The immediately-preceding pipeline stage, wired explicitly (not
     * derived via pointer arithmetic into g_stages, which would be
     * undefined behavior for a desc built outside that array — see the
     * ZCL_TESTING run_stage_tick entry point at the bottom of this file).
     * NULL/NULL for header_admit, the pipeline head (no upstream reducer
     * stage — it waits on the live network tip instead). */
    const char *upstream_name;
    uint64_t  (*upstream_cursor)(void);

    /* mutable runtime state, owned by this translation unit */
    struct liveness_contract contract;
    supervisor_child_id      id;    /* SUPERVISOR_INVALID_ID until registered */
    struct main_state       *ms;
    bool                     init_ok;
    /* Stall-escalation state (single-writer: staged_stage_tick, the
     * supervisor thread only). True once the "stage_stalled_<name>"
     * blocker is standing; cleared the instant real progress resumes. See
     * staged_stage_stall_escalation_apply()'s comment for how this predicate
     * differs from "stage_spin_<name>" and "reducer_drive_stuck". */
    bool                     stall_escalated;
    /* Edge-triggered dedup for the reducer_drive_active() skip-branch LOG_INFO
     * (logged once per skip streak, not every 2s tick). */
    bool                     drive_skip_logged;
};

/* ---- per-stage stall bodies (the only genuinely per-stage code) ---- */

static void header_admit_log_stall(void)
{
    /* A stall here means header admission is not moving; the condition
     * layer decides whether this is missing input or a live-chain stall. */
    LOG_WARN("supervisor", "[supervisor] staged.header_admit stalled " "(cursor=%llu admitted=%llu) — stage log behind live chain", (unsigned long long)header_admit_stage_cursor(), (unsigned long long)header_admit_stage_admitted_total());
}

static void validate_headers_log_stall(void)
{
    /* Validate can fall behind admit or wait on a stalled live chain; surface
     * the cursor gap and let conditions classify the cause. */
    LOG_WARN("supervisor", "[supervisor] staged.validate_headers stalled " "(cursor=%llu passed=%llu failed=%llu) — validator behind admit", (unsigned long long)validate_headers_stage_cursor(), (unsigned long long)validate_headers_stage_passed_total(), (unsigned long long)validate_headers_stage_failed_total());
}

static void body_fetch_log_stall(void)
{
    /* Stall = body_fetch falling behind validate OR bodies
     * not arriving on disk. Either way, surface but do nothing
     * destructive. */
    LOG_WARN("supervisor", "[supervisor] staged.body_fetch stalled " "(cursor=%llu observed=%llu skipped=%llu) — fetch behind validate", (unsigned long long)body_fetch_stage_cursor(), (unsigned long long)body_fetch_stage_observed_total(), (unsigned long long)body_fetch_stage_skipped_total());
}

static void body_persist_log_stall(void)
{
    LOG_WARN("supervisor", "[supervisor] staged.body_persist stalled " "(cursor=%llu verified=%llu upstream_failed=%llu read_failed=%llu) " "— persist behind body_fetch", (unsigned long long)body_persist_stage_cursor(), (unsigned long long)body_persist_stage_verified_total(), (unsigned long long)body_persist_stage_upstream_failed_total(), (unsigned long long)body_persist_stage_read_failed_total());
}

static void script_validate_log_stall(void)
{
    LOG_WARN("supervisor", "[supervisor] staged.script_validate stalled " "(cursor=%llu verified=%llu upstream_failed=%llu internal_error=%llu) " "— script validation behind body_persist", (unsigned long long)script_validate_stage_cursor(), (unsigned long long)script_validate_stage_verified_total(), (unsigned long long)script_validate_stage_upstream_failed_total(), (unsigned long long)script_validate_stage_internal_error_total());
}

static void proof_validate_log_stall(void)
{
    LOG_WARN("supervisor", "[supervisor] staged.proof_validate stalled " "(cursor=%llu verified=%llu upstream_failed=%llu internal_error=%llu) " "— proof validation behind script_validate", (unsigned long long)proof_validate_stage_cursor(), (unsigned long long)proof_validate_stage_verified_total(), (unsigned long long)proof_validate_stage_upstream_failed_total(), (unsigned long long)proof_validate_stage_internal_error_total());
}

static void utxo_apply_log_stall(void)
{
    LOG_WARN("supervisor", "[supervisor] staged.utxo_apply stalled " "(cursor=%llu verified=%llu upstream_failed=%llu internal_error=%llu) " "— UTXO apply behind proof_validate", (unsigned long long)utxo_apply_stage_cursor(), (unsigned long long)utxo_apply_stage_verified_total(), (unsigned long long)utxo_apply_stage_upstream_failed_total(), (unsigned long long)utxo_apply_stage_internal_error_total());
}

static void tip_finalize_log_stall(void)
{
    LOG_WARN("supervisor", "[supervisor] staged.tip_finalize stalled "
             "(cursor=%llu finalized=%llu upstream_failed=%llu reorg=%llu "
             "last_blocked=%s) — tip finalize behind utxo_apply or live tip",
             (unsigned long long)tip_finalize_stage_cursor(),
             (unsigned long long)tip_finalize_stage_finalized_total(),
             (unsigned long long)tip_finalize_stage_upstream_failed_total(),
             (unsigned long long)tip_finalize_stage_reorg_detected_total(),
             tip_finalize_stage_last_blocked_reason());
}

/* The eight stages in EXACT pipeline order (header_admit → … →
 * tip_finalize). Each INIT_DESC row binds one stage's name, init/drain/
 * cursor entry points, batch macro, init-failure WARN text, stall body, and
 * its upstream stage's name + cursor reader (NULL/NULL for header_admit,
 * the pipeline head). The register-failure WARN, period=2s, and the shared
 * quiet window are uniform and applied by the generic helper below. */
#define INIT_DESC(NM, FAILMSG, PFX, BATCH, FANOUT, UPNAME, UPCURSOR)  \
    { .name = (NM), .init_fail_msg = (FAILMSG),         \
      .init = PFX##_stage_init, .drain = PFX##_stage_drain, \
      .cursor = PFX##_stage_cursor, .batch = (BATCH),   \
      .per_step_fanout = (FANOUT),                      \
      .log_stall = PFX##_log_stall,                     \
      .upstream_name = (UPNAME), .upstream_cursor = (UPCURSOR), \
      .id = SUPERVISOR_INVALID_ID, .ms = NULL }

static struct staged_stage_desc g_stages[] = {
    INIT_DESC("staged.header_admit",
              "[supervisor] WARN staged.header_admit init failed — " "stage not running this boot",
              header_admit, HEADER_ADMIT_BATCH_PER_TICK, 1,
              NULL, NULL),
    /* validate_headers fans out VH_BATCH_SIZE Equihash verifications per
     * step_once (see STAGE_DRAIN_IMPL + validate_headers_stage.c). Its fanout
     * caps the accelerated catch-up batch (scaled by the catch-up pool width,
     * max VH_CATCHUP_STEP_MULT) so per-commit work stays wall-clock-bounded. */
    INIT_DESC("staged.validate_headers",
              "[supervisor] WARN staged.validate_headers init failed — " "validator not running this boot",
              validate_headers, VH_BATCH_PER_TICK, VH_BATCH_SIZE,
              "staged.header_admit", header_admit_stage_cursor),
    INIT_DESC("staged.body_fetch",
              "[supervisor] WARN staged.body_fetch init failed — " "fetch not running this boot",
              body_fetch, BODY_FETCH_BATCH_PER_TICK, 1,
              "staged.validate_headers", validate_headers_stage_cursor),
    INIT_DESC("staged.body_persist",
              "[supervisor] WARN staged.body_persist init failed — " "persist not running this boot",
              body_persist, BODY_PERSIST_BATCH_PER_TICK, 1,
              "staged.body_fetch", body_fetch_stage_cursor),
    INIT_DESC("staged.script_validate",
              "[supervisor] WARN staged.script_validate init failed — " "script validation not running this boot",
              script_validate, SCRIPT_VALIDATE_BATCH_PER_TICK, 1,
              "staged.body_persist", body_persist_stage_cursor),
    INIT_DESC("staged.proof_validate",
              "[supervisor] WARN staged.proof_validate init failed — " "proof validation not running this boot",
              proof_validate, PROOF_VALIDATE_BATCH_PER_TICK, 1,
              "staged.script_validate", script_validate_stage_cursor),
    INIT_DESC("staged.utxo_apply",
              "[supervisor] WARN staged.utxo_apply init failed — " "UTXO apply not running this boot",
              utxo_apply, UTXO_APPLY_BATCH_PER_TICK, 1,
              "staged.proof_validate", proof_validate_stage_cursor),
    INIT_DESC("staged.tip_finalize",
              "[supervisor] WARN staged.tip_finalize init failed — " "tip finalize not running this boot",
              tip_finalize, TIP_FINALIZE_BATCH_PER_TICK, 1,
              "staged.utxo_apply", utxo_apply_stage_cursor),
};

#undef INIT_DESC

#define STAGED_STAGE_COUNT (sizeof(g_stages) / sizeof(g_stages[0]))

/* progress.kv durability gate. During IBD / the bodies-only refold the
 * stage cursor commits do not need to fsync (a crash just replays from the
 * last durable cursor, idempotently), so synchronous=OFF removes the
 * per-block fsync from the fold's critical path. Once at-tip it MUST revert
 * to NORMAL so the live tip is not left in a wider crash-durability window.
 *
 * This is a pure I/O control — it never changes WHAT a stage computes or
 * commits, only when those bytes reach disk. We gate on the existing
 * is_initial_block_download() signal and issue the PRAGMA only on a
 * transition (tracked in g_progress_sync_ibd). -1 = not yet applied. */
static _Atomic int g_progress_sync_ibd = -1;

static void staged_sync_apply_progress_durability(struct main_state *ms)
{
    if (!ms) return;
    int want = is_initial_block_download(ms) ? 1 : 0;
    int have = atomic_load(&g_progress_sync_ibd);
    if (have == want) return;  /* no transition — skip the PRAGMA */
    if (progress_store_set_sync_mode(want != 0))
        atomic_store(&g_progress_sync_ibd, want);
}

/* Strip the "staged." domain prefix off a stage's dotted supervisor name
 * ("staged.body_persist" -> "body_persist"), for compact blocker ids and
 * reason text. */
static const char *staged_stage_short_name(const char *dotted_name)
{
    if (!dotted_name) return "unknown";
    const char *dot = strchr(dotted_name, '.');
    return dot ? dot + 1 : dotted_name;
}

/* Build the "stage_stalled_<name>" blocker id into `buf` (>= BLOCKER_ID_MAX). */
/* blocker-id: stage_stalled_* */
static void staged_stage_blocker_id(char *buf, size_t buflen,
                                    const char *dotted_name)
{
    snprintf(buf, buflen, "stage_stalled_%s",
             staged_stage_short_name(dotted_name));
}

/* Stall-escalation decision — a pure function of the caller-supplied
 * quiet duration, no clock reads and no liveness_contract access, so tests
 * can drive it directly (same shape as reducer_drain.c's
 * reducer_drain_spin_observe()). `quiet_us` is elapsed time since this
 * stage's progress_marker last actually changed; `escalated` is the
 * caller-owned per-stage flag (staged_stage_tick passes &d->stall_escalated
 * in production) used only to avoid a redundant blocker_clear() call on
 * every healthy tick — blocker_set() is already self-rate-limiting, so the
 * SET side is safe to call repeatedly while the condition holds.
 *
 * DISTINCT PREDICATE, not a duplicate of:
 *   - "stage_spin_<name>" (app/services/src/reducer_drain.c): fires when a
 *     stage reports advance>0 for K consecutive DRAIN ROUNDS inside one
 *     bounded reducer_drain_core() call while its own cursor stays frozen —
 *     a reported-vs-durable-cursor divergence at drain-round granularity.
 *   - "reducer_drive_stuck" (app/conditions/src/reducer_drive_watchdog.c):
 *     fires when a SYNCHRONOUS reducer drive (reducer_drive_guard.h) has
 *     been continuously active for too long without the utxo_apply cursor
 *     moving — a drive-AGE predicate.
 * This one fires when a stage's OWN progress_marker has been wall-clock
 * quiet, at supervisor tick granularity (period=2s, windows of
 * STAGED_STAGE_QUIET_US=30min each), for M consecutive windows — it is the
 * escalation of the existing log_stall() one-shot WARN (staged_stage_stall
 * below), which only fires once per continuous freeze because the
 * supervisor's own NO_PROGRESS gate is edge-triggered
 * (lib/util/src/supervisor.c). Computed here from staged_stage_tick every
 * 2s (not from the edge-triggered on_stall callback) precisely so it does
 * not need to re-arm that edge or duplicate its bookkeeping. */
static void staged_stage_stall_escalation_apply(const char *dotted_name,
                                                 const char *upstream_dotted_name,
                                                 uint64_t cursor,
                                                 uint64_t upstream_cursor,
                                                 bool have_upstream,
                                                 int64_t quiet_us,
                                                 bool *escalated)
{
    int windows = quiet_us > 0 ? (int)(quiet_us / STAGED_STAGE_QUIET_US) : 0;
    int m = staged_stage_escalate_windows();

    char id[BLOCKER_ID_MAX];
    staged_stage_blocker_id(id, sizeof(id), dotted_name);

    if (windows >= m) {
        char reason[BLOCKER_REASON_MAX];
        if (have_upstream) {
            snprintf(reason, sizeof(reason),
                "stage=%.32s frozen cursor=%llu upstream=%.32s:%llu "
                "quiet=%llds windows=%d/%d; supervisor wall-clock stall, "
                "separate from stage_spin/reducer_drive_stuck",
                staged_stage_short_name(dotted_name),
                (unsigned long long)cursor,
                staged_stage_short_name(upstream_dotted_name),
                (unsigned long long)upstream_cursor,
                (long long)(quiet_us / 1000000), windows, m);
        } else {
            snprintf(reason, sizeof(reason),
                "stage=%.32s frozen cursor=%llu, no upstream reducer stage; "
                "waiting on live network tip, quiet=%llds windows=%d/%d; "
                "supervisor wall-clock stall, separate from "
                "stage_spin/reducer_drive_stuck",
                staged_stage_short_name(dotted_name),
                (unsigned long long)cursor,
                (long long)(quiet_us / 1000000), windows, m);
        }
        struct blocker_record r;
        if (blocker_init(&r, id, "staged_sync_supervisor",
                         BLOCKER_TRANSIENT, reason)) {
            (void)blocker_set(&r);
            /* Edge-triggered: make the escalation audible in node.log exactly
             * once per continuous freeze (the false->true edge), so a stage
             * crossing the M-window threshold is a NAMED blocker in the log
             * stream, not only a registry fact a `dumpstate blocker` call must
             * surface. blocker_set() is self-rate-limiting, so the repeat 2s
             * ticks stay quiet — this WARN never spams. The named blocker is
             * exactly the empty-escape class blocker_stall_meta_detector.c
             * backstops with the always-terminating recovery ladder. */
            if (escalated && !*escalated)
                LOG_WARN("supervisor",
                         "[supervisor] escalated %s to typed blocker '%s' after "
                         "%d quiet window(s) — %s",
                         dotted_name, id, windows, reason);
            if (escalated) *escalated = true;
        }
    } else if (escalated && *escalated) {
        /* Falling edge: the stage advanced again — name the clear so the
         * recovery is as audible as the escalation was, never a silent
         * disappearance of the typed blocker from the registry. */
        LOG_WARN("supervisor",
                 "[supervisor] %s progress resumed — cleared typed blocker '%s'",
                 dotted_name, id);
        blocker_clear(id);
        *escalated = false;
    }
}

/* Effective drain batch for one tick: refold_cadence wins over
 * catchup_cadence when both could apply. refold_cadence_drain_batch is
 * contractually a no-op (returns normal_batch unchanged) whenever
 * refold_cadence_active() is false, so this precedence check is trivially
 * correct — an offline from-anchor/genesis refold keeps its proven
 * 2000/250ms values untouched, and only when no refold is in progress does a
 * live catch-up (peers connected, gap >= threshold) get to raise one-block
 * stages to catchup_cadence's measured default. Neither override touches the
 * shared 2s tick period. */
static int stage_effective_batch(int normal_batch, int per_step_fanout)
{
    int refold_batch = refold_cadence_drain_batch(normal_batch);
    if (refold_batch != normal_batch)
        return refold_batch;
    int catchup_batch = catchup_cadence_drain_batch(normal_batch);
    /* Fan-out containment (A12): a stage whose step_once verifies
     * per_step_fanout units
     * of consensus work (validate_headers: VH_BATCH_SIZE Equihash solutions per
     * step) would, at an accelerated step count, run per_step_fanout * batch
     * verifications inside ONE commit held under progress_store_tx_lock —
     * stalling every other supervised child (incl. the dumpstate/status front
     * door) for the whole sweep (catchup_cadence.h:37-44 does not model this).
     * During catch-up the stage's Equihash pool is itself scaled
     * (ZCL_VH_CATCHUP_POOL_SIZE, default min(nproc,16) — see
     * validate_headers_tuning.c), so the containment is loosened by exactly
     * the pool scale actually in force, capped at VH_CATCHUP_STEP_MULT:
     * per-tick wall time stays bounded by the same work at a wider width,
     * and an operator who pins the pool at/below VH_POOL_SIZE gets NO step
     * raise. No-op when the override is inactive
     * (catchup_batch == normal_batch) or the stage does not fan out
     * — the live hot path is left untouched. */
    if (per_step_fanout > 1 && catchup_batch > normal_batch)
        catchup_batch = validate_headers_stage_catchup_step_cap(normal_batch);
    return catchup_batch;
}

/* Generic per-stage tick: drain a bounded batch each tick — keeps
 * progress.kv churn low and avoids starving other supervisor children —
 * then publish the cursor and heartbeat. Recovers its stage from the
 * contract's ctx pointer. */
static void staged_stage_tick(struct liveness_contract *c)
{
    struct staged_stage_desc *d = (struct staged_stage_desc *)c->ctx;
    if (!d || !d->ms) return;

    /* Keep progress.kv's durability mode tracking the IBD/at-tip signal.
     * Cheap: only flips the PRAGMA on an actual IBD<->at-tip transition. */
    staged_sync_apply_progress_durability(d->ms);
    /* Yield to an in-flight SYNCHRONOUS reducer drive (reducer_ingest_block on
     * the mining/submitblock/rebuild thread). The stages share the active-chain
     * window, which is not under the per-stage progress.kv lock, so draining a
     * stage here concurrently with that drive races and can record a permanent
     * failure row for the block being ingested. No-op for live network sync,
     * where reducer_ingest_block is never on the path so the flag stays 0.
     *
     * Publish WHY this stage isn't ticking instead of a blind heartbeat: the
     * progress_marker becomes the active drive's age_us (reducer_drive_guard.h)
     * rather than the stage's own (now-frozen) cursor. Two effects: (1)
     * dumpstate supervisor shows a genuinely moving number instead of one that
     * LOOKS wedged at the pre-drive cursor for as long as the drive runs
     * (which can be hours for a mint/refold fold); (2) because it is
     * non-frozen, it also keeps THIS child's own quiet-window math — both the
     * built-in supervisor NO_PROGRESS gate and staged_stage_stall_escalation_
     * apply() above — from misreading a legitimate long drive as a stalled
     * stage. The drive's string label (only available via
     * reducer_drive_label(), not through the numeric-only supervisor child
     * fields) goes to node.log once per skip streak — see `dumpstate
     * reducer_drive` for the live value. */
    if (reducer_drive_active()) {
        if (!d->drive_skip_logged) {
            LOG_INFO("supervisor",
                     "%s yielding to active reducer drive label=%s "
                     "age_us=%lld — publishing drive age as progress_marker "
                     "(see dumpstate reducer_drive for the label)",
                     d->name, reducer_drive_label(),
                     (long long)reducer_drive_age_us());
            d->drive_skip_logged = true;
        }
        supervisor_progress(d->id, reducer_drive_age_us());
        supervisor_tick(d->id);
        return;
    }
    if (d->drive_skip_logged) d->drive_skip_logged = false;

    /* Drain batch: the stage default (d->batch) on a normal at-tip live
     * node — stage_effective_batch() returns its argument unchanged unless
     * either accelerated cadence is active. During a -mint-anchor/-refold-*
     * fold it returns the accelerated ZCL_REFOLD_DRAIN_BATCH (default 2000);
     * during a live catch-up (peers connected, gap >= threshold, no refold
     * in progress) it returns ZCL_CATCHUP_DRAIN_BATCH (default 500). Batch
     * size never changes WHAT a stage folds — only the commit cadence and
     * latency. */
    /* Catch-up stages can emit one event and/or block write per step. Reuse
     * the reducer's crash-ordered outer scope so those writes sync once at a
     * pre-commit boundary, not once per imported header/body. At tip this is
     * false, so each write keeps its normal immediate sync. */
    const bool batch_catchup_sync = catchup_cadence_active();
    if (batch_catchup_sync)
        reducer_enter_batched_body_sync();
    (void)d->drain(stage_effective_batch(d->batch, d->per_step_fanout));
    if (batch_catchup_sync)
        reducer_exit_batched_body_sync();

    /* The asynchronous pipeline can reach the exact fully-applied at-tip
     * lookahead shape without another synchronous reducer_kick. Re-evaluate
     * after tip_finalize's own tick so a continuously-running node gets the
     * same one-head authority close as the synchronous and clean-restart
     * paths. The helper is a no-op for every other stage/shape. */
    if (d->drain == tip_finalize_stage_drain)
        reducer_publish_fully_applied_at_tip(boot_activation_controller());

    /* Effective per-child tick period for the NEXT sweep: refold_cadence
     * wins over catchup_cadence when both could apply (same precedence as
     * stage_effective_batch above); refold_cadence_tick_period_us() is
     * already a hard 0 whenever refold_cadence_active() is false, so this
     * check is trivially correct. Recomputed every tick (not just at
     * registration) so the period snaps back to 0 -> the shared 2s
     * period_secs applies again the instant neither cadence is active --
     * the load-bearing property that a normal at-tip node keeps its exact
     * 2s tick and full validation is never altered. lib/util/src/
     * supervisor.c's sweep re-reads period_us fresh every pass, so this
     * atomic_store takes effect on the very next sweep. */
    int64_t eff = refold_cadence_tick_period_us();
    if (eff <= 0) eff = catchup_cadence_tick_period_us();
    atomic_store(&d->contract.period_us, eff);

    uint64_t cur = d->cursor();
    supervisor_progress(d->id, (int64_t)cur);
    supervisor_tick(d->id);

    /* Stall escalation: after M consecutive STAGED_STAGE_QUIET_US windows of
     * frozen progress (default M=2, 60 min; env ZCL_STAGE_STALL_ESCALATE_
     * WINDOWS), name a typed "stage_stalled_<name>" blocker instead of only
     * the one-shot log_stall() WARN. quiet_us is read from the SAME
     * progress_changed_at_us the supervisor's own built-in NO_PROGRESS gate
     * maintains (updated by the supervisor_progress() call just above), so
     * this reads as "wall-clock quiet since the last real cursor advance"
     * without any extra clock/cursor bookkeeping of our own. */
    int64_t now      = platform_time_monotonic_us();
    int64_t changed   = atomic_load(&d->contract.progress_changed_at_us);
    int64_t quiet_us  = now - changed;
    bool have_upstream = d->upstream_cursor != NULL;
    uint64_t upstream_cursor = have_upstream ? d->upstream_cursor() : 0;
    const char *upstream_name = d->upstream_name ? d->upstream_name : "";
    staged_stage_stall_escalation_apply(d->name, upstream_name, cur,
                                        upstream_cursor, have_upstream,
                                        quiet_us, &d->stall_escalated);
}

/* Generic per-stage stall: defer to the stage's own LOG_WARN body. */
static void staged_stage_stall(struct liveness_contract *c)
{
    struct staged_stage_desc *d = (struct staged_stage_desc *)c->ctx;
    if (!d) return;
    d->log_stall();
}

/* Register a failed-init placeholder. The stage remains disabled (period=0,
 * no callbacks), but the expected child name is present in supervisor
 * diagnostics with a child_reported stall. That keeps boot from looping on a
 * perma-IDLE stage while making the missing core child visible. */
static void staged_stage_register_init_failed(struct staged_stage_desc *d)
{
    liveness_contract_init(&d->contract, d->name);
    atomic_store(&d->contract.period_secs, (int64_t)0);
    atomic_store(&d->contract.deadline_secs, (int64_t)0);
    atomic_store(&d->contract.progress_max_quiet_us, (int64_t)0);
    d->contract.ctx      = d;
    d->contract.on_tick  = NULL;
    d->contract.on_stall = NULL;
    d->ms = NULL;
    d->init_ok = false;
    d->id = supervisor_register_in_domain(g_chain_sup, &d->contract);
    if (d->id == SUPERVISOR_INVALID_ID) {
        LOG_WARN("supervisor",
                 "[supervisor] WARN %s init-failed marker register failed",
                 d->name);
        return;
    }
    supervisor_report_stall(d->id, SUPERVISOR_STALL_CHILD_REPORTED);
}

/* Generic registration for one stage. The successful path is the production
 * stage contract: idempotent on its own id, period=2s, the shared quiet
 * window, in the chain domain. Init failures register a disabled diagnostic
 * child instead of disappearing from the tree. */
static void staged_stage_register(struct staged_stage_desc *d,
                                  struct main_state *ms)
{
    if (!ms) return;
    if (d->id != SUPERVISOR_INVALID_ID) return;  /* idempotent */

    /* Bind the stage to the live chainstate. If progress_store didn't
     * open at boot, init returns false — log and register a disabled
     * diagnostic child so the missing core stage is visible. */
    if (!d->init_ok && !d->init(ms)) {
        LOG_WARN("supervisor", "%s", d->init_fail_msg);
        staged_stage_register_init_failed(d);
        return;
    }

    d->ms = ms;
    d->init_ok = true;
    liveness_contract_init(&d->contract, d->name);
    atomic_store(&d->contract.period_secs, (int64_t)2);
    /* Generous progress-quiet window: the stage can legitimately be IDLE
     * for long stretches when the live chain is stuck. 30 min before
     * we emit a progress warning. */
    atomic_store(&d->contract.progress_max_quiet_us, STAGED_STAGE_QUIET_US);
    /* Accelerated cadence for a mint/refold offline fold ONLY: a sub-second
     * tick period so the sweep drives the stages more often than the 2s live
     * cadence. Gated on refold_cadence_active() — false on a normal boot, so
     * period_us stays 0 (⇒ the sweep uses period_secs=2, unchanged) and
     * the loop wake stays at its 1000ms default. When active we also lower the
     * loop wake so the sub-second period can actually fire. */
    int64_t accel_us = refold_cadence_tick_period_us();
    if (accel_us > 0) {
        atomic_store(&d->contract.period_us, accel_us);
        supervisor_request_min_tick_ms((int)(accel_us / 1000));
    }
    d->contract.on_tick  = staged_stage_tick;
    d->contract.on_stall = staged_stage_stall;
    d->contract.ctx      = d;
    d->id = supervisor_register_in_domain(g_chain_sup, &d->contract);
    if (d->id == SUPERVISOR_INVALID_ID) {
        LOG_WARN("supervisor", "[supervisor] WARN %s register failed", d->name);
    }
}

bool staged_sync_supervisor_init_stages_offline(struct main_state *ms)
{
    if (!ms) return false;
    bool ok = true;
    for (size_t i = 0; i < STAGED_STAGE_COUNT; i++) {
        struct staged_stage_desc *d = &g_stages[i];
        if (d->init_ok) {
            d->ms = ms;
            continue;
        }
        if (!d->init(ms)) {
            LOG_WARN("supervisor", "%s", d->init_fail_msg);
            ok = false;
            continue;
        }
        d->ms = ms;
        d->init_ok = true;
    }
    return ok;
}

void staged_sync_supervisor_shutdown_stages(void)
{
    if (g_stages[7].init_ok) tip_finalize_stage_shutdown();
    if (g_stages[6].init_ok) utxo_apply_stage_shutdown();
    if (g_stages[5].init_ok) proof_validate_stage_shutdown();
    if (g_stages[4].init_ok) script_validate_stage_shutdown();
    if (g_stages[3].init_ok) body_persist_stage_shutdown();
    if (g_stages[2].init_ok) body_fetch_stage_shutdown();
    if (g_stages[1].init_ok) validate_headers_stage_shutdown();
    if (g_stages[0].init_ok) header_admit_stage_shutdown();

    for (size_t i = 0; i < STAGED_STAGE_COUNT; i++) {
        /* Resolve any standing stall-escalation blocker before the stage's
         * identity/contract state resets — an unregistered stage that still
         * "owns" a live blocker is a ghost fact nothing will ever clear. */
        if (g_stages[i].stall_escalated) {
            char id[BLOCKER_ID_MAX];
            staged_stage_blocker_id(id, sizeof(id), g_stages[i].name);
            blocker_clear(id);
        }
        g_stages[i].id = SUPERVISOR_INVALID_ID;
        g_stages[i].ms = NULL;
        g_stages[i].init_ok = false;
        g_stages[i].stall_escalated = false;
        g_stages[i].drive_skip_logged = false;
        memset(&g_stages[i].contract, 0, sizeof(g_stages[i].contract));
    }
    atomic_store(&g_progress_sync_ibd, -1);
}

void staged_sync_supervisor_register(struct main_state *ms)
{
    if (!ms) return;
    supervisor_domains_init();
    /* Pipeline order follows the reducer dataflow (table is in order). */
    for (size_t i = 0; i < STAGED_STAGE_COUNT; i++) {
        staged_stage_register(&g_stages[i], ms);
    }
}

#ifdef ZCL_TESTING
void staged_sync_supervisor_test_reset_runtime(void)
{
    staged_sync_supervisor_shutdown_stages();
}

int64_t staged_sync_supervisor_test_quiet_window_us(void)
{
    return STAGED_STAGE_QUIET_US;
}

void staged_sync_supervisor_test_apply_stall_escalation(
    const char *dotted_name, const char *upstream_dotted_name,
    uint64_t cursor, uint64_t upstream_cursor, bool have_upstream,
    int64_t quiet_us, bool *escalated)
{
    staged_stage_stall_escalation_apply(dotted_name, upstream_dotted_name,
                                        cursor, upstream_cursor,
                                        have_upstream, quiet_us, escalated);
}

int64_t staged_sync_supervisor_test_run_stage_tick(
    const char *name, const char *upstream_name,
    int (*drain)(int max_steps), uint64_t (*cursor)(void),
    uint64_t (*upstream_cursor)(void),
    struct main_state *ms, bool *stall_escalated_inout,
    int64_t *period_us_out)
{
    struct staged_stage_desc d;
    memset(&d, 0, sizeof(d));
    d.name          = name;
    d.init_fail_msg = "staged_sync_supervisor_test_run_stage_tick";
    d.drain         = drain;
    d.cursor        = cursor;
    d.batch         = 1;
    d.log_stall     = NULL;   /* on_stall is never invoked on this path */
    d.upstream_name   = upstream_name;
    d.upstream_cursor = upstream_cursor;
    d.ms      = ms;
    d.init_ok = true;
    if (stall_escalated_inout) d.stall_escalated = *stall_escalated_inout;

    liveness_contract_init(&d.contract, name);
    d.contract.ctx = &d;
    /* staged_stage_tick's supervisor_progress()/supervisor_tick() calls
     * look the contract up BY ID through the global registry, not via the
     * pointer we hold here — a real (even if throwaway) registration is
     * required or those calls silently no-op against d.contract. Same
     * chain-domain path staged_stage_register() uses in production. */
    supervisor_domains_init();
    d.id = supervisor_register_in_domain(g_chain_sup, &d.contract);

    staged_stage_tick(&d.contract);

    int64_t marker = atomic_load(&d.contract.progress_marker);
    if (stall_escalated_inout) *stall_escalated_inout = d.stall_escalated;
    if (period_us_out) *period_us_out = atomic_load(&d.contract.period_us);
    supervisor_unregister(d.id);
    return marker;
}

int staged_sync_supervisor_test_effective_batch(int normal_batch,
                                                 int per_step_fanout)
{
    return stage_effective_batch(normal_batch, per_step_fanout);
}
#endif
