/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * reducer_drive_watchdog — makes the synchronous reducer/mint drive
 * observable and named when it wedges. See the header for the SYMPTOM /
 * REMEDY / WITNESSED contract. Also owns the "reducer_drive" dumpstate
 * subsystem (reducer_drive_dump_state_json) — this file is the state, so it
 * is the natural owner rather than a bespoke command (CLAUDE.md "Adding
 * state introspection"). */

#include "conditions/reducer_drive_watchdog.h"
#include "conditions/condition_registry.h"
#include "framework/condition.h"
#include "jobs/utxo_apply_stage.h"
#include "json/json.h"
#include "platform/time_compat.h"
#include "services/reducer_drain.h"
#include "services/reducer_ingest_service.h"
#include "services/sticky_escalator.h"
#include "storage/coins_kv.h"
#include "storage/event_log.h"    /* event_log_append_stats */
#include "storage/progress_store.h"
#include "util/blocker.h"
#include "util/log_macros.h"
#include "util/reducer_drive_guard.h"
#include "util/stage.h"           /* stage_batch_stats_snapshot */

#include <sqlite3.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

/* Typed blocker id — see util/blocker.h. TRANSIENT: a wedged drive is
 * recoverable the instant the drive itself exits or advances. There is no
 * SAFE escape that touches the drive's write path (killing a synchronous
 * drive mid-write risks a torn commit), but there IS a safe escape that does
 * NOT touch it: arm the top-level recovery ladder, whose rungs re-derive on
 * their own supervised ticks. The blocker carries that escape with a grace
 * deadline so blocker_supervisor_sweep() ACTUATES it if the drive stays
 * frozen past the window, rather than only surfacing the fault. */
#define REDUCER_DRIVE_WATCHDOG_BLOCKER_ID "reducer_drive_stuck"
#define REDUCER_DRIVE_WATCHDOG_DEFAULT_SEC 60

/* Escape wiring for the reducer_drive_stuck blocker. The action name is
 * interned (static string) as blocker_register_escape requires. The deadline
 * is measured from the blocker's first set (by which point the drive has
 * already been frozen >= the watchdog threshold), so the ladder is armed only
 * after a genuine sustained wedge — a legitimately long fold that resolves
 * within the grace window never trips it. */
#define REDUCER_DRIVE_ESCAPE_ACTION       "reducer_drive_ladder_kick"
#define REDUCER_DRIVE_ESCAPE_DEADLINE_SEC 60

/* Baseline cursor tracking (single-writer: the condition engine tick
 * thread calls detect/remedy/witness for one condition serially, never
 * concurrently with itself). UINT64_MAX is the "no observation yet"
 * sentinel — a real utxo_apply cursor never reaches it. */
static _Atomic uint64_t g_last_cursor_seen = UINT64_MAX;

/* Fields captured at the detect() tick that tripped the condition; remedy()
 * and the dump function read them back. */
static _Atomic int64_t g_age_at_detect_us;
static _Atomic uint64_t g_cursor_at_detect;

/* Unix time of the last blocker_set fired by remedy(); 0 = never. Read by
 * the dumpstate subsystem. */
static _Atomic int64_t g_last_fire_unix;

#ifdef ZCL_TESTING
static _Atomic int g_test_remedy_calls;
/* -1 = unset (use the real env-or-default lookup); >= 0 = forced value,
 * including 0 (trip the instant any age > 0 is observed). */
static _Atomic int g_test_threshold_override = -1;
/* -1 = unset (use the real utxo_apply_stage_cursor()); >= 0 = forced
 * cursor, so tests never need to spin up the real utxo_apply stage. */
static _Atomic int64_t g_test_cursor_override = -1;
#endif

static int reducer_drive_watchdog_threshold_secs(void)
{
#ifdef ZCL_TESTING
    int ov = atomic_load(&g_test_threshold_override);
    if (ov >= 0)
        return ov;
#endif
    const char *env = getenv("ZCL_DRIVE_WATCHDOG_SEC");
    if (env && env[0]) {
        char *end = NULL;
        long v = strtol(env, &end, 10);
        if (end != env && v > 0 && v < 1000000000L)
            return (int)v;
    }
    return REDUCER_DRIVE_WATCHDOG_DEFAULT_SEC;
}

/* The single reader for the durable utxo_apply cursor — lock-free (see
 * utxo_apply_stage_cursor()/stage_cursor(): guarded field, torn 64-bit read
 * tolerated by design, no sqlite/mutex on this path), safe to call from the
 * condition engine thread without racing a long-running drive. Tests inject
 * a fixed value instead of spinning up the real utxo_apply stage module. */
static uint64_t reducer_drive_watchdog_read_cursor(void)
{
#ifdef ZCL_TESTING
    int64_t ov = atomic_load(&g_test_cursor_override);
    if (ov >= 0)
        return (uint64_t)ov;
#endif
    return utxo_apply_stage_cursor();
}

static bool detect_reducer_drive_watchdog(void)
{
    if (!reducer_drive_active()) {
        /* Not driving — nothing to track. Reset the baseline so the next
         * drive starts with a clean "no observation yet" state. */
        atomic_store(&g_last_cursor_seen, UINT64_MAX);
        return false;
    }

    uint64_t cursor = reducer_drive_watchdog_read_cursor();
    uint64_t last = atomic_exchange(&g_last_cursor_seen, cursor);

    /* First observation of this drive episode, or the cursor moved since
     * the previous detect tick — forward progress observed, not stuck. */
    if (last == UINT64_MAX || cursor != last)
        return false;

    int64_t age_us = reducer_drive_age_us();
    int64_t threshold_us =
        (int64_t)reducer_drive_watchdog_threshold_secs() * 1000000;
    if (age_us <= threshold_us)
        return false;

    atomic_store(&g_age_at_detect_us, age_us);
    atomic_store(&g_cursor_at_detect, cursor);
    return true;
}

/* Escape dispatched by blocker_supervisor_sweep() once the reducer_drive_stuck
 * blocker outlives its escape deadline (the drive stayed frozen past the grace
 * window). It does NOT touch the drive's write path — it arms the top-level
 * always-terminating recovery ladder (sticky_escalator), whose rungs
 * re-derive on their own supervised ticks and self-clear on real tip
 * progress. Cheap + reentrant-safe; idempotent re-arm if already armed. */
static void reducer_drive_stuck_escape(const struct blocker_snapshot *snap)
{
    (void)snap;
    sticky_escalator_note_stall("reducer_drive_stuck");
    LOG_WARN("condition",
             "[condition:reducer_drive_watchdog] escape fired — armed recovery "
             "ladder (action=%s)", REDUCER_DRIVE_ESCAPE_ACTION);
}

static enum condition_remedy_result remedy_reducer_drive_watchdog(void)
{
    int64_t age_us = atomic_load(&g_age_at_detect_us);
    uint64_t cursor = atomic_load(&g_cursor_at_detect);
    const char *label = reducer_drive_label();
    if (!label[0])
        label = "unlabeled";
    int threshold_secs = reducer_drive_watchdog_threshold_secs();

    char reason[BLOCKER_REASON_MAX];
    snprintf(reason, sizeof(reason),
             "reducer drive '%s' active %llds, utxo_apply cursor frozen at "
             "height %llu (threshold=%ds) — recovery ladder armed via escape "
             "'%s' if still frozen in %ds; clears when the drive advances or "
             "exits",
             label, (long long)(age_us / 1000000),
             (unsigned long long)cursor, threshold_secs,
             REDUCER_DRIVE_ESCAPE_ACTION, REDUCER_DRIVE_ESCAPE_DEADLINE_SEC);

    struct blocker_record r;
    if (blocker_init(&r, REDUCER_DRIVE_WATCHDOG_BLOCKER_ID, "reducer_drive",
                     BLOCKER_TRANSIENT, reason)) {
        /* Deadline-gated escape: blocker_supervisor_sweep() fires
         * reducer_drive_stuck_escape at since_us + deadline if the drive is
         * still frozen (the blocker still present). */
        r.escape_deadline_secs = REDUCER_DRIVE_ESCAPE_DEADLINE_SEC;
        snprintf(r.escape_action, sizeof(r.escape_action), "%s",
                 REDUCER_DRIVE_ESCAPE_ACTION);
        (void)blocker_set(&r);
        atomic_store(&g_last_fire_unix, platform_time_wall_unix());
    }

    LOG_WARN("condition",
             "[condition:reducer_drive_watchdog] label=%s age_s=%lld "
             "cursor=%llu threshold_s=%d action=name_blocker+arm_escape",
             label, (long long)(age_us / 1000000),
             (unsigned long long)cursor, threshold_secs);

#ifdef ZCL_TESTING
    atomic_fetch_add(&g_test_remedy_calls, 1);
#endif

    /* The remedy itself cannot safely touch the synchronous drive on another
     * thread, so it returns FAILED here — but it is no longer a dead end: the
     * blocker now carries a deadline-gated escape (armed above) that
     * blocker_supervisor_sweep() actuates into the recovery ladder if the
     * drive stays frozen past the grace window. FAILED pages the operator on
     * the normal ladder as a parallel last resort; the cooldown re-arm keeps
     * re-notifying without ever latching a recoverable stall forever. */
    return COND_REMEDY_FAILED;
}

static bool witness_reducer_drive_watchdog(int64_t target_at_detect)
{
    (void)target_at_detect;
    // honest-witness-ok: cleared iff the drive actually exited OR the
    // utxo_apply cursor genuinely advanced past the height frozen at
    // detect() — both read live, non-cached state.
    bool active = reducer_drive_active();
    uint64_t cursor = reducer_drive_watchdog_read_cursor();
    uint64_t frozen = atomic_load(&g_cursor_at_detect);
    bool resolved = !active || cursor != frozen;
    if (resolved)
        blocker_clear(REDUCER_DRIVE_WATCHDOG_BLOCKER_ID);
    return resolved;
}

static bool detail_reducer_drive_watchdog(struct json_value *out)
{
    if (!out)
        return false;
    const char *label = reducer_drive_label();
    bool ok = true;
    ok = ok && json_push_kv_bool(out, "drive_active", reducer_drive_active());
    ok = ok && json_push_kv_str(out, "label", label[0] ? label : "");
    ok = ok && json_push_kv_int(out, "age_at_detect_us",
                                atomic_load(&g_age_at_detect_us));
    ok = ok && json_push_kv_int(out, "cursor_at_detect",
                                (int64_t)atomic_load(&g_cursor_at_detect));
    ok = ok && json_push_kv_int(out, "threshold_secs",
                                reducer_drive_watchdog_threshold_secs());
    ok = ok && json_push_kv_int(out, "last_fire_unix",
                                atomic_load(&g_last_fire_unix));
    return ok;
}

static struct condition c_reducer_drive_watchdog = {
    .name = "reducer_drive_watchdog",
    .severity = COND_CRITICAL,
    .poll_secs = 15,
    .backoff_secs = 60,
    /* No automated repair seam (see remedy) — page fast, then keep
     * re-notifying on cooldown rather than spinning remedy attempts that
     * can never change the outcome. */
    .max_attempts = 1,
    /* Continue-with-cooldown (sticky-node plan #7): a wedged synchronous
     * drive is not a local deterministic-unrecoverable fault in the
     * consensus sense — it may be a long but legitimate fold that briefly
     * looks frozen, or a genuine hang. Either way latching operator_needed
     * forever is a human dead-end; re-arm every 10 minutes, unbounded,
     * while it stays wedged. The episode itself clears instantly (via
     * witness) the moment the drive advances or exits. */
    .cooldown_secs = 600,
    .cooldown_max_rearms = 0,
    .detect = detect_reducer_drive_watchdog,
    .remedy = remedy_reducer_drive_watchdog,
    .witness = witness_reducer_drive_watchdog,
    .detail = detail_reducer_drive_watchdog,
    .witness_window_secs = 60,
};

void register_reducer_drive_watchdog(void)
{
    (void)condition_register(&c_reducer_drive_watchdog);
    /* Wire the escape so blocker_supervisor_sweep() can actuate the ladder on
     * deadline. Idempotent: only register when absent, so a test that wipes
     * the escape registry (blocker_reset_for_testing) re-registers cleanly and
     * a duplicate production call never logs a spurious "duplicate" error. */
    if (!blocker_lookup_escape(REDUCER_DRIVE_ESCAPE_ACTION))
        (void)blocker_register_escape(REDUCER_DRIVE_ESCAPE_ACTION,
                                      reducer_drive_stuck_escape);
}

bool reducer_drive_dump_state_json(struct json_value *out, const char *key)
{
    (void)key;
    if (!out)
        return false;
    json_set_object(out);

    const char *label = reducer_drive_label();
    bool ok = true;
    ok = ok && json_push_kv_bool(out, "active", reducer_drive_active());
    ok = ok && json_push_kv_str(out, "label", label[0] ? label : "");
    ok = ok && json_push_kv_int(out, "age_us", reducer_drive_age_us());
    ok = ok && json_push_kv_int(out, "watchdog_threshold_secs",
                                reducer_drive_watchdog_threshold_secs());
    ok = ok && json_push_kv_int(out, "last_watchdog_fire_unix",
                                atomic_load(&g_last_fire_unix));
    ok = ok && json_push_kv_int(out, "utxo_apply_cursor",
                                (int64_t)reducer_drive_watchdog_read_cursor());

    /* Advance-or-blocker spin counters (engine/services/src/reducer_drain.c): a
     * "stage_spin" object naming any stage that reported drain advances while
     * its own cursor stayed frozen. Emitted only when at least one stage is
     * nonzero (a healthy drive shows nothing); per-stage nested objects carry
     * {rounds_frozen, steps_reported}. The accessor does lock-free atomic reads
     * with no allocation. */
    struct reducer_stage_spin_entry spin[REDUCER_DRAIN_NUM_STAGES];
    int spin_n = reducer_drain_spin_snapshot(spin, REDUCER_DRAIN_NUM_STAGES);
    int spin_nonzero = 0;
    for (int i = 0; i < spin_n; i++)
        if (spin[i].rounds_frozen > 0)
            spin_nonzero++;
    if (spin_nonzero > 0) {
        struct json_value spin_obj = {0};
        json_set_object(&spin_obj);
        for (int i = 0; i < spin_n; i++) {
            if (spin[i].rounds_frozen == 0)
                continue;
            struct json_value one = {0};
            json_set_object(&one);
            json_push_kv_int(&one, "rounds_frozen",
                             (int64_t)spin[i].rounds_frozen);
            json_push_kv_int(&one, "steps_reported",
                             (int64_t)spin[i].steps_reported);
            json_push_kv(&spin_obj, spin[i].name, &one);
            json_free(&one);
        }
        ok = ok && json_push_kv(out, "stage_spin", &spin_obj);
        json_free(&spin_obj);
    }

    /* Drain-exit telemetry (drive+fsync telemetry gap 1): deconflates a
     * round loop that genuinely CONVERGED (no more work) from one that hit
     * its wall-clock/round BUDGET ceiling — see
     * engine/services/src/reducer_drain.c's counters' doc comment for exactly
     * what does and does not count toward each total. Lock-free atomic
     * reads, no allocation. */
    {
        struct reducer_drain_exit_stats des;
        reducer_drain_exit_stats_snapshot(&des);
        ok = ok && json_push_kv_int(out, "drain_exit_converged_total",
                                    (int64_t)des.exit_converged_total);
        ok = ok && json_push_kv_int(out, "drain_exit_budget_total",
                                    (int64_t)des.exit_budget_total);
        ok = ok && json_push_kv_int(out, "drain_last_round_advances",
                                    des.last_round_advances);
        ok = ok && json_push_kv_int(out, "drain_last_elapsed_us",
                                    des.last_elapsed_us);
        /* Stage names come from reducer_drain.c's own table (the single
         * authority) rather than a second copy maintained here, which could
         * drift out of pipeline order and silently mislabel every number. */
        struct json_value stage_us;
        json_init(&stage_us);
        json_set_object(&stage_us);
        for (int i = 0; i < REDUCER_DRAIN_NUM_STAGES; i++) {
            const char *n = reducer_drain_stage_name(i);
            ok = ok && n && json_push_kv_int(&stage_us, n,
                                             des.last_stage_us[i]);
        }
        ok = ok && json_push_kv(out, "drain_last_stage_us", &stage_us);
        json_free(&stage_us);

        /* CUMULATIVE per-stage totals. drain_last_stage_us above describes one
         * round and is overwritten every round, so a sampled observer nearly
         * always catches a converged all-idle round and sees zeros — it cannot
         * attribute a fold's time. These are monotonic since process start:
         * difference two samples for an exact interval share, and divide by
         * the same interval's advances for microseconds per folded block. */
        ok = ok && json_push_kv_int(out, "drain_rounds_total",
                                    (int64_t)des.rounds_total);
        struct json_value totals;
        json_init(&totals);
        json_set_object(&totals);
        for (int i = 0; i < REDUCER_DRAIN_NUM_STAGES; i++) {
            const char *n = reducer_drain_stage_name(i);
            if (!n) { ok = false; break; }
            struct json_value one;
            json_init(&one);
            json_set_object(&one);
            json_push_kv_int(&one, "us", (int64_t)des.stage_us_total[i]);
            json_push_kv_int(&one, "calls", (int64_t)des.stage_calls[i]);
            json_push_kv_int(&one, "adv", (int64_t)des.stage_advances[i]);
            ok = ok && json_push_kv(&totals, n, &one);
            json_free(&one);
        }
        ok = ok && json_push_kv(out, "drain_stage_totals", &totals);
        json_free(&totals);
    }

    /* Outer-batch transaction accounting (core/modules/sync/src/stage_batch.c).
     * STAGE_DRAIN_IMPL opens one write transaction per stage per drain round,
     * so `empty` — opened, nothing advanced, rolled back — is the measured
     * size of the converged-round overhead that was previously only asserted. */
    {
        struct stage_batch_stats sbs;
        stage_batch_stats_snapshot(&sbs);
        ok = ok && json_push_kv_int(out, "batch_opened_total",
                                    (int64_t)sbs.opened);
        ok = ok && json_push_kv_int(out, "batch_committed_total",
                                    (int64_t)sbs.committed);
        ok = ok && json_push_kv_int(out, "batch_rolled_back_total",
                                    (int64_t)sbs.rolled_back);
        ok = ok && json_push_kv_int(out, "batch_empty_total",
                                    (int64_t)sbs.empty);
        ok = ok && json_push_kv_int(out, "batch_commit_us_total",
                                    (int64_t)sbs.commit_us_total);
        ok = ok && json_push_kv_int(out, "batch_commit_us_ewma",
                                    sbs.commit_us_ewma);
    }

    /* Batched pre-commit durability flush timing (drive+fsync telemetry gap
     * 2): the fdatasync/event_log flush that brackets every stage-batch
     * COMMIT (engine/services/src/reducer_body_fsync.c) — see
     * engine/conditions/src/batch_fsync_slow.c for the condition that watches
     * fsync_flush_us_ewma against a budget. Both read 0 before the first
     * batch commit is ever observed. */
    {
        int64_t last_flush_us = 0, flush_us_ewma = 0;
        uint64_t flush_count = 0, flush_us_total = 0;
        unsigned scope_depth = 0;
        bool event_log_deferred = false;
        reducer_body_fsync_timing_snapshot(&last_flush_us, &flush_us_ewma);
        reducer_body_fsync_totals_snapshot(&flush_count, &flush_us_total);
        reducer_body_fsync_scope_snapshot(&scope_depth, &event_log_deferred);
        ok = ok && json_push_kv_int(out, "fsync_last_flush_us", last_flush_us);
        ok = ok && json_push_kv_int(out, "fsync_flush_us_ewma", flush_us_ewma);
        /* One flush == one durability barrier for one committing batch, so
         * this count divided by blocks folded over the same interval IS the
         * "barriers per block" figure. */
        ok = ok && json_push_kv_int(out, "fsync_flush_count",
                                    (int64_t)flush_count);
        ok = ok && json_push_kv_int(out, "fsync_flush_us_total",
                                    (int64_t)flush_us_total);
        ok = ok && json_push_kv_int(out, "fsync_scope_depth",
                                    (int64_t)scope_depth);
        ok = ok && json_push_kv_bool(out, "event_log_deferred",
                                     event_log_deferred);
        /* event_log_deferred above is the mode RIGHT NOW; these three are the
         * cumulative split of which append path the fold actually took (see
         * storage/event_log.h). The batched scope is armed and disarmed per
         * drain, so "deferred mode exists" does not mean the fold used it:
         * event_log_barrier_appends / (barrier + deferred) is the fraction of
         * appends that still paid two ext4 journal commits, and
         * event_log_barrier_us_total is what that cost in wall time. Divide
         * barrier_us_total by 2*barrier_appends for this disk's per-barrier
         * price. */
        uint64_t el_barrier = 0, el_deferred = 0, el_barrier_us = 0;
        event_log_append_stats(&el_barrier, &el_deferred, &el_barrier_us);
        ok = ok && json_push_kv_int(out, "event_log_barrier_appends",
                                    (int64_t)el_barrier);
        ok = ok && json_push_kv_int(out, "event_log_deferred_appends",
                                    (int64_t)el_deferred);
        ok = ok && json_push_kv_int(out, "event_log_barrier_us_total",
                                    (int64_t)el_barrier_us);
    }

    /* coins_applied_height is the LAGGING measure (the durable coins_kv
     * frontier vs. the immediate in-memory utxo_apply cursor above) — the
     * gap between the two is exactly the -fold-inram batching lag. Read
     * under progress_store_tx_trylock: NEVER a blocking coins/progress lock
     * from an observational surface (LOCK-ORDER LAW) — a synchronous drive
     * can hold this lock for a long stretch, and this dump function may be
     * called from a native-command or RPC thread that must not stall behind it. */
    sqlite3 *db = progress_store_db();
    if (!db || !progress_store_tx_trylock()) {
        ok = ok && json_push_kv_bool(out, "coins_applied_read_ok", false);
        ok = ok && json_push_kv_int(out, "coins_applied_height", -1);
        return ok;
    }
    int32_t coins_applied = -1;
    bool found = false;
    bool read_ok = coins_kv_get_applied_height(db, &coins_applied, &found);
    progress_store_tx_unlock();
    ok = ok && json_push_kv_bool(out, "coins_applied_read_ok", read_ok);
    ok = ok && json_push_kv_int(out, "coins_applied_height",
                                (read_ok && found) ? coins_applied : -1);
    return ok;
}

#ifdef ZCL_TESTING
void reducer_drive_watchdog_test_reset(void)
{
    atomic_store(&g_last_cursor_seen, UINT64_MAX);
    atomic_store(&g_age_at_detect_us, 0);
    atomic_store(&g_cursor_at_detect, 0);
    atomic_store(&g_last_fire_unix, 0);
    atomic_store(&g_test_remedy_calls, 0);
    atomic_store(&g_test_threshold_override, -1);
    atomic_store(&g_test_cursor_override, -1);
    blocker_clear(REDUCER_DRIVE_WATCHDOG_BLOCKER_ID);
    condition_reset_state(&c_reducer_drive_watchdog);
}

int reducer_drive_watchdog_test_remedy_calls(void)
{
    return atomic_load(&g_test_remedy_calls);
}

void reducer_drive_watchdog_test_set_threshold_secs(int secs)
{
    atomic_store(&g_test_threshold_override, secs);
}

void reducer_drive_watchdog_test_set_cursor_override(int64_t cursor)
{
    atomic_store(&g_test_cursor_override, cursor);
}
#endif
