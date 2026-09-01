/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * utxo_apply_stage_observe — implementation. See
 * utxo_apply_stage_observe.h. */

#include "utxo_apply_stage_observe.h"

#include "platform/time_compat.h"
#include "utxo_apply_stage_internal.h"

#include "core/uint256.h"
#include "event/event.h"
#include "util/blocker.h"
#include "util/log_macros.h"

#include <pthread.h>
#include <stdbool.h>
#include <stdatomic.h>
#include <stdio.h>
#include <string.h>

#define STAGE_NAME "utxo_apply"
#define REJECT_REEMIT_SECS 300

/* Registry id for the durable-upstream-hole typed blocker. Named for the
 * subsystem that OWNS the repair (the reducer_frontier log set), not for the
 * stage that observes it. */
#define UA_UPSTREAM_HOLE_BLOCKER_ID "reducer_frontier.upstream_log_hole"
#define UA_EVIDENCE_BLOCKER_ID "utxo_apply.upstream_evidence_mode"

/* Fold-progress heartbeat cadence (Task A — mint/catch-up observability). One
 * LOG_INFO every UA_PROGRESS_LOG_EVERY applied heights so a from-genesis fold
 * (the mint, whose own log is ~88% schema-version spam) and the daily catch-up
 * are MEASURABLE — ETA + termination become observable from node.log alone.
 * Log-only: never touches consensus/fold behavior, O(1) per block. */
#define UA_PROGRESS_LOG_EVERY 10000

/* CS-F4 blocked-reject dedup. A consensus-rejected height returns
 * JOB_BLOCKED and recomputes every tick BY DESIGN (an upstream repair can
 * clear it), but the per-status totals must count BLOCKS — not ticks — and
 * re-emitting the same EV_BLOCK_REJECTED every tick evicts the
 * original-failure evidence from the bounded event ring. Counter + emit
 * fire only on a NEW (height,status) pair, plus a keep-alive re-emit every
 * REJECT_REEMIT_SECS carrying the cumulative suppressed-tick count (counter
 * NOT re-bumped). Cleared on JOB_ADVANCED (and shutdown) so a pair re-hit
 * after a rewind-then-reapply counts as a new block. g_reject_lock guards
 * the non-atomic fields. */
static _Atomic int64_t g_last_reject_height = -1;
static pthread_mutex_t g_reject_lock = PTHREAD_MUTEX_INITIALIZER;
static char     g_last_reject_status[24];
static int64_t  g_last_reject_emit_unix;
static uint64_t g_reject_repeat_ticks;

/* Durable-upstream-hole observability. The transition memo is touched ONLY
 * by the single-threaded step path — the g_cursor_gap_warn convention from
 * tip_finalize_stage.c — so it needs no lock. */
static struct { int64_t h; uint64_t reps; int64_t last_log; }
    g_upstream_hole_warn = { .h = -1 };

/* label_splice WARN memo — same shape/contract as g_upstream_hole_warn. */
static struct { int64_t h; uint64_t reps; int64_t last_log; }
    g_label_splice_warn = { .h = -1 };

/* Touched ONLY by the single-threaded step_apply path, so it needs no lock.
 * first_h/first_unix anchor the rate estimate to the first successful apply
 * THIS process; last_logged_h dedups the heartbeat to one line per boundary
 * even if the same boundary is re-reached after a reorg rewind. */
static struct { int64_t first_h; int64_t first_unix; int64_t last_logged_h; }
    g_ua_progress = { .first_h = -1, .first_unix = 0, .last_logged_h = -1 };

/* tipfin_warn_throttled shape (tip_finalize_stage.c:78): emit on a height
 * TRANSITION (first occurrence never suppressed) or as a 300 s keep-alive
 * carrying the suppressed-tick count; suppressed calls still count. */
static bool warn_throttled(bool changed, int64_t now, uint64_t *reps,
                           int64_t *last_log, uint64_t *out_shown)
{
    if (changed) {
        *out_shown = *reps;  /* repeats of the PRIOR hole/splice */
        *reps = 0;
        *last_log = now;
        return true;
    }
    *out_shown = ++*reps;
    if (now - *last_log < 300) return false;
    *last_log = now;
    return true;
}

void utxo_apply_reject_count_and_emit(int height, const char *status,
                                      _Atomic uint64_t *counter,
                                      const char *label)
{
    if (!status) status = "unknown";
    int64_t now = platform_time_wall_unix();
    uint64_t repeats = 0;
    pthread_mutex_lock(&g_reject_lock);
    bool same = atomic_load(&g_last_reject_height) == (int64_t)height &&
                strncmp(g_last_reject_status, status,
                        sizeof(g_last_reject_status) - 1) == 0;
    if (same) {
        repeats = ++g_reject_repeat_ticks;
        if (now - g_last_reject_emit_unix < REJECT_REEMIT_SECS) {
            pthread_mutex_unlock(&g_reject_lock);
            return;
        }
    } else {
        atomic_store(&g_last_reject_height, (int64_t)height);
        snprintf(g_last_reject_status, sizeof(g_last_reject_status), "%s",
                 status);
        g_reject_repeat_ticks = 0;
    }
    g_last_reject_emit_unix = now;
    pthread_mutex_unlock(&g_reject_lock);
    if (!same) {
        atomic_fetch_add(counter, 1);
        event_emitf(EV_BLOCK_REJECTED, 0, "utxo_apply %s height=%d",
                    label, height);
    } else {
        event_emitf(EV_BLOCK_REJECTED, 0,
                    "utxo_apply %s height=%d repeats=%llu",
                    label, height, (unsigned long long)repeats);
    }
}

void utxo_apply_reject_memo_clear(void)
{
    pthread_mutex_lock(&g_reject_lock);
    atomic_store(&g_last_reject_height, (int64_t)-1);
    g_last_reject_status[0] = '\0';
    g_reject_repeat_ticks = 0;
    pthread_mutex_unlock(&g_reject_lock);
}

void utxo_apply_upstream_hole_note(int height, uint64_t pv_cursor)
{
    int64_t now = platform_time_wall_unix();
    bool changed = g_upstream_hole_warn.h != (int64_t)height;
    if (changed) {
        g_upstream_hole_warn.h = (int64_t)height;
        atomic_fetch_add(&g_ua_upstream_hole_total, 1);
        atomic_store(&g_ua_upstream_hole_height, (int64_t)height);
        atomic_store(&g_ua_upstream_hole_first_unix, now);
        atomic_store(&g_ua_upstream_hole_consec, (uint64_t)1);
    } else {
        atomic_fetch_add(&g_ua_upstream_hole_consec, 1);
    }

    /* Registry-visible typed blocker alongside the WARN + dump counters. A
     * durable hole holds utxo_apply (and therefore H*) indefinitely, and
     * without this record, native blocker diagnostics read 0 for the stall — the
     * 3166989 script_validate_log/proof_validate_log hole ran 3 h with zero
     * named blockers. DEPENDENCY, not TRANSIENT: utxo_apply cannot fill the
     * row itself — it waits on the reducer_frontier_reconcile_light condition
     * to refill it from the PoW-verified on-disk body (escape_action names
     * that healer; no deadline — the condition runs on its own cadence).
     * Deliberately NOT c->blocker/JOB_BLOCKED (see step_apply): the registry
     * record only names the fact and never feeds the restart ladder.
     * blocker_set's token bucket dedups the per-tick re-fire. */
    struct blocker_record rec;
    char reason[BLOCKER_REASON_MAX];
    snprintf(reason, sizeof(reason),
             "proof_validate_log row ABSENT at height=%d while the "
             "proof_validate cursor=%llu is already past it; utxo_apply "
             "holds below the hole until reducer_frontier_reconcile_light "
             "refills the row",
             height, (unsigned long long)pv_cursor);
    if (blocker_init(&rec, UA_UPSTREAM_HOLE_BLOCKER_ID, STAGE_NAME,
                     BLOCKER_DEPENDENCY, reason)) {
        snprintf(rec.escape_action, sizeof(rec.escape_action),
                 "reducer_frontier_reconcile_light");
        (void)blocker_set(&rec);  /* 1 = rate-limited dup — the fact persists;
                                   * -1 already logged by blocker_set */
    }

    uint64_t shown = 0;
    if (warn_throttled(changed, now, &g_upstream_hole_warn.reps,
                       &g_upstream_hole_warn.last_log, &shown)) {
        atomic_fetch_add(&g_ua_upstream_hole_warn_total, 1);
        LOG_WARN(STAGE_NAME,
                 "[utxo_apply] durable upstream hole: proof_validate_log row "
                 "ABSENT at height=%d while proof_validate cursor=%llu is "
                 "already past it (suppressed=%llu); stage stays JOB_IDLE by "
                 "design — the reconcile-light Condition is the healer, this "
                 "WARN/dump is the alarm",
                 height, (unsigned long long)pv_cursor,
                 (unsigned long long)shown);
    }
}

void utxo_apply_upstream_hole_healed(int height)
{
    if (g_upstream_hole_warn.h == (int64_t)height) {
        g_upstream_hole_warn.h = -1;
        g_upstream_hole_warn.reps = 0;
        g_upstream_hole_warn.last_log = 0;
        atomic_store(&g_ua_upstream_hole_consec, (uint64_t)0);
        blocker_clear(UA_UPSTREAM_HOLE_BLOCKER_ID);
    }
}

job_result_t utxo_apply_evidence_refuse(
    struct stage_step_ctx *c, int height,
    enum mint_validation_evidence expected,
    enum mint_validation_evidence proof,
    enum mint_validation_evidence script)
{
    char reason[BLOCKER_REASON_MAX];
    snprintf(reason, sizeof(reason),
             "height=%d success evidence proof=%s script=%s expected=%s; "
             "coin application holds instead of crossing validation profiles",
             height, mint_validation_evidence_status(proof),
             mint_validation_evidence_status(script),
             mint_validation_evidence_status(expected));
    if (!c || !blocker_init(&c->blocker, UA_EVIDENCE_BLOCKER_ID, STAGE_NAME,
                            BLOCKER_DEPENDENCY, reason))
        return JOB_FATAL;
    snprintf(c->blocker.escape_action, sizeof(c->blocker.escape_action),
             "resume the matching offline producer or replay crypto stages");
    c->blocker.retry_budget = -1;
    return JOB_BLOCKED;
}

void utxo_apply_evidence_clear(void)
{
    blocker_clear(UA_EVIDENCE_BLOCKER_ID);
}

job_result_t utxo_apply_label_splice_refuse(struct stage_step_ctx *c,
                                            int height,
                                            const char *verdict_source,
                                            const struct uint256 *applying,
                                            const struct uint256 *verdict)
{
    const char *source = verdict_source ? verdict_source : "upstream_log";
    char want_hex[65] = {0};
    char got_hex[65] = {0};
    uint256_get_hex(applying, want_hex);
    if (verdict)
        uint256_get_hex(verdict, got_hex);
    else
        snprintf(got_hex, sizeof(got_hex), "MISSING");

    int64_t now = platform_time_wall_unix();
    bool changed = g_label_splice_warn.h != (int64_t)height;
    if (changed) {
        g_label_splice_warn.h = (int64_t)height;
        atomic_fetch_add(&g_ua_label_splice_total, 1);
    }
    uint64_t shown = 0;
    if (warn_throttled(changed, now, &g_label_splice_warn.reps,
                       &g_label_splice_warn.last_log, &shown)) {
        LOG_WARN(STAGE_NAME,
                 "[utxo_apply] label_splice height=%d: %s "
                 "row is hash-bound to %s but the block being applied is "
                 "%s; refusing apply until the verdict is re-bound "
                 "(suppressed=%llu)",
                 height, source, got_hex, want_hex,
                 (unsigned long long)shown);
    }

    char reason[BLOCKER_REASON_MAX];
    snprintf(reason, sizeof(reason),
             "height=%d %s block_hash %.16s.. != "
             "applying block %.16s..; height-keyed verdict belongs to a "
             "different block (label splice) — apply refused",
             height, source, got_hex, want_hex);
    blocker_init(&c->blocker, "utxo_apply.label_splice", STAGE_NAME,
                 BLOCKER_TRANSIENT, reason);
    c->blocker.escape_deadline_secs = 60;
    c->blocker.retry_budget = 5;
    atomic_store(&g_ua_last_blocked_unix, platform_time_wall_unix());
    return JOB_BLOCKED;
}

void utxo_apply_label_splice_healed(int height)
{
    if (g_label_splice_warn.h == (int64_t)height) {
        g_label_splice_warn.h = -1;
        g_label_splice_warn.reps = 0;
        g_label_splice_warn.last_log = 0;
        blocker_clear("utxo_apply.label_splice");
    }
}

void utxo_apply_progress_note(int applied_height, uint64_t next_cursor)
{
    int64_t now = platform_time_wall_unix();
    if (g_ua_progress.first_h < 0) {
        g_ua_progress.first_h = (int64_t)applied_height;
        g_ua_progress.first_unix = now;
    }
    if ((applied_height % UA_PROGRESS_LOG_EVERY) == 0 &&
        g_ua_progress.last_logged_h != (int64_t)applied_height) {
        g_ua_progress.last_logged_h = (int64_t)applied_height;
        int64_t elapsed = now - g_ua_progress.first_unix;
        int64_t done = (int64_t)applied_height - g_ua_progress.first_h;
        double rate = (elapsed > 0 && done > 0)
                      ? (double)done / (double)elapsed : 0.0;
        LOG_INFO(STAGE_NAME,
                 "[utxo_apply] fold progress: applied_height=%d "
                 "(coins_applied_height=%llu, base_this_run=%lld) "
                 "rate=%.1f blocks/s",
                 applied_height, (unsigned long long)next_cursor,
                 (long long)g_ua_progress.first_h, rate);
    }
}

void utxo_apply_observe_reset(void)
{
    utxo_apply_reject_memo_clear();
    if (g_upstream_hole_warn.h >= 0)
        blocker_clear(UA_UPSTREAM_HOLE_BLOCKER_ID);
    g_upstream_hole_warn.h = -1;
    g_upstream_hole_warn.reps = 0;
    g_upstream_hole_warn.last_log = 0;
    if (g_label_splice_warn.h >= 0)
        blocker_clear("utxo_apply.label_splice");
    g_label_splice_warn.h = -1;
    g_label_splice_warn.reps = 0;
    g_label_splice_warn.last_log = 0;
    g_ua_progress.first_h = -1;
    g_ua_progress.first_unix = 0;
    g_ua_progress.last_logged_h = -1;
}
