/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * tip_finalize_stage_observe — implementation. See
 * tip_finalize_stage_observe.h. */

#include "tip_finalize_stage_observe.h"

#include "platform/time_compat.h"
#include "jobs/stage_helpers.h"

#include "core/arith_uint256.h"
#include "json/json.h"
#include "util/blocker.h"
#include "util/log_macros.h"
#include "support/log_throttle.h"
#include "util/sync.h"

#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <string.h>

#define STAGE_NAME "tip_finalize"

/* Typed blocker id for the cursor_in > uv_cursor anomaly (lane/stall-taxonomy
 * audit): the pipeline order guarantees utxo_apply commits a height before
 * tip_finalize consumes it, so reaching here means utxo_apply's cursor
 * REGRESSED below tip_finalize's (e.g. a targeted operator repair) without a
 * matching tip_finalize rewind. See tip_finalize_observe_note_cursor_gap. */
#define TF_CURSOR_GAP_BLOCKER_ID "tip_finalize.uv_cursor_gap"

/* Typed blocker id for the current-tip-missing anomaly (Task A #11): after the
 * active-chain window, the durable finalized-hash table, AND the best-header
 * ancestry all fail to resolve the block at next_h that finalize extends FROM,
 * the finalize is genuinely wedged on missing data — this names it so the
 * safety net does not rely on the generic reducer_drive_watchdog alone. */
#define TF_TIP_MISSING_BLOCKER_ID "tip_finalize.current_tip_missing"

static _Atomic uint64_t g_finalized_total = 0;
static _Atomic uint64_t g_upstream_failed_total = 0;
static _Atomic uint64_t g_reorg_detected_total = 0;
static _Atomic uint64_t g_utxo_count_diverged_total = 0;
static _Atomic uint64_t g_precondition_failed_total = 0;
/* Lookahead successor (H+1) is not yet body-on-disk / script-valid: the
 * finalize of H is correctly DEFERRED (cursor held, JOB_IDLE), not skipped.
 * Distinct from g_precondition_failed_total, which counts ONLY the genuine
 * competing-fork skip (chainwork_not_greater). */
static _Atomic uint64_t g_successor_pending_total = 0;
/* Header-only canonical-successor finalizes (deadlock-cure step 3): N finalized
 * on N+1's HEADER witness because N+1's body/scripts were not yet pipelined.
 * A SUBSET of g_finalized_total (which counts these too); the complement of
 * g_successor_pending_total (the HOLD when N+1 is NOT yet a canonical
 * successor). One `z23 dumpstate utxo_apply` call confirms the cure. */
static _Atomic uint64_t g_header_witness_total = 0;
static _Atomic uint64_t g_total_work_added_high = 0;
static _Atomic uint64_t g_total_work_added_low = 0;
static _Atomic int64_t  g_last_step_unix = 0;
static _Atomic int64_t  g_last_blocked_unix = 0;
static _Atomic int64_t  g_last_advance_height = -1;

static const char *const k_blocked_name[TIP_FINALIZE_BLOCKED_CLASS_N] = {
    "", "uv_cursor_gap", "at_utxo_frontier", "utxo_apply_row_missing",
    "lookahead_tip_missing", "current_tip_missing", "successor_pending",
};
static _Atomic int      g_last_blocked_class = TIP_FINALIZE_BLOCKED_NONE;
static _Atomic uint64_t g_blocked_class_total[TIP_FINALIZE_BLOCKED_CLASS_N];

static uint8_t     g_last_advance_hash[32];
static zcl_mutex_t g_last_advance_hash_mu;

/* Last specific precondition that blocked tip_finalize. The persisted
 * tip_finalize_log status column stays the generic "precondition_failed"
 * token; this names WHICH check failed so a script-validation stall is not
 * masked. Guarded by g_block_reason_mu. */
static _Atomic int64_t g_last_precondition_height = -1;
static char            g_last_precondition_reason[40] = "";
static zcl_mutex_t     g_block_reason_mu;
static bool            g_mutexes_ready = false;
static pthread_mutex_t g_lifecycle_lock = PTHREAD_MUTEX_INITIALIZER;

/* CS-F1/F3 WARN-storm throttle. reducer_drain_to_convergence runs up to 4096
 * rounds per activation kick, so a per-tick WARN on a held frontier repeats
 * the SAME line millions of times in minutes. Emit only on a pair TRANSITION
 * or as a 300 s keep-alive with the running count; suppressed calls still
 * count. */
static struct log_throttle g_precondition_throttle = LOG_THROTTLE_INIT;
static struct log_throttle g_cursor_gap_throttle = LOG_THROTTLE_INIT;

static void ensure_mutexes_ready(void)
{
    pthread_mutex_lock(&g_lifecycle_lock);
    if (g_mutexes_ready) {
        pthread_mutex_unlock(&g_lifecycle_lock);
        return;
    }
    zcl_mutex_init(&g_last_advance_hash_mu);
    zcl_mutex_init(&g_block_reason_mu);
    g_mutexes_ready = true;
    pthread_mutex_unlock(&g_lifecycle_lock);
}

void tip_finalize_observe_init(void)
{
    ensure_mutexes_ready();
}

void tip_finalize_observe_shutdown(void)
{
    ensure_mutexes_ready();
    zcl_mutex_lock(&g_last_advance_hash_mu);
    atomic_store(&g_last_advance_height, (int64_t)-1);
    memset(g_last_advance_hash, 0, sizeof(g_last_advance_hash));
    zcl_mutex_unlock(&g_last_advance_hash_mu);
    atomic_store(&g_finalized_total, (uint64_t)0);
    atomic_store(&g_upstream_failed_total, (uint64_t)0);
    atomic_store(&g_reorg_detected_total, (uint64_t)0);
    atomic_store(&g_utxo_count_diverged_total, (uint64_t)0);
    atomic_store(&g_precondition_failed_total, (uint64_t)0);
    atomic_store(&g_successor_pending_total, (uint64_t)0);
    atomic_store(&g_header_witness_total, (uint64_t)0);
    atomic_store(&g_total_work_added_high, (uint64_t)0);
    atomic_store(&g_total_work_added_low, (uint64_t)0);
    atomic_store(&g_last_step_unix, (int64_t)0);
    atomic_store(&g_last_blocked_unix, (int64_t)0);
    atomic_store(&g_last_blocked_class, TIP_FINALIZE_BLOCKED_NONE);
    for (int i = 0; i < TIP_FINALIZE_BLOCKED_CLASS_N; i++)
        atomic_store(&g_blocked_class_total[i], (uint64_t)0);
    atomic_store(&g_last_precondition_height, (int64_t)-1);
    log_throttle_reset(&g_precondition_throttle);
    log_throttle_reset(&g_cursor_gap_throttle);
    /* Registry hygiene: both re-derived on next fire, so clearing here
     * loses nothing (tests re-init in-process). */
    blocker_clear(TF_CURSOR_GAP_BLOCKER_ID);
    stage_upstream_log_hole_clear(STAGE_NAME);
    pthread_mutex_lock(&g_lifecycle_lock);
    if (g_mutexes_ready) {
        zcl_mutex_lock(&g_block_reason_mu);
        g_last_precondition_reason[0] = '\0';
        zcl_mutex_unlock(&g_block_reason_mu);
        zcl_mutex_destroy(&g_last_advance_hash_mu);
        zcl_mutex_destroy(&g_block_reason_mu);
        g_mutexes_ready = false;
    } else {
        g_last_precondition_reason[0] = '\0';
    }
    pthread_mutex_unlock(&g_lifecycle_lock);
}

void tip_finalize_observe_mark_step(void)
{
    atomic_store(&g_last_step_unix, platform_time_wall_unix());
}

void tip_finalize_observe_mark_blocked(enum tip_finalize_blocked_class cls)
{
    atomic_store(&g_last_blocked_unix, platform_time_wall_unix());
    atomic_store(&g_last_blocked_class, (int)cls);
    if (cls > TIP_FINALIZE_BLOCKED_NONE &&
        cls < TIP_FINALIZE_BLOCKED_CLASS_N)
        atomic_fetch_add(&g_blocked_class_total[cls], 1);
}

void tip_finalize_observe_note_cursor_gap(int next_h, uint64_t uv_cursor)
{
    int64_t now = platform_time_wall_unix();
    /* Key the de-storm on the (cursor_in, utxo_apply) height pair: a change in
     * either height re-emits immediately, otherwise a 300 s keep-alive. Both
     * fit 32 bits (block heights), so the pack is lossless and key-equality is
     * exact. */
    uint64_t key = ((uint64_t)(uint32_t)next_h << 32) |
                   (uint32_t)uv_cursor;
    uint64_t shown = 0;
    if (log_throttle_should_emit(&g_cursor_gap_throttle, key, now, 300,
                                 &shown))
        LOG_WARN("tip_finalize",
            "[tip_finalize] cursor_in=%d exceeds utxo_apply cursor=%llu repeats=%llu",
            next_h, (unsigned long long)uv_cursor,
            (unsigned long long)shown);
    tip_finalize_observe_mark_blocked(TIP_FINALIZE_BLOCKED_UV_CURSOR_GAP);

    /* Registry-visible typed blocker (JOB_IDLE at the call site, never
     * JOB_BLOCKED — tip_finalize can't fix utxo_apply's cursor itself;
     * utxo_apply catching back up, or an operator repair, is the healer). */
    char reason[BLOCKER_REASON_MAX];
    snprintf(reason, sizeof(reason),
             "height=%d exceeds the utxo_apply cursor=%llu — tip_finalize's "
             "own cursor is ahead of its upstream, which the pipeline order "
             "should make unreachable; holding until utxo_apply's cursor "
             "catches back up", next_h, (unsigned long long)uv_cursor);
    struct blocker_record rec;
    if (blocker_init(&rec, TF_CURSOR_GAP_BLOCKER_ID, STAGE_NAME,
                     BLOCKER_DEPENDENCY, reason))
        blocker_set(&rec);
}

void tip_finalize_observe_clear_cursor_gap(void)
{
    blocker_clear(TF_CURSOR_GAP_BLOCKER_ID);
}

void tip_finalize_observe_note_tip_missing(int next_h)
{
    tip_finalize_observe_mark_blocked(TIP_FINALIZE_BLOCKED_TIP_MISSING);

    /* Registry-visible typed blocker (JOB_IDLE at the call site — tip_finalize
     * cannot itself manufacture the missing block; it heals once the body/
     * header for next_h connects). TRANSIENT so the supervisor sweep retires a
     * stale claim once the anomaly clears and stops re-firing. */
    char reason[BLOCKER_REASON_MAX];
    snprintf(reason, sizeof(reason),
             "height=%d finalize predecessor is absent from active chain, "
             "durable finalized hashes, and header ancestry; holding until "
             "the block connects", next_h);
    struct blocker_record rec;
    if (blocker_init(&rec, TF_TIP_MISSING_BLOCKER_ID, STAGE_NAME,
                     BLOCKER_TRANSIENT, reason))
        (void)blocker_set(&rec);
}

void tip_finalize_observe_clear_tip_missing(void)
{
    blocker_clear(TF_TIP_MISSING_BLOCKER_ID);
}

void tip_finalize_observe_note_reorg_rewind(void)
{
    atomic_fetch_add(&g_reorg_detected_total, 1);
    atomic_store(&g_last_blocked_unix, platform_time_wall_unix());
}

void tip_finalize_observe_record_precondition_block(int height,
                                                    const char *reason)
{
    const char *r = reason ? reason : "";
    int64_t now = platform_time_wall_unix();
    uint64_t shown = 0;
    ensure_mutexes_ready();
    zcl_mutex_lock(&g_block_reason_mu);
    bool changed = (int64_t)height != atomic_load(&g_last_precondition_height)
                   || strcmp(r, g_last_precondition_reason) != 0;
    atomic_store(&g_last_precondition_height, (int64_t)height);
    snprintf(g_last_precondition_reason, sizeof g_last_precondition_reason,
             "%s", r);
    bool emit = log_throttle_should_emit_changed(&g_precondition_throttle,
                                                 changed, now, 300, &shown);
    zcl_mutex_unlock(&g_block_reason_mu);
    if (emit)
        LOG_WARN("tip_finalize",
                 "[tip_finalize] precondition_failed height=%d reason=%s repeats=%llu",
                 height, r, (unsigned long long)shown);
}

void tip_finalize_observe_update_last_advance(int height,
                                              const uint8_t hash[32])
{
    ensure_mutexes_ready();
    zcl_mutex_lock(&g_last_advance_hash_mu);
    memcpy(g_last_advance_hash, hash, 32);
    /* Height publishes last under the same lock the pair-reader takes. */
    atomic_store(&g_last_advance_height, (int64_t)height);
    zcl_mutex_unlock(&g_last_advance_hash_mu);
}

bool tip_finalize_observe_get_last_advance(int64_t *height,
                                           uint8_t hash[32])
{
    if (!height || !hash)
        return false;
    ensure_mutexes_ready();
    zcl_mutex_lock(&g_last_advance_hash_mu);
    *height = atomic_load(&g_last_advance_height);
    if (*height >= 0)
        memcpy(hash, g_last_advance_hash, 32);
    zcl_mutex_unlock(&g_last_advance_hash_mu);
    return *height >= 0;
}

int64_t tip_finalize_observe_last_height(void)
{
    return atomic_load(&g_last_advance_height);
}

void tip_finalize_observe_reset_last_height(void)
{
    ensure_mutexes_ready();
    zcl_mutex_lock(&g_last_advance_hash_mu);
    atomic_store(&g_last_advance_height, (int64_t)-1);
    memset(g_last_advance_hash, 0, sizeof(g_last_advance_hash));
    zcl_mutex_unlock(&g_last_advance_hash_mu);
}

void tip_finalize_observe_inc_finalized(void)
{
    atomic_fetch_add(&g_finalized_total, 1);
}

void tip_finalize_observe_inc_upstream_failed(void)
{
    atomic_fetch_add(&g_upstream_failed_total, 1);
}

void tip_finalize_observe_inc_reorg_detected(void)
{
    atomic_fetch_add(&g_reorg_detected_total, 1);
}

void tip_finalize_observe_inc_utxo_count_diverged(void)
{
    atomic_fetch_add(&g_utxo_count_diverged_total, 1);
}

void tip_finalize_observe_inc_precondition_failed(void)
{
    atomic_fetch_add(&g_precondition_failed_total, 1);
}

void tip_finalize_observe_inc_successor_pending(void)
{
    atomic_fetch_add(&g_successor_pending_total, 1);
}

void tip_finalize_observe_inc_header_witness(void)
{
    atomic_fetch_add(&g_header_witness_total, 1);
}

void tip_finalize_observe_add_work(const struct arith_uint256 *delta)
{
    if (!delta)
        return;
    atomic_fetch_add(&g_total_work_added_low,
                     arith_uint256_get_low64(delta));
    atomic_fetch_add(&g_total_work_added_high,
                     ((uint64_t)delta->pn[3] << 32) | delta->pn[2]);
}

uint64_t tip_finalize_observe_finalized_total(void)
{
    return atomic_load(&g_finalized_total);
}

uint64_t tip_finalize_observe_upstream_failed_total(void)
{
    return atomic_load(&g_upstream_failed_total);
}

uint64_t tip_finalize_observe_reorg_detected_total(void)
{
    return atomic_load(&g_reorg_detected_total);
}

uint64_t tip_finalize_observe_utxo_count_diverged_total(void)
{
    return atomic_load(&g_utxo_count_diverged_total);
}

uint64_t tip_finalize_observe_precondition_failed_total(void)
{
    return atomic_load(&g_precondition_failed_total);
}

uint64_t tip_finalize_observe_successor_pending_total(void)
{
    return atomic_load(&g_successor_pending_total);
}

uint64_t tip_finalize_observe_header_witness_total(void)
{
    return atomic_load(&g_header_witness_total);
}

uint64_t tip_finalize_observe_total_work_added_low(void)
{
    return atomic_load(&g_total_work_added_low);
}

const char *tip_finalize_observe_last_blocked_reason(void)
{
    int cls = atomic_load(&g_last_blocked_class);
    if (cls <= TIP_FINALIZE_BLOCKED_NONE ||
        cls >= TIP_FINALIZE_BLOCKED_CLASS_N)
        return "";
    return k_blocked_name[cls];
}

bool tip_finalize_observe_dump_state_json(struct json_value *out,
                                          const char *key,
                                          sqlite3 *db,
                                          const stage_t *stage)
{
    (void)key;
    if (!out)
        return false;
    json_set_object(out);

    int64_t now = platform_time_wall_unix();
    int64_t last = atomic_load(&g_last_step_unix);
    /* The runtime counters below are atomic. Durable log_rows is optional
     * observational detail and must never queue an RPC behind a reducer batch
     * that owns the singleton progress connection. stage_log_row_count takes
     * this recursive lock internally, so an outer successful trylock safely
     * brackets the exact handle without adding a blocking path. */
    bool durable_snapshot = db && progress_store_tx_trylock();

    stage_dump_header(out, STAGE_NAME, stage);
    json_push_kv_bool(out, "durable_snapshot_available", durable_snapshot);
    json_push_kv_str(out, "durable_snapshot_status",
                     !db ? "progress_store_unavailable" :
                     durable_snapshot ? "available" : "progress_store_busy");
    json_push_kv_int(out, "finalized_total",
                     (int64_t)atomic_load(&g_finalized_total));
    json_push_kv_int(out, "upstream_failed_total",
                     (int64_t)atomic_load(&g_upstream_failed_total));
    json_push_kv_int(out, "reorg_detected_total",
                     (int64_t)atomic_load(&g_reorg_detected_total));
    json_push_kv_int(out, "utxo_count_diverged_total",
                     (int64_t)atomic_load(&g_utxo_count_diverged_total));
    json_push_kv_int(out, "precondition_failed_total",
                     (int64_t)atomic_load(&g_precondition_failed_total));
    json_push_kv_int(out, "successor_pending_total",
                     (int64_t)atomic_load(&g_successor_pending_total));
    json_push_kv_int(out, "header_witness_total",
                     (int64_t)atomic_load(&g_header_witness_total));
    json_push_kv_int(out, "last_precondition_height",
                     atomic_load(&g_last_precondition_height));
    json_push_kv_int(out, "precondition_repeat_count",
                     (int64_t)log_throttle_reps(&g_precondition_throttle));
    {
        char reason_buf[40] = "";
        if (stage) {
            ensure_mutexes_ready();
            zcl_mutex_lock(&g_block_reason_mu);
            snprintf(reason_buf, sizeof reason_buf, "%s",
                     g_last_precondition_reason);
            zcl_mutex_unlock(&g_block_reason_mu);
        }
        json_push_kv_str(out, "last_precondition_reason", reason_buf);
    }
    json_push_kv_int(out, "total_work_added_high",
                     (int64_t)atomic_load(&g_total_work_added_high));
    json_push_kv_int(out, "total_work_added_low",
                     (int64_t)atomic_load(&g_total_work_added_low));
    json_push_kv_int(out, "last_advance_height",
                     atomic_load(&g_last_advance_height));
    json_push_kv_int(out, "last_step_unix", last);
    json_push_kv_int(out, "last_step_age_seconds",
                     last > 0 ? now - last : -1);
    json_push_kv_int(out, "last_blocked_unix",
                     atomic_load(&g_last_blocked_unix));
    {
        int cls = atomic_load(&g_last_blocked_class);
        if (cls < 0 || cls >= TIP_FINALIZE_BLOCKED_CLASS_N)
            cls = TIP_FINALIZE_BLOCKED_NONE;
        json_push_kv_str(out, "last_blocked_reason", k_blocked_name[cls]);
        for (int i = TIP_FINALIZE_BLOCKED_NONE + 1;
             i < TIP_FINALIZE_BLOCKED_CLASS_N; i++) {
            char blocked_key[64];
            snprintf(blocked_key, sizeof blocked_key,
                     "blocked_%s_total", k_blocked_name[i]);
            json_push_kv_int(out, blocked_key,
                             (int64_t)atomic_load(&g_blocked_class_total[i]));
        }
    }
    json_push_kv_int(out, "log_rows",
                     durable_snapshot
                         ? stage_log_row_count(db, STAGE_NAME,
                                               "tip_finalize_log")
                         : -1);
    stage_dump_counters(out, stage);

    /* Reserved `_health` key (see docs/work "Adding state introspection" +
     * engine/controllers/src/diagnostics_health_rollup.c): { ok, reason }.
     * Maps the already-computed "initialised" + accumulated error_count
     * counters above — no new health logic. */
    {
        bool initialised = (stage != NULL);
        uint64_t errors = initialised ? stage_error_count(stage) : 0;
        bool ok = initialised && errors == 0;
        char reason_buf[128] = "";
        if (!initialised) {
            snprintf(reason_buf, sizeof(reason_buf),
                     "tip_finalize stage not initialised");
        } else if (errors > 0) {
            int cls = atomic_load(&g_last_blocked_class);
            if (cls < 0 || cls >= TIP_FINALIZE_BLOCKED_CLASS_N)
                cls = TIP_FINALIZE_BLOCKED_NONE;
            snprintf(reason_buf, sizeof(reason_buf),
                     "tip_finalize recorded %llu step error(s); "
                     "last_blocked_reason=%s",
                     (unsigned long long)errors, k_blocked_name[cls]);
        }
        diag_push_health(out, ok, reason_buf);
    }
    if (durable_snapshot)
        progress_store_tx_unlock();
    return true;
}
