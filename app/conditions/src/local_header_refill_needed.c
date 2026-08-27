/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

#include "conditions/local_header_refill_needed.h"
#include "core/uint256.h"
#include "util/log_macros.h"
#include "framework/condition.h"

#include "net/connman.h"
#include "services/block_source_policy.h"
#include "services/sync_monitor.h"
#include "sync/sync_state.h"
#include "validation/chainstate.h"
#include "validation/main_state.h"

#include <stdatomic.h>
#include <stdio.h>

static _Atomic int g_tip_at_detect = -1;
static _Atomic int g_missing_height = -1;
static _Atomic int g_peer_max_at_detect = -1;
static _Atomic int g_last_witness_peer_max = -1;
static _Atomic int g_last_witness_arrived;
static _Atomic int g_last_best_header_body_target = -1;

#ifdef ZCL_TESTING
static _Atomic int g_test_remedy_calls;
#endif

static int best_header_same_height_body_target(struct main_state *ms)
{
    int target = -1;
    if (!ms) {
        LOG_WARN("condition",
                 "[condition:local_header_refill_needed] best-header body "
                 "target unavailable: missing main_state");
        return target;
    }

    zcl_mutex_lock(&ms->cs_main);
    struct block_index *tip = active_chain_tip(&ms->chain_active);
    struct block_index *best = ms->pindex_best_header;
    if (tip && tip->phashBlock && best &&
        best->nHeight >= tip->nHeight) {
        struct block_index *side =
            block_index_get_ancestor(best, tip->nHeight);
        struct block_index *active = tip;

        /* A best-header fork can stop header refill even when its tip is only
         * level with the active tip. Walk just the divergent segment and name
         * its earliest missing body, so parents are fetched before an already
         * available descendant. This schedules bytes only; validation and
         * chain selection retain their existing authority. */
        while (side && active && side->nHeight == active->nHeight) {
            if (!side->phashBlock || !active->phashBlock ||
                block_has_any_failure(side)) {
                target = -1;
                break;
            }
            if (uint256_eq(side->phashBlock, active->phashBlock))
                break;
            if ((side->nStatus & BLOCK_HAVE_DATA) == 0)
                target = side->nHeight;
            side = side->pprev;
            active = active->pprev;
        }
    }
    zcl_mutex_unlock(&ms->cs_main);
    return target;
}

static bool detect_local_header_refill_needed(void)
{
    struct connman *cm = sync_monitor_connman();
    struct main_state *ms = sync_monitor_main_state();
    if (!cm || !ms)
        return false;

    int peer_max = connman_max_peer_height(cm);
    int tip_h = -1;
    int next_h = -1;
    bool missing = false;
    zcl_mutex_lock(&ms->cs_main);
    struct block_index *tip = active_chain_tip(&ms->chain_active);
    if (tip) {
        tip_h = tip->nHeight;
        next_h = tip_h + 1;
        missing = peer_max >= next_h &&
            !sync_monitor_active_next_child_exists(ms, tip, next_h);
    }
    zcl_mutex_unlock(&ms->cs_main);
    if (!missing)
        return false;

    atomic_store(&g_tip_at_detect, tip_h);
    atomic_store(&g_missing_height, next_h);
    atomic_store(&g_peer_max_at_detect, peer_max);
    return true;
}

static enum condition_remedy_result remedy_local_header_refill_needed(void)
{
    struct connman *cm = sync_monitor_connman();
    int next_h = atomic_load(&g_missing_height);
    int peers = sync_monitor_local_header_refill(
        cm, next_h, "condition:local_header_refill_needed");
    struct watchdog_local_recovery_stats lr;
    sync_monitor_get_local_recovery_stats(&lr);
    struct bsp_decision decision;
    bool proceed = block_source_policy_local_header_refill_needed(
        atomic_load(&g_tip_at_detect),
        next_h,
        atomic_load(&g_peer_max_at_detect),
        peers,
        lr.retry_count,
        lr.retries_exhausted,
        &decision);
    LOG_WARN("condition", "[condition:local_header_refill_needed] missing=%d peer_max=%d " "eligible=%d decision=%s reason=%s", next_h, atomic_load(&g_peer_max_at_detect), peers, proceed ? "proceed" : "wait", decision.reason);
    if (proceed) {
        bool queued_body = false;
        struct main_state *ms = sync_monitor_main_state();
        int body_h = best_header_same_height_body_target(ms);
        atomic_store(&g_last_best_header_body_target, body_h);
        if (body_h >= 0) {
            struct zcl_result qr = sync_monitor_queue_best_header_body(
                body_h, NULL,
                "condition:local_header_refill_needed same-height fork body");
            if (!qr.ok) {
                LOG_WARN("condition",
                         "[condition:local_header_refill_needed] best-header "
                         "body queue failed h=%d code=%d msg=%s",
                         body_h, qr.code, qr.message);
            } else {
                LOG_WARN("condition",
                         "[condition:local_header_refill_needed] queued "
                         "best-header same-height body h=%d",
                         body_h);
                queued_body = true;
            }
        }
        if (!queued_body) {
            if (!sync_set_state(SYNC_HEADERS_DOWNLOAD,
                                "condition local_header_refill_needed")) {
                sync_set_state(SYNC_IDLE, "condition local refill via idle");
                sync_set_state(SYNC_HEADERS_DOWNLOAD,
                               "condition local_header_refill_needed");
            }
            sync_monitor_kick_local_sync(
                "condition:local_header_refill_needed");
        }
    }
#ifdef ZCL_TESTING
    atomic_fetch_add(&g_test_remedy_calls, 1);
#endif
    return COND_REMEDY_OK;
}

static bool witness_local_header_refill_needed(int64_t target_at_detect)
{
    (void)target_at_detect;
    /* Witness the symptom MOVED, not that detect flipped. The remedy's job
     * was to supply the missing header at g_missing_height. Verify forward
     * progress directly: either that header child now exists (it arrived), or
     * peers no longer reach that height (the gap closed from the other end).
     * Re-running detect would only confirm "the poison I named is gone" — a
     * tautology forbidden by Law 7. */
    int missing_h = atomic_load(&g_missing_height);
    if (missing_h < 0)
        return false;

    struct connman *cm = sync_monitor_connman();
    struct main_state *ms = sync_monitor_main_state();
    if (!cm || !ms)
        return false;

    int peer_max = connman_max_peer_height(cm);
    atomic_store(&g_last_witness_peer_max, peer_max);
    if (peer_max < missing_h)
        return true; /* peers retreated below the needed height */

    bool arrived = false;
    zcl_mutex_lock(&ms->cs_main);
    struct block_index *tip = active_chain_tip(&ms->chain_active);
    if (tip && tip->nHeight >= missing_h)
        arrived = true;
    else if (tip)
        arrived = sync_monitor_active_next_child_exists(ms, tip, missing_h);
    zcl_mutex_unlock(&ms->cs_main);
    atomic_store(&g_last_witness_arrived, arrived ? 1 : 0);
    return arrived; /* the missing header child actually showed up */
}

static bool detail_local_header_refill_needed(struct json_value *out)
{
    struct connman *cm = sync_monitor_connman();
    struct main_state *ms = sync_monitor_main_state();
    struct watchdog_local_recovery_stats lr;
    sync_monitor_get_local_recovery_stats(&lr);

    int missing_h = atomic_load(&g_missing_height);
    int current_tip = -1;
    bool current_missing_child_exists = false;
    if (ms) {
        zcl_mutex_lock(&ms->cs_main);
        struct block_index *tip = active_chain_tip(&ms->chain_active);
        if (tip) {
            current_tip = tip->nHeight;
            current_missing_child_exists =
                missing_h >= 0 &&
                (tip->nHeight >= missing_h ||
                 sync_monitor_active_next_child_exists(ms, tip, missing_h));
        }
        zcl_mutex_unlock(&ms->cs_main);
    }

    bool ok = true;
    ok = ok && json_push_kv_str(out, "sync_state",
                                sync_state_name(sync_get_state()));
    ok = ok && json_push_kv_bool(out, "has_connman", cm != NULL);
    ok = ok && json_push_kv_bool(out, "has_main_state", ms != NULL);
    ok = ok && json_push_kv_int(out, "current_tip_height", current_tip);
    ok = ok && json_push_kv_int(out, "current_peer_max",
                                cm ? connman_max_peer_height(cm) : -1);
    ok = ok && json_push_kv_int(out, "tip_height_at_detect",
                                atomic_load(&g_tip_at_detect));
    ok = ok && json_push_kv_int(out, "missing_height", missing_h);
    ok = ok && json_push_kv_int(out, "peer_max_at_detect",
                                atomic_load(&g_peer_max_at_detect));
    ok = ok && json_push_kv_bool(out, "current_missing_child_exists",
                                 current_missing_child_exists);
    ok = ok && json_push_kv_int(out, "last_witness_peer_max",
                                atomic_load(&g_last_witness_peer_max));
    ok = ok && json_push_kv_bool(out, "last_witness_arrived",
                                 atomic_load(&g_last_witness_arrived) != 0);
    ok = ok && json_push_kv_int(out, "last_best_header_body_target",
                                atomic_load(&g_last_best_header_body_target));
    ok = ok && json_push_kv_bool(out, "local_recovery_active", lr.active);
    ok = ok && json_push_kv_bool(out, "mirror_repair_gated",
                                 lr.mirror_repair_gated);
    ok = ok && json_push_kv_bool(out, "retries_exhausted",
                                 lr.retries_exhausted);
    ok = ok && json_push_kv_int(out, "local_recovery_missing_height",
                                lr.missing_height);
    ok = ok && json_push_kv_int(out, "retry_count", lr.retry_count);
    ok = ok && json_push_kv_int(out, "distinct_peer_count",
                                lr.distinct_peer_count);
    ok = ok && json_push_kv_int(out, "peer_rotation_count",
                                lr.peer_rotation_count);
    ok = ok && json_push_kv_str(out, "local_recovery_mode", lr.mode);
    ok = ok && json_push_kv_str(out, "local_recovery_last_reason",
                                lr.last_reason);
    ok = ok && json_push_kv_str(
        out, "remedy_contract",
        "refill is witnessed when the missing child arrives or peers no longer advertise the missing height");
    return ok;
}

static struct condition c_local_header_refill_needed = {
    .name = "local_header_refill_needed",
    .severity = COND_WARN,
    .poll_secs = 5,
    .backoff_secs = 300,
    .max_attempts = 3,
    .detect = detect_local_header_refill_needed,
    .remedy = remedy_local_header_refill_needed,
    .witness = witness_local_header_refill_needed,
    .detail = detail_local_header_refill_needed,
    .witness_window_secs = 60,
};

void register_local_header_refill_needed(void)
{
    (void)condition_register(&c_local_header_refill_needed);
}

#ifdef ZCL_TESTING
void local_header_refill_needed_test_reset(void)
{
    atomic_store(&g_tip_at_detect, -1);
    atomic_store(&g_missing_height, -1);
    atomic_store(&g_peer_max_at_detect, -1);
    atomic_store(&g_last_witness_peer_max, -1);
    atomic_store(&g_last_witness_arrived, 0);
    atomic_store(&g_last_best_header_body_target, -1);
    atomic_store(&g_test_remedy_calls, 0);
}

int local_header_refill_needed_test_remedy_calls(void)
{
    return atomic_load(&g_test_remedy_calls);
}
#endif
