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
static struct condition c_local_header_refill_needed;
/* Accessed under main_state.cs_main, alongside the active tip. */
static struct uint256 g_tip_hash_at_detect;
static bool g_tip_hash_known;

#ifdef ZCL_TESTING
static _Atomic int g_test_remedy_calls;
#endif

#define REFILL_FORK_WINDOW 16
struct refill_body_target {
    struct uint256 hash;
    int height;
};

static void refill_ring_push(struct refill_body_target *ring, size_t *start,
                             size_t *count, const struct block_index *side)
{
    *start = (*start + REFILL_FORK_WINDOW - 1) % REFILL_FORK_WINDOW;
    ring[*start].hash = *side->phashBlock;
    ring[*start].height = side->nHeight;
    if (*count < REFILL_FORK_WINDOW)
        (*count)++;
}

/* Snapshot the lowest missing bodies only after finding a shared parent. */
static size_t best_header_fork_window(struct main_state *ms,
                                      struct refill_body_target *out)
{
    size_t count = 0;
    size_t start = 0;
    struct refill_body_target ring[REFILL_FORK_WINDOW];
    bool anchored = false;
    if (!ms)
        return 0;
    zcl_mutex_lock(&ms->cs_main);
    struct block_index *tip = active_chain_tip(&ms->chain_active);
    struct block_index *best = ms->pindex_best_header;
    if (tip && best && best->nHeight >= tip->nHeight) {
        struct block_index *side = block_index_get_ancestor(best, tip->nHeight);
        struct block_index *active = tip;
        while (side && active && side->nHeight == active->nHeight) {
            if (!side->phashBlock || !active->phashBlock ||
                block_has_any_failure(side))
                break;
            if (uint256_eq(side->phashBlock, active->phashBlock)) {
                anchored = true;
                break;
            }
            if (!(side->nStatus & BLOCK_HAVE_DATA)) {
                refill_ring_push(ring, &start, &count, side);
            }
            side = side->pprev;
            active = active->pprev;
        }
    }
    zcl_mutex_unlock(&ms->cs_main);
    if (!anchored)
        return 0;
    for (size_t i = 0; i < count; i++)
        out[i] = ring[(start + i) % REFILL_FORK_WINDOW];
    return count;
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
        /* Detection precedes witness even for an active episode. Preserve
         * the episode's parent until it is witnessed or superseded. */
        if (missing &&
            !atomic_load(&c_local_header_refill_needed.state.currently_active)) {
            atomic_store(&g_tip_at_detect, tip_h);
            atomic_store(&g_missing_height, next_h);
            atomic_store(&g_peer_max_at_detect, peer_max);
            g_tip_hash_known = tip->phashBlock != NULL;
            if (g_tip_hash_known)
                g_tip_hash_at_detect = *tip->phashBlock;
        }
    }
    zcl_mutex_unlock(&ms->cs_main);
    return missing;
}

static enum condition_remedy_result remedy_local_header_refill_needed(void)
{
    struct connman *cm = sync_monitor_connman();
    int next_h = atomic_load(&g_missing_height);
    int peers = sync_monitor_local_header_refill(
        cm, next_h, "condition:local_header_refill_needed");
    if (peers < 0)
        return COND_REMEDY_SKIP;
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
        struct refill_body_target targets[REFILL_FORK_WINDOW];
        size_t count = best_header_fork_window(ms, targets);
        atomic_store(&g_last_best_header_body_target,
                     count ? targets[0].height : -1);
        for (size_t i = 0; i < count; i++) {
            bool queued = false;
            struct zcl_result qr = sync_monitor_queue_best_header_body_checked(
                targets[i].height, &targets[i].hash,
                "condition:local_header_refill_needed fork body", &queued);
            if (!qr.ok) {
                LOG_WARN("condition",
                         "[condition:local_header_refill_needed] best-header "
                         "body queue failed h=%d code=%d msg=%s",
                         targets[i].height, qr.code, qr.message);
                break;
            }
            queued_body = queued_body || queued;
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

/* Caller holds cs_main; absence of a hash is not evidence of replacement. */
static bool local_refill_parent_superseded(const struct block_index *tip)
{
    if (!tip) return false;
    if (tip->nHeight < atomic_load(&g_tip_at_detect)) return true;
    return g_tip_hash_known && tip->phashBlock &&
        !uint256_eq(&g_tip_hash_at_detect, tip->phashBlock);
}

static bool witness_local_header_refill_needed(int64_t target_at_detect)
{
    (void)target_at_detect;
    /* Witness the symptom MOVED, not that detect flipped. The remedy's job
     * was to supply the missing header at g_missing_height. Verify forward
     * progress directly: either that header child now exists (it arrived), or
     * peers no longer reach that height (the gap closed from the other end),
     * or the original active parent was superseded by a reorg.
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
    if (peer_max < missing_h) {
        sync_monitor_local_header_refill_witnessed(missing_h);
        return true; /* peers retreated below the needed height */
    }

    bool arrived = false;
    bool rewound = false;
    zcl_mutex_lock(&ms->cs_main);
    struct block_index *tip = active_chain_tip(&ms->chain_active);
    if (tip && tip->nHeight >= missing_h)
        arrived = true;
    else if (local_refill_parent_superseded(tip))
        rewound = true;
    else if (tip)
        arrived = sync_monitor_active_next_child_exists(ms, tip, missing_h);
    zcl_mutex_unlock(&ms->cs_main);
    atomic_store(&g_last_witness_arrived, arrived ? 1 : 0);
    if (arrived || rewound)
        sync_monitor_local_header_refill_witnessed(missing_h);
    return arrived || rewound; /* arrived or old frontier superseded */
}

static void read_current_tip_and_missing_child(struct main_state *ms,
                                               int missing_h,
                                               int *current_tip,
                                               bool *child_exists)
{
    if (ms) {
        zcl_mutex_lock(&ms->cs_main);
        struct block_index *tip = active_chain_tip(&ms->chain_active);
        if (tip) {
            *current_tip = tip->nHeight;
            *child_exists = missing_h >= 0 &&
                (tip->nHeight >= missing_h ||
                 sync_monitor_active_next_child_exists(ms, tip, missing_h));
        }
        zcl_mutex_unlock(&ms->cs_main);
    }
}

static bool push_status_and_detect_fields(struct json_value *out,
                                          struct connman *cm,
                                          struct main_state *ms,
                                          int current_tip,
                                          int missing_h,
                                          bool current_missing_child_exists)
{
    return json_push_kv_str(out, "sync_state",
                            sync_state_name(sync_get_state())) &&
        json_push_kv_bool(out, "has_connman", cm != NULL) &&
        json_push_kv_bool(out, "has_main_state", ms != NULL) &&
        json_push_kv_int(out, "current_tip_height", current_tip) &&
        json_push_kv_int(out, "current_peer_max",
                         cm ? connman_max_peer_height(cm) : -1) &&
        json_push_kv_int(out, "tip_height_at_detect",
                         atomic_load(&g_tip_at_detect)) &&
        json_push_kv_int(out, "missing_height", missing_h) &&
        json_push_kv_int(out, "peer_max_at_detect",
                         atomic_load(&g_peer_max_at_detect)) &&
        json_push_kv_bool(out, "current_missing_child_exists",
                          current_missing_child_exists);
}

static bool push_witness_and_recovery_fields(
    struct json_value *out,
    const struct watchdog_local_recovery_stats *lr)
{
    return json_push_kv_int(out, "last_witness_peer_max",
                            atomic_load(&g_last_witness_peer_max)) &&
        json_push_kv_bool(out, "last_witness_arrived",
                          atomic_load(&g_last_witness_arrived) != 0) &&
        json_push_kv_int(out, "last_best_header_body_target",
                         atomic_load(&g_last_best_header_body_target)) &&
        json_push_kv_bool(out, "local_recovery_active", lr->active) &&
        json_push_kv_bool(out, "mirror_repair_gated",
                          lr->mirror_repair_gated) &&
        json_push_kv_bool(out, "retries_exhausted", lr->retries_exhausted);
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
    read_current_tip_and_missing_child(ms, missing_h, &current_tip,
                                       &current_missing_child_exists);

    bool ok = true;
    ok = ok && push_status_and_detect_fields(out, cm, ms, current_tip,
                                             missing_h,
                                             current_missing_child_exists);
    ok = ok && push_witness_and_recovery_fields(out, &lr);
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
        "refill ends when the missing child arrives, peers no longer advertise its height, or the active parent is superseded");
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
    g_tip_hash_known = false;
    atomic_store(&g_test_remedy_calls, 0);
}

int local_header_refill_needed_test_remedy_calls(void)
{
    return atomic_load(&g_test_remedy_calls);
}
#endif
