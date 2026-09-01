/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

#include "conditions/header_stall_at_height.h"
#include "util/log_macros.h"
#include "framework/condition.h"

#include "net/connman.h"
#include "platform/time_compat.h"
#include "services/header_probe.h"
#include "services/sync_monitor.h"
#include "sync/sync_state.h"
#include "validation/chainstate.h"
#include "validation/main_state.h"

#include <stdatomic.h>
#include <stdio.h>

static _Atomic int g_last_header_height = -1;
static _Atomic int g_header_height_at_detect = -1;
static _Atomic int g_peer_max_at_detect = -1;
static _Atomic int64_t g_unchanged_since = 0;
static _Atomic int64_t g_age_at_detect = 0;

#ifdef ZCL_TESTING
static _Atomic int g_test_remedy_calls;
#endif

static bool detect_header_stall_at_height(void)
{
    struct main_state *ms = sync_monitor_main_state();
    struct connman *cm = sync_monitor_connman();
    enum sync_state state = sync_get_state();
    if (!ms || !cm ||
        (state != SYNC_HEADERS_DOWNLOAD && state != SYNC_BLOCKS_DOWNLOAD)) {
        atomic_store(&g_unchanged_since, 0);
        atomic_store(&g_last_header_height, -1);
        return false;
    }

    int header_h = ms->pindex_best_header ? ms->pindex_best_header->nHeight : -1;
    int peer_max = connman_max_peer_height(cm);
    int64_t now = platform_time_wall_unix();
    int prev = atomic_load(&g_last_header_height);
    if (header_h < 0 || peer_max <= header_h) {
        atomic_store(&g_unchanged_since, 0);
        atomic_store(&g_last_header_height, header_h);
        return false;
    }
    if (prev != header_h) {
        atomic_store(&g_last_header_height, header_h);
        atomic_store(&g_unchanged_since, now);
        return false;
    }

    int64_t since = atomic_load(&g_unchanged_since);
    if (since == 0) {
        atomic_store(&g_unchanged_since, now);
        return false;
    }
    int64_t age = now - since;
    if (age < 300)
        return false;

    atomic_store(&g_header_height_at_detect, header_h);
    atomic_store(&g_peer_max_at_detect, peer_max);
    atomic_store(&g_age_at_detect, age);
    return true;
}

static enum condition_remedy_result remedy_header_stall_at_height(void)
{
    int header_h = atomic_load(&g_header_height_at_detect);
    int peer_max = atomic_load(&g_peer_max_at_detect);
    LOG_WARN("condition", "[condition:header_stall_at_height] header=%d peer_max=%d " "age=%llds action=kick_headers", header_h, peer_max, (long long)atomic_load(&g_age_at_detect));

    struct connman *cm = sync_monitor_connman();
    if (cm) {
        zcl_mutex_lock(&cm->manager.cs_nodes);
        for (size_t i = 0; i < cm->manager.num_nodes; i++) {
            struct p2p_node *n = cm->manager.nodes[i];
            if (!n || n->disconnect || n->inbound)
                continue;
            atomic_store_explicit(&n->last_getheaders_time, 0,
                                  memory_order_relaxed);
            atomic_store_explicit(&n->getheaders_stale_count, 0,
                                  memory_order_relaxed);
        }
        zcl_mutex_unlock(&cm->manager.cs_nodes);
    }

    if (!sync_set_state(SYNC_HEADERS_DOWNLOAD,
                        "condition header_stall_at_height")) {
        sync_set_state(SYNC_IDLE, "condition header_stall via idle");
        sync_set_state(SYNC_HEADERS_DOWNLOAD,
                       "condition header_stall_at_height");
    }
    (void)header_probe_pull_range(header_h + 1, 2000, NULL);

#ifdef ZCL_TESTING
    atomic_fetch_add(&g_test_remedy_calls, 1);
#endif
    return COND_REMEDY_OK;
}

static bool witness_header_stall_at_height(int64_t target_at_detect)
{
    (void)target_at_detect;
    struct main_state *ms = sync_monitor_main_state();
    if (!ms || !ms->pindex_best_header)
        return false;
    return ms->pindex_best_header->nHeight >
           atomic_load(&g_header_height_at_detect);
}

static struct condition c_header_stall_at_height = {
    .name = "header_stall_at_height",
    .severity = COND_CRITICAL,
    .poll_secs = 5,
    .backoff_secs = 300,
    .max_attempts = 3,
    .detect = detect_header_stall_at_height,
    .remedy = remedy_header_stall_at_height,
    .witness = witness_header_stall_at_height,
    .witness_window_secs = 60,
    /* External-resource fault (peers not serving headers): re-arm on a cooldown
     * so the kick keeps retrying until headers flow again, instead of latching
     * operator_needed forever. Pages once at the cap; never gives up. Mirrors
     * peer_floor_violated. */
    .cooldown_secs = 600,
    .cooldown_max_rearms = 0,
};

void register_header_stall_at_height(void)
{
    (void)condition_register(&c_header_stall_at_height);
}

#ifdef ZCL_TESTING
void header_stall_at_height_test_reset(void)
{
    atomic_store(&g_last_header_height, -1);
    atomic_store(&g_header_height_at_detect, -1);
    atomic_store(&g_peer_max_at_detect, -1);
    atomic_store(&g_unchanged_since, 0);
    atomic_store(&g_age_at_detect, 0);
    atomic_store(&g_test_remedy_calls, 0);
}

int header_stall_at_height_test_remedy_calls(void)
{
    return atomic_load(&g_test_remedy_calls);
}
#endif
