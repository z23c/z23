/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

#include "conditions/sync_violation_lag.h"
#include "util/log_macros.h"
#include "framework/condition.h"

#include "config/state_offer_peer.h"   /* the held-rung-fetch exemption */
#include "event/event.h"
#include "net/connman.h"
#include "net/net.h"
#include "platform/time_compat.h"
#include "services/sync_monitor.h"
#include "sync/sync_state.h"
#include "validation/chainstate.h"
#include "validation/main_state.h"

#include <stdatomic.h>
#include <stdio.h>

#define SYNC_VIOLATION_GAP 100
#define SYNC_VIOLATION_SECS 600
#define SYNC_VIOLATION_COOLDOWN_SECS 3600

static _Atomic int64_t g_first_seen_unix;
static _Atomic int64_t g_last_attempt_unix;
static _Atomic int g_last_local_seen;
static _Atomic int g_local_tip_at_detect;
static _Atomic int g_peer_max_at_detect;
static _Atomic int g_gap_at_detect;
static _Atomic int64_t g_age_at_detect;

#ifdef ZCL_TESTING
static _Atomic int g_test_remedy_calls;
#endif

static bool detect_sync_violation_lag(void)
{
    struct connman *cm = sync_monitor_connman();
    struct main_state *ms = sync_monitor_main_state();
    if (!cm || !ms) {
        atomic_store(&g_first_seen_unix, 0);
        return false;
    }

    int local = active_chain_height(&ms->chain_active);
    int peer_max = connman_max_peer_height(cm);
    int gap = peer_max - local;
    if (peer_max <= 0 || local < 0 || gap <= SYNC_VIOLATION_GAP) {
        atomic_store(&g_first_seen_unix, 0);
        atomic_store(&g_last_local_seen, local);
        return false;
    }

    int64_t now = platform_time_wall_unix();
    int last_local = atomic_load(&g_last_local_seen);
    if (last_local != local) {
        atomic_store(&g_last_local_seen, local);
        atomic_store(&g_first_seen_unix, now);
        return false;
    }

    int64_t first = atomic_load(&g_first_seen_unix);
    if (first == 0) {
        atomic_store(&g_first_seen_unix, now);
        return false;
    }
    int64_t age = now - first;
    if (age < SYNC_VIOLATION_SECS)
        return false;

    atomic_store(&g_local_tip_at_detect, local);
    atomic_store(&g_peer_max_at_detect, peer_max);
    atomic_store(&g_gap_at_detect, gap);
    atomic_store(&g_age_at_detect, age);
    return true;
}

/* Under the FlySync header hold the local tip cannot move until the rung
 * bundle lands, so the lag is expected; rotating the peer streaming that
 * bundle only restarts the fetch (run F2 at 600 s). When such a peer exists,
 * rotate every other outbound peer exactly as connman_force_outbound_rotation
 * would; otherwise use it unchanged. Returns the peers asked to disconnect. */
static bool live_outbound(const struct p2p_node *n)
{
    return n && !n->inbound && !n->disconnect;
}

static int rotate_outbound(struct connman *cm, const char *reason)
{
    bool spare = false;
    zcl_mutex_lock(&cm->manager.cs_nodes);
    for (size_t i = 0; i < cm->manager.num_nodes && !spare; i++)
        spare = live_outbound(cm->manager.nodes[i]) &&
                state_offer_peer_serving_held_fetch(cm->manager.nodes[i]);
    int disconnected = 0;
    for (size_t i = 0; i < cm->manager.num_nodes && spare; i++) {
        struct p2p_node *n = cm->manager.nodes[i];
        if (!live_outbound(n) || state_offer_peer_serving_held_fetch(n))
            continue;
        (void)p2p_node_request_disconnect(n, P2P_DISCONNECT_POLICY_ROTATION,
                                          P2P_DISCONNECT_SOURCE_PEER_POLICY,
                                          n->endpoint_generation);
        disconnected++;
    }
    zcl_mutex_unlock(&cm->manager.cs_nodes);
    if (!spare)
        return connman_force_outbound_rotation(cm, reason);
    LOG_WARN("condition", "[condition:sync_violation_lag] outbound rotation reason=%s "
             "disconnected=%d; kept the peer streaming the held FlySync rung bundle",
             reason, disconnected);
    connman_kick_seed_discovery(cm);
    return disconnected;
}

static enum condition_remedy_result remedy_sync_violation_lag(void)
{
    int64_t now = platform_time_wall_unix();
    int64_t last = atomic_load(&g_last_attempt_unix);
    if (last != 0 && now - last < SYNC_VIOLATION_COOLDOWN_SECS)
        return COND_REMEDY_SKIP;

    struct connman *cm = sync_monitor_connman();
    if (!cm)
        return COND_REMEDY_SKIP;

    LOG_WARN("condition", "[condition:sync_violation_lag] local=%d peer_max=%d gap=%d " "age=%llds action=outbound_rotation", atomic_load(&g_local_tip_at_detect), atomic_load(&g_peer_max_at_detect), atomic_load(&g_gap_at_detect), (long long)atomic_load(&g_age_at_detect));
    event_emitf(EV_SYNC_STATE_CHANGE, 0,
                "condition SYNC_VIOLATION local=%d peer_max=%d gap=%d",
                atomic_load(&g_local_tip_at_detect),
                atomic_load(&g_peer_max_at_detect),
                atomic_load(&g_gap_at_detect));
    int disconnected = rotate_outbound(cm, "condition:sync_violation_lag");
    sync_monitor_record_recovery(WATCHDOG_SYNC_VIOLATION,
                                 atomic_load(&g_local_tip_at_detect),
                                 atomic_load(&g_peer_max_at_detect),
                                 disconnected,
                                 "condition:sync_violation_lag");
    sync_set_state(SYNC_IDLE, "condition sync_violation_lag");
    sync_monitor_kick_local_sync("condition:sync_violation_lag");
    atomic_store(&g_last_attempt_unix, now);
#ifdef ZCL_TESTING
    atomic_fetch_add(&g_test_remedy_calls, 1);
#endif
    return COND_REMEDY_OK;
}

static bool witness_sync_violation_lag(int64_t target_at_detect)
{
    (void)target_at_detect;
    struct connman *cm = sync_monitor_connman();
    struct main_state *ms = sync_monitor_main_state();
    if (!cm || !ms)
        return false;
    int local = active_chain_height(&ms->chain_active);
    int peer_max = connman_max_peer_height(cm);
    return peer_max - local <= SYNC_VIOLATION_GAP;
}

static struct condition c_sync_violation_lag = {
    .name = "sync_violation_lag",
    .severity = COND_CRITICAL,
    .poll_secs = 5,
    .backoff_secs = 60,
    .max_attempts = 1,
    /* Continue-with-cooldown (sticky-node plan #7): lagging the network's
     * peer-reported tip is an external-resource condition (peers can still
     * be far ahead, or new peers can arrive) — never a local deterministic-
     * unrecoverable fault. Before this fix cooldown_secs was 0 ("legacy"),
     * so a persistent gap (e.g. the only peer ahead of us is inbound and
     * survives connman_force_outbound_rotation) latched EV_OPERATOR_NEEDED
     * permanently after the single attempt and never retried the remedy —
     * observed live: paging every 3600s for 27h with no re-attempt. Re-arm
     * every 10 minutes, UNBOUNDED (cooldown_max_rearms = 0), matching every
     * sibling network-dependent condition (peer_floor_violated,
     * header_stall_at_height, sync_state_stuck, net_tip_regression, ...). */
    .cooldown_secs = 600,
    .cooldown_max_rearms = 0,
    .detect = detect_sync_violation_lag,
    .remedy = remedy_sync_violation_lag,
    .witness = witness_sync_violation_lag,
    .witness_window_secs = 60,
};

void register_sync_violation_lag(void)
{
    (void)condition_register(&c_sync_violation_lag);
}

#ifdef ZCL_TESTING
void sync_violation_lag_test_reset(void)
{
    atomic_store(&g_first_seen_unix, 0);
    atomic_store(&g_last_attempt_unix, 0);
    atomic_store(&g_last_local_seen, -1);
    atomic_store(&g_local_tip_at_detect, -1);
    atomic_store(&g_peer_max_at_detect, -1);
    atomic_store(&g_gap_at_detect, 0);
    atomic_store(&g_age_at_detect, 0);
    atomic_store(&g_test_remedy_calls, 0);
}

int sync_violation_lag_test_remedy_calls(void)
{
    return atomic_load(&g_test_remedy_calls);
}
#endif
