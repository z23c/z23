/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * net_partition_suspected condition — see conditions/net_partition_suspected.h.
 * A redundant, independent "WE may be cut off" signal: either our peer count
 * collapses (eclipse) or, with peers present, we are behind and nothing is
 * moving. Observational; peer re-discovery is peer_floor_violated's job. */

#include "conditions/net_partition_suspected.h"

#include "framework/condition.h"
#include "services/network_monitor.h"
#include "services/sync_monitor.h"
#include "net/connman.h"
#include "validation/chainstate.h"
#include "validation/main_state.h"
#include "util/blocker.h"
#include "util/log_macros.h"
#include "platform/time_compat.h"

#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#define NET_PARTITION_BLOCKER_ID "net_partition_suspected"
#define NET_PARTITION_OWNER      "network_monitor"
#define NET_PARTITION_MIN_PEERS  2    /* below this = collapse (eclipse) */
#define NET_PARTITION_SECS       600  /* sustained this long before firing */

static _Atomic int64_t g_low_peers_since;        /* 0 = not low */
static _Atomic int64_t g_maxh_ref = INT64_MIN;
static _Atomic int64_t g_maxh_since;
static _Atomic int64_t g_ourh_ref = INT64_MIN;
static _Atomic int64_t g_ourh_since;

/* captured at detect for the blocker reason + witness */
static _Atomic int g_peers_at_detect;
static _Atomic int64_t g_our_at_detect = -1;
static _Atomic int64_t g_max_at_detect = -1;
static _Atomic int g_sig_a_at_detect; /* 1 = eclipse, 0 = frozen-behind */
#ifdef ZCL_TESTING
static _Atomic int64_t g_now_override = -1;
#endif

static int64_t nps_now(void)
{
#ifdef ZCL_TESTING
    int64_t o = atomic_load(&g_now_override);
    if (o >= 0)
        return o;
#endif
    return platform_time_wall_unix();
}

static int nps_partition_secs(void)
{
    const char *e = getenv("ZCL_NET_PARTITION_SECS");
    if (e && e[0]) {
        int v = atoi(e);
        if (v >= 1)
            return v;
    }
    return NET_PARTITION_SECS;
}

static void nps_reset_tracking(void)
{
    atomic_store(&g_low_peers_since, 0);
    atomic_store(&g_maxh_ref, INT64_MIN);
    atomic_store(&g_ourh_ref, INT64_MIN);
}

static bool detect_net_partition_suspected(void)
{
    struct network_consensus_view v = {0};
    if (!network_monitor_get_view(&v)) {
        nps_reset_tracking();
        return false;
    }

    int64_t now = nps_now();
    int peers = v.num_peers;
    int64_t our = v.our_height;
    int64_t maxh = v.max_height;

    /* Signal A bookkeeping: sustained peer collapse. */
    if (peers < NET_PARTITION_MIN_PEERS) {
        if (atomic_load(&g_low_peers_since) == 0)
            atomic_store(&g_low_peers_since, now);
    } else {
        atomic_store(&g_low_peers_since, 0);
    }

    /* Signal B bookkeeping: track when max/our height last MOVED. */
    if (maxh != atomic_load(&g_maxh_ref)) {
        atomic_store(&g_maxh_ref, maxh);
        atomic_store(&g_maxh_since, now);
    }
    if (our != atomic_load(&g_ourh_ref)) {
        atomic_store(&g_ourh_ref, our);
        atomic_store(&g_ourh_since, now);
    }

    int secs = nps_partition_secs();
    int64_t low_since = atomic_load(&g_low_peers_since);
    bool sig_a = low_since != 0 && (now - low_since) >= secs;
    bool sig_b = peers >= 1 && our >= 0 && maxh >= 0 && our < maxh &&
                 (now - atomic_load(&g_maxh_since)) >= secs &&
                 (now - atomic_load(&g_ourh_since)) >= secs;

    if (sig_a || sig_b) {
        atomic_store(&g_peers_at_detect, peers);
        atomic_store(&g_our_at_detect, our);
        atomic_store(&g_max_at_detect, maxh);
        atomic_store(&g_sig_a_at_detect, sig_a ? 1 : 0);
        return true;
    }
    return false;
}

static enum condition_remedy_result remedy_net_partition_suspected(void)
{
    int sig_a = atomic_load(&g_sig_a_at_detect);
    char reason[BLOCKER_REASON_MAX];
    snprintf(reason, sizeof(reason),
             "signal=%s peers=%d our_height=%lld max_height=%lld window>=%ds",
             sig_a ? "peer_collapse" : "frozen_behind",
             atomic_load(&g_peers_at_detect),
             (long long)atomic_load(&g_our_at_detect),
             (long long)atomic_load(&g_max_at_detect),
             nps_partition_secs());

    struct blocker_record r;
    if (blocker_init(&r, NET_PARTITION_BLOCKER_ID, NET_PARTITION_OWNER,
                     BLOCKER_TRANSIENT, reason))
        (void)blocker_set(&r);
    LOG_WARN("condition", "[condition:net_partition_suspected] %s", reason);
    /* Observational: peer re-discovery is peer_floor_violated's remedy. This
     * is a redundant, independent naming of the fall-behind class. */
    return COND_REMEDY_FAILED;
}

static bool witness_net_partition_suspected(int64_t target_at_detect)
{
    (void)target_at_detect;
    struct connman *cm = sync_monitor_connman();
    int healthy = cm ? (int)connman_outbound_healthy_count(cm) : 0;
    struct main_state *ms = sync_monitor_main_state();
    int64_t our_now = ms ? (int64_t)active_chain_height(&ms->chain_active) : -1;
    int64_t our_at_detect = atomic_load(&g_our_at_detect);
    int64_t max_at_detect = atomic_load(&g_max_at_detect);

    /* Resolved iff our served height actually MOVED (we are ingesting again),
     * OR peers recovered above the collapse floor AND we are no longer behind
     * the height we were stuck below. Reads OBSERVABLE progress
     * (active_chain_height, connman_outbound_healthy_count). */
    bool resolved =
        (our_now >= 0 && our_at_detect >= 0 && our_now > our_at_detect) ||
        (healthy >= NET_PARTITION_MIN_PEERS && max_at_detect >= 0 &&
         our_now >= max_at_detect);
    if (resolved)
        blocker_clear(NET_PARTITION_BLOCKER_ID);
    return resolved;
}

static struct condition c_net_partition_suspected = {
    .name = "net_partition_suspected",
    .severity = COND_WARN,
    .poll_secs = 30,
    .backoff_secs = 120,
    .max_attempts = 1,
    .cooldown_secs = 600,
    .cooldown_max_rearms = 0,
    .detect = detect_net_partition_suspected,
    .remedy = remedy_net_partition_suspected,
    .witness = witness_net_partition_suspected,
    .witness_window_secs = 60,
};

void register_net_partition_suspected(void)
{
    (void)condition_register(&c_net_partition_suspected);
}

#ifdef ZCL_TESTING
void net_partition_suspected_test_reset(void)
{
    nps_reset_tracking();
    atomic_store(&g_maxh_since, 0);
    atomic_store(&g_ourh_since, 0);
    atomic_store(&g_now_override, -1);
    atomic_store(&g_peers_at_detect, 0);
    atomic_store(&g_our_at_detect, -1);
    atomic_store(&g_max_at_detect, -1);
    atomic_store(&g_sig_a_at_detect, 0);
    blocker_clear(NET_PARTITION_BLOCKER_ID);
}

void net_partition_suspected_test_set_now(int64_t now_unix)
{
    atomic_store(&g_now_override, now_unix);
}

bool net_partition_suspected_test_detect(void)
{
    return detect_net_partition_suspected();
}
#endif
