/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * net_fork_detected condition — see conditions/net_fork_detected.h. Names real
 * fork evidence (two peer clusters at one height, different tip hashes, each
 * >= NM_FORK_MIN_CLUSTER peers). Purely observational — the node never picks a
 * branch here; find_most_work_chain stays authoritative. */

#include "conditions/net_fork_detected.h"

#include "framework/condition.h"
#include "services/network_monitor.h"
#include "services/sync_monitor.h"
#include "validation/chainstate.h"
#include "validation/main_state.h"
#include "util/blocker.h"
#include "util/log_macros.h"

#include <stdatomic.h>
#include <stdio.h>

#define NET_FORK_BLOCKER_ID "net_fork_detected"
#define NET_FORK_OWNER      "network_monitor"

static _Atomic int64_t g_fork_height_at_detect = -1;

static bool detect_net_fork_detected(void)
{
    struct network_consensus_view v = {0};
    if (!network_monitor_get_view(&v))
        return false; // raw-return-ok:view-not-ready-no-signal
    if (!v.fork_detected)
        return false;
    atomic_store(&g_fork_height_at_detect, v.fork_height);
    return true;
}

static enum condition_remedy_result remedy_net_fork_detected(void)
{
    struct network_consensus_view v = {0};
    if (!network_monitor_get_view(&v) || !v.fork_detected)
        return COND_REMEDY_SKIP;

    char reason[BLOCKER_REASON_MAX];
    snprintf(reason, sizeof(reason),
             "height=%lld hash_a=%s(%d peers) hash_b=%s(%d peers)",
             (long long)v.fork_height, v.fork_hash_a, v.fork_count_a,
             v.fork_hash_b, v.fork_count_b);

    struct blocker_record r;
    if (blocker_init(&r, NET_FORK_BLOCKER_ID, NET_FORK_OWNER,
                     BLOCKER_TRANSIENT, reason))
        (void)blocker_set(&r);
    LOG_WARN("condition", "[condition:net_fork_detected] %s", reason);
    /* Observational: the node does not resolve forks — it follows the most-work
     * valid chain. This only makes the disagreement loud. */
    return COND_REMEDY_FAILED;
}

static bool witness_net_fork_detected(int64_t target_at_detect)
{
    (void)target_at_detect;
    struct network_consensus_view v = {0};
    bool have = network_monitor_get_view(&v);
    struct main_state *ms = sync_monitor_main_state();
    int64_t our_now = ms ? (int64_t)active_chain_height(&ms->chain_active) : -1;
    int64_t fork_h = atomic_load(&g_fork_height_at_detect);

    /* Resolved iff the network no longer shows a fork, OR our own tip has
     * advanced past the contested height (we built beyond the fork and settled
     * onto a branch). The second clause reads OBSERVABLE progress
     * (active_chain_height MOVED), not the detector's own flag. */
    bool resolved = (have && !v.fork_detected) ||
                    (our_now >= 0 && fork_h >= 0 && our_now > fork_h);
    if (resolved)
        blocker_clear(NET_FORK_BLOCKER_ID);
    return resolved;
}

static struct condition c_net_fork_detected = {
    .name = "net_fork_detected",
    .severity = COND_WARN,
    .poll_secs = 30,
    .backoff_secs = 120,
    .max_attempts = 1,
    .cooldown_secs = 600,
    .cooldown_max_rearms = 0,
    .detect = detect_net_fork_detected,
    .remedy = remedy_net_fork_detected,
    .witness = witness_net_fork_detected,
    .witness_window_secs = 60,
};

void register_net_fork_detected(void)
{
    (void)condition_register(&c_net_fork_detected);
}

#ifdef ZCL_TESTING
void net_fork_detected_test_reset(void)
{
    atomic_store(&g_fork_height_at_detect, -1);
    blocker_clear(NET_FORK_BLOCKER_ID);
}

bool net_fork_detected_test_detect(void)
{
    return detect_net_fork_detected();
}
#endif
