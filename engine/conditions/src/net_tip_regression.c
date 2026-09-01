/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * net_tip_regression condition — see conditions/net_tip_regression.h. One of
 * several redundant "are we falling behind" signals: the network's modal height
 * keeps advancing while our served height is frozen and we are behind. Purely
 * observational; never changes chain selection. */

#include "conditions/net_tip_regression.h"

#include "framework/condition.h"
#include "services/network_monitor.h"
#include "services/sync_monitor.h"
#include "validation/chainstate.h"
#include "validation/main_state.h"
#include "util/blocker.h"
#include "util/log_macros.h"
#include "platform/time_compat.h"

#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>

#define NET_TIP_REGRESSION_BLOCKER_ID   "net_tip_regression"
#define NET_TIP_REGRESSION_OWNER        "network_monitor"
#define NET_TIP_REGRESSION_SECS         900  /* our height frozen this long */
#define NET_TIP_REGRESSION_MODAL_MARGIN 2    /* network advanced >= this many */

static _Atomic int64_t g_last_our_height = -1;
static _Atomic int64_t g_our_height_since;
static _Atomic int64_t g_modal_at_since = -1;
static _Atomic int64_t g_our_height_at_detect = -1;
#ifdef ZCL_TESTING
static _Atomic int64_t g_now_override = -1;
#endif

static int64_t ntr_now(void)
{
#ifdef ZCL_TESTING
    int64_t o = atomic_load(&g_now_override);
    if (o >= 0)
        return o;
#endif
    return platform_time_wall_unix();
}

static int ntr_regression_secs(void)
{
    const char *e = getenv("ZCL_NET_TIP_REGRESSION_SECS");
    if (e && e[0]) {
        int v = atoi(e);
        if (v >= 1)
            return v;
    }
    return NET_TIP_REGRESSION_SECS;
}

static bool detect_net_tip_regression(void)
{
    struct network_consensus_view v = {0};
    if (!network_monitor_get_view(&v) || v.num_peers == 0) {
        atomic_store(&g_last_our_height, -1); /* no signal — reset baseline */
        return false;
    }

    int64_t our = v.our_height;
    int64_t modal = v.modal_height;
    int64_t maxh = v.max_height;
    int64_t now = ntr_now();

    int64_t last = atomic_load(&g_last_our_height);
    if (our != last) {
        /* our height changed (or first observation): re-baseline the freeze. */
        atomic_store(&g_last_our_height, our);
        atomic_store(&g_our_height_since, now);
        atomic_store(&g_modal_at_since, modal);
        return false;
    }
    if (our < 0)
        return false; /* our height unknown — cannot judge regression */

    int64_t frozen = now - atomic_load(&g_our_height_since);
    int64_t modal_at = atomic_load(&g_modal_at_since);
    if (frozen >= ntr_regression_secs() &&
        modal_at >= 0 &&
        modal >= modal_at + NET_TIP_REGRESSION_MODAL_MARGIN &&
        maxh > our) {
        atomic_store(&g_our_height_at_detect, our);
        return true;
    }
    return false;
}

static enum condition_remedy_result remedy_net_tip_regression(void)
{
    struct network_consensus_view v = {0};
    (void)network_monitor_get_view(&v);
    char reason[BLOCKER_REASON_MAX];
    snprintf(reason, sizeof(reason),
             "our_height=%lld modal=%lld max=%lld delta=%lld frozen>=%ds",
             (long long)v.our_height, (long long)v.modal_height,
             (long long)v.max_height, (long long)v.delta,
             ntr_regression_secs());

    struct blocker_record r;
    if (blocker_init(&r, NET_TIP_REGRESSION_BLOCKER_ID, NET_TIP_REGRESSION_OWNER,
                     BLOCKER_TRANSIENT, reason))
        (void)blocker_set(&r);
    LOG_WARN("condition", "[condition:net_tip_regression] %s", reason);
    /* Observational: naming a fall-behind is not a self-heal — chain selection
     * (find_most_work_chain) and peer recovery (peer_floor_violated) act. */
    return COND_REMEDY_FAILED;
}

static bool witness_net_tip_regression(int64_t target_at_detect)
{
    (void)target_at_detect;
    struct main_state *ms = sync_monitor_main_state();
    int64_t our_now = ms ? (int64_t)active_chain_height(&ms->chain_active) : -1;
    int64_t at_detect = atomic_load(&g_our_height_at_detect);
    struct network_consensus_view v = {0};
    bool have = network_monitor_get_view(&v);

    /* Resolved iff our served height actually MOVED past the detect height, OR
     * we reached the network's best advertised height (caught up). Both read
     * OBSERVABLE progress (active_chain_height), never poison/FSM absence. */
    bool resolved = (our_now >= 0 && at_detect >= 0 && our_now > at_detect) ||
                    (have && v.max_height >= 0 && our_now >= v.max_height);
    if (resolved)
        blocker_clear(NET_TIP_REGRESSION_BLOCKER_ID);
    return resolved;
}

static struct condition c_net_tip_regression = {
    .name = "net_tip_regression",
    .severity = COND_WARN,
    .poll_secs = 30,
    .backoff_secs = 120,
    .max_attempts = 1,
    .cooldown_secs = 600,
    .cooldown_max_rearms = 0,
    .detect = detect_net_tip_regression,
    .remedy = remedy_net_tip_regression,
    .witness = witness_net_tip_regression,
    .witness_window_secs = 60,
};

void register_net_tip_regression(void)
{
    (void)condition_register(&c_net_tip_regression);
}

#ifdef ZCL_TESTING
void net_tip_regression_test_reset(void)
{
    atomic_store(&g_last_our_height, -1);
    atomic_store(&g_our_height_since, 0);
    atomic_store(&g_modal_at_since, -1);
    atomic_store(&g_our_height_at_detect, -1);
    atomic_store(&g_now_override, -1);
    blocker_clear(NET_TIP_REGRESSION_BLOCKER_ID);
}

void net_tip_regression_test_set_now(int64_t now_unix)
{
    atomic_store(&g_now_override, now_unix);
}

bool net_tip_regression_test_detect(void)
{
    return detect_net_tip_regression();
}
#endif
