/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * net_eclipse_suspected condition — see conditions/net_eclipse_suspected.h.
 * Promotes the network_crawler census `eclipse_suspected` field to a typed
 * healer: DETECT eclipse for 2 consecutive census rounds, REMEDY by kicking
 * seed + onion discovery, WITNESS by the census clearing while we hold healthy
 * outbound peers. Observational; never touches chain selection. */

#include "conditions/net_eclipse_suspected.h"

#include "framework/condition.h"
#include "services/network_crawler.h"
#include "services/sync_monitor.h"
#include "net/connman.h"
#include "util/blocker.h"
#include "util/log_macros.h"

#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>

#define NET_ECLIPSE_BLOCKER_ID "net_eclipse_suspected"
#define NET_ECLIPSE_OWNER      "network_crawler"
/* Two consecutive census rounds flagged before firing (one noisy sample is not
 * an eclipse). */
#define NET_ECLIPSE_MIN_ROUNDS 2

/* Edge-tracking across census rounds (keyed by the census `computed_at`). */
static _Atomic int64_t g_last_census_at = -1;
static _Atomic int     g_consecutive_eclipse;

/* Captured at detect for the blocker reason + witness. */
static _Atomic int64_t g_own_modal_at_detect = -1;
static _Atomic int64_t g_net_modal_at_detect = -1;
static _Atomic int     g_reachable_at_detect;
static _Atomic int     g_at_own_at_detect;

static void nes_reset_tracking(void)
{
    atomic_store(&g_last_census_at, -1);
    atomic_store(&g_consecutive_eclipse, 0);
}

static bool detect_net_eclipse_suspected(void)
{
    struct network_census_view v;
    if (!network_crawler_get_view(&v)) {
        nes_reset_tracking();
        return false;
    }

    /* Advance the consecutive-round counter only when a NEW census fold is
     * observed (computed_at moved), so a fast detect poll cadence cannot
     * inflate the count faster than the crawler actually re-samples. */
    int64_t last = atomic_load(&g_last_census_at);
    if (v.computed_at != last) {
        atomic_store(&g_last_census_at, v.computed_at);
        if (v.eclipse_suspected)
            atomic_fetch_add(&g_consecutive_eclipse, 1);
        else
            atomic_store(&g_consecutive_eclipse, 0);
    }

    bool fire = v.eclipse_suspected &&
                atomic_load(&g_consecutive_eclipse) >= NET_ECLIPSE_MIN_ROUNDS;
    if (fire) {
        atomic_store(&g_own_modal_at_detect, v.own_modal_height);
        atomic_store(&g_net_modal_at_detect, v.network_modal_height);
        atomic_store(&g_reachable_at_detect, v.reachable_count);
        atomic_store(&g_at_own_at_detect, v.network_count_at_own_modal);
    }
    return fire;
}

static enum condition_remedy_result remedy_net_eclipse_suspected(void)
{
    char reason[BLOCKER_REASON_MAX];
    snprintf(reason, sizeof(reason),
             "our peers modal=%lld is %d/%d of the reachable network "
             "(network modal=%lld) for >=%d census rounds",
             (long long)atomic_load(&g_own_modal_at_detect),
             atomic_load(&g_at_own_at_detect),
             atomic_load(&g_reachable_at_detect),
             (long long)atomic_load(&g_net_modal_at_detect),
             NET_ECLIPSE_MIN_ROUNDS);

    struct blocker_record r;
    if (blocker_init(&r, NET_ECLIPSE_BLOCKER_ID, NET_ECLIPSE_OWNER,
                     BLOCKER_TRANSIENT, reason))
        (void)blocker_set(&r);
    LOG_WARN("condition", "[condition:net_eclipse_suspected] %s", reason);

    /* Actively widen peering — pull fresh clearnet + onion seeds so we can
     * escape a minority peer cluster. Best-effort; the witness confirms. */
    struct connman *cm = sync_monitor_connman();
    if (!cm)
        return COND_REMEDY_FAILED;
    connman_kick_seed_discovery(cm);
    connman_kick_onion_seeds(cm);
    return COND_REMEDY_OK;
}

static bool witness_net_eclipse_suspected(int64_t target_at_detect)
{
    (void)target_at_detect;
    struct connman *cm = sync_monitor_connman();
    int healthy = cm ? (int)connman_outbound_healthy_count(cm) : 0;

    struct network_census_view v;
    bool census_ready = network_crawler_get_view(&v);

    /* Resolved iff the census no longer suspects eclipse AND we hold at least
     * one healthy outbound peer (we are genuinely re-peered, not just idle).
     * Reads OBSERVABLE state (connman_outbound_healthy_count + a fresh census),
     * never the poison flag the remedy set. */
    bool resolved = census_ready && !v.eclipse_suspected && healthy >= 1;
    if (resolved) {
        blocker_clear(NET_ECLIPSE_BLOCKER_ID);
        nes_reset_tracking();
    }
    return resolved;
}

static struct condition c_net_eclipse_suspected = {
    .name = "net_eclipse_suspected",
    .severity = COND_WARN,
    .poll_secs = 30,
    .backoff_secs = 120,
    .max_attempts = 3,
    /* External-dependency class (peer discovery): re-arm after a long backoff
     * instead of latching permanently. */
    .cooldown_secs = 600,
    .cooldown_max_rearms = 0,
    .detect = detect_net_eclipse_suspected,
    .remedy = remedy_net_eclipse_suspected,
    .witness = witness_net_eclipse_suspected,
    .witness_window_secs = 120,
};

void register_net_eclipse_suspected(void)
{
    (void)condition_register(&c_net_eclipse_suspected);
}

#ifdef ZCL_TESTING
void net_eclipse_suspected_test_reset(void)
{
    nes_reset_tracking();
    atomic_store(&g_own_modal_at_detect, -1);
    atomic_store(&g_net_modal_at_detect, -1);
    atomic_store(&g_reachable_at_detect, 0);
    atomic_store(&g_at_own_at_detect, 0);
    blocker_clear(NET_ECLIPSE_BLOCKER_ID);
}

bool net_eclipse_suspected_test_detect(void)
{
    return detect_net_eclipse_suspected();
}

int net_eclipse_suspected_test_remedy(void)
{
    return (int)remedy_net_eclipse_suspected();
}
#endif
