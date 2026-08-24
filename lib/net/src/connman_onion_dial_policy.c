/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: keep local Tor readiness and shared-budget refusal out of peer
 * failure accounting while making every held onion dial observable. */

#include "net/connman_onion_dial_policy.h"
#include "net/onion_stream.h"
#include "net/tor_integration.h"
#include "platform/time_compat.h"
#include "util/log_macros.h"

/* The scheduler retries every 200ms-1s; one line per 10s proves the hold
 * without turning a slow public Tor bootstrap into a log flood. */
static int64_t s_last_not_ready_log_ms;

bool connman_onion_dial_policy_allows(const struct net_service *svc,
                                      int64_t remaining_budget_ms)
{
    if (!svc || !net_addr_is_tor(&svc->addr)) {
        LOG_FAIL("net", "onion dial policy refused non-onion service");
        return false;
    }

    char dest[NET_SERVICE_STR_MAX + 1];
    net_service_to_string(svc, dest, sizeof(dest));
    if (remaining_budget_ms <= 0) {
        onion_stream_note_last_dial(dest, "dial_deferred");
        LOG_WARN("net", "onion stage=dial_deferred target=%s (batch spent "
                        "its whole %d ms circuit budget)",
                 dest, ONION_STREAM_CONNECT_TIMEOUT_MS);
        return false;
    }

    bool tor_enabled = tor_integration_is_enabled();
    if (tor_enabled && tor_integration_is_dial_ready())
        return true;

    /* A local bootstrap wait is not a dead peer. Charging addnode TCP
     * backoff here used to strand the dial after dynhost became ready. */
    const char *stage = tor_enabled ? "dynhost_not_ready" : "tor_not_running";
    onion_stream_note_last_dial(dest, stage);
    int64_t now_ms = platform_time_monotonic_ms();
    if (now_ms - s_last_not_ready_log_ms >= 10000) {
        LOG_INFO("net", "onion stage=%s target=%s (holding addnode; "
                        "not charging backoff)", stage, dest);
        s_last_not_ready_log_ms = now_ms;
    }
    return false;
}
