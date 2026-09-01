/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

#include "util/service_state.h"

#include "json/json.h"
#include "util/log_macros.h"

#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <string.h>

static _Atomic int g_service_state = SERVICE_STATE_BOOT;
static pthread_mutex_t g_reason_lock = PTHREAD_MUTEX_INITIALIZER;
static char g_reason[128] = "boot";

static const char *const k_names[SERVICE_STATE__COUNT] = {
    [SERVICE_STATE_BOOT]             = "boot",
    [SERVICE_STATE_RESTORE]          = "restore",
    [SERVICE_STATE_RECONCILE]        = "reconcile",
    [SERVICE_STATE_DEGRADED_SERVING] = "degraded_serving",
    [SERVICE_STATE_SYNCING]          = "syncing",
    [SERVICE_STATE_HEALTHY]          = "healthy",
    [SERVICE_STATE_REPAIRING]        = "repairing",
};

const char *service_state_name(enum service_state s)
{
    if ((int)s < 0 || (int)s >= SERVICE_STATE__COUNT || !k_names[s])
        return "unknown";
    return k_names[s];
}

enum service_state service_state_current(void)
{
    return (enum service_state)atomic_load(&g_service_state);
}

const char *service_state_reason(void)
{
    return g_reason;
}

void service_state_reason_copy(char *buf, size_t cap)
{
    if (!buf || cap == 0)
        return;
    pthread_mutex_lock(&g_reason_lock);
    snprintf(buf, cap, "%s", g_reason);
    pthread_mutex_unlock(&g_reason_lock);
}

void service_state_advance(enum service_state next, const char *reason)
{
    if ((int)next < 0 || (int)next >= SERVICE_STATE__COUNT) {
        LOG_WARN("service_state",
                 "[service_state] ignoring out-of-range target %d",
                 (int)next);
        return;
    }

    enum service_state prev =
        (enum service_state)atomic_exchange(&g_service_state, (int)next);

    pthread_mutex_lock(&g_reason_lock);
    if (reason && reason[0]) {
        strncpy(g_reason, reason, sizeof(g_reason) - 1);
        g_reason[sizeof(g_reason) - 1] = '\0';
    }
    pthread_mutex_unlock(&g_reason_lock);

    if (prev != next)
        LOG_INFO("service_state", "[service_state] %s -> %s (%s)",
                 service_state_name(prev), service_state_name(next),
                 reason && reason[0] ? reason : "-");
}

bool service_state_dump_state_json(struct json_value *out, const char *key)
{
    (void)key;
    if (!out)
        return false;
    enum service_state cur = service_state_current();
    json_set_object(out);
    json_push_kv_str(out, "state", service_state_name(cur));
    json_push_kv_int(out, "state_id", (int)cur);
    /* Snapshot the reason under g_reason_lock via the safe accessor instead
     * of the lock-free service_state_reason(), which can race the writer in
     * service_state_advance. */
    char reason_snap[128];
    service_state_reason_copy(reason_snap, sizeof(reason_snap));
    json_push_kv_str(out, "reason", reason_snap);
    return true;
}
