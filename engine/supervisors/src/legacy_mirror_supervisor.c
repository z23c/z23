/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Supervisor contract for the zclassicd mirror observer.
 */

#include "supervisors/legacy_mirror_supervisor.h"

#include "services/legacy_mirror_sync_service.h"
#include "supervisors/domains.h"
#include "event/event.h"
#include "util/log_macros.h"
#include "util/supervisor.h"

#include <stdatomic.h>

static _Atomic supervisor_child_id g_legacy_mirror_supervisor_id =
    SUPERVISOR_INVALID_ID;
static struct liveness_contract g_legacy_mirror_contract;
static _Atomic int g_legacy_mirror_base_cadence = 3;
static _Atomic uint32_t g_legacy_mirror_consecutive_failures;
static _Atomic uint64_t g_legacy_mirror_stall_events;

#define LEGACY_MIRROR_BACKOFF_MAX_SECS 300

int legacy_mirror_supervisor_backoff_secs(int base_cadence_secs,
                                          uint32_t consecutive_failures)
{
    int base = base_cadence_secs > 0 ? base_cadence_secs : 3;
    if (base > LEGACY_MIRROR_BACKOFF_MAX_SECS)
        base = LEGACY_MIRROR_BACKOFF_MAX_SECS;
    if (consecutive_failures == 0)
        return base;

    /* Exponential retry, capped before the shift can overflow. */
    uint32_t shifts = consecutive_failures < 7 ? consecutive_failures : 7;
    int64_t delayed = (int64_t)base << shifts;
    return delayed < LEGACY_MIRROR_BACKOFF_MAX_SECS
               ? (int)delayed : LEGACY_MIRROR_BACKOFF_MAX_SECS;
}

bool legacy_mirror_supervisor_should_emit_stall(uint64_t stall_count)
{
    /* Preserve the first occurrence, then only powers of two. The cumulative
     * rpc_errors counter and last causal detail remain available in typed
     * mirror diagnostics without flooding logs or the event ledger. */
    return stall_count != 0 &&
           (stall_count & (stall_count - 1)) == 0;
}

static int64_t legacy_mirror_progress_marker(
    const struct legacy_mirror_sync_stats *s)
{
    if (!s)
        return -1;
    if (s->last_attempt > 0)
        return s->last_attempt;
    return s->catchups_total;
}

static void legacy_mirror_on_stall(struct liveness_contract *c)
{
    struct legacy_mirror_sync_stats s;
    legacy_mirror_sync_stats_snapshot(&s);

    const char *reason = c
        ? supervisor_stall_reason_name(
              (enum supervisor_stall_reason)atomic_load(&c->stall_reason))
        : "unknown";
    uint64_t event_count =
        atomic_fetch_add(&g_legacy_mirror_stall_events, 1) + 1;
    if (legacy_mirror_supervisor_should_emit_stall(event_count)) {
        uint32_t failures =
            atomic_load(&g_legacy_mirror_consecutive_failures);
        int retry_secs = legacy_mirror_supervisor_backoff_secs(
            atomic_load(&g_legacy_mirror_base_cadence), failures);
        LOG_WARN("legacy_mirror",
                 "[legacy_mirror] supervisor stall reason=%s legacy=%d local=%d rpc_errors=%lld occurrences=%llu consecutive=%u retry_secs=%d",
                 reason, s.legacy_height, s.local_height,
                 (long long)s.rpc_errors,
                 (unsigned long long)event_count, failures, retry_secs);
        event_emitf(EV_CHAIN_ADVANCE_DECISION, 0,
                    "source=legacy_mirror decision=dependency_stall "
                    "reason=%s legacy_height=%d local_height=%d "
                    "rpc_errors=%lld occurrences=%llu consecutive=%u "
                    "retry_secs=%d",
                    reason, s.legacy_height, s.local_height,
                    (long long)s.rpc_errors,
                    (unsigned long long)event_count, failures, retry_secs);
    }
}

static void legacy_mirror_on_tick(struct liveness_contract *c)
{
    (void)c;
    supervisor_child_id id =
        atomic_load(&g_legacy_mirror_supervisor_id);
    if (id == SUPERVISOR_INVALID_ID)
        return;

    supervisor_tick(id);

    struct legacy_mirror_sync_stats before;
    legacy_mirror_sync_stats_snapshot(&before);
    bool ok = legacy_mirror_sync_request_catchup("supervisor_tick").ok;

    struct legacy_mirror_sync_stats after;
    legacy_mirror_sync_stats_snapshot(&after);
    supervisor_progress(id, legacy_mirror_progress_marker(&after));
    if (!ok || after.rpc_errors > before.rpc_errors) {
        uint32_t failures = atomic_fetch_add(
            &g_legacy_mirror_consecutive_failures, 1) + 1;
        supervisor_set_period(id, legacy_mirror_supervisor_backoff_secs(
            atomic_load(&g_legacy_mirror_base_cadence), failures));
        /* -legacyoracle=auto is an OPTIONAL reference observer.  A missing
         * zclassicd is legitimate idle/degraded dependency state, not a
         * failure of this sovereign node.  Keep cumulative error evidence and
         * exponential retry, but do not raise a supervisor stall (which also
         * launches an expensive all-subsystem debug bundle). */
        supervisor_progress_idle(id);
    } else {
        atomic_store(&g_legacy_mirror_consecutive_failures, 0);
        supervisor_set_period(id,
                              atomic_load(&g_legacy_mirror_base_cadence));
    }
}

bool legacy_mirror_supervisor_start(int cadence_secs)
{
    if (cadence_secs <= 0)
        cadence_secs = 3;
    atomic_store(&g_legacy_mirror_base_cadence, cadence_secs);
    atomic_store(&g_legacy_mirror_consecutive_failures, 0);
    atomic_store(&g_legacy_mirror_stall_events, 0);
    if (!supervisor_start())
        LOG_FAIL("legacy_mirror", "legacy_mirror_supervisor_start failed");

    supervisor_child_id id =
        atomic_load(&g_legacy_mirror_supervisor_id);
    if (id != SUPERVISOR_INVALID_ID) {
        struct legacy_mirror_sync_stats s;
        legacy_mirror_sync_stats_snapshot(&s);
        supervisor_set_period(id, cadence_secs);
        supervisor_progress(id, legacy_mirror_progress_marker(&s));
        supervisor_tick(id);
        return true;
    }

    liveness_contract_init(&g_legacy_mirror_contract, "chain.legacy_mirror");
    atomic_store(&g_legacy_mirror_contract.period_secs, cadence_secs);
    atomic_store(&g_legacy_mirror_contract.deadline_secs, 0);
    atomic_store(&g_legacy_mirror_contract.progress_max_quiet_us, 0);
    g_legacy_mirror_contract.on_tick = legacy_mirror_on_tick;
    g_legacy_mirror_contract.on_stall = legacy_mirror_on_stall;

    supervisor_domains_init();
    id = supervisor_register_in_domain(g_chain_sup, &g_legacy_mirror_contract);
    if (id == SUPERVISOR_INVALID_ID)
        LOG_FAIL("legacy_mirror", "legacy_mirror_supervisor_register failed");

    atomic_store(&g_legacy_mirror_supervisor_id, id);
    {
        struct legacy_mirror_sync_stats s;
        legacy_mirror_sync_stats_snapshot(&s);
        supervisor_progress(id, legacy_mirror_progress_marker(&s));
    }
    supervisor_tick(id);
    return true;
}

void legacy_mirror_supervisor_stop(void)
{
    supervisor_child_id id =
        atomic_load(&g_legacy_mirror_supervisor_id);
    if (id == SUPERVISOR_INVALID_ID)
        return;
    supervisor_set_period(id, 0);
    atomic_store(&g_legacy_mirror_consecutive_failures, 0);
#ifdef ZCL_TESTING
    id = atomic_exchange(&g_legacy_mirror_supervisor_id,
                         SUPERVISOR_INVALID_ID);
    if (id != SUPERVISOR_INVALID_ID)
        supervisor_unregister(id);
#endif
}

bool legacy_mirror_supervisor_running(void)
{
    supervisor_child_id id =
        atomic_load(&g_legacy_mirror_supervisor_id);
    return id != SUPERVISOR_INVALID_ID &&
           atomic_load(&g_legacy_mirror_contract.period_secs) > 0;
}
