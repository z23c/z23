// one-result-type-ok:audit-predicate-and-diagnostic-dumper
// utxo_mirror_sync_audit_snapshot is a snapshot predicate and
// utxo_mirror_sync_dump_state_json implements diagnostics_dump_fn. Neither
// owns a fallible service operation; run_once/start carry those results.

/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Lock-free audit and diagnostics views for utxo_mirror_sync_service. Kept
 * separate from the write/lifecycle implementation so observation cannot
 * obscure the projection's transactional boundary. */

#include "services/utxo_mirror_sync_service.h"

#include "json/json.h"
#include "util/log_macros.h"

#include <stdatomic.h>

bool utxo_mirror_sync_audit_snapshot(uint64_t *generation_out)
{
    if (!generation_out)
        LOG_RETURN(false, "utxo_mirror",
                   "audit_snapshot: null generation_out");
    struct utxo_mirror_sync_service *svc = g_utxo_mirror_sync;
    if (!svc) {
        *generation_out = 0;
        return true;
    }

    uint32_t active_before = atomic_load(&svc->updates_active);
    uint64_t generation = atomic_load(&svc->update_generation);
    uint32_t active_after = atomic_load(&svc->updates_active);
    if (active_before != 0 || active_after != 0)
        return false;
    *generation_out = generation;
    return true;
}

static const char *utxo_mirror_sync_state_name(int state)
{
    switch (state) {
    case UTXO_MIRROR_SYNC_IDLE:    return "idle";
    case UTXO_MIRROR_SYNC_RUNNING: return "running";
    case UTXO_MIRROR_SYNC_STOPPED: return "stopped";
    default:                       return "unknown";
    }
}

static const char *utxo_mirror_health_state_name(int state)
{
    switch (state) {
    case UTXO_MIRROR_HEALTHY: return "HEALTHY";
    case UTXO_MIRROR_AUDITING: return "AUDITING";
    case UTXO_MIRROR_QUARANTINED: return "QUARANTINED";
    default: return "UNKNOWN";
    }
}

/* Reentrant-safe: g_utxo_mirror_sync is NULL before service start. Atomic
 * fields are loaded explicitly. tick_seconds is immutable after init and is
 * published before the worker is spawned. */
bool utxo_mirror_sync_dump_state_json(struct json_value *out, const char *key)
{
    (void)key;
    if (!out)
        return false;
    json_set_object(out);

    struct utxo_mirror_sync_service *svc = g_utxo_mirror_sync;
    json_push_kv_bool(out, "instance_present", svc != NULL);
    if (!svc)
        return true;

    json_push_kv_str(out, "state",
                     utxo_mirror_sync_state_name(atomic_load(&svc->state)));
    json_push_kv_str(out, "mirror_health",
                     utxo_mirror_health_state_name(
                         atomic_load(&svc->mirror_health)));
    json_push_kv_bool(out, "thread_started", atomic_load(&svc->thread_started));
    json_push_kv_int(out, "tick_seconds", (int64_t)svc->tick_seconds);
    json_push_kv_int(out, "rebuilds_run", atomic_load(&svc->rebuilds_run));
    json_push_kv_int(out, "delta_passes_run",
                     atomic_load(&svc->delta_passes_run));
    json_push_kv_int(out, "delta_rows_changed",
                     atomic_load(&svc->delta_rows_changed));
    json_push_kv_int(out, "quarantines_total",
                     atomic_load(&svc->quarantines_total));
    json_push_kv_int(out, "rows_written", atomic_load(&svc->rows_written));
    json_push_kv_int(out, "last_mirror_height",
                     atomic_load(&svc->last_mirror_height));
    json_push_kv_int(out, "last_frontier", atomic_load(&svc->last_frontier));
    json_push_kv_int(out, "last_pass_unix", atomic_load(&svc->last_pass_unix));
    json_push_kv_int(out, "last_error_unix",
                     atomic_load(&svc->last_error_unix));
    json_push_kv_int(out, "last_quarantine_unix",
                     atomic_load(&svc->last_quarantine_unix));
    return true;
}
