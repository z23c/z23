/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Supervision for the REST /api cache-refresh detached thread — split out
 * of api_controller.c (E1 file-size ceiling: the liveness-tree
 * additions pushed api_controller.c past its 800-line ceiling). See
 * api_controller.c's api_cache_refresh_thread / ensure_cache_thread for the
 * supervised loop and its lifecycle; this file owns only the liveness
 * contract.
 *
 * An unsupervised
 * `while (running) { ...; sleep(10); }` loop is unsafe here: a DB-lock hang inside any
 * compute_* call freezes the REST /api cache forever with no liveness
 * signal anywhere. Self-driven contract (mirrors disk_monitor.c): the
 * thread ticks its own heartbeat once per outer-loop pass (~10s cadence);
 * the independent supervisor sweep fires SUPERVISOR_STALL_TIME_DEADLINE if
 * those ticks ever stop. */

#include "controllers/api_controller.h"
#include "supervisors/domains.h"
#include "util/blocker.h"
#include "util/log_macros.h"
#include "util/supervisor.h"

#include "api_controller_internal.h"

#include <stdatomic.h>
#include <stdint.h>

#define API_CACHE_SUPERVISOR_DEADLINE_SEC 120
static struct liveness_contract    g_api_cache_contract;
static _Atomic supervisor_child_id g_api_cache_sup_id = SUPERVISOR_INVALID_ID;
static _Atomic int64_t             g_api_cache_loop_ticks = 0;

static void api_cache_on_stall(struct liveness_contract *c)
{
    const char *reason = c
        ? supervisor_stall_reason_name(
              (enum supervisor_stall_reason)atomic_load(&c->stall_reason))
        : "unknown";
    LOG_WARN("api", "[api] cache-refresh thread stall reason=%s "
             "loop_ticks=%lld — serving STALE cache indefinitely",
             reason, (long long)atomic_load(&g_api_cache_loop_ticks));
    struct blocker_record rec;
    if (blocker_init(&rec, "api_cache_refresh_stalled", "op.api_cache_refresh",
                     BLOCKER_TRANSIENT,
                     "REST /api cache-refresh thread stopped heartbeating; "
                     "/api/blocks,/stats,/supply,/hodl are serving a stale "
                     "cache indefinitely"))
        (void)blocker_set(&rec);
}

void api_cache_register_supervisor(void)
{
    supervisor_child_id existing = atomic_load(&g_api_cache_sup_id);
    if (existing != SUPERVISOR_INVALID_ID) {
        /* stop() deliberately disarms the deadline. A later worker generation
         * must re-arm and heartbeat the existing child, not merely reuse its
         * id while remaining silently unsupervised. */
        api_cache_supervisor_tick();
        supervisor_set_deadline(existing, API_CACHE_SUPERVISOR_DEADLINE_SEC);
        return;
    }
    if (!supervisor_start()) {
        LOG_WARN("api", "[api] cache-refresh: supervisor_start failed");
        return;
    }
    liveness_contract_init(&g_api_cache_contract, "op.api_cache_refresh");
    atomic_store(&g_api_cache_contract.period_secs, (int64_t)0);
    atomic_store(&g_api_cache_contract.deadline_secs,
                (int64_t)API_CACHE_SUPERVISOR_DEADLINE_SEC);
    g_api_cache_contract.on_stall = api_cache_on_stall;
    supervisor_domains_init();
    supervisor_child_id id =
        supervisor_register_in_domain(g_op_sup, &g_api_cache_contract);
    if (id == SUPERVISOR_INVALID_ID) {
        LOG_WARN("api", "[api] cache-refresh: supervisor register failed");
        return;
    }
    atomic_store(&g_api_cache_sup_id, id);
    api_cache_supervisor_tick();
}

/* Called once per api_cache_refresh_thread outer-loop pass. */
void api_cache_supervisor_tick(void)
{
    atomic_fetch_add(&g_api_cache_loop_ticks, 1);
    supervisor_child_id id = atomic_load(&g_api_cache_sup_id);
    if (id == SUPERVISOR_INVALID_ID)
        return;
    supervisor_tick(id);
    supervisor_progress(id, atomic_load(&g_api_cache_loop_ticks));
}

/* Suppress a false stall while the detached thread winds down (it is not
 * joined — mirrors disk_monitor_stop's shutdown-quiesce). */
void api_cache_supervisor_quiesce(void)
{
    supervisor_child_id id = atomic_load(&g_api_cache_sup_id);
    if (id != SUPERVISOR_INVALID_ID)
        supervisor_set_deadline(id, 0);
}

#ifdef ZCL_TESTING
/* #13 test seams — registers the liveness contract WITHOUT spawning the
 * real detached thread (which sleeps 5s and drives compute_* against
 * whatever main_state is/isn't set), so the wiring can be exercised
 * hermetically and fast. */
void api_cache_test_register_supervisor(void)
{
    api_cache_register_supervisor();
}

supervisor_child_id api_cache_test_supervisor_id(void)
{
    return atomic_load(&g_api_cache_sup_id);
}

int64_t api_cache_test_loop_ticks(void)
{
    return atomic_load(&g_api_cache_loop_ticks);
}

void api_cache_test_force_stall(void)
{
    api_cache_on_stall(&g_api_cache_contract);
}
#endif
