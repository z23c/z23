/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * canary_sentinel_poll Job — see jobs/canary_sentinel_poll.h. */

#include "jobs/canary_sentinel_poll.h"
#include "util/log_macros.h"

#include "services/canary_sentinel_watch.h"
#include "supervisors/domains.h"
#include "util/supervisor.h"

#include <stdatomic.h>
#include <stdint.h>

/* Cadence: 60 s — a dir scan over at most a handful of ~400-byte sentinel
 * files; the canary itself runs nightly, so this is generously fresh. */
#define CANARY_SENTINEL_POLL_PERIOD_SECS  ((int64_t)60)

static struct liveness_contract        g_contract;
static _Atomic supervisor_child_id     g_id = SUPERVISOR_INVALID_ID;
/* Monotonic per-tick marker so `z23 dumpstate supervisor` shows the
 * job ticking even on a box that never ran the canary (perpetual no-op).
 * Progress-quiet stall detection is deliberately disabled for this job
 * (progress_max_quiet_us=0 below), so the marker is introspection-only. */
static _Atomic int64_t                 g_tick_counter = 0;

static void canary_sentinel_poll_tick(struct liveness_contract *c)
{
    (void)c;
    /* All scanning/latching lives in the service; pure scheduling shim. */
    canary_sentinel_watch_tick_once();

    int64_t marker = atomic_fetch_add(&g_tick_counter, 1) + 1;
    supervisor_progress(atomic_load(&g_id), marker);
    supervisor_tick(atomic_load(&g_id));
}

void canary_sentinel_poll_register(void)
{
    if (atomic_load(&g_id) != SUPERVISOR_INVALID_ID) return; /* idempotent */

    liveness_contract_init(&g_contract, "ops.canary_sentinel_poll");
    atomic_store(&g_contract.period_secs, CANARY_SENTINEL_POLL_PERIOD_SECS);
    /* No deadline / progress-quiet stall: an absent verdict dir is a
     * legitimate perpetual no-op, not a Job stall. */
    atomic_store(&g_contract.deadline_secs, (int64_t)0);
    atomic_store(&g_contract.progress_max_quiet_us, (int64_t)0);
    g_contract.on_tick  = canary_sentinel_poll_tick;
    g_contract.on_stall = NULL;

    supervisor_domains_init();
    supervisor_child_id id =
        supervisor_register_in_domain(g_op_sup, &g_contract);
    atomic_store(&g_id, id);
    if (id == SUPERVISOR_INVALID_ID) {
        LOG_WARN("canary_sentinel_poll",
                 "[canary_sentinel_poll] WARN register failed");
    }
}

bool canary_sentinel_poll_is_registered(void)
{
    return atomic_load(&g_id) != SUPERVISOR_INVALID_ID;
}
