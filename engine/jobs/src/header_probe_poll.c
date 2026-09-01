/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * header_probe_poll Job — see jobs/header_probe_poll.h. */

#include "jobs/header_probe_poll.h"
#include "util/log_macros.h"

#include "services/header_probe.h"
#include "supervisors/domains.h"
#include "util/supervisor.h"

#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>

/* Cadence: 30 s preserves the heartbeat-driven path's poll period. */
#define HEADER_PROBE_POLL_PERIOD_SECS  ((int64_t)30)

static struct liveness_contract        g_contract;
static _Atomic supervisor_child_id     g_id = SUPERVISOR_INVALID_ID;
/* Per-tick monotonic counter so the supervisor's progress-quiet
 * detector observes movement on every tick (the underlying poll
 * may legitimately do nothing for hours when our header tip is
 * already at the remote tip). Bumping a counter here keeps the
 * progress_marker advancing without polluting it with stale
 * height data. */
static _Atomic int64_t                 g_tick_counter = 0;

static void header_probe_poll_tick(struct liveness_contract *c)
{
    (void)c;
    /* The service decides what to do based on its own gating
     * (initialized + main_state + lag threshold). This Job is a
     * pure scheduling shim. */
    header_probe_tick_once();

    int64_t marker = atomic_fetch_add(&g_tick_counter, 1) + 1;
    supervisor_progress(atomic_load(&g_id), marker);
    supervisor_tick(atomic_load(&g_id));
}

void header_probe_poll_register(void)
{
    if (atomic_load(&g_id) != SUPERVISOR_INVALID_ID) return; /* idempotent */

    liveness_contract_init(&g_contract, "net.header_probe_poll");
    atomic_store(&g_contract.period_secs, HEADER_PROBE_POLL_PERIOD_SECS);
    /* No deadline_secs — period_secs drives on_tick; progress-quiet is
     * also disabled because the underlying RPC can legitimately be
     * unreachable for long stretches without it being a Job stall. */
    atomic_store(&g_contract.deadline_secs, (int64_t)0);
    atomic_store(&g_contract.progress_max_quiet_us, (int64_t)0);
    g_contract.on_tick  = header_probe_poll_tick;
    g_contract.on_stall = NULL;

    supervisor_domains_init();
    supervisor_child_id id =
        supervisor_register_in_domain(g_net_sup, &g_contract);
    atomic_store(&g_id, id);
    if (id == SUPERVISOR_INVALID_ID) {
        LOG_WARN("header_probe_poll", "[header_probe_poll] WARN register failed");
    }
}

bool header_probe_poll_is_registered(void)
{
    return atomic_load(&g_id) != SUPERVISOR_INVALID_ID;
}
