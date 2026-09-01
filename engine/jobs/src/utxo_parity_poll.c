/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * utxo_parity_poll Job — see jobs/utxo_parity_poll.h. */

#include "jobs/utxo_parity_poll.h"
#include "util/log_macros.h"

#include "services/utxo_parity_service.h"
#include "supervisors/domains.h"
#include "util/supervisor.h"

#include <stdatomic.h>
#include <stdint.h>

/* Cadence: 60 s bounds the per-check full-set SHA3 cost (~1.3M rows). */
#define UTXO_PARITY_POLL_PERIOD_SECS  ((int64_t)60)

static struct liveness_contract        g_contract;
static _Atomic supervisor_child_id     g_id = SUPERVISOR_INVALID_ID;
/* Monotonic per-tick counter so the supervisor's progress-quiet detector
 * sees movement even when the service is dormant (the underlying check may
 * legitimately do nothing for long stretches when the frontier is frozen). */
static _Atomic int64_t                 g_tick_counter = 0;

static void utxo_parity_poll_tick(struct liveness_contract *c)
{
    (void)c;
    /* All gating (enabled + reference + env gate + stable frontier target)
     * lives in the service; this Job is a pure scheduling shim. */
    utxo_parity_tick_once();

    int64_t marker = atomic_fetch_add(&g_tick_counter, 1) + 1;
    supervisor_progress(atomic_load(&g_id), marker);
    supervisor_tick(atomic_load(&g_id));
}

void utxo_parity_poll_register(void)
{
    if (atomic_load(&g_id) != SUPERVISOR_INVALID_ID) return; /* idempotent */

    liveness_contract_init(&g_contract, "chain.utxo_parity_poll");
    atomic_store(&g_contract.period_secs, UTXO_PARITY_POLL_PERIOD_SECS);
    /* No deadline / progress-quiet stall: a frozen frontier (tip not
     * advancing) is a legitimate no-op, not a Job stall. */
    atomic_store(&g_contract.deadline_secs, (int64_t)0);
    atomic_store(&g_contract.progress_max_quiet_us, (int64_t)0);
    g_contract.on_tick  = utxo_parity_poll_tick;
    g_contract.on_stall = NULL;

    supervisor_domains_init();
    supervisor_child_id id =
        supervisor_register_in_domain(g_chain_sup, &g_contract);
    atomic_store(&g_id, id);
    if (id == SUPERVISOR_INVALID_ID) {
        LOG_WARN("utxo_parity_poll", "[utxo_parity_poll] WARN register failed");
    }
}

bool utxo_parity_poll_is_registered(void)
{
    return atomic_load(&g_id) != SUPERVISOR_INVALID_ID;
}
