/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * soak_attestation_poll Job — supervised 60 s cadence for the soak
 * attestation service. Registered in the `op` supervisor domain.
 * The service owns all gating; this Job is a pure scheduling shim. */

#include "jobs/soak_attestation_poll.h"
#include "services/soak_attestation_service.h"
#include "supervisors/domains.h"
#include "util/supervisor.h"
#include "util/log_macros.h"

#include <stdatomic.h>
#include <stdint.h>

/* Cadence: 60 s matches the MVP evidence-density target (1 sample/min). */
#define SOAK_ATTESTATION_POLL_PERIOD_SECS  ((int64_t)60)

static struct liveness_contract    g_contract;
static _Atomic supervisor_child_id g_id = SUPERVISOR_INVALID_ID;
/* Monotonic per-tick counter so the supervisor's progress-quiet detector
 * sees movement even when the service is dormant (no-op with disabled init). */
static _Atomic int64_t             g_tick_counter = 0;

static void soak_attestation_poll_tick(struct liveness_contract *c)
{
    (void)c;
    /* All gating (initialized + fd open) lives in the service. */
    soak_attestation_tick();

    int64_t marker = atomic_fetch_add(&g_tick_counter, 1) + 1;
    supervisor_progress(atomic_load(&g_id), marker);
    supervisor_tick(atomic_load(&g_id));
}

void soak_attestation_poll_register(void)
{
    if (atomic_load(&g_id) != SUPERVISOR_INVALID_ID)
        return; /* idempotent */

    liveness_contract_init(&g_contract, "op.soak_attestation_poll");
    atomic_store(&g_contract.period_secs,
                 SOAK_ATTESTATION_POLL_PERIOD_SECS);
    /* No deadline / progress-quiet stall: a skipped write (e.g. fd not open)
     * is a logged best-effort failure, not a supervisor stall. */
    atomic_store(&g_contract.deadline_secs,          (int64_t)0);
    atomic_store(&g_contract.progress_max_quiet_us,  (int64_t)0);
    g_contract.on_tick  = soak_attestation_poll_tick;
    g_contract.on_stall = NULL;

    supervisor_domains_init();
    supervisor_child_id id =
        supervisor_register_in_domain(g_op_sup, &g_contract);
    atomic_store(&g_id, id);
    if (id == SUPERVISOR_INVALID_ID) {
        LOG_WARN("soak_attest_poll",
                 "[soak_attest_poll] WARN supervisor register failed");
    }
}

bool soak_attestation_poll_is_registered(void)
{
    return atomic_load(&g_id) != SUPERVISOR_INVALID_ID;
}
