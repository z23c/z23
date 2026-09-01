/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Boot wiring for the independent supervisor-sweep-heartbeat watcher
 * (Pillar 7 — "supervise the supervisor"; see
 * util/supervisor_backstop.h for the design notes). Kept in its own TU,
 * same pattern as boot_mem_pressure.c: boot_services.c gains only a
 * single registration call, and start/stop just forward to the
 * platform/modules/util module's own thread lifecycle (no node_db/main_state needed
 * — the watcher only reads supervisor_sweep_heartbeat()). */

#include "config/boot_internal.h"
#include "util/supervisor_backstop.h"

static bool boot_supervisor_backstop_start(void *ctx)
{
    (void)ctx;
    /* Built-in defaults: 5 s poll cadence, 30 s freeze threshold — see
     * SUPERVISOR_BACKSTOP_DEFAULT_POLL_US / _FREEZE_US in
     * util/supervisor_backstop.h. */
    return supervisor_backstop_start(0, 0);
}

static void boot_supervisor_backstop_stop(void *ctx)
{
    (void)ctx;
    supervisor_backstop_stop();
}

bool boot_supervisor_backstop_register(struct boot_svc_ctx *svc)
{
    if (!svc)
        return false;
    const struct zcl_service_spec spec = {
        .name = "supervisor_backstop",
        .start = boot_supervisor_backstop_start,
        .stop = boot_supervisor_backstop_stop,
        .ctx = svc,
        .flags = ZCL_SERVICE_OPTIONAL,
    };
    return zcl_service_kernel_register(&svc->runtime_kernel, &spec);
}
