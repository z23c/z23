/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Boot wiring for the memory-pressure organ (Rung 1 follow-on,
 * docs/adr/0003-os-substrate-verdict.md). Kept in its own TU so
 * boot_services.c gains only a single registration call (the
 * boot_canary_watch.c pattern) — mem_pressure needs no node_db/main_state,
 * only the health periodic ring, so start/stop just forward to
 * mem_pressure_start()/stop(). */

#include "config/boot_internal.h"

#include "util/mem_pressure.h"

#include <stdio.h>

static bool boot_mem_pressure_start(void *ctx)
{
    (void)ctx;
    if (!mem_pressure_start())
        return false; // raw-return-ok:mem-pressure-start-already-logged

    printf("[mem-pressure] armed: %ds health-ring poll\n",
           MEM_PRESSURE_POLL_SECS);
    return true;
}

static void boot_mem_pressure_stop(void *ctx)
{
    (void)ctx;
    mem_pressure_stop();
}

bool boot_mem_pressure_register(struct boot_svc_ctx *svc)
{
    if (!svc)
        return false;
    const struct zcl_service_spec spec = {
        .name = "mem_pressure",
        .start = boot_mem_pressure_start,
        .stop = boot_mem_pressure_stop,
        .ctx = svc,
        .flags = ZCL_SERVICE_OPTIONAL,
    };
    return zcl_service_kernel_register(&svc->runtime_kernel, &spec);
}
