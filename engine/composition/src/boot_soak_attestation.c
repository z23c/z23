/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Boot wiring for the soak attestation service. Kept in its own TU so the
 * composition-root mega-files (boot_services.c) gain only one call.
 *
 * Activation: unconditionally ON when the node starts. The service writes
 * one JSON line to <datadir>/soak_attestation.jsonl every 60 s. No operator
 * opt-out is needed — the file is a persistent evidence log for MVP criterion
 * 7 (7-day soak), and writing 60-byte lines at 1 Hz is negligible overhead.
 *
 * The service is READ-ONLY with respect to chain state: it calls
 * node_health_collect() (which reads consensus state through the established
 * csr->lock THEN coins_kv order) and then writes to a plain file. It never
 * touches the reducer drive, sqlite, or consensus tables. */

#include "config/boot_internal.h"
#include "services/soak_attestation_service.h"
#include "jobs/soak_attestation_poll.h"
#include "util/log_macros.h"

#include <stdio.h>

static bool boot_soak_attestation_start(void *ctx)
{
    struct boot_svc_ctx *svc = ctx;
    if (!svc || !svc->datadir || !svc->datadir[0])
        return false;

    soak_attestation_init(svc->datadir);
    soak_attestation_poll_register();

    if (soak_attestation_poll_is_registered()) {
        printf("[soak-attest] active: writing to %s/soak_attestation.jsonl "
               "(60s cadence, 50 MB rotation)\n",
               svc->datadir);
    } else {
        /* Non-fatal: node runs fine without attestation; log the miss. */
        LOG_WARN("soak_attest",
                 "[soak-attest] WARN: supervisor registration failed — "
                 "attestation log will NOT be written");
    }
    return true; /* always non-fatal */
}

static void boot_soak_attestation_stop(void *ctx)
{
    (void)ctx;
    /* No-op: supervisor unregister happens at supervisor_stop(); the file
     * descriptor in g_soak is closed by soak_attestation_reset_for_test()
     * only (tests), or leaked on process exit (acceptable — kernel closes it). */
}

bool boot_soak_attestation_register(struct boot_svc_ctx *svc)
{
    if (!svc)
        return false;
    const struct zcl_service_spec spec = {
        .name  = "soak_attestation",
        .start = boot_soak_attestation_start,
        .stop  = boot_soak_attestation_stop,
        .ctx   = svc,
        .flags = ZCL_SERVICE_OPTIONAL,
    };
    return zcl_service_kernel_register(&svc->runtime_kernel, &spec);
}
