/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Boot wiring for the replay-canary sentinel watch. Kept in its own TU so
 * boot_services.c gains only a single registration call (the
 * boot_utxo_parity.c pattern).
 *
 * Activation default — always-on, always-quiet: the watch is a 60 s
 * supervised dir scan over the canary verdict dir ($ZCL_CANARY_VERDICT_DIR,
 * default $HOME/.local/state/zclassic23-canary). A box that never ran the
 * replay canary has no dir and the tick is a silent no-op — no log spam, no
 * health degradation. When a sentinel reports verdict==FAIL the
 * replay_canary_failed Condition (registered via condition_registry) pages.
 *
 * The watch is a READ-ONLY OBSERVER by construction: file-scan only — no DB
 * writes, no chain locks, no threads beyond the supervised poll Job. */

#include "config/boot_internal.h"

#include "services/canary_sentinel_watch.h"
#include "jobs/canary_sentinel_poll.h"

#include <limits.h>
#include <stdio.h>

static bool boot_canary_watch_start(void *ctx)
{
    struct boot_svc_ctx *svc = ctx;
    if (!svc)
        return false;

    canary_sentinel_poll_register();

    char dir[PATH_MAX];
    if (!canary_sentinel_watch_resolve_dir(dir, sizeof(dir)))
        dir[0] = '\0';
    if (canary_sentinel_poll_is_registered())
        printf("[canary-watch] armed: 60s supervised sentinel scan (dir=%s)\n",
               dir[0] ? dir : "unresolved");
    else
        printf("[canary-watch] dormant (supervisor registration missed)\n");
    return true; /* non-fatal: introspection still works either way */
}

static void boot_canary_watch_stop(void *ctx)
{
    (void)ctx;
    /* No-op: supervisor unregister happens at supervisor_stop(); the watch
     * holds no resources between ticks. */
}

bool boot_canary_watch_register(struct boot_svc_ctx *svc)
{
    if (!svc)
        return false;
    const struct zcl_service_spec spec = {
        .name = "canary_watch",
        .start = boot_canary_watch_start,
        .stop = boot_canary_watch_stop,
        .ctx = svc,
        .flags = ZCL_SERVICE_OPTIONAL,
    };
    return zcl_service_kernel_register(&svc->runtime_kernel, &spec);
}
