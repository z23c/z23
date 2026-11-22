/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * boot_sv_lookahead — wiring for the cross-height transparent-script
 * pre-verification pool (engine/jobs/src/sv_lookahead.c), the script_validate
 * counterpart of boot_pv_lookahead. One boot call starts both pools, because
 * boot_services.c sits at its line ceiling.
 *
 * DEFAULT OFF: the script pool starts only under -sv-lookahead. It lands dark
 * and is enabled after a replay comparison against the inline sweep.
 *
 * FAIL-SAFE in both directions: a failed start is logged and ignored, and a
 * cache miss verifies inline exactly as today. The pool can cost throughput. It
 * cannot change a verdict: sv_lookahead_take consumes only on an exact (height,
 * block hash, flags, branch id, resolver pair) match, and a sweep with any
 * unresolved prevout is never cached.
 *
 * ORDERING: boot_services.c calls this after staged_sync_supervisor_register
 * ran script_validate_stage_init. script_validate_lookahead_start snapshots the
 * stage's tuple under the stage lock, and an unbound stage fails the start. */

#include "config/boot_internal.h"

#include "jobs/script_validate_stage.h"   /* script_validate_lookahead_start/stop */
#include "util/log_macros.h"

#include <stddef.h>

/* Whether this process started the script pool, so stop stays a no-op
 * otherwise. script_validate_stage_shutdown also stops it; both are idempotent. */
static bool g_svla_started = false;

void boot_lookahead_pools_start(const struct app_context *ctx,
                                struct main_state *ms)
{
    boot_pv_lookahead_start(ctx, ms);   /* proofs: default on, -pv-lookahead=0 */
    if (!ctx || !ctx->sv_lookahead)
        return;   /* scripts: default off, script_validate verifies inline */
    g_svla_started = ms && script_validate_lookahead_start();
    if (g_svla_started)
        LOG_INFO("sv_lookahead",
                 "[sv_lookahead] cross-height script pre-verification pool "
                 "started (-sv-lookahead)");
    else
        LOG_WARN("sv_lookahead",
                 "[sv_lookahead] -sv-lookahead set but the pool did not start; "
                 "script_validate verifies inline (fail-safe)");
}

void boot_sv_lookahead_stop(void)
{
    if (!g_svla_started)
        return;
    script_validate_lookahead_stop();
    g_svla_started = false;
}
