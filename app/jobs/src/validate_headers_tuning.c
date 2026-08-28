/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * validate_headers_tuning — runtime pool-width / forward-batch sizing for the
 * validate_headers reducer stage. Sibling-private (validate_headers_internal.h)
 * except validate_headers_stage_catchup_step_cap(), which the staged-sync
 * supervisor's fan-out containment (A12) calls through the public stage header.
 *
 * Equihash PoW verification is the per-header cost of the stage and it is a
 * PURE function of the header (nonce, solution, nBits) — no coins/UTXO/anchor
 * state. A WIDER pool and a LARGER forward batch therefore verify more heights
 * concurrently with byte-identical per-height verdicts: every
 * validate_headers_log row is still written from its own independent validator
 * result, and the width only changes how many run at once, never WHAT is
 * checked nor WHICH row is written. Cursor semantics, the failure-recheck
 * floor, and the authoritative mark are untouched.
 *
 * SAFETY — two strictly gated overrides, refold winning over catch-up (the
 * same precedence stage_effective_batch() gives their drain batches):
 *   1. fold:    ONLY while refold_cadence_active() (a `-mint-anchor` fold
 *               ceiling is set, or a `-refold-*` fold is in progress).
 *   2. catch-up: ONLY while catchup_cadence_active() (peers connected AND the
 *               tip gap is at least ZCL_CATCHUP_GAP_THRESHOLD) — pool width
 *               only; the per-step forward batch stays VH_BATCH_SIZE.
 * On a NORMAL live node (no fold, at/near tip or no peers) both accessors
 * return the compile-time VH_POOL_SIZE / VH_BATCH_SIZE regardless of the
 * environment, so the live hot path is byte-for-byte unchanged and no
 * environment variable can widen it. Pinned by test_validate_headers_tuning.
 *
 * TUNABLE (only while the matching gate is active):
 *   ZCL_VH_POOL               Equihash worker threads  default 16  clamp [1,128]   (fold)
 *   ZCL_VH_BATCH              heights per forward step default 256 clamp [1,4096]  (fold)
 *   ZCL_VH_CATCHUP_POOL_SIZE  Equihash worker threads  default min(nproc,16)
 *                             clamp [1,128]                                      (catch-up)
 */

#include "validate_headers_internal.h"

#include "jobs/catchup_cadence.h"
#include "jobs/refold_cadence.h"
#include "jobs/validate_headers_stage.h"
#include "platform/logical_cpu.h"

#include <stdlib.h>

static int vh_env_clamped(const char *name, int def, int lo, int hi)
{
    const char *v = getenv(name);
    if (!v || !v[0])
        return def;
    char *end = NULL;
    long n = strtol(v, &end, 10);
    if (end == v)
        return def;
    if (n < lo) n = lo;
    if (n > hi) n = hi;
    return (int)n;
}

/* Catch-up pool default: min(online processors, VH_CATCHUP_POOL_CAP). */
static int vh_catchup_pool_default(void)
{
    uint32_t n = platform_logical_cpu_count();
    if (n > VH_CATCHUP_POOL_CAP) n = VH_CATCHUP_POOL_CAP;
    return (int)n;
}

int vh_runtime_pool_size(void)
{
    if (refold_cadence_active())
        return vh_env_clamped("ZCL_VH_POOL", VH_FOLD_POOL_DEFAULT, 1,
                              VH_MAX_POOL);
    if (catchup_cadence_active())
        return vh_env_clamped("ZCL_VH_CATCHUP_POOL_SIZE",
                              vh_catchup_pool_default(), 1, VH_MAX_POOL);
    return VH_POOL_SIZE;
}

int vh_runtime_batch_size(void)
{
    /* Catch-up widens concurrency + steps-per-tick only; the per-step
     * forward batch stays VH_BATCH_SIZE so the per-step commit shape is
     * unchanged. */
    if (!refold_cadence_active())
        return VH_BATCH_SIZE;
    return vh_env_clamped("ZCL_VH_BATCH", VH_FOLD_BATCH_DEFAULT, 1,
                          VH_MAX_BATCH);
}

int validate_headers_stage_catchup_step_cap(int normal_steps)
{
    if (!catchup_cadence_active())
        return normal_steps;   /* live hot path: unchanged */
    int scale = vh_runtime_pool_size() / VH_POOL_SIZE;
    if (scale < 1) scale = 1;
    if (scale > VH_CATCHUP_STEP_MULT) scale = VH_CATCHUP_STEP_MULT;
    return normal_steps * scale;
}
