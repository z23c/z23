/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * refold_cadence — implementation. See jobs/refold_cadence.h for the contract
 * and the SAFETY property (inert on a normal live node).
 */

#include "jobs/refold_cadence.h"
#include "jobs/refold_progress.h"     /* refold_in_progress */
#include "jobs/mint_fold_ceiling.h"   /* mint_fold_ceiling_get, MINT_FOLD_NO_CEILING */
#include "util/log_macros.h"

#include <stdatomic.h>
#include <stdlib.h>   /* getenv, strtol */

/* Parse an env int, clamped. Returns `def` when unset/empty/unparsable. */
static int cadence_env_int(const char *name, int def, int lo, int hi)
{
    const char *v = getenv(name);
    if (!v || !v[0])
        return def;
    char *end = NULL;
    long n = strtol(v, &end, 10);
    if (end == v)          /* no digits parsed */
        return def;
    if (n < lo) n = lo;
    if (n > hi) n = hi;
    return (int)n;
}

bool refold_cadence_active(void)
{
    return refold_in_progress() ||
           mint_fold_ceiling_get() != MINT_FOLD_NO_CEILING;
}

/* One-time INFO so the operator can see the accelerated cadence is armed and at
 * what values, without a rebuild. Fires at most once per process the first time
 * an accelerated batch is actually requested. */
static void cadence_log_once(int batch, int64_t tick_us)
{
    static _Atomic int logged = 0;
    int expected = 0;
    if (atomic_compare_exchange_strong(&logged, &expected, 1))
        LOG_INFO("refold_cadence",
                 "[refold_cadence] accelerated fold cadence ARMED: "
                 "drain_batch=%d (ZCL_REFOLD_DRAIN_BATCH), tick=%lldms "
                 "(ZCL_REFOLD_TICK_MS) — full validation unchanged",
                 batch, (long long)(tick_us / 1000));
}

int refold_cadence_drain_batch(int normal_batch)
{
    if (!refold_cadence_active())
        return normal_batch;   /* live hot path: unchanged */
    int batch = cadence_env_int("ZCL_REFOLD_DRAIN_BATCH",
                                REFOLD_CADENCE_DEFAULT_DRAIN_BATCH,
                                1, 1000000);
    cadence_log_once(batch, refold_cadence_tick_period_us());
    return batch;
}

int64_t refold_cadence_tick_period_us(void)
{
    if (!refold_cadence_active())
        return 0;              /* caller uses its normal period_secs */
    int ms = cadence_env_int("ZCL_REFOLD_TICK_MS",
                             REFOLD_CADENCE_DEFAULT_TICK_MS,
                             1, 60000);
    return (int64_t)ms * 1000;
}
