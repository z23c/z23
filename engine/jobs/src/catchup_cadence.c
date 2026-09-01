/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * catchup_cadence — implementation. See jobs/catchup_cadence.h for the
 * contract and the SAFETY property (inert on a normal at-tip live node).
 */

#include "jobs/catchup_cadence.h"
#include "jobs/tip_finalize_stage.h"  /* tip_finalize_stage_cursor (lock-free) */
#include "net/connman.h"              /* connman_max_peer_height, connman_get_node_count */
#include "services/sync_monitor.h"    /* sync_monitor_connman */
#include "util/log_macros.h"

#include <stdatomic.h>
#include <stdint.h>
#include <stdlib.h>   /* getenv, strtol */

/* Parse an env int, clamped. Returns `def` when unset/empty/unparsable.
 * Mirrors refold_cadence.c's cadence_env_int() (file-static there too — no
 * shared env-clamp helper exists in this codebase; every cadence-style
 * module keeps its own tiny copy, same as ibd_throttle.c/reducer_drain.c/
 * peer_scoring.c/http_middleware.c). */
static int catchup_env_int(const char *name, int def, int lo, int hi)
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

static int catchup_gap_threshold(void)
{
    return catchup_env_int("ZCL_CATCHUP_GAP_THRESHOLD",
                           CATCHUP_CADENCE_DEFAULT_GAP_THRESHOLD,
                           1, 100000000);
}

#ifdef ZCL_TESTING
static _Atomic int64_t g_test_log_head_override = -1;
#endif

/* log_head — the same definition sync_rate_below_floor.c's sr_read_log_head()
 * uses: tip_finalize_stage_cursor() (lock-free), the terminal/durable
 * reducer cursor. -1 = unavailable. */
static int64_t cc_read_log_head(void)
{
#ifdef ZCL_TESTING
    int64_t forced = atomic_load(&g_test_log_head_override);
    if (forced >= 0)
        return forced;
#endif
    uint64_t h = tip_finalize_stage_cursor();
    return (h <= (uint64_t)INT64_MAX) ? (int64_t)h : -1;
}

bool catchup_cadence_active(void)
{
    /* Same lock-safe primitives sync_rate_below_floor.c's detect() uses for
     * this exact gap computation (see that file's header comment for the
     * LOCK-ORDER LAW compliance note) — zero new lock surface added here.
     * Never touches progress_store, coins_kv, or any reducer-drive lock. */
    struct connman *cm = sync_monitor_connman();
    if (!cm || connman_get_node_count(cm) == 0)
        return false;

    int network_tip = connman_max_peer_height(cm);
    if (network_tip <= 0)
        return false;

    int64_t log_head = cc_read_log_head();
    if (log_head < 0)
        return false;  /* unusable cursor sentinel */

    int64_t gap = (int64_t)network_tip - log_head;
    if (gap < 0)
        return false;  /* at or ahead of the best-known peer height */

    return gap >= (int64_t)catchup_gap_threshold();
}

/* One-time INFO so the operator can see the accelerated cadence is armed,
 * without a rebuild. Fires at most once per process the first time an
 * accelerated batch is actually requested — same pattern as
 * refold_cadence.c's cadence_log_once(). */
static void catchup_log_once(int batch, int64_t tick_us)
{
    static _Atomic int logged = 0;
    int expected = 0;
    if (atomic_compare_exchange_strong(&logged, &expected, 1))
        LOG_INFO("catchup_cadence",
                 "[catchup_cadence] accelerated catch-up cadence ARMED: "
                 "drain_batch=%d (ZCL_CATCHUP_DRAIN_BATCH), gap_threshold=%d "
                 "(ZCL_CATCHUP_GAP_THRESHOLD), tick=%lldms "
                 "(ZCL_CATCHUP_TICK_MS, per-child only — global supervisor "
                 "min-tick untouched), full validation unchanged",
                 batch, catchup_gap_threshold(), (long long)(tick_us / 1000));
}

int catchup_cadence_drain_batch(int normal_batch)
{
    if (!catchup_cadence_active())
        return normal_batch;   /* live hot path: unchanged */
    int batch = catchup_env_int("ZCL_CATCHUP_DRAIN_BATCH",
                                CATCHUP_CADENCE_DEFAULT_DRAIN_BATCH,
                                1, 1000000);
    catchup_log_once(batch, catchup_cadence_tick_period_us());
    return batch;
}

int64_t catchup_cadence_tick_period_us(void)
{
    if (!catchup_cadence_active())
        return 0;              /* caller uses its normal period_secs */
    int ms = catchup_env_int("ZCL_CATCHUP_TICK_MS",
                             CATCHUP_CADENCE_DEFAULT_TICK_MS,
                             1000, 2000);
    return (int64_t)ms * 1000;
}

#ifdef ZCL_TESTING
void catchup_cadence_test_set_log_head_override(int64_t v)
{
    atomic_store(&g_test_log_head_override, v);
}

void catchup_cadence_test_reset(void)
{
    atomic_store(&g_test_log_head_override, -1);
}
#endif
