/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * catchup_cadence — implementation. See jobs/catchup_cadence.h for the
 * contract and the SAFETY property (inert on a normal at-tip live node).
 */

#include "jobs/catchup_cadence.h"
#include "platform/time_compat.h"
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

static int catchup_defer_gap_threshold(void)
{
    return catchup_env_int("ZCL_CATCHUP_DEFER_GAP_THRESHOLD",
                           CATCHUP_CADENCE_DEFER_SYNC_DEFAULT_GAP_THRESHOLD,
                           1, 100000000);
}

#ifdef ZCL_TESTING
static _Atomic int64_t g_test_log_head_override = -1;
#endif

/* Cached verdict of the last catchup_cadence_active() evaluation — see the
 * store site for who consumes it and why it is lock-free. */
static _Atomic bool g_active_cache = false;

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

/* Peers-connected + gap measurement shared by both gates below, so the
 * deferred-sync gate can never disagree with the cadence gate about the
 * measurement — only about the threshold. Same lock-safe primitives
 * sync_rate_below_floor.c's detect() uses for this exact gap computation
 * (see that file's header comment for the LOCK-ORDER LAW compliance note)
 * — zero new lock surface added here. Never touches progress_store,
 * coins_kv, or any reducer-drive lock. Writes the gap (or -1 when either
 * side is unavailable) through when the caller wants it. */
static bool catchup_gap_eval(int64_t *gap_out)
{
    struct connman *cm = sync_monitor_connman();
    if (!cm || connman_get_node_count(cm) == 0)
        return false;
    int network_tip = connman_max_peer_height(cm);
    int64_t log_head = cc_read_log_head();
    if (gap_out)
        *gap_out = (network_tip > 0 && log_head >= 0)
                       ? (int64_t)network_tip - log_head
                       : -1;
    return true;
}

bool catchup_cadence_active(void)
{
    int64_t gap = -1;
    bool active = catchup_gap_eval(&gap) &&
                  gap >= (int64_t)catchup_gap_threshold();
    /* Publish the verdict for the ONE caller that may not evaluate this gate
     * itself: the batched pre-commit durability hook
     * (engine/reducer/services/src/reducer_body_fsync.c) fires under
     * progress_store_tx_lock, where evaluating the gate would newly nest the
     * connman read under the reducer-drive lock. The hook instead reads the
     * CACHED verdict (catchup_cadence_active_cached) — a plain atomic load,
     * zero lock surface. Every existing caller of this function (supervisor
     * tick, kick/drain entry) already re-evaluates at least once per catch-up
     * scope, so the cache can never be stale by more than one scope; a closed
     * gate restores the strict per-commit flush on the very next commit, and
     * the fail-safe default (never evaluated -> false) is the strict regime. */
    atomic_store_explicit(&g_active_cache, active, memory_order_release);
    return active;
}

bool catchup_cadence_deferred_sync_active(void)
{
    /* Deliberately does NOT publish g_active_cache: the R1 precommit flush
     * cadence in reducer_body_fsync.c must stay keyed to the genuine
     * accelerated-catch-up verdict, so a short-chain sync inside this gate
     * keeps the strict flush-on-every-commit regime (batched per commit,
     * never demoted to the 1-per-8-commits interval). */
    int64_t gap = -1;
    return catchup_gap_eval(&gap) &&
           gap >= (int64_t)catchup_defer_gap_threshold();
}

/* See the store site above: the lock-free cached verdict, refreshed by every
 * catchup_cadence_active() call. Default false = strict per-commit regime. */
bool catchup_cadence_active_cached(void)
{
    return atomic_load_explicit(&g_active_cache, memory_order_acquire);
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

struct catchup_drain_budget catchup_drain_budget_begin(void)
{
    struct catchup_drain_budget budget = {0};
    const char *value = getenv("ZCL_CATCHUP_DRAIN_BUDGET_MS");
    if (!catchup_cadence_active_cached() || !value || !value[0]) return budget;
    char *end = NULL;
    long ms = strtol(value, &end, 10);
    if (!end || *end || ms < 1 || ms > 60000) return budget;
    budget.limit_us = (int64_t)ms * 1000;
    budget.start_us = platform_time_monotonic_us();
    return budget;
}

bool catchup_drain_budget_due(const struct catchup_drain_budget *budget)
{
    if (!budget || !budget->limit_us) return false;
    int64_t now = platform_time_monotonic_us();
    return budget->start_us <= 0 || now <= 0 || now < budget->start_us ||
           now - budget->start_us >= budget->limit_us;
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
    /* Also drop the cached gate verdict: a test that drove the gate open via
     * this override must not leak a stale "catch-up active" into the next
     * group's precommit-flush cadence (engine/reducer/services/src/
     * reducer_body_fsync.c reads the cache on every stage-batch COMMIT). */
    atomic_store_explicit(&g_active_cache, false, memory_order_release);
}
#endif
