/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * rss_trim — see util/rss_trim.h. */

#include "util/rss_trim.h"

#include "platform/allocator_compat.h"
#include "platform/os_proc.h"
#include "platform/time_compat.h"
#include "util/log_macros.h"

#include <inttypes.h>

void rss_trim_policy_init(struct rss_trim_policy *p, int64_t interval_us)
{
    if (!p) return;
    p->interval_us = interval_us > 0 ? interval_us : RSS_TRIM_INTERVAL_US;
    atomic_store(&p->last_trim_us, 0);
    atomic_store(&p->have_trim, false);
    atomic_store(&p->cache_released, false);
}

/* True once per sync -> steady transition. Entering sync re-arms the latch. */
bool rss_trim_cache_due(struct rss_trim_policy *p, bool in_sync)
{
    if (!p) return false;
    if (in_sync) {
        atomic_store(&p->cache_released, false);
        return false;
    }
    return !atomic_load(&p->cache_released);
}

/* True at most once per interval, never during initial sync. Concurrent
 * callers race on a CAS so exactly one wins an interval. */
bool rss_trim_heap_due(struct rss_trim_policy *p, int64_t now_us,
                       bool in_sync)
{
    if (!p || in_sync) return false;
    if (!atomic_load(&p->have_trim)) {
        bool expect = false;
        if (!atomic_compare_exchange_strong(&p->have_trim, &expect, true))
            return false;
        atomic_store(&p->last_trim_us, now_us);
        return true;
    }
    int64_t last = atomic_load(&p->last_trim_us);
    if (now_us - last < p->interval_us) return false;
    return atomic_compare_exchange_strong(&p->last_trim_us, &last, now_us);
}

static void rss_trim_do_cache(struct rss_trim_policy *p,
                              const struct rss_trim_ops *ops)
{
    int64_t bytes = 0;
    enum rss_trim_release r = ops->release_cache(ops->ctx, &bytes);
    if (r == RSS_TRIM_RELEASE_RETRY) return;
    atomic_store(&p->cache_released, true);
    if (r == RSS_TRIM_RELEASE_DONE)
        LOG_INFO("rss_trim",
                 "projection page cache released bytes=%" PRId64, bytes);
}

static void rss_trim_do_heap(const struct rss_trim_ops *ops)
{
    int64_t before = ops->resident_kib ? ops->resident_kib() : -1;
    ops->trim_heap();
    int64_t after = ops->resident_kib ? ops->resident_kib() : -1;
    LOG_INFO("rss_trim",
             "heap trim resident_kib before=%" PRId64 " after=%" PRId64,
             before, after);
}

void rss_trim_tick(struct rss_trim_policy *p, const struct rss_trim_ops *ops)
{
    if (!p || !ops || !ops->now_us || !ops->in_initial_sync ||
        !ops->trim_heap)
        return;
    bool in_sync = ops->in_initial_sync(ops->ctx);
    if (ops->release_cache && rss_trim_cache_due(p, in_sync))
        rss_trim_do_cache(p, ops);
    if (rss_trim_heap_due(p, ops->now_us(), in_sync))
        rss_trim_do_heap(ops);
}

static int64_t rss_trim_prod_resident(void)
{
    return os_proc_resident_kib();
}

static void rss_trim_prod_heap(void)
{
    platform_allocator_release_free_pages();
}

void rss_trim_production_ops(struct rss_trim_ops *out, void *ctx,
                             bool (*in_initial_sync)(void *ctx),
                             enum rss_trim_release
                                 (*release_cache)(void *ctx, int64_t *bytes))
{
    if (!out) return;
    out->now_us = platform_time_monotonic_us;
    out->in_initial_sync = in_initial_sync;
    out->release_cache = release_cache;
    out->trim_heap = rss_trim_prod_heap;
    out->resident_kib = rss_trim_prod_resident;
    out->ctx = ctx;
}
