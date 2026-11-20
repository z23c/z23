/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * rss_trim — see util/rss_trim.h. */

#include "util/rss_trim.h"

#include "platform/allocator_compat.h"
#include "platform/os_proc.h"
#include "platform/time_compat.h"
#include "util/log_macros.h"

#include <inttypes.h>

enum { CACHE_ARMED, CACHE_RUNNING, CACHE_DONE, CACHE_REARM };

void rss_trim_policy_init(struct rss_trim_policy *p, int64_t interval_us)
{
    if (!p) return;
    p->interval_us = interval_us > 0 ? interval_us : RSS_TRIM_INTERVAL_US;
    p->last_trim_us = 0;
    p->have_trim = false;
    atomic_store(&p->heap_gate, false);
    atomic_store(&p->cache_state, CACHE_ARMED);
}

/* A sync observation re-arms without disturbing an in-flight release. */
bool rss_trim_cache_due(struct rss_trim_policy *p, bool in_sync)
{
    if (!p) return false;
    if (in_sync) {
        int state = atomic_load(&p->cache_state);
        while (state == CACHE_DONE || state == CACHE_RUNNING) {
            int next = state == CACHE_DONE ? CACHE_ARMED : CACHE_REARM;
            if (atomic_compare_exchange_weak(&p->cache_state, &state, next)) break;
        }
        return false;
    }
    return atomic_load(&p->cache_state) == CACHE_ARMED;
}

/* True at most once per interval, never during initial sync. Concurrent
 * callers use a nonblocking claim so at most one wins an interval. */
bool rss_trim_heap_due(struct rss_trim_policy *p, int64_t now_us,
                       bool in_sync)
{
    if (!p || in_sync || atomic_exchange(&p->heap_gate, true)) return false;
    bool have = p->have_trim;
    int64_t last = p->last_trim_us;
    bool due = !have || (now_us >= last &&
        (uint64_t)now_us - (uint64_t)last >= (uint64_t)p->interval_us);
    if (due) {
        p->last_trim_us = now_us;
        p->have_trim = true;
    }
    atomic_store(&p->heap_gate, false);
    return due;
}

static void rss_trim_do_cache(struct rss_trim_policy *p,
                              const struct rss_trim_ops *ops)
{
    int expect = CACHE_ARMED;
    if (!atomic_compare_exchange_strong(&p->cache_state, &expect, CACHE_RUNNING)) return;
    int64_t bytes = 0;
    enum rss_trim_release r = ops->release_cache(ops->ctx, &bytes);
    expect = CACHE_RUNNING;
    int next = r == RSS_TRIM_RELEASE_RETRY ? CACHE_ARMED : CACHE_DONE;
    if (!atomic_compare_exchange_strong(&p->cache_state, &expect, next))
        atomic_store(&p->cache_state, CACHE_ARMED);
    if (r == RSS_TRIM_RELEASE_RETRY) return;
    if (r == RSS_TRIM_RELEASE_DONE)
        LOG_INFO("rss_trim",
                 "projection page cache released bytes=%" PRId64, bytes);
}

static bool rss_trim_do_heap(const struct rss_trim_ops *ops)
{
    int64_t before = ops->resident_kib ? ops->resident_kib() : -1;
    bool ran = ops->trim_heap();
    if (!ran) {
        LOG_INFO("rss_trim", "heap trim unavailable");
        return false;
    }
    int64_t after = ops->resident_kib ? ops->resident_kib() : -1;
    LOG_INFO("rss_trim",
             "heap trim resident_kib before=%" PRId64 " after=%" PRId64,
             before, after);
    return ran;
}

bool rss_trim_tick(struct rss_trim_policy *p, const struct rss_trim_ops *ops)
{
    if (!p || !ops || !ops->now_us || !ops->in_initial_sync ||
        !ops->trim_heap)
        return false;
    bool in_sync = ops->in_initial_sync(ops->ctx);
    if (ops->release_cache && rss_trim_cache_due(p, in_sync))
        rss_trim_do_cache(p, ops);
    int cache = atomic_load(&p->cache_state);
    if (cache == CACHE_RUNNING || cache == CACHE_REARM) return false;
    if (rss_trim_heap_due(p, ops->now_us(), in_sync))
        return rss_trim_do_heap(ops);
    return false;
}

static int64_t rss_trim_prod_resident(void)
{
    return os_proc_resident_kib();
}

static bool rss_trim_prod_heap(void)
{
#if defined(__GLIBC__)
    platform_allocator_release_free_pages();
    return true;
#else
    return false;
#endif
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
