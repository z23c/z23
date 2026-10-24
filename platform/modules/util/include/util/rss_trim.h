/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * rss_trim — steady-node resident-memory discipline.
 *
 * WHY: after catch-up a node keeps (a) the block-index projection SQLite page
 * cache that boot sized for catch-up and (b) freed-but-retained glibc arena
 * pages. mem_pressure's malloc_trim sink only fires above nominal pressure, so
 * a steady node never gives either back. This policy runs from an existing
 * periodic tick and does two things, both non-consensus:
 *   1. once per catch-up -> steady transition, release the projection cache;
 *   2. while steady, trim freed heap at most once per interval (10 minutes).
 *
 * The policy is a pure function of (clock, ibd flag, latches); the effects
 * (cache release, heap trim, resident read, clock, ibd) are injected so the
 * cadence, sync gate and once-per-transition rules are unit-testable with a
 * counting sink. Thread-safe: the latches are atomics, so the several staged
 * stage ticks may call rss_trim_tick() concurrently and each effect still
 * fires once.
 *
 * LOCKING CONTRACT: the caller MUST NOT hold cs_main, the reducer lock or any
 * store lock, and MUST NOT call from a signal handler. (The malloc_trim in
 * chain_restore_repair.c's historic "SEGV" was a missing cs_main in the
 * caller, not a malloc_trim fault; malloc_trim itself is thread-safe.) */

#ifndef ZCL_UTIL_RSS_TRIM_H
#define ZCL_UTIL_RSS_TRIM_H

#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>

#define RSS_TRIM_INTERVAL_US (600LL * 1000000LL)

/* Outcome of an injected cache release. RETRY (e.g. connection busy) leaves
 * the once-per-transition latch open so the next tick tries again. */
enum rss_trim_release {
    RSS_TRIM_RELEASE_DONE = 0,   /* released; *bytes is valid */
    RSS_TRIM_RELEASE_RETRY,      /* could not run now; try next tick */
    RSS_TRIM_RELEASE_NONE,       /* nothing to release; latch, no log */
};

struct rss_trim_ops {
    int64_t (*now_us)(void);                 /* monotonic clock */
    bool    (*in_initial_sync)(void *ctx);
    enum rss_trim_release (*release_cache)(void *ctx, int64_t *bytes);
    void    (*trim_heap)(void);
    int64_t (*resident_kib)(void);           /* -1 if unknown */
    void    *ctx;
};

struct rss_trim_policy {
    int64_t          interval_us;
    _Atomic int64_t  last_trim_us;       /* valid iff have_trim */
    _Atomic bool     have_trim;
    _Atomic bool     cache_released;     /* latched until the next sync */
};

void rss_trim_policy_init(struct rss_trim_policy *p, int64_t interval_us);

/* Pure gates (exposed for tests). */
bool rss_trim_cache_due(struct rss_trim_policy *p, bool in_sync);
bool rss_trim_heap_due(struct rss_trim_policy *p, int64_t now_us,
                       bool in_sync);

/* One policy step: cache release first (frees pages into the heap), then the
 * heap trim. Logs one INFO line per cache release and one per trim. */
void rss_trim_tick(struct rss_trim_policy *p, const struct rss_trim_ops *ops);

/* Production ops: monotonic clock, malloc_trim, statm resident, and the
 * caller's IBD predicate and cache release. */
void rss_trim_production_ops(struct rss_trim_ops *out, void *ctx,
                             bool (*in_initial_sync)(void *ctx),
                             enum rss_trim_release
                                 (*release_cache)(void *ctx, int64_t *bytes));

#endif
