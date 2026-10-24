/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Unit tests for util/rss_trim.h: the cadence gate (at most once per
 * interval), the sync gate (never during initial sync), the once-per-
 * transition cache release (RETRY keeps the latch open), plus a fixture
 * micro-measure that frees ~200 MiB of small chunks and shows the real
 * platform trim drop resident memory (os_proc_resident_kib, /proc/self/statm).
 * The policy tests use an injectable clock and counting sinks. */

#include "test/test_core.h"
#include "platform/allocator_compat.h"
#include "platform/os_proc.h"
#include "util/rss_trim.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#define RT_CHECK(name, expr) do { \
    printf("rss_trim: %s... ", (name)); \
    if ((expr)) printf("OK\n"); \
    else { printf("FAIL\n"); failures++; } \
} while (0)

static int64_t g_now;
static bool g_sync;
static int g_cache_calls, g_heap_calls;
static enum rss_trim_release g_cache_result;

static int64_t t_now(void) { return g_now; }
static bool t_sync(void *c) { (void)c; return g_sync; }
static int64_t t_res(void) { return 1000; }
static void t_heap(void) { g_heap_calls++; }
static enum rss_trim_release t_cache(void *c, int64_t *bytes)
{
    (void)c;
    g_cache_calls++;
    *bytes = 4096;
    return g_cache_result;
}

#define MIN_US (60LL * 1000000LL)

static int rt_policy_cases(void)
{
    int failures = 0;
    struct rss_trim_policy p;
    struct rss_trim_ops ops = { t_now, t_sync, t_cache, t_heap, t_res, NULL };
    rss_trim_policy_init(&p, RSS_TRIM_INTERVAL_US);
    g_now = 100 * MIN_US; g_sync = true;
    g_cache_calls = g_heap_calls = 0; g_cache_result = RSS_TRIM_RELEASE_DONE;

    for (int i = 0; i < 5; i++) { g_now += MIN_US; rss_trim_tick(&p, &ops); }
    RT_CHECK("sync gate: no cache release or trim during initial sync",
             g_cache_calls == 0 && g_heap_calls == 0);

    g_sync = false;
    rss_trim_tick(&p, &ops);
    RT_CHECK("transition: cache released once and heap trimmed once",
             g_cache_calls == 1 && g_heap_calls == 1);
    for (int i = 0; i < 9; i++) { g_now += MIN_US; rss_trim_tick(&p, &ops); }
    RT_CHECK("cadence: no second trim inside 10 minutes",
             g_heap_calls == 1 && g_cache_calls == 1);
    g_now += MIN_US;
    rss_trim_tick(&p, &ops);
    RT_CHECK("cadence: second trim at 10 minutes, cache not repeated",
             g_heap_calls == 2 && g_cache_calls == 1);

    g_sync = true; rss_trim_tick(&p, &ops);
    g_sync = false; g_now += 100 * MIN_US; rss_trim_tick(&p, &ops);
    RT_CHECK("re-entering sync re-arms exactly one more cache release",
             g_cache_calls == 2 && g_heap_calls == 3);

    rss_trim_policy_init(&p, RSS_TRIM_INTERVAL_US);
    g_cache_calls = g_heap_calls = 0; g_cache_result = RSS_TRIM_RELEASE_RETRY;
    rss_trim_tick(&p, &ops);
    g_cache_result = RSS_TRIM_RELEASE_DONE; g_now += MIN_US;
    rss_trim_tick(&p, &ops); rss_trim_tick(&p, &ops);
    RT_CHECK("busy connection retries next tick, then latches",
             g_cache_calls == 3 - 1 && g_heap_calls == 1);
    return failures;
}

#define CHUNK 512
#define NCHUNK ((200u * 1024u * 1024u) / CHUNK)

static int rt_measure_cases(void)
{
    int failures = 0;
#if defined(__GLIBC__) && !defined(__SANITIZE_ADDRESS__)
    void **v = calloc(NCHUNK, sizeof(*v));
    if (!v) return 1;
    int64_t base = os_proc_resident_kib();
    for (size_t i = 0; i < NCHUNK; i++) {
        v[i] = malloc(CHUNK);
        if (!v[i]) { RT_CHECK("measure alloc", false); return failures + 1; }
        ((volatile char *)v[i])[0] = 1;
        ((volatile char *)v[i])[CHUNK - 1] = 1;
    }
    void *pin = v[NCHUNK - 1];   /* top-of-heap pin: free cannot shrink brk */
    int64_t full = os_proc_resident_kib();
    for (size_t i = 0; i + 1 < NCHUNK; i++) free(v[i]);
    int64_t freed = os_proc_resident_kib();
    platform_allocator_release_free_pages();
    int64_t trimmed = os_proc_resident_kib();
    free(pin); free(v);
    printf("rss_trim: measure KiB base=%lld full=%lld after_free=%lld "
           "after_trim=%lld\n", (long long)base, (long long)full,
           (long long)freed, (long long)trimmed);
    RT_CHECK("statm reads resident", base > 0 && full > base);
    RT_CHECK("freed chunks stay resident until the trim", freed > full / 2);
    RT_CHECK("trim returns >= 150 MiB to the OS",
             freed - trimmed >= 150 * 1024);
#endif
    return failures;
}

int test_rss_trim(void);
int test_rss_trim(void)
{
    int failures = rt_policy_cases() + rt_measure_cases();
    printf(failures ? "=== rss_trim tests: %d FAILURE(S) ===\n\n"
                    : "=== rss_trim tests: ALL PASS (%d) ===\n\n", failures);
    return failures;
}
