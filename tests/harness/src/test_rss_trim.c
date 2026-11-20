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

#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

/* GCC names a ThreadSanitizer build with __SANITIZE_THREAD__; Clang reports it
 * through __has_feature(thread_sanitizer). */
#if defined(__SANITIZE_THREAD__)
#define RT_UNDER_TSAN 1
#elif defined(__has_feature)
#if __has_feature(thread_sanitizer)
#define RT_UNDER_TSAN 1
#endif
#endif

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
static bool t_heap(void) { g_heap_calls++; return true; }
static bool t_heap_unsupported(void) { g_heap_calls++; return false; }
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
    RT_CHECK("steady heap trim interval is pinned at 150 s (<= 5 minutes)",
             RSS_TRIM_INTERVAL_US == 150LL * 1000000LL &&
             RSS_TRIM_INTERVAL_US <= 5 * MIN_US);
    rss_trim_policy_init(&p, RSS_TRIM_INTERVAL_US);
    g_now = 100 * MIN_US; g_sync = true;
    g_cache_calls = g_heap_calls = 0; g_cache_result = RSS_TRIM_RELEASE_DONE;

    for (int i = 0; i < 5; i++) { g_now += MIN_US; rss_trim_tick(&p, &ops); }
    RT_CHECK("sync gate: no cache release or trim during initial sync",
             g_cache_calls == 0 && g_heap_calls == 0);

    g_sync = false;
    bool ran = rss_trim_tick(&p, &ops);
    RT_CHECK("transition: cache released once and heap trimmed once",
             g_cache_calls == 1 && g_heap_calls == 1 && ran);
    for (int i = 0; i < 2; i++) { g_now += MIN_US; rss_trim_tick(&p, &ops); }
    RT_CHECK("cadence: no second trim inside 150 s",
             g_heap_calls == 1 && g_cache_calls == 1);
    g_now += MIN_US;
    ran = rss_trim_tick(&p, &ops);
    RT_CHECK("cadence: second trim at 150 s, cache not repeated",
             g_heap_calls == 2 && g_cache_calls == 1 && ran);

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
    rss_trim_policy_init(&p, RSS_TRIM_INTERVAL_US);
    ops.trim_heap = t_heap_unsupported;
    RT_CHECK("unsupported heap operation is not reported as a trim",
             !rss_trim_tick(&p, &ops));
    RT_CHECK("no trim before next interval is not reported as a trim",
             !rss_trim_tick(&p, &ops));
    rss_trim_policy_init(&p, 100);
    RT_CHECK("time zero is a valid first trim", rss_trim_heap_due(&p, 0, false));
    RT_CHECK("time zero is not a second first trim", !rss_trim_heap_due(&p, 0, false));
    RT_CHECK("interval boundary trims", rss_trim_heap_due(&p, 100, false));
    RT_CHECK("clock rollback does not trim", !rss_trim_heap_due(&p, 0, false));
    RT_CHECK("after rollback the original deadline remains", rss_trim_heap_due(&p, 200, false));
    rss_trim_policy_init(&p, 100);
    RT_CHECK("extreme initial time", rss_trim_heap_due(&p, INT64_MIN, false));
    RT_CHECK("extreme elapsed time", rss_trim_heap_due(&p, INT64_MAX, false));
    RT_CHECK("extreme rollback", !rss_trim_heap_due(&p, INT64_MIN, false));
    rss_trim_policy_init(&p, 100);
    ops.trim_heap = t_heap;
    g_cache_calls = 0;
    g_cache_result = RSS_TRIM_RELEASE_NONE;
    rss_trim_tick(&p, &ops);
    rss_trim_tick(&p, &ops);
    RT_CHECK("nothing to release latches", g_cache_calls == 1);
    return failures;
}

static pthread_mutex_t rt_mu = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t rt_cv = PTHREAD_COND_INITIALIZER;
static bool rt_entered, rt_continue;
static _Atomic int rt_calls, rt_heaps;
static _Atomic bool rt_sync;
static bool rt_concurrent_sync(void *ctx) { (void)ctx; return atomic_load(&rt_sync); }
static int64_t rt_concurrent_now(void) { return 1000000000; }
static bool rt_concurrent_heap(void) { atomic_fetch_add(&rt_heaps, 1); return true; }
static enum rss_trim_release rt_blocked_cache(void *ctx, int64_t *bytes)
{
    (void)ctx;
    (void)bytes;
    if (atomic_fetch_add(&rt_calls, 1) == 0) {
        pthread_mutex_lock(&rt_mu);
        rt_entered = true;
        pthread_cond_broadcast(&rt_cv);
        while (!rt_continue) pthread_cond_wait(&rt_cv, &rt_mu);
        pthread_mutex_unlock(&rt_mu);
    }
    return RSS_TRIM_RELEASE_NONE;
}
struct rt_thread_args { struct rss_trim_policy *p; const struct rss_trim_ops *ops; };
static void *rt_tick_thread(void *arg)
{
    struct rt_thread_args *a = arg;
    rss_trim_tick(a->p, a->ops);
    return NULL;
}
static int rt_concurrent_cases(void)
{
    int failures = 0;
    struct rss_trim_policy p;
    struct rss_trim_ops ops = {rt_concurrent_now, rt_concurrent_sync, rt_blocked_cache, rt_concurrent_heap, NULL, NULL};
    struct rt_thread_args arg = {&p, &ops};
    pthread_t thread;
    rss_trim_policy_init(&p, RSS_TRIM_INTERVAL_US);
    atomic_store(&rt_calls, 0);
    atomic_store(&rt_heaps, 0);
    atomic_store(&rt_sync, false);
    rt_entered = false;
    rt_continue = false;
    if (pthread_create(&thread, NULL, rt_tick_thread, &arg) != 0) return 1;
    pthread_mutex_lock(&rt_mu);
    while (!rt_entered) pthread_cond_wait(&rt_cv, &rt_mu);
    pthread_mutex_unlock(&rt_mu);
    rss_trim_tick(&p, &ops);
    int concurrent = atomic_load(&rt_calls);
    int heaps_blocked = atomic_load(&rt_heaps);
    atomic_store(&rt_sync, true);
    rss_trim_tick(&p, &ops);
    atomic_store(&rt_sync, false);
    pthread_mutex_lock(&rt_mu);
    rt_continue = true;
    pthread_cond_broadcast(&rt_cv);
    pthread_mutex_unlock(&rt_mu);
    pthread_join(thread, NULL);
    rss_trim_tick(&p, &ops);
    int rearmed = atomic_load(&rt_calls);
    printf("rss_trim: concurrent=%d rearmed=%d\n", concurrent, rearmed);
    RT_CHECK("one release while first is in flight", concurrent == 1);
    RT_CHECK("heap waits while cache release is in flight", heaps_blocked == 0);
    RT_CHECK("sync during release re-arms the next steady tick", rearmed == concurrent + 1);
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
#if defined(RT_UNDER_TSAN)
    /* TSan's allocator keeps the freed chunks mapped and the platform trim
     * returns nothing: the TSan sweep (pfx-rs.log) measured after_free=829084
     * and after_trim=829104 KiB. Skipped under TSan only, with that reason. */
    printf("rss_trim: trim returns >= 150 MiB to the OS SKIP under ThreadSanitizer "
           "(the trim released no resident memory: after_free=%lld after_trim=%lld KiB)\n",
           (long long)freed, (long long)trimmed);
#else
    RT_CHECK("trim returns >= 150 MiB to the OS",
             freed - trimmed >= 150 * 1024);
#endif
#endif
    return failures;
}

int test_rss_trim(void);
int test_rss_trim(void)
{
    int failures = rt_policy_cases() + rt_concurrent_cases() + rt_measure_cases();
    printf(failures ? "=== rss_trim tests: %d FAILURE(S) ===\n\n"
                    : "=== rss_trim tests: ALL PASS (%d) ===\n\n", failures);
    return failures;
}
