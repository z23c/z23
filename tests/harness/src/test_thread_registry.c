/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * thread_registry stress test. */

#include "test/test_core.h"
#include "util/thread_registry.h"

#include <pthread.h>
#include <stdatomic.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

struct worker_ctx {
    _Atomic int started;
    _Atomic int exited;
};

#if defined(__APPLE__)
struct darwin_stack_ctx {
    size_t observed;
};

static void *tr_observe_stack(void *arg)
{
    struct darwin_stack_ctx *ctx = arg;
    ctx->observed = pthread_get_stacksize_np(pthread_self());
    return NULL;
}

static int t_registry_darwin_stack_headroom(void)
{
    int failures = 0;
    thread_registry_reset_for_test();

    TEST("thread_registry: Darwin workers receive explicit stack headroom") {
        struct darwin_stack_ctx ctx = {0};
        pthread_t tid;
        ASSERT_EQ(thread_registry_spawn("tr-stack", tr_observe_stack,
                                        &ctx, &tid), 0);
        ASSERT_EQ(pthread_join(tid, NULL), 0);
        ASSERT(ctx.observed >= ZCL_DARWIN_THREAD_STACK_BYTES);
        PASS();
    } _test_next:;
    return failures;
}
#endif

/* Worker polls the registry's shutdown flag every ~10 ms and exits
 * cleanly when it flips. This is the contract every long-running
 * zclassic23 thread must follow. */
static void *tr_worker(void *arg)
{
    struct worker_ctx *ctx = arg;
    atomic_fetch_add_explicit(&ctx->started, 1, memory_order_relaxed);
    while (!thread_registry_shutdown_requested()) {
        struct timespec ts = {.tv_sec = 0, .tv_nsec = 10 * 1000 * 1000};
        nanosleep(&ts, NULL);
    }
    atomic_fetch_add_explicit(&ctx->exited, 1, memory_order_relaxed);
    return NULL;
}

/* Spawn N worker threads. Block (condvar) until all of them reach
 * the top of their poll loop, then assert that toggling the registry
 * shutdown flag drains them. */
static int t_registry_stress_50_threads(void)
{
    int failures = 0;
    thread_registry_reset_for_test();

    TEST("thread_registry: 50 workers all exit on shutdown") {
        struct worker_ctx ctx = {0};
        const int N = 50;

        for (int i = 0; i < N; i++) {
            char name[32];
            snprintf(name, sizeof(name), "tr-worker-%d", i);
            ASSERT_EQ(thread_registry_spawn(name, tr_worker, &ctx, NULL), 0);
        }

        /* Wait for all workers to start polling — the registry count
         * stays at N until trampoline unregister runs. */
        int waited_ms = 0;
        while (atomic_load_explicit(&ctx.started, memory_order_relaxed) < N
               && waited_ms < 5000) {
            struct timespec ts = {.tv_sec = 0, .tv_nsec = 10 * 1000 * 1000};
            nanosleep(&ts, NULL);
            waited_ms += 10;
        }
        ASSERT_EQ(atomic_load_explicit(&ctx.started, memory_order_relaxed),
                  N);
        ASSERT_EQ(thread_registry_live_count(), N);
        ASSERT(!thread_registry_shutdown_requested());

        /* Flip the flag → all workers exit their poll loop. */
        thread_registry_request_shutdown();
        ASSERT(thread_registry_shutdown_requested());

        /* Returned registry-owned pthreads are no longer live, but they stay
         * tracked until join_all reaps their pthread resources. This is the
         * distinction TSan's thread-leak detector requires. */
        waited_ms = 0;
        while ((atomic_load_explicit(&ctx.exited, memory_order_relaxed) < N ||
                thread_registry_live_count() != 0)
               && waited_ms < 5000) {
            struct timespec ts = {.tv_sec = 0, .tv_nsec = 10 * 1000 * 1000};
            nanosleep(&ts, NULL);
            waited_ms += 10;
        }
        ASSERT_EQ(atomic_load_explicit(&ctx.exited, memory_order_relaxed), N);
        ASSERT_EQ(thread_registry_live_count(), 0);
        ASSERT_EQ(thread_registry_unreaped_count(), N);

        /* Join with 10s per-thread budget. Returns the count of
         * stragglers; expect 0 because workers poll at 10 ms. */
        int stragglers = thread_registry_join_all(10);
        ASSERT_EQ(stragglers, 0);
        ASSERT_EQ(atomic_load_explicit(&ctx.exited, memory_order_relaxed),
                  N);
        ASSERT_EQ(thread_registry_live_count(), 0);
        ASSERT_EQ(thread_registry_unreaped_count(), 0);

        PASS();
    } _test_next:;
    return failures;
}

/* Stuck worker — ignores the shutdown flag. join_all must report
 * exactly one straggler and name it. */
static void *tr_stuck_worker(void *arg)
{
    (void)arg;
    /* Sleep past the join_all timeout. */
    struct timespec ts = {.tv_sec = 3, .tv_nsec = 0};
    nanosleep(&ts, NULL);
    return NULL;
}

static int t_registry_reports_straggler(void)
{
    int failures = 0;
    thread_registry_reset_for_test();

    TEST("thread_registry: join_all reports straggler after timeout") {
        ASSERT_EQ(thread_registry_spawn("tr-stuck",
                                        tr_stuck_worker, NULL, NULL),
                  0);
        /* 1-second timeout on a 3-second sleep → exactly one straggler. */
        ASSERT_EQ(thread_registry_join_all(1), 1);
        /* The straggler eventually exits; final sweep drains it. */
        ASSERT_EQ(thread_registry_join_all(5), 0);
        PASS();
    } _test_next:;
    return failures;
}

static int t_registry_owned_join_waits_for_straggler(void)
{
    int failures = 0;
    thread_registry_reset_for_test();

    TEST("thread_registry: owned join never abandons a live worker") {
        ASSERT_EQ(thread_registry_spawn("tr-owned",
                                        tr_stuck_worker, NULL, NULL),
                  0);
        ASSERT_EQ(thread_registry_join_all(0), 1);
        thread_registry_join_all_owned();
        ASSERT_EQ(thread_registry_live_count(), 0);
        ASSERT_EQ(thread_registry_unreaped_count(), 0);
        PASS();
    } _test_next:;
    return failures;
}

struct excluded_worker_ctx {
    _Atomic bool started;
    _Atomic bool release;
};

static void *tr_excluded_worker(void *arg)
{
    struct excluded_worker_ctx *ctx = arg;
    atomic_store_explicit(&ctx->started, true, memory_order_release);
    while (!atomic_load_explicit(&ctx->release, memory_order_acquire)) {
        struct timespec ts = {.tv_sec = 0, .tv_nsec = 10 * 1000 * 1000};
        nanosleep(&ts, NULL);
    }
    return NULL;
}

static int t_registry_exact_exclusion_retains_provider(void)
{
    int failures = 0;
    thread_registry_reset_for_test();

    TEST("thread_registry: exact exclusion retains dependency provider") {
        struct excluded_worker_ctx ctx;
        atomic_init(&ctx.started, false);
        atomic_init(&ctx.release, false);
        pthread_t provider;
        ASSERT_EQ(thread_registry_spawn("tr-provider", tr_excluded_worker,
                                        &ctx, &provider), 0);
        for (int i = 0; i < 100 &&
                        !atomic_load_explicit(&ctx.started,
                                              memory_order_acquire); i++) {
            struct timespec ts = {.tv_sec = 0, .tv_nsec = 10 * 1000 * 1000};
            nanosleep(&ts, NULL);
        }
        ASSERT(atomic_load_explicit(&ctx.started, memory_order_acquire));

        /* The consumer sweep must neither join nor report this exact provider. */
        ASSERT_EQ(thread_registry_join_all_except(0, &provider, 1), 0);
        ASSERT_EQ(thread_registry_live_count(), 1);
        ASSERT_EQ(thread_registry_unreaped_count(), 1);

        atomic_store_explicit(&ctx.release, true, memory_order_release);
        /* out_tid transferred join ownership to this subsystem fixture. */
        ASSERT_EQ(pthread_join(provider, NULL), 0);
        ASSERT_EQ(thread_registry_live_count(), 0);
        ASSERT_EQ(thread_registry_unreaped_count(), 0);
        PASS();
    } _test_next:;
    return failures;
}

/* spawn returns pthread errno on pthread_create failure. Feed it an
 * obviously broken entry (NULL) and assert the registry doesn't leak
 * a reserved slot on the rejected spawn. */
static int t_registry_rejects_null_entry(void)
{
    int failures = 0;
    thread_registry_reset_for_test();

    TEST("thread_registry: spawn(NULL entry) rejects without leaking slot") {
        int rc = thread_registry_spawn("bad", NULL, NULL, NULL);
        ASSERT(rc != 0);
        ASSERT_EQ(thread_registry_live_count(), 0);
        ASSERT_EQ(thread_registry_unreaped_count(), 0);
        PASS();
    } _test_next:;
    return failures;
}

/* ── thread_registry_snapshot ──────────────────────────────────────────
 *
 * Pinned against live registered workers: the snapshot returns exactly
 * the live entries with their exact registered names, honours the `cap`
 * truncation, and reports 0 for a zero cap. The registry mutex is held
 * only briefly inside the call, so the snapshot is consistent without
 * the callers freezing the world. One function per TEST, as the
 * harness's hardcoded `goto _test_next` requires. */
static int t_registry_snapshot(void)
{
    int failures = 0;
    thread_registry_reset_for_test();

    TEST("thread_registry: snapshot lists exact live names and honours cap") {
        struct worker_ctx ctx = {0};
        const int N = 3;
        for (int i = 0; i < N; i++) {
            char name[32];
            snprintf(name, sizeof(name), "tr-snap-%d", i);
            ASSERT_EQ(thread_registry_spawn(name, tr_worker, &ctx, NULL), 0);
        }
        int waited_ms = 0;
        while (atomic_load_explicit(&ctx.started, memory_order_relaxed) < N
               && waited_ms < 5000) {
            struct timespec ts = {.tv_sec = 0, .tv_nsec = 10 * 1000 * 1000};
            nanosleep(&ts, NULL);
            waited_ms += 10;
        }
        ASSERT_EQ(atomic_load_explicit(&ctx.started, memory_order_relaxed),
                  N);

        struct thread_registry_view out[8];
        int n = thread_registry_snapshot(out, 8);
        ASSERT_EQ(n, N);
        for (int i = 0; i < N; i++) {
            char want[32];
            snprintf(want, sizeof(want), "tr-snap-%d", i);
            ASSERT(strncmp(out[i].name, want, sizeof(out[i].name)) == 0);
        }

        /* cap=2 truncates to exactly 2, preserving registry order. */
        struct thread_registry_view few[2];
        ASSERT_EQ(thread_registry_snapshot(few, 2), 2);
        ASSERT(strncmp(few[0].name, "tr-snap-0", sizeof(few[0].name)) == 0);
        ASSERT(strncmp(few[1].name, "tr-snap-1", sizeof(few[1].name)) == 0);

        /* Zero cap writes nothing and reports 0. */
        ASSERT_EQ(thread_registry_snapshot(out, 0), 0);

        thread_registry_request_shutdown();
        ASSERT_EQ(thread_registry_join_all(10), 0);
        PASS();
    } _test_next:;
    return failures;
}

int test_thread_registry(void);

int test_thread_registry(void)
{
    printf("\n=== thread_registry tests ===\n");
    int failures = 0;
#if defined(__APPLE__)
    failures += t_registry_darwin_stack_headroom();
#endif
    failures += t_registry_rejects_null_entry();
    failures += t_registry_snapshot();
    failures += t_registry_stress_50_threads();
    failures += t_registry_reports_straggler();
    failures += t_registry_owned_join_waits_for_straggler();
    failures += t_registry_exact_exclusion_retains_provider();
    return failures;
}
