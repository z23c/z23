/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Tests for the ibd_throttle service.
 *
 * Strategy
 * --------
 * Most assertions exercise `ibd_throttle_refill()` directly — it's
 * the pure primitive and doesn't touch globals, time, or sleep.
 * The lifecycle / hot-path / event-emission branches are covered
 * with a fast configuration (burst 3, rate 10000/s) so the blocking
 * tests finish in well under a second without real time scaling.
 */

#include "platform/time_compat.h"
#include "platform/barrier.h"
#include "test/test_core.h"
#include "services/ibd_throttle.h"
#include "event/event.h"

#include <math.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include "test/setup_result.h"

static _Atomic int g_it_events;

static void it_ev_observer(enum event_type type, uint32_t peer_id,
                            const void *payload, uint32_t payload_len,
                            void *ctx)
{
    (void)peer_id; (void)payload; (void)payload_len; (void)ctx;
    if (type == EV_IBD_THROTTLED) atomic_fetch_add(&g_it_events, 1);
}

static void it_reset_observer(void)
{
    event_clear_observers(EV_IBD_THROTTLED);
    atomic_store(&g_it_events, 0);
    event_observe(EV_IBD_THROTTLED, it_ev_observer, NULL);
}

#define IT_CHECK(name, expr) do {  \
    printf("%s... ", (name));      \
    if ((expr)) printf("OK\n");    \
    else { printf("FAIL\n"); failures++; } \
} while (0)

static bool near_d(double a, double b) { return fabs(a - b) < 1e-6; }

struct it_worker_arg {
    _Atomic bool *done;
    zcl_barrier_t *barrier;  /* count=2 rendezvous with main */
};

static void *it_acquire_worker(void *a)
{
    struct it_worker_arg *w = a;
    /* Rendezvous with the main thread immediately before entering the
     * blocking acquire() loop. Replaces a blind fixed sleep with a
     * deterministic synchronization point so the main thread knows the
     * worker is about to block before it calls ibd_throttle_stop(). */
    zcl_barrier_wait(w->barrier);
    (void)ibd_throttle_acquire();
    atomic_store(w->done, true);
    return NULL;
}

int test_ibd_throttle(void)
{
    printf("\n=== ibd_throttle tests ===\n");
    int failures = 0;

    /* Always start from a known-stopped state. */
    ibd_throttle_stop();

    /* ── 1. Defaults applied when cfg is zeroed ─────────────── */
    {
        struct ibd_throttle_config cfg = {0};
        ibd_throttle_config_defaults(&cfg);
        IT_CHECK("it: defaults set blocks_per_sec = 500",
                 cfg.blocks_per_sec == IBD_THROTTLE_DEFAULT_BLOCKS_PER_SEC);
        IT_CHECK("it: defaults set burst = 50",
                 cfg.burst == IBD_THROTTLE_DEFAULT_BURST);
    }

    /* ── 2. Env overrides ──────────────────────────────────── */
    {
        setenv("ZCL_IBD_BLOCKS_PER_SEC", "123", 1);
        setenv("ZCL_IBD_BURST", "7", 1);
        struct ibd_throttle_config cfg;
        ibd_throttle_config_from_env(&cfg);
        IT_CHECK("it: env ZCL_IBD_BLOCKS_PER_SEC applied",
                 cfg.blocks_per_sec == 123);
        IT_CHECK("it: env ZCL_IBD_BURST applied",
                 cfg.burst == 7);
        unsetenv("ZCL_IBD_BLOCKS_PER_SEC");
        unsetenv("ZCL_IBD_BURST");
    }

    /* ── 3. Env ignored when non-positive / non-numeric ────── */
    {
        setenv("ZCL_IBD_BLOCKS_PER_SEC", "-5", 1);
        setenv("ZCL_IBD_BURST", "abc", 1);
        struct ibd_throttle_config cfg;
        ibd_throttle_config_from_env(&cfg);
        IT_CHECK("it: negative env falls back to default",
                 cfg.blocks_per_sec == IBD_THROTTLE_DEFAULT_BLOCKS_PER_SEC);
        IT_CHECK("it: junk env falls back to default",
                 cfg.burst == IBD_THROTTLE_DEFAULT_BURST);
        unsetenv("ZCL_IBD_BLOCKS_PER_SEC");
        unsetenv("ZCL_IBD_BURST");
    }

    /* ── 4. Pure refill — elapsed 0 keeps tokens ───────────── */
    {
        double t = ibd_throttle_refill(10.0, 500.0, 50.0, 0);
        IT_CHECK("it: refill elapsed=0 keeps tokens", near_d(t, 10.0));
    }

    /* ── 5. Pure refill — 1 second at rate 500 caps at burst — */
    {
        double t = ibd_throttle_refill(0.0, 500.0, 50.0, 1000000);
        IT_CHECK("it: refill caps at burst", near_d(t, 50.0));
    }

    /* ── 6. Pure refill — sub-second partial refill ────────── */
    {
        /* Rate 1000/s, elapsed 2ms → +2 tokens. */
        double t = ibd_throttle_refill(0.0, 1000.0, 100.0, 2000);
        IT_CHECK("it: refill sub-second arithmetic", near_d(t, 2.0));
    }

    /* ── 7. Pure refill — negative tokens clamped to 0 first — */
    {
        double t = ibd_throttle_refill(-5.0, 1000.0, 10.0, 1000);
        /* 0 + (1000 * 0.001) = 1.0 */
        IT_CHECK("it: refill clamps negative input to 0",
                 near_d(t, 1.0));
    }

    /* ── 8. Pure refill — zero rate is a no-op ─────────────── */
    {
        double t = ibd_throttle_refill(3.0, 0.0, 10.0, 1000000);
        IT_CHECK("it: refill with rate=0 is a no-op",
                 near_d(t, 3.0));
    }

    /* ── 9. Not-running: acquire is a pass-through ─────────── */
    {
        IT_CHECK("it: stopped acquire passes through",
                 ibd_throttle_acquire().ok == true);
        IT_CHECK("it: stopped try_acquire passes through",
                 ibd_throttle_try_acquire() == true);
        IT_CHECK("it: is_running is false",
                 ibd_throttle_is_running() == false);
    }

    /* ── 10. Start/stop lifecycle ──────────────────────────── */
    {
        struct ibd_throttle_config cfg = { .blocks_per_sec = 10000,
                                            .burst = 3 };
        bool ok = ibd_throttle_start(&cfg).ok;
        IT_CHECK("it: start with explicit cfg", ok == true);
        IT_CHECK("it: double start returns false",
                 ibd_throttle_start(&cfg).ok == false);
        IT_CHECK("it: is_running true after start",
                 ibd_throttle_is_running() == true);
        ibd_throttle_stop();
        IT_CHECK("it: is_running false after stop",
                 ibd_throttle_is_running() == false);
        /* stop is idempotent */
        ibd_throttle_stop();
    }

    /* ── 11. Burst drains to zero then refuses try_acquire ── */
    {
        struct ibd_throttle_config cfg = { .blocks_per_sec = 1,
                                            .burst = 3 };
        ZCL_TEST_SETUP(ibd_throttle_start(&cfg));
        bool a = ibd_throttle_try_acquire();
        bool b = ibd_throttle_try_acquire();
        bool c = ibd_throttle_try_acquire();
        bool d = ibd_throttle_try_acquire();
        IT_CHECK("it: burst yields 3 successful try_acquire",
                 a && b && c);
        IT_CHECK("it: 4th try_acquire fails (bucket empty)",
                 d == false);
        ibd_throttle_stop();
    }

    /* ── 12. Counters match successful acquires ────────────── */
    {
        struct ibd_throttle_config cfg = { .blocks_per_sec = 10000,
                                            .burst = 5 };
        ZCL_TEST_SETUP(ibd_throttle_start(&cfg));
        for (int i = 0; i < 5; i++) (void)ibd_throttle_try_acquire();
        struct ibd_throttle_status st;
        ibd_throttle_status_snapshot(&st);
        IT_CHECK("it: acquired_count reflects successful acquires",
                 st.acquired_count == 5);
        IT_CHECK("it: blocked_count zero for non-blocking path",
                 st.blocked_count == 0);
        IT_CHECK("it: tokens ≈ 0 after burst drain",
                 st.tokens_available < 1.0);
        ibd_throttle_stop();
    }

    /* ── 13. acquire() blocks then returns once refilled ───── */
    {
        /* burst=1, rate=500/s → 2ms per token. */
        struct ibd_throttle_config cfg = { .blocks_per_sec = 500,
                                            .burst = 1 };
        ZCL_TEST_SETUP(ibd_throttle_start(&cfg));
        /* Drain. */
        (void)ibd_throttle_try_acquire();
        struct timespec t0, t1;
        platform_time_monotonic_timespec(&t0);
        bool got = ibd_throttle_acquire().ok;
        platform_time_monotonic_timespec(&t1);
        int64_t dur_ms = (int64_t)(t1.tv_sec - t0.tv_sec) * 1000 +
                         (t1.tv_nsec - t0.tv_nsec) / 1000000;
        IT_CHECK("it: acquire returns true after blocking", got == true);
        /* Lower bound only. The bucket is drained and refills at 500/s, so the
         * call CANNOT return before ~2ms have passed — and a busy machine only
         * ever makes the observed wait longer, never shorter. That direction is
         * forced; the other one is not.
         *
         * There used to be an "it: blocked less than 100ms" assertion here. It
         * asserted nothing about ibd_throttle: an over-100ms reading means the
         * OS did not schedule this thread promptly, which is a fact about the
         * box, not about the token bucket. The refill arithmetic it was
         * standing in for is covered exactly and without a clock by the pure
         * ibd_throttle_refill() cases above (4-8). Kept as an opt-in
         * measurement below so the number is still available on demand. */
        IT_CHECK("it: blocked at least ~1ms before refill",
                 dur_ms >= 1);

        /* Upper bound, kept in the DEFAULT suite, via best-of-N.
         *
         * Deleting it lost real coverage: a 200x oversleep planted in
         * ibd_throttle_acquire's wait loop leaves every other assertion here
         * green, because the pure refill cases (4-8) never touch the sleep
         * path and the lower bound only gets easier to satisfy.
         *
         * A single wall-clock sample cannot carry the bound — an over-100ms
         * reading usually means the OS did not schedule us, which is a fact
         * about the box. The MINIMUM over several attempts can: it needs only
         * ONE unimpeded sample, so load has to starve every attempt to make it
         * fire, while a genuine oversleep inflates all of them equally and
         * still trips it. Same reason a benchmark quotes its best run. */
        int64_t best_ms = dur_ms;
        for (int attempt = 0; attempt < 8 && best_ms >= 100; attempt++) {
            (void)ibd_throttle_try_acquire();   /* drain again */
            platform_time_monotonic_timespec(&t0);
            bool again = ibd_throttle_acquire().ok;
            platform_time_monotonic_timespec(&t1);
            if (!again) break;
            int64_t d = (int64_t)(t1.tv_sec - t0.tv_sec) * 1000 +
                        (t1.tv_nsec - t0.tv_nsec) / 1000000;
            if (d < best_ms) best_ms = d;
        }
        printf("it: blocked acquire best-of-9 measured %lld ms\n",
               (long long)best_ms);
        IT_CHECK("it: fastest blocked acquire is well under 100ms",
                 best_ms < 100);

        struct ibd_throttle_status st;
        ibd_throttle_status_snapshot(&st);
        IT_CHECK("it: blocked_count > 0 after blocked acquire",
                 st.blocked_count >= 1);
        IT_CHECK("it: total_wait_us > 0",
                 st.total_wait_us > 0);
        ibd_throttle_stop();
    }

    /* ── 14. stop() while waiting makes acquire return ────── */
    {
        /* burst=1 then drain; kick off a thread that blocks in
         * acquire, then stop the throttle. acquire must unstick. */
        struct ibd_throttle_config cfg = { .blocks_per_sec = 1,
                                            .burst = 1 };
        ZCL_TEST_SETUP(ibd_throttle_start(&cfg));
        (void)ibd_throttle_try_acquire();

        _Atomic bool done = false;
        pthread_t th;
        zcl_barrier_t barrier;
        zcl_barrier_init(&barrier, 2);
        struct it_worker_arg arg = { .done = &done, .barrier = &barrier };
        pthread_create(&th, NULL, it_acquire_worker, &arg);
        /* Deterministically rendezvous with the worker right before it
         * enters the blocking acquire() loop (replaces a fixed 5ms
         * nanosleep guess). After the barrier the worker is about to
         * block on a drained bucket; stop() must unstick it. */
        zcl_barrier_wait(&barrier);
        ibd_throttle_stop();
        pthread_join(th, NULL);
        zcl_barrier_destroy(&barrier);
        IT_CHECK("it: stop while blocked releases the waiter",
                 atomic_load(&done) == true);
    }

    /* ── 15. Event fires on blocked acquire (rate-limit aware) */
    {
        it_reset_observer();
        struct ibd_throttle_config cfg = { .blocks_per_sec = 500,
                                            .burst = 1 };
        ZCL_TEST_SETUP(ibd_throttle_start(&cfg));
        (void)ibd_throttle_try_acquire();
        /* Blocked acquire #1 — emits (last_event_us was 0). */
        (void)ibd_throttle_acquire();
        IT_CHECK("it: first blocked acquire emits EV_IBD_THROTTLED",
                 atomic_load(&g_it_events) == 1);
        /* A subsequent blocked acquire within 60s must NOT
         * emit again. */
        (void)ibd_throttle_try_acquire(); /* may or may not drain */
        (void)ibd_throttle_acquire();
        IT_CHECK("it: second blocked acquire is rate-limited",
                 atomic_load(&g_it_events) == 1);
        ibd_throttle_stop();
    }

    /* ── 16. No event if nothing ever blocks ───────────────── */
    {
        it_reset_observer();
        struct ibd_throttle_config cfg = { .blocks_per_sec = 100000,
                                            .burst = 100 };
        ZCL_TEST_SETUP(ibd_throttle_start(&cfg));
        for (int i = 0; i < 5; i++) (void)ibd_throttle_acquire();
        IT_CHECK("it: no event when never blocked",
                 atomic_load(&g_it_events) == 0);
        ibd_throttle_stop();
    }

    /* ── 17. Status snapshot reflects resolved config ──────── */
    {
        struct ibd_throttle_config cfg = { .blocks_per_sec = 777,
                                            .burst = 12 };
        ZCL_TEST_SETUP(ibd_throttle_start(&cfg));
        struct ibd_throttle_status st;
        ibd_throttle_status_snapshot(&st);
        IT_CHECK("it: snapshot running=true after start",
                 st.running == true);
        IT_CHECK("it: snapshot blocks_per_sec matches cfg",
                 st.blocks_per_sec == 777);
        IT_CHECK("it: snapshot burst matches cfg",
                 st.burst == 12);
        IT_CHECK("it: snapshot tokens seeded to burst",
                 st.tokens_available <= 12.0 &&
                 st.tokens_available >= 11.999);
        ibd_throttle_stop();
    }

    printf("ibd_throttle tests: %s (%d failures)\n",
           failures == 0 ? "OK" : "FAIL", failures);
    return failures + ZCL_TEST_SETUP_FAILURES();
}
