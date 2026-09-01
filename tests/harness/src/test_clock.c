/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Unit tests for the platform clock abstraction (platform/modules/platform/src/clock.c).
 *
 * Coverage:
 *   - real default returns monotonically non-decreasing values
 *   - real default returns wall-clock ms in a sane epoch range
 *   - clock_set_default injects a fake; clock_now_monotonic_ns reads it
 *   - clock_set_default(NULL) is rejected (no-op)
 *   - clock_reset_default restores real behavior
 */

#include "test/test_core.h"
#include "platform/clock.h"

#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <time.h>

#define CLK_CHECK(name, expr) do { \
    printf("clock: %s... ", (name)); \
    if ((expr)) printf("OK\n"); \
    else { printf("FAIL\n"); failures++; } \
} while (0)

/* Fake clock — returns whatever the test writes into its atomic cells. */
struct fake_clock {
    _Atomic int64_t mono_ns;
    _Atomic int64_t wall_ms;
};

static int64_t fake_now_mono(void *self)
{
    struct fake_clock *c = (struct fake_clock *)self;
    return atomic_load(&c->mono_ns);
}

static int64_t fake_now_wall(void *self)
{
    struct fake_clock *c = (struct fake_clock *)self;
    return atomic_load(&c->wall_ms);
}

int test_clock(void)
{
    printf("\n=== platform clock tests ===\n");
    int failures = 0;

    /* ── real default: monotonic ─────────────────────────────────── */
    {
        clock_reset_default();

        int64_t a = clock_now_monotonic_ns();
        /* Tight loop to push the clock forward at least one tick. */
        for (volatile int i = 0; i < 10000; i++) { /* spin */ }
        int64_t b = clock_now_monotonic_ns();
        int64_t c = clock_now_monotonic_ns();

        CLK_CHECK("real mono returns positive", a > 0);
        CLK_CHECK("real mono non-decreasing a<=b", a <= b);
        CLK_CHECK("real mono non-decreasing b<=c", b <= c);
    }

    /* ── real default: wall clock in sane range ──────────────────── */
    {
        clock_reset_default();
        int64_t wall = clock_now_wall_ms();

        /* 2025-01-01 00:00:00 UTC = 1735689600 seconds = 1735689600000 ms.
         * 2035-01-01 00:00:00 UTC = 2051222400 seconds = 2051222400000 ms.
         * Generous upper bound covers the next decade of CI runs. */
        const int64_t LO = 1735689600000LL;
        const int64_t HI = 2051222400000LL;
        CLK_CHECK("real wall_ms >= 2025-01-01", wall >= LO);
        CLK_CHECK("real wall_ms <  2035-01-01", wall <  HI);
    }

    /* ── injection: fake clock observed by helpers ───────────────── */
    {
        struct fake_clock fake;
        atomic_store(&fake.mono_ns, (int64_t)42);
        atomic_store(&fake.wall_ms, (int64_t)99);

        const clock_iface_t iface = {
            .now_monotonic_ns = fake_now_mono,
            .now_wall_ms      = fake_now_wall,
            .self             = &fake,
        };
        clock_set_default(&iface);

        int64_t m1 = clock_now_monotonic_ns();
        int64_t w1 = clock_now_wall_ms();
        CLK_CHECK("fake mono observed", m1 == 42);
        CLK_CHECK("fake wall observed", w1 == 99);

        atomic_store(&fake.mono_ns, (int64_t)1000);
        atomic_store(&fake.wall_ms, (int64_t)2000);
        CLK_CHECK("fake mono updated", clock_now_monotonic_ns() == 1000);
        CLK_CHECK("fake wall updated", clock_now_wall_ms() == 2000);

        CLK_CHECK("clock_default returns the injected pointer",
                  clock_default() == &iface);

        /* Restore — important so later tests are not corrupted. */
        clock_reset_default();
        int64_t real_after = clock_now_monotonic_ns();
        CLK_CHECK("after reset: real mono > fake value",
                  real_after > 1000);
    }

    /* ── set NULL is rejected ────────────────────────────────────── */
    {
        clock_reset_default();
        const clock_iface_t *before = clock_default();
        clock_set_default(NULL);
        const clock_iface_t *after = clock_default();
        CLK_CHECK("set_default(NULL) is no-op", before == after);
    }

    /* Final defensive reset. */
    clock_reset_default();

    if (failures == 0) {
        printf("=== platform clock tests: ALL PASS ===\n\n");
    } else {
        printf("=== platform clock tests: %d FAILURE(S) ===\n\n", failures);
    }
    return failures;
}
