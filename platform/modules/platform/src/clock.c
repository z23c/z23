/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Injectable clock — implementation. See platform/clock.h for design. */

#include "platform/clock.h"

#include "util/log_macros.h"

#include <errno.h>
#include <stdatomic.h>
#include <stddef.h>
#include <stdio.h>
#include <time.h>

/* ── Real-syscall implementation ─────────────────────────────────── */

static int64_t real_now_monotonic_ns(void *self)
{
    (void)self;
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
        /* clock_gettime can only fail with EINVAL (bad clock id) or
         * EFAULT (bad pointer). Both are programming errors. Log and
         * return zero so callers see a stuck clock rather than UB. */
        int e = errno;
        fprintf(stderr, // obs-ok:platform-primitive
            "[platform] %s:%d %s(): clock_gettime(CLOCK_MONOTONIC) failed errno=%d\n",
            __FILE__, __LINE__, __func__, e);
        return 0;
    }
    return (int64_t)ts.tv_sec * 1000000000LL + (int64_t)ts.tv_nsec;
}

static int64_t real_now_wall_ms(void *self)
{
    (void)self;
    struct timespec ts;
    if (clock_gettime(CLOCK_REALTIME, &ts) != 0) {
        int e = errno;
        fprintf(stderr, // obs-ok:platform-primitive
            "[platform] %s:%d %s(): clock_gettime(CLOCK_REALTIME) failed errno=%d\n",
            __FILE__, __LINE__, __func__, e);
        return 0;
    }
    return (int64_t)ts.tv_sec * 1000LL + (int64_t)ts.tv_nsec / 1000000LL;
}

static const clock_iface_t g_real_iface = {
    .now_monotonic_ns = real_now_monotonic_ns,
    .now_wall_ms      = real_now_wall_ms,
    .self             = NULL,
};

/* ── Process-wide default ────────────────────────────────────────── */

/* Atomic pointer so `clock_set_default` is safe vs concurrent readers.
 * In practice swaps only happen from tests/simulator setup, but making
 * the read lock-free is essentially free and keeps the contract clean. */
static _Atomic(const clock_iface_t *) g_default = &g_real_iface;

/* Installed simulator/tape source. NULL in production. */
static _Atomic(struct platform_clock_source *) g_clock_source = NULL;

const clock_iface_t *clock_default(void)
{
    const clock_iface_t *p = atomic_load_explicit(&g_default,
                                                  memory_order_acquire);
    /* Defensive: should never be NULL because reset restores g_real_iface
     * and set rejects NULL. Belt-and-braces in case a future change
     * regresses one of those. */
    return p ? p : &g_real_iface;
}

int64_t clock_now_monotonic_ns(void)
{
    /* Fast install-hook check; see rng.c:rng_u64 for rationale. */
    struct platform_clock_source *src =
        atomic_load_explicit(&g_clock_source, memory_order_acquire);
    if (src != NULL) {
        /* Source returns microseconds; this entry point is ns. */
        return src->monotonic_us(src->user) * 1000LL;
    }
    const clock_iface_t *p = clock_default();
    return p->now_monotonic_ns(p->self);
}

int64_t clock_now_wall_ms(void)
{
    struct platform_clock_source *src =
        atomic_load_explicit(&g_clock_source, memory_order_acquire);
    if (src != NULL) {
        /* Source returns unix seconds; this entry point is ms. */
        return src->wall_unix(src->user) * 1000LL;
    }
    const clock_iface_t *p = clock_default();
    return p->now_wall_ms(p->self);
}

int64_t clock_now_monotonic_raw_us(void)
{
    struct timespec ts;
#if defined(CLOCK_MONOTONIC_RAW)
    if (clock_gettime(CLOCK_MONOTONIC_RAW, &ts) == 0)
        return (int64_t)ts.tv_sec * 1000000LL + (int64_t)ts.tv_nsec / 1000LL;
    /* CLOCK_MONOTONIC_RAW is a compile-time constant on this platform but can
     * still fail at runtime (unsupported kernel); fall through to the
     * CLOCK_MONOTONIC fallback below rather than returning a stuck zero. */
#endif
    /* No CLOCK_MONOTONIC_RAW available — CLOCK_MONOTONIC is the closest
     * substitute (still never steps backward, just may be gently slewed). */
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
        int e = errno;
        fprintf(stderr, // obs-ok:platform-primitive
            "[platform] %s:%d %s(): clock_gettime(CLOCK_MONOTONIC) fallback failed errno=%d\n",
            __FILE__, __LINE__, __func__, e);
        return 0;
    }
    return (int64_t)ts.tv_sec * 1000000LL + (int64_t)ts.tv_nsec / 1000LL;
}

int64_t clock_thread_cpu_ns(void)
{
    /* MinGW implements CLOCK_THREAD_CPUTIME_ID over GetThreadTimes, whose
     * 15.625 ms scheduler-tick quantization makes sub-quantum work samples
     * pure noise (observed: a constant-time ratio test read lo=31.25 ms,
     * hi=15.62 ms — exact tick multiples — and failed on quantization, not
     * on any real timing divergence). The monotonic wall clock (QPC-backed)
     * is the only fine-grained time source on Windows, and the paired-median
     * callers absorb preemption jitter by design. */
#if defined(CLOCK_THREAD_CPUTIME_ID) && !defined(_WIN32)
    struct timespec ts;
    if (clock_gettime(CLOCK_THREAD_CPUTIME_ID, &ts) == 0)
        return (int64_t)ts.tv_sec * 1000000000LL + (int64_t)ts.tv_nsec;
#endif
    /* No per-thread CPU clock available — fall back to the monotonic wall
     * clock. The work-ratio measurement is less preemption-robust on such a
     * platform but still functions. */
    return real_now_monotonic_ns(NULL);
}

void clock_set_default(const clock_iface_t *iface)
{
    if (!iface) {
        fprintf(stderr,
            "[platform] %s:%d %s(): refusing to install NULL clock iface\n",
            __FILE__, __LINE__, __func__);
        return;
    }
    atomic_store_explicit(&g_default, iface, memory_order_release);
}

void clock_reset_default(void)
{
    atomic_store_explicit(&g_default, &g_real_iface, memory_order_release);
}

void platform_clock_set_source(struct platform_clock_source *src)
{
    if (!src) {
        fprintf(stderr,
            "[platform] %s:%d %s(): refusing NULL — use platform_clock_clear_source\n",
            __FILE__, __LINE__, __func__);
        return;
    }
    atomic_store_explicit(&g_clock_source, src, memory_order_release);
}

void platform_clock_clear_source(void)
{
    atomic_store_explicit(&g_clock_source, NULL, memory_order_release);
}
