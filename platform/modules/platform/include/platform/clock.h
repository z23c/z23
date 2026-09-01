/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Injectable clock interface.
 *
 * Why:
 *   Half the bugs in a node like this hide behind "real time". The
 *   watchdog stall window, the IBD lag SLO, retry backoffs, fee-rate
 *   smoothing — all read `clock_gettime` directly unless they use this
 *   platform boundary. Tests and the deterministic simulator can
 *   fast-forward through the same API that production uses for real time.
 *
 *   This header offers a one-pointer abstraction: production resolves
 *   to a static vtable that wraps `clock_gettime` (the same syscalls
 *   today's call sites use), and tests/simulator can install a virtual
 *   clock with `clock_set_default(...)`.
 *
 * The simulator wires its own `clock_iface_t` whose `now_*` cell reads from a
 * virtual clock advanced by the scheduler.
 *
 * Thread safety:
 *   `clock_set_default` / `clock_reset_default` are atomic pointer
 *   swaps, so callers can swap the default from a test thread while
 *   another thread reads `clock_now_monotonic_ns()`. Production code
 *   never calls the swappers.
 */

#ifndef ZCL_PLATFORM_CLOCK_H
#define ZCL_PLATFORM_CLOCK_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct clock_iface clock_iface_t;

struct clock_iface {
    int64_t (*now_monotonic_ns)(void *self);
    int64_t (*now_wall_ms)(void *self);
    void    *self;
};

/* Returns the process default vtable. Always non-NULL.
 *
 * The default wraps real syscalls (`clock_gettime(CLOCK_MONOTONIC,...)`
 * + `clock_gettime(CLOCK_REALTIME,...)`). The pointer itself may be
 * swapped by `clock_set_default`; this returns whatever is current. */
const clock_iface_t *clock_default(void);

/* Convenience readers — equivalent to
 *   clock_default()->now_monotonic_ns(clock_default()->self).
 * Use these for one-shot reads; cache `clock_default()` in a local
 * only when you genuinely call it in a hot inner loop. */
int64_t clock_now_monotonic_ns(void);
int64_t clock_now_wall_ms(void);

/* CLOCK_MONOTONIC_RAW microseconds — the hardware monotonic counter with NO
 * NTP frequency-slewing applied (unlike CLOCK_MONOTONIC, which a running
 * `ntpd`/`chronyd` can gently speed up or slow down to converge on true
 * time). This is the intended clock for the time-discipline organ
 * (util/time_authority.h): it needs a monotonic reference that is itself
 * immune to the very adjustment it is trying to detect in the OTHER two
 * clocks (now_monotonic_ns / now_wall_ms). Falls back to CLOCK_MONOTONIC on
 * a platform/kernel without CLOCK_MONOTONIC_RAW (pre-2.6.28 Linux, some
 * non-Linux libcs) so the return value is always well-defined.
 *
 * Deliberately NOT part of the injectable clock_iface_t / tape-source
 * surface — same rationale as clock_thread_cpu_ns() below: it measures a
 * real hardware property (no NTP correction applied) that a simulated/
 * fast-forwarded clock cannot meaningfully model, and the one caller that
 * needs it is specifically trying to observe drift in the adjustable
 * clocks relative to this unadjusted one. Injecting it would erase the
 * signal it exists to measure. */
int64_t clock_now_monotonic_raw_us(void);

/* Per-thread CPU time in nanoseconds — only accrues while THIS thread is
 * executing on a core, so it is immune to cross-process scheduler preemption.
 * That is the correct clock for a constant-time work-ratio measurement: it
 * counts the work the algorithm does, not the wall time the OS gave us. Falls
 * back to the monotonic wall clock on platforms without a per-thread CPU clock.
 *
 * Deliberately not injectable — it measures real on-core work, which the
 * simulator's virtual clock cannot meaningfully model. The single caller is
 * the constant-time timing gate in the crypto tests. */
int64_t clock_thread_cpu_ns(void);

/* Swap the process-wide default. Intended for tests and the
 * deterministic simulator only — production code never calls this.
 *
 * `iface` must outlive every concurrent reader (typically static
 * storage). Passing NULL is rejected (no-op). */
void clock_set_default(const clock_iface_t *iface);

/* Restore the real-syscall default. Safe to call any number of times. */
void clock_reset_default(void);

/* Install-hook API for the seed tape / simulator.
 *
 * The install-hook is a thinner, faster path than `clock_set_default`:
 * it intercepts the two convenience readers (`clock_now_monotonic_ns`,
 * `clock_now_wall_ms`) that are the simulator's hot path. Default
 * behavior is unchanged when no source is installed (one atomic_load
 * + predictable branch, <5 ns in production).
 *
 * The source vtable is in microseconds (the units the simulator
 * naturally tracks). Conversion to/from ns and ms happens in the
 * wrapper. Wall is in unix seconds — the conversion adds zero cost
 * on the production path (which is never installed).
 *
 * Thread safety: see `platform_rng_set_source`. */
struct platform_clock_source {
    int64_t (*monotonic_us)(void *user);
    int64_t (*wall_unix)(void *user);  /* unix epoch seconds */
    void *user;
};

/* Install a tape-driven (or otherwise injected) source. The `src`
 * pointer must outlive every concurrent reader. NULL is rejected —
 * use `platform_clock_clear_source` instead. */
void platform_clock_set_source(struct platform_clock_source *src);

/* Restore the default (real clock_gettime) path. */
void platform_clock_clear_source(void);

#ifdef __cplusplus
}
#endif

#endif /* ZCL_PLATFORM_CLOCK_H */
