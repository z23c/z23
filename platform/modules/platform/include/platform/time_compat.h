/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Small platform time helpers for time_t/timespec call sites.
 * Prefer clock_now_* directly in new code; these wrappers keep C library
 * time shapes routed through platform.clock.
 */

#ifndef ZCL_PLATFORM_TIME_COMPAT_H
#define ZCL_PLATFORM_TIME_COMPAT_H

#include "base/utc_tm.h"
#include "platform/clock.h"

#include <stdbool.h>
#include <stdint.h>
#include <time.h>
#if defined(_WIN32)
#include <windows.h>
#endif

static inline int64_t platform_time_wall_unix(void)
{
    return clock_now_wall_ms() / 1000;
}

static inline time_t platform_time_wall_time_t(void)
{
    return (time_t)platform_time_wall_unix();
}

/* Forwards to base. log_level.c -- the sink platform.clock itself logs
 * through -- needs this conversion and cannot include platform, so base
 * owns the definition and this stays the name the rest of the tree uses. */
static inline bool platform_time_utc_tm(time_t value, struct tm *out)
{
    return zcl_utc_tm(value, out);
}

static inline int platform_time_monotonic_timespec(struct timespec *ts)
{
    if (!ts) return -1;
    int64_t ns = clock_now_monotonic_ns();
    ts->tv_sec = (time_t)(ns / 1000000000LL);
    ts->tv_nsec = (long)(ns % 1000000000LL);
    return 0;
}

static inline int platform_time_realtime_timespec(struct timespec *ts)
{
    if (!ts) return -1;
    int64_t ms = clock_now_wall_ms();
    ts->tv_sec = (time_t)(ms / 1000LL);
    ts->tv_nsec = (long)((ms % 1000LL) * 1000000LL);
    return 0;
}

static inline int64_t platform_time_realtime_us(void)
{
    return clock_now_wall_ms() * 1000LL;
}

static inline int64_t platform_time_monotonic_us(void)
{
    return clock_now_monotonic_ns() / 1000;
}

static inline int64_t platform_time_monotonic_ms(void)
{
    return clock_now_monotonic_ns() / 1000000;
}

/* Sleep helper: deliberately uses raw nanosleep and does NOT route
 * through platform.clock — sleeping is not a clock read. Matches the
 * prior behavior of the per-service sleep_ms wrappers it replaces. */
static inline void platform_sleep_ms(int ms)
{
#if defined(_WIN32)
    if (ms > 0) Sleep((DWORD)ms);
#else
    struct timespec ts = { ms / 1000, (ms % 1000) * 1000000L };
    nanosleep(&ts, NULL);
#endif
}

#endif /* ZCL_PLATFORM_TIME_COMPAT_H */
