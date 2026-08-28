/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Small platform time helpers for time_t/timespec call sites.
 * Prefer clock_now_* directly in new code; these wrappers keep C library
 * time shapes routed through platform.clock.
 */

#ifndef ZCL_PLATFORM_TIME_COMPAT_H
#define ZCL_PLATFORM_TIME_COMPAT_H

#include "platform/clock.h"

#include <stdbool.h>
#include <stdint.h>
#include <time.h>

static inline int64_t platform_time_wall_unix(void)
{
    return clock_now_wall_ms() / 1000;
}

static inline time_t platform_time_wall_time_t(void)
{
    return (time_t)platform_time_wall_unix();
}

static inline bool platform_time_utc_tm(time_t value, struct tm *out)
{
    if (!out) return false;
#if defined(_WIN32)
    return gmtime_s(out, &value) == 0;
#else
    return gmtime_r(&value, out) != NULL;
#endif
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
    struct timespec ts = { ms / 1000, (ms % 1000) * 1000000L };
    nanosleep(&ts, NULL);
}

#endif /* ZCL_PLATFORM_TIME_COMPAT_H */
