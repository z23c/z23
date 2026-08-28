/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: bounded pthread_join for shutdown paths (supervisor,
 * thread_registry, connman, gap_fill_service) that must not hang forever on
 * a stuck worker. Linux's pthread_timedjoin_np() enforces the deadline; on
 * hosts without it (Darwin) this falls back to a plain, UNTIMED
 * pthread_join(), so a caller relying on the deadline there can still hang —
 * callers on that path need their own outer timeout. */

#ifndef ZCL_PLATFORM_THREAD_COMPAT_H
#define ZCL_PLATFORM_THREAD_COMPAT_H

#include <pthread.h>
#include <time.h>

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <errno.h>
#include <stdint.h>
#endif

static inline int platform_thread_join_until(pthread_t thread,
                                             void **result,
                                             const struct timespec *deadline)
{
#if defined(_WIN32)
    if (!deadline)
        return EINVAL;
    /* Win32 epoch time directly, not timespec_get(): that is a C11
     * function mingw-w64 declares only under _UCRT, so on a msvcrt
     * target it does not exist at all and this arm would not compile.
     * GetSystemTimeAsFileTime is always present and needs nothing
     * beyond the <windows.h> this arm already includes. */
    FILETIME ft;
    GetSystemTimeAsFileTime(&ft);
    ULARGE_INTEGER ticks = { .LowPart = ft.dwLowDateTime,
                             .HighPart = ft.dwHighDateTime };
    /* FILETIME counts 100ns ticks from 1601-01-01; shift to the Unix
     * epoch so the caller-supplied deadline is on the same scale. */
    const uint64_t kUnixEpochTicks = UINT64_C(116444736000000000);
    uint64_t unix_ticks = ticks.QuadPart < kUnixEpochTicks
                              ? 0
                              : ticks.QuadPart - kUnixEpochTicks;
    struct timespec now = {
        .tv_sec = (time_t)(unix_ticks / UINT64_C(10000000)),
        .tv_nsec = (long)((unix_ticks % UINT64_C(10000000)) * 100),
    };
    int64_t remaining_ns =
        ((int64_t)deadline->tv_sec - (int64_t)now.tv_sec) * INT64_C(1000000000) +
        ((int64_t)deadline->tv_nsec - (int64_t)now.tv_nsec);
    DWORD wait_ms = 0;
    if (remaining_ns > 0) {
        uint64_t rounded_ms = ((uint64_t)remaining_ns + UINT64_C(999999)) /
                              UINT64_C(1000000);
        wait_ms = rounded_ms >= (uint64_t)INFINITE ? INFINITE - 1u
                                                    : (DWORD)rounded_ms;
    }
    HANDLE handle = (HANDLE)pthread_gethandle(thread);
    if (!handle)
        return ESRCH;
    DWORD wait_result = WaitForSingleObject(handle, wait_ms);
    if (wait_result == WAIT_TIMEOUT)
        return ETIMEDOUT;
    if (wait_result != WAIT_OBJECT_0)
        return EINVAL;
    return pthread_join(thread, result);
#elif defined(__linux__)
    return pthread_timedjoin_np(thread, result, deadline);
#else
    (void)deadline;
    return pthread_join(thread, result);
#endif
}

#endif
