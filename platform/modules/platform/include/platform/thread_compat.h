/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: bounded pthread_join for shutdown paths (supervisor,
 * thread_registry, connman, gap_fill_service) that must not hang forever on
 * a stuck worker. Linux's pthread_timedjoin_np() and Win32's waitable thread
 * handles enforce the deadline directly. Android polls Bionic's retained
 * thread tid before joining. Darwin has neither API, so it polls
 * pthread_kill(thread, 0) for ESRCH (exited, still unjoined) and only then
 * joins. It never cancels a thread inside pthread_join (ThreadSanitizer
 * CHECK-fails on that) and never joins twice; a timed-out target stays
 * joinable for a later final drain. */

#ifndef ZCL_PLATFORM_THREAD_COMPAT_H
#define ZCL_PLATFORM_THREAD_COMPAT_H

#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <time.h>

#if defined(__ANDROID__)
#include <errno.h>

/* The caller owns a joinable thread and excludes concurrent join/detach.
 * Bionic retains its thread record until join and the kernel clears its tid
 * on exit. Only tid zero proves that pthread_join will not wait for exit.
 * A positive tid can be recycled, so thread-directed signals are unsuitable. */
static inline int platform_thread_tryjoin(pthread_t thread, void **result)
{
    if (pthread_equal(thread, pthread_self()))
        return EDEADLK;
    pid_t tid = pthread_gettid_np(thread);
    if (tid < 0)
        return ESRCH;
    if (tid != 0)
        return EBUSY;
    return pthread_join(thread, result);
}
#endif

#if defined(__APPLE__)
#include <errno.h>
#include <signal.h>

/* The caller owns a joinable thread and excludes concurrent join/detach.
 * On Darwin an exited-but-unjoined thread keeps its pthread_t valid and
 * pthread_kill(thread, 0) reports ESRCH for it (verified on macOS), while a
 * live thread reports 0. pthread_join then returns without blocking. No
 * helper thread is created and nothing is canceled: the target stays
 * joinable until the one pthread_join the caller makes after it has exited,
 * so a timed-out caller can retry or fall back to a plain pthread_join. */
static inline int platform_thread_tryjoin(pthread_t thread, void **result)
{
    if (pthread_equal(thread, pthread_self()))
        return EDEADLK;
    int alive = pthread_kill(thread, 0);
    if (alive == 0)
        return EBUSY;
    if (alive != ESRCH)
        return alive;
    return pthread_join(thread, result);
}
#endif

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
#elif defined(__ANDROID__) || defined(__APPLE__)
    if (!deadline || deadline->tv_nsec < 0 || deadline->tv_nsec >= 1000000000L)
        return EINVAL;
    for (;;) {
        int rc = platform_thread_tryjoin(thread, result);
        if (rc != EBUSY)
            return rc;
        struct timespec now;
        if (clock_gettime(CLOCK_REALTIME, &now) != 0)
            return errno;
        if (now.tv_sec > deadline->tv_sec ||
            (now.tv_sec == deadline->tv_sec && now.tv_nsec >= deadline->tv_nsec))
            return ETIMEDOUT;
        struct timespec delay = { .tv_sec = 0, .tv_nsec = 1000000L };
        if (now.tv_sec == deadline->tv_sec &&
            deadline->tv_nsec - now.tv_nsec < delay.tv_nsec)
            delay.tv_nsec = deadline->tv_nsec - now.tv_nsec;
        if (nanosleep(&delay, NULL) != 0 && errno != EINTR)
            return errno;
    }
#elif defined(__linux__)
    return pthread_timedjoin_np(thread, result, deadline);
#else
    (void)deadline;
    return pthread_join(thread, result);
#endif
}

/* Bounded mutex acquire: true when *m was locked within wait_ns, false on
 * timeout or any error (the caller never waits unbounded). Where
 * pthread_mutex_timedlock exists it enforces an absolute CLOCK_REALTIME
 * deadline. Darwin has no such call, so its arm retries pthread_mutex_trylock
 * against a CLOCK_MONOTONIC deadline with a short sleep between tries. A
 * non-positive wait_ns is a single try. */
static inline bool platform_mutex_lock_bounded_ns(pthread_mutex_t *m,
                                                  int64_t wait_ns)
{
    if (!m)
        return false;
    if (wait_ns < 0)
        wait_ns = 0;
#if defined(__APPLE__)
    struct timespec start;
    if (clock_gettime(CLOCK_MONOTONIC, &start) != 0) // platform-ok: bounded trylock deadline is a kernel measured interval
        return pthread_mutex_trylock(m) == 0;
    for (;;) {
        if (pthread_mutex_trylock(m) == 0)
            return true;
        struct timespec now;
        if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) // platform-ok: bounded trylock deadline is a kernel measured interval
            return false;
        int64_t elapsed_ns =
            ((int64_t)now.tv_sec - (int64_t)start.tv_sec) * INT64_C(1000000000) +
            ((int64_t)now.tv_nsec - (int64_t)start.tv_nsec);
        if (elapsed_ns >= wait_ns)
            return false;
        int64_t left_ns = wait_ns - elapsed_ns;
        struct timespec delay = { .tv_sec = 0, .tv_nsec = 500000L };
        if (left_ns < delay.tv_nsec)
            delay.tv_nsec = (long)left_ns;
        (void)nanosleep(&delay, NULL);
    }
#else
    struct timespec dl;
    if (clock_gettime(CLOCK_REALTIME, &dl) != 0) // platform-ok: timedlock needs an absolute CLOCK_REALTIME deadline
        return pthread_mutex_trylock(m) == 0;
    int64_t ns = (int64_t)dl.tv_nsec + wait_ns % INT64_C(1000000000);
    dl.tv_sec += (time_t)(wait_ns / INT64_C(1000000000)) +
                 (time_t)(ns / INT64_C(1000000000));
    dl.tv_nsec = (long)(ns % INT64_C(1000000000));
    return pthread_mutex_timedlock(m, &dl) == 0;
#endif
}

#endif
