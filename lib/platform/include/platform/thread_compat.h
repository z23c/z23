/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: bounded pthread_join for shutdown paths (supervisor,
 * thread_registry, connman, gap_fill_service) that must not hang forever on
 * a stuck worker. Linux's pthread_timedjoin_np() and Win32's waitable thread
 * handles enforce the deadline directly. Darwin has neither API, so its arm
 * uses a short-lived join waiter: canceling a waiter blocked in pthread_join()
 * leaves the target joinable, preserving ownership for a later final drain. */

#ifndef ZCL_PLATFORM_THREAD_COMPAT_H
#define ZCL_PLATFORM_THREAD_COMPAT_H

#include <pthread.h>
#include <time.h>

#if defined(__APPLE__)
#include <errno.h>
#include <stdbool.h>
#include <stdlib.h>

struct platform_darwin_join_context {
    pthread_t target;
    pthread_mutex_t mutex;
    pthread_cond_t condition;
    bool finished;
    int target_join_rc;
    void *target_result;
};

static inline void *platform_darwin_join_waiter(void *opaque)
{
    struct platform_darwin_join_context *context = opaque;
    void *target_result = NULL;
    int target_join_rc = pthread_join(context->target, &target_result);

    /* After pthread_join() returns there are deliberately no cancellation
     * points before publication. A concurrent timeout may request
     * cancellation, but it cannot steal a target that this waiter reaped. */
    (void)pthread_mutex_lock(&context->mutex);
    context->target_join_rc = target_join_rc;
    context->target_result = target_result;
    context->finished = true;
    (void)pthread_cond_broadcast(&context->condition);
    (void)pthread_mutex_unlock(&context->mutex);
    return NULL;
}

static inline void platform_darwin_join_context_destroy(
    struct platform_darwin_join_context *context)
{
    (void)pthread_cond_destroy(&context->condition);
    (void)pthread_mutex_destroy(&context->mutex);
    free(context);
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
#elif defined(__linux__)
    return pthread_timedjoin_np(thread, result, deadline);
#elif defined(__APPLE__)
    if (!deadline)
        return EINVAL;

    /* The context is heap-backed so even an impossible owned-helper join
     * failure cannot turn into a use-after-return. That failure leaks this
     * small context intentionally and reports the pthread error; normal and
     * timeout paths always destroy it. */
    /* The platform layer cannot depend upward on util/safe_alloc.h. */
    struct platform_darwin_join_context *context = calloc( // raw-alloc-ok:platform-layer
        1, sizeof(*context));
    if (!context)
        return ENOMEM;
    context->target = thread;

    int rc = pthread_mutex_init(&context->mutex, NULL);
    if (rc != 0) {
        free(context);
        return rc;
    }
    rc = pthread_cond_init(&context->condition, NULL);
    if (rc != 0) {
        (void)pthread_mutex_destroy(&context->mutex);
        free(context);
        return rc;
    }

    pthread_t waiter;
    rc = pthread_create(&waiter, NULL, platform_darwin_join_waiter, context);
    if (rc != 0) {
        platform_darwin_join_context_destroy(context);
        return rc;
    }

    bool finished_before_cancel = false;
    rc = pthread_mutex_lock(&context->mutex);
    if (rc == 0) {
        while (!context->finished) {
            rc = pthread_cond_timedwait(&context->condition,
                                        &context->mutex, deadline);
            if (rc != 0)
                break;
        }
        finished_before_cancel = context->finished;
        (void)pthread_mutex_unlock(&context->mutex);
    }

    if (rc != 0 && !finished_before_cancel) {
        /* POSIX requires a target of a canceled pthread_join() to remain
         * joinable. This is what lets the caller retry or retain ownership
         * for its process-level shutdown watchdog. */
        int cancel_rc = pthread_cancel(waiter);
        if (cancel_rc != 0)
            return cancel_rc;
    }

    int waiter_join_rc = pthread_join(waiter, NULL);
    if (waiter_join_rc != 0)
        return waiter_join_rc;

    /* A target can finish while the timeout path is requesting cancellation.
     * In that race the waiter publishes its successful join before exiting;
     * prefer the observed completion over a stale ETIMEDOUT. */
    if (context->finished) {
        rc = context->target_join_rc;
        if (rc == 0 && result)
            *result = context->target_result;
    }
    platform_darwin_join_context_destroy(context);
    return rc;
#else
    (void)deadline;
    return pthread_join(thread, result);
#endif
}

#endif
