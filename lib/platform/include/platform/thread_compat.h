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

static inline int platform_thread_join_until(pthread_t thread,
                                             void **result,
                                             const struct timespec *deadline)
{
#if defined(__linux__)
    return pthread_timedjoin_np(thread, result, deadline);
#else
    (void)deadline;
    return pthread_join(thread, result);
#endif
}

#endif
