/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

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
