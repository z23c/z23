/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Headless acceptance for the bounded cross-platform thread join seam. */


/* pthread_timedjoin_np is a glibc extension, so the Linux arm of
 * platform_thread_join_until() is invisible under a strict
 * -D_POSIX_C_SOURCE=200809L -- which is exactly what the acceptance
 * gate compiles with. Declared here, before any include, the way
 * supervisor.c, thread_registry.c, connman.c and tor_integration.c
 * already do it. A header cannot repair this for us: by the time it
 * is read, libc has already decided what to publish. */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "platform/thread_compat.h"

#include <errno.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <time.h>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#endif

static void *delayed_exit(void *unused)
{
    (void)unused;
#ifdef _WIN32
    Sleep(200);
#else
    struct timespec delay = { .tv_sec = 0, .tv_nsec = 200000000L };
    nanosleep(&delay, NULL);
#endif
    return NULL;
}

static struct timespec deadline_after_ms(int milliseconds)
{
    struct timespec deadline;
#ifdef _WIN32
    /* Same reason as platform/thread_compat.h: mingw-w64 publishes
     * timespec_get() only under _UCRT, so a msvcrt target has no
     * such function. GetSystemTimeAsFileTime always exists. */
    FILETIME ft;
    GetSystemTimeAsFileTime(&ft);
    ULARGE_INTEGER ticks = { .LowPart = ft.dwLowDateTime,
                             .HighPart = ft.dwHighDateTime };
    const uint64_t kUnixEpochTicks = UINT64_C(116444736000000000);
    uint64_t unix_ticks = ticks.QuadPart < kUnixEpochTicks
                              ? 0
                              : ticks.QuadPart - kUnixEpochTicks;
    deadline.tv_sec = (time_t)(unix_ticks / UINT64_C(10000000));
    deadline.tv_nsec = (long)((unix_ticks % UINT64_C(10000000)) * 100);
#else
    (void)timespec_get(&deadline, TIME_UTC);
#endif
    deadline.tv_sec += milliseconds / 1000;
    deadline.tv_nsec += (long)(milliseconds % 1000) * 1000000L;
    if (deadline.tv_nsec >= 1000000000L) {
        deadline.tv_sec++;
        deadline.tv_nsec -= 1000000000L;
    }
    return deadline;
}

int main(void)
{
    pthread_t thread;
    /* This is a headless acceptance program for platform_thread_join_until()
     * itself: thread_registry is that primitive's CALLER in production
     * code, not its subject here, so routing this spawn through the
     * registry would test the wrong thing -- it deliberately stays bare. */
    /* raw-pthread-ok: thread-join-primitive-under-test */
    if (pthread_create(&thread, NULL, delayed_exit, NULL) != 0)
        return 1;

    struct timespec short_deadline = deadline_after_ms(20);
    if (platform_thread_join_until(thread, NULL, &short_deadline) != ETIMEDOUT) {
        fprintf(stderr, "thread join did not honor short deadline\n");
        return 2;
    }

    struct timespec long_deadline = deadline_after_ms(2000);
    if (platform_thread_join_until(thread, NULL, &long_deadline) != 0) {
        fprintf(stderr, "thread join did not reap completed worker\n");
        return 3;
    }

    puts("thread_join_acceptance: ok");
    return 0;
}
