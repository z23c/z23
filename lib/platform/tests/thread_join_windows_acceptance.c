/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: Verify the bounded cross-platform thread join seam. */

#include "platform/thread_compat.h"

#include <errno.h>
#include <pthread.h>
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
    (void)timespec_get(&deadline, TIME_UTC);
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
    /* raw-pthread-ok: acceptance owns and joins the only worker */
    if (pthread_create(&thread, NULL, delayed_exit, NULL) != 0)
        return 1;

    struct timespec short_deadline = deadline_after_ms(20);
    if (platform_thread_join_until(thread, NULL, &short_deadline) != ETIMEDOUT) {
        fprintf(stderr,  // obs-ok:acceptance-failure-exits-synchronously
                "thread join did not honor short deadline\n");
        return 2;
    }

    struct timespec long_deadline = deadline_after_ms(2000);
    if (platform_thread_join_until(thread, NULL, &long_deadline) != 0) {
        fprintf(stderr,  // obs-ok:acceptance-failure-exits-synchronously
                "thread join did not reap completed worker\n");
        return 3;
    }

    puts("thread_join_acceptance: ok");
    return 0;
}
