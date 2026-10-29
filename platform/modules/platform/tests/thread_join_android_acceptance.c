/* Copyright 2026 Rhett Creighton - Apache License 2.0 */
#define _GNU_SOURCE
#include "platform/thread_compat.h"

#include <stdatomic.h>
#include <stdio.h>

#ifndef __ANDROID__
#error This acceptance test requires Android Bionic.
#endif

static atomic_bool release_worker;
static atomic_bool destructor_entered;
static atomic_int worker_error;
static pthread_key_t destructor_key;
static int result_token;

static void pause_once(void)
{
    struct timespec delay = { .tv_nsec = 1000000L };
    (void)nanosleep(&delay, NULL);
}

static void wait_for_release(void *value)
{
    if (value != &result_token)
        atomic_store(&worker_error, EINVAL);
    atomic_store(&destructor_entered, true);
    while (!atomic_load(&release_worker))
        pause_once();
}

static void *worker(void *unused)
{
    (void)unused;
    int rc = pthread_setspecific(destructor_key, &result_token);
    if (rc != 0)
        atomic_store(&worker_error, rc);
    return &result_token;
}

static bool deadline_after_ms(long milliseconds, struct timespec *deadline)
{
    if (clock_gettime(CLOCK_REALTIME, deadline) != 0)
        return false;
    deadline->tv_nsec += milliseconds * 1000000L;
    deadline->tv_sec += deadline->tv_nsec / 1000000000L;
    deadline->tv_nsec %= 1000000000L;
    return true;
}

#define CHECK(condition) do { \
    if (!(condition)) { \
        fprintf(stderr, "FAIL line %d: %s (worker_error=%d)\n", \
                __LINE__, #condition, atomic_load(&worker_error)); \
        goto cleanup; \
    } \
} while (0)

static bool wait_destructor(void)
{
    struct timespec deadline;
    CHECK(deadline_after_ms(2000, &deadline));
    while (!atomic_load(&destructor_entered)) {
        struct timespec now;
        CHECK(atomic_load(&worker_error) == 0);
        CHECK(clock_gettime(CLOCK_REALTIME, &now) == 0);
        CHECK(now.tv_sec < deadline.tv_sec ||
              (now.tv_sec == deadline.tv_sec && now.tv_nsec < deadline.tv_nsec));
        pause_once();
    }
    return atomic_load(&worker_error) == 0;
cleanup:
    return false;
}

static bool test_iteration(void)
{
    bool owned = false;
    bool ok = false;
    pthread_t thread;
    struct timespec deadline;
    void *result = NULL;
    atomic_store(&release_worker, false);
    atomic_store(&destructor_entered, false);
    atomic_store(&worker_error, 0);
    /* raw-pthread-ok: standalone test owns the complete join lifecycle. */
    CHECK(pthread_create(&thread, NULL, worker, NULL) == 0);
    owned = true;
    CHECK(wait_destructor());
    int rc = platform_thread_tryjoin(thread, &result);
    if (rc == 0) owned = false;
    CHECK(rc == EBUSY);
    CHECK(deadline_after_ms(2, &deadline));
    rc = platform_thread_join_until(thread, &result, &deadline);
    if (rc == 0) owned = false;
    CHECK(rc == ETIMEDOUT);
    CHECK(result == NULL);
    atomic_store(&release_worker, true);
    CHECK(deadline_after_ms(2000, &deadline));
    rc = platform_thread_join_until(thread, &result, &deadline);
    if (rc == 0) owned = false;
    CHECK(rc == 0);
    CHECK(result == &result_token);
    CHECK(atomic_load(&worker_error) == 0);
    ok = true;
cleanup:
    atomic_store(&release_worker, true);
    if (owned && pthread_join(thread, NULL) != 0) {
        fputs("FAIL cleanup join\n", stderr);
        ok = false;
    }
    return ok;
}

static bool test_errors(void)
{
    struct timespec deadline;
    CHECK(deadline_after_ms(0, &deadline));
    CHECK(platform_thread_join_until(pthread_self(), NULL, &deadline) == EDEADLK);
    CHECK(platform_thread_join_until(pthread_self(), NULL, NULL) == EINVAL);
    deadline.tv_nsec = 1000000000L;
    CHECK(platform_thread_join_until(pthread_self(), NULL, &deadline) == EINVAL);
    return true;
cleanup:
    return false;
}

int main(void)
{
    bool key_created = false;
    int status = 1;
    CHECK(pthread_key_create(&destructor_key, wait_for_release) == 0);
    key_created = true;
    for (int iteration = 0; iteration < 64; ++iteration)
        CHECK(test_iteration());
    CHECK(test_errors());
    status = 0;
cleanup:
    if (key_created && pthread_key_delete(destructor_key) != 0)
        status = 1;
    if (status != 0)
        return status;
    puts("PASS Android bounded join: live destructor, timeout, retry, result, self");
    return 0;
}
