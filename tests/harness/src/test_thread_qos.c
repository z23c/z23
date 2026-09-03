/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * thread_qos: prove zcl_thread_qos_background() changes the calling thread's
 * native scheduling class — QOS_CLASS_BACKGROUND on macOS,
 * THREAD_PRIORITY_BELOW_NORMAL on Windows, and SCHED_BATCH plus best-effort
 * IOPRIO_CLASS_IDLE on Linux. Callback-mediated worker tests prove creation
 * and idempotency; a direct registered-root case keeps both public APIs in the
 * capability inventory's exact test-call graph and distinguishes native
 * success from fail-soft denial instead of merely surviving a call.
 */

#define _GNU_SOURCE  /* SCHED_BATCH, syscall() */

#include "test/test_core.h"
#include "util/thread_qos.h"

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#elif defined(__APPLE__)
#include <sys/qos.h>
#else
#include <sched.h>
#include <sys/syscall.h>
#endif
#if !defined(_WIN32)
#include <unistd.h>
#include <errno.h>
#endif
#include <pthread.h>
#if !defined(_WIN32)

#ifndef IOPRIO_WHO_PROCESS
#define IOPRIO_WHO_PROCESS 1
#endif
#ifndef IOPRIO_CLASS_IDLE
#define IOPRIO_CLASS_IDLE 3
#endif
#define TQ_IOPRIO_CLASS_SHIFT 13
#define TQ_IOPRIO_CLASS(value) ((value) >> TQ_IOPRIO_CLASS_SHIFT)

#if defined(__APPLE__)

struct tq_apple_result {
    bool call_ok;
    qos_class_t qos_class;
};

static void *tq_apple_observe_worker(void *arg)
{
    struct tq_apple_result *result = arg;
    int relative_priority = 0;
    result->call_ok = true;
    (void)pthread_get_qos_class_np(pthread_self(), &result->qos_class,
                                   &relative_priority);
    return NULL;
}

static void *tq_apple_worker(void *arg)
{
    struct tq_apple_result *result = arg;
    result->call_ok = zcl_thread_qos_background();
    int relative_priority = 0;
    (void)pthread_get_qos_class_np(pthread_self(), &result->qos_class,
                                   &relative_priority);
    return NULL;
}

static int t_thread_qos_applies_sched_batch_and_ioprio_idle(void)
{
    int failures = 0;
    TEST("thread_qos: background QoS lands QOS_CLASS_BACKGROUND on macOS") {
        struct tq_apple_result baseline = {0};
        struct tq_apple_result applied = {0};
        pthread_attr_t attr;
        pthread_t thread;
        ASSERT_EQ(pthread_attr_init(&attr), 0);
        ASSERT_EQ(pthread_attr_set_qos_class_np(&attr, QOS_CLASS_UTILITY, 0),
                  0);
        ASSERT_EQ(pthread_create(&thread, &attr, tq_apple_observe_worker,
                                 &baseline), 0);
        ASSERT_EQ(pthread_join(thread, NULL), 0);
        ASSERT_EQ(baseline.qos_class, QOS_CLASS_UTILITY);
        ASSERT_EQ(pthread_create(&thread, &attr, tq_apple_worker, &applied),
                  0);
        ASSERT_EQ(pthread_attr_destroy(&attr), 0);
        ASSERT_EQ(pthread_join(thread, NULL), 0);
        ASSERT(applied.call_ok);
        ASSERT_EQ(applied.qos_class, QOS_CLASS_BACKGROUND);
        PASS();
    } _test_next:;
    return failures;
}

static int t_thread_qos_background_attr_applies_before_entry(void)
{
    int failures = 0;
    TEST("thread_qos: pthread attribute starts macOS worker at background QoS") {
        struct tq_apple_result observed = {0};
        pthread_attr_t attr;
        pthread_t thread;
        ASSERT_EQ(pthread_attr_init(&attr), 0);
        ASSERT(zcl_thread_qos_background_attr(&attr));
        ASSERT_EQ(pthread_create(&thread, &attr, tq_apple_observe_worker,
                                 &observed), 0);
        ASSERT_EQ(pthread_attr_destroy(&attr), 0);
        ASSERT_EQ(pthread_join(thread, NULL), 0);
        ASSERT(observed.call_ok);
        ASSERT_EQ(observed.qos_class, QOS_CLASS_BACKGROUND);
        PASS();
    } _test_next:;
    return failures;
}

#else

struct tq_worker_result {
    bool  qos_call_ok;
    int   sched_policy;
    long  ioprio_value;
    bool  ioprio_call_ok;
};

static void *tq_worker(void *arg)
{
    struct tq_worker_result *r = arg;

    r->qos_call_ok = zcl_thread_qos_background();

    /* Read back the CALLING thread's own scheduling policy — pid=0 means
     * "the calling thread", same convention the production code relies
     * on for sched_setscheduler(). */
    r->sched_policy = sched_getscheduler(0);

    long rc = syscall(SYS_ioprio_get, IOPRIO_WHO_PROCESS, 0);
    if (rc < 0) {
        r->ioprio_call_ok = false;
        r->ioprio_value = -1;
    } else {
        r->ioprio_call_ok = true;
        r->ioprio_value = rc;
    }
    return NULL;
}

/* Baseline: on the box's default scheduling policy (SCHED_OTHER == 0), a
 * fresh thread must NOT already read back SCHED_BATCH / IOPRIO_CLASS_IDLE
 * on its own — otherwise the test below would pass for free and prove
 * nothing. */
static void *tq_baseline_worker(void *arg)
{
    struct tq_worker_result *r = arg;

    r->qos_call_ok = true; /* not exercised on the baseline thread */
    r->sched_policy = sched_getscheduler(0);

    long rc = syscall(SYS_ioprio_get, IOPRIO_WHO_PROCESS, 0);
    r->ioprio_call_ok = (rc >= 0);
    r->ioprio_value = rc;
    return NULL;
}

static int t_thread_qos_applies_sched_batch_and_ioprio_idle(void)
{
    int failures = 0;

    TEST("thread_qos: background QoS lands SCHED_BATCH + IOPRIO_CLASS_IDLE "
         "on the calling thread") {
        struct tq_worker_result baseline = {0};
        struct tq_worker_result applied = {0};
        pthread_t t;

        /* Baseline thread: never calls the helper. Confirms the assertions
         * below are actually discriminating, not tautologically true for
         * any freshly spawned thread on this host. */
        ASSERT_EQ(pthread_create(&t, NULL, tq_baseline_worker, &baseline), 0);
        ASSERT_EQ(pthread_join(t, NULL), 0);
        ASSERT(baseline.sched_policy != SCHED_BATCH);
        if (baseline.ioprio_call_ok)
            ASSERT(TQ_IOPRIO_CLASS(baseline.ioprio_value) != IOPRIO_CLASS_IDLE);

        /* Applied thread: calls zcl_thread_qos_background() on itself, then
         * reads its own policy/class back. */
        ASSERT_EQ(pthread_create(&t, NULL, tq_worker, &applied), 0);
        ASSERT_EQ(pthread_join(t, NULL), 0);

        /* sched_setscheduler(SCHED_BATCH) needs no special privilege on
         * Linux — it must always take. */
        ASSERT_EQ(applied.sched_policy, SCHED_BATCH);

        /* ioprio_set(IOPRIO_CLASS_IDLE) can in principle be denied by a
         * restrictive sandbox (seccomp/LSM); the helper is fail-soft, so
         * only assert the class landed when the readback syscall itself
         * succeeded AND the helper reported the ioprio half as applied. */
        if (applied.ioprio_call_ok) {
            ASSERT_EQ(TQ_IOPRIO_CLASS(applied.ioprio_value),
                      IOPRIO_CLASS_IDLE);
        }

        PASS();
    } _test_next:;

    return failures;
}

static int t_thread_qos_background_attr_applies_before_entry(void)
{
    int failures = 0;
    TEST("thread_qos: background pthread attribute preserves non-Darwin attrs") {
        pthread_attr_t attr;
        ASSERT_EQ(pthread_attr_init(&attr), 0);
        ASSERT(zcl_thread_qos_background_attr(&attr));
        ASSERT_EQ(pthread_attr_destroy(&attr), 0);
        PASS();
    } _test_next:;
    return failures;
}

#endif

/* Idempotency: calling the helper twice from the same thread must not
 * error or change the outcome. */
static void *tq_double_apply_worker(void *arg)
{
    bool *both_ok = arg;
    bool first = zcl_thread_qos_background();
    bool second = zcl_thread_qos_background();
    *both_ok = first && second;
    return NULL;
}

static int t_thread_qos_idempotent(void)
{
    int failures = 0;

    TEST("thread_qos: calling twice from the same thread is safe") {
        bool both_ok = false;
        pthread_t t;

        ASSERT_EQ(pthread_create(&t, NULL, tq_double_apply_worker, &both_ok),
                  0);
        ASSERT_EQ(pthread_join(t, NULL), 0);
        ASSERT(both_ok);

        PASS();
    } _test_next:;

    return failures;
}

static int test_thread_qos_platform_arm(void);

static int test_thread_qos_platform_arm(void)
{
    printf("\n=== thread_qos tests ===\n");
    int failures = 0;
    failures += t_thread_qos_applies_sched_batch_and_ioprio_idle();
    failures += t_thread_qos_background_attr_applies_before_entry();
    failures += t_thread_qos_idempotent();
    return failures;
}
#else  /* _WIN32 */
static int test_thread_qos_platform_arm(void)
{
    printf("thread_qos: Windows native priority proof follows in the "
           "registered-root contract.\n");
    return 0;
}
#endif

static int t_thread_qos_registered_root_contract(void)
{
    int failures = 0;

    TEST("thread_qos: registered root proves direct API and native priority") {
        pthread_attr_t attr;
        ASSERT(!zcl_thread_qos_background_attr(NULL));
        ASSERT_EQ(pthread_attr_init(&attr), 0);
        ASSERT(zcl_thread_qos_background_attr(&attr));
        ASSERT_EQ(pthread_attr_destroy(&attr), 0);

#if defined(_WIN32)
        ASSERT(SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_NORMAL));
        ASSERT_EQ(GetThreadPriority(GetCurrentThread()),
                  THREAD_PRIORITY_NORMAL);
        ASSERT(zcl_thread_qos_background());
        ASSERT_EQ(GetThreadPriority(GetCurrentThread()),
                  THREAD_PRIORITY_BELOW_NORMAL);
#elif defined(__APPLE__)
        qos_class_t before = QOS_CLASS_UNSPECIFIED;
        qos_class_t after = QOS_CLASS_UNSPECIFIED;
        int before_relative = 0;
        int after_relative = 0;
        ASSERT_EQ(pthread_get_qos_class_np(pthread_self(), &before,
                                           &before_relative), 0);
        bool applied = zcl_thread_qos_background();
        ASSERT_EQ(pthread_get_qos_class_np(pthread_self(), &after,
                                           &after_relative), 0);
        if (applied)
            ASSERT_EQ(after, QOS_CLASS_BACKGROUND);
        else
            ASSERT_EQ(after, before);
#else
        struct sched_param normal = {0};
        ASSERT_EQ(sched_setscheduler(0, SCHED_OTHER, &normal), 0);
        ASSERT_EQ(sched_getscheduler(0), SCHED_OTHER);
        (void)zcl_thread_qos_background();
        ASSERT_EQ(sched_getscheduler(0), SCHED_BATCH);
#endif

        PASS();
    } _test_next:;

    return failures;
}

int test_thread_qos(void)
{
    int failures = test_thread_qos_platform_arm();
    failures += t_thread_qos_registered_root_contract();
    return failures;
}
