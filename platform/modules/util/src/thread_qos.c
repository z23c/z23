/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Background thread QoS armor (lane/os-armor). See util/thread_qos.h for
 * the contract. Genuinely-background bulk workers (catalog/backfill jobs,
 * the background validation walker, similar linger workers) call
 * zcl_thread_qos_background() once at thread start so the kernel schedules
 * them behind the reducer pipeline, net, RPC, and tip-follow threads
 * instead of contending with them for CPU and disk I/O — grounded in the
 * prior OOM kill of the user manager on this host: a bulk background
 * worker should never be able to starve the node's own liveness threads.
 *
 * Two knobs, both per-thread attributes on Linux (each targets the calling
 * thread, not the whole process, when passed pid/who == 0):
 *   - CPU: SCHED_BATCH via sched_setscheduler(2). Batch-classified threads
 *     are still fully scheduled (no starvation risk like SCHED_IDLE), but
 *     the scheduler assumes they are CPU-bound/non-interactive and yields
 *     to interactive threads more readily. Needs no special privilege.
 *   - I/O: IOPRIO_CLASS_IDLE via the ioprio_set(2) syscall — glibc ships no
 *     wrapper for it, so the syscall number and the IOPRIO_PRIO_VALUE
 *     encoding are hand-rolled here directly from the stable kernel UAPI
 *     (linux/ioprio.h), avoiding a kernel-header build dependency.
 *
 * Fail-soft by design: a denied syscall is logged and the thread keeps
 * running at its inherited priority rather than aborting.
 */

#if !defined(_WIN32)
#define _GNU_SOURCE  /* SCHED_BATCH, syscall() */
#endif

#include "util/thread_qos.h"
#include "util/log_macros.h"

#include <stdatomic.h>

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#else
#include <sched.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#endif
#if defined(__APPLE__)
#include <pthread.h>
#include <sys/qos.h>
#endif

/* ioprio_set(2) argument encoding — kernel UAPI, not a glibc wrapper. */
#ifndef IOPRIO_WHO_PROCESS
#define IOPRIO_WHO_PROCESS 1
#endif
#ifndef IOPRIO_CLASS_IDLE
#define IOPRIO_CLASS_IDLE 3
#endif
#define ZCL_IOPRIO_CLASS_SHIFT 13
#define ZCL_IOPRIO_PRIO_VALUE(class_, data_) \
    (((class_) << ZCL_IOPRIO_CLASS_SHIFT) | (data_))

/* Short-burst background pools may create a thread per bounded batch. QoS is
 * still applied to every thread, but a success line per worker would let
 * ordinary chain verification become a log-volume attack on the node itself.
 * Keep failures visible and publish one representative success per process. */
static _Atomic bool g_background_success_logged = false;

bool zcl_thread_qos_background_attr(pthread_attr_t *attr)
{
    if (!attr)
        LOG_FAIL("thread_qos", "background pthread attribute is NULL");
#if defined(__APPLE__)
    int rc = pthread_attr_set_qos_class_np(attr, QOS_CLASS_BACKGROUND, 0);
    if (rc != 0)
        LOG_FAIL("thread_qos", "background pthread attribute denied: %s",
                 strerror(rc));
#else
    /* Linux I/O priority and Windows thread priority can only be applied by
     * the new thread itself. Preserve the caller's initialized attributes;
     * zcl_thread_qos_background() on worker entry applies those controls. */
    (void)attr;
#endif
    return true;
}

bool zcl_thread_qos_background(void)
{
#if defined(_WIN32)
    /* GetCurrentThread returns a process-local pseudo-handle for exactly the
     * calling thread. It is neither stored nor closed. BELOW_NORMAL is an
     * idempotent advisory priority suitable for repeated calls; Windows'
     * THREAD_MODE_BACKGROUND_BEGIN deliberately rejects a second call. */
    if (!SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_BELOW_NORMAL)) {
        LOG_WARN("thread_qos",
                 "background QoS denied error=%lu (continuing at inherited "
                 "CPU priority)", (unsigned long)GetLastError());
        return false;
    }
    if (!atomic_exchange_explicit(&g_background_success_logged, true,
                                  memory_order_relaxed))
        LOG_INFO("thread_qos",
                 "background QoS applied tid=%lu priority=below-normal "
                 "(later successes suppressed)",
                 (unsigned long)GetCurrentThreadId());
    return true;
#elif defined(__APPLE__)
    int rc = pthread_set_qos_class_self_np(QOS_CLASS_BACKGROUND, 0);
    if (rc != 0) {
        LOG_WARN("thread_qos", "background QoS denied: %s", strerror(rc));
        return false;
    }
    uint64_t tid = 0;
    (void)pthread_threadid_np(NULL, &tid);
    if (!atomic_exchange_explicit(&g_background_success_logged, true,
                                  memory_order_relaxed))
        LOG_INFO("thread_qos",
                 "background QoS applied tid=%llu class=background "
                 "(later successes suppressed)",
                 (unsigned long long)tid);
    return true;
#else
    bool cpu_ok = true;
    bool io_ok = true;

    /* CPU: SCHED_BATCH, priority 0 — the only valid priority for a
     * non-realtime policy. pid=0 targets the calling thread: Linux
     * scheduling policy is a per-thread attribute, not per-process. */
    struct sched_param sp;
    memset(&sp, 0, sizeof(sp));
    if (sched_setscheduler(0, SCHED_BATCH, &sp) != 0) {
        LOG_WARN("thread_qos",
                 "sched_setscheduler(SCHED_BATCH) denied: %s (continuing "
                 "at inherited CPU priority)", strerror(errno));
        cpu_ok = false;
    }

    /* I/O: IOPRIO_CLASS_IDLE, data=0. IOPRIO_WHO_PROCESS + who=0 also
     * targets the calling thread — ioprio is a per-task kernel attribute,
     * same as the CPU scheduling policy above. */
    long rc = syscall(SYS_ioprio_set, IOPRIO_WHO_PROCESS, 0,
                      ZCL_IOPRIO_PRIO_VALUE(IOPRIO_CLASS_IDLE, 0));
    if (rc != 0) {
        LOG_WARN("thread_qos",
                 "ioprio_set(IOPRIO_CLASS_IDLE) denied: %s (continuing at "
                 "inherited I/O priority)", strerror(errno));
        io_ok = false;
    }

    if (!atomic_exchange_explicit(&g_background_success_logged, true,
                                  memory_order_relaxed))
        LOG_INFO("thread_qos",
                 "background QoS applied tid=%ld sched=%s io=%s "
                 "(later successes suppressed)",
                 (long)syscall(SYS_gettid),
                 cpu_ok ? "SCHED_BATCH" : "unchanged",
                 io_ok ? "IOPRIO_CLASS_IDLE" : "unchanged");

    return cpu_ok && io_ok;
#endif
}
