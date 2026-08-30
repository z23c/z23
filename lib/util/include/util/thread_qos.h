/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Background thread OS-QoS armor (lane/os-armor). One knob:
 * zcl_thread_qos_background() — call it once, at thread start, from a
 * genuinely-background bulk worker (catalog/backfill jobs, the background
 * validation walker, similar linger workers). NEVER call it from the
 * reducer pipeline, net, RPC, or tip-follow threads — those must stay
 * responsive and are scheduled normally.
 */

#ifndef ZCL_THREAD_QOS_H
#define ZCL_THREAD_QOS_H

#include <pthread.h>
#include <stdbool.h>

/* Apply background QoS to the CALLING thread. On Linux:
 *   - CPU: SCHED_BATCH scheduling class (sched_setscheduler). The kernel
 *     treats the thread as CPU-bound/non-interactive — it is still fully
 *     scheduled (no starvation, unlike SCHED_IDLE), it just yields to
 *     interactive threads more readily. Needs no special privilege.
 *   - I/O: IOPRIO_CLASS_IDLE I/O priority (ioprio_set syscall — no glibc
 *     wrapper exists, so the syscall is hand-rolled). The thread only gets
 *     disk I/O when no other process wants the device.
 *
 * On Windows, the calling thread is assigned the idempotent advisory
 * THREAD_PRIORITY_BELOW_NORMAL priority; process priority is unchanged.
 *
 * Fail-soft: a denied OS call is logged via LOG_WARN and the thread keeps
 * running at its inherited priority — this is best-effort armor, not a
 * precondition. The return value reports whether BOTH knobs were applied;
 * callers are not required to check it. Idempotent — safe to call more
 * than once from the same thread. The first successful application per
 * process is logged; later successes are intentionally quiet so short-burst
 * worker pools cannot flood the node log. */
bool zcl_thread_qos_background(void);

/* Mark an already-initialized pthread attribute for background work. Darwin
 * applies QOS_CLASS_BACKGROUND at creation time, before the new thread can run
 * any user code; other hosts leave the attribute unchanged because their
 * background CPU/I/O controls are calling-thread operations. The worker must
 * still call zcl_thread_qos_background() on entry: that supplies Linux I/O
 * priority and is an idempotent confirmation of the Darwin class.
 *
 * Returns false (logged) for NULL or when Darwin refuses the attribute. The
 * caller retains ownership and must pthread_attr_destroy() the attribute. */
bool zcl_thread_qos_background_attr(pthread_attr_t *attr);

#endif /* ZCL_THREAD_QOS_H */
