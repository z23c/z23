/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * thread_work_probe — see util/thread_work_probe.h for what this measures and,
 * just as importantly, what it deliberately refuses to claim.
 *
 * The raw per-thread kernel counters come from platform/os_proc.h, which is
 * the one blessed home for OS-introspection reads. What lives HERE is the
 * policy layered on top of them, and the policy is one sentence: work is an
 * ADVANCE between two readings of the same thread, and a reading the platform
 * could not take is not an advance. */

#include "util/thread_work_probe.h"

#include "platform/os_proc.h"

#include <string.h>

long thread_work_probe_self_tid(void)
{
    return os_proc_self_tid();
}

bool thread_work_probe_sample(long tid, struct thread_work_sample *out)
{
    struct os_proc_thread_work w;
    if (!out)
        return false;
    memset(out, 0, sizeof(*out));
    if (!os_proc_thread_work_read(tid, &w))
        return false;
    out->cpu_ticks    = w.cpu_ticks;
    out->major_faults = w.major_faults;
    out->io_bytes     = w.io_bytes;
    out->observed     = true;
    return true;
}

bool thread_work_probe_supported(void)
{
    struct thread_work_sample s;
    return thread_work_probe_sample(thread_work_probe_self_tid(), &s);
}

bool thread_work_probe_advanced(const struct thread_work_sample *prev,
                                const struct thread_work_sample *now)
{
    /* Unobservable is not alive. A caller that cannot see the subject must
     * fall back to its other evidence, never assume the subject is fine. */
    if (!prev || !now || !prev->observed || !now->observed)
        return false;
    return now->cpu_ticks    > prev->cpu_ticks ||
           now->major_faults > prev->major_faults ||
           now->io_bytes     > prev->io_bytes;
}

bool thread_bounded_wait_begin_at(struct thread_bounded_wait *wait,
                                  int64_t now_us, int64_t timeout_us)
{
    if (!wait)
        return false;
    atomic_store_explicit(&wait->deadline_us, 0, memory_order_release);
    if (now_us < 0 || timeout_us <= 0 ||
        timeout_us > THREAD_BOUNDED_WAIT_MAX_US ||
        now_us > INT64_MAX - timeout_us)
        return false;
    atomic_store_explicit(&wait->deadline_us, now_us + timeout_us,
                          memory_order_release);
    return true;
}

void thread_bounded_wait_end(struct thread_bounded_wait *wait)
{
    if (wait)
        atomic_store_explicit(&wait->deadline_us, 0, memory_order_release);
}

int64_t thread_bounded_wait_deadline(const struct thread_bounded_wait *wait)
{
    return wait ? atomic_load_explicit(&wait->deadline_us,
                                       memory_order_acquire) : 0;
}

bool thread_bounded_wait_active_at(const struct thread_bounded_wait *wait,
                                   int64_t now_us)
{
    int64_t deadline_us = thread_bounded_wait_deadline(wait);
    return now_us >= 0 && deadline_us > now_us;
}
