/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * thread_work_probe — "is this thread doing anything?", asked of the kernel.
 *
 * WHY THIS EXISTS
 * ---------------
 * Every long-running loop in this tree publishes a timestamp at the top of
 * its loop, and every liveness check built on those timestamps asks the same
 * question: "did this loop get back to the top within N seconds?" That is not
 * a question about the loop. It is a question about how much work the loop was
 * handed and how fast the machine underneath it runs. A node serving blocks
 * off a 7200rpm disk, or one whose pages are being reclaimed under memory
 * pressure, takes longer to come round — and is graded dead for it, while an
 * identical node on an SSD is graded alive. That is a machine measurement
 * wearing a liveness costume, and it is how a network quietly evicts its
 * slowest honest members.
 *
 * One discriminator that does NOT depend on machine speed is whether the
 * kernel reports completed work on that thread's behalf:
 *
 *   - CPU time (utime+stime) advances while the thread computes, and while it
 *     sits in direct reclaim faulting pages back in.
 *   - Major faults advance while the thread is stalled on memory it must read
 *     back from disk — the exact state a thrashing-but-progressing node is in.
 *   - Block I/O bytes advance while the thread waits on a slow device.
 *
 * A thread parked in a bounded socket poll can also advance none of them. Such
 * waits must publish a thread_bounded_wait lease before entering the kernel.
 * The lease expires at the operation's declared deadline, so an intentional
 * wait stays alive while a wait that overruns its budget becomes silence. A
 * thread that publishes neither advancing work nor a live bounded-wait lease
 * is not assumed healthy.
 *
 * WHAT THIS DELIBERATELY CANNOT DO
 * --------------------------------
 * A thread spinning in a livelock burns CPU and reads here as working. This
 * probe does not detect livelock and must never be presented as if it does;
 * a frozen thread and a spinning thread are different failures with different
 * detectors (the supervisor tree's NO_PROGRESS contracts own the second).
 *
 * UNOBSERVABLE IS NOT ALIVE
 * -------------------------
 * On a platform without per-thread kernel counters — or under a sandbox that
 * denies /proc — every sample comes back `observed=false` and
 * thread_work_probe_advanced() returns false. A caller then falls back to
 * whatever it did before this probe existed. Silence about the subject is
 * never evidence in the subject's favor.
 */

#ifndef ZCL_THREAD_WORK_PROBE_H
#define ZCL_THREAD_WORK_PROBE_H

#include <stdbool.h>
#include <stdint.h>
#include <stdatomic.h>

/* A bounded wait is explicit evidence that a loop intentionally handed
 * control to a blocking OS operation. The deadline is load-bearing: if the
 * operation exceeds the declared budget, the lease expires and cannot hide a
 * wedge. Five minutes is the local ceiling for one declaration; callers use
 * their smaller operation-specific timeout. */
#define THREAD_BOUNDED_WAIT_MAX_US (300LL * 1000000LL)

struct thread_bounded_wait {
    _Atomic int64_t deadline_us;
};

#define THREAD_BOUNDED_WAIT_INIT { .deadline_us = 0 }

/* One reading of the kernel's own work counters for one thread. Absolute
 * values are meaningless across boots or platforms; only DIFFERENCES between
 * two samples of the same thread carry information. */
struct thread_work_sample {
    bool     observed;      /* false => the counters could not be read */
    uint64_t cpu_ticks;     /* utime + stime, in clock ticks           */
    uint64_t major_faults;  /* faults that required a disk read        */
    uint64_t io_bytes;      /* read_bytes + write_bytes at the device  */
};

/* This thread's OS-level thread id, suitable for thread_work_probe_sample().
 * Returns 0 when the platform has no such concept. */
long thread_work_probe_self_tid(void);

/* True when per-thread kernel counters are readable at all in this process.
 * Cheap; result is cached after the first call. */
bool thread_work_probe_supported(void);

/* Read `tid`'s counters. `tid` must name a thread of THIS process. Returns
 * false and sets out->observed = false when the counters are unavailable.
 * Touches only kernel-generated pseudo-files: it takes no node lock, issues
 * no block-device I/O, and cannot be delayed by the node's own storage. */
bool thread_work_probe_sample(long tid, struct thread_work_sample *out);

/* PURE. True when the kernel says this thread did work between `prev` and
 * `now`. An unobserved sample on either side is NOT work. */
bool thread_work_probe_advanced(const struct thread_work_sample *prev,
                                const struct thread_work_sample *now);

/* Publish/clear an intentional blocking wait. `now_us` and `timeout_us` use
 * the monotonic clock. begin refuses non-positive, overflowing, or
 * policy-exceeding durations. active is pure apart from the atomic load. */
bool thread_bounded_wait_begin_at(struct thread_bounded_wait *wait,
                                  int64_t now_us, int64_t timeout_us);
void thread_bounded_wait_end(struct thread_bounded_wait *wait);
bool thread_bounded_wait_active_at(const struct thread_bounded_wait *wait,
                                   int64_t now_us);
int64_t thread_bounded_wait_deadline(
    const struct thread_bounded_wait *wait);

#endif /* ZCL_THREAD_WORK_PROBE_H */
