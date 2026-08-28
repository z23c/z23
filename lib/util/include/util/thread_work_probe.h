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
 * The discriminator that does NOT depend on machine speed is whether the
 * kernel is still doing work on that thread's behalf:
 *
 *   - CPU time (utime+stime) advances while the thread computes, and while it
 *     sits in direct reclaim faulting pages back in.
 *   - Major faults advance while the thread is stalled on memory it must read
 *     back from disk — the exact state a thrashing-but-progressing node is in.
 *   - Block I/O bytes advance while the thread waits on a slow device.
 *
 * A thread that is genuinely wedged — deadlocked on a mutex, parked on a
 * futex that will never be posted, blocked on a socket read with no timeout —
 * advances NONE of them. That is the distinction a watchdog needs, and it is
 * the same distinction on a slow box and a fast one: a slow box does less work
 * per second, but it never does zero.
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

#endif /* ZCL_THREAD_WORK_PROBE_H */
