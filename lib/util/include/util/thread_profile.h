/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * In-process thread CPU profiler — the C primitive behind `zclassic23 profile`.
 *
 * Samples /proc/self/task/<tid>/stat twice, `sample_ms` apart, and reports the
 * per-thread user+system CPU-time delta over the window, each thread's name and
 * current kernel wait channel (wchan), and a one-line verdict classifying where
 * the process spends the window (cpu-bound in a named thread, io-wait in a
 * named wait channel such as jbd2, or idle). This replaces the /proc sampling
 * an operator does by hand to find a bottleneck.
 *
 * Read-only: it opens /proc entries of THIS process only, allocates a bounded
 * snapshot, and never mutates node state. A thread that exits mid-window (its
 * /proc entry vanishes between the two samples) is skipped, never fatal.
 */

#ifndef ZCL_UTIL_THREAD_PROFILE_H
#define ZCL_UTIL_THREAD_PROFILE_H

#include <stdbool.h>
#include <stddef.h>

struct json_value;

/* Bounds. A process with more than THREAD_PROFILE_MAX live threads is sampled
 * up to the cap (the busiest are still surfaced; the count reports the cap). */
#define THREAD_PROFILE_MAX      1024
#define THREAD_PROFILE_TOP_MAX  32

struct thread_profile_opts {
    int sample_ms;   /* window length; clamped to [50, 60000] */
    int top_n;       /* busiest threads to report; clamped to [1, 32] */
};

/* Sample the current process's threads and fill `out` (an object this fills
 * via json_set_object) with:
 *   { sample_ms, sampled_threads, reported_threads, clk_tck,
 *     verdict, busiest_thread,
 *     threads: [ { tid, name, cpu_ms, cpu_fraction, wchan }, ... ] }
 * Threads are sorted by descending cpu_ms. Returns true on success; false and
 * an empty object only if /proc/self/task is unreadable. Never crashes on a
 * thread that races the sample. */
bool thread_profile_sample(const struct thread_profile_opts *opts,
                           struct json_value *out);

#endif /* ZCL_UTIL_THREAD_PROFILE_H */
