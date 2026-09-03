/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Load-adaptive wall-clock budgets for harness throughput assertions.
 *
 * A fixed wall-clock budget (e.g. "reopen stays below 300 ms") is a load
 * detector, not a work bound: on a host running many parallel lanes the same
 * code measures 244 ms one run and 427 ms the next, so the verdict flakes
 * while the work never changed. What the test means to bound is the WORK —
 * an incremental reopen must not redo a full scan — and wall time only
 * proves that on an idle host.
 *
 * This header turns a nominal budget into an effective one for the current
 * host. test_budget_scale() runs a short fixed CPU-bound calibration (1 MiB
 * of the tree's SHA3-256, 3 samples, median, timed on the monotonic clock),
 * compares it against the expected idle-host cost
 * (TEST_BUDGET_CALIB_EXPECTED_US), and scales the nominal budget by
 * measured/expected, floored at 1x and capped at 8x. Call sites print the
 * nominal budget, the effective budget, and the calibration factor in the
 * verdict line so a receipt shows why a run passed.
 *
 * For purely CPU-bound single-threaded measurements, prefer
 * test_thread_cpu_us() (per-thread CPU time, immune to descheduling) over
 * wall time outright — the sapling/secp256k1 constant-time tests already use
 * that shape via clock_thread_cpu_ns(). The codeindex open path below keeps
 * wall time because it includes filesystem/SQLite IO; scaling keeps that
 * latency bound meaningful instead of deleting it.
 */

#ifndef ZCL_TEST_TIMING_BUDGET_H
#define ZCL_TEST_TIMING_BUDGET_H

#include <stddef.h>
#include <stdint.h>

#include "crypto/sha3.h"
#include "platform/clock.h"
#include "platform/time_compat.h"

/* Fixed calibration work: 1 MiB hashed per sample. */
enum { TEST_BUDGET_CALIB_BYTES = 1048576 };
/* Odd sample count so the median is exact. */
enum { TEST_BUDGET_CALIB_SAMPLES = 3 };
/* Expected 1 MiB SHA3-256 wall time on an idle dev host, microseconds.
 * Measured ~2200 us on a 32-core dev box at load ~29 (already elevated), so
 * the true-idle reference sits just below: idle hosts calibrate to the 1x
 * floor, loaded hosts scale up. */
enum { TEST_BUDGET_CALIB_EXPECTED_US = 2000 };
/* Ceiling: beyond 8x the host is not slow, it is wedged — fail loudly. */
enum { TEST_BUDGET_FACTOR_MAX = 8 };

struct test_budget {
    uint64_t nominal_us;
    uint64_t calib_med_us;
    double factor;
    uint64_t effective_us;
};

/* Volatile sink for the calibration digest: sha3_256 lives in another
 * translation unit, but the store makes the work observably used in every
 * build profile (including LTO) so no sample can be folded away. */
static volatile uint64_t g_test_budget_sink;

/* One calibration sample: wall-clock microseconds to hash 1 MiB. */
static inline uint64_t test_budget_one_sample_us(unsigned char *buf,
                                                 size_t len)
{
    unsigned char out[32];
    int64_t t0 = platform_time_monotonic_us();
    sha3_256(buf, len, out);
    int64_t t1 = platform_time_monotonic_us();
    for (int i = 0; i < 32; i++)
        g_test_budget_sink += out[i];
    return t1 > t0 ? (uint64_t)(t1 - t0) : 0;
}

/* Median calibration cost in microseconds. Static buffer: no allocation to
 * check, no ~1 MiB stack frame, one BSS copy per including TU. */
static inline uint64_t test_budget_calibrate_med_us(void)
{
    static unsigned char s_calib_buf[TEST_BUDGET_CALIB_BYTES];
    for (size_t i = 0; i < (size_t)TEST_BUDGET_CALIB_BYTES; i++)
        s_calib_buf[i] = (unsigned char)(i * 31u + 7u);
    uint64_t s[TEST_BUDGET_CALIB_SAMPLES];
    for (int i = 0; i < TEST_BUDGET_CALIB_SAMPLES; i++)
        s[i] = test_budget_one_sample_us(s_calib_buf,
                                         (size_t)TEST_BUDGET_CALIB_BYTES);
    for (int i = 0; i < TEST_BUDGET_CALIB_SAMPLES - 1; i++) {
        for (int j = i + 1; j < TEST_BUDGET_CALIB_SAMPLES; j++) {
            if (s[j] < s[i]) {
                uint64_t t = s[i];
                s[i] = s[j];
                s[j] = t;
            }
        }
    }
    return s[TEST_BUDGET_CALIB_SAMPLES / 2];
}

/* Scale a nominal wall-clock budget for the current host load. */
static inline struct test_budget test_budget_scale(uint64_t nominal_us)
{
    struct test_budget b;
    b.nominal_us = nominal_us;
    b.calib_med_us = test_budget_calibrate_med_us();
    b.factor = (double)b.calib_med_us /
        (double)TEST_BUDGET_CALIB_EXPECTED_US;
    if (!(b.factor >= 1.0))
        b.factor = 1.0;
    if (b.factor > (double)TEST_BUDGET_FACTOR_MAX)
        b.factor = (double)TEST_BUDGET_FACTOR_MAX;
    b.effective_us = (uint64_t)((double)nominal_us * b.factor);
    if (b.effective_us < nominal_us)
        b.effective_us = nominal_us;
    return b;
}

/* Per-thread CPU microseconds for CPU-bound single-threaded measurements.
 * Only accrues while this thread executes, so scheduler preemption drops
 * out; falls back to the monotonic wall clock where no thread clock
 * exists (see clock_thread_cpu_ns). */
static inline uint64_t test_thread_cpu_us(void)
{
    int64_t ns = clock_thread_cpu_ns();
    return ns > 0 ? (uint64_t)ns / 1000u : 0;
}

#endif /* ZCL_TEST_TIMING_BUDGET_H */
