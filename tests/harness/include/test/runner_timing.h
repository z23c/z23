/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0
 * purpose: Checked monotonic duration for one runner child. */
#ifndef ZCL_TEST_RUNNER_TIMING_H
#define ZCL_TEST_RUNNER_TIMING_H
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

struct runner_timing { int64_t start_us, elapsed_ms; bool valid; };

static inline void runner_timing_finish(struct runner_timing *timing, int64_t end_us)
{
    timing->valid = timing->start_us > 0 && end_us >= timing->start_us;
    timing->elapsed_ms = timing->valid ? (end_us - timing->start_us) / 1000 : 0;
}

/* Caller owns the buffer; never render invalid timing as a measured zero. */
static inline const char *runner_timing_label(const struct runner_timing *timing,
                                              char out[32])
{
    if (!timing->valid) return "unknown";
    (void)snprintf(out, 32, "%lld.%03llds",
                   (long long)(timing->elapsed_ms / 1000),
                   (long long)(timing->elapsed_ms % 1000));
    return out;
}
#endif
