/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0
 * purpose: Checked monotonic duration for one runner child. */
#ifndef ZCL_TEST_RUNNER_TIMING_H
#define ZCL_TEST_RUNNER_TIMING_H
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

struct runner_timing { int64_t start_us, end_us, elapsed_ms; bool valid; };

static inline void runner_timing_finish(struct runner_timing *timing, int64_t end_us)
{
    timing->valid = timing->start_us > 0 && end_us >= timing->start_us;
    timing->end_us = end_us;
    timing->elapsed_ms = timing->valid ? (end_us - timing->start_us) / 1000 : 0;
}

/* Raw monotonic values share an origin only within the same suite process. */
static inline void runner_timing_interval(FILE *out, const char *group,
                                          const char *phase, unsigned attempt,
                                          const struct runner_timing *timing,
                                          int exit_code, int signal_number)
{
    fprintf(out, "test_parallel: attempt_interval group=%s phase=%s attempt=%u ",
            group, phase, attempt);
    if (timing->valid)
        fprintf(out, "clock=monotonic_suite valid=1 start_us=%lld end_us=%lld ",
                (long long)timing->start_us, (long long)timing->end_us);
    else
        fputs("clock=monotonic_suite valid=0 start_us=unknown end_us=unknown ", out);
    if (exit_code < 0) fputs("exit_code=unknown ", out);
    else fprintf(out, "exit_code=%d ", exit_code);
    fprintf(out, "signal=%d\n", signal_number);
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
