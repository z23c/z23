/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0
 * purpose: Checked monotonic duration for one runner child. */
#ifndef ZCL_TEST_RUNNER_TIMING_H
#define ZCL_TEST_RUNNER_TIMING_H
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

struct runner_cpu { int64_t user_us, system_us; bool valid; };
struct runner_timing { int64_t start_us, end_us, elapsed_ms; bool valid; struct runner_cpu cpu; };

/* Linux wait4: the child and descendants it actually waited for, not cgroup CPU. */
static inline bool runner_cpu_time(int64_t sec, int64_t usec, int64_t *out)
{
    if (sec < 0 || usec < 0 || usec >= 1000000 ||
        sec > (INT64_MAX - usec) / 1000000) return false;
    *out = sec * 1000000 + usec;
    return true;
}

static inline void runner_cpu_set(struct runner_cpu *cpu, int64_t user_sec,
                                  int64_t user_usec, int64_t system_sec,
                                  int64_t system_usec)
{
    *cpu = (struct runner_cpu){0};
    cpu->valid = runner_cpu_time(user_sec, user_usec, &cpu->user_us) &&
                 runner_cpu_time(system_sec, system_usec, &cpu->system_us);
}

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
    fprintf(out, "signal=%d ", signal_number);
    if (timing->cpu.valid)
        fprintf(out, "cpu_valid=1 cpu_user_us=%lld cpu_system_us=%lld\n",
                (long long)timing->cpu.user_us, (long long)timing->cpu.system_us);
    else
        fputs("cpu_valid=0 cpu_user_us=unknown cpu_system_us=unknown\n", out);
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
