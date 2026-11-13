/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0
 * purpose: Bound contributor subprocess work by a shared monotonic budget. */
#include "contrib_inbox_process.h"
#include "platform/clock.h"
#include "util/spawn.h"

#include <limits.h>
#include <stdlib.h>

bool ci_process_budget_start_at(struct ci_process_budget *budget,
                                const char *seconds, int64_t now_us)
{
    if (!budget) return false;
    *budget = (struct ci_process_budget){0};
    if (!seconds || !*seconds || now_us <= 0) return false;
    int value = 0;
    for (const char *p = seconds; *p; ++p) {
        if (*p < '0' || *p > '9') return false;
        int digit = *p - '0';
        if (value > (86400 - digit) / 10) return false;
        value = value * 10 + digit;
    }
    if (value == 0 || now_us > INT64_MAX - (int64_t)value * 1000000)
        return false;
    budget->started_us = now_us;
    budget->deadline_us = now_us + (int64_t)value * 1000000;
    return true;
}

int ci_process_budget_remaining_at(const struct ci_process_budget *budget,
                                   int64_t now_us, int requested_ms)
{
    if (!budget || budget->started_us <= 0 ||
        budget->deadline_us <= budget->started_us ||
        now_us < budget->started_us || now_us >= budget->deadline_us ||
        requested_ms <= 0) return 0;
    int64_t remaining_ms = (budget->deadline_us - now_us) / 1000;
    if (remaining_ms <= 0) return 0;
    return remaining_ms < requested_ms ? (int)remaining_ms : requested_ms;
}

int ci_process_run(const struct ci_process_budget *budget,
                   const char *const argv[], const char *cwd, int timeout_ms,
                   bool merged, char *out, size_t cap)
{
    if (!out || cap == 0) return -1;
    out[0] = '\0';
    int allowed = ci_process_budget_remaining_at(
        budget, (clock_now_monotonic_ns() / 1000), timeout_ms);
    if (allowed == 0) return 124;
    bool timed_out = false;
    int rc = merged
        ? zcl_spawn_capture_merged_in_dir_observed(argv, cwd, out, cap,
                                                    allowed, &timed_out)
        : zcl_spawn_capture_in_dir_observed(argv, cwd, out, cap,
                                            allowed, &timed_out);
    return timed_out ? 124 : rc;
}

int ci_process_engine_run(const struct ci_process_budget *budget,
    const struct ci_process_engine *engine, char *out, size_t cap)
{
    long seconds = strtol(engine->timeout, NULL, 10);
    if (seconds <= 0 || seconds > 86400) return -1;
    const char *argv[] = {engine->env, "-u", "CLAUDECODE", "-u", "CLAUDE_CODE_ENTRYPOINT",
        engine->binary, "--engine", engine->engine, "--kind", "contrib-help",
        "--task", engine->task, "--no-group", "--worktree", engine->worktree,
        "--yes-dispatch", "--rounds", "1", "--state-dir", engine->unit,
        "--timeout", engine->timeout, engine->fixture[0] ? "--fixture-reply" : NULL,
        engine->fixture[0] ? engine->fixture : NULL, NULL};
    return ci_process_run(budget, argv, NULL, (int)(seconds * 1000) + 60000, true, out, cap);
}
