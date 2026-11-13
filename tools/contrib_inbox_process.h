/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0
 * Purpose: shared monotonic budgets for contributor subprocess work. */
#ifndef ZCL_CONTRIB_INBOX_PROCESS_H
#define ZCL_CONTRIB_INBOX_PROCESS_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct ci_process_budget {
    int64_t started_us;
    int64_t deadline_us;
};
struct ci_process_engine {
    const char *env, *binary, *engine, *worktree;
    const char *unit, *task, *timeout, *fixture;
};

bool ci_process_budget_start_at(struct ci_process_budget *budget,
                                const char *seconds, int64_t now_us);
int ci_process_budget_remaining_at(const struct ci_process_budget *budget,
                                   int64_t now_us, int requested_ms);
int ci_process_run(const struct ci_process_budget *budget,
                   const char *const argv[], const char *cwd, int timeout_ms,
                   bool merged, char *out, size_t cap);
int ci_process_engine_run(const struct ci_process_budget *budget,
    const struct ci_process_engine *engine, char *out, size_t cap);
#endif
