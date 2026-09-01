/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

#ifndef ZCL_CONTROLLERS_AGENT_RESTART_WATCHDOG_H
#define ZCL_CONTROLLERS_AGENT_RESTART_WATCHDOG_H

#include <stdbool.h>
#include <stdint.h>

struct json_value;

struct agent_restart_watchdog_snapshot {
    bool registered;
    int64_t highest_tip;
    int64_t last_advance_unix;
    int64_t age_secs;
    int64_t escalation_level;
    uint64_t fires_mirror;
    uint64_t fires_restart;
    uint64_t fires_operator_needed;
    int64_t threshold_restart_secs;
    int64_t persisted_stuck_height;
    int64_t no_progress_restarts;
    int64_t max_restarts;
    bool operator_needed;
};

void agent_restart_watchdog_snapshot_collect(
    struct agent_restart_watchdog_snapshot *snapshot);
void agent_push_restart_watchdog_json(
    struct json_value *out,
    const char *key,
    const struct agent_restart_watchdog_snapshot *snapshot);

#endif
