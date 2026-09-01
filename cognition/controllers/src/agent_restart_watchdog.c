/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * First-call restart/liveness telemetry for AI/operator status. */

#include "controllers/agent_restart_watchdog.h"

#include "json/json.h"
#include "services/chain_tip_watchdog.h"

#include <string.h>

static int64_t restart_watchdog_remaining(
    const struct agent_restart_watchdog_snapshot *s)
{
    if (!s || s->max_restarts < 0 || s->no_progress_restarts < 0)
        return 0;
    if (s->no_progress_restarts >= s->max_restarts)
        return 0;
    return s->max_restarts - s->no_progress_restarts;
}

static bool restart_watchdog_budget_burning(
    const struct agent_restart_watchdog_snapshot *s)
{
    return s && s->no_progress_restarts > 0 &&
           s->persisted_stuck_height >= 0;
}

static bool restart_watchdog_budget_exhausted(
    const struct agent_restart_watchdog_snapshot *s)
{
    return s && s->max_restarts > 0 &&
           s->no_progress_restarts >= s->max_restarts;
}

static const char *restart_watchdog_status(
    const struct agent_restart_watchdog_snapshot *s)
{
    if (!s || !s->registered)
        return "unregistered";
    if (s->operator_needed)
        return "escalating";
    if (restart_watchdog_budget_exhausted(s))
        return "restart_budget_exhausted";
    if (restart_watchdog_budget_burning(s))
        return "restart_budget_burning";
    if (s->escalation_level >= 3)
        return "restart_threshold";
    if (s->escalation_level >= 1)
        return "stall_watch";
    return "ok";
}

static const char *restart_watchdog_last_reason(
    const struct agent_restart_watchdog_snapshot *s)
{
    if (restart_watchdog_budget_burning(s) || (s && s->fires_restart > 0))
        return "no_progress_tip_stall";
    if (s && s->operator_needed)
        return "restart_budget_or_deterministic_stall";
    return "none";
}

void agent_restart_watchdog_snapshot_collect(
    struct agent_restart_watchdog_snapshot *snapshot)
{
    if (!snapshot)
        return;
    memset(snapshot, 0, sizeof(*snapshot));

    struct chain_tip_watchdog_stats stats;
    chain_tip_watchdog_get_stats(&stats);
    snapshot->registered = stats.registered;
    snapshot->highest_tip = stats.highest_tip;
    snapshot->last_advance_unix = stats.last_advance_unix;
    snapshot->age_secs = stats.age_secs;
    snapshot->escalation_level = stats.escalation_level;
    snapshot->fires_mirror = stats.fires_mirror;
    snapshot->fires_restart = stats.fires_restart;
    snapshot->fires_operator_needed = stats.fires_operator_needed;
    snapshot->threshold_restart_secs = stats.threshold_restart_secs;
    snapshot->persisted_stuck_height = stats.persisted_stuck_height;
    snapshot->no_progress_restarts = stats.no_progress_restarts;
    snapshot->max_restarts = stats.max_restarts;
    snapshot->operator_needed = stats.operator_needed;
}

void agent_push_restart_watchdog_json(
    struct json_value *out,
    const char *key,
    const struct agent_restart_watchdog_snapshot *snapshot)
{
    if (!out)
        return;

    struct agent_restart_watchdog_snapshot live;
    if (!snapshot) {
        agent_restart_watchdog_snapshot_collect(&live);
        snapshot = &live;
    }

    struct json_value obj = {0};
    json_set_object(&obj);
    json_push_kv_str(&obj, "schema", "zcl.restart_watchdog.v1");
    json_push_kv_int(&obj, "schema_version", 1);
    json_push_kv_str(&obj, "status", restart_watchdog_status(snapshot));
    json_push_kv_bool(&obj, "registered", snapshot->registered);
    json_push_kv_bool(&obj, "last_restart_autonomous",
                      restart_watchdog_budget_burning(snapshot) ||
                          snapshot->fires_restart > 0);
    json_push_kv_str(&obj, "last_restart_reason",
                     restart_watchdog_last_reason(snapshot));
    json_push_kv_int(&obj, "highest_tip", snapshot->highest_tip);
    json_push_kv_int(&obj, "last_advance_unix",
                     snapshot->last_advance_unix);
    json_push_kv_int(&obj, "age_secs", snapshot->age_secs);
    json_push_kv_int(&obj, "escalation_level",
                     snapshot->escalation_level);
    json_push_kv_int(&obj, "threshold_restart_secs",
                     snapshot->threshold_restart_secs);
    json_push_kv_int(&obj, "persisted_stuck_height",
                     snapshot->persisted_stuck_height);
    json_push_kv_int(&obj, "no_progress_restarts",
                     snapshot->no_progress_restarts);
    json_push_kv_int(&obj, "max_restarts", snapshot->max_restarts);
    json_push_kv_int(&obj, "restarts_remaining",
                     restart_watchdog_remaining(snapshot));
    json_push_kv_bool(&obj, "restart_budget_burning",
                      restart_watchdog_budget_burning(snapshot));
    json_push_kv_bool(&obj, "restart_budget_exhausted",
                      restart_watchdog_budget_exhausted(snapshot));
    json_push_kv_bool(&obj, "operator_needed",
                      snapshot->operator_needed);
    json_push_kv_int(&obj, "fires_mirror",
                     (int64_t)snapshot->fires_mirror);
    json_push_kv_int(&obj, "fires_restart",
                     (int64_t)snapshot->fires_restart);
    json_push_kv_int(&obj, "fires_operator_needed",
                     (int64_t)snapshot->fires_operator_needed);
    json_push_kv_str(&obj, "deep_state",
                     "z23 dumpstate chain_tip_watchdog");
    json_push_kv_str(&obj, "source", "chain_tip_watchdog");
    json_push_kv(out, key && key[0] ? key : "restart_watchdog", &obj);
    json_free(&obj);
}
