/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

#ifndef ZCL_CONTROLLERS_AGENT_FIRST_CALL_H
#define ZCL_CONTROLLERS_AGENT_FIRST_CALL_H

#include <stdbool.h>
#include <stdint.h>

struct json_value;

#define ZCL_AGENT_FIRST_CALL_BUDGET_AGENT_MS       250
#define ZCL_AGENT_FIRST_CALL_BUDGET_HEALTHCHECK_MS 500
#define ZCL_AGENT_FIRST_CALL_BUDGET_LIVENESS_MS    750
#define ZCL_AGENT_FIRST_CALL_BUDGET_DIAGNOSE_MS    900

struct agent_first_call_view {
    const char *api;
    const char *result_completeness;
    const char *source;
    const char *partial_reason;
    const char *full_mode_command;
    int64_t budget_ms;
    int64_t started_us;
    bool partial_result;
};

int64_t agent_first_call_start_us(void);
int64_t agent_first_call_elapsed_ms(int64_t started_us);
bool agent_first_call_budget_exceeded(int64_t started_us, int64_t budget_ms);
void agent_push_first_call_json(struct json_value *out, const char *key,
                                const struct agent_first_call_view *view);
void agent_push_first_call_simple_json(struct json_value *out, const char *key,
                                       const char *api, const char *source,
                                       int64_t budget_ms, int64_t started_us,
                                       bool partial_result,
                                       const char *partial_reason,
                                       const char *full_mode_command);

#endif
