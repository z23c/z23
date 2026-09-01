/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

#include "controllers/agent_first_call.h"

#include "json/json.h"
#include "platform/time_compat.h"

int64_t agent_first_call_start_us(void)
{
    return platform_time_monotonic_us();
}

int64_t agent_first_call_elapsed_ms(int64_t started_us)
{
    int64_t now_us = platform_time_monotonic_us();
    if (started_us <= 0 || now_us < started_us)
        return 0;
    return (now_us - started_us) / 1000;
}

bool agent_first_call_budget_exceeded(int64_t started_us, int64_t budget_ms)
{
    return budget_ms > 0 && agent_first_call_elapsed_ms(started_us) > budget_ms;
}

void agent_push_first_call_json(struct json_value *out, const char *key,
                                const struct agent_first_call_view *view)
{
    if (!out || !key || !view)
        return;

    const int64_t elapsed_ms =
        agent_first_call_elapsed_ms(view->started_us);

    struct json_value obj = {0};
    json_set_object(&obj);
    json_push_kv_str(&obj, "schema", "zcl.first_call_contract.v1");
    json_push_kv_str(&obj, "api", view->api ? view->api : "");
    json_push_kv_str(&obj, "result_completeness",
                     view->result_completeness
                         ? view->result_completeness : "bounded");
    json_push_kv_bool(&obj, "partial_result", view->partial_result);
    json_push_kv_str(&obj, "source", view->source ? view->source : "");
    json_push_kv_int(&obj, "budget_ms", view->budget_ms);
    json_push_kv_int(&obj, "elapsed_ms", elapsed_ms);
    json_push_kv_bool(&obj, "budget_exceeded",
                      view->budget_ms > 0 && elapsed_ms > view->budget_ms);
    json_push_kv_str(&obj, "budget_semantics",
                     "first-call path must use cached/bounded sources and return valid JSON");
    if (view->partial_reason && view->partial_reason[0])
        json_push_kv_str(&obj, "partial_reason", view->partial_reason);
    if (view->full_mode_command && view->full_mode_command[0])
        json_push_kv_str(&obj, "full_mode_command",
                         view->full_mode_command);
    json_push_kv(out, key, &obj);
    json_free(&obj);
}

void agent_push_first_call_simple_json(struct json_value *out, const char *key,
                                       const char *api, const char *source,
                                       int64_t budget_ms, int64_t started_us,
                                       bool partial_result,
                                       const char *partial_reason,
                                       const char *full_mode_command)
{
    const struct agent_first_call_view view = {
        .api = api,
        .result_completeness = "bounded",
        .source = source,
        .partial_reason = partial_reason,
        .full_mode_command = full_mode_command,
        .budget_ms = budget_ms,
        .started_us = started_us,
        .partial_result = partial_result,
    };
    agent_push_first_call_json(out, key, &view);
}
