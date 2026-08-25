/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Node-free native front door for the bounded external SLO evidence reader. */

#include "command/native_command.h"

#include "json/json.h"
#include "kernel/command_registry.h"
#include "platform/time_compat.h"
#include "services/slo_ledger_summary.h"

void zcl_native_handle_ops_slo(const struct zcl_command_request *request,
                               struct zcl_command_reply *reply)
{
    if (!request || !request->input || !reply)
        return;

    const struct json_value *instance_value =
        json_get(request->input, "instance");
    const char *instance = NULL;
    if (instance_value) {
        instance = json_get_str(instance_value);
        if (instance_value->type != JSON_STR || !instance[0] ||
            !slo_ledger_instance_valid(instance)) {
            zcl_command_reply_fail(
                reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INVALID,
                "INVALID_INSTANCE", "validate", false, false,
                "instance must be 1 to 32 letters, digits, dots, dashes, or "
                "underscores", instance);
            return;
        }
    }
    const struct json_value *hours_value =
        json_get(request->input, "window_hours");
    int64_t hours = SLO_SUMMARY_DEFAULT_HOURS;
    if (hours_value) {
        if (hours_value->type != JSON_INT) {
            zcl_command_reply_fail(
                reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INVALID,
                "INVALID_WINDOW", "validate", false, false,
                "window_hours must be an integer from 1 through 168",
                "window_hours");
            return;
        }
        hours = json_get_int(hours_value);
    }
    if (hours < 1 || hours > SLO_SUMMARY_MAX_HOURS) {
        zcl_command_reply_fail(
            reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INVALID,
            "INVALID_WINDOW", "validate", false, false,
            "window_hours must be an integer from 1 through 168",
            "window_hours");
        return;
    }
    if (!slo_ledger_summary_render(
            instance, (unsigned)hours,
            (int64_t)platform_time_wall_time_t(), &reply->data)) {
        zcl_command_reply_fail(
            reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INTERNAL,
            "SLO_EVIDENCE_UNAVAILABLE", "read", true, false,
            "the bounded external SLO evidence reader could not render its "
            "ledger", instance ? instance : "all instances");
        return;
    }
    reply->status = ZCL_COMMAND_STATUS_PASSED;
    reply->exit_code = ZCL_COMMAND_EXIT_OK;
}
