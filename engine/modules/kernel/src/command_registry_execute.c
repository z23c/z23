/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Dispatch refuse/run chain for zcl_command_registry_execute_json(), split
 * so each arm stays under cyclomatic 15. Refusal codes and debit/release
 * behaviour are unchanged. */

#include "kernel/command_registry.h"

#include "services/agent_spend_policy.h"  // lib-layer-ok:agent-spend-policy-gate

#include <string.h>

static bool lane_allowed(const struct zcl_command_spec *spec,
                         const struct zcl_command_context *context)
{
    if (!spec || spec->allowed_lanes == 0)
        return false;
    if (spec->allowed_lanes & ZCL_COMMAND_LANE_LOCAL)
        return true;
    const char *lane = context ? context->operator_lane : NULL;
    if (!lane || !lane[0])
        return false;
    if (strcmp(lane, "dev") == 0)
        return (spec->allowed_lanes & ZCL_COMMAND_LANE_DEV) != 0;
    if (strcmp(lane, "canonical") == 0 || strcmp(lane, "live") == 0)
        return (spec->allowed_lanes & ZCL_COMMAND_LANE_CANONICAL) != 0;
    if (strcmp(lane, "soak") == 0)
        return (spec->allowed_lanes & ZCL_COMMAND_LANE_SOAK) != 0;
    if (strcmp(lane, "offline-copy") == 0)
        return (spec->allowed_lanes & ZCL_COMMAND_LANE_OFFLINE_COPY) != 0;
    return false;
}

static bool refuse_planned(const struct zcl_command_spec *spec,
                           struct zcl_command_reply *reply)
{
    if (spec->availability != ZCL_COMMAND_PLANNED)
        return false;
    zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_BLOCKED,
                           ZCL_COMMAND_EXIT_BLOCKED, "COMMAND_PLANNED",
                           "dispatch", false, false,
                           "command is declared but not implemented",
                           spec->availability_reason);
    (void)command_registry_reply_add_describe_next(
        reply, spec, "inspect availability and replacement");
    return true;
}

static bool refuse_no_handler(const struct zcl_command_spec *spec,
                              zcl_command_handler_fn handler,
                              struct zcl_command_reply *reply)
{
    if (handler)
        return false;
    zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_BLOCKED,
                           ZCL_COMMAND_EXIT_BLOCKED, "COMMAND_COMPAT_ONLY",
                           "dispatch", false, false,
                           "canonical adapter is not executable yet",
                           spec->compat_target);
    (void)command_registry_reply_add_describe_next(
        reply, spec, "inspect the compatibility target");
    return true;
}

static bool refuse_lane(const struct zcl_command_spec *spec,
                        const struct zcl_command_context *context,
                        struct zcl_command_reply *reply)
{
    if (lane_allowed(spec, context))
        return false;
    zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_BLOCKED,
                           ZCL_COMMAND_EXIT_DENIED, "LANE_DENIED", "authorize",
                           false, false, "command is not allowed in this lane",
                           context && context->operator_lane
                               ? context->operator_lane
                               : "unknown");
    (void)command_registry_reply_add_describe_next(
        reply, spec, "inspect the declared lane scope");
    return true;
}

static bool refuse_authority(const struct zcl_command_spec *spec,
                             const struct zcl_command_context *context,
                             struct zcl_command_reply *reply)
{
    if (!context || spec->authority <= context->authority_ceiling)
        return false;
    zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_BLOCKED,
                           ZCL_COMMAND_EXIT_DENIED, "AUTHORITY_DENIED",
                           "authorize", false, false,
                           "command authority exceeds the session ceiling",
                           zcl_command_authority_name(spec->authority));
    (void)command_registry_reply_add_describe_next(
        reply, spec, "inspect the required authority");
    return true;
}

static bool refuse_capability(const struct zcl_command_spec *spec,
                              const struct zcl_command_context *context,
                              struct zcl_command_reply *reply)
{
    if (!context ||
        (spec->required_capabilities & ~context->granted_capabilities) == 0)
        return false;
    zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_BLOCKED,
                           ZCL_COMMAND_EXIT_DENIED, "CAPABILITY_DENIED",
                           "authorize", false, false,
                           "required capability was not granted", spec->path);
    (void)command_registry_reply_add_describe_next(
        reply, spec, "inspect required capabilities");
    return true;
}

static bool refuse_policy(const struct zcl_command_spec *spec,
                          const struct zcl_command_context *context,
                          const struct json_value *input,
                          struct zcl_command_reply *reply,
                          struct agent_spend_policy_decision *policy)
{
    const struct json_value *confirm_v = json_get(input, "confirm");
    bool committing =
        spec->confirmation != ZCL_COMMAND_CONFIRM_PLAN_COMMIT ||
        (confirm_v && json_get_bool(confirm_v));
    agent_spend_policy_evaluate(context ? context->agent_session : NULL, spec,
                                input, committing, policy);
    if (policy->allowed)
        return false;
    zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_BLOCKED,
                           ZCL_COMMAND_EXIT_DENIED,
                           policy->code[0] ? policy->code : "POLICY_DENIED",
                           "authorize", false, false,
                           policy->detail[0]
                               ? policy->detail
                               : "the agent session's spend policy "
                                 "refused this command",
                           policy->evidence);
    (void)command_registry_reply_add_describe_next(
        reply, spec, "inspect the session's spend policy");
    return true;
}

static void execute_handler(const struct zcl_command_spec *spec,
                            const struct zcl_command_context *context,
                            const struct json_value *input,
                            zcl_command_handler_fn handler,
                            bool invoked_by_alias, const char *invoked_name,
                            const char *view, size_t budget_bytes,
                            size_t max_items, const char *cursor,
                            struct zcl_command_reply *reply,
                            struct agent_spend_policy_decision *policy)
{
    struct zcl_command_request request = {
        .spec = spec,
        .context = context,
        .input = input,
        .view = view && view[0] ? view : "normal",
        .budget_bytes = budget_bytes,
        .max_items = max_items,
        .cursor = cursor,
        .invoked_by_alias = invoked_by_alias,
        .invoked_name = invoked_name,
        .agent_policy_settled = true,
    };
    handler(&request, reply);
    if ((policy->debited_zat > 0 || policy->intent_debit_managed) &&
        !reply->error.mutated) {
        agent_spend_policy_release(context ? context->agent_session : NULL,
                                   policy);
        policy->debited_zat = 0;
    }
}

void command_registry_execute_run(
    const struct zcl_command_spec *spec,
    const struct zcl_command_context *context, const struct json_value *input,
    zcl_command_handler_fn handler, bool invoked_by_alias,
    const char *invoked_name, const char *view, size_t budget_bytes,
    size_t max_items, const char *cursor, struct zcl_command_reply *reply,
    struct agent_spend_policy_decision *policy)
{
    if (refuse_planned(spec, reply) || refuse_no_handler(spec, handler, reply) ||
        refuse_lane(spec, context, reply) ||
        refuse_authority(spec, context, reply) ||
        refuse_capability(spec, context, reply) ||
        refuse_policy(spec, context, input, reply, policy))
        return;
    execute_handler(spec, context, input, handler, invoked_by_alias,
                    invoked_name, view, budget_bytes, max_items, cursor, reply,
                    policy);
}
