/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: native read-only list/show adapters for transaction discovery.
 */

#include "command/native_command.h"

#include "controllers/transaction_type_catalog.h"
#include "json/json.h"

#include <string.h>

static void tt_csv_array(const char *csv, struct json_value *out)
{
    json_set_array(out);
    if (!csv || !csv[0])
        return;
    const char *cursor = csv;
    while (*cursor) {
        const char *end = strchr(cursor, ',');
        size_t len = end ? (size_t)(end - cursor) : strlen(cursor);
        if (len > 0 && len < ZCL_COMMAND_MAX_PATH) {
            char value[ZCL_COMMAND_MAX_PATH];
            memcpy(value, cursor, len);
            value[len] = 0;
            struct json_value item;
            json_init(&item);
            json_set_str(&item, value);
            (void)json_push_back(out, &item);
            json_free(&item);
        }
        if (!end)
            break;
        cursor = end + 1;
    }
}

static bool tt_command_contract(
    const struct zcl_command_registry *registry, const char *role,
    const char *path, struct json_value *contracts,
    bool *all_ready, bool *needs_money, bool *needs_owner)
{
    if (!path || !path[0])
        return false;
    const struct zcl_command_spec *spec =
        zcl_command_registry_find(registry, path, NULL);
    if (!spec) {
        *all_ready = false;
        return false;
    }
    struct json_value item;
    json_init(&item);
    json_set_object(&item);
    (void)json_push_kv_str(&item, "role", role);
    (void)json_push_kv_str(&item, "command", spec->path);
    (void)json_push_kv_str(&item, "availability",
                           zcl_command_availability_name(spec->availability));
    (void)json_push_kv_str(&item, "summary", spec->summary);
    (void)json_push_kv_str(&item, "semantics", spec->semantics);
    (void)json_push_kv_str(&item, "input_schema", spec->input_schema);
    (void)json_push_kv_str(&item, "output_schema", spec->output_schema);
    struct json_value keys;
    json_init(&keys);
    tt_csv_array(spec->input_keys, &keys);
    (void)json_push_kv(&item, "allowed_keys", &keys);
    json_free(&keys);
    (void)json_push_kv_str(&item, "example", spec->example);
    (void)json_push_kv_str(&item, "effect",
                           zcl_command_effect_name(spec->effect));
    (void)json_push_kv_str(&item, "risk", zcl_command_risk_name(spec->risk));
    (void)json_push_kv_str(&item, "authority",
                           zcl_command_authority_name(spec->authority));
    (void)json_push_kv_str(&item, "confirmation",
                           zcl_command_confirmation_name(spec->confirmation));
    (void)json_push_back(contracts, &item);
    json_free(&item);
    if (spec->availability != ZCL_COMMAND_READY)
        *all_ready = false;
    if (spec->risk == ZCL_COMMAND_RISK_WALLET)
        *needs_money = true;
    if (spec->authority == ZCL_COMMAND_AUTH_OWNER)
        *needs_owner = true;
    return true;
}

static bool tt_is_primary_command(
    const struct zcl_transaction_type_contract *type,
    const char *path, size_t len)
{
    const char *primary[] = { type->builder_command, type->commit_command,
                              type->inspect_command };
    for (size_t i = 0; i < sizeof(primary) / sizeof(primary[0]); i++)
        if (primary[i] && strlen(primary[i]) == len &&
            memcmp(primary[i], path, len) == 0)
            return true;
    return false;
}

static size_t tt_component_contracts(
    const struct zcl_command_registry *registry,
    const struct zcl_transaction_type_contract *type,
    struct json_value *contracts, bool *all_ready,
    bool *needs_money, bool *needs_owner)
{
    const char *cursor = type->component_commands_csv;
    size_t count = 0;
    while (cursor && *cursor) {
        const char *end = strchr(cursor, ',');
        size_t len = end ? (size_t)(end - cursor) : strlen(cursor);
        if (len > 0 && len < ZCL_COMMAND_MAX_PATH &&
            !tt_is_primary_command(type, cursor, len)) {
            char path[ZCL_COMMAND_MAX_PATH];
            memcpy(path, cursor, len);
            path[len] = 0;
            count += tt_command_contract(registry, "component", path,
                contracts, all_ready, needs_money, needs_owner) ? 1u : 0u;
        }
        if (!end)
            break;
        cursor = end + 1;
    }
    return count;
}

static bool tt_has_command_alias(const char *type_id,
                                 const char *command_path)
{
    size_t count = 0;
    const struct zcl_transaction_command_alias *aliases =
        zcl_transaction_command_alias_catalog(&count);
    if (!type_id || !command_path)
        return false;
    for (size_t i = 0; i < count; i++)
        if (strcmp(aliases[i].type_id, type_id) == 0 &&
            strcmp(aliases[i].command_path, command_path) == 0)
            return true;
    return false;
}

static const char *tt_agent_decision(
    const struct zcl_transaction_type_contract *type)
{
    if (strcmp(type->availability, "ready") == 0 &&
        tt_has_command_alias(type->id, "vault.intent.submit"))
        return "discover_schema_then_plan_then_owner_authorized_submit_then_poll_status";
    if (strcmp(type->availability, "ready") == 0)
        return "discover_schema_then_plan_then_request_owner_commit";
    if (strcmp(type->availability, "process_only") == 0)
        return "receive_validate_and_inspect_only";
    if (strcmp(type->availability, "contained") == 0)
        return "refuse_outside_declared_network_policy";
    return "refuse_not_implemented";
}

static void tt_command_roles_json(uint32_t roles, struct json_value *out)
{
    static const enum zcl_transaction_command_role ordered[] = {
        ZCL_TRANSACTION_COMMAND_ROLE_BUILDER,
        ZCL_TRANSACTION_COMMAND_ROLE_PLAN,
        ZCL_TRANSACTION_COMMAND_ROLE_COMMIT,
        ZCL_TRANSACTION_COMMAND_ROLE_ROUTE,
        ZCL_TRANSACTION_COMMAND_ROLE_COMPONENT,
        ZCL_TRANSACTION_COMMAND_ROLE_INSPECT,
    };
    json_set_array(out);
    for (size_t i = 0; i < sizeof(ordered) / sizeof(ordered[0]); i++) {
        if ((roles & (uint32_t)ordered[i]) == 0)
            continue;
        struct json_value item;
        json_init(&item);
        json_set_str(&item, zcl_transaction_command_role_name(ordered[i]));
        (void)json_push_back(out, &item);
        json_free(&item);
    }
}

static const char *tt_alias_explanation(const char *type_id,
                                         const char *command_path)
{
    size_t count = 0;
    const struct zcl_transaction_command_alias *aliases =
        zcl_transaction_command_alias_catalog(&count);
    for (size_t i = 0; i < count; i++)
        if (strcmp(aliases[i].type_id, type_id) == 0 &&
            strcmp(aliases[i].command_path, command_path) == 0)
            return aliases[i].explanation;
    return "";
}

static const char *tt_command_participation(uint32_t roles,
                                             enum zcl_command_effect effect)
{
    if (roles == ZCL_TRANSACTION_COMMAND_ROLE_NONE)
        return "unclassified_never_assume_off_chain";
    if (roles & (ZCL_TRANSACTION_COMMAND_ROLE_COMMIT |
                 ZCL_TRANSACTION_COMMAND_ROLE_ROUTE))
        return "may_sign_or_submit_chain_transaction";
    if (roles & (ZCL_TRANSACTION_COMMAND_ROLE_BUILDER |
                 ZCL_TRANSACTION_COMMAND_ROLE_PLAN))
        return "may_prepare_chain_transaction";
    if (roles & ZCL_TRANSACTION_COMMAND_ROLE_COMPONENT)
        return effect == ZCL_COMMAND_EFFECT_READ
            ? "read_only_workflow_component"
            : "mutating_workflow_component";
    return "read_only_chain_inspection";
}

void zcl_native_handle_transaction_types_list(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply)
{
    (void)request;
    if (!zcl_transaction_types_index_json(&reply->data))
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INTERNAL, "CATALOG_FAILED",
                               "render", false, false,
                               "transaction type catalog could not be rendered",
                               "");
}

void zcl_native_handle_transaction_micro_lab(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply)
{
    int64_t slot = json_get_int_or(request->input, "slot", 0);
    if (slot < 0 || slot > ZCL_TRANSACTION_MICRO_LAB_TARGET) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INVALID, "BAD_SLOT",
                               "normalize", false, false,
                               "slot must be an integer from 1 through 100, or omitted for the campaign summary",
                               "slot");
        return;
    }
    if (!zcl_transaction_micro_lab_json((int)slot, &reply->data))
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INTERNAL,
                               "MICRO_LAB_RENDER_FAILED", "render", false,
                               false, "micro-lab campaign could not be rendered",
                               "");
}

void zcl_native_handle_transaction_wire_catalog(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply)
{
    (void)request;
    if (!zcl_transaction_wire_catalog_json(&reply->data))
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INTERNAL,
                               "WIRE_CATALOG_FAILED", "render", false, false,
                               "transaction wire catalog could not be rendered",
                               "");
}

void zcl_native_handle_transaction_type_show(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply)
{
    const char *id = json_get_str(json_get(request->input, "type"));
    if (!id || !id[0]) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INVALID, "MISSING_TYPE",
                               "normalize", false, false,
                               "type is required", "");
        return;
    }
    if (!zcl_transaction_type_show_json(id, &reply->data)) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_BLOCKED,
                               ZCL_COMMAND_EXIT_BLOCKED, "UNKNOWN_TYPE",
                               "resolve", false, false,
                               "no such semantic transaction type", id);
        (void)zcl_command_reply_add_next(reply, "app.transaction-types.list",
                                         "{}", "list transaction types");
    }
}

static void tt_append_str_array(const char *const *items, size_t count,
                                struct json_value *out)
{
    for (size_t i = 0; i < count; i++) {
        struct json_value item;
        json_init(&item);
        json_set_str(&item, items[i]);
        (void)json_push_back(out, &item);
        json_free(&item);
    }
}

static void tt_push_submission_preferences(
    struct json_value *data, const struct zcl_transaction_type_contract *type,
    bool async_submit)
{
    (void)json_push_kv_str(data, "preferred_submission_mode",
        async_submit ? "immediate_ack_async" : "foreground_commit");
    (void)json_push_kv_str(data, "preferred_submission_command",
        async_submit ? "vault.intent.submit" : type->commit_command);
    (void)json_push_kv_str(data, "initial_reply_boundary",
        async_submit ? "durable_queue" : "commit_result");
    (void)json_push_kv_str(data, "operation_id_source",
        async_submit ? "plan_id" : "none");
    (void)json_push_kv_str(data, "status_command", type->inspect_command);
}

static void tt_push_command_contracts(
    struct json_value *data, const struct zcl_command_registry *registry,
    const struct zcl_transaction_type_contract *type, bool async_submit,
    bool *all_ready, bool *needs_money, bool *needs_owner)
{
    *all_ready = true;
    *needs_money = type->commit_command[0] != 0;
    *needs_owner = false;
    size_t count = 0;
    struct json_value contracts;
    json_init(&contracts);
    json_set_array(&contracts);
    count += tt_command_contract(registry, "builder", type->builder_command,
        &contracts, all_ready, needs_money, needs_owner) ? 1u : 0u;
    count += tt_command_contract(registry, "commit", type->commit_command,
        &contracts, all_ready, needs_money, needs_owner) ? 1u : 0u;
    if (async_submit)
        count += tt_command_contract(registry, "submit",
            "vault.intent.submit", &contracts, all_ready, needs_money,
            needs_owner) ? 1u : 0u;
    count += tt_component_contracts(registry, type, &contracts, all_ready,
                                    needs_money, needs_owner);
    count += tt_command_contract(registry, "inspect", type->inspect_command,
        &contracts, all_ready, needs_money, needs_owner) ? 1u : 0u;
    (void)json_push_kv(data, "command_contracts", &contracts);
    json_free(&contracts);
    (void)json_push_kv_int(data, "command_contract_count", (int64_t)count);
}

static void tt_push_execution_readiness(
    struct json_value *data, const struct zcl_transaction_type_contract *type,
    bool all_ready, bool needs_money, bool needs_owner)
{
    bool can_execute = strcmp(type->availability, "ready") == 0 &&
        type->builder_command[0] && all_ready;
    (void)json_push_kv_bool(data, "can_execute", can_execute);
    (void)json_push_kv_bool(data, "money_snapshot_required",
                            needs_money);
    (void)json_push_kv_bool(data, "owner_authorization_required",
                            needs_owner);
    (void)json_push_kv_str(data, "money_snapshot_command",
        needs_money ? "metaverse.agent.money" : "");
    (void)json_push_kv_str(data, "proof_command",
                           "make transaction-lab-proof");
    (void)json_push_kv_str(data, "focused_test_group",
                           type->test_group);
}

static void tt_push_safety_checklist(struct json_value *data)
{
    static const char *const checklist[] = {
        "reject planned, contained-network, stale, unknown, or conflicted state",
        "discover current schemas; never infer flags or wallet scope",
        "obtain a current identity-bound money snapshot before any spend",
        "plan first and preserve outputs, fee, expiry, snapshot, and idempotency",
        "submit or commit only after explicit owner authorization",
        "inspect txid or operation state before recording redacted evidence",
    };
    struct json_value safety;
    json_init(&safety);
    json_set_array(&safety);
    tt_append_str_array(checklist, sizeof(checklist) / sizeof(checklist[0]),
                        &safety);
    (void)json_push_kv(data, "safety_checklist", &safety);
    json_free(&safety);
}

void zcl_native_handle_transaction_type_guide(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply)
{
    const char *id = json_get_str(json_get(request->input, "type"));
    if (!id || !id[0]) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INVALID, "MISSING_TYPE",
                               "normalize", false, false,
                               "type is required", "");
        return;
    }
    const struct zcl_transaction_type_contract *type =
        zcl_transaction_type_find(id);
    if (!type) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_BLOCKED,
                               ZCL_COMMAND_EXIT_BLOCKED, "UNKNOWN_TYPE",
                               "resolve", false, false,
                               "no such semantic transaction type", id);
        (void)zcl_command_reply_add_next(reply, "app.transaction-types.list",
                                         "{}", "list transaction types");
        return;
    }
    const struct zcl_command_registry *registry = request->context
        ? request->context->registry : NULL;
    if (!registry) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INTERNAL,
                               "REGISTRY_UNAVAILABLE", "join", true, false,
                               "live command registry is unavailable", id);
        return;
    }

    json_set_object(&reply->data);
    (void)json_push_kv_str(&reply->data, "schema",
                           ZCL_TRANSACTION_TYPE_GUIDE_SCHEMA);
    struct json_value type_json;
    json_init(&type_json);
    (void)zcl_transaction_type_show_json(id, &type_json);
    (void)json_push_kv(&reply->data, "transaction_type", &type_json);
    json_free(&type_json);
    (void)json_push_kv_str(&reply->data, "agent_decision",
                           tt_agent_decision(type));

    const bool async_submit =
        tt_has_command_alias(type->id, "vault.intent.submit");
    tt_push_submission_preferences(&reply->data, type, async_submit);
    struct json_value lifecycle_states;
    json_init(&lifecycle_states);
    json_set_array(&lifecycle_states);
    if (async_submit) {
        static const char *const states[] = {
            "planned", "proving", "mempool_accepted", "confirmed",
            "finalized", "reorged", "conflicted", "expired", "failed",
        };
        tt_append_str_array(states, sizeof(states) / sizeof(states[0]),
                            &lifecycle_states);
    }
    (void)json_push_kv(&reply->data, "lifecycle_states", &lifecycle_states);
    json_free(&lifecycle_states);

    bool all_ready;
    bool needs_money;
    bool needs_owner;
    tt_push_command_contracts(&reply->data, registry, type, async_submit,
                              &all_ready, &needs_money, &needs_owner);
    tt_push_execution_readiness(&reply->data, type, all_ready, needs_money,
                                needs_owner);
    tt_push_safety_checklist(&reply->data);
}

static size_t tt_append_type_mappings(const char *path,
                                      struct json_value *mappings,
                                      uint32_t *aggregate_roles)
{
    size_t type_count = 0;
    const struct zcl_transaction_type_contract *types =
        zcl_transaction_type_catalog(&type_count);
    size_t mapping_count = 0;
    for (size_t i = 0; i < type_count; i++) {
        const uint32_t roles =
            zcl_transaction_type_command_roles(&types[i], path);
        if (roles == ZCL_TRANSACTION_COMMAND_ROLE_NONE)
            continue;
        *aggregate_roles |= roles;
        struct json_value mapping;
        json_init(&mapping);
        json_set_object(&mapping);
        (void)json_push_kv_str(&mapping, "type", types[i].id);
        (void)json_push_kv_str(&mapping, "family", types[i].family);
        (void)json_push_kv_str(&mapping, "availability",
                               types[i].availability);
        struct json_value roles_json;
        json_init(&roles_json);
        tt_command_roles_json(roles, &roles_json);
        (void)json_push_kv(&mapping, "roles", &roles_json);
        json_free(&roles_json);
        const char *alias = tt_alias_explanation(types[i].id, path);
        (void)json_push_kv_bool(&mapping, "alternate_route", alias[0] != 0);
        (void)json_push_kv_str(&mapping, "route_explanation", alias);
        (void)json_push_kv_str(&mapping, "guide_command",
                               "app.transaction-types.guide");
        struct json_value guide_input;
        json_init(&guide_input);
        json_set_object(&guide_input);
        (void)json_push_kv_str(&guide_input, "type", types[i].id);
        (void)json_push_kv(&mapping, "guide_input", &guide_input);
        json_free(&guide_input);
        (void)json_push_back(mappings, &mapping);
        json_free(&mapping);
        mapping_count++;
    }
    return mapping_count;
}

static void tt_push_command_classification(
    struct json_value *data, const struct zcl_command_spec *spec,
    const struct zcl_transaction_nonchain_command *nonchain,
    struct json_value *mappings, uint32_t aggregate_roles,
    size_t mapping_count)
{
    (void)json_push_kv_str(data, "catalog_status",
        mapping_count ? "mapped" :
        (nonchain ? "explicitly_non_chain" : "unclassified"));
    (void)json_push_kv_str(data, "chain_participation",
        nonchain ? "no_chain_transaction" :
        tt_command_participation(aggregate_roles, spec->effect));
    (void)json_push_kv_bool(data, "may_prepare_chain_material",
        spec->effect != ZCL_COMMAND_EFFECT_READ &&
        (aggregate_roles & (ZCL_TRANSACTION_COMMAND_ROLE_BUILDER |
                            ZCL_TRANSACTION_COMMAND_ROLE_PLAN |
                            ZCL_TRANSACTION_COMMAND_ROLE_COMPONENT)) != 0);
    (void)json_push_kv_bool(data, "may_sign_or_submit",
        spec->effect != ZCL_COMMAND_EFFECT_READ &&
        (aggregate_roles & (ZCL_TRANSACTION_COMMAND_ROLE_COMMIT |
                            ZCL_TRANSACTION_COMMAND_ROLE_ROUTE)) != 0);
    (void)json_push_kv_bool(data, "unmapped_is_not_off_chain_proof",
                            mapping_count == 0 && !nonchain);
    (void)json_push_kv_bool(data, "explicitly_non_chain",
                            nonchain != NULL);
    (void)json_push_kv_str(data, "non_chain_category",
                           nonchain ? nonchain->category : "");
    (void)json_push_kv_str(data, "non_chain_explanation",
                           nonchain ? nonchain->explanation : "");
    (void)json_push_kv_int(data, "transaction_type_count",
                           (int64_t)mapping_count);
    (void)json_push_kv(data, "transaction_types", mappings);
    json_free(mappings);
    (void)json_push_kv_str(data, "agent_decision",
        mapping_count ? "select_a_type_then_call_its_guide" :
        (nonchain ? "no_transaction_workflow_for_this_command"
                  : "stop_unclassified_never_assume_off_chain"));
    (void)json_push_kv_str(data, "authority_note",
        "discovery_only_this_result_never_grants_wallet_signing_or_broadcast_authority");
}

void zcl_native_handle_transaction_command(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply)
{
    const char *path = json_get_str(json_get(request->input, "path"));
    if (!path || !path[0]) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INVALID, "MISSING_PATH",
                               "normalize", false, false,
                               "path is required", "");
        return;
    }
    const struct zcl_command_registry *registry = request->context
        ? request->context->registry : NULL;
    if (!registry) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INTERNAL,
                               "REGISTRY_UNAVAILABLE", "join", true, false,
                               "live command registry is unavailable", path);
        return;
    }
    const struct zcl_command_spec *spec =
        zcl_command_registry_find(registry, path, NULL);
    if (!spec || spec->mode == ZCL_COMMAND_MODE_BRANCH) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_BLOCKED,
                               ZCL_COMMAND_EXIT_BLOCKED, "UNKNOWN_COMMAND",
                               "resolve", false, false,
                               "path is not a native command leaf", path);
        (void)zcl_command_reply_add_next(reply, "discover.search",
            "{\"query\":\"transaction\"}", "find a native command leaf");
        return;
    }

    json_set_object(&reply->data);
    (void)json_push_kv_str(&reply->data, "schema",
                           ZCL_TRANSACTION_COMMAND_SCHEMA);
    (void)json_push_kv_str(&reply->data, "command", spec->path);
    (void)json_push_kv_str(&reply->data, "summary", spec->summary);
    (void)json_push_kv_str(&reply->data, "availability",
                           zcl_command_availability_name(spec->availability));
    (void)json_push_kv_str(&reply->data, "effect",
                           zcl_command_effect_name(spec->effect));
    (void)json_push_kv_str(&reply->data, "risk",
                           zcl_command_risk_name(spec->risk));
    (void)json_push_kv_str(&reply->data, "authority",
                           zcl_command_authority_name(spec->authority));
    (void)json_push_kv_str(&reply->data, "confirmation",
                           zcl_command_confirmation_name(spec->confirmation));

    struct json_value mappings;
    json_init(&mappings);
    json_set_array(&mappings);
    uint32_t aggregate_roles = ZCL_TRANSACTION_COMMAND_ROLE_NONE;
    const size_t mapping_count =
        tt_append_type_mappings(spec->path, &mappings, &aggregate_roles);
    const struct zcl_transaction_nonchain_command *nonchain =
        mapping_count ? NULL : zcl_transaction_nonchain_command_find(spec->path);
    tt_push_command_classification(&reply->data, spec, nonchain, &mappings,
                                   aggregate_roles, mapping_count);
}
