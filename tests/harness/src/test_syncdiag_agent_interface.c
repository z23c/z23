/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * agentinterface and agentdeployguard cases: the probed runtime
 * interface document (resources, restart watchdog) and the deploy
 * guard verdict for each lane and action.
 */

#include "test/syncdiag_rpc_fixture.h"

enum {
    AGENT_INTERFACE_OP_TYPE_OBJ = 1,
    AGENT_INTERFACE_OP_IS_NULL,
    AGENT_INTERFACE_OP_STR_EQ,
    AGENT_INTERFACE_OP_STR_EQ_BUILD,
    AGENT_INTERFACE_OP_SUBSTR,
    AGENT_INTERFACE_OP_BOOL,
    AGENT_INTERFACE_OP_INT_EQ,
    AGENT_INTERFACE_OP_INT_GE,
    AGENT_INTERFACE_OP_SIZE_EQ,
    AGENT_INTERFACE_OP_SIZE_GE,
    AGENT_INTERFACE_OP_ARRAY_SUBSTR,
    AGENT_INTERFACE_OP_STR_EQ_OTHER
};

enum {
    AI_DOC_INTERFACE = 0,
    AI_DOC_TRANSPORTS,
    AI_DOC_MUST_LIVE,
    AI_DOC_AVOID,
    AI_DOC_CAPABILITIES,
    AI_DOC_APP_PROTOCOLS,
    AI_DOC_SERVICE_CATALOG,
    AI_DOC_LANE_TOPOLOGY,
    AI_DOC_UNIFIED_LIVENESS,
    AI_DOC_FULL_COMPAT,
    AI_DOC_RUNTIME_STATUS,
    AI_DOC_RUNTIME_ALIAS,
    AI_DOC_MIRROR,
    AI_DOC_DEPLOY,
    AI_DOC_STATE_CATALOG,
    AI_DOC_TIMELINE,
    AI_DOC_SUBSYSTEM,
    AI_DOC_SEMANTIC,
    AI_DOC_NODE_LOG,
    AI_DOC_BOUNDED_LOGS,
    AI_DOC_SQL,
    AI_DOC_SELECT_SQL,
    AI_DOC_DEV_LOOP,
    AI_DOC_VISUAL_INSTRUMENTS,
    AI_DOC_VISUAL_QR,
    AI_DOC_VISUAL_STATUS,
    AI_DOC_VISUAL_DIFF,
    AI_DOC_VISUAL_PROGRESS,
    AI_DOC_VISUAL_CONFIRM,
    AI_DOC_VISUAL_CORPUS,
    AI_DOC_VISUAL_GROWTH,
    AI_DOC_VISUAL_ECOSYSTEM,
    AI_DOC_VISUAL_PUBLICATION,
    AI_DOC_VISUAL_BOUNDED,
    AI_DOC_VISUAL_RELEASE,
    AI_DOC_VISUAL_LOOP,
    AI_DOC_MACHINE,
    AI_DOC_RUNTIME,
    AI_DOC_AVAILABILITY,
    AI_DOC_AGENT_METHOD,
    AI_DOC_AGENTOPS_METHOD
};

struct agent_interface_expect {
    int obj;
    const char *key;
    int op;
    const char *text;
    int64_t num;
    bool flag;
    bool guard;
    int other;
    const char *other_key;
};

static bool agent_interface_field_holds(
    const struct json_value *field,
    const struct agent_interface_expect *row,
    const struct json_value **objs)
{
    switch (row->op) {
    case AGENT_INTERFACE_OP_STR_EQ:
        return strcmp(json_get_str(field), row->text) == 0;
    case AGENT_INTERFACE_OP_STR_EQ_BUILD:
        return strcmp(json_get_str(field), zcl_build_commit()) == 0;
    case AGENT_INTERFACE_OP_SUBSTR:
        return strstr(json_get_str(field), row->text) != NULL;
    case AGENT_INTERFACE_OP_BOOL:
        return json_get_bool(field) == row->flag;
    case AGENT_INTERFACE_OP_INT_EQ:
        return json_get_int(field) == row->num;
    case AGENT_INTERFACE_OP_INT_GE:
        return json_get_int(field) >= row->num;
    case AGENT_INTERFACE_OP_SIZE_EQ:
        return json_size(field) == (size_t)row->num;
    case AGENT_INTERFACE_OP_SIZE_GE:
        return json_size(field) >= (size_t)row->num;
    case AGENT_INTERFACE_OP_ARRAY_SUBSTR:
        return json_array_has_substr(field, row->text);
    case AGENT_INTERFACE_OP_STR_EQ_OTHER:
        return strcmp(json_get_str(field),
                      json_get_str(json_get(objs[row->other],
                                            row->other_key))) == 0;
    default:
        return false;
    }
}

static bool agent_interface_expect_rows(
    bool ok,
    const struct json_value **objs,
    const struct agent_interface_expect *rows,
    size_t n)
{
    for (size_t i = 0; ok && i < n; i++) {
        const struct agent_interface_expect *row = &rows[i];
        const struct json_value *obj = objs[row->obj];
        if (row->op == AGENT_INTERFACE_OP_IS_NULL)
            ok = obj == NULL;
        else if (row->op == AGENT_INTERFACE_OP_TYPE_OBJ)
            ok = obj && obj->type == JSON_OBJ;
        else if (row->guard && !obj)
            ok = false;
        else {
            const struct json_value *field = row->key
                ? json_get(obj, row->key) : obj;
            ok = agent_interface_field_holds(field, row, objs);
        }
    }
    return ok;
}

static const struct agent_interface_expect k_agent_interface_doc_rows[] = {
    { .obj = AI_DOC_INTERFACE, .op = AGENT_INTERFACE_OP_TYPE_OBJ },
    { .obj = AI_DOC_INTERFACE, .key = "schema",
      .op = AGENT_INTERFACE_OP_STR_EQ,
      .text = "zcl.agent_interface.v2" },
    { .obj = AI_DOC_INTERFACE, .key = "build_commit",
      .op = AGENT_INTERFACE_OP_STR_EQ_BUILD },
    { .obj = AI_DOC_INTERFACE, .key = "preferred_transport",
      .op = AGENT_INTERFACE_OP_STR_EQ, .text = "native_cli" },
    { .obj = AI_DOC_INTERFACE, .key = "capabilities_schema",
      .op = AGENT_INTERFACE_OP_STR_EQ,
      .text = "zcl.agent_capability.v2" },
    { .obj = AI_DOC_TRANSPORTS, .op = AGENT_INTERFACE_OP_SIZE_EQ,
      .num = 2, .guard = true },
    { .obj = AI_DOC_MUST_LIVE, .op = AGENT_INTERFACE_OP_ARRAY_SUBSTR,
      .text = "deploy/restart safety decisions" },
    { .obj = AI_DOC_AVOID, .op = AGENT_INTERFACE_OP_ARRAY_SUBSTR,
      .text = "do not require Python" },
    { .obj = AI_DOC_CAPABILITIES, .op = AGENT_INTERFACE_OP_SIZE_GE,
      .num = 8, .guard = true },
    { .obj = AI_DOC_APP_PROTOCOLS, .key = "schema",
      .op = AGENT_INTERFACE_OP_STR_EQ,
      .text = "zcl.application_protocols.index.v2", .guard = true },
    { .obj = AI_DOC_SERVICE_CATALOG, .key = "schema",
      .op = AGENT_INTERFACE_OP_STR_EQ,
      .text = "zcl.service_catalog.v2", .guard = true },
    { .obj = AI_DOC_LANE_TOPOLOGY, .key = "schema",
      .op = AGENT_INTERFACE_OP_STR_EQ,
      .text = "zcl.agent_lanes.v2", .guard = true },
    { .obj = AI_DOC_UNIFIED_LIVENESS, .key = "schema",
      .op = AGENT_INTERFACE_OP_STR_EQ,
      .text = "zcl.agent_liveness.v2", .guard = true },
    { .obj = AI_DOC_FULL_COMPAT, .key = "schema",
      .op = AGENT_INTERFACE_OP_STR_EQ,
      .text = "zcl.public_status.v3", .guard = true },
    { .obj = AI_DOC_RUNTIME_STATUS, .op = AGENT_INTERFACE_OP_IS_NULL },
    { .obj = AI_DOC_RUNTIME_ALIAS, .op = AGENT_INTERFACE_OP_IS_NULL },
    { .obj = AI_DOC_MIRROR, .key = "schema",
      .op = AGENT_INTERFACE_OP_STR_EQ,
      .text = "zcl.mirror_status.v2", .guard = true },
    { .obj = AI_DOC_MIRROR, .key = "native",
      .op = AGENT_INTERFACE_OP_STR_EQ,
      .text = "z23 getmirrorstatus", .guard = true },
    { .obj = AI_DOC_DEPLOY, .key = "schema",
      .op = AGENT_INTERFACE_OP_STR_EQ,
      .text = "zcl.agent_deploy_guard.v1", .guard = true },
    { .obj = AI_DOC_STATE_CATALOG, .key = "schema",
      .op = AGENT_INTERFACE_OP_STR_EQ,
      .text = "zcl.state_catalog.v2", .guard = true },
    { .obj = AI_DOC_TIMELINE, .key = "schema",
      .op = AGENT_INTERFACE_OP_STR_EQ,
      .text = "zcl.timeline.v2", .guard = true },
    { .obj = AI_DOC_SUBSYSTEM, .key = "method",
      .op = AGENT_INTERFACE_OP_STR_EQ,
      .text = "dumpstate", .guard = true },
    { .obj = AI_DOC_SUBSYSTEM, .key = "contract_source",
      .op = AGENT_INTERFACE_OP_STR_EQ,
      .text = "agent_contracts.def", .guard = true },
    { .obj = AI_DOC_SUBSYSTEM, .key = "registry_alias",
      .op = AGENT_INTERFACE_OP_BOOL, .flag = false },
    { .obj = AI_DOC_SEMANTIC, .key = "method",
      .op = AGENT_INTERFACE_OP_STR_EQ,
      .text = "dumpstate", .guard = true },
    { .obj = AI_DOC_SEMANTIC, .key = "schema",
      .op = AGENT_INTERFACE_OP_STR_EQ_OTHER,
      .guard = true, .other = AI_DOC_SUBSYSTEM,
      .other_key = "schema" },
    { .obj = AI_DOC_SEMANTIC, .key = "registry_alias",
      .op = AGENT_INTERFACE_OP_BOOL, .flag = true, .guard = true },
    { .obj = AI_DOC_SEMANTIC, .key = "canonical_capability",
      .op = AGENT_INTERFACE_OP_STR_EQ,
      .text = "subsystem_state", .guard = true },
    { .obj = AI_DOC_NODE_LOG, .key = "method",
      .op = AGENT_INTERFACE_OP_STR_EQ,
      .text = "getnodelog", .guard = true },
    { .obj = AI_DOC_BOUNDED_LOGS, .key = "method",
      .op = AGENT_INTERFACE_OP_STR_EQ,
      .text = "getnodelog", .guard = true },
    { .obj = AI_DOC_BOUNDED_LOGS, .key = "registry_alias",
      .op = AGENT_INTERFACE_OP_BOOL, .flag = true, .guard = true },
    { .obj = AI_DOC_SQL, .key = "method",
      .op = AGENT_INTERFACE_OP_STR_EQ,
      .text = "dbquery", .guard = true },
    { .obj = AI_DOC_SELECT_SQL, .key = "method",
      .op = AGENT_INTERFACE_OP_STR_EQ,
      .text = "dbquery", .guard = true },
    { .obj = AI_DOC_SELECT_SQL, .key = "registry_alias",
      .op = AGENT_INTERFACE_OP_BOOL, .flag = true, .guard = true },
    { .obj = AI_DOC_DEV_LOOP, .key = "status",
      .op = AGENT_INTERFACE_OP_STR_EQ,
      .text = "z23 status", .guard = true },
    { .obj = AI_DOC_DEV_LOOP, .key = "full_compatibility_status",
      .op = AGENT_INTERFACE_OP_STR_EQ,
      .text = "z23 agent", .guard = true },
    { .obj = AI_DOC_DEV_LOOP, .key = "subsystem_state",
      .op = AGENT_INTERFACE_OP_STR_EQ,
      .text = "z23 dumpstate <subsystem> [key]", .guard = true },
    { .obj = AI_DOC_DEV_LOOP, .key = "logs",
      .op = AGENT_INTERFACE_OP_STR_EQ,
      .text = "z23 getnodelog <pattern>", .guard = true },
    { .obj = AI_DOC_DEV_LOOP, .key = "database",
      .op = AGENT_INTERFACE_OP_STR_EQ,
      .text = "z23 dbquery <SELECT>", .guard = true },
    { .obj = AI_DOC_VISUAL_INSTRUMENTS, .op = AGENT_INTERFACE_OP_SIZE_EQ,
      .num = 11, .guard = true },
    { .obj = AI_DOC_VISUAL_QR, .key = "native",
      .op = AGENT_INTERFACE_OP_STR_EQ,
      .text = "z23 app qr show 'zclassic:t1...?amount=0.01'",
      .guard = true },
    { .obj = AI_DOC_VISUAL_QR, .key = "path",
      .op = AGENT_INTERFACE_OP_STR_EQ,
      .text = "app.qr.show", .guard = true },
    { .obj = AI_DOC_VISUAL_QR, .key = "input_schema",
      .op = AGENT_INTERFACE_OP_STR_EQ,
      .text = "zcl.app_qr_show.input.v1", .guard = true },
    { .obj = AI_DOC_VISUAL_QR, .key = "input_keys",
      .op = AGENT_INTERFACE_OP_SUBSTR, .text = "output", .guard = true },
    { .obj = AI_DOC_VISUAL_STATUS, .key = "native",
      .op = AGENT_INTERFACE_OP_STR_EQ,
      .text = "z23 app presentation status", .guard = true },
    { .obj = AI_DOC_VISUAL_DIFF, .key = "native",
      .op = AGENT_INTERFACE_OP_SUBSTR,
      .text = "app presentation code-change", .guard = true },
    { .obj = AI_DOC_VISUAL_PROGRESS, .key = "native",
      .op = AGENT_INTERFACE_OP_SUBSTR,
      .text = "app presentation reproduction", .guard = true },
    { .obj = AI_DOC_VISUAL_CONFIRM, .key = "native",
      .op = AGENT_INTERFACE_OP_SUBSTR,
      .text = "app presentation publication-confirm", .guard = true },
    { .obj = AI_DOC_VISUAL_CORPUS, .key = "native",
      .op = AGENT_INTERFACE_OP_STR_EQ,
      .text = "z23 app presentation corpus", .guard = true },
    { .obj = AI_DOC_VISUAL_GROWTH, .key = "path",
      .op = AGENT_INTERFACE_OP_STR_EQ,
      .text = "app.presentation.code-growth", .guard = true },
    { .obj = AI_DOC_VISUAL_GROWTH, .key = "input_schema",
      .op = AGENT_INTERFACE_OP_STR_EQ,
      .text = "zcl.app_presentation_code_growth.input.v1", .guard = true },
    { .obj = AI_DOC_VISUAL_ECOSYSTEM, .key = "path",
      .op = AGENT_INTERFACE_OP_STR_EQ,
      .text = "app.presentation.ecosystem", .guard = true },
    { .obj = AI_DOC_VISUAL_ECOSYSTEM, .key = "native",
      .op = AGENT_INTERFACE_OP_STR_EQ,
      .text = "z23 app presentation ecosystem", .guard = true },
    { .obj = AI_DOC_VISUAL_PUBLICATION, .key = "native",
      .op = AGENT_INTERFACE_OP_SUBSTR,
      .text = "app presentation publication-status", .guard = true },
    { .obj = AI_DOC_VISUAL_BOUNDED, .key = "native",
      .op = AGENT_INTERFACE_OP_SUBSTR,
      .text = "app presentation show", .guard = true },
    { .obj = AI_DOC_VISUAL_BOUNDED, .key = "input_schema",
      .op = AGENT_INTERFACE_OP_STR_EQ,
      .text = "zcl.app_presentation_show.input.v1", .guard = true },
    { .obj = AI_DOC_VISUAL_BOUNDED, .key = "discover_input",
      .op = AGENT_INTERFACE_OP_STR_EQ,
      .text = "z23 discover schema app.presentation.show", .guard = true },
    { .obj = AI_DOC_VISUAL_RELEASE, .key = "native",
      .op = AGENT_INTERFACE_OP_SUBSTR,
      .text = "app presentation release-confirm", .guard = true },
    { .obj = AI_DOC_VISUAL_LOOP, .key = "schema",
      .op = AGENT_INTERFACE_OP_STR_EQ,
      .text = "zcl.agent_visual_loop.v1", .guard = true },
    { .obj = AI_DOC_VISUAL_LOOP, .key = "default_channel",
      .op = AGENT_INTERFACE_OP_STR_EQ,
      .text = "ai_conversation", .guard = true },
    { .obj = AI_DOC_VISUAL_LOOP, .key = "unsolicited_windows",
      .op = AGENT_INTERFACE_OP_BOOL, .flag = false, .guard = true },
    { .obj = AI_DOC_VISUAL_LOOP, .key = "query_rule",
      .op = AGENT_INTERFACE_OP_SUBSTR,
      .text = "answer ordinary questions directly", .guard = true },
    { .obj = AI_DOC_VISUAL_LOOP, .key = "visual_trigger",
      .op = AGENT_INTERFACE_OP_SUBSTR,
      .text = "explicitly asks", .guard = true },
    { .obj = AI_DOC_VISUAL_LOOP, .key = "media_rule",
      .op = AGENT_INTERFACE_OP_SUBSTR,
      .text = "QR, image, movie, and NFT media", .guard = true },
    { .obj = AI_DOC_VISUAL_LOOP, .key = "media_rule",
      .op = AGENT_INTERFACE_OP_SUBSTR,
      .text = "never improvise a browser", .guard = true },
    { .obj = AI_DOC_VISUAL_LOOP, .key = "input_discovery",
      .op = AGENT_INTERFACE_OP_STR_EQ,
      .text = "z23 discover schema <leaf>", .guard = true },
    { .obj = AI_DOC_VISUAL_LOOP, .key = "text_companion",
      .op = AGENT_INTERFACE_OP_SUBSTR,
      .text = "output=text", .guard = true },
    { .obj = AI_DOC_VISUAL_LOOP, .key = "selection_rule",
      .op = AGENT_INTERFACE_OP_SUBSTR,
      .text = "typed instrument for node-owned facts", .guard = true },
    { .obj = AI_DOC_VISUAL_LOOP, .key = "browser_required",
      .op = AGENT_INTERFACE_OP_BOOL, .flag = false, .guard = true },
    { .obj = AI_DOC_VISUAL_LOOP, .key = "authority_rule",
      .op = AGENT_INTERFACE_OP_SUBSTR,
      .text = "visual host owns none", .guard = true },
    { .obj = AI_DOC_VISUAL_LOOP, .key = "generic_model_policy",
      .op = AGENT_INTERFACE_OP_SUBSTR,
      .text = "only for inert agent-supplied visuals", .guard = true },
    { .obj = AI_DOC_MACHINE, .key = "schema",
      .op = AGENT_INTERFACE_OP_STR_EQ,
      .text = "zcl.agent_machine_contract.v2", .guard = true },
    { .obj = AI_DOC_MACHINE, .key = "payload",
      .op = AGENT_INTERFACE_OP_STR_EQ,
      .text = "json_object", .guard = true },
    { .obj = AI_DOC_MACHINE, .key = "schema_required",
      .op = AGENT_INTERFACE_OP_BOOL, .flag = true },
    { .obj = AI_DOC_MACHINE, .key = "transport_equivalent_payloads",
      .op = AGENT_INTERFACE_OP_BOOL, .flag = true },
    { .obj = AI_DOC_MACHINE, .key = "no_python_required",
      .op = AGENT_INTERFACE_OP_BOOL, .flag = true },
    { .obj = AI_DOC_MACHINE, .key = "typed_native_commands_required",
      .op = AGENT_INTERFACE_OP_BOOL, .flag = true },
    { .obj = AI_DOC_RUNTIME, .key = "schema",
      .op = AGENT_INTERFACE_OP_STR_EQ,
      .text = "zcl.agent_runtime_identity.v1", .guard = true },
    { .obj = AI_DOC_RUNTIME, .key = "build_commit",
      .op = AGENT_INTERFACE_OP_STR_EQ_BUILD, .guard = true },
    { .obj = AI_DOC_RUNTIME, .key = "binary",
      .op = AGENT_INTERFACE_OP_STR_EQ,
      .text = "zclassic23", .guard = true },
    { .obj = AI_DOC_AVAILABILITY, .key = "schema",
      .op = AGENT_INTERFACE_OP_STR_EQ,
      .text = "zcl.agent_runtime_availability.v3", .guard = true },
    { .obj = AI_DOC_AVAILABILITY, .key = "schema_version",
      .op = AGENT_INTERFACE_OP_INT_EQ, .num = 3, .guard = true },
    { .obj = AI_DOC_AVAILABILITY, .key = "availability_scope",
      .op = AGENT_INTERFACE_OP_STR_EQ,
      .text = "target_rpc_probe", .guard = true },
    { .obj = AI_DOC_AVAILABILITY, .key = "probe_status",
      .op = AGENT_INTERFACE_OP_STR_EQ, .text = "ok", .guard = true },
    { .obj = AI_DOC_AVAILABILITY, .key = "target_source_id_sha256",
      .op = AGENT_INTERFACE_OP_STR_EQ,
      .text = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
      .guard = true },
    { .obj = AI_DOC_AVAILABILITY, .key = "target_build_commit",
      .op = AGENT_INTERFACE_OP_STR_EQ,
      .text = "oldbuild", .guard = true },
    { .obj = AI_DOC_AVAILABILITY, .key = "producer_target_source_relation",
      .op = AGENT_INTERFACE_OP_STR_EQ,
      .text = "different", .guard = true },
    { .obj = AI_DOC_AVAILABILITY, .key = "producer_target_build_relation",
      .op = AGENT_INTERFACE_OP_STR_EQ,
      .text = "unknown", .guard = true },
    { .obj = AI_DOC_AVAILABILITY,
      .key = "producer_target_build_relation_authority",
      .op = AGENT_INTERFACE_OP_STR_EQ,
      .text = "unavailable_artifact_and_build_epoch_identity",
      .guard = true },
    { .obj = AI_DOC_AVAILABILITY, .key = "unsupported_count",
      .op = AGENT_INTERFACE_OP_INT_GE, .num = 1, .guard = true },
    { .obj = AI_DOC_AVAILABILITY, .key = "safe_next_action",
      .op = AGENT_INTERFACE_OP_SUBSTR,
      .text = "do not call unsupported methods", .guard = true },
    { .obj = AI_DOC_AGENT_METHOD, .key = "target_runtime_support",
      .op = AGENT_INTERFACE_OP_STR_EQ,
      .text = "supported", .guard = true },
    { .obj = AI_DOC_AGENT_METHOD, .key = "safe_to_call_target",
      .op = AGENT_INTERFACE_OP_BOOL, .flag = true },
    { .obj = AI_DOC_AGENTOPS_METHOD, .key = "target_runtime_support",
      .op = AGENT_INTERFACE_OP_STR_EQ,
      .text = "unsupported_method_not_found", .guard = true },
    { .obj = AI_DOC_AGENTOPS_METHOD, .key = "target_runtime_supports",
      .op = AGENT_INTERFACE_OP_BOOL, .flag = false, .guard = true },
    { .obj = AI_DOC_AGENTOPS_METHOD, .key = "safe_to_call_target",
      .op = AGENT_INTERFACE_OP_BOOL, .flag = false, .guard = true },
    { .obj = AI_DOC_AGENTOPS_METHOD, .key = "rpc_error_code",
      .op = AGENT_INTERFACE_OP_INT_EQ,
      .num = RPC_METHOD_NOT_FOUND, .guard = true },
};

static bool agent_interface_document_matches(
    bool ok, const struct json_value *interface)
{
    const struct json_value *interface_transports =
        json_get(interface, "transports");
    const struct json_value *must_live_in_c =
        json_get(interface, "must_live_in_c");
    const struct json_value *avoid = json_get(interface, "avoid");
    const struct json_value *capabilities =
        json_get(interface, "capabilities");
    const struct json_value *full_compatibility_status =
        find_object_with_str(capabilities, "name",
                             "full_compatibility_status");
    const struct json_value *runtime_status =
        find_object_with_str(capabilities, "name", "runtime_status");
    const struct json_value *runtime_status_alias =
        find_object_with_str(capabilities, "name", "runtime_status_alias");
    const struct json_value *mirror_status =
        find_object_with_str(capabilities, "name", "mirror_status");
    const struct json_value *lane_topology =
        find_object_with_str(capabilities, "name", "lane_topology");
    const struct json_value *unified_liveness =
        find_object_with_str(capabilities, "name", "unified_liveness");
    const struct json_value *deploy_cap =
        find_object_with_str(capabilities, "name", "deploy_guard");
    const struct json_value *state_catalog_cap =
        find_object_with_str(capabilities, "name", "state_catalog");
    const struct json_value *timeline_cap =
        find_object_with_str(capabilities, "name", "semantic_timeline");
    const struct json_value *app_protocols_cap =
        find_object_with_str(capabilities, "name",
                             "application_protocol_catalog");
    const struct json_value *service_catalog_cap =
        find_object_with_str(capabilities, "name",
                             "sovereign_service_catalog");
    const struct json_value *subsystem_state_cap =
        find_object_with_str(capabilities, "name", "subsystem_state");
    const struct json_value *semantic_state_cap =
        find_object_with_str(capabilities, "name", "semantic_state");
    const struct json_value *node_log_cap =
        find_object_with_str(capabilities, "name", "node_log_search");
    const struct json_value *bounded_logs_cap =
        find_object_with_str(capabilities, "name", "bounded_logs");
    const struct json_value *sql_cap =
        find_object_with_str(capabilities, "name", "sql_inspection");
    const struct json_value *select_sql_cap =
        find_object_with_str(capabilities, "name", "select_sql");
    const struct json_value *machine =
        json_get(interface, "machine_contract");
    const struct json_value *runtime =
        json_get(interface, "runtime_identity");
    const struct json_value *development_loop =
        json_get(interface, "development_loop");
    const struct json_value *visual_instruments =
        json_get(interface, "native_visual_instruments");
    const struct json_value *visual_loop =
        json_get(interface, "native_visual_loop");
    const struct json_value *visual_qr =
        find_object_with_str(visual_instruments, "name", "qr");
    const struct json_value *visual_status =
        find_object_with_str(visual_instruments, "name", "node_status");
    const struct json_value *visual_diff =
        find_object_with_str(visual_instruments, "name", "code_change");
    const struct json_value *visual_progress =
        find_object_with_str(visual_instruments, "name",
                             "reproduction_progress");
    const struct json_value *visual_confirmation =
        find_object_with_str(visual_instruments, "name",
                             "publication_confirmation");
    const struct json_value *visual_corpus =
        find_object_with_str(visual_instruments, "name",
                             "corpus_status");
    const struct json_value *visual_growth =
        find_object_with_str(visual_instruments, "name", "code_growth");
    const struct json_value *visual_ecosystem =
        find_object_with_str(visual_instruments, "name", "ecosystem");
    const struct json_value *visual_publication =
        find_object_with_str(visual_instruments, "name",
                             "publication_status");
    const struct json_value *visual_bounded =
        find_object_with_str(visual_instruments, "name",
                             "bounded_display");
    const struct json_value *visual_release_confirmation =
        find_object_with_str(visual_instruments, "name",
                             "release_confirmation");
    const struct json_value *availability =
        json_get(interface, "runtime_availability");
    const struct json_value *availability_methods =
        availability ? json_get(availability, "methods") : NULL;
    const struct json_value *agent_method =
        find_object_with_str(availability_methods, "method", "agent");
    const struct json_value *agentops_method =
        find_object_with_str(availability_methods, "method", "agentops");
    const struct json_value *objs[] = {
        interface,
        interface_transports,
        must_live_in_c,
        avoid,
        capabilities,
        app_protocols_cap,
        service_catalog_cap,
        lane_topology,
        unified_liveness,
        full_compatibility_status,
        runtime_status,
        runtime_status_alias,
        mirror_status,
        deploy_cap,
        state_catalog_cap,
        timeline_cap,
        subsystem_state_cap,
        semantic_state_cap,
        node_log_cap,
        bounded_logs_cap,
        sql_cap,
        select_sql_cap,
        development_loop,
        visual_instruments,
        visual_qr,
        visual_status,
        visual_diff,
        visual_progress,
        visual_confirmation,
        visual_corpus,
        visual_growth,
        visual_ecosystem,
        visual_publication,
        visual_bounded,
        visual_release_confirmation,
        visual_loop,
        machine,
        runtime,
        availability,
        agent_method,
        agentops_method,
    };
    return agent_interface_expect_rows(
        ok, objs, k_agent_interface_doc_rows,
        sizeof k_agent_interface_doc_rows /
            sizeof k_agent_interface_doc_rows[0]);
}

enum {
    AI_PROBED_AVAILABILITY = 0,
    AI_PROBED_METHOD
};

static const struct agent_interface_expect k_agent_interface_probed_rows[] = {
    { .obj = AI_PROBED_AVAILABILITY, .key = "availability_scope",
      .op = AGENT_INTERFACE_OP_STR_EQ,
      .text = "target_rpc_probe", .guard = true },
    { .obj = AI_PROBED_METHOD, .key = "target_runtime_support",
      .op = AGENT_INTERFACE_OP_STR_EQ,
      .text = "unsupported_method_not_found", .guard = true },
};

static bool agent_interface_probed_ops_matches(
    bool ok, struct rpc_table *tbl, struct json_value *params)
{
    struct json_value probed_ops;
    json_init(&probed_ops);
    ok = ok && rpc_table_execute(tbl, "agentops", params, &probed_ops);
    const struct json_value *probed_ops_availability =
        json_get(&probed_ops, "runtime_availability");
    const struct json_value *probed_ops_methods =
        probed_ops_availability
            ? json_get(probed_ops_availability, "methods") : NULL;
    const struct json_value *probed_ops_method =
        find_object_with_str(probed_ops_methods, "method", "agentops");
    const struct json_value *objs[] = {
        probed_ops_availability, probed_ops_method
    };
    ok = agent_interface_expect_rows(
        ok, objs, k_agent_interface_probed_rows,
        sizeof k_agent_interface_probed_rows /
            sizeof k_agent_interface_probed_rows[0]);
    json_free(&probed_ops);
    agent_runtime_availability_reset();
    return ok;
}

static const struct agent_interface_expect k_agent_interface_rss_rows[] = {
    { .op = AGENT_INTERFACE_OP_TYPE_OBJ },
    { .key = "schema", .op = AGENT_INTERFACE_OP_STR_EQ,
      .text = "zcl.node_resources.v1" },
    { .key = "schema_version", .op = AGENT_INTERFACE_OP_INT_EQ, .num = 1 },
    { .key = "rss_mb", .op = AGENT_INTERFACE_OP_INT_EQ, .num = 5000 },
    { .key = "rss_warning", .op = AGENT_INTERFACE_OP_BOOL, .flag = true },
    { .key = "memory_pressure", .op = AGENT_INTERFACE_OP_STR_EQ,
      .text = "warn" },
    { .key = "memory_pressure_detail", .op = AGENT_INTERFACE_OP_STR_EQ,
      .text = "rss_over_threshold" },
    { .key = "pressure_basis", .op = AGENT_INTERFACE_OP_STR_EQ,
      .text = "rss" },
};

static const struct agent_interface_expect k_agent_interface_cgroup_ok_rows[] = {
    { .op = AGENT_INTERFACE_OP_TYPE_OBJ },
    { .key = "cgroup_memory_available",
      .op = AGENT_INTERFACE_OP_BOOL, .flag = true },
    { .key = "cgroup_memory_current_mb",
      .op = AGENT_INTERFACE_OP_INT_EQ, .num = 9000 },
    { .key = "cgroup_memory_stat_available",
      .op = AGENT_INTERFACE_OP_BOOL, .flag = true },
    { .key = "cgroup_memory_working_set_mb",
      .op = AGENT_INTERFACE_OP_INT_EQ, .num = 4300 },
    { .key = "cgroup_memory_reclaimable_dominant",
      .op = AGENT_INTERFACE_OP_BOOL, .flag = true },
    { .key = "memory_pressure", .op = AGENT_INTERFACE_OP_STR_EQ,
      .text = "ok" },
    { .key = "memory_pressure_detail", .op = AGENT_INTERFACE_OP_STR_EQ,
      .text = "within_limits" },
    { .key = "pressure_basis", .op = AGENT_INTERFACE_OP_STR_EQ,
      .text = "cgroup_high" },
};

static const struct agent_interface_expect
k_agent_interface_cgroup_cache_watch_rows[] = {
    { .op = AGENT_INTERFACE_OP_TYPE_OBJ },
    { .key = "cgroup_memory_watch",
      .op = AGENT_INTERFACE_OP_BOOL, .flag = true },
    { .key = "cgroup_memory_warning",
      .op = AGENT_INTERFACE_OP_BOOL, .flag = false },
    { .key = "memory_pressure", .op = AGENT_INTERFACE_OP_STR_EQ,
      .text = "watch" },
    { .key = "memory_pressure_detail", .op = AGENT_INTERFACE_OP_STR_EQ,
      .text = "cgroup_cache_watch" },
};

static const struct agent_interface_expect
k_agent_interface_cgroup_reclaimable_rows[] = {
    { .op = AGENT_INTERFACE_OP_TYPE_OBJ },
    { .key = "cgroup_memory_watch",
      .op = AGENT_INTERFACE_OP_BOOL, .flag = true },
    { .key = "cgroup_memory_warning",
      .op = AGENT_INTERFACE_OP_BOOL, .flag = false },
    { .key = "memory_pressure", .op = AGENT_INTERFACE_OP_STR_EQ,
      .text = "watch" },
    { .key = "memory_pressure_detail", .op = AGENT_INTERFACE_OP_STR_EQ,
      .text = "cgroup_reclaimable_cache_high" },
};

static const struct agent_interface_expect
k_agent_interface_cgroup_working_set_rows[] = {
    { .op = AGENT_INTERFACE_OP_TYPE_OBJ },
    { .key = "cgroup_memory_warning",
      .op = AGENT_INTERFACE_OP_BOOL, .flag = true },
    { .key = "memory_pressure", .op = AGENT_INTERFACE_OP_STR_EQ,
      .text = "warn" },
    { .key = "memory_pressure_detail", .op = AGENT_INTERFACE_OP_STR_EQ,
      .text = "cgroup_working_set_high" },
};

static bool agent_interface_one_resource_matches(
    bool ok,
    const struct agent_resource_snapshot *snap,
    const struct agent_interface_expect *rows,
    size_t n)
{
    struct json_value resources_body;
    json_init(&resources_body);
    json_set_object(&resources_body);
    agent_push_resources_json(&resources_body, "resources", snap);
    const struct json_value *fixed = json_get(&resources_body, "resources");
    const struct json_value *objs[] = { fixed };
    ok = agent_interface_expect_rows(ok, objs, rows, n);
    json_free(&resources_body);
    return ok;
}

static bool agent_interface_resource_snapshots_match(bool ok)
{
    struct agent_resource_snapshot fixed_resources = {
        .rss_mb = 5000,
        .rss_warn_threshold_mb = 4096,
        .rss_warning = true,
        .cgroup_memory_available = false,
        .cgroup_memory_current_mb = -1,
        .cgroup_memory_high_mb = -1,
        .cgroup_memory_max_mb = -1,
        .cgroup_memory_high_pct = -1,
        .cgroup_memory_max_pct = -1,
        .cgroup_memory_stat_available = false,
        .cgroup_memory_anon_mb = -1,
        .cgroup_memory_file_mb = -1,
        .cgroup_memory_kernel_mb = -1,
        .cgroup_memory_inactive_file_mb = -1,
        .cgroup_memory_slab_reclaimable_mb = -1,
        .cgroup_memory_reclaimable_mb = -1,
        .cgroup_memory_working_set_mb = -1,
        .cgroup_memory_working_set_high_pct = -1,
        .cgroup_memory_working_set_max_pct = -1,
        .cgroup_memory_reclaimable_dominant = false,
        .cgroup_memory_watch = false,
        .cgroup_memory_warning = false,
        .uptime_seconds = 123,
    };
    ok = agent_interface_one_resource_matches(
        ok, &fixed_resources, k_agent_interface_rss_rows,
        sizeof k_agent_interface_rss_rows /
            sizeof k_agent_interface_rss_rows[0]);

    struct agent_resource_snapshot cgroup_resources = {
        .rss_mb = 9000,
        .rss_warn_threshold_mb = 4096,
        .rss_warning = true,
        .cgroup_memory_available = true,
        .cgroup_memory_current_mb = 9000,
        .cgroup_memory_high_mb = 12000,
        .cgroup_memory_max_mb = 16000,
        .cgroup_memory_high_pct = 75,
        .cgroup_memory_max_pct = 56,
        .cgroup_memory_stat_available = true,
        .cgroup_memory_anon_mb = 3000,
        .cgroup_memory_file_mb = 5000,
        .cgroup_memory_kernel_mb = 200,
        .cgroup_memory_inactive_file_mb = 4500,
        .cgroup_memory_slab_reclaimable_mb = 200,
        .cgroup_memory_reclaimable_mb = 4700,
        .cgroup_memory_working_set_mb = 4300,
        .cgroup_memory_working_set_high_pct = 35,
        .cgroup_memory_working_set_max_pct = 26,
        .cgroup_memory_reclaimable_dominant = true,
        .cgroup_memory_watch = false,
        .cgroup_memory_warning = false,
        .uptime_seconds = 456,
    };
    ok = agent_interface_one_resource_matches(
        ok, &cgroup_resources, k_agent_interface_cgroup_ok_rows,
        sizeof k_agent_interface_cgroup_ok_rows /
            sizeof k_agent_interface_cgroup_ok_rows[0]);

    cgroup_resources.cgroup_memory_current_mb = 10320;
    cgroup_resources.cgroup_memory_high_pct = 86;
    cgroup_resources.cgroup_memory_max_pct = 64;
    cgroup_resources.cgroup_memory_working_set_mb = 4300;
    cgroup_resources.cgroup_memory_working_set_high_pct = 35;
    cgroup_resources.cgroup_memory_working_set_max_pct = 26;
    cgroup_resources.cgroup_memory_reclaimable_dominant = true;
    cgroup_resources.cgroup_memory_watch = true;
    cgroup_resources.cgroup_memory_warning = false;
    ok = agent_interface_one_resource_matches(
        ok, &cgroup_resources, k_agent_interface_cgroup_cache_watch_rows,
        sizeof k_agent_interface_cgroup_cache_watch_rows /
            sizeof k_agent_interface_cgroup_cache_watch_rows[0]);

    cgroup_resources.cgroup_memory_current_mb = 11520;
    cgroup_resources.cgroup_memory_high_pct = 96;
    cgroup_resources.cgroup_memory_max_pct = 72;
    cgroup_resources.cgroup_memory_working_set_mb = 4800;
    cgroup_resources.cgroup_memory_working_set_high_pct = 40;
    cgroup_resources.cgroup_memory_working_set_max_pct = 30;
    cgroup_resources.cgroup_memory_reclaimable_dominant = true;
    cgroup_resources.cgroup_memory_watch = true;
    cgroup_resources.cgroup_memory_warning = false;
    ok = agent_interface_one_resource_matches(
        ok, &cgroup_resources, k_agent_interface_cgroup_reclaimable_rows,
        sizeof k_agent_interface_cgroup_reclaimable_rows /
            sizeof k_agent_interface_cgroup_reclaimable_rows[0]);

    cgroup_resources.cgroup_memory_current_mb = 11400;
    cgroup_resources.cgroup_memory_high_pct = 95;
    cgroup_resources.cgroup_memory_max_pct = 71;
    cgroup_resources.cgroup_memory_working_set_mb = 10320;
    cgroup_resources.cgroup_memory_working_set_high_pct = 86;
    cgroup_resources.cgroup_memory_working_set_max_pct = 64;
    cgroup_resources.cgroup_memory_reclaimable_dominant = false;
    cgroup_resources.cgroup_memory_watch = true;
    cgroup_resources.cgroup_memory_warning = true;
    return agent_interface_one_resource_matches(
        ok, &cgroup_resources, k_agent_interface_cgroup_working_set_rows,
        sizeof k_agent_interface_cgroup_working_set_rows /
            sizeof k_agent_interface_cgroup_working_set_rows[0]);
}

static const struct agent_interface_expect
k_agent_interface_watchdog_burning_rows[] = {
    { .op = AGENT_INTERFACE_OP_TYPE_OBJ },
    { .key = "schema", .op = AGENT_INTERFACE_OP_STR_EQ,
      .text = "zcl.restart_watchdog.v1" },
    { .key = "status", .op = AGENT_INTERFACE_OP_STR_EQ,
      .text = "restart_budget_burning" },
    { .key = "last_restart_autonomous",
      .op = AGENT_INTERFACE_OP_BOOL, .flag = true },
    { .key = "last_restart_reason", .op = AGENT_INTERFACE_OP_STR_EQ,
      .text = "no_progress_tip_stall" },
    { .key = "persisted_stuck_height",
      .op = AGENT_INTERFACE_OP_INT_EQ, .num = 3171109 },
    { .key = "no_progress_restarts",
      .op = AGENT_INTERFACE_OP_INT_EQ, .num = 1 },
    { .key = "restarts_remaining",
      .op = AGENT_INTERFACE_OP_INT_EQ, .num = 2 },
    { .key = "deep_state", .op = AGENT_INTERFACE_OP_STR_EQ,
      .text = "z23 dumpstate chain_tip_watchdog" },
};

static const struct agent_interface_expect
k_agent_interface_watchdog_exhausted_rows[] = {
    { .op = AGENT_INTERFACE_OP_TYPE_OBJ },
    { .key = "status", .op = AGENT_INTERFACE_OP_STR_EQ,
      .text = "restart_budget_exhausted" },
    { .key = "restart_budget_exhausted",
      .op = AGENT_INTERFACE_OP_BOOL, .flag = true },
    { .key = "restarts_remaining",
      .op = AGENT_INTERFACE_OP_INT_EQ, .num = 0 },
};

static bool agent_interface_one_watchdog_matches(
    bool ok,
    const struct agent_restart_watchdog_snapshot *wd,
    const struct agent_interface_expect *rows,
    size_t n)
{
    struct json_value watchdog_body;
    json_init(&watchdog_body);
    json_set_object(&watchdog_body);
    agent_push_restart_watchdog_json(&watchdog_body,
                                     "restart_watchdog", wd);
    const struct json_value *wd_json =
        json_get(&watchdog_body, "restart_watchdog");
    const struct json_value *objs[] = { wd_json };
    ok = agent_interface_expect_rows(ok, objs, rows, n);
    json_free(&watchdog_body);
    return ok;
}

static bool agent_interface_watchdog_snapshots_match(bool ok)
{
    struct agent_restart_watchdog_snapshot wd = {
        .registered = true,
        .highest_tip = 3171111,
        .last_advance_unix = 1783268402,
        .age_secs = 45,
        .escalation_level = 0,
        .fires_mirror = 2,
        .fires_restart = 0,
        .fires_operator_needed = 0,
        .threshold_restart_secs = 1200,
        .persisted_stuck_height = 3171109,
        .no_progress_restarts = 1,
        .max_restarts = 3,
        .operator_needed = false,
    };
    ok = agent_interface_one_watchdog_matches(
        ok, &wd, k_agent_interface_watchdog_burning_rows,
        sizeof k_agent_interface_watchdog_burning_rows /
            sizeof k_agent_interface_watchdog_burning_rows[0]);

    wd.no_progress_restarts = 3;
    wd.fires_restart = 3;
    wd.operator_needed = false;
    return agent_interface_one_watchdog_matches(
        ok, &wd, k_agent_interface_watchdog_exhausted_rows,
        sizeof k_agent_interface_watchdog_exhausted_rows /
            sizeof k_agent_interface_watchdog_exhausted_rows[0]);
}

enum {
    AI_GUARD_ROOT = 0,
    AI_GUARD_TARGET,
    AI_GUARD_RECOVERY
};

static const struct agent_interface_expect
k_agent_interface_canonical_rows[] = {
    { .obj = AI_GUARD_ROOT, .op = AGENT_INTERFACE_OP_TYPE_OBJ },
    { .obj = AI_GUARD_ROOT, .key = "schema",
      .op = AGENT_INTERFACE_OP_STR_EQ,
      .text = "zcl.agent_deploy_guard.v1" },
    { .obj = AI_GUARD_ROOT, .key = "allowed",
      .op = AGENT_INTERFACE_OP_BOOL, .flag = false },
    { .obj = AI_GUARD_ROOT, .key = "decision",
      .op = AGENT_INTERFACE_OP_STR_EQ, .text = "refuse" },
    { .obj = AI_GUARD_ROOT, .key = "reason",
      .op = AGENT_INTERFACE_OP_STR_EQ,
      .text = "operator_confirmation_required" },
    { .obj = AI_GUARD_ROOT, .key = "exit_code",
      .op = AGENT_INTERFACE_OP_INT_EQ, .num = 1 },
    { .obj = AI_GUARD_ROOT, .key = "operator_lane_name",
      .op = AGENT_INTERFACE_OP_STR_EQ, .text = "canonical" },
    { .obj = AI_GUARD_ROOT, .key = "automation_restart_ok",
      .op = AGENT_INTERFACE_OP_BOOL, .flag = false },
    { .obj = AI_GUARD_ROOT, .key = "automation_deploy_ok",
      .op = AGENT_INTERFACE_OP_BOOL, .flag = false },
    { .obj = AI_GUARD_ROOT, .key = "requires_operator_confirmation",
      .op = AGENT_INTERFACE_OP_BOOL, .flag = true },
    { .obj = AI_GUARD_ROOT, .key = "preferred_deploy_target",
      .op = AGENT_INTERFACE_OP_STR_EQ, .text = "dev" },
    { .obj = AI_GUARD_ROOT, .key = "safe_default_action",
      .op = AGENT_INTERFACE_OP_STR_EQ,
      .text = "observe_only_or_use_dev_lane" },
    { .obj = AI_GUARD_ROOT, .key = "action_scope",
      .op = AGENT_INTERFACE_OP_STR_EQ,
      .text = "explicit_target_lane" },
    { .obj = AI_GUARD_ROOT, .key = "current_lane_name",
      .op = AGENT_INTERFACE_OP_STR_EQ, .text = "canonical" },
    { .obj = AI_GUARD_ROOT, .key = "target_lane_name",
      .op = AGENT_INTERFACE_OP_STR_EQ, .text = "canonical" },
    { .obj = AI_GUARD_TARGET, .op = AGENT_INTERFACE_OP_TYPE_OBJ },
    { .obj = AI_GUARD_TARGET, .key = "lane",
      .op = AGENT_INTERFACE_OP_STR_EQ, .text = "canonical" },
    { .obj = AI_GUARD_TARGET, .key = "https_port",
      .op = AGENT_INTERFACE_OP_INT_EQ, .num = 8443 },
};

static const struct agent_interface_expect
k_agent_interface_inferred_rows[] = {
    { .obj = AI_GUARD_TARGET, .op = AGENT_INTERFACE_OP_TYPE_OBJ },
    { .obj = AI_GUARD_TARGET, .key = "lane",
      .op = AGENT_INTERFACE_OP_STR_EQ, .text = "canonical" },
    { .obj = AI_GUARD_TARGET, .key = "lane_source",
      .op = AGENT_INTERFACE_OP_STR_EQ,
      .text = "inferred_exact_topology" },
    { .obj = AI_GUARD_TARGET, .key = "lane_declared",
      .op = AGENT_INTERFACE_OP_BOOL, .flag = false },
    { .obj = AI_GUARD_TARGET, .key = "lane_inferred",
      .op = AGENT_INTERFACE_OP_BOOL, .flag = true },
    { .obj = AI_GUARD_ROOT, .key = "current_lane_name",
      .op = AGENT_INTERFACE_OP_STR_EQ, .text = "canonical" },
    { .obj = AI_GUARD_ROOT, .key = "operator_lane_name",
      .op = AGENT_INTERFACE_OP_STR_EQ, .text = "canonical" },
    { .obj = AI_GUARD_ROOT, .key = "guard_env",
      .op = AGENT_INTERFACE_OP_STR_EQ,
      .text = "ZCL_DEPLOY_ALLOW_CANONICAL" },
    { .obj = AI_GUARD_ROOT, .key = "allowed",
      .op = AGENT_INTERFACE_OP_BOOL, .flag = false },
    { .obj = AI_GUARD_ROOT, .key = "reason",
      .op = AGENT_INTERFACE_OP_STR_EQ,
      .text = "operator_confirmation_required" },
};

static bool agent_interface_inferred_home_guard_matches(
    bool ok, struct rpc_table *tbl)
{
    ok = ok && setenv("HOME", "/tmp/zcl-agent-home", 1) == 0;
    rpc_agent_set_boot_context("unknown", "full",
                               "/tmp/zcl-agent-home/.zclassic-c23",
                               18232, 8033, 8443, 18034);
    struct json_value inferred_guard_params;
    json_init(&inferred_guard_params);
    json_set_array(&inferred_guard_params);
    struct json_value action;
    json_init(&action);
    json_set_str(&action, "deploy");
    json_push_back(&inferred_guard_params, &action);
    json_free(&action);
    struct json_value inferred_guard;
    json_init(&inferred_guard);
    ok = ok && rpc_table_execute(tbl, "agentdeployguard",
                                 &inferred_guard_params, &inferred_guard);
    const struct json_value *inferred_lane =
        json_get(&inferred_guard, "operator_lane");
    const struct json_value *objs[] = { &inferred_guard, inferred_lane };
    ok = agent_interface_expect_rows(
        ok, objs, k_agent_interface_inferred_rows,
        sizeof k_agent_interface_inferred_rows /
            sizeof k_agent_interface_inferred_rows[0]);
    json_free(&inferred_guard_params);
    json_free(&inferred_guard);
    return ok;
}

static const struct agent_interface_expect
k_agent_interface_restart_object_rows[] = {
    { .key = "action", .op = AGENT_INTERFACE_OP_STR_EQ,
      .text = "canonical-restart" },
    { .key = "allowed", .op = AGENT_INTERFACE_OP_BOOL, .flag = false },
};

static const struct agent_interface_expect
k_agent_interface_dev_clean_rows[] = {
    { .obj = AI_GUARD_ROOT, .key = "action",
      .op = AGENT_INTERFACE_OP_STR_EQ, .text = "deploy-dev" },
    { .obj = AI_GUARD_ROOT, .key = "allowed",
      .op = AGENT_INTERFACE_OP_BOOL, .flag = true },
    { .obj = AI_GUARD_ROOT, .key = "decision",
      .op = AGENT_INTERFACE_OP_STR_EQ, .text = "allow" },
    { .obj = AI_GUARD_ROOT, .key = "reason",
      .op = AGENT_INTERFACE_OP_STR_EQ,
      .text = "deployment_safety_allows_action" },
    { .obj = AI_GUARD_ROOT, .key = "action_scope",
      .op = AGENT_INTERFACE_OP_STR_EQ,
      .text = "explicit_target_lane" },
    { .obj = AI_GUARD_ROOT, .key = "current_lane_name",
      .op = AGENT_INTERFACE_OP_STR_EQ, .text = "canonical" },
    { .obj = AI_GUARD_ROOT, .key = "operator_lane_name",
      .op = AGENT_INTERFACE_OP_STR_EQ, .text = "dev" },
    { .obj = AI_GUARD_ROOT, .key = "lane",
      .op = AGENT_INTERFACE_OP_STR_EQ, .text = "dev" },
    { .obj = AI_GUARD_ROOT, .key = "target_lane_name",
      .op = AGENT_INTERFACE_OP_STR_EQ, .text = "dev" },
    { .obj = AI_GUARD_TARGET, .op = AGENT_INTERFACE_OP_TYPE_OBJ },
    { .obj = AI_GUARD_TARGET, .key = "development",
      .op = AGENT_INTERFACE_OP_BOOL, .flag = true },
    { .obj = AI_GUARD_TARGET, .key = "automation_deploy_ok",
      .op = AGENT_INTERFACE_OP_BOOL, .flag = true },
    { .obj = AI_GUARD_TARGET, .key = "requires_operator_confirmation",
      .op = AGENT_INTERFACE_OP_BOOL, .flag = false, .guard = true },
    { .obj = AI_GUARD_ROOT, .key = "recovery_deploy_blocker",
      .op = AGENT_INTERFACE_OP_BOOL, .flag = false },
    { .obj = AI_GUARD_ROOT, .key = "recovery_status",
      .op = AGENT_INTERFACE_OP_STR_EQ, .text = "clean" },
    { .obj = AI_GUARD_ROOT, .key = "explicit_recovery_env",
      .op = AGENT_INTERFACE_OP_STR_EQ,
      .text = "ZCL_DEV_ALLOW_AUTO_REINDEX_DEPLOY" },
    { .obj = AI_GUARD_RECOVERY, .op = AGENT_INTERFACE_OP_TYPE_OBJ },
    { .obj = AI_GUARD_RECOVERY, .key = "schema",
      .op = AGENT_INTERFACE_OP_STR_EQ,
      .text = "zcl.operator_lane_recovery.v1" },
    { .obj = AI_GUARD_RECOVERY, .key = "status",
      .op = AGENT_INTERFACE_OP_STR_EQ, .text = "clean" },
    { .obj = AI_GUARD_RECOVERY, .key = "deploy_blocker",
      .op = AGENT_INTERFACE_OP_BOOL, .flag = false, .guard = true },
    { .obj = AI_GUARD_RECOVERY, .key = "explicit_recovery_env",
      .op = AGENT_INTERFACE_OP_STR_EQ,
      .text = "ZCL_DEV_ALLOW_AUTO_REINDEX_DEPLOY" },
    { .obj = AI_GUARD_ROOT, .key = "safe_default_action",
      .op = AGENT_INTERFACE_OP_STR_EQ, .text = "deploy_dev_lane" },
};

static bool agent_interface_dev_clean_guard_matches(
    bool ok,
    struct rpc_table *tbl,
    char *guard_home,
    size_t guard_home_cap,
    char *guard_devdir,
    size_t guard_devdir_cap,
    struct json_value *dev_guard_params,
    struct json_value *dev_guard)
{
    test_make_tmpdir(guard_home, guard_home_cap, "syncdiag",
                     "deploy_guard_home");
    int guard_devdir_len = snprintf(guard_devdir, guard_devdir_cap,
                                    "%s/.zclassic-c23-dev",
                                    guard_home);
    ok = ok && guard_devdir_len > 0 &&
        (size_t)guard_devdir_len < guard_devdir_cap;
    ok = ok && mkdir(guard_devdir, 0755) == 0;
    ok = ok && setenv("HOME", guard_home, 1) == 0;

    json_init(dev_guard_params);
    json_set_array(dev_guard_params);
    struct json_value action;
    json_init(&action);
    json_set_str(&action, "deploy-dev");
    json_push_back(dev_guard_params, &action);
    json_free(&action);
    json_init(dev_guard);
    ok = ok && rpc_table_execute(tbl, "agentdeployguard",
                                 dev_guard_params, dev_guard);
    const struct json_value *dev_target =
        json_get(dev_guard, "target_lane");
    const struct json_value *dev_recovery =
        json_get(dev_target, "recovery_state");
    const struct json_value *objs[] = {
        dev_guard, dev_target, dev_recovery
    };
    return agent_interface_expect_rows(
        ok, objs, k_agent_interface_dev_clean_rows,
        sizeof k_agent_interface_dev_clean_rows /
            sizeof k_agent_interface_dev_clean_rows[0]);
}

static const struct agent_interface_expect
k_agent_interface_dev_pending_rows[] = {
    { .obj = AI_GUARD_ROOT, .key = "action",
      .op = AGENT_INTERFACE_OP_STR_EQ, .text = "deploy-dev" },
    { .obj = AI_GUARD_ROOT, .key = "allowed",
      .op = AGENT_INTERFACE_OP_BOOL, .flag = false },
    { .obj = AI_GUARD_ROOT, .key = "decision",
      .op = AGENT_INTERFACE_OP_STR_EQ, .text = "refuse" },
    { .obj = AI_GUARD_ROOT, .key = "reason",
      .op = AGENT_INTERFACE_OP_STR_EQ,
      .text = "pending_auto_reindex_requires_explicit_recovery_boot" },
    { .obj = AI_GUARD_ROOT, .key = "recovery_deploy_blocker",
      .op = AGENT_INTERFACE_OP_BOOL, .flag = true },
    { .obj = AI_GUARD_ROOT, .key = "recovery_status",
      .op = AGENT_INTERFACE_OP_STR_EQ,
      .text = "pending_auto_reindex" },
    { .obj = AI_GUARD_ROOT, .key = "explicit_recovery_env",
      .op = AGENT_INTERFACE_OP_STR_EQ,
      .text = "ZCL_DEV_ALLOW_AUTO_REINDEX_DEPLOY" },
    { .obj = AI_GUARD_ROOT, .key = "exit_code",
      .op = AGENT_INTERFACE_OP_INT_EQ, .num = 1 },
    { .obj = AI_GUARD_TARGET, .op = AGENT_INTERFACE_OP_TYPE_OBJ },
    { .obj = AI_GUARD_TARGET, .key = "status",
      .op = AGENT_INTERFACE_OP_STR_EQ,
      .text = "pending_auto_reindex" },
    { .obj = AI_GUARD_TARGET, .key = "auto_reindex_marker_present",
      .op = AGENT_INTERFACE_OP_BOOL, .flag = true },
    { .obj = AI_GUARD_TARGET, .key = "auto_reindex_status_well_formed",
      .op = AGENT_INTERFACE_OP_BOOL, .flag = true },
    { .obj = AI_GUARD_TARGET, .key = "auto_reindex_pending",
      .op = AGENT_INTERFACE_OP_BOOL, .flag = true },
    { .obj = AI_GUARD_TARGET, .key = "auto_reindex_terminal",
      .op = AGENT_INTERFACE_OP_BOOL, .flag = false, .guard = true },
    { .obj = AI_GUARD_TARGET, .key = "deploy_blocker",
      .op = AGENT_INTERFACE_OP_BOOL, .flag = true, .guard = true },
    { .obj = AI_GUARD_TARGET, .key = "auto_reindex_anchor",
      .op = AGENT_INTERFACE_OP_INT_EQ, .num = 3172354 },
    { .obj = AI_GUARD_TARGET, .key = "auto_reindex_count",
      .op = AGENT_INTERFACE_OP_INT_EQ, .num = 1 },
    { .obj = AI_GUARD_TARGET, .key = "deploy_blocker_reason",
      .op = AGENT_INTERFACE_OP_STR_EQ,
      .text = "pending_auto_reindex_requires_explicit_recovery_boot" },
};

static const struct agent_interface_expect
k_agent_interface_dev_terminal_rows[] = {
    { .obj = AI_GUARD_ROOT, .key = "allowed",
      .op = AGENT_INTERFACE_OP_BOOL, .flag = true },
    { .obj = AI_GUARD_ROOT, .key = "decision",
      .op = AGENT_INTERFACE_OP_STR_EQ, .text = "allow" },
    { .obj = AI_GUARD_ROOT, .key = "recovery_deploy_blocker",
      .op = AGENT_INTERFACE_OP_BOOL, .flag = false },
    { .obj = AI_GUARD_ROOT, .key = "recovery_status",
      .op = AGENT_INTERFACE_OP_STR_EQ,
      .text = "terminal_auto_reindex" },
    { .obj = AI_GUARD_TARGET, .op = AGENT_INTERFACE_OP_TYPE_OBJ },
    { .obj = AI_GUARD_TARGET, .key = "status",
      .op = AGENT_INTERFACE_OP_STR_EQ,
      .text = "terminal_auto_reindex" },
    { .obj = AI_GUARD_TARGET, .key = "auto_reindex_pending",
      .op = AGENT_INTERFACE_OP_BOOL, .flag = false, .guard = true },
    { .obj = AI_GUARD_TARGET, .key = "auto_reindex_terminal",
      .op = AGENT_INTERFACE_OP_BOOL, .flag = true, .guard = true },
    { .obj = AI_GUARD_TARGET, .key = "deploy_blocker",
      .op = AGENT_INTERFACE_OP_BOOL, .flag = false, .guard = true },
    { .obj = AI_GUARD_TARGET, .key = "auto_reindex_count",
      .op = AGENT_INTERFACE_OP_INT_EQ,
      .num = BOOT_AUTO_REINDEX_TERMINAL },
};

static bool agent_interface_dev_reindex_guard_matches(
    bool ok,
    struct rpc_table *tbl,
    const char *guard_devdir,
    struct json_value *dev_guard_params,
    struct json_value *pending_guard,
    struct json_value *terminal_guard)
{
    ok = ok && boot_auto_reindex_request(
                  guard_devdir, 3172354,
                  BOOT_AUTO_REINDEX_REASON_UNSPECIFIED) == 1;
    json_init(pending_guard);
    ok = ok && rpc_table_execute(tbl, "agentdeployguard",
                                 dev_guard_params, pending_guard);
    const struct json_value *pending_target =
        json_get(pending_guard, "target_lane");
    const struct json_value *pending_recovery =
        pending_target ? json_get(pending_target, "recovery_state") : NULL;
    const struct json_value *pending_objs[] = {
        pending_guard, pending_recovery
    };
    ok = agent_interface_expect_rows(
        ok, pending_objs, k_agent_interface_dev_pending_rows,
        sizeof k_agent_interface_dev_pending_rows /
            sizeof k_agent_interface_dev_pending_rows[0]);

    ok = ok && boot_auto_reindex_mark_terminal(guard_devdir, 3172354);
    json_init(terminal_guard);
    ok = ok && rpc_table_execute(tbl, "agentdeployguard",
                                 dev_guard_params, terminal_guard);
    const struct json_value *terminal_target =
        json_get(terminal_guard, "target_lane");
    const struct json_value *terminal_recovery =
        terminal_target ? json_get(terminal_target,
                                   "recovery_state") : NULL;
    const struct json_value *terminal_objs[] = {
        terminal_guard, terminal_recovery
    };
    return agent_interface_expect_rows(
        ok, terminal_objs, k_agent_interface_dev_terminal_rows,
        sizeof k_agent_interface_dev_terminal_rows /
            sizeof k_agent_interface_dev_terminal_rows[0]);
}

static const struct agent_interface_expect
k_agent_interface_canonical_from_dev_rows[] = {
    { .key = "action", .op = AGENT_INTERFACE_OP_STR_EQ,
      .text = "canonical-deploy" },
    { .key = "allowed", .op = AGENT_INTERFACE_OP_BOOL, .flag = false },
    { .key = "decision", .op = AGENT_INTERFACE_OP_STR_EQ,
      .text = "refuse" },
    { .key = "reason", .op = AGENT_INTERFACE_OP_STR_EQ,
      .text = "operator_confirmation_required" },
    { .key = "action_scope", .op = AGENT_INTERFACE_OP_STR_EQ,
      .text = "explicit_target_lane" },
    { .key = "current_lane_name", .op = AGENT_INTERFACE_OP_STR_EQ,
      .text = "dev" },
    { .key = "target_lane_name", .op = AGENT_INTERFACE_OP_STR_EQ,
      .text = "canonical" },
    { .key = "operator_lane_name", .op = AGENT_INTERFACE_OP_STR_EQ,
      .text = "canonical" },
    { .key = "automation_deploy_ok",
      .op = AGENT_INTERFACE_OP_BOOL, .flag = false },
    { .key = "requires_operator_confirmation",
      .op = AGENT_INTERFACE_OP_BOOL, .flag = true },
};

int syncdiag_cases_agent_interface(void)
{
    int failures = 0;

    printf("api: native RPC returns agent interface and deploy guard... ");
    {
        struct rpc_table tbl;
        rpc_table_init(&tbl);
        register_event_rpc_commands(&tbl);
        register_diagnostics_rpc_commands(&tbl);
        if (rpc_is_in_warmup(NULL, 0))
            set_rpc_warmup_finished();

        struct json_value params;
        json_init(&params);
        json_set_array(&params);

        bool ok = true;

        struct json_value interface;
        json_init(&interface);
        agent_runtime_availability_begin_probe("test_target_rpc",
                                               "/tmp/zcl-canonical",
                                               18232, "ok");
        agent_runtime_availability_set_target_source_id_sha256(
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        agent_runtime_availability_set_target_build_commit("oldbuild");
        agent_runtime_availability_record_method("agent", "supported", 0, "");
        agent_runtime_availability_record_method(
            "agentops", "unsupported_method_not_found",
            RPC_METHOD_NOT_FOUND, "Method not found");
        ok = ok && rpc_table_execute(&tbl, "agentinterface",
                                     &params, &interface);
        ok = agent_interface_document_matches(ok, &interface);

        ok = agent_interface_probed_ops_matches(ok, &tbl, &params);

        ok = agent_interface_resource_snapshots_match(ok);

        ok = agent_interface_watchdog_snapshots_match(ok);

        rpc_agent_set_boot_context("canonical", "full",
                                   "/tmp/zcl-agent-canonical",
                                   18232, 8033, 8443, 18033);
        struct json_value guard;
        json_init(&guard);
        struct json_value guard_params;
        json_init(&guard_params);
        json_set_array(&guard_params);
        struct json_value action;
        json_init(&action);
        json_set_str(&action, "canonical-deploy");
        json_push_back(&guard_params, &action);
        json_free(&action);
        ok = ok && rpc_table_execute(&tbl, "agentdeployguard",
                                     &guard_params, &guard);
        const struct json_value *canonical_target =
            json_get(&guard, "target_lane");
        const struct json_value *canonical_objs[] = {
            &guard, canonical_target
        };
        ok = agent_interface_expect_rows(
            ok, canonical_objs, k_agent_interface_canonical_rows,
            sizeof k_agent_interface_canonical_rows /
                sizeof k_agent_interface_canonical_rows[0]);

        const char *old_home_env = getenv("HOME");
        char old_home_buf[4096];
        bool old_home_set = old_home_env != NULL;
        if (old_home_set)
            snprintf(old_home_buf, sizeof(old_home_buf), "%s",
                     old_home_env);
        ok = agent_interface_inferred_home_guard_matches(ok, &tbl);
        if (old_home_set)
            setenv("HOME", old_home_buf, 1);
        else
            unsetenv("HOME");

        struct json_value guard_object_params;
        json_init(&guard_object_params);
        json_set_object(&guard_object_params);
        json_push_kv_str(&guard_object_params, "action",
                         "canonical-restart");
        struct json_value guard_object;
        json_init(&guard_object);
        ok = ok && rpc_table_execute(&tbl, "agentdeployguard",
                                     &guard_object_params, &guard_object);
        const struct json_value *restart_objs[] = { &guard_object };
        ok = agent_interface_expect_rows(
            ok, restart_objs, k_agent_interface_restart_object_rows,
            sizeof k_agent_interface_restart_object_rows /
                sizeof k_agent_interface_restart_object_rows[0]);

        const char *guard_old_home_env = getenv("HOME");
        char guard_old_home_buf[4096];
        bool guard_old_home_set = guard_old_home_env != NULL;
        if (guard_old_home_set)
            snprintf(guard_old_home_buf, sizeof(guard_old_home_buf), "%s",
                     guard_old_home_env);
        char guard_home[512];
        char guard_devdir[768];
        struct json_value dev_guard_params;
        struct json_value dev_guard;
        ok = agent_interface_dev_clean_guard_matches(
            ok, &tbl, guard_home, sizeof(guard_home),
            guard_devdir, sizeof(guard_devdir),
            &dev_guard_params, &dev_guard);
        struct json_value pending_guard;
        struct json_value terminal_guard;
        ok = agent_interface_dev_reindex_guard_matches(
            ok, &tbl, guard_devdir, &dev_guard_params,
            &pending_guard, &terminal_guard);

        if (guard_old_home_set)
            setenv("HOME", guard_old_home_buf, 1);
        else
            unsetenv("HOME");
        test_cleanup_tmpdir(guard_home);

        rpc_agent_set_boot_context("dev", "full",
                                   "/tmp/zcl-agent-dev",
                                   18252, 8053, 0, 18034);
        struct json_value canonical_from_dev_params;
        json_init(&canonical_from_dev_params);
        json_set_array(&canonical_from_dev_params);
        json_init(&action);
        json_set_str(&action, "canonical-deploy");
        json_push_back(&canonical_from_dev_params, &action);
        json_free(&action);
        struct json_value canonical_from_dev;
        json_init(&canonical_from_dev);
        ok = ok && rpc_table_execute(&tbl, "agentdeployguard",
                                     &canonical_from_dev_params,
                                     &canonical_from_dev);
        const struct json_value *from_dev_objs[] = { &canonical_from_dev };
        ok = agent_interface_expect_rows(
            ok, from_dev_objs, k_agent_interface_canonical_from_dev_rows,
            sizeof k_agent_interface_canonical_from_dev_rows /
                sizeof k_agent_interface_canonical_from_dev_rows[0]);


        json_free(&params);
        json_free(&interface);
        json_free(&guard_params);
        json_free(&guard);
        json_free(&guard_object_params);
        json_free(&guard_object);
        json_free(&dev_guard_params);
        json_free(&dev_guard);
        json_free(&pending_guard);
        json_free(&terminal_guard);
        json_free(&canonical_from_dev_params);
        json_free(&canonical_from_dev);
        rpc_agent_set_boot_context(NULL, NULL, NULL, 0, 0, 0, 0);

        if (ok) printf("OK\n");
        else    { printf("FAIL\n"); failures++; }
    }

    return failures;
}
