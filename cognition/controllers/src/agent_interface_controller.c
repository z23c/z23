/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Versioned AI/operator interface contracts. These are pure JSON discovery and
 * safety-decision helpers; they do not mutate node, wallet, chain, or
 * consensus state. */

#include "controllers/agent_controller.h"
#include "controllers/strong_params.h"

#include "json/json.h"
#include "util/clientversion.h"

#include <stdint.h>
#include <string.h>

static void agent_interface_push_str(struct json_value *arr, const char *s)
{
    struct json_value v;
    json_init(&v);
    json_set_str(&v, s ? s : "");
    json_push_back(arr, &v);
    json_free(&v);
}

static void agent_interface_push_transport(struct json_value *arr,
                                           int64_t rank,
                                           const char *name,
                                           const char *interface,
                                           const char *first_call,
                                           const char *format,
                                           const char *use_for)
{
    struct json_value obj;
    json_init(&obj);
    json_set_object(&obj);
    json_push_kv_int(&obj, "rank", rank);
    json_push_kv_str(&obj, "name", name);
    json_push_kv_str(&obj, "interface", interface);
    json_push_kv_str(&obj, "first_call", first_call);
    json_push_kv_str(&obj, "format", format);
    json_push_kv_str(&obj, "use_for", use_for);
    json_push_back(arr, &obj);
    json_free(&obj);
}

static const char *agent_interface_param0_str(const struct json_value *params,
                                              const char *fallback)
{
    if (!params)
        return fallback;

    const struct json_value *v = NULL;
    if (params->type == JSON_OBJ) {
        v = json_get(params, "action");
    } else if (params->type == JSON_ARR && json_size(params) > 0) {
        v = json_at(params, 0);
    }
    if (!v || v->type != JSON_STR)
        return fallback;
    const char *s = json_get_str(v);
    return (s && s[0]) ? s : fallback;
}

static bool agent_deploy_action_known(const char *action)
{
    return action &&
           (strcmp(action, "canonical-deploy") == 0 ||
            strcmp(action, "canonical-restart") == 0 ||
            strcmp(action, "deploy-dev") == 0 ||
            strcmp(action, "dev-deploy") == 0 ||
            strcmp(action, "restart-dev") == 0 ||
            strcmp(action, "dev-restart") == 0 ||
            strcmp(action, "deploy") == 0 ||
            strcmp(action, "restart") == 0);
}

static bool agent_deploy_action_is_restart(const char *action)
{
    return action &&
           (strcmp(action, "canonical-restart") == 0 ||
            strcmp(action, "restart-dev") == 0 ||
            strcmp(action, "dev-restart") == 0 ||
            strcmp(action, "restart") == 0);
}

static const char *agent_deploy_action_target_lane(const char *action)
{
    if (!action)
        return "";
    if (strcmp(action, "canonical-deploy") == 0 ||
        strcmp(action, "canonical-restart") == 0)
        return "canonical";
    if (strcmp(action, "deploy-dev") == 0 ||
        strcmp(action, "dev-deploy") == 0 ||
        strcmp(action, "restart-dev") == 0 ||
        strcmp(action, "dev-restart") == 0)
        return "dev";
    return "";
}

static void agent_deploy_push_target_lane(struct json_value *out,
                                          const char *action,
                                          const char *current_lane)
{
    const char *target = agent_deploy_action_target_lane(action);
    struct json_value lane;
    json_init(&lane);

    if (target[0]) {
        if (!agent_fill_known_operator_lane_contract_json(&lane, target)) {
            agent_fill_operator_lane_contract_json(
                &lane, target, "unknown", "", 0, 0, 0, 0);
        }
    } else {
        const struct json_value *current = json_get(out, "operator_lane");
        if (current && current->type == JSON_OBJ) {
            json_copy(&lane, current);
        } else {
            agent_fill_operator_lane_contract_json(
                &lane, current_lane ? current_lane : "unknown",
                "unknown", "", 0, 0, 0, 0);
        }
    }

    json_push_kv(out, "target_lane", &lane);
    json_free(&lane);
}

bool rpc_agent_interface(const struct json_value *params, bool help,
                         struct json_value *result)
{
    (void)params;
    RPC_HELP(help, result,
        "agentinterface\n"
        "\nReturn the preferred AI development interface: ranked transports,\n"
        "JSON rules, native C ownership, and shell/Python anti-patterns.\n"
        "\nResult:\n"
        "  { \"schema\":\"zcl.agent_interface.v2\", "
        "\"preferred_transport\":\"native_cli\", ... }\n");

    struct json_value transports, capabilities, machine, runtime, loop,
                      visual_instruments, visual_loop, native_owned, avoid,
                      versioning;
    json_set_object(result);
    json_push_kv_str(result, "schema", "zcl.agent_interface.v2");
    json_push_kv_str(result, "api_version", "v1");
    json_push_kv_str(result, "status", "ok");
    json_push_kv_str(result, "source_id_sha256",
                     zcl_build_source_id_sha256());
    json_push_kv_str(result, "build_commit", zcl_build_commit());
    json_push_kv_str(result, "preferred_transport", "native_cli");
    json_push_kv_str(result, "preferred_payload", "json");
    json_push_kv_str(result, "canonical_implementation",
                     "cognition/controllers/src/agent_interface_controller.c");
    json_push_kv_str(result, "capabilities_schema",
                     "zcl.agent_capability.v2");
    json_push_kv_str(result, "summary",
                     "Use typed native zclassic23 commands for AI, scripts, and humans; REST is public read-only.");

    json_init(&transports);
    json_set_array(&transports);
    agent_interface_push_transport(&transports, 1, "native_cli",
        "z23 agent*", "z23 agentinterface", "stdout JSON",
        "primary typed AI/operator commands, scripts, and zero-wrapper diagnostics");
    agent_interface_push_transport(&transports, 2, "rest",
        "GET /api/v1/agent", "GET /api/v1/agent", "HTTP JSON",
        "public read-only status and explorer-facing discovery");
    json_push_kv(result, "transports", &transports);
    json_free(&transports);

    json_init(&capabilities);
    json_set_array(&capabilities);
    agent_push_contract_capabilities_json(&capabilities);
    agent_push_contract_capability_json(
        &capabilities, "dumpstate", "semantic_state",
        "generic subsystem state without adding bespoke tools");
    agent_push_contract_capability_json(
        &capabilities, "getnodelog", "bounded_logs",
        "server-side log search without shipping full node.log history");
    agent_push_contract_capability_json(
        &capabilities, "dbquery", "select_sql",
        "bounded SELECT-only node.db inspection");
    json_push_kv(result, "capabilities", &capabilities);
    json_free(&capabilities);

    json_init(&machine);
    json_set_object(&machine);
    json_push_kv_str(&machine, "schema", "zcl.agent_machine_contract.v2");
    json_push_kv_str(&machine, "payload", "json_object");
    json_push_kv_bool(&machine, "schema_required", true);
    json_push_kv_bool(&machine, "api_version_required", true);
    json_push_kv_bool(&machine, "status_required", true);
    json_push_kv_bool(&machine, "append_only_v2", true);
    json_push_kv_bool(&machine, "transport_equivalent_payloads", true);
    json_push_kv_bool(&machine, "no_python_required", true);
    json_push_kv_bool(&machine, "typed_native_commands_required", true);
    json_push_kv_str(&machine, "preferred_error_style",
                     "zcl.result.v1 or another typed native JSON object");
    json_push_kv_str(&machine, "compatibility_rule",
                     "Agents may rely on existing field meanings; new optional fields are additive until v3.");
    json_push_kv(result, "machine_contract", &machine);
    json_free(&machine);

    json_init(&runtime);
    json_set_object(&runtime);
    json_push_kv_str(&runtime, "schema", "zcl.agent_runtime_identity.v1");
    json_push_kv_str(&runtime, "source_id_sha256",
                     zcl_build_source_id_sha256());
    json_push_kv_str(&runtime, "build_commit", zcl_build_commit());
    json_push_kv_str(&runtime, "binary", "zclassic23");
    json_push_kv_str(&runtime, "generated_by",
                     "cognition/controllers/src/agent_interface_controller.c");
    json_push_kv_str(&runtime, "identity_rule",
                     "source_id_sha256 identifies the runtime source tree; build_commit is display-only GitHub trace metadata.");
    json_push_kv(result, "runtime_identity", &runtime);
    json_free(&runtime);
    agent_push_runtime_availability_json(result, "runtime_availability");

    json_init(&loop);
    json_set_object(&loop);
    json_push_kv_str(&loop, "status", "z23 status");
    agent_push_contract_native_field_json(&loop, "full_compatibility_status",
                                          "agent");
    agent_push_contract_native_field_json(&loop, "discover",
                                          "agentinterface");
    agent_push_contract_native_field_json(&loop, "mirror_status",
                                          "getmirrorstatus");
    agent_push_contract_native_field_json(&loop, "lane_topology",
                                          "agentlanes");
    agent_push_contract_native_field_json(&loop, "liveness",
                                          "agentliveness");
    agent_push_contract_native_field_json(&loop, "code_map", "agentmap");
    agent_push_contract_native_field_json(&loop, "changed_files_to_tests",
                                          "agentimpact");
    agent_push_contract_native_field_json(&loop, "build_contract",
                                          "agentbuild");
    agent_push_contract_native_field_json(&loop, "ops_command_center",
                                          "agentops");
    agent_push_contract_native_field_json(&loop, "contract_registry",
                                          "agentcontracts");
    agent_push_contract_native_field_json(&loop, "deploy_guard",
                                          "agentdeployguard");
    agent_push_contract_native_field_json(&loop, "subsystem_state",
                                          "dumpstate");
    agent_push_contract_native_field_json(&loop, "logs", "getnodelog");
    agent_push_contract_native_field_json(&loop, "database", "dbquery");
    json_push_kv_str(&loop, "quality_lanes", "make quality-linger-status");
    json_push_kv(result, "development_loop", &loop);
    json_free(&loop);

    json_init(&visual_instruments);
    json_set_array(&visual_instruments);
    agent_push_contract_command_surface_json(
        &visual_instruments, "agentinterface.visual_instruments");
    json_push_kv(result, "native_visual_instruments", &visual_instruments);
    json_free(&visual_instruments);

    json_init(&visual_loop);
    json_set_object(&visual_loop);
    json_push_kv_str(&visual_loop, "schema", "zcl.agent_visual_loop.v1");
    json_push_kv_str(&visual_loop, "default_channel", "ai_conversation");
    json_push_kv_bool(&visual_loop, "unsolicited_windows", false);
    json_push_kv_str(&visual_loop, "query_rule",
                     "answer ordinary questions directly in the AI conversation from typed node facts; do not open a native window");
    json_push_kv_str(&visual_loop, "visual_trigger",
                     "open a native instrument only when the user explicitly asks to see, scan, manipulate, compare, select, or confirm something");
    json_push_kv_str(&visual_loop, "media_rule",
                     "QR, image, movie, and NFT media are valid explicit visual requests; use only an admitted display-only native instrument and never improvise a browser or software authority");
    json_push_kv_str(&visual_loop, "request",
                     "user intent plus the smallest exact subject identity");
    json_push_kv_str(&visual_loop, "agent_action",
                     "invoke one native_visual_instruments command");
    json_push_kv_str(&visual_loop, "display",
                     "warm same-binary C23 presentation host");
    json_push_kv_str(&visual_loop, "result",
                     "bounded display result or exact human decision");
    json_push_kv_str(&visual_loop, "input_discovery",
                     "z23 discover schema <leaf>");
    json_push_kv_str(&visual_loop, "text_companion",
                     "set output=text for the deterministic companion from the same bounded model; no native window opens");
    json_push_kv_str(&visual_loop, "selection_rule",
                     "use a typed instrument for node-owned facts or human decisions; use bounded_display only for inert agent-owned facts");
    json_push_kv_str(&visual_loop, "authority_rule",
                     "the full node owns facts and independently rechecks every effect; the visual host owns none");
    json_push_kv_str(&visual_loop, "generic_model_policy",
                     "app presentation show is only for inert agent-supplied visuals; node-owned facts and confirmations use their typed instruments");
    json_push_kv_bool(&visual_loop, "browser_required", false);
    json_push_kv_bool(&visual_loop, "python_required", false);
    json_push_kv(result, "native_visual_loop", &visual_loop);
    json_free(&visual_loop);

    json_init(&native_owned);
    json_set_array(&native_owned);
    agent_interface_push_str(&native_owned, "schema/version emission");
    agent_interface_push_str(&native_owned, "status and blocker interpretation");
    agent_interface_push_str(&native_owned, "changed-file impact mapping");
    agent_interface_push_str(&native_owned, "deploy/restart safety decisions");
    agent_interface_push_str(&native_owned, "diagnostic drill-down routing");
    agent_interface_push_str(&native_owned,
                             "background quality lane contracts");
    agent_interface_push_str(&native_owned,
                             "canonical visual fact projection and confirmation chrome");
    json_push_kv(result, "must_live_in_c", &native_owned);
    json_free(&native_owned);

    json_init(&avoid);
    json_set_array(&avoid);
    agent_interface_push_str(
        &avoid,
        "do not add external operator wrappers; use typed native "
        "zclassic23 commands");
    agent_interface_push_str(&avoid,
                             "do not require Python to parse agent API JSON");
    agent_interface_push_str(&avoid,
                             "do not scrape logs when z23 getnodelog can answer");
    agent_interface_push_str(&avoid,
                             "do not scrape node.db when z23 dbquery or a typed command exists");
    agent_interface_push_str(&avoid,
                             "do not infer deploy safety from comments or unit names");
    agent_interface_push_str(
        &avoid,
        "do not fabricate privileged visual facts or confirmation text; invoke the semantic native visual command");
    json_push_kv(result, "avoid", &avoid);
    json_free(&avoid);

    json_init(&versioning);
    json_set_object(&versioning);
    json_push_kv_bool(&versioning, "schema_required", true);
    json_push_kv_bool(&versioning, "api_version_required", true);
    json_push_kv_str(&versioning, "compatibility_rule",
                     "Add fields without changing meaning; use v2 for breaking shape changes.");
    json_push_kv_str(&versioning, "test_floor",
                     "syncdiag_rpc, command_registry_catalog, api, make_lint_gates");
    json_push_kv(result, "versioning", &versioning);
    json_free(&versioning);
    return true;
}

bool rpc_agent_deploy_guard(const struct json_value *params, bool help,
                            struct json_value *result)
{
    RPC_HELP(help, result,
        "agentdeployguard ( action )\n"
        "\nReturn a C-native allow/refuse decision for deploy/restart\n"
        "automation based on zcl.operator_deployment_safety.v1.\n"
        "\nActions: canonical-deploy, canonical-restart, deploy, restart,\n"
        "         deploy-dev, restart-dev.\n"
        "\nResult:\n"
        "  { \"schema\":\"zcl.agent_deploy_guard.v1\", "
        "\"allowed\":false, \"exit_code\":1, ... }\n");

    const char *action = agent_interface_param0_str(params,
                                                    "canonical-deploy");
    json_set_object(result);
    json_push_kv_str(result, "schema", "zcl.agent_deploy_guard.v1");
    json_push_kv_str(result, "api_version", "v1");
    json_push_kv_str(result, "status", "ok");
    json_push_kv_str(result, "action", action);
    agent_push_operator_lane_json(result, "operator_lane");

    const struct json_value *lane = json_get(result, "operator_lane");
    agent_deploy_push_target_lane(result, action,
                                  lane && json_get(lane, "lane")
                                      ? json_get_str(json_get(lane, "lane"))
                                      : "unknown");
    const struct json_value *target_lane = json_get(result, "target_lane");
    const struct json_value *safety =
        target_lane ? json_get(target_lane, "deployment_safety") : NULL;
    const bool deploy_ok = safety &&
        json_get_bool(json_get(safety, "automation_deploy_ok"));
    const bool restart_ok = safety &&
        json_get_bool(json_get(safety, "automation_restart_ok"));
    const bool requires = safety &&
        json_get_bool(json_get(safety, "requires_operator_confirmation"));
    const struct json_value *recovery =
        target_lane ? json_get(target_lane, "recovery_state") : NULL;
    const bool recovery_deploy_blocker = recovery &&
        json_get_bool(json_get(recovery, "deploy_blocker"));
    const char *recovery_status = recovery &&
        json_get(recovery, "status")
            ? json_get_str(json_get(recovery, "status")) : "";
    const char *lane_name = lane && json_get(lane, "lane")
        ? json_get_str(json_get(lane, "lane")) : "unknown";
    const char *target_lane_name = target_lane && json_get(target_lane, "lane")
        ? json_get_str(json_get(target_lane, "lane")) : lane_name;
    const bool known = agent_deploy_action_known(action);
    const bool wants_restart = agent_deploy_action_is_restart(action);
    const bool allowed = known && !requires &&
        !recovery_deploy_blocker &&
        (wants_restart ? restart_ok : deploy_ok);

    json_push_kv_str(result, "current_lane_name", lane_name);
    json_push_kv_str(result, "operator_lane_name", target_lane_name);
    json_push_kv_bool(result, "automation_restart_ok", restart_ok);
    json_push_kv_bool(result, "automation_deploy_ok", deploy_ok);
    json_push_kv_bool(result, "requires_operator_confirmation", requires);
    json_push_kv_bool(result, "recovery_deploy_blocker",
                      recovery_deploy_blocker);
    json_push_kv_str(result, "recovery_status", recovery_status);
    json_push_kv_str(result, "recovery_safe_next_action",
                     recovery && json_get(recovery, "safe_next_action")
                         ? json_get_str(json_get(recovery,
                                                "safe_next_action")) : "");
    json_push_kv_str(result, "explicit_recovery_env",
                     recovery && json_get(recovery, "explicit_recovery_env")
                         ? json_get_str(json_get(recovery,
                                                "explicit_recovery_env")) : "");
    json_push_kv_str(result, "preferred_deploy_target",
                     safety && json_get(safety, "preferred_deploy_target")
                         ? json_get_str(json_get(safety,
                                                "preferred_deploy_target"))
                         : "");
    json_push_kv_str(result, "safe_default_action",
                     safety && json_get(safety, "safe_default_action")
                         ? json_get_str(json_get(safety,
                                                "safe_default_action")) : "");
    json_push_kv_bool(result, "allowed", allowed);
    json_push_kv_int(result, "exit_code", allowed ? 0 : 1);
    json_push_kv_str(result, "decision", allowed ? "allow" : "refuse");
    json_push_kv_str(result, "required_contract",
                     "zcl.operator_deployment_safety.v1");
    json_push_kv_str(result, "source", "native_c_agent_interface_controller");
    json_push_kv_str(result, "action_scope",
                     agent_deploy_action_target_lane(action)[0]
                         ? "explicit_target_lane"
                         : "current_runtime_lane");
    if (!known) {
        json_push_kv_str(result, "reason", "unknown_action");
    } else if (requires) {
        json_push_kv_str(result, "reason",
                         "operator_confirmation_required");
    } else if (recovery_deploy_blocker) {
        json_push_kv_str(result, "reason",
                         "pending_auto_reindex_requires_explicit_recovery_boot");
    } else if (wants_restart && !restart_ok) {
        json_push_kv_str(result, "reason", "automation_restart_not_allowed");
    } else if (!wants_restart && !deploy_ok) {
        json_push_kv_str(result, "reason", "automation_deploy_not_allowed");
    } else {
        json_push_kv_str(result, "reason", "deployment_safety_allows_action");
    }
    json_push_kv_str(result, "lane", target_lane_name);
    json_push_kv_str(result, "target_lane_name", target_lane_name);
    json_push_kv_str(result, "guard_env",
                     safety && json_get(safety, "guard_env")
                         ? json_get_str(json_get(safety, "guard_env")) : "");
    return true;
}
