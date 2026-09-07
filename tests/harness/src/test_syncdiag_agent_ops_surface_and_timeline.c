/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * agentops sibling: the operator work surface fields, agentdiagnose,
 * the runtime-lane inference, the event timeline (basic, filtered, and
 * CLI-style filters), the state catalog, and agentlanes. Each scenario
 * builds its params or event fixture off the shared
 * struct sd_agent_ops_ctx, calls the RPC through the shared table,
 * asserts on the result, and frees what it owns; the assertion helpers
 * above each scenario are private to that scenario and add no
 * file-scope mutable state of their own.
 */

#include "test/syncdiag_rpc_fixture.h"
#include "test/test_syncdiag_agent_ops_priv.h"

static bool sd_ops_fields_contract(const struct json_value *ops)
{
    bool ok = true;
    ok = ok && ops->type == JSON_OBJ;
    ok = ok && strcmp(json_get_str(json_get(ops, "schema")),
                      "zcl.agent_ops.v2") == 0;
    ok = ok && strcmp(json_get_str(json_get(ops, "method")),
                      "agentops") == 0;
    ok = ok && json_get_bool(json_get(ops, "no_jq_required"));
    ok = ok && strcmp(json_get_str(json_get(ops, "native_command")),
                      "z23 agentops") == 0;
    ok = ok && strcmp(json_get_str(json_get(ops, "contract_source")),
                      "agent_contracts.def") == 0;
    ok = ok && strcmp(json_get_str(json_get(ops, "api_style")),
                      "one compact first call, then registry-owned primitive drilldowns") == 0;
    ok = ok && strcmp(json_get_str(json_get(ops, "dry_source")),
                      "agent_contracts.def + agent_contract_registry.c") == 0;
    ok = ok && strcmp(json_get_str(json_get(ops,
                                            "diagnostics_catalog_command")),
                      "z23 statecatalog") == 0;
    ok = ok && strcmp(json_get_str(json_get(ops,
                                            "diagnose_command")),
                      "z23 agentdiagnose") == 0;
    ok = ok && strcmp(json_get_str(json_get(ops,
                                            "anchor_status_command")),
                      "z23 anchorstatus [-datadir=<anchor-datadir>]")
        == 0;
    ok = ok && strcmp(json_get_str(json_get(ops,
                                            "proof_bundle_command")),
                      "z23 proofbundle [anchor_datadir]") == 0;
    return ok;
}

static bool sd_ops_fields_direct_commands_core(const struct json_value *ops)
{
    bool ok = true;
    const struct json_value *ops_direct_commands =
        json_get(ops, "direct_commands");
    const struct json_value *ops_direct_agentops =
        find_object_with_str(ops_direct_commands, "method", "agentops");
    const struct json_value *ops_direct_diagnose =
        find_object_with_str(ops_direct_commands, "method",
                             "agentdiagnose");
    ok = ok && strcmp(json_get_str(json_get(ops,
                                            "peer_incidents_command")),
                      "z23 peerincidents") == 0;
    ok = ok && strcmp(json_get_str(json_get(ops,
                                            "service_catalog_command")),
                      "z23 servicecatalog") == 0;
    ok = ok && strcmp(json_get_str(json_get(ops,
                                            "service_operations_command")),
                      "z23 serviceoperations [operation_id|key=value...]") == 0;
    ok = ok && strcmp(json_get_str(json_get(ops,
                                            "dev_status_command")),
                      "z23 agentdevstatus") == 0;
    ok = ok && strcmp(json_get_str(json_get(ops,
                                            "deploy_guard_command")),
                      "z23 agentdeployguard [action]") == 0;
    ok = ok && ops_direct_agentops &&
        strcmp(json_get_str(json_get(ops_direct_agentops, "schema")),
               "zcl.agent_ops.v2") == 0;
    ok = ok && ops_direct_agentops &&
        strcmp(json_get_str(json_get(ops_direct_agentops, "native")),
               "z23 agentops") == 0;
    ok = ok && ops_direct_diagnose &&
        strcmp(json_get_str(json_get(ops_direct_diagnose, "schema")),
               "zcl.agent_diagnose.v2") == 0;
    return ok;
}

static bool sd_ops_fields_direct_commands_native(const struct json_value *ops)
{
    bool ok = true;
    const struct json_value *ops_direct_commands =
        json_get(ops, "direct_commands");
    const struct json_value *ops_direct_app_protocols =
        find_object_with_str(ops_direct_commands, "method",
                             "appprotocols");
    const struct json_value *ops_direct_service_operations =
        find_object_with_str(ops_direct_commands, "method",
                             "serviceoperations");
    const struct json_value *ops_direct_dumpstate =
        find_object_with_str(ops_direct_commands, "method",
                             "dumpstate");
    const struct json_value *ops_direct_getnodelog =
        find_object_with_str(ops_direct_commands, "method",
                             "getnodelog");
    const struct json_value *ops_direct_peerincidents =
        find_object_with_str(ops_direct_commands, "method",
                             "peerincidents");
    const struct json_value *ops_direct_dev_status =
        find_object_with_str(ops_direct_commands, "method",
                             "agentdevstatus");
    ok = ok && ops_direct_app_protocols &&
        strcmp(json_get_str(json_get(ops_direct_app_protocols,
                                     "schema")),
               "zcl.application_protocols.index.v2") == 0;
    ok = ok && ops_direct_service_operations &&
        strcmp(json_get_str(json_get(ops_direct_service_operations,
                                     "schema")),
               "zcl.service_operations.index.v2") == 0;
    ok = ok && ops_direct_dumpstate &&
        strcmp(json_get_str(json_get(ops_direct_dumpstate, "native")),
               "z23 dumpstate <subsystem> [key]") == 0;
    ok = ok && ops_direct_getnodelog &&
        strcmp(json_get_str(json_get(ops_direct_getnodelog, "native")),
               "z23 getnodelog <pattern>") == 0;
    ok = ok && ops_direct_peerincidents &&
        strcmp(json_get_str(json_get(ops_direct_peerincidents, "native")),
               "z23 peerincidents") == 0;
    ok = ok && ops_direct_dev_status &&
        strcmp(json_get_str(json_get(ops_direct_dev_status, "schema")),
               "zcl.agent_dev_status.v2") == 0;
    return ok;
}

static bool sd_ops_fields_direct_commands_proof_bundle(const struct json_value *ops)
{
    bool ok = true;
    const struct json_value *ops_direct_commands =
        json_get(ops, "direct_commands");
    const struct json_value *ops_direct_dev_status =
        find_object_with_str(ops_direct_commands, "method",
                             "agentdevstatus");
    const struct json_value *ops_direct_proof_bundle =
        find_object_with_str(ops_direct_commands, "method",
                             "proofbundle");
    ok = ok && ops_direct_dev_status &&
        strcmp(json_get_str(json_get(ops_direct_dev_status, "native")),
               "z23 agentdevstatus") == 0;
    ok = ok && ops_direct_proof_bundle &&
        strcmp(json_get_str(json_get(ops_direct_proof_bundle, "schema")),
               "zcl.operator_proof_bundle.v2") == 0;
    ok = ok && ops_direct_proof_bundle &&
        strcmp(json_get_str(json_get(ops_direct_proof_bundle, "native")),
               "z23 proofbundle [anchor_datadir]") == 0;
    ok = ok && strstr(json_get_str(json_get(ops,
                                            "refold_plain_english")),
                      "borrowed snapshot seed") != NULL;
    ok = ok &&
        agent_contract_work_surface_count("agentops.api_gaps") == 3;
    ok = ok &&
        agent_contract_work_surface_count("agentops.workflow") == 5;
    ok = ok &&
        agent_contract_work_surface_count("agentops.top_next_work") == 5;
    ok = ok &&
        agent_contract_work_surface_count("missing.surface") == 0;
    ok = ok &&
        agent_contract_field_surface_count("agentops.first_call") == 14;
    return ok;
}

static bool sd_ops_fields_gaps_and_workflow(const struct json_value *ops)
{
    bool ok = true;
    const struct json_value *ops_gaps = json_get(ops, "api_gaps");
    const struct json_value *ops_workflow = json_get(ops, "workflow");
    ok = ok &&
        agent_contract_field_surface_count("missing.surface") == 0;
    ok = ok &&
        agent_contract_review_surface_count(
            "agentops.architecture_review") == 5;
    ok = ok &&
        agent_contract_review_surface_count("missing.surface") == 0;
    ok = ok && ops_gaps && json_size(ops_gaps) == 3;
    ok = ok && find_object_with_str(ops_gaps, "name",
                                    "runtime_identity_everywhere") != NULL;
    ok = ok && find_object_with_str(ops_gaps, "name",
                                    "timeline_query") != NULL;
    ok = ok && ops_workflow && json_size(ops_workflow) == 5;
    ok = ok && find_object_with_str(ops_workflow, "name",
                                    "first_call") != NULL;
    ok = ok && find_object_with_str(ops_workflow, "name",
                                    "change_with_impact") != NULL;
    ok = ok && find_object_with_str(ops_workflow, "name",
                                    "drill_down_only_when_needed") != NULL;
    return ok;
}

static bool sd_ops_fields_top_next_work(const struct json_value *ops)
{
    bool ok = true;
    const struct json_value *ops_work = json_get(ops, "top_next_work");
    const struct json_value *ops_api_ux = json_get(ops, "api_ux");
    ok = ok && strcmp(json_get_str(json_get(ops,
                                            "preferred_transport")),
                      "native_cli") == 0;
    ok = ok && ops_api_ux &&
        strstr(json_get_str(json_get(ops_api_ux, "preferred_drilldowns")),
               "z23 dumpstate") != NULL;
    ok = ok && ops_api_ux &&
        strstr(json_get_str(json_get(ops_api_ux, "start_here")),
               "z23 status") != NULL;
    ok = ok && ops_api_ux &&
        strstr(json_get_str(json_get(ops_api_ux, "add_new_api_rule")),
               "registry-owned primitives") != NULL;
    ok = ok && ops_work && json_size(ops_work) == 5;
    ok = ok && find_object_with_str(ops_work, "name",
                                    "finish_self_verified_utxo_anchor_rebuild")
        != NULL;
    ok = ok && find_object_with_str(ops_work, "name",
                                    "harden_peer_bootstrap_lifecycle")
        != NULL;
    ok = ok && find_object_with_str(ops_work, "name",
                                    "promote_mvp_operator_proofs") != NULL;
    return ok;
}

static bool sd_ops_fields_architecture_review(const struct json_value *ops)
{
    bool ok = true;
    const struct json_value *ops_work = json_get(ops, "top_next_work");
    const struct json_value *ops_availability =
        json_get(ops, "runtime_availability");
    const struct json_value *ops_availability_methods =
        ops_availability ? json_get(ops_availability, "methods") : NULL;
    const struct json_value *ops_method_agentops =
        find_object_with_str(ops_availability_methods, "method",
                             "agentops");
    const struct json_value *ops_review =
        json_get(ops, "architecture_review");
    ok = ok && find_object_with_str(ops_work, "name",
                                    "shrink_boot_refold_supervised_units")
        != NULL;
    ok = ok && find_object_with_str(ops_work, "name",
                                    "dry_agent_contract_registry") == NULL;
    ok = ok && ops_review != NULL;
    ok = ok && ops_review &&
        strstr(json_get_str(json_get(ops_review, "architecture_center")),
               "progress.kv fact log") != NULL;
    ok = ok && ops_review &&
        strcmp(json_get_str(json_get(ops_review, "preferred_payload")),
               "versioned JSON with direct decision fields and explicit drill-down commands")
            == 0;
    ok = ok && ops_availability &&
        strcmp(json_get_str(json_get(ops_availability, "schema")),
               "zcl.agent_runtime_availability.v3") == 0;
    ok = ok && ops_method_agentops &&
        strcmp(json_get_str(json_get(ops_method_agentops,
                                     "target_runtime_support")),
               "supported") == 0;

    return ok;
}

static bool sd_diagnose_contract(const struct json_value *diagnose)
{
    bool ok = true;
    ok = ok && diagnose->type == JSON_OBJ;
    ok = ok && strcmp(json_get_str(json_get(diagnose, "schema")),
                      "zcl.agent_diagnose.v2") == 0;
    ok = ok && strcmp(json_get_str(json_get(diagnose, "method")),
                      "agentdiagnose") == 0;
    ok = ok && json_get_bool(json_get(diagnose, "no_jq_required"));
    ok = ok && strcmp(json_get_str(json_get(diagnose,
                                            "native_command")),
                      "z23 agentdiagnose") == 0;
    ok = ok && strcmp(json_get_str(json_get(diagnose,
                                            "contract_source")),
                      "agent_contracts.def") == 0;
    ok = ok && json_get(diagnose, "verdict") != NULL;
    ok = ok && json_get(diagnose, "safe_next_action") != NULL;
    ok = ok && json_get(diagnose, "findings") != NULL;
    ok = ok && json_get(diagnose, "agent") != NULL;
    ok = ok && json_get(diagnose, "healthcheck") != NULL;
    return ok;
}

static bool sd_diagnose_peer_incidents_and_timeline(const struct json_value *diagnose)
{
    bool ok = true;
    const struct json_value *diagnose_first_call =
        json_get(diagnose, "first_call");
    const struct json_value *diagnose_peers =
        json_get(diagnose, "peer_incidents");
    const struct json_value *diagnose_timeline =
        json_get(diagnose, "timeline");
    ok = ok && diagnose_peers && diagnose_peers->type == JSON_OBJ;
    ok = ok && strcmp(json_get_str(json_get(diagnose_peers, "schema")),
                      "zcl.peer_incidents.v2") == 0;
    ok = ok && strcmp(json_get_str(json_get(diagnose_peers, "method")),
                      "peerincidents") == 0;
    ok = ok && strcmp(json_get_str(json_get(diagnose_peers,
                                            "native_command")),
                      "z23 peerincidents") == 0;
    ok = ok && strcmp(json_get_str(json_get(diagnose_peers,
                                            "contract_source")),
                      "agent_contracts.def") == 0;
    ok = ok && diagnose_timeline && diagnose_timeline->type == JSON_OBJ;
    ok = ok && strcmp(json_get_str(json_get(diagnose_timeline,
                                            "schema")),
                      "zcl.timeline.v2") == 0;
    ok = ok && diagnose_first_call &&
        strcmp(json_get_str(json_get(diagnose_first_call, "schema")),
               "zcl.first_call_contract.v1") == 0;
    ok = ok && strcmp(json_get_str(json_get(diagnose_first_call, "api")),
                      "agentdiagnose") == 0;
    return ok;
}

static bool sd_diagnose_first_call_budget(const struct json_value *diagnose)
{
    bool ok = true;
    const struct json_value *diagnose_first_call =
        json_get(diagnose, "first_call");
    ok = ok && json_get_int(json_get(diagnose_first_call,
                                     "budget_ms")) == 900;
    ok = ok && json_get_bool(json_get(diagnose_first_call,
                                      "partial_result"));
    return ok;
}

static bool sd_inferred_lane_topology(const struct json_value *inferred_ops)
{
    bool ok = true;
    const struct json_value *inferred_ops_lane =
        json_get(inferred_ops, "current_runtime_lane");
    const struct json_value *inferred_ops_availability =
        json_get(inferred_ops, "runtime_availability");
    ok = ok && inferred_ops_lane && inferred_ops_lane->type == JSON_OBJ;
    ok = ok && strcmp(json_get_str(json_get(inferred_ops_lane, "lane")),
                      "canonical") == 0;
    ok = ok && strcmp(json_get_str(json_get(inferred_ops_lane,
                                            "lane_source")),
                      "inferred_exact_topology") == 0;
    ok = ok && json_get_bool(json_get(inferred_ops_lane,
                                      "lane_inferred"));
    ok = ok && inferred_ops_availability &&
        strcmp(json_get_str(json_get(inferred_ops_availability,
                                     "operator_lane_name")),
               "canonical") == 0;
    ok = ok && inferred_ops_availability &&
        strcmp(json_get_str(json_get(inferred_ops_availability,
                                     "operator_lane_source")),
               "inferred_exact_topology") == 0;
    return ok;
}

static bool sd_timeline_basic_contract(const struct json_value *timeline)
{
    bool ok = true;
    const struct json_value *timeline_events =
        json_get(timeline, "events");
    const struct json_value *timeline_summary =
        json_get(timeline, "semantic_summary");
    ok = ok && timeline->type == JSON_OBJ;
    ok = ok && strcmp(json_get_str(json_get(timeline, "schema")),
                      "zcl.timeline.v2") == 0;
    ok = ok && strcmp(json_get_str(json_get(timeline, "status")),
                      "ok") == 0;
    ok = ok && strcmp(json_get_str(json_get(timeline, "category")),
                      "sync") == 0;
    ok = ok && json_get_int(json_get(timeline, "head_seq")) >= 4;
    ok = ok && timeline_events && timeline_events->type == JSON_ARR &&
        json_size(timeline_events) == 3;
    ok = ok && timeline_summary &&
        json_get_int(json_get(timeline_summary, "event_count")) == 3;
    ok = ok && timeline_summary &&
        json_get_int(json_get(timeline_summary,
                              "problem_event_count")) == 1;
    return ok;
}

static bool sd_timeline_basic_summary(const struct json_value *timeline)
{
    bool ok = true;
    const struct json_value *timeline_summary =
        json_get(timeline, "semantic_summary");
    const struct json_value *timeline_type_counts =
        json_get(timeline, "type_counts");
    const struct json_value *timeline_tip_stale =
        find_object_with_str(timeline_type_counts, "type",
                             "sync.tip_stale");
    const struct json_value *timeline_drilldowns =
        json_get(timeline, "recommended_drilldowns");
    ok = ok && timeline_summary &&
        json_get_bool(json_get(timeline_summary, "has_problem_events"));
    ok = ok && timeline_summary &&
        strcmp(json_get_str(json_get(timeline_summary,
                                     "dominant_type")),
               "sync.state_change") == 0;
    ok = ok && timeline_tip_stale &&
        json_get_bool(json_get(timeline_tip_stale, "problem"));
    ok = ok && timeline_drilldowns &&
        json_array_has_substr(timeline_drilldowns, "reducer_frontier");
    ok = ok && timeline_drilldowns &&
        json_array_has_substr(timeline_drilldowns, "fail|reject|stale");
    return ok;
}

static bool sd_timeline_filtered_contract(const struct json_value *timeline_filtered)
{
    bool ok = true;
    const struct json_value *timeline_filtered_filters =
        json_get(timeline_filtered, "filters");
    ok = ok && timeline_filtered->type == JSON_OBJ;
    ok = ok && strcmp(json_get_str(json_get(timeline_filtered,
                                            "schema")),
                      "zcl.timeline.v2") == 0;
    ok = ok && strcmp(json_get_str(json_get(timeline_filtered,
                                            "status")),
                      "ok") == 0;
    ok = ok && strcmp(json_get_str(json_get(timeline_filtered,
                                            "filter_model")),
                      "bounded_server_side_scan_then_filter") == 0;
    ok = ok &&
        json_get_int(json_get(timeline_filtered, "scan_count")) == 16;
    ok = ok &&
        json_get_int(json_get(timeline_filtered,
                              "matched_before_limit")) == 1;
    ok = ok &&
        json_get_int(json_get(timeline_filtered,
                              "count_returned")) == 1;
    ok = ok && timeline_filtered_filters &&
        json_get_bool(json_get(timeline_filtered_filters, "active"));
    ok = ok && timeline_filtered_filters &&
        json_get_int(json_get(timeline_filtered_filters, "peer")) == 9;
    return ok;
}

static bool sd_timeline_filtered_filters_reducer(const struct json_value *timeline_filtered)
{
    bool ok = true;
    const struct json_value *timeline_filtered_filters =
        json_get(timeline_filtered, "filters");
    ok = ok && timeline_filtered_filters &&
        json_get_int(json_get(timeline_filtered_filters, "height")) == 42;
    ok = ok && timeline_filtered_filters &&
        strcmp(json_get_str(json_get(timeline_filtered_filters,
                                     "reducer_stage")),
               "body_fetch") == 0;
    ok = ok && timeline_filtered_filters &&
        strcmp(json_get_str(json_get(timeline_filtered_filters,
                                     "condition")),
               "download_queue_starved") == 0;
    return ok;
}

static bool sd_timeline_filtered_filters_deploy_lane(const struct json_value *timeline_filtered)
{
    bool ok = true;
    const struct json_value *timeline_filtered_events =
        json_get(timeline_filtered, "events");
    const struct json_value *timeline_filtered_filters =
        json_get(timeline_filtered, "filters");
    const struct json_value *timeline_filtered_first =
        timeline_filtered_events && timeline_filtered_events->type == JSON_ARR
            && json_size(timeline_filtered_events) > 0
                ? json_at(timeline_filtered_events, 0) : NULL;
    ok = ok && timeline_filtered_filters &&
        strcmp(json_get_str(json_get(timeline_filtered_filters,
                                     "deploy")),
               "make-deploy") == 0;
    ok = ok && timeline_filtered_filters &&
        strcmp(json_get_str(json_get(timeline_filtered_filters,
                                     "lane")),
               "dev") == 0;
    ok = ok && timeline_filtered_first &&
        json_get_int(json_get(timeline_filtered_first, "peer")) == 9;
    return ok;
}

static bool sd_timeline_filtered_first_event(const struct json_value *timeline_filtered)
{
    bool ok = true;
    const struct json_value *timeline_filtered_events =
        json_get(timeline_filtered, "events");
    const struct json_value *timeline_filtered_refs =
        json_get(timeline_filtered, "log_references");
    const struct json_value *timeline_filtered_first =
        timeline_filtered_events && timeline_filtered_events->type == JSON_ARR
            && json_size(timeline_filtered_events) > 0
                ? json_at(timeline_filtered_events, 0) : NULL;
    ok = ok && timeline_filtered_first &&
        strstr(json_get_str(json_get(timeline_filtered_first, "data")),
               "download_queue_starved") != NULL;
    ok = ok && timeline_filtered_refs &&
        json_array_has_substr(timeline_filtered_refs,
                              "download_queue_starved");
    ok = ok && json_get(timeline_filtered,
                        "safe_next_action") != NULL;
    return ok;
}

static bool sd_timeline_cli_contract(const struct json_value *timeline_cli)
{
    bool ok = true;
    ok = ok && timeline_cli->type == JSON_OBJ;
    ok = ok && strcmp(json_get_str(json_get(timeline_cli, "schema")),
                      "zcl.timeline.v2") == 0;
    ok = ok && strcmp(json_get_str(json_get(timeline_cli, "status")),
                      "ok") == 0;
    ok = ok && strcmp(json_get_str(json_get(timeline_cli, "category")),
                      "sync") == 0;
    ok = ok &&
        json_get_int(json_get(timeline_cli, "matched_before_limit")) == 1;
    ok = ok &&
        json_get_int(json_get(timeline_cli, "count_returned")) == 1;
    return ok;
}

static bool sd_timeline_cli_first_event(const struct json_value *timeline_cli)
{
    bool ok = true;
    const struct json_value *timeline_cli_events =
        json_get(timeline_cli, "events");
    const struct json_value *timeline_cli_filters =
        json_get(timeline_cli, "filters");
    const struct json_value *timeline_cli_first =
        timeline_cli_events && timeline_cli_events->type == JSON_ARR &&
        json_size(timeline_cli_events) > 0
            ? json_at(timeline_cli_events, 0) : NULL;
    ok = ok && timeline_cli_filters &&
        json_get_bool(json_get(timeline_cli_filters, "active"));
    ok = ok && timeline_cli_first &&
        strstr(json_get_str(json_get(timeline_cli_first, "data")),
               "h=42") != NULL;
    ok = ok && timeline_cli_first &&
        strstr(json_get_str(json_get(timeline_cli_first, "data")),
               "h=420") == NULL;
    return ok;
}

static bool sd_statecatalog_contract_block_index(const struct json_value *catalog)
{
    bool ok = true;
    const struct json_value *catalog_subsystems =
        json_get(catalog, "subsystems");
    const struct json_value *block_index_cat =
        find_object_with_str(catalog_subsystems, "name", "block_index");
    ok = ok && catalog->type == JSON_OBJ;
    ok = ok && strcmp(json_get_str(json_get(catalog, "schema")),
                      "zcl.state_catalog.v2") == 0;
    ok = ok && strcmp(json_get_str(json_get(catalog, "build_commit")),
                      zcl_build_commit()) == 0;
    ok = ok && catalog_subsystems &&
        catalog_subsystems->type == JSON_ARR &&
        json_size(catalog_subsystems) >= 50;
    ok = ok && block_index_cat &&
        json_get_bool(json_get(block_index_cat, "accepts_key"));
    ok = ok && block_index_cat &&
        strcmp(json_get_str(json_get(block_index_cat, "key_hint")),
               "height or 64-char block hash") == 0;
    ok = ok && block_index_cat &&
        strcmp(json_get_str(json_get(block_index_cat, "subsystem")),
               "block_index") == 0;
    return ok;
}

static bool sd_statecatalog_block_index_detail(const struct json_value *catalog)
{
    bool ok = true;
    const struct json_value *catalog_subsystems =
        json_get(catalog, "subsystems");
    const struct json_value *block_index_cat =
        find_object_with_str(catalog_subsystems, "name", "block_index");
    ok = ok && block_index_cat &&
        strcmp(json_get_str(json_get(block_index_cat, "owner_file")),
               "engine/controllers/src/diagnostics_block_index.c") == 0;
    ok = ok && block_index_cat &&
        strcmp(json_get_str(json_get(block_index_cat, "safety_level")),
               "read_only") == 0;
    ok = ok && block_index_cat &&
        json_array_has_str(json_get(block_index_cat, "accepted_keys"),
                           "height or 64-char block hash");
    ok = ok && block_index_cat &&
        json_array_has_str(json_get(block_index_cat, "key_examples"),
                           "3170000");
    ok = ok && block_index_cat &&
        json_array_has_substr(json_get(block_index_cat, "tests"),
                              "test_block_index_integrity.c");
    ok = ok && block_index_cat &&
        json_array_has_substr(json_get(block_index_cat, "drilldowns"),
                              "z23 dumpstate block_index");
    return ok;
}

static bool sd_statecatalog_reducer_frontier(const struct json_value *catalog)
{
    bool ok = true;
    const struct json_value *catalog_subsystems =
        json_get(catalog, "subsystems");
    const struct json_value *frontier_cat =
        find_object_with_str(catalog_subsystems, "name",
                             "reducer_frontier");
    ok = ok && frontier_cat &&
        strcmp(json_get_str(json_get(frontier_cat, "state_class")),
               "reducer_stage") == 0;
    ok = ok && frontier_cat &&
        strcmp(json_get_str(json_get(frontier_cat, "owner_file")),
               "engine/reducer/jobs/src/reducer_frontier_dump.c") == 0;
    ok = ok && frontier_cat &&
        strcmp(json_get_str(json_get(frontier_cat, "safety_level")),
               "read_only") == 0;
    ok = ok && frontier_cat &&
        json_array_has_substr(json_get(frontier_cat, "tests"),
                              "test_reducer_frontier.c");
    ok = ok && frontier_cat &&
        json_array_has_str(json_get(frontier_cat, "accepted_keys"), "") ==
        false;
    ok = ok && frontier_cat &&
        json_array_has_substr(json_get(frontier_cat, "drilldowns"),
                              "z23 dumpstate reducer_frontier");
    return ok;
}

static bool sd_lanes_contract_status_command(const struct json_value *lanes)
{
    bool ok = true;
    const struct json_value *lane_commands =
        json_get(lanes, "commands");
    const struct json_value *lane_status_cmd =
        find_object_with_str(lane_commands, "name", "status");
    ok = ok && lanes->type == JSON_OBJ;
    ok = ok && strcmp(json_get_str(json_get(lanes, "schema")),
                      "zcl.agent_lanes.v2") == 0;
    ok = ok && strcmp(json_get_str(json_get(lanes,
                                            "default_deploy_target")),
                      "dev") == 0;
    ok = ok && lane_commands && lane_commands->type == JSON_ARR &&
        json_size(lane_commands) >= 4;
    ok = ok && lane_status_cmd &&
        strcmp(json_get_str(json_get(lane_status_cmd, "method")),
               "agent") == 0;
    ok = ok && lane_status_cmd &&
        strcmp(json_get_str(json_get(lane_status_cmd, "native")),
               "z23 agent") == 0;
    ok = ok && lane_status_cmd &&
        strcmp(json_get_str(json_get(lane_status_cmd, "schema")),
               "zcl.public_status.v3") == 0;
    return ok;
}

static bool sd_lanes_commands(const struct json_value *lanes)
{
    bool ok = true;
    const struct json_value *runtime_services =
        json_get(lanes, "current_runtime_services");
    const struct json_value *runtime_availability =
        json_get(lanes, "current_runtime_availability");
    const struct json_value *lane_commands =
        json_get(lanes, "commands");
    const struct json_value *lane_topology_cmd =
        find_object_with_str(lane_commands, "name", "lane_topology");
    const struct json_value *deploy_guard_cmd =
        find_object_with_str(lane_commands, "name", "deploy_guard");
    const struct json_value *lane_health_cmd =
        find_object_with_str(lane_commands, "name", "lane_health");
    ok = ok && lane_topology_cmd &&
        strcmp(json_get_str(json_get(lane_topology_cmd, "method")),
               "agentlanes") == 0;
    ok = ok && deploy_guard_cmd &&
        strcmp(json_get_str(json_get(deploy_guard_cmd, "method")),
               "agentdeployguard") == 0;
    ok = ok && deploy_guard_cmd &&
        strcmp(json_get_str(json_get(deploy_guard_cmd, "native")),
               "z23 agentdeployguard [action]") == 0;
    ok = ok && lane_health_cmd &&
        strcmp(json_get_str(json_get(lane_health_cmd, "native")),
               "tools/scripts/lane_health.sh --json") == 0;
    ok = ok && runtime_services &&
        strcmp(json_get_str(json_get(runtime_services, "schema")),
               "zcl.agent_runtime_services.v1") == 0;
    ok = ok && runtime_availability &&
        strcmp(json_get_str(json_get(runtime_availability, "schema")),
               "zcl.agent_runtime_availability.v3") == 0;
    return ok;
}

static bool sd_lanes_current_runtime_services(const struct json_value *lanes)
{
    bool ok = true;
    const struct json_value *runtime_services =
        json_get(lanes, "current_runtime_services");
    const struct json_value *runtime_availability =
        json_get(lanes, "current_runtime_availability");
    ok = ok && runtime_availability &&
        strcmp(json_get_str(json_get(runtime_availability,
                                     "availability_scope")),
               "producer_runtime") == 0;
    ok = ok && runtime_services &&
        json_get_int(json_get(runtime_services,
                              "rpc_configured_port")) == 0;
    ok = ok && runtime_services &&
        !json_get_bool(json_get(runtime_services, "rpc_running"));
    ok = ok && runtime_services &&
        json_get_int(json_get(runtime_services,
                              "https_configured_port")) == 0;
    ok = ok && runtime_services &&
        !json_get_bool(json_get(runtime_services, "https_running"));
    ok = ok && runtime_services &&
        json_get_int(json_get(runtime_services, "https_bound_port")) == 0;
    return ok;
}

static bool sd_lanes_fs_and_lane_list(const struct json_value *lanes)
{
    bool ok = true;
    const struct json_value *lane_arr = json_get(lanes, "lanes");
    const struct json_value *runtime_services =
        json_get(lanes, "current_runtime_services");
    const struct json_value *canonical =
        find_object_with_str(lane_arr, "lane", "canonical");
    ok = ok && runtime_services &&
        !json_get_bool(json_get(runtime_services, "fs_running"));
    ok = ok && runtime_services &&
        json_get_int(json_get(runtime_services, "fs_bound_port")) == 0;
    ok = ok && lane_arr && lane_arr->type == JSON_ARR &&
        json_size(lane_arr) >= 3;
    ok = ok && canonical &&
        strcmp(json_get_str(json_get(canonical, "unit")),
               "zclassic23") == 0;
    ok = ok && canonical &&
        json_get_int(json_get(canonical, "https_port")) == 8443;
    return ok;
}

static bool sd_lanes_canonical_and_dev(const struct json_value *lanes)
{
    bool ok = true;
    const struct json_value *lane_arr = json_get(lanes, "lanes");
    const struct json_value *canonical =
        find_object_with_str(lane_arr, "lane", "canonical");
    const struct json_value *dev =
        find_object_with_str(lane_arr, "lane", "dev");
    const struct json_value *canonical_safety =
        canonical ? json_get(canonical, "deployment_safety") : NULL;
    ok = ok && canonical &&
        json_get_int(json_get(canonical, "fs_port")) == 0;
    ok = ok && canonical_safety &&
        json_get_bool(json_get(canonical_safety,
                               "requires_operator_confirmation"));
    ok = ok && !json_get_bool(json_get(canonical_safety,
                                       "automation_deploy_ok"));
    ok = ok && dev &&
        strcmp(json_get_str(json_get(dev, "unit")), "zcl23-dev") == 0;
    ok = ok && dev && json_get_int(json_get(dev, "https_port")) == 0;
    ok = ok && dev && json_get_int(json_get(dev, "fs_port")) == 18034;
    return ok;
}

static bool sd_lanes_dev_deployment_safety(const struct json_value *lanes)
{
    bool ok = true;
    const struct json_value *lane_arr = json_get(lanes, "lanes");
    const struct json_value *dev =
        find_object_with_str(lane_arr, "lane", "dev");
    const struct json_value *dev_safety =
        dev ? json_get(dev, "deployment_safety") : NULL;
    ok = ok && dev_safety &&
        json_get_bool(json_get(dev_safety, "automation_deploy_ok"));
    ok = ok && strcmp(json_get_str(json_get(dev_safety,
                                            "safe_default_action")),
                      "deploy_dev_lane") == 0;
    return ok;
}

bool sd_ops_fields_scenario(struct sd_agent_ops_ctx *ctx)
{
    struct json_value ops;
    json_init(&ops);
    agent_runtime_availability_reset();
    bool ok = rpc_table_execute(&ctx->tbl, "agentops", &ctx->params, &ops);
    ok = sd_ops_fields_contract(&ops) && ok;
    ok = sd_ops_fields_direct_commands_core(&ops) && ok;
    ok = sd_ops_fields_direct_commands_native(&ops) && ok;
    ok = sd_ops_fields_direct_commands_proof_bundle(&ops) && ok;
    ok = sd_ops_fields_gaps_and_workflow(&ops) && ok;
    ok = sd_ops_fields_top_next_work(&ops) && ok;
    ok = sd_ops_fields_architecture_review(&ops) && ok;
    json_free(&ops);
    return ok;
}

/* case: agentdiagnose full-detail payload, its embedded peer_incidents
 * and timeline sections, and its first_call contract. */
bool sd_diagnose_scenario(struct sd_agent_ops_ctx *ctx)
{
    event_log_init();
    event_emitf(EV_SYNC_HEARTBEAT, 0, "diagnose sync heartbeat");
    struct json_value diagnose_full_params;
    json_init(&diagnose_full_params);
    json_set_array(&diagnose_full_params);
    struct json_value diagnose_full_arg;
    json_init(&diagnose_full_arg);
    json_set_str(&diagnose_full_arg, "full");
    json_push_back(&diagnose_full_params, &diagnose_full_arg);
    json_free(&diagnose_full_arg);
    struct json_value diagnose;
    json_init(&diagnose);
    bool ok = rpc_table_execute(&ctx->tbl, "agentdiagnose",
                                &diagnose_full_params, &diagnose);
    ok = sd_diagnose_contract(&diagnose) && ok;
    ok = sd_diagnose_peer_incidents_and_timeline(&diagnose) && ok;
    ok = sd_diagnose_first_call_budget(&diagnose) && ok;
    json_free(&diagnose);
    json_free(&diagnose_full_params);
    return ok;
}

/* case: agentops re-derives the runtime lane from an inferred exact
 * topology boot context. */
bool sd_inferred_lane_scenario(struct sd_agent_ops_ctx *ctx)
{
    struct json_value inferred_ops;
    json_init(&inferred_ops);
    agent_runtime_availability_reset();
    rpc_agent_set_boot_context("unknown", "full", "~/.zclassic-c23",
                               18232, 8033, 8443, 18034);
    bool ok = rpc_table_execute(&ctx->tbl, "agentops", &ctx->params,
                                &inferred_ops);
    ok = sd_inferred_lane_topology(&inferred_ops) && ok;
    json_free(&inferred_ops);
    rpc_agent_set_boot_context("unknown", "full", "", 0, 0, 0, 0);
    agent_runtime_availability_reset();
    return ok;
}

/* case: the sync-category timeline, its semantic summary, and its
 * recommended drilldowns. */
bool sd_timeline_basic_scenario(struct sd_agent_ops_ctx *ctx)
{
    event_log_init();
    event_emitf(EV_SYNC_STATE_CHANGE, 0, "idle->headers");
    event_emitf(EV_MSG_RECEIVED, 0, "noise");
    event_emitf(EV_SYNC_HEARTBEAT, 0, "state=headers h=10");
    event_emitf(EV_TIP_STALE, 7,
                "state=headers since=600 peers=0 max_peer=20");
    struct json_value timeline_params;
    json_init(&timeline_params);
    json_set_array(&timeline_params);
    struct json_value timeline_category;
    json_init(&timeline_category);
    json_set_str(&timeline_category, "sync");
    json_push_back(&timeline_params, &timeline_category);
    json_free(&timeline_category);
    struct json_value timeline_count;
    json_init(&timeline_count);
    json_set_int(&timeline_count, 3);
    json_push_back(&timeline_params, &timeline_count);
    json_free(&timeline_count);
    struct json_value timeline;
    json_init(&timeline);
    bool ok = rpc_table_execute(&ctx->tbl, "timeline", &timeline_params,
                                &timeline);
    ok = sd_timeline_basic_contract(&timeline) && ok;
    ok = sd_timeline_basic_summary(&timeline) && ok;
    json_free(&timeline);
    json_free(&timeline_params);
    return ok;
}

/* case: the same timeline filtered server-side by peer, height, reducer
 * stage, condition, deploy, and lane. */
bool sd_timeline_filtered_scenario(struct sd_agent_ops_ctx *ctx)
{
    event_emitf(EV_CONDITION_DETECTED, 9,
                "name=download_queue_starved stage=body_fetch "
                "lane=dev deploy=make-deploy height=42");
    event_emitf(EV_SYNC_HEARTBEAT, 9,
                "state=headers h=420 stage=body_fetch lane=dev");
    event_emitf(EV_SYNC_HEARTBEAT, 9,
                "state=headers h=42 stage=body_fetch lane=dev");
    struct json_value timeline_filter_params;
    json_init(&timeline_filter_params);
    json_set_object(&timeline_filter_params);
    json_push_kv_str(&timeline_filter_params, "category", "all");
    json_push_kv_int(&timeline_filter_params, "count", 5);
    json_push_kv_int(&timeline_filter_params, "scan_count", 16);
    json_push_kv_int(&timeline_filter_params, "since_secs", 3600);
    json_push_kv_int(&timeline_filter_params, "peer", 9);
    json_push_kv_int(&timeline_filter_params, "height", 42);
    json_push_kv_str(&timeline_filter_params, "reducer_stage",
                     "body_fetch");
    json_push_kv_str(&timeline_filter_params, "condition",
                     "download_queue_starved");
    json_push_kv_str(&timeline_filter_params, "deploy", "make-deploy");
    json_push_kv_str(&timeline_filter_params, "lane", "dev");
    struct json_value timeline_filtered;
    json_init(&timeline_filtered);
    bool ok = rpc_table_execute(&ctx->tbl, "timeline",
                                &timeline_filter_params,
                                &timeline_filtered);
    ok = sd_timeline_filtered_contract(&timeline_filtered) && ok;
    ok = sd_timeline_filtered_filters_reducer(&timeline_filtered) && ok;
    ok = sd_timeline_filtered_filters_deploy_lane(&timeline_filtered) && ok;
    ok = sd_timeline_filtered_first_event(&timeline_filtered) && ok;
    json_free(&timeline_filtered);
    json_free(&timeline_filter_params);
    return ok;
}

/* case: the same filters, this time supplied as a single CLI-style JSON
 * argument. */
bool sd_timeline_cli_scenario(struct sd_agent_ops_ctx *ctx)
{
    struct json_value timeline_cli_params;
    json_init(&timeline_cli_params);
    json_set_array(&timeline_cli_params);
    struct json_value timeline_cli_arg;
    json_init(&timeline_cli_arg);
    json_set_str(&timeline_cli_arg,
                 "{\"category\":\"sync\",\"count\":2,"
                 "\"since_secs\":3600,\"peer\":9,\"height\":42,"
                 "\"reducer_stage\":\"body_fetch\",\"lane\":\"dev\"}");
    json_push_back(&timeline_cli_params, &timeline_cli_arg);
    json_free(&timeline_cli_arg);
    struct json_value timeline_cli;
    json_init(&timeline_cli);
    bool ok = rpc_table_execute(&ctx->tbl, "timeline",
                                &timeline_cli_params, &timeline_cli);
    ok = sd_timeline_cli_contract(&timeline_cli) && ok;
    ok = sd_timeline_cli_first_event(&timeline_cli) && ok;
    json_free(&timeline_cli);
    json_free(&timeline_cli_params);
    return ok;
}

/* case: statecatalog's subsystem list and the block_index and
 * reducer_frontier entries in it. */
bool sd_statecatalog_scenario(struct sd_agent_ops_ctx *ctx)
{
    struct json_value catalog;
    json_init(&catalog);
    bool ok = rpc_table_execute(&ctx->tbl, "statecatalog", &ctx->params,
                                &catalog);
    ok = sd_statecatalog_contract_block_index(&catalog) && ok;
    ok = sd_statecatalog_block_index_detail(&catalog) && ok;
    ok = sd_statecatalog_reducer_frontier(&catalog) && ok;
    json_free(&catalog);
    return ok;
}

/* case: agentlanes' command list, runtime services/availability, and the
 * canonical and dev lane deployment-safety entries. */
bool sd_lanes_scenario(struct sd_agent_ops_ctx *ctx)
{
    struct json_value lanes;
    json_init(&lanes);
    bool ok = rpc_table_execute(&ctx->tbl, "agentlanes", &ctx->params,
                                &lanes);
    ok = sd_lanes_contract_status_command(&lanes) && ok;
    ok = sd_lanes_commands(&lanes) && ok;
    ok = sd_lanes_current_runtime_services(&lanes) && ok;
    ok = sd_lanes_fs_and_lane_list(&lanes) && ok;
    ok = sd_lanes_canonical_and_dev(&lanes) && ok;
    ok = sd_lanes_dev_deployment_safety(&lanes) && ok;
    return ok;
}
