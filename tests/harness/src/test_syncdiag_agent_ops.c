/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * agentops case: the operator work surface and everything it fans out
 * to — agentdiagnose, the event timeline, the state catalog,
 * agentlanes, agentbuild, agentdevstatus, and the agentliveness rollup
 * in compact and full detail modes.
 */

#include "test/syncdiag_rpc_fixture.h"

int syncdiag_cases_agent_ops(void)
{
    int failures = 0;

    printf("api: native RPC returns agent ops, lanes, build, and liveness... ");
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

        struct json_value ops;
        json_init(&ops);
        agent_runtime_availability_reset();
        ok = ok && rpc_table_execute(&tbl, "agentops", &params, &ops);
        const struct json_value *ops_work = json_get(&ops, "top_next_work");
        const struct json_value *ops_gaps = json_get(&ops, "api_gaps");
        const struct json_value *ops_workflow = json_get(&ops, "workflow");
        const struct json_value *ops_api_ux = json_get(&ops, "api_ux");
        const struct json_value *ops_availability =
            json_get(&ops, "runtime_availability");
        const struct json_value *ops_availability_methods =
            ops_availability ? json_get(ops_availability, "methods") : NULL;
        const struct json_value *ops_direct_commands =
            json_get(&ops, "direct_commands");
        const struct json_value *ops_method_agentops =
            find_object_with_str(ops_availability_methods, "method",
                                 "agentops");
        const struct json_value *ops_direct_agentops =
            find_object_with_str(ops_direct_commands, "method", "agentops");
        ok = ok && ops.type == JSON_OBJ;
        ok = ok && strcmp(json_get_str(json_get(&ops, "schema")),
                          "zcl.agent_ops.v2") == 0;
        ok = ok && strcmp(json_get_str(json_get(&ops, "method")),
                          "agentops") == 0;
        ok = ok && json_get_bool(json_get(&ops, "no_jq_required"));
        ok = ok && strcmp(json_get_str(json_get(&ops, "native_command")),
                          "z23 agentops") == 0;
        ok = ok && strcmp(json_get_str(json_get(&ops, "contract_source")),
                          "agent_contracts.def") == 0;
        ok = ok && strcmp(json_get_str(json_get(&ops, "api_style")),
                          "one compact first call, then registry-owned primitive drilldowns") == 0;
        ok = ok && strcmp(json_get_str(json_get(&ops, "dry_source")),
                          "agent_contracts.def + agent_contract_registry.c") == 0;
        ok = ok && strcmp(json_get_str(json_get(&ops,
                                                "diagnostics_catalog_command")),
                          "z23 statecatalog") == 0;
        ok = ok && strcmp(json_get_str(json_get(&ops,
                                                "diagnose_command")),
                          "z23 agentdiagnose") == 0;
        ok = ok && strcmp(json_get_str(json_get(&ops,
                                                "anchor_status_command")),
                          "z23 anchorstatus [-datadir=<anchor-datadir>]")
            == 0;
        ok = ok && strcmp(json_get_str(json_get(&ops,
                                                "proof_bundle_command")),
                          "z23 proofbundle [anchor_datadir]") == 0;
        ok = ok && strcmp(json_get_str(json_get(&ops,
                                                "peer_incidents_command")),
                          "z23 peerincidents") == 0;
        ok = ok && strcmp(json_get_str(json_get(&ops,
                                                "service_catalog_command")),
                          "z23 servicecatalog") == 0;
        ok = ok && strcmp(json_get_str(json_get(&ops,
                                                "service_operations_command")),
                          "z23 serviceoperations [operation_id|key=value...]") == 0;
        ok = ok && strcmp(json_get_str(json_get(&ops,
                                                "dev_status_command")),
                          "z23 agentdevstatus") == 0;
        ok = ok && strcmp(json_get_str(json_get(&ops,
                                                "deploy_guard_command")),
                          "z23 agentdeployguard [action]") == 0;
        ok = ok && ops_direct_agentops &&
            strcmp(json_get_str(json_get(ops_direct_agentops, "schema")),
                   "zcl.agent_ops.v2") == 0;
        ok = ok && ops_direct_agentops &&
            strcmp(json_get_str(json_get(ops_direct_agentops, "native")),
                   "z23 agentops") == 0;
        const struct json_value *ops_direct_diagnose =
            find_object_with_str(ops_direct_commands, "method",
                                 "agentdiagnose");
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
        const struct json_value *ops_direct_proof_bundle =
            find_object_with_str(ops_direct_commands, "method",
                                 "proofbundle");
        ok = ok && ops_direct_diagnose &&
            strcmp(json_get_str(json_get(ops_direct_diagnose, "schema")),
                   "zcl.agent_diagnose.v2") == 0;
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
        ok = ok && ops_direct_dev_status &&
            strcmp(json_get_str(json_get(ops_direct_dev_status, "native")),
                   "z23 agentdevstatus") == 0;
        ok = ok && ops_direct_proof_bundle &&
            strcmp(json_get_str(json_get(ops_direct_proof_bundle, "schema")),
                   "zcl.operator_proof_bundle.v2") == 0;
        ok = ok && ops_direct_proof_bundle &&
            strcmp(json_get_str(json_get(ops_direct_proof_bundle, "native")),
                   "z23 proofbundle [anchor_datadir]") == 0;
        ok = ok && strstr(json_get_str(json_get(&ops,
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
        ok = ok && strcmp(json_get_str(json_get(&ops,
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
        ok = ok && find_object_with_str(ops_work, "name",
                                        "shrink_boot_refold_supervised_units")
            != NULL;
        ok = ok && find_object_with_str(ops_work, "name",
                                        "dry_agent_contract_registry") == NULL;
        const struct json_value *ops_review =
            json_get(&ops, "architecture_review");
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
        ok = ok && rpc_table_execute(&tbl, "agentdiagnose",
                                     &diagnose_full_params, &diagnose);
        const struct json_value *diagnose_first_call =
            json_get(&diagnose, "first_call");
        const struct json_value *diagnose_peers =
            json_get(&diagnose, "peer_incidents");
        const struct json_value *diagnose_timeline =
            json_get(&diagnose, "timeline");
        ok = ok && diagnose.type == JSON_OBJ;
        ok = ok && strcmp(json_get_str(json_get(&diagnose, "schema")),
                          "zcl.agent_diagnose.v2") == 0;
        ok = ok && strcmp(json_get_str(json_get(&diagnose, "method")),
                          "agentdiagnose") == 0;
        ok = ok && json_get_bool(json_get(&diagnose, "no_jq_required"));
        ok = ok && strcmp(json_get_str(json_get(&diagnose,
                                                "native_command")),
                          "z23 agentdiagnose") == 0;
        ok = ok && strcmp(json_get_str(json_get(&diagnose,
                                                "contract_source")),
                          "agent_contracts.def") == 0;
        ok = ok && json_get(&diagnose, "verdict") != NULL;
        ok = ok && json_get(&diagnose, "safe_next_action") != NULL;
        ok = ok && json_get(&diagnose, "findings") != NULL;
        ok = ok && json_get(&diagnose, "agent") != NULL;
        ok = ok && json_get(&diagnose, "healthcheck") != NULL;
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
        ok = ok && json_get_int(json_get(diagnose_first_call,
                                         "budget_ms")) == 900;
        ok = ok && json_get_bool(json_get(diagnose_first_call,
                                          "partial_result"));
        json_free(&diagnose);
        json_free(&diagnose_full_params);

        struct json_value inferred_ops;
        json_init(&inferred_ops);
        agent_runtime_availability_reset();
        rpc_agent_set_boot_context("unknown", "full", "~/.zclassic-c23",
                                   18232, 8033, 8443, 18034);
        ok = ok && rpc_table_execute(&tbl, "agentops", &params,
                                     &inferred_ops);
        const struct json_value *inferred_ops_lane =
            json_get(&inferred_ops, "current_runtime_lane");
        const struct json_value *inferred_ops_availability =
            json_get(&inferred_ops, "runtime_availability");
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
        json_free(&inferred_ops);
        rpc_agent_set_boot_context("unknown", "full", "", 0, 0, 0, 0);
        agent_runtime_availability_reset();

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
        ok = ok && rpc_table_execute(&tbl, "timeline", &timeline_params,
                                     &timeline);
        const struct json_value *timeline_events =
            json_get(&timeline, "events");
        const struct json_value *timeline_summary =
            json_get(&timeline, "semantic_summary");
        const struct json_value *timeline_type_counts =
            json_get(&timeline, "type_counts");
        const struct json_value *timeline_tip_stale =
            find_object_with_str(timeline_type_counts, "type",
                                 "sync.tip_stale");
        const struct json_value *timeline_drilldowns =
            json_get(&timeline, "recommended_drilldowns");
        ok = ok && timeline.type == JSON_OBJ;
        ok = ok && strcmp(json_get_str(json_get(&timeline, "schema")),
                          "zcl.timeline.v2") == 0;
        ok = ok && strcmp(json_get_str(json_get(&timeline, "status")),
                          "ok") == 0;
        ok = ok && strcmp(json_get_str(json_get(&timeline, "category")),
                          "sync") == 0;
        ok = ok && json_get_int(json_get(&timeline, "head_seq")) >= 4;
        ok = ok && timeline_events && timeline_events->type == JSON_ARR &&
            json_size(timeline_events) == 3;
        ok = ok && timeline_summary &&
            json_get_int(json_get(timeline_summary, "event_count")) == 3;
        ok = ok && timeline_summary &&
            json_get_int(json_get(timeline_summary,
                                  "problem_event_count")) == 1;
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
        ok = ok && rpc_table_execute(&tbl, "timeline",
                                     &timeline_filter_params,
                                     &timeline_filtered);
        const struct json_value *timeline_filtered_events =
            json_get(&timeline_filtered, "events");
        const struct json_value *timeline_filtered_filters =
            json_get(&timeline_filtered, "filters");
        const struct json_value *timeline_filtered_refs =
            json_get(&timeline_filtered, "log_references");
        const struct json_value *timeline_filtered_first =
            timeline_filtered_events && timeline_filtered_events->type == JSON_ARR
                && json_size(timeline_filtered_events) > 0
                    ? json_at(timeline_filtered_events, 0) : NULL;
        ok = ok && timeline_filtered.type == JSON_OBJ;
        ok = ok && strcmp(json_get_str(json_get(&timeline_filtered,
                                                "schema")),
                          "zcl.timeline.v2") == 0;
        ok = ok && strcmp(json_get_str(json_get(&timeline_filtered,
                                                "status")),
                          "ok") == 0;
        ok = ok && strcmp(json_get_str(json_get(&timeline_filtered,
                                                "filter_model")),
                          "bounded_server_side_scan_then_filter") == 0;
        ok = ok &&
            json_get_int(json_get(&timeline_filtered, "scan_count")) == 16;
        ok = ok &&
            json_get_int(json_get(&timeline_filtered,
                                  "matched_before_limit")) == 1;
        ok = ok &&
            json_get_int(json_get(&timeline_filtered,
                                  "count_returned")) == 1;
        ok = ok && timeline_filtered_filters &&
            json_get_bool(json_get(timeline_filtered_filters, "active"));
        ok = ok && timeline_filtered_filters &&
            json_get_int(json_get(timeline_filtered_filters, "peer")) == 9;
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
        ok = ok && timeline_filtered_first &&
            strstr(json_get_str(json_get(timeline_filtered_first, "data")),
                   "download_queue_starved") != NULL;
        ok = ok && timeline_filtered_refs &&
            json_array_has_substr(timeline_filtered_refs,
                                  "download_queue_starved");
        ok = ok && json_get(&timeline_filtered,
                            "safe_next_action") != NULL;

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
        ok = ok && rpc_table_execute(&tbl, "timeline",
                                     &timeline_cli_params, &timeline_cli);
        const struct json_value *timeline_cli_events =
            json_get(&timeline_cli, "events");
        const struct json_value *timeline_cli_filters =
            json_get(&timeline_cli, "filters");
        const struct json_value *timeline_cli_first =
            timeline_cli_events && timeline_cli_events->type == JSON_ARR &&
            json_size(timeline_cli_events) > 0
                ? json_at(timeline_cli_events, 0) : NULL;
        ok = ok && timeline_cli.type == JSON_OBJ;
        ok = ok && strcmp(json_get_str(json_get(&timeline_cli, "schema")),
                          "zcl.timeline.v2") == 0;
        ok = ok && strcmp(json_get_str(json_get(&timeline_cli, "status")),
                          "ok") == 0;
        ok = ok && strcmp(json_get_str(json_get(&timeline_cli, "category")),
                          "sync") == 0;
        ok = ok &&
            json_get_int(json_get(&timeline_cli, "matched_before_limit")) == 1;
        ok = ok &&
            json_get_int(json_get(&timeline_cli, "count_returned")) == 1;
        ok = ok && timeline_cli_filters &&
            json_get_bool(json_get(timeline_cli_filters, "active"));
        ok = ok && timeline_cli_first &&
            strstr(json_get_str(json_get(timeline_cli_first, "data")),
                   "h=42") != NULL;
        ok = ok && timeline_cli_first &&
            strstr(json_get_str(json_get(timeline_cli_first, "data")),
                   "h=420") == NULL;
        json_free(&timeline_cli);
        json_free(&timeline_cli_params);

        struct json_value catalog;
        json_init(&catalog);
        ok = ok && rpc_table_execute(&tbl, "statecatalog", &params,
                                     &catalog);
        const struct json_value *catalog_subsystems =
            json_get(&catalog, "subsystems");
        const struct json_value *block_index_cat =
            find_object_with_str(catalog_subsystems, "name", "block_index");
        const struct json_value *frontier_cat =
            find_object_with_str(catalog_subsystems, "name",
                                 "reducer_frontier");
        ok = ok && catalog.type == JSON_OBJ;
        ok = ok && strcmp(json_get_str(json_get(&catalog, "schema")),
                          "zcl.state_catalog.v2") == 0;
        ok = ok && strcmp(json_get_str(json_get(&catalog, "build_commit")),
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
        struct json_value lanes;
        json_init(&lanes);
        ok = ok && rpc_table_execute(&tbl, "agentlanes", &params, &lanes);
        const struct json_value *lane_arr = json_get(&lanes, "lanes");
        const struct json_value *runtime_services =
            json_get(&lanes, "current_runtime_services");
        const struct json_value *runtime_availability =
            json_get(&lanes, "current_runtime_availability");
        const struct json_value *lane_commands =
            json_get(&lanes, "commands");
        const struct json_value *lane_status_cmd =
            find_object_with_str(lane_commands, "name", "status");
        const struct json_value *lane_topology_cmd =
            find_object_with_str(lane_commands, "name", "lane_topology");
        const struct json_value *deploy_guard_cmd =
            find_object_with_str(lane_commands, "name", "deploy_guard");
        const struct json_value *lane_health_cmd =
            find_object_with_str(lane_commands, "name", "lane_health");
        const struct json_value *canonical =
            find_object_with_str(lane_arr, "lane", "canonical");
        const struct json_value *dev =
            find_object_with_str(lane_arr, "lane", "dev");
        const struct json_value *canonical_safety =
            canonical ? json_get(canonical, "deployment_safety") : NULL;
        const struct json_value *dev_safety =
            dev ? json_get(dev, "deployment_safety") : NULL;
        ok = ok && lanes.type == JSON_OBJ;
        ok = ok && strcmp(json_get_str(json_get(&lanes, "schema")),
                          "zcl.agent_lanes.v2") == 0;
        ok = ok && strcmp(json_get_str(json_get(&lanes,
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
        ok = ok && dev_safety &&
            json_get_bool(json_get(dev_safety, "automation_deploy_ok"));
        ok = ok && strcmp(json_get_str(json_get(dev_safety,
                                                "safe_default_action")),
                          "deploy_dev_lane") == 0;
        const char *old_quality_env = getenv("ZCL_QUALITY_STATE_DIR");
        char old_quality_env_buf[4096];
        bool old_quality_env_set = old_quality_env != NULL;
        bool old_quality_env_saved = true;
        char quality_tmp[] = "/tmp/zcl_quality_rpc_XXXXXX";
        char quality_status_dir[4096];
        char quality_fuzz_file[4096];
        char *quality_root = mkdtemp(quality_tmp);
        bool quality_fixture_ok = quality_root != NULL;
        if (old_quality_env_set) {
            int n = snprintf(old_quality_env_buf,
                             sizeof(old_quality_env_buf), "%s",
                             old_quality_env);
            old_quality_env_saved = n >= 0 &&
                (size_t)n < sizeof(old_quality_env_buf);
        }
        if (quality_fixture_ok) {
            int n = snprintf(quality_status_dir,
                             sizeof(quality_status_dir), "%s/status",
                             quality_root);
            quality_fixture_ok = n >= 0 &&
                (size_t)n < sizeof(quality_status_dir) &&
                mkdir(quality_status_dir, 0700) == 0;
        }
        if (quality_fixture_ok) {
            int n = snprintf(quality_fuzz_file, sizeof(quality_fuzz_file),
                             "%s/fuzz.json", quality_status_dir);
            quality_fixture_ok = n >= 0 &&
                (size_t)n < sizeof(quality_fuzz_file);
        }
        if (quality_fixture_ok) {
            FILE *f = fopen(quality_fuzz_file, "wb");
            quality_fixture_ok = f != NULL;
            if (f) {
                fprintf(f,
                        "{\"schema\":\"zcl.background_quality_lane.v1\","
                        "\"lane\":\"fuzz\",\"status\":\"passed\","
                        "\"started_at\":\"2026-07-05T00:00:00Z\","
                        "\"finished_at\":\"2026-07-05T00:01:00Z\","
                        "\"elapsed_seconds\":60,\"exit_code\":0,"
                        "\"source_id_sha256\":\"deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef\","
                        "\"commit\":\"%s\",\"log\":\"/tmp/fuzz.log\","
                        "\"artifacts\":\"/tmp/artifacts\","
                        "\"detail\":\"fixture\"}\n",
                        zcl_build_commit());
                quality_fixture_ok = fclose(f) == 0;
            }
        }
        if (quality_fixture_ok)
            quality_fixture_ok =
                setenv("ZCL_QUALITY_STATE_DIR", quality_root, 1) == 0;
        ok = ok && old_quality_env_saved && quality_fixture_ok;

        struct json_value build;
        json_init(&build);
        ok = ok && rpc_table_execute(&tbl, "agentbuild", &params, &build);
        const struct json_value *loop =
            json_get(&build, "recommended_loop");
        const struct json_value *incremental =
            json_get(&build, "incremental_compile");
        const struct json_value *dev_binary =
            json_get(&build, "dev_node_binary");
        const struct json_value *indexing = json_get(&build, "indexing");
        const struct json_value *dev_loop_benchmark =
            json_get(&build, "dev_loop_benchmark");
        const struct json_value *cache = json_get(&build, "cache");
        const struct json_value *history =
            json_get(&build, "immutable_history_canaries");
        const struct json_value *commands = json_get(&build, "commands");
        const struct json_value *repro =
            json_get(&build, "reproducible_release");
        const struct json_value *quality_status =
            json_get(&build, "background_quality_status");
        const struct json_value *quality_lanes =
            quality_status ? json_get(quality_status, "lanes") : NULL;
        const struct json_value *fuzz_lane =
            find_object_with_str(quality_lanes, "lane", "fuzz");
        const struct json_value *coverage_lane =
            find_object_with_str(quality_lanes, "lane", "coverage");
        const struct json_value *latest_fuzz =
            fuzz_lane ? json_get(fuzz_lane, "latest") : NULL;
        ok = ok && build.type == JSON_OBJ;
        ok = ok && strcmp(json_get_str(json_get(&build, "schema")),
                          "zcl.agent_build.v2") == 0;
        ok = ok && strcmp(json_get_str(json_get(&build, "build_commit")),
                          zcl_build_commit()) == 0;
        ok = ok && loop && strcmp(json_get_str(json_get(loop, "schema")),
                                  "zcl.agent_build_loop.v2") == 0;
        ok = ok && strcmp(json_get_str(json_get(loop, "default_edit_gate")),
                          "make agent-loop") == 0;
        ok = ok && strcmp(json_get_str(json_get(loop,
                           "default_underlying_gate")),
                          "make fast-ci") == 0;
        ok = ok && strcmp(json_get_str(json_get(loop,
                           "read_only_fast_plan")),
                          "make agent-plan") == 0;
        ok = ok && strcmp(json_get_str(json_get(loop, "doctor")),
                          "make agent-doctor") == 0;
        ok = ok && strcmp(json_get_str(json_get(loop,
                           "dev_lane_status")),
                          "make agent-dev-status") == 0;
        ok = ok && strcmp(json_get_str(json_get(loop,
                           "native_dev_lane_status")),
                          "z23 agentdevstatus") == 0;
        ok = ok && strcmp(json_get_str(json_get(loop,
                           "stage_dev_binary_no_restart")),
                          "contained: make agent-stage-dev refuses") == 0;
        ok = ok && strcmp(json_get_str(json_get(loop,
                           "optional_dev_stage_no_restart")),
                          "contained: ZCL_AGENT_LOOP_DEPLOY=stage make agent-loop refuses") == 0;
        ok = ok && strcmp(json_get_str(json_get(loop,
                           "direct_changed_compile")),
                          "make fast-changed-compile") == 0;
        ok = ok && strcmp(json_get_str(json_get(loop,
                           "fast_no_link_compile")),
                          "make fast-compile") == 0;
        ok = ok && strcmp(json_get_str(json_get(loop,
                           "fast_ci_compile_default")),
                          "ZCL_FAST_COMPILE=changed -> source-wide make fast-compile in an exact compile epoch") == 0;
        ok = ok && strstr(json_get_str(json_get(loop, "rule")),
                          "classification hints only") != NULL;
        ok = ok && strcmp(json_get_str(json_get(loop,
                           "immutable_history_canaries")),
                          "make immutable-history-canaries") == 0;
        ok = ok && strcmp(json_get_str(json_get(loop,
                           "pre_push_compile_default")),
                          "none; native pre-push never compiles") == 0;
        ok = ok && incremental && json_get_bool(json_get(incremental,
                                                         "header_depfiles"));
        ok = ok && strcmp(json_get_str(json_get(incremental,
                                                "changed_compile_check")),
                          "make fast-changed-compile") == 0;
        ok = ok && strstr(json_get_str(json_get(incremental, "behavior")),
                          "build/dev-obj/epochs/<compile_epoch>") != NULL;
        ok = ok && strstr(json_get_str(json_get(incremental,
                                                "changed_compile_fallbacks")),
                          "path hints never reduce") != NULL;
        ok = ok && strcmp(json_get_str(json_get(incremental,
                                                "fast_compile_check")),
                          "make fast-compile") == 0;
        ok = ok && strcmp(json_get_str(json_get(incremental,
                                                "dev_binary_command")),
                          "make fast-rebuild") == 0;
        ok = ok && dev_binary && json_get_bool(json_get(dev_binary,
                                                        "enabled"));
        ok = ok && strcmp(json_get_str(json_get(dev_binary, "binary")),
                          "build/bin/z23-dev") == 0;
        ok = ok && indexing &&
            strcmp(json_get_str(json_get(indexing, "schema")),
                   "zcl.agent_index_runtime.v1") == 0;
        ok = ok && indexing &&
            json_get(indexing, "collector_complete") != NULL;
        ok = ok && indexing &&
            json_get(indexing, "collector_deferred") != NULL;
        bool indexing_complete = indexing &&
            json_get_bool(json_get(indexing, "collector_complete"));
        ok = ok && indexing &&
            json_get_bool(json_get(indexing, "collector_deferred")) ==
                !indexing_complete;
        ok = ok && indexing &&
            strcmp(json_get_str(json_get(indexing, "command")),
                   "make agent-index") == 0;
        ok = ok && indexing &&
            (!indexing_complete ||
             strcmp(json_get_str(json_get(indexing, "generator")),
                    "tools/dev/generate-compdb.sh") == 0);
        ok = ok && indexing && json_get(indexing, "freshness") != NULL;
        ok = ok && indexing && json_get(indexing, "clangd_optional") != NULL;
        ok = ok && dev_loop_benchmark &&
            strcmp(json_get_str(json_get(dev_loop_benchmark, "schema")),
                   "zcl.dev_loop_bench.v1") == 0;
        ok = ok && dev_loop_benchmark &&
            json_get(dev_loop_benchmark, "collector_complete") != NULL;
        ok = ok && dev_loop_benchmark &&
            json_get(dev_loop_benchmark, "collector_deferred") != NULL;
        bool benchmark_complete = dev_loop_benchmark &&
            json_get_bool(json_get(dev_loop_benchmark,
                                    "collector_complete"));
        ok = ok && dev_loop_benchmark &&
            json_get_bool(json_get(dev_loop_benchmark,
                                   "collector_deferred")) ==
                !benchmark_complete;
        ok = ok && dev_loop_benchmark &&
            (benchmark_complete
                ? json_get(dev_loop_benchmark, "slo") != NULL
                : (strcmp(json_get_str(json_get(dev_loop_benchmark,
                                                "status")),
                          "unavailable") == 0 &&
                   json_get(dev_loop_benchmark, "slo") == NULL &&
                   json_get(dev_loop_benchmark, "collector_blocker") !=
                       NULL));
        ok = ok && find_object_with_str(commands, "name", "agent_index") != NULL;
        ok = ok && find_object_with_str(commands, "name",
                                         "dev_loop_benchmark") != NULL;
        ok = ok && strcmp(json_get_str(json_get(dev_binary,
                                                "native_status_command")),
                          "z23 agentdevstatus") == 0;
        ok = ok && strcmp(json_get_str(json_get(dev_binary,
                                                "agent_loop_stage_no_restart")),
                          "contained: ZCL_AGENT_LOOP_DEPLOY=stage make agent-loop refuses") == 0;
        ok = ok && !json_get_bool(json_get(dev_binary,
                                           "release_or_deploy_artifact"));
        ok = ok && strstr(json_get_str(json_get(dev_binary,
                                                "hot_path_buckets")),
                          "core/modules/crypto") != NULL;
        ok = ok && cache && strstr(json_get_str(json_get(cache,
                                                         "auto_select_order")),
                                   "sccache cc") != NULL;
        ok = ok && strcmp(json_get_str(json_get(cache, "plan_command")),
                          "make agent-plan") == 0;
        ok = ok && strcmp(json_get_str(json_get(cache, "plan_schema")),
                          "zcl.agent_fast_plan.v1") == 0;
        ok = ok && strstr(json_get_str(json_get(cache,
                                                "makefile_auto_wrapper")),
                          "sccache cc") != NULL;
        ok = ok && find_object_with_str(json_get(cache, "knobs"), "name",
                                        "ZCL_FAST_CHANGED_FILES_ONLY") != NULL;
        ok = ok && history && history->type == JSON_OBJ;
        ok = ok && strcmp(json_get_str(json_get(history, "schema")),
                          "zcl.immutable_history_canaries.v1") == 0;
        ok = ok && json_get_bool(json_get(history, "enabled"));
        ok = ok && strcmp(json_get_str(json_get(history, "fast_command")),
                          "make immutable-history-canaries") == 0;
        ok = ok && strstr(json_get_str(json_get(history, "fast_groups")),
                          "domain_consensus_tx_structural") != NULL;
        ok = ok && strstr(json_get_str(json_get(history, "fast_groups")),
                          "consensus_parity") != NULL;
        ok = ok && strstr(json_get_str(json_get(history,
                                                "pinned_fixture")),
                          "h=478544") != NULL;
        ok = ok && strstr(json_get_str(json_get(history,
                                                "pinned_fixture")),
                          "size=125811") != NULL;
        ok = ok && strstr(json_get_str(json_get(history, "provenance")),
                          "fixture_tx_oversize_478544.c") != NULL;
        ok = ok && strcmp(json_get_str(json_get(history,
                                                "full_replay_anchor")),
                          "make replay-canary-anchor") == 0;
        ok = ok && strcmp(json_get_str(json_get(history,
                                                "full_replay_genesis")),
                          "make replay-canary-genesis") == 0;
        ok = ok && strstr(json_get_str(json_get(history,
                                                "tightening_rule")),
                          "real-chain replay") != NULL;
        ok = ok && find_object_with_str(commands, "name",
                                        "agent_plan") != NULL;
        ok = ok && find_object_with_str(commands, "name",
                                        "fast_changed_compile") != NULL;
        ok = ok && find_object_with_str(commands, "name",
                                        "agent_loop") != NULL;
        ok = ok && find_object_with_str(commands, "name",
                                        "agent_doctor") != NULL;
        ok = ok && find_object_with_str(commands, "name",
                                        "agent_dev_status_native") != NULL;
        ok = ok && find_object_with_str(commands, "name",
                                        "agent_clear_stale_dev_reindex") != NULL;
        ok = ok && find_object_with_str(commands, "name",
                                        "fast_dev_deploy") != NULL;
        ok = ok && find_object_with_str(commands, "name",
                                        "fast_compile") != NULL;
        ok = ok && find_object_with_str(commands, "name",
                                        "compile_check") != NULL;
        ok = ok && find_object_with_str(commands, "name",
                                        "fast_rebuild") != NULL;
        ok = ok && find_object_with_str(commands, "name",
                                        "dev_node_binary") != NULL;
        ok = ok && find_object_with_str(commands, "name",
                                        "immutable_history_canaries") != NULL;
        ok = ok && find_object_with_str(commands, "name",
                                        "byte_identity") != NULL;
        ok = ok && repro && strcmp(json_get_str(json_get(repro, "command")),
                                   "make ci-reproducible") == 0;
        ok = ok && strcmp(json_get_str(json_get(repro, "portable_isa")),
                          "x86-64-v3") == 0;
        ok = ok && quality_status && quality_status->type == JSON_OBJ;
        ok = ok && strcmp(json_get_str(json_get(quality_status, "schema")),
                          "zcl.background_quality_runtime.v1") == 0;
        ok = ok && json_get_bool(json_get(quality_status,
                                          "native_status_reader"));
        ok = ok && !json_get_bool(json_get(quality_status,
                                           "requires_python"));
        ok = ok && strcmp(json_get_str(json_get(quality_status,
                                                "state_dir")),
                          quality_root ? quality_root : "") == 0;
        ok = ok && strcmp(json_get_str(json_get(quality_status,
                                                "summary")),
                          "background_quality_stale") == 0;
        ok = ok && strcmp(json_get_str(json_get(quality_status,
                                                "agent_next_action")),
                          "restart_or_wait_for_current_source_quality_lanes")
            == 0;
        ok = ok && strcmp(json_get_str(json_get(quality_status,
                                                "freshness_authority")),
                          "source_id_sha256") == 0;
        ok = ok && json_get_int(json_get(quality_status,
                                         "status_files_present")) == 1;
        ok = ok && json_get_int(json_get(quality_status,
                                         "status_files_valid")) == 1;
        ok = ok && json_get_int(json_get(quality_status,
                                         "passed_count")) == 1;
        ok = ok && json_get_int(json_get(quality_status,
                                         "current_commit_count")) == 0;
        ok = ok && json_get_int(json_get(quality_status,
                                         "stale_commit_count")) == 1;
        ok = ok && json_get_int(json_get(quality_status,
                                         "unknown_commit_count")) == 0;
        ok = ok && quality_lanes && quality_lanes->type == JSON_ARR &&
            json_size(quality_lanes) == 3;
        ok = ok && fuzz_lane &&
            json_get_bool(json_get(fuzz_lane, "status_file_present"));
        ok = ok && fuzz_lane &&
            json_get_bool(json_get(fuzz_lane, "latest_json_valid"));
        ok = ok && fuzz_lane &&
            strcmp(json_get_str(json_get(fuzz_lane, "latest_status")),
                   "passed") == 0;
        ok = ok && latest_fuzz && latest_fuzz->type == JSON_OBJ;
        ok = ok && latest_fuzz &&
            strcmp(json_get_str(json_get(latest_fuzz, "commit")),
                   zcl_build_commit()) == 0;
        ok = ok && fuzz_lane &&
            strcmp(json_get_str(json_get(fuzz_lane, "latest_commit")),
                   zcl_build_commit()) == 0;
        ok = ok && fuzz_lane &&
            strcmp(json_get_str(json_get(fuzz_lane, "expected_commit")),
                   zcl_build_commit()) == 0;
        ok = ok && fuzz_lane &&
            json_get_bool(json_get(fuzz_lane, "commit_present"));
        ok = ok && fuzz_lane &&
            !json_get_bool(json_get(fuzz_lane, "commit_matches_expected"));
        ok = ok && fuzz_lane &&
            !json_get_bool(json_get(fuzz_lane,
                                    "source_id_matches_expected"));
        ok = ok && fuzz_lane &&
            strcmp(json_get_str(json_get(fuzz_lane,
                                         "source_id_freshness")),
                   "stale") == 0;
        ok = ok && fuzz_lane &&
            strcmp(json_get_str(json_get(fuzz_lane, "commit_freshness")),
                   "stale") == 0;
        ok = ok && coverage_lane &&
            !json_get_bool(json_get(coverage_lane, "status_file_present"));
        ok = ok && coverage_lane &&
            strcmp(json_get_str(json_get(coverage_lane, "commit_freshness")),
                   "no_verdict") == 0;

        /* Installed binaries and bounded collectors may not have repository
         * scripts available. That is an explicit deferred proof state, never
         * a passing or silently absent benchmark. */
        char saved_cwd[4096];
        bool moved_outside_repo = quality_root &&
            getcwd(saved_cwd, sizeof(saved_cwd)) != NULL &&
            chdir(quality_root) == 0;
        struct json_value deferred_build;
        json_init(&deferred_build);
        bool deferred_read = moved_outside_repo &&
            rpc_table_execute(&tbl, "agentbuild", &params, &deferred_build);
        bool restored_cwd = !moved_outside_repo || chdir(saved_cwd) == 0;
        const struct json_value *deferred_index =
            json_get(&deferred_build, "indexing");
        const struct json_value *deferred_benchmark =
            json_get(&deferred_build, "dev_loop_benchmark");
        ok = ok && moved_outside_repo && deferred_read && restored_cwd;
        ok = ok && deferred_index &&
            !json_get_bool(json_get(deferred_index, "collector_complete"));
        ok = ok && deferred_index &&
            json_get_bool(json_get(deferred_index, "collector_deferred"));
        ok = ok && deferred_index &&
            strcmp(json_get_str(json_get(deferred_index, "status")),
                   "unavailable") == 0;
        ok = ok && deferred_benchmark &&
            !json_get_bool(json_get(deferred_benchmark,
                                    "collector_complete"));
        ok = ok && deferred_benchmark &&
            json_get_bool(json_get(deferred_benchmark,
                                   "collector_deferred"));
        ok = ok && deferred_benchmark &&
            strcmp(json_get_str(json_get(deferred_benchmark, "status")),
                   "unavailable") == 0;
        ok = ok && deferred_benchmark &&
            json_get(deferred_benchmark, "slo") == NULL;
        json_free(&deferred_build);
        const char *old_dev_status_cmd = getenv("ZCL_AGENT_DEV_STATUS_CMD");
        char old_dev_status_cmd_buf[4096];
        bool old_dev_status_cmd_set = old_dev_status_cmd != NULL;
        bool old_dev_status_cmd_saved = true;
        if (old_dev_status_cmd_set) {
            int n = snprintf(old_dev_status_cmd_buf,
                             sizeof(old_dev_status_cmd_buf), "%s",
                             old_dev_status_cmd);
            old_dev_status_cmd_saved = n >= 0 &&
                (size_t)n < sizeof(old_dev_status_cmd_buf);
        }
        ok = ok && old_dev_status_cmd_saved;
        ok = ok && set_dev_status_cmd_json(
            "{\"schema\":\"zcl.agent_dev_status.v2\","
            "\"worker_lane\":{\"name\":\"dev\",\"role\":\"worker\","
            "\"mutation_policy\":\"noncanonical_dev_only\","
            "\"canonical_guard\":\"never_touches_live_or_soak\","
            "\"stage_command\":\"make agent-stage-dev\","
            "\"recover_command\":\"make agent-dev-recover\"},"
            "\"next_action\":\"unit-test\","
            "\"service\":{\"active_state\":\"active\"},"
            "\"rpc\":{\"status\":\"ok\"}}");
        struct json_value dev_status;
        json_init(&dev_status);
        ok = ok && rpc_table_execute(&tbl, "agentdevstatus", &params,
                                     &dev_status);
        if (old_dev_status_cmd_set)
            setenv("ZCL_AGENT_DEV_STATUS_CMD",
                   old_dev_status_cmd_buf, 1);
        else
            unsetenv("ZCL_AGENT_DEV_STATUS_CMD");
        ok = ok && dev_status.type == JSON_OBJ;
        ok = ok && strcmp(json_get_str(json_get(&dev_status, "schema")),
                          "zcl.agent_dev_status.v2") == 0;
        ok = ok && strcmp(json_get_str(json_get(&dev_status, "status")),
                          "ok") == 0;
        ok = ok && strcmp(json_get_str(json_get(&dev_status,
                                                "native_command")),
                          "z23 agentdevstatus") == 0;
        ok = ok && strcmp(json_get_str(json_get(&dev_status,
                                                "next_action")),
                          "unit-test") == 0;
        const struct json_value *dev_worker =
            json_get(&dev_status, "worker_lane");
        ok = ok && dev_worker && dev_worker->type == JSON_OBJ;
        ok = ok && strcmp(json_get_str(json_get(dev_worker, "role")),
                          "worker") == 0;
        ok = ok && strcmp(json_get_str(json_get(dev_worker,
                                                "mutation_policy")),
                          "noncanonical_dev_only") == 0;
        ok = ok && strcmp(json_get_str(json_get(dev_worker,
                                                "canonical_guard")),
                          "never_touches_live_or_soak") == 0;
        ok = ok && strcmp(json_get_str(json_get(dev_worker,
                                                "stage_command")),
                          "make agent-stage-dev") == 0;
        ok = ok && strcmp(json_get_str(json_get(dev_worker,
                                                "recover_command")),
                          "make agent-dev-recover") == 0;
        struct json_value liveness;
        json_init(&liveness);
        ok = ok && rpc_table_execute(&tbl, "agentliveness", &params,
                                     &liveness);
        const struct json_value *live_summary =
            json_get(&liveness, "liveness_summary");
        const struct json_value *live_runtime =
            json_get(&liveness, "runtime_services");
        const struct json_value *live_availability =
            json_get(&liveness, "runtime_availability");
        const struct json_value *live_quality =
            json_get(&liveness, "background_quality_status");
        const struct json_value *live_supervisor =
            json_get(&liveness, "supervisor_state");
        const struct json_value *live_drilldowns =
            json_get(&liveness, "recommended_drilldowns");
        const struct json_value *live_first_call =
            json_get(&liveness, "first_call");
        const struct json_value *live_omitted =
            json_get(&liveness, "omitted_sections");
        ok = ok && liveness.type == JSON_OBJ;
        ok = ok && strcmp(json_get_str(json_get(&liveness, "schema")),
                          "zcl.agent_liveness.v2") == 0;
        ok = ok && strcmp(json_get_str(json_get(&liveness, "method")),
                          "agentliveness") == 0;
        ok = ok && strcmp(json_get_str(json_get(&liveness,
                                                "native_command")),
                          "z23 agentliveness") == 0;
        ok = ok && strcmp(json_get_str(json_get(&liveness,
                                                "contract_source")),
                          "agent_contracts.def") == 0;
        ok = ok && strcmp(json_get_str(json_get(&liveness, "detail_mode")),
                          "brief") == 0;
        ok = ok && !json_get_bool(json_get(&liveness,
                                           "embedded_drilldowns"));
        ok = ok && strcmp(json_get_str(json_get(&liveness,
                                                "full_mode_command")),
                          "z23 agentliveness full") == 0;
        ok = ok && live_first_call && live_first_call->type == JSON_OBJ;
        ok = ok && strcmp(json_get_str(json_get(live_first_call, "schema")),
                          "zcl.first_call_contract.v1") == 0;
        ok = ok && strcmp(json_get_str(json_get(live_first_call, "api")),
                          "agentliveness") == 0;
        ok = ok && strcmp(json_get_str(json_get(live_first_call,
                                                "result_completeness")),
                          "bounded") == 0;
        ok = ok && strcmp(json_get_str(json_get(live_first_call, "source")),
                          "runtime_supervisor_quality_status_brief") == 0;
        ok = ok && json_get_bool(json_get(live_first_call,
                                          "partial_result"));
        ok = ok && strcmp(json_get_str(json_get(live_first_call,
                                                "partial_reason")),
                          "brief_mode_omits_embedded_drilldowns") == 0;
        ok = ok && strcmp(json_get_str(json_get(live_first_call,
                                                "full_mode_command")),
                          "z23 agentliveness full") == 0;
        ok = ok && json_get_int(json_get(live_first_call,
                                         "budget_ms")) == 750;
        ok = ok && json_get(live_first_call, "elapsed_ms") != NULL;
        ok = ok && json_get(live_first_call, "budget_exceeded") != NULL;
        ok = ok && live_omitted &&
            json_array_has_str(live_omitted, "runtime_availability.methods");
        ok = ok && live_omitted &&
            json_array_has_str(live_omitted, "background_quality_status.lanes");
        ok = ok && live_omitted &&
            json_array_has_str(live_omitted, "supervisor_state.domains");
        ok = ok && strcmp(json_get_str(json_get(&liveness,
                                                "overall_liveness")),
                          "static_or_offline_context") == 0;
        ok = ok && live_summary &&
            strcmp(json_get_str(json_get(live_summary,
                                         "background_quality_summary")),
                   "background_quality_stale") == 0;
        ok = ok && live_summary &&
            json_get_int(json_get(live_summary,
                                  "background_quality_status_files_valid")) == 1;
        ok = ok && live_runtime &&
            strcmp(json_get_str(json_get(live_runtime, "schema")),
                   "zcl.agent_runtime_services.v1") == 0;
        ok = ok && live_availability &&
            strcmp(json_get_str(json_get(live_availability, "schema")),
                   "zcl.agent_runtime_availability.v3") == 0;
        ok = ok && live_availability &&
            strcmp(json_get_str(json_get(live_availability,
                                         "object_completeness")),
                   "compact") == 0;
        ok = ok && live_availability &&
            json_get(live_availability, "methods") == NULL;
        ok = ok && live_availability &&
            !json_get_bool(json_get(live_availability,
                                    "target_rpc_attempted"));
        ok = ok && live_summary &&
            !json_get_bool(json_get(live_summary,
                                    "target_runtime_reachable"));
        ok = ok && live_summary &&
            !json_get_bool(json_get(live_summary,
                                    "effective_runtime_reachable"));
        ok = ok && live_summary &&
            strcmp(json_get_str(json_get(live_summary,
                                         "producer_runtime_state")),
                   "inactive_or_static_probe") == 0;
        ok = ok && live_summary &&
            strcmp(json_get_str(json_get(live_summary,
                                         "target_runtime_state")),
                   "not_probed") == 0;
        ok = ok && live_summary &&
            strcmp(json_get_str(json_get(live_summary,
                                         "effective_runtime_scope")),
                   "none") == 0;
        ok = ok && live_summary &&
            strcmp(json_get_str(json_get(live_summary,
                                         "runtime_observation_scope")),
                   "producer_runtime") == 0;
        ok = ok && live_quality &&
            strcmp(json_get_str(json_get(live_quality, "schema")),
                   "zcl.background_quality_runtime.v1") == 0;
        ok = ok && live_quality &&
            strcmp(json_get_str(json_get(live_quality,
                                         "object_completeness")),
                   "compact") == 0;
        ok = ok && live_quality &&
            json_get(live_quality, "lanes") == NULL;
        ok = ok && live_supervisor &&
            json_get(live_supervisor, "running") != NULL;
        ok = ok && live_supervisor &&
            strcmp(json_get_str(json_get(live_supervisor,
                                         "object_completeness")),
                   "compact") == 0;
        ok = ok && live_supervisor &&
            json_get(live_supervisor, "domains") == NULL;
        ok = ok && live_drilldowns &&
            json_array_has_substr(live_drilldowns,
                                  "z23 dumpstate supervisor");

        struct json_value liveness_full_params, full_mode, liveness_full;
        json_init(&liveness_full_params);
        json_set_array(&liveness_full_params);
        json_init(&full_mode);
        json_set_str(&full_mode, "full");
        json_push_back(&liveness_full_params, &full_mode);
        json_free(&full_mode);
        json_init(&liveness_full);
        ok = ok && rpc_table_execute(&tbl, "agentliveness",
                                     &liveness_full_params, &liveness_full);
        const struct json_value *full_availability =
            json_get(&liveness_full, "runtime_availability");
        const struct json_value *full_quality =
            json_get(&liveness_full, "background_quality_status");
        const struct json_value *full_supervisor =
            json_get(&liveness_full, "supervisor_state");
        const struct json_value *full_first_call =
            json_get(&liveness_full, "first_call");
        ok = ok && strcmp(json_get_str(json_get(&liveness_full,
                                                "detail_mode")),
                          "full") == 0;
        ok = ok && json_get_bool(json_get(&liveness_full,
                                          "embedded_drilldowns"));
        ok = ok && json_get(&liveness_full, "omitted_sections") == NULL;
        ok = ok && full_availability &&
            json_get(full_availability, "methods") != NULL;
        ok = ok && full_quality && json_get(full_quality, "lanes") != NULL;
        ok = ok && full_supervisor &&
            json_get(full_supervisor, "domains") != NULL;
        ok = ok && full_first_call &&
            strcmp(json_get_str(json_get(full_first_call, "source")),
                   "runtime_supervisor_quality_status_full") == 0;
        json_free(&liveness_full);
        json_free(&liveness_full_params);

        agent_runtime_availability_begin_probe("test_target_rpc",
                                               "/tmp/zcl-canonical",
                                               18232, "ok");
        agent_runtime_availability_record_method("agent", "supported", 0, "");
        struct json_value probed_liveness;
        json_init(&probed_liveness);
        ok = ok && rpc_table_execute(&tbl, "agentliveness", &params,
                                     &probed_liveness);
        const struct json_value *probed_summary =
            json_get(&probed_liveness, "liveness_summary");
        const struct json_value *probed_availability =
            json_get(&probed_liveness, "runtime_availability");
        ok = ok && strcmp(json_get_str(json_get(&probed_liveness,
                                                "overall_liveness")),
                          "target_runtime_reachable") == 0;
        ok = ok && probed_summary &&
            json_get_bool(json_get(probed_summary,
                                   "target_runtime_reachable"));
        ok = ok && probed_summary &&
            json_get_bool(json_get(probed_summary,
                                   "effective_runtime_reachable"));
        ok = ok && probed_summary &&
            strcmp(json_get_str(json_get(probed_summary,
                                         "producer_runtime_state")),
                   "inactive_or_static_probe") == 0;
        ok = ok && probed_summary &&
            strcmp(json_get_str(json_get(probed_summary,
                                         "target_runtime_state")),
                   "reachable") == 0;
        ok = ok && probed_summary &&
            strcmp(json_get_str(json_get(probed_summary,
                                         "effective_runtime_scope")),
                   "target_rpc_probe") == 0;
        ok = ok && probed_summary &&
            strcmp(json_get_str(json_get(probed_summary,
                                         "runtime_observation_scope")),
                   "target_rpc_probe") == 0;
        ok = ok && probed_availability &&
            json_get_bool(json_get(probed_availability,
                                   "target_rpc_reachable"));
        ok = ok && strcmp(json_get_str(json_get(&probed_liveness,
                                                "agent_next_action")),
                          "monitor_target_runtime") == 0;
        json_free(&probed_liveness);
        agent_runtime_availability_reset();
        json_free(&params);
        json_free(&ops);
        json_free(&timeline);
        json_free(&timeline_params);
        json_free(&timeline_filtered);
        json_free(&timeline_filter_params);
        json_free(&catalog);
        json_free(&lanes);
        json_free(&build);
        json_free(&dev_status);
        json_free(&liveness);
        if (old_quality_env_set)
            setenv("ZCL_QUALITY_STATE_DIR", old_quality_env_buf, 1);
        else
            unsetenv("ZCL_QUALITY_STATE_DIR");
        if (quality_fixture_ok) {
            unlink(quality_fuzz_file);
            rmdir(quality_status_dir);
            rmdir(quality_tmp);
        }

        if (ok) printf("OK\n");
        else    { printf("FAIL\n"); failures++; }
    }

    return failures;
}
