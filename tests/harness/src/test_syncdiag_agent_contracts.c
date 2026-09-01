/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * agentcontracts case: the contract registry document — schemas,
 * per-method contracts and their field/work surfaces, and the
 * advertised transports.
 */

#include "test/syncdiag_rpc_fixture.h"

int syncdiag_cases_agent_contracts(void)
{
    int failures = 0;

    printf("api: native RPC returns agent contracts and build contract... ");
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

        struct json_value contracts;
        json_init(&contracts);
        bool ok = rpc_table_execute(&tbl, "agentcontracts",
                                    &params, &contracts);
        const struct json_value *schemas = json_get(&contracts, "schemas");
        const struct json_value *contract_list =
            json_get(&contracts, "contracts");
        const struct json_value *contract_summary =
            json_get(&contracts, "contract_summary");
        const struct json_value *transports =
            json_get(&contracts, "transports");
        const struct json_value *contract_agentops =
            find_object_with_str(contract_list, "method", "agentops");
        const struct json_value *contract_agentdevstatus =
            find_object_with_str(contract_list, "method", "agentdevstatus");
        const struct json_value *contract_diagnose =
            find_object_with_str(contract_list, "method", "agentdiagnose");
        const struct json_value *contract_api =
            find_object_with_str(contract_list, "method", "api");
        const struct json_value *contract_app_protocols =
            find_object_with_str(contract_list, "method", "appprotocols");
        const struct json_value *contract_service_catalog =
            find_object_with_str(contract_list, "method", "servicecatalog");
        const struct json_value *contract_service_operations =
            find_object_with_str(contract_list, "method", "serviceoperations");
        const struct json_value *contract_status =
            find_object_with_str(contract_list, "method", "status");
        const struct json_value *contract_dumpstate =
            find_object_with_str(contract_list, "method", "dumpstate");
        const struct json_value *contract_getnodelog =
            find_object_with_str(contract_list, "method", "getnodelog");
        const struct json_value *contract_dbquery =
            find_object_with_str(contract_list, "method", "dbquery");
        const struct json_value *contract_eventlog =
            find_object_with_str(contract_list, "method", "eventlog");
        const struct json_value *contract_healthcheck =
            find_object_with_str(contract_list, "method", "healthcheck");
        const struct json_value *contract_milestone =
            find_object_with_str(contract_list, "method", "milestone");
        const struct json_value *contract_refold =
            find_object_with_str(contract_list, "method", "refold");
        const struct json_value *contract_proof_bundle =
            find_object_with_str(contract_list, "method", "proofbundle");
        const struct json_value *contract_peerincidents =
            find_object_with_str(contract_list, "method", "peerincidents");
        ok = ok && contracts.type == JSON_OBJ;
        ok = ok && strcmp(json_get_str(json_get(&contracts, "schema")),
                          "zcl.agent_contracts.v2") == 0;
        ok = ok && contract_list && contract_list->type == JSON_ARR;
        ok = ok && contract_summary &&
            json_get_int(json_get(contract_summary, "contract_count")) >= 20;
        ok = ok && contract_summary &&
            json_get_int(json_get(contract_summary,
                                  "native_declared_count")) >= 20;
        ok = ok && contract_summary &&
            strcmp(json_get_str(json_get(contract_summary,
                                         "registry_source")),
                   "agent_contracts.def + agent_contract_registry.c") == 0;
        ok = ok && contract_summary &&
            strcmp(json_get_str(json_get(contract_summary,
                                         "schema_registry_source")),
                   "agent_contract_schema_registry.c") == 0;
        ok = ok && contract_summary &&
            strcmp(json_get_str(json_get(contract_summary,
                                         "review_registry_source")),
                   "agent_contract_review_registry.c") == 0;
        ok = ok && contract_summary &&
            json_get_int(json_get(contract_summary,
                                  "schema_surface_count")) ==
                (int64_t)agent_contract_schema_surface_count();
        ok = ok && contract_summary &&
            json_get_int(json_get(contract_summary,
                                  "review_surface_count")) ==
                (int64_t)agent_contract_review_surface_total_count();
        ok = ok && agent_contract_schema_surface_count() >= 18;
        ok = ok && agent_contract_review_surface_total_count() >= 5;
        ok = ok && contract_agentops &&
            strcmp(json_get_str(json_get(contract_agentops, "schema")),
                   "zcl.agent_ops.v2") == 0;
        ok = ok && contract_agentops &&
            strcmp(json_get_str(json_get(contract_agentops, "native")),
                   "z23 agentops") == 0;
        ok = ok && contract_agentops &&
            strcmp(json_get_str(json_get(contract_agentops,
                                         "api_cli_field")),
                   "ops_command") == 0;
        ok = ok && contract_agentops &&
            strcmp(json_get_str(json_get(contract_agentops,
                                         "ops_surface")),
                   "direct") == 0;
        ok = ok && contract_agentops &&
            json_get_int(json_get(contract_agentops, "ops_rank")) == 1;
        ok = ok && contract_agentops &&
            strcmp(json_get_str(json_get(contract_agentops, "ops_name")),
                   "no_jq_contract") == 0;
        ok = ok && contract_agentops &&
            strcmp(json_get_str(json_get(contract_agentops,
                                         "ops_purpose")),
                   "compact top-level fields for common agent decisions") == 0;
        ok = ok && contract_agentdevstatus &&
            strcmp(json_get_str(json_get(contract_agentdevstatus, "schema")),
                   "zcl.agent_dev_status.v2") == 0;
        ok = ok && contract_agentdevstatus &&
            strcmp(json_get_str(json_get(contract_agentdevstatus, "native")),
                   "z23 agentdevstatus") == 0;
        ok = ok && contract_agentdevstatus &&
            strcmp(json_get_str(json_get(contract_agentdevstatus,
                                         "api_cli_field")),
                   "dev_status_command") == 0;
        ok = ok && contract_agentdevstatus &&
            strcmp(json_get_str(json_get(contract_agentdevstatus,
                                         "ops_surface")),
                   "direct") == 0;
        ok = ok && contract_status == NULL;
        ok = ok && contract_diagnose &&
            strcmp(json_get_str(json_get(contract_diagnose, "schema")),
                   "zcl.agent_diagnose.v2") == 0;
        ok = ok && contract_api &&
            strcmp(json_get_str(json_get(contract_api, "api_cli_field")),
                   "api_command") == 0;
        ok = ok && contract_app_protocols &&
            strcmp(json_get_str(json_get(contract_app_protocols, "schema")),
                   "zcl.application_protocols.index.v2") == 0;
        ok = ok && contract_app_protocols &&
            strcmp(json_get_str(json_get(contract_app_protocols, "native")),
                   "z23 appprotocols") == 0;
        ok = ok && contract_app_protocols &&
            strcmp(json_get_str(json_get(contract_app_protocols, "rest")),
                   "GET /api/v1/protocols") == 0;
        ok = ok && contract_app_protocols &&
            strcmp(json_get_str(json_get(contract_app_protocols,
                                         "api_cli_field")),
                   "app_protocols_command") == 0;
        ok = ok && contract_service_catalog &&
            strcmp(json_get_str(json_get(contract_service_catalog, "schema")),
                   "zcl.service_catalog.v2") == 0;
        ok = ok && contract_service_catalog &&
            strcmp(json_get_str(json_get(contract_service_catalog, "native")),
                   "z23 servicecatalog") == 0;
        ok = ok && contract_service_catalog &&
            strcmp(json_get_str(json_get(contract_service_catalog, "rest")),
                   "GET /api/v1/service-catalog") == 0;
        ok = ok && contract_service_catalog &&
            strcmp(json_get_str(json_get(contract_service_catalog,
                                         "api_cli_field")),
                   "service_catalog_command") == 0;
        ok = ok && contract_service_operations &&
            strcmp(json_get_str(json_get(contract_service_operations,
                                         "schema")),
                   "zcl.service_operations.index.v2") == 0;
        ok = ok && contract_service_operations &&
            strcmp(json_get_str(json_get(contract_service_operations,
                                         "native")),
                   "z23 serviceoperations [operation_id|key=value...]") == 0;
        ok = ok && contract_service_operations &&
            strcmp(json_get_str(json_get(contract_service_operations,
                                         "rest")),
                   "GET /api/v1/service-operations") == 0;
        ok = ok && contract_service_operations &&
            strcmp(json_get_str(json_get(contract_service_operations,
                                         "api_cli_field")),
                   "service_operations_command") == 0;
        ok = ok && contract_dumpstate &&
            strcmp(json_get_str(json_get(contract_dumpstate, "native")),
                   "z23 dumpstate <subsystem> [key]") == 0;
        ok = ok && contract_dumpstate &&
            strcmp(json_get_str(json_get(contract_dumpstate,
                                         "ops_name")),
                   "state_drilldown") == 0;
        ok = ok && contract_getnodelog &&
            strcmp(json_get_str(json_get(contract_getnodelog, "native")),
                   "z23 getnodelog <pattern>") == 0;
        ok = ok && contract_dbquery &&
            strcmp(json_get_str(json_get(contract_dbquery, "schema")),
                   "zcl.sql_result.v1") == 0;
        ok = ok && contract_dbquery &&
            strcmp(json_get_str(json_get(contract_dbquery, "native")),
                   "z23 dbquery <SELECT>") == 0;
        ok = ok && contract_dbquery &&
            strstr(json_get_str(json_get(contract_dbquery,
                                         "probe_params_json")),
                   "sqlite_master") != NULL;
        ok = ok && strcmp(agent_contract_probe_params_json("agent"), "[]")
                         == 0;
        ok = ok && strstr(agent_contract_probe_params_json("dbquery"),
                          "sqlite_master") != NULL;
        ok = ok && contract_eventlog &&
            strcmp(json_get_str(json_get(contract_eventlog, "schema")),
                   "zcl.event_log.v1") == 0;
        ok = ok && contract_eventlog &&
            strcmp(json_get_str(json_get(contract_eventlog, "native")),
                   "z23 eventlog <count>") == 0;
        ok = ok && contract_eventlog &&
            strcmp(json_get_str(json_get(contract_eventlog,
                                         "probe_params_json")),
                   "[1]") == 0;
        ok = ok && strcmp(agent_contract_probe_params_json("eventlog"), "[1]")
                         == 0;
        ok = ok && contract_healthcheck &&
            strcmp(json_get_str(json_get(contract_healthcheck, "schema")),
                   "zcl.healthcheck.v1") == 0;
        ok = ok && contract_healthcheck &&
            strcmp(json_get_str(json_get(contract_healthcheck,
                                         "api_cli_field")),
                   "drilldown_command") == 0;
        ok = ok && contract_milestone &&
            strcmp(json_get_str(json_get(contract_milestone, "rest")),
                   "GET /api/v1/milestone") == 0;
        ok = ok && contract_refold &&
            strcmp(json_get_str(json_get(contract_refold, "rest")),
                   "GET /api/v1/refold") == 0;
        ok = ok && contract_proof_bundle &&
            strcmp(json_get_str(json_get(contract_proof_bundle, "schema")),
                   "zcl.operator_proof_bundle.v2") == 0;
        ok = ok && contract_proof_bundle &&
            strcmp(json_get_str(json_get(contract_proof_bundle, "native")),
                   "z23 proofbundle [anchor_datadir]") == 0;
        ok = ok && contract_proof_bundle &&
            strcmp(json_get_str(json_get(contract_proof_bundle,
                                         "api_cli_field")),
                   "proof_bundle_command") == 0;
        ok = ok && contract_peerincidents &&
            strcmp(json_get_str(json_get(contract_peerincidents, "schema")),
                   "zcl.peer_incidents.v2") == 0;
        ok = ok && contract_peerincidents &&
            strcmp(json_get_str(json_get(contract_peerincidents, "native")),
                   "z23 peerincidents") == 0;
        ok = ok && contract_peerincidents &&
            strcmp(json_get_str(json_get(contract_peerincidents,
                                         "api_cli_field")),
                   "peer_incidents_command") == 0;
        ok = ok && contract_peerincidents &&
            strcmp(json_get_str(json_get(contract_peerincidents,
                                         "ops_name")),
                   "peer_incidents") == 0;
        ok = ok && find_object_with_str(schemas, "schema",
                                        "zcl.agent_build.v2") != NULL;
        ok = ok && find_object_with_str(schemas, "schema",
                                        "zcl.agent_dev_status.v2") != NULL;
        ok = ok && find_object_with_str(schemas, "schema",
                                        "zcl.mvp_operator_proofs.v1")
            != NULL;
        ok = ok && find_object_with_str(schemas, "schema",
                                        "zcl.peer_incidents.v2") != NULL;
        ok = ok && find_object_with_str(schemas, "schema",
                                        "zcl.background_quality_runtime.v1")
            != NULL;
        ok = ok && find_object_with_str(schemas, "schema",
                                        "zcl.agent_readiness.v1") != NULL;
        ok = ok && find_object_with_str(schemas, "schema",
                                        "zcl.runtime_build.v2") != NULL;
        ok = ok && find_object_with_str(schemas, "schema",
                                        "zcl.agent_runtime_availability.v3")
            != NULL;
        ok = ok && find_object_with_str(schemas, "schema",
                                        "zcl.operator_latch.v2") != NULL;
        ok = ok && find_object_with_str(schemas, "schema",
                                        "zcl.service_catalog.v2") != NULL;
        ok = ok && find_object_with_str(schemas, "schema",
                                        "zcl.service_operations.index.v2")
            != NULL;
        ok = ok && find_object_with_str(schemas, "schema",
                                        "zcl.service_operation.v2") != NULL;
        ok = ok && find_object_with_str(schemas, "schema",
                                        "zcl.service_contract.v2") != NULL;
        ok = ok &&
            find_object_with_str(schemas, "schema",
                                 "zcl.condition_engine_summary.v2") != NULL;
        ok = ok && find_object_with_str(schemas, "schema",
                                        "zcl.agent_interface.v2") != NULL;
        ok = ok && find_object_with_str(schemas, "schema",
                                        "zcl.agent_ops.v2") != NULL;
        ok = ok && find_object_with_str(schemas, "schema",
                                        "zcl.agent_diagnose.v2") != NULL;
        ok = ok && find_object_with_str(schemas, "schema",
                                        "zcl.timeline.v2") != NULL;
        ok = ok && find_object_with_str(schemas, "schema",
                                        "zcl.state_catalog.v2") != NULL;
        ok = ok && find_object_with_str(schemas, "schema",
                                        "subsystem-specific diagnostic JSON")
            != NULL;
        ok = ok && find_object_with_str(schemas, "schema",
                                        "zcl.node_log.v1") != NULL;
        ok = ok && find_object_with_str(schemas, "schema",
                                        "zcl.sql_result.v1") != NULL;
        ok = ok && find_object_with_str(schemas, "schema",
                                        "zcl.event_log.v1") != NULL;
        ok = ok && find_object_with_str(schemas, "schema",
                                        "zcl.healthcheck.v1") != NULL;
        ok = ok && find_object_with_str(schemas, "schema",
                                        "zcl.milestone_status.v2") != NULL;
        ok = ok && find_object_with_str(schemas, "schema",
                                        "zcl.refold_status.v2") != NULL;
        ok = ok && find_object_with_str(schemas, "schema",
                                        "zcl.operator_proof_bundle.v2")
            != NULL;
        ok = ok && find_object_with_str(schemas, "schema",
                                        "zcl.agent_lanes.v2") != NULL;
        ok = ok && find_object_with_str(schemas, "schema",
                                        "zcl.agent_liveness.v2") != NULL;
        ok = ok && find_object_with_str(schemas, "schema",
                                        "zcl.agent_runtime_services.v1") != NULL;
        ok = ok && find_object_with_str(schemas, "schema",
                                        "zcl.agent_capability.v2") != NULL;
        ok = ok && find_object_with_str(schemas, "schema",
                                        "zcl.agent_machine_contract.v2")
            != NULL;
        ok = ok && find_object_with_str(schemas, "schema",
                                        "zcl.agent_deploy_guard.v1") != NULL;
        ok = ok && find_object_with_str(schemas, "schema",
                                        "zcl.operator_lane.v1") != NULL;
        ok = ok &&
            find_object_with_str(schemas, "schema",
                                 "zcl.operator_deployment_safety.v1") != NULL;
        ok = ok && json_array_has_substr(transports,
                                         "z23 agentbuild");
        ok = ok && json_array_has_substr(transports,
                                         "z23 agentdevstatus");
        ok = ok && json_array_has_substr(transports,
                                         "z23 agentops");
        ok = ok && json_array_has_substr(transports,
                                         "z23 agentdiagnose");
        ok = ok && json_array_has_substr(transports,
                                         "z23 appprotocols");
        ok = ok && json_array_has_substr(transports,
                                         "z23 servicecatalog");
        ok = ok && json_array_has_substr(transports,
                                         "z23 serviceoperations");
        ok = ok && json_array_has_substr(transports,
                                         "z23 statecatalog");
        ok = ok && json_array_has_substr(transports,
                                         "z23 dumpstate");
        ok = ok && json_array_has_substr(transports,
                                         "z23 getnodelog");
        ok = ok && json_array_has_substr(transports,
                                         "z23 dbquery");
        ok = ok && json_array_has_substr(transports,
                                         "z23 eventlog");
        ok = ok && json_array_has_substr(transports,
                                         "z23 timeline");
        ok = ok && json_array_has_substr(transports,
                                         "z23 healthcheck");
        ok = ok && json_array_has_substr(transports,
                                         "z23 milestone");
        ok = ok && json_array_has_substr(transports,
                                         "z23 refold");
        ok = ok && json_array_has_substr(transports,
                                         "z23 proofbundle");
        ok = ok && !json_array_has_substr(transports, "z23 status");

        json_free(&params);
        json_free(&contracts);

        if (ok) printf("OK\n");
        else    { printf("FAIL\n"); failures++; }
    }

    return failures;
}
