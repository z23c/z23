/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * agentcontracts case: the contract registry document — schemas,
 * per-method contracts and their field/work surfaces, and the
 * advertised transports.
 */

#include "test/syncdiag_rpc_fixture.h"

/* Slots in syncdiag_ac_facts.obj. The step table names a slot instead of
 * capturing a pointer, so the rows stay static and run in source order. */
enum {
    SYNCDIAG_AC_CONTRACTS = 0,
    SYNCDIAG_AC_LIST,
    SYNCDIAG_AC_SUMMARY,
    SYNCDIAG_AC_STATUS,
    SYNCDIAG_AC_AGENTOPS,
    SYNCDIAG_AC_AGENTDEVSTATUS,
    SYNCDIAG_AC_DIAGNOSE,
    SYNCDIAG_AC_API,
    SYNCDIAG_AC_APP_PROTOCOLS,
    SYNCDIAG_AC_SERVICE_CATALOG,
    SYNCDIAG_AC_SERVICE_OPERATIONS,
    SYNCDIAG_AC_DUMPSTATE,
    SYNCDIAG_AC_GETNODELOG,
    SYNCDIAG_AC_DBQUERY,
    SYNCDIAG_AC_EVENTLOG,
    SYNCDIAG_AC_HEALTHCHECK,
    SYNCDIAG_AC_MILESTONE,
    SYNCDIAG_AC_REFOLD,
    SYNCDIAG_AC_PROOF_BUNDLE,
    SYNCDIAG_AC_PEERINCIDENTS,
    SYNCDIAG_AC_OBJ_COUNT
};

struct syncdiag_ac_facts {
    const struct json_value *obj[SYNCDIAG_AC_OBJ_COUNT];
    const struct json_value *schemas;
    const struct json_value *transports;
};

/* Positional fields: obj, key, want, number, count_fn, present.
 * key is a JSON field or a probe method. present is only read by the
 * transport row. A failed row skips every later row. */
struct syncdiag_ac_check {
    int obj;
    const char *key;
    const char *want;
    int64_t number;
    size_t (*count_fn)(void);
    bool present;
};

struct syncdiag_ac_step {
    bool (*pred)(const struct syncdiag_ac_facts *facts,
                 const struct syncdiag_ac_check *row);
    struct syncdiag_ac_check row;
};

static bool syncdiag_ac_doc_is_object(
    const struct syncdiag_ac_facts *facts,
    const struct syncdiag_ac_check *row)
{
    return facts->obj[row->obj]->type == JSON_OBJ;
}

static bool syncdiag_ac_list_is_array(
    const struct syncdiag_ac_facts *facts,
    const struct syncdiag_ac_check *row)
{
    const struct json_value *list = facts->obj[row->obj];
    return list && list->type == JSON_ARR;
}

static bool syncdiag_ac_status_is_absent(
    const struct syncdiag_ac_facts *facts,
    const struct syncdiag_ac_check *row)
{
    return facts->obj[row->obj] == NULL;
}

static bool syncdiag_ac_int_at_least(
    const struct syncdiag_ac_facts *facts,
    const struct syncdiag_ac_check *row)
{
    const struct json_value *obj = facts->obj[row->obj];
    return obj && json_get_int(json_get(obj, row->key)) >= row->number;
}

static bool syncdiag_ac_int_equals(
    const struct syncdiag_ac_facts *facts,
    const struct syncdiag_ac_check *row)
{
    const struct json_value *obj = facts->obj[row->obj];
    return obj && json_get_int(json_get(obj, row->key)) == row->number;
}

static bool syncdiag_ac_int_equals_count(
    const struct syncdiag_ac_facts *facts,
    const struct syncdiag_ac_check *row)
{
    const struct json_value *obj = facts->obj[row->obj];
    return obj &&
           json_get_int(json_get(obj, row->key)) ==
               (int64_t)row->count_fn();
}

static bool syncdiag_ac_count_at_least(
    const struct syncdiag_ac_facts *facts,
    const struct syncdiag_ac_check *row)
{
    (void)facts;
    return row->count_fn() >= (size_t)row->number;
}

static bool syncdiag_ac_field_equals(
    const struct syncdiag_ac_facts *facts,
    const struct syncdiag_ac_check *row)
{
    const struct json_value *obj = facts->obj[row->obj];
    return obj &&
           strcmp(json_get_str(json_get(obj, row->key)), row->want) == 0;
}

static bool syncdiag_ac_field_contains(
    const struct syncdiag_ac_facts *facts,
    const struct syncdiag_ac_check *row)
{
    const struct json_value *obj = facts->obj[row->obj];
    return obj &&
           strstr(json_get_str(json_get(obj, row->key)), row->want) != NULL;
}

static bool syncdiag_ac_probe_equals(
    const struct syncdiag_ac_facts *facts,
    const struct syncdiag_ac_check *row)
{
    (void)facts;
    return strcmp(agent_contract_probe_params_json(row->key), row->want) == 0;
}

static bool syncdiag_ac_probe_contains(
    const struct syncdiag_ac_facts *facts,
    const struct syncdiag_ac_check *row)
{
    (void)facts;
    return strstr(agent_contract_probe_params_json(row->key), row->want) !=
           NULL;
}

static bool syncdiag_ac_schema_listed(
    const struct syncdiag_ac_facts *facts,
    const struct syncdiag_ac_check *row)
{
    return find_object_with_str(facts->schemas, "schema", row->want) != NULL;
}

static bool syncdiag_ac_transport_matches(
    const struct syncdiag_ac_facts *facts,
    const struct syncdiag_ac_check *row)
{
    return json_array_has_substr(facts->transports, row->want) == row->present;
}

static const struct syncdiag_ac_step k_syncdiag_ac_steps[] = {
    { syncdiag_ac_doc_is_object,
      { SYNCDIAG_AC_CONTRACTS, NULL, NULL, 0, NULL, false } },
    { syncdiag_ac_field_equals,
      { SYNCDIAG_AC_CONTRACTS, "schema", "zcl.agent_contracts.v2",
        0, NULL, false } },
    { syncdiag_ac_list_is_array,
      { SYNCDIAG_AC_LIST, NULL, NULL, 0, NULL, false } },
    { syncdiag_ac_int_at_least,
      { SYNCDIAG_AC_SUMMARY, "contract_count", NULL, 20, NULL, false } },
    { syncdiag_ac_int_at_least,
      { SYNCDIAG_AC_SUMMARY, "native_declared_count", NULL, 20, NULL, false } },
    { syncdiag_ac_field_equals,
      { SYNCDIAG_AC_SUMMARY, "registry_source",
        "agent_contracts.def + agent_contract_registry.c", 0, NULL, false } },
    { syncdiag_ac_field_equals,
      { SYNCDIAG_AC_SUMMARY, "schema_registry_source",
        "agent_contract_schema_registry.c", 0, NULL, false } },
    { syncdiag_ac_field_equals,
      { SYNCDIAG_AC_SUMMARY, "review_registry_source",
        "agent_contract_review_registry.c", 0, NULL, false } },
    { syncdiag_ac_int_equals_count,
      { SYNCDIAG_AC_SUMMARY, "schema_surface_count", NULL, 0,
        agent_contract_schema_surface_count, false } },
    { syncdiag_ac_int_equals_count,
      { SYNCDIAG_AC_SUMMARY, "review_surface_count", NULL, 0,
        agent_contract_review_surface_total_count, false } },
    { syncdiag_ac_count_at_least,
      { 0, NULL, NULL, 18, agent_contract_schema_surface_count, false } },
    { syncdiag_ac_count_at_least,
      { 0, NULL, NULL, 5, agent_contract_review_surface_total_count, false } },
    { syncdiag_ac_field_equals,
      { SYNCDIAG_AC_AGENTOPS, "schema", "zcl.agent_ops.v2", 0, NULL, false } },
    { syncdiag_ac_field_equals,
      { SYNCDIAG_AC_AGENTOPS, "native", "z23 agentops", 0, NULL, false } },
    { syncdiag_ac_field_equals,
      { SYNCDIAG_AC_AGENTOPS, "api_cli_field", "ops_command",
        0, NULL, false } },
    { syncdiag_ac_field_equals,
      { SYNCDIAG_AC_AGENTOPS, "ops_surface", "direct", 0, NULL, false } },
    { syncdiag_ac_int_equals,
      { SYNCDIAG_AC_AGENTOPS, "ops_rank", NULL, 1, NULL, false } },
    { syncdiag_ac_field_equals,
      { SYNCDIAG_AC_AGENTOPS, "ops_name", "no_jq_contract",
        0, NULL, false } },
    { syncdiag_ac_field_equals,
      { SYNCDIAG_AC_AGENTOPS, "ops_purpose",
        "compact top-level fields for common agent decisions",
        0, NULL, false } },
    { syncdiag_ac_field_equals,
      { SYNCDIAG_AC_AGENTDEVSTATUS, "schema", "zcl.agent_dev_status.v2",
        0, NULL, false } },
    { syncdiag_ac_field_equals,
      { SYNCDIAG_AC_AGENTDEVSTATUS, "native", "z23 agentdevstatus",
        0, NULL, false } },
    { syncdiag_ac_field_equals,
      { SYNCDIAG_AC_AGENTDEVSTATUS, "api_cli_field", "dev_status_command",
        0, NULL, false } },
    { syncdiag_ac_field_equals,
      { SYNCDIAG_AC_AGENTDEVSTATUS, "ops_surface", "direct",
        0, NULL, false } },
    { syncdiag_ac_status_is_absent,
      { SYNCDIAG_AC_STATUS, NULL, NULL, 0, NULL, false } },
    { syncdiag_ac_field_equals,
      { SYNCDIAG_AC_DIAGNOSE, "schema", "zcl.agent_diagnose.v2",
        0, NULL, false } },
    { syncdiag_ac_field_equals,
      { SYNCDIAG_AC_API, "api_cli_field", "api_command", 0, NULL, false } },
    { syncdiag_ac_field_equals,
      { SYNCDIAG_AC_APP_PROTOCOLS, "schema",
        "zcl.application_protocols.index.v2", 0, NULL, false } },
    { syncdiag_ac_field_equals,
      { SYNCDIAG_AC_APP_PROTOCOLS, "native", "z23 appprotocols",
        0, NULL, false } },
    { syncdiag_ac_field_equals,
      { SYNCDIAG_AC_APP_PROTOCOLS, "rest", "GET /api/v1/protocols",
        0, NULL, false } },
    { syncdiag_ac_field_equals,
      { SYNCDIAG_AC_APP_PROTOCOLS, "api_cli_field", "app_protocols_command",
        0, NULL, false } },
    { syncdiag_ac_field_equals,
      { SYNCDIAG_AC_SERVICE_CATALOG, "schema", "zcl.service_catalog.v2",
        0, NULL, false } },
    { syncdiag_ac_field_equals,
      { SYNCDIAG_AC_SERVICE_CATALOG, "native", "z23 servicecatalog",
        0, NULL, false } },
    { syncdiag_ac_field_equals,
      { SYNCDIAG_AC_SERVICE_CATALOG, "rest", "GET /api/v1/service-catalog",
        0, NULL, false } },
    { syncdiag_ac_field_equals,
      { SYNCDIAG_AC_SERVICE_CATALOG, "api_cli_field",
        "service_catalog_command", 0, NULL, false } },
    { syncdiag_ac_field_equals,
      { SYNCDIAG_AC_SERVICE_OPERATIONS, "schema",
        "zcl.service_operations.index.v2", 0, NULL, false } },
    { syncdiag_ac_field_equals,
      { SYNCDIAG_AC_SERVICE_OPERATIONS, "native",
        "z23 serviceoperations [operation_id|key=value...]",
        0, NULL, false } },
    { syncdiag_ac_field_equals,
      { SYNCDIAG_AC_SERVICE_OPERATIONS, "rest",
        "GET /api/v1/service-operations", 0, NULL, false } },
    { syncdiag_ac_field_equals,
      { SYNCDIAG_AC_SERVICE_OPERATIONS, "api_cli_field",
        "service_operations_command", 0, NULL, false } },
    { syncdiag_ac_field_equals,
      { SYNCDIAG_AC_DUMPSTATE, "native", "z23 dumpstate <subsystem> [key]",
        0, NULL, false } },
    { syncdiag_ac_field_equals,
      { SYNCDIAG_AC_DUMPSTATE, "ops_name", "state_drilldown",
        0, NULL, false } },
    { syncdiag_ac_field_equals,
      { SYNCDIAG_AC_GETNODELOG, "native", "z23 getnodelog <pattern>",
        0, NULL, false } },
    { syncdiag_ac_field_equals,
      { SYNCDIAG_AC_DBQUERY, "schema", "zcl.sql_result.v1",
        0, NULL, false } },
    { syncdiag_ac_field_equals,
      { SYNCDIAG_AC_DBQUERY, "native", "z23 dbquery <SELECT>",
        0, NULL, false } },
    { syncdiag_ac_field_contains,
      { SYNCDIAG_AC_DBQUERY, "probe_params_json", "sqlite_master",
        0, NULL, false } },
    { syncdiag_ac_probe_equals,
      { 0, "agent", "[]", 0, NULL, false } },
    { syncdiag_ac_probe_contains,
      { 0, "dbquery", "sqlite_master", 0, NULL, false } },
    { syncdiag_ac_field_equals,
      { SYNCDIAG_AC_EVENTLOG, "schema", "zcl.event_log.v1",
        0, NULL, false } },
    { syncdiag_ac_field_equals,
      { SYNCDIAG_AC_EVENTLOG, "native", "z23 eventlog <count>",
        0, NULL, false } },
    { syncdiag_ac_field_equals,
      { SYNCDIAG_AC_EVENTLOG, "probe_params_json", "[1]", 0, NULL, false } },
    { syncdiag_ac_probe_equals,
      { 0, "eventlog", "[1]", 0, NULL, false } },
    { syncdiag_ac_field_equals,
      { SYNCDIAG_AC_HEALTHCHECK, "schema", "zcl.healthcheck.v1",
        0, NULL, false } },
    { syncdiag_ac_field_equals,
      { SYNCDIAG_AC_HEALTHCHECK, "api_cli_field", "drilldown_command",
        0, NULL, false } },
    { syncdiag_ac_field_equals,
      { SYNCDIAG_AC_MILESTONE, "rest", "GET /api/v1/milestone",
        0, NULL, false } },
    { syncdiag_ac_field_equals,
      { SYNCDIAG_AC_REFOLD, "rest", "GET /api/v1/refold", 0, NULL, false } },
    { syncdiag_ac_field_equals,
      { SYNCDIAG_AC_PROOF_BUNDLE, "schema", "zcl.operator_proof_bundle.v2",
        0, NULL, false } },
    { syncdiag_ac_field_equals,
      { SYNCDIAG_AC_PROOF_BUNDLE, "native",
        "z23 proofbundle [anchor_datadir]", 0, NULL, false } },
    { syncdiag_ac_field_equals,
      { SYNCDIAG_AC_PROOF_BUNDLE, "api_cli_field", "proof_bundle_command",
        0, NULL, false } },
    { syncdiag_ac_field_equals,
      { SYNCDIAG_AC_PEERINCIDENTS, "schema", "zcl.peer_incidents.v2",
        0, NULL, false } },
    { syncdiag_ac_field_equals,
      { SYNCDIAG_AC_PEERINCIDENTS, "native", "z23 peerincidents",
        0, NULL, false } },
    { syncdiag_ac_field_equals,
      { SYNCDIAG_AC_PEERINCIDENTS, "api_cli_field", "peer_incidents_command",
        0, NULL, false } },
    { syncdiag_ac_field_equals,
      { SYNCDIAG_AC_PEERINCIDENTS, "ops_name", "peer_incidents",
        0, NULL, false } },
    { syncdiag_ac_schema_listed,
      { 0, NULL, "zcl.agent_build.v2", 0, NULL, false } },
    { syncdiag_ac_schema_listed,
      { 0, NULL, "zcl.agent_dev_status.v2", 0, NULL, false } },
    { syncdiag_ac_schema_listed,
      { 0, NULL, "zcl.mvp_operator_proofs.v1", 0, NULL, false } },
    { syncdiag_ac_schema_listed,
      { 0, NULL, "zcl.peer_incidents.v2", 0, NULL, false } },
    { syncdiag_ac_schema_listed,
      { 0, NULL, "zcl.background_quality_runtime.v1", 0, NULL, false } },
    { syncdiag_ac_schema_listed,
      { 0, NULL, "zcl.agent_readiness.v1", 0, NULL, false } },
    { syncdiag_ac_schema_listed,
      { 0, NULL, "zcl.runtime_build.v2", 0, NULL, false } },
    { syncdiag_ac_schema_listed,
      { 0, NULL, "zcl.agent_runtime_availability.v3", 0, NULL, false } },
    { syncdiag_ac_schema_listed,
      { 0, NULL, "zcl.operator_latch.v2", 0, NULL, false } },
    { syncdiag_ac_schema_listed,
      { 0, NULL, "zcl.service_catalog.v2", 0, NULL, false } },
    { syncdiag_ac_schema_listed,
      { 0, NULL, "zcl.service_operations.index.v2", 0, NULL, false } },
    { syncdiag_ac_schema_listed,
      { 0, NULL, "zcl.service_operation.v2", 0, NULL, false } },
    { syncdiag_ac_schema_listed,
      { 0, NULL, "zcl.service_contract.v2", 0, NULL, false } },
    { syncdiag_ac_schema_listed,
      { 0, NULL, "zcl.condition_engine_summary.v2", 0, NULL, false } },
    { syncdiag_ac_schema_listed,
      { 0, NULL, "zcl.agent_interface.v2", 0, NULL, false } },
    { syncdiag_ac_schema_listed,
      { 0, NULL, "zcl.agent_ops.v2", 0, NULL, false } },
    { syncdiag_ac_schema_listed,
      { 0, NULL, "zcl.agent_diagnose.v2", 0, NULL, false } },
    { syncdiag_ac_schema_listed,
      { 0, NULL, "zcl.timeline.v2", 0, NULL, false } },
    { syncdiag_ac_schema_listed,
      { 0, NULL, "zcl.state_catalog.v2", 0, NULL, false } },
    { syncdiag_ac_schema_listed,
      { 0, NULL, "subsystem-specific diagnostic JSON", 0, NULL, false } },
    { syncdiag_ac_schema_listed,
      { 0, NULL, "zcl.node_log.v1", 0, NULL, false } },
    { syncdiag_ac_schema_listed,
      { 0, NULL, "zcl.sql_result.v1", 0, NULL, false } },
    { syncdiag_ac_schema_listed,
      { 0, NULL, "zcl.event_log.v1", 0, NULL, false } },
    { syncdiag_ac_schema_listed,
      { 0, NULL, "zcl.healthcheck.v1", 0, NULL, false } },
    { syncdiag_ac_schema_listed,
      { 0, NULL, "zcl.milestone_status.v2", 0, NULL, false } },
    { syncdiag_ac_schema_listed,
      { 0, NULL, "zcl.refold_status.v2", 0, NULL, false } },
    { syncdiag_ac_schema_listed,
      { 0, NULL, "zcl.operator_proof_bundle.v2", 0, NULL, false } },
    { syncdiag_ac_schema_listed,
      { 0, NULL, "zcl.agent_lanes.v2", 0, NULL, false } },
    { syncdiag_ac_schema_listed,
      { 0, NULL, "zcl.agent_liveness.v2", 0, NULL, false } },
    { syncdiag_ac_schema_listed,
      { 0, NULL, "zcl.agent_runtime_services.v1", 0, NULL, false } },
    { syncdiag_ac_schema_listed,
      { 0, NULL, "zcl.agent_capability.v2", 0, NULL, false } },
    { syncdiag_ac_schema_listed,
      { 0, NULL, "zcl.agent_machine_contract.v2", 0, NULL, false } },
    { syncdiag_ac_schema_listed,
      { 0, NULL, "zcl.agent_deploy_guard.v1", 0, NULL, false } },
    { syncdiag_ac_schema_listed,
      { 0, NULL, "zcl.operator_lane.v1", 0, NULL, false } },
    { syncdiag_ac_schema_listed,
      { 0, NULL, "zcl.operator_deployment_safety.v1", 0, NULL, false } },
    { syncdiag_ac_transport_matches,
      { 0, NULL, "z23 agentbuild", 0, NULL, true } },
    { syncdiag_ac_transport_matches,
      { 0, NULL, "z23 agentdevstatus", 0, NULL, true } },
    { syncdiag_ac_transport_matches,
      { 0, NULL, "z23 agentops", 0, NULL, true } },
    { syncdiag_ac_transport_matches,
      { 0, NULL, "z23 agentdiagnose", 0, NULL, true } },
    { syncdiag_ac_transport_matches,
      { 0, NULL, "z23 appprotocols", 0, NULL, true } },
    { syncdiag_ac_transport_matches,
      { 0, NULL, "z23 servicecatalog", 0, NULL, true } },
    { syncdiag_ac_transport_matches,
      { 0, NULL, "z23 serviceoperations", 0, NULL, true } },
    { syncdiag_ac_transport_matches,
      { 0, NULL, "z23 statecatalog", 0, NULL, true } },
    { syncdiag_ac_transport_matches,
      { 0, NULL, "z23 dumpstate", 0, NULL, true } },
    { syncdiag_ac_transport_matches,
      { 0, NULL, "z23 getnodelog", 0, NULL, true } },
    { syncdiag_ac_transport_matches,
      { 0, NULL, "z23 dbquery", 0, NULL, true } },
    { syncdiag_ac_transport_matches,
      { 0, NULL, "z23 eventlog", 0, NULL, true } },
    { syncdiag_ac_transport_matches,
      { 0, NULL, "z23 timeline", 0, NULL, true } },
    { syncdiag_ac_transport_matches,
      { 0, NULL, "z23 healthcheck", 0, NULL, true } },
    { syncdiag_ac_transport_matches,
      { 0, NULL, "z23 milestone", 0, NULL, true } },
    { syncdiag_ac_transport_matches,
      { 0, NULL, "z23 refold", 0, NULL, true } },
    { syncdiag_ac_transport_matches,
      { 0, NULL, "z23 proofbundle", 0, NULL, true } },
    { syncdiag_ac_transport_matches,
      { 0, NULL, "z23 status", 0, NULL, false } },
};

static bool syncdiag_ac_checks_pass(const struct syncdiag_ac_facts *facts)
{
    bool ok = true;
    for (size_t i = 0;
         i < sizeof k_syncdiag_ac_steps / sizeof k_syncdiag_ac_steps[0];
         i++)
        ok = ok && k_syncdiag_ac_steps[i].pred(
                       facts, &k_syncdiag_ac_steps[i].row);
    return ok;
}

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
        struct syncdiag_ac_facts facts = {
            .obj = {
                [SYNCDIAG_AC_CONTRACTS] = &contracts,
                [SYNCDIAG_AC_LIST] = contract_list,
                [SYNCDIAG_AC_SUMMARY] = contract_summary,
                [SYNCDIAG_AC_STATUS] = contract_status,
                [SYNCDIAG_AC_AGENTOPS] = contract_agentops,
                [SYNCDIAG_AC_AGENTDEVSTATUS] = contract_agentdevstatus,
                [SYNCDIAG_AC_DIAGNOSE] = contract_diagnose,
                [SYNCDIAG_AC_API] = contract_api,
                [SYNCDIAG_AC_APP_PROTOCOLS] = contract_app_protocols,
                [SYNCDIAG_AC_SERVICE_CATALOG] = contract_service_catalog,
                [SYNCDIAG_AC_SERVICE_OPERATIONS] = contract_service_operations,
                [SYNCDIAG_AC_DUMPSTATE] = contract_dumpstate,
                [SYNCDIAG_AC_GETNODELOG] = contract_getnodelog,
                [SYNCDIAG_AC_DBQUERY] = contract_dbquery,
                [SYNCDIAG_AC_EVENTLOG] = contract_eventlog,
                [SYNCDIAG_AC_HEALTHCHECK] = contract_healthcheck,
                [SYNCDIAG_AC_MILESTONE] = contract_milestone,
                [SYNCDIAG_AC_REFOLD] = contract_refold,
                [SYNCDIAG_AC_PROOF_BUNDLE] = contract_proof_bundle,
                [SYNCDIAG_AC_PEERINCIDENTS] = contract_peerincidents,
            },
            .schemas = schemas,
            .transports = transports,
        };
        ok = ok && syncdiag_ac_checks_pass(&facts);

        json_free(&params);
        json_free(&contracts);

        if (ok) printf("OK\n");
        else    { printf("FAIL\n"); failures++; }
    }

    return failures;
}
