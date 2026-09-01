/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Versioned AI/operator API contract registry. */

#include "controllers/agent_controller.h"
#include "controllers/strong_params.h"

#include "json/json.h"

#include <stdio.h>

static void contracts_push_str(struct json_value *arr, const char *s)
{
    struct json_value v;
    json_init(&v);
    json_set_str(&v, s ? s : "");
    json_push_back(arr, &v);
    json_free(&v);
}

static void contracts_push_schema(struct json_value *arr, const char *schema,
                                  const char *producer, const char *purpose)
{
    struct json_value obj;
    json_init(&obj);
    json_set_object(&obj);
    json_push_kv_str(&obj, "schema", schema);
    json_push_kv_str(&obj, "producer", producer);
    json_push_kv_str(&obj, "purpose", purpose);
    json_push_back(arr, &obj);
    json_free(&obj);
}

static void contracts_push_registry_schema(
    struct json_value *arr, const struct agent_contract *contract)
{
    if (!arr || !contract)
        return;
    char producer[320];
    if (contract->rest_route && contract->rest_route[0]) {
        snprintf(producer, sizeof(producer), "%s / %s",
                 contract->native_command ? contract->native_command : "",
                 contract->rest_route);
    } else {
        snprintf(producer, sizeof(producer), "%s",
                 contract->native_command ? contract->native_command : "");
    }
    contracts_push_schema(arr, contract->schema, producer,
                          contract->purpose);
}

static void contracts_push_agent_registry_schemas(struct json_value *arr)
{
    for (size_t i = 0; i < agent_contract_count(); i++) {
        const struct agent_contract *c = agent_contract_at(i);
        if (!c)
            continue;
        contracts_push_registry_schema(arr, c);
    }
}

bool rpc_agent_contracts(const struct json_value *params, bool help,
                         struct json_value *result)
{
    (void)params;
    RPC_HELP(help, result,
        "agentcontracts\n"
        "\nReturn the versioned AI/operator API contracts and their native\n"
        "and REST transport names.\n"
        "\nResult:\n"
        "  { \"schema\":\"zcl.agent_contracts.v2\", "
        "\"schemas\":[...] }\n");

    struct json_value contract_list, schemas, transports, rules;
    json_set_object(result);
    json_push_kv_str(result, "schema", "zcl.agent_contracts.v2");
    json_push_kv_str(result, "api_version", "v1");
    json_push_kv_str(result, "status", "ok");
    json_push_kv_str(result, "canonical_interface",
                     "native zclassic23 commands and REST reads");
    agent_push_contract_summary_json(result, "contract_summary");

    json_init(&contract_list);
    json_set_array(&contract_list);
    agent_push_contracts_json(&contract_list);
    json_push_kv(result, "contracts", &contract_list);
    json_free(&contract_list);

    json_init(&schemas);
    json_set_array(&schemas);
    contracts_push_agent_registry_schemas(&schemas);
    agent_push_contract_schema_surface_json(&schemas);
    json_push_kv(result, "schemas", &schemas);
    json_free(&schemas);

    json_init(&transports);
    json_set_array(&transports);
    agent_push_contract_transport_summary_json(&transports);
    json_push_kv(result, "transports", &transports);
    json_free(&transports);

    json_init(&rules);
    json_set_array(&rules);
    contracts_push_str(&rules, "Do not put new logic in shell wrappers.");
    contracts_push_str(&rules,
                       "Build JSON once in native services/controllers, then expose through native commands and REST.");
    contracts_push_str(&rules,
                       "Every new contract needs schema, docs, and focused tests.");
    contracts_push_str(&rules,
                       "No Python is required to consume the preferred agent API.");
    contracts_push_str(&rules,
                       "Automation must read deployment_safety before restarting a lane.");
    contracts_push_str(&rules,
                       "Consensus-risk paths require parity review and strict relevant tests.");
    json_push_kv(result, "design_rules", &rules);
    json_free(&rules);
    return true;
}
