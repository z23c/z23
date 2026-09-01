/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * api cases: the versioned discovery document, the application protocol catalog, and the sovereign service catalog and its operations.
 */

#include "test/syncdiag_rpc_fixture.h"

int syncdiag_cases_api_catalog(void)
{
    int failures = 0;

    printf("api: native RPC returns versioned discovery document... ");
    {
        struct rpc_table tbl;
        rpc_table_init(&tbl);
        register_event_rpc_commands(&tbl);
        if (rpc_is_in_warmup(NULL, 0))
            set_rpc_warmup_finished();

        struct json_value params;
        json_init(&params);
        json_set_array(&params);

        struct json_value result;
        json_init(&result);

        bool executed = rpc_table_execute(&tbl, "api", &params, &result);
        const struct json_value *resources = json_get(&result, "resources");
        const struct json_value *cli = json_get(&result, "cli");
        bool ok = executed && result.type == JSON_OBJ;
        ok = ok && strcmp(json_get_str(json_get(&result, "schema")),
                          "zcl.rest_index.v2") == 0;
        ok = ok && strcmp(json_get_str(json_get(&result, "api_version")),
                          "v1") == 0;
        ok = ok && strcmp(json_get_str(json_get(&result, "base_path")),
                          "/api/v1") == 0;
        ok = ok && strcmp(json_get_str(json_get(&result, "compat_base_path")),
                          "/api") == 0;
        ok = ok && strcmp(json_get_str(json_get(&result, "first_call")),
                          "/api/v1/agent") == 0;
        ok = ok && resources && resources->type == JSON_ARR &&
            json_size(resources) >= 4;
        ok = ok && cli && cli->type == JSON_OBJ &&
            strcmp(json_get_str(json_get(cli, "api_command")),
                   "z23 api") == 0;
        ok = ok && strcmp(json_get_str(json_get(cli,
                                                "app_protocols_command")),
                          "z23 appprotocols") == 0;
        ok = ok && strcmp(json_get_str(json_get(cli,
                                                "service_catalog_command")),
                          "z23 servicecatalog") == 0;
        ok = ok && strcmp(json_get_str(json_get(cli,
                                                "service_operations_command")),
                          "z23 serviceoperations [operation_id|key=value...]") == 0;
        ok = ok && strcmp(json_get_str(json_get(cli, "first_command")),
                          "z23 agent") == 0;
        ok = ok && strcmp(json_get_str(json_get(cli, "map_command")),
                          "z23 agentmap") == 0;
        ok = ok && strcmp(json_get_str(json_get(cli, "lanes_command")),
                          "z23 agentlanes") == 0;
        ok = ok && strcmp(json_get_str(json_get(cli, "impact_command")),
                          "z23 agentimpact <files...>") == 0;
        ok = ok && strcmp(json_get_str(json_get(cli, "contracts_command")),
                          "z23 agentcontracts") == 0;
        ok = ok && strcmp(json_get_str(json_get(cli, "build_command")),
                          "z23 agentbuild") == 0;
        ok = ok && strcmp(json_get_str(json_get(cli,
                                                "interface_command")),
                          "z23 agentinterface") == 0;
        ok = ok && strcmp(json_get_str(json_get(cli,
                                                "deploy_guard_command")),
                          "z23 agentdeployguard [action]") == 0;
        ok = ok && strcmp(json_get_str(json_get(cli, "drilldown_command")),
                          "z23 healthcheck") == 0;
        ok = ok && strcmp(json_get_str(json_get(cli, "milestone_command")),
                          "z23 milestone") == 0;
        ok = ok && strcmp(json_get_str(json_get(cli, "refold_command")),
                          "z23 refold") == 0;
        ok = ok && strcmp(json_get_str(json_get(cli,
                                                "peer_incidents_command")),
                          "z23 peerincidents") == 0;

        struct json_value alias;
        json_init(&alias);
        bool alias_executed = rpc_table_execute(&tbl, "apiindex",
                                                &params, &alias);
        ok = ok && alias_executed && alias.type == JSON_OBJ &&
            strcmp(json_get_str(json_get(&alias, "schema")),
                   "zcl.rest_index.v2") == 0;

        json_free(&alias);
        json_free(&params);
        json_free(&result);

        if (ok) printf("OK\n");
        else    { printf("FAIL\n"); failures++; }
    }

    printf("api: native RPC returns application protocol catalog... ");
    {
        struct rpc_table tbl;
        rpc_table_init(&tbl);
        register_event_rpc_commands(&tbl);
        if (rpc_is_in_warmup(NULL, 0))
            set_rpc_warmup_finished();

        struct json_value params;
        json_init(&params);
        json_set_array(&params);

        struct json_value result;
        json_init(&result);

        bool executed = rpc_table_execute(&tbl, "appprotocols",
                                          &params, &result);
        const struct json_value *protocols =
            json_get(&result, "protocols");
        const struct json_value *zlsp =
            find_object_with_str(protocols, "name", "zlsp");
        const struct json_value *zslp =
            find_object_with_str(protocols, "name", "zslp");
        const struct json_value *znam =
            find_object_with_str(protocols, "name", "znam");
        const struct json_value *market =
            find_object_with_str(protocols, "name", "market");
        const struct json_value *script_contracts =
            find_object_with_str(protocols, "name", "script_contracts");
        bool ok = executed && result.type == JSON_OBJ;
        ok = ok && strcmp(json_get_str(json_get(&result, "schema")),
                          "zcl.application_protocols.index.v2") == 0;
        ok = ok && strcmp(json_get_str(json_get(&result, "base_layer")),
                          "zclassic_l1") == 0;
        ok = ok && strcmp(json_get_str(json_get(&result,
                                                "service_layer")),
                          "zclassic23_application_layer") == 0;
        ok = ok && protocols && protocols->type == JSON_ARR &&
            json_get_int(json_get(&result, "protocol_count")) ==
            (int64_t)json_size(protocols);
        ok = ok && zlsp &&
            strcmp(json_get_str(json_get(zlsp, "status")),
                   "design") == 0;
        ok = ok && zlsp &&
            strcmp(json_get_str(json_get(zlsp, "family")),
                   "application_protocol_framework") == 0;
        ok = ok && zlsp &&
            json_array_has_str(json_get(zlsp, "crud_capabilities"),
                               "construct_transaction");
        ok = ok && zslp &&
            json_array_has_str(json_get(zslp, "crud_capabilities"),
                               "read_collection");
        ok = ok && zslp &&
            strcmp(json_get_str(json_get(zslp, "anchor_kind")),
                   "op_return") == 0;
        ok = ok && zslp &&
            json_array_has_str(json_get(zslp, "object_types"),
                               "token_genesis");
        ok = ok && znam &&
            json_array_has_str(json_get(znam, "ux_surfaces"),
                               "identity_profile");
        ok = ok && znam &&
            strstr(json_get_str(json_get(znam, "crypto_model")),
                   "owner_authority") != NULL;
        ok = ok && market &&
            json_array_has_str(json_get(market, "object_types"),
                               "signed_listing");
        ok = ok && market &&
            strstr(json_get_str(json_get(market, "privacy_model")),
                   "allowlist") != NULL;
        ok = ok && script_contracts &&
            strcmp(json_get_str(json_get(script_contracts, "anchor_kind")),
                   "standard_script") == 0;
        ok = ok && script_contracts &&
            strstr(json_get_str(json_get(script_contracts, "crypto_model")),
                   "legacy_valid_zclassic_script") != NULL;

        struct json_value alias;
        json_init(&alias);
        bool alias_executed = rpc_table_execute(&tbl, "protocols",
                                                &params, &alias);
        ok = ok && alias_executed &&
            strcmp(json_get_str(json_get(&alias, "schema")),
                   "zcl.application_protocols.index.v2") == 0;

        json_free(&alias);
        json_free(&params);
        json_free(&result);

        if (ok) printf("OK\n");
        else    { printf("FAIL\n"); failures++; }
    }

    printf("api: native RPC returns sovereign service catalog... ");
    {
        struct rpc_table tbl;
        rpc_table_init(&tbl);
        register_event_rpc_commands(&tbl);
        if (rpc_is_in_warmup(NULL, 0))
            set_rpc_warmup_finished();

        struct json_value params;
        json_init(&params);
        json_set_array(&params);

        struct json_value result;
        json_init(&result);

        bool executed = rpc_table_execute(&tbl, "servicecatalog",
                                          &params, &result);
        const struct json_value *services = json_get(&result, "services");
        const struct json_value *bootstrap =
            find_object_with_str(services, "name", "bootstrap");
        const struct json_value *names =
            find_object_with_str(services, "name", "znam_names");
        const struct json_value *onion =
            find_object_with_str(services, "name", "onion_directory");
        const struct json_value *contracts =
            find_object_with_str(services, "name", "script_contracts");
        bool ok = executed && result.type == JSON_OBJ;
        ok = ok && strcmp(json_get_str(json_get(&result, "schema")),
                          "zcl.service_catalog.v2") == 0;
        ok = ok && strcmp(json_get_str(json_get(&result, "base_layer")),
                          "zclassic_l1") == 0;
        const struct json_value *ux = json_get(&result, "sovereign_ux");
        ok = ok && ux &&
            strcmp(json_get_str(json_get(ux, "schema")),
                   "zcl.sovereign_ux_contract.v2") == 0;
        ok = ok && ux &&
            json_array_has_str(json_get(ux, "flow"),
                               "verify_service_records");
        ok = ok && ux &&
            json_array_has_str(json_get(ux, "primary_entities"),
                               "endpoint_record");
        ok = ok && services && services->type == JSON_ARR &&
            json_get_int(json_get(&result, "service_count")) ==
            (int64_t)json_size(services);
        ok = ok && bootstrap &&
            strcmp(json_get_str(json_get(bootstrap, "rest_collection")),
                   "/api/v1/bootstrap") == 0;
        ok = ok && bootstrap &&
            json_array_has_str(json_get(bootstrap, "transports"), "p2p");
        ok = ok && bootstrap &&
            json_array_has_str(json_get(bootstrap, "depends_on_services"),
                               "full_node");
        const struct json_value *bootstrap_status_op =
            find_object_with_str(json_get(bootstrap, "operations"),
                                 "operation", "read_bootstrap_status");
        ok = ok && names &&
            strcmp(json_get_str(json_get(names, "application_protocol")),
                   "znam") == 0;
        ok = ok && names &&
            json_array_has_str(json_get(names, "crud_capabilities"),
                               "construct_transaction");
        ok = ok && names &&
            strcmp(json_get_str(json_get(names, "read_model")),
                   "znam_projection_confirmed_chain_records") == 0;
        ok = ok && names &&
            strcmp(json_get_str(json_get(names, "write_model")),
                   "construct_znam_op_return_transactions") == 0;
        const struct json_value *name_register_op =
            find_object_with_str(json_get(names, "operations"), "operation",
                                 "construct_name_register");
        ok = ok && name_register_op &&
            strcmp(json_get_str(json_get(name_register_op, "rpc_method")),
                   "name_register") == 0;
        ok = ok && name_register_op &&
            json_get_bool(json_get(name_register_op, "destructive"));
        ok = ok && onion &&
            json_array_has_str(json_get(onion, "transports"), "onion");
        ok = ok && contracts &&
            strstr(json_get_str(json_get(contracts, "verified_by")),
                   "zclassic_script") != NULL;

        struct json_value alias;
        json_init(&alias);
        bool alias_executed = rpc_table_execute(&tbl, "service_catalog",
                                                &params, &alias);
        ok = ok && alias_executed &&
            strcmp(json_get_str(json_get(&alias, "schema")),
                   "zcl.service_catalog.v2") == 0;

        struct json_value one_params;
        json_init(&one_params);
        json_set_array(&one_params);
        struct json_value one_name;
        json_init(&one_name);
        json_set_str(&one_name, "bootstrap");
        json_push_back(&one_params, &one_name);
        json_free(&one_name);

        struct json_value one;
        json_init(&one);
        bool one_executed = rpc_table_execute(&tbl, "servicecatalog",
                                              &one_params, &one);
        ok = ok && one_executed &&
            strcmp(json_get_str(json_get(&one, "schema")),
                   "zcl.service_contract.v2") == 0;
        ok = ok && strcmp(json_get_str(json_get(&one, "name")),
                          "bootstrap") == 0;
        ok = ok && strcmp(json_get_str(json_get(&one, "self_route")),
                          "/api/v1/service-catalog/bootstrap") == 0;
        ok = ok && json_array_has_str(json_get(&one, "transports"), "p2p");
        ok = ok && json_array_has_str(json_get(&one,
                             "depends_on_services"), "full_node");
        ok = ok && strcmp(json_get_str(json_get(&one, "read_model")),
                          "network_bootstrap_status_and_peer_projection") == 0;
        bootstrap_status_op = find_object_with_str(json_get(&one,
                             "operations"), "operation",
                             "read_bootstrap_status");
        ok = ok && bootstrap_status_op &&
            strcmp(json_get_str(json_get(bootstrap_status_op, "rpc_method")),
                   "bootstrapstatus") == 0;

        struct json_value bad_params;
        json_init(&bad_params);
        json_set_array(&bad_params);
        struct json_value bad_name;
        json_init(&bad_name);
        json_set_str(&bad_name, "not_real");
        json_push_back(&bad_params, &bad_name);
        json_free(&bad_name);

        struct json_value bad;
        json_init(&bad);
        bool bad_executed = rpc_table_execute(&tbl, "servicecatalog",
                                              &bad_params, &bad);
        ok = ok && bad_executed &&
            strcmp(json_get_str(json_get(&bad, "schema")),
                   "zcl.service_catalog_error.v1") == 0;
        ok = ok && json_array_has_str(json_get(&bad, "valid_services"),
                                      "bootstrap");

        json_free(&bad);
        json_free(&bad_params);
        json_free(&one);
        json_free(&one_params);
        json_free(&alias);
        json_free(&params);
        json_free(&result);

        if (ok) printf("OK\n");
        else    { printf("FAIL\n"); failures++; }
    }

    printf("api: native RPC returns sovereign service operations... ");
    {
        struct rpc_table tbl;
        rpc_table_init(&tbl);
        register_event_rpc_commands(&tbl);
        if (rpc_is_in_warmup(NULL, 0))
            set_rpc_warmup_finished();

        struct json_value params;
        json_init(&params);
        json_set_array(&params);

        struct json_value result;
        json_init(&result);

        bool executed = rpc_table_execute(&tbl, "serviceoperations",
                                          &params, &result);
        const struct json_value *summary = json_get(&result, "summary");
        const struct json_value *operations = json_get(&result, "operations");
        const struct json_value *bootstrap_op =
            find_object_with_str(operations, "operation_id",
                                 "bootstrap.read_bootstrap_status");
        const struct json_value *name_op =
            find_object_with_str(operations, "operation_id",
                                 "znam_names.resolve_name");
        bool ok = executed && result.type == JSON_OBJ;
        ok = ok && strcmp(json_get_str(json_get(&result, "schema")),
                          "zcl.service_operations.index.v2") == 0;
        ok = ok && strcmp(json_get_str(json_get(&result, "catalog_route")),
                          "/api/v1/service-catalog") == 0;
        ok = ok && strcmp(json_get_str(json_get(&result,
                                                "member_route")),
                          "/api/v1/service-operations/{operation_id}") == 0;
        ok = ok && summary && json_get_int(json_get(summary,
                                                    "operation_count")) >= 20;
        ok = ok && operations && operations->type == JSON_ARR &&
            json_get_int(json_get(&result, "operation_count")) ==
            (int64_t)json_size(operations);
        ok = ok && bootstrap_op &&
            strcmp(json_get_str(json_get(bootstrap_op, "rest_route")),
                   "/api/v1/bootstrap") == 0;
        ok = ok && bootstrap_op &&
            strcmp(json_get_str(json_get(bootstrap_op,
                                         "agent_preferred_interface")),
                   "rest") == 0;
        ok = ok && name_op &&
            strcmp(json_get_str(json_get(name_op, "crud_capability")),
                   "read_item") == 0;
        ok = ok && name_op &&
            strcmp(json_get_str(json_get(name_op, "authority")),
                   "confirmed_chain_projection") == 0;

        struct json_value alias;
        json_init(&alias);
        bool alias_executed = rpc_table_execute(&tbl, "service_operations",
                                                &params, &alias);
        ok = ok && alias_executed &&
            strcmp(json_get_str(json_get(&alias, "schema")),
                   "zcl.service_operations.index.v2") == 0;

        struct json_value one_params;
        json_init(&one_params);
        json_set_array(&one_params);
        struct json_value operation_id;
        json_init(&operation_id);
        json_set_str(&operation_id, "bootstrap.read_bootstrap_status");
        json_push_back(&one_params, &operation_id);
        json_free(&operation_id);

        struct json_value one;
        json_init(&one);
        bool one_executed = rpc_table_execute(&tbl, "serviceoperation",
                                              &one_params, &one);
        ok = ok && one_executed &&
            strcmp(json_get_str(json_get(&one, "schema")),
                   "zcl.service_operation.v2") == 0;
        ok = ok &&
            strcmp(json_get_str(json_get(&one, "operation_id")),
                   "bootstrap.read_bootstrap_status") == 0;
        ok = ok && strcmp(json_get_str(json_get(&one, "self_route")),
                          "/api/v1/service-operations/"
                          "bootstrap.read_bootstrap_status") == 0;
        ok = ok && strcmp(json_get_str(json_get(&one,
                                                "write_safety")),
                          "public_read_only") == 0;

        struct json_value bad_params;
        json_init(&bad_params);
        json_set_array(&bad_params);
        struct json_value bad_id;
        json_init(&bad_id);
        json_set_str(&bad_id, "not_real.nope");
        json_push_back(&bad_params, &bad_id);
        json_free(&bad_id);

        struct json_value bad;
        json_init(&bad);
        bool bad_executed = rpc_table_execute(&tbl, "serviceoperations",
                                              &bad_params, &bad);
        ok = ok && bad_executed &&
            strcmp(json_get_str(json_get(&bad, "schema")),
                   "zcl.service_operation_error.v1") == 0;
        ok = ok && strcmp(json_get_str(json_get(&bad, "error")),
                          "operation_not_found") == 0;
        ok = ok && strcmp(json_get_str(json_get(&bad,
                                                "operation_collection_route")),
                          "/api/v1/service-operations") == 0;

        struct json_value filtered_params;
        json_init(&filtered_params);
        json_set_array(&filtered_params);
        struct json_value filter_arg;
        json_init(&filter_arg);
        json_set_str(&filter_arg, "service=bootstrap");
        json_push_back(&filtered_params, &filter_arg);
        json_set_str(&filter_arg, "write_safety=public_read_only");
        json_push_back(&filtered_params, &filter_arg);
        json_free(&filter_arg);

        struct json_value filtered;
        json_init(&filtered);
        bool filtered_executed =
            rpc_table_execute(&tbl, "serviceoperations",
                              &filtered_params, &filtered);
        const struct json_value *filtered_filters =
            json_get(&filtered, "filters");
        const struct json_value *filtered_summary =
            json_get(&filtered, "summary");
        const struct json_value *filtered_ops =
            json_get(&filtered, "operations");
        ok = ok && filtered_executed &&
            strcmp(json_get_str(json_get(&filtered, "schema")),
                   "zcl.service_operations.index.v2") == 0;
        ok = ok && filtered_filters &&
            json_get_bool(json_get(filtered_filters, "active"));
        ok = ok && filtered_filters &&
            strcmp(json_get_str(json_get(filtered_filters, "service")),
                   "bootstrap") == 0;
        ok = ok && filtered_filters &&
            strcmp(json_get_str(json_get(filtered_filters,
                                         "write_safety")),
                   "public_read_only") == 0;
        ok = ok && filtered_summary &&
            json_get_int(json_get(filtered_summary,
                                  "operation_count")) == 2;
        ok = ok && filtered_ops && filtered_ops->type == JSON_ARR &&
            json_size(filtered_ops) == 2;
        ok = ok && find_object_with_str(filtered_ops, "operation_id",
                                        "bootstrap.read_bootstrap_status");
        ok = ok && find_object_with_str(filtered_ops, "operation_id",
                                        "bootstrap.list_peer_projection");

        json_free(&bad);
        json_free(&bad_params);
        json_free(&filtered);
        json_free(&filtered_params);
        json_free(&one);
        json_free(&one_params);
        json_free(&alias);
        json_free(&params);
        json_free(&result);

        if (ok) printf("OK\n");
        else    { printf("FAIL\n"); failures++; }
    }


    return failures;
}
