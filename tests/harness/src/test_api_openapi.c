/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * API OpenAPI document: the generated spec must stay derived from the route
 * contract table rather than hand-maintained.
 */

#include "test/api_test_fixtures.h"

int api_openapi_focused_tests(void)
{
    int failures = 0;

    printf("api: OpenAPI document is generated from route contracts... ");
    {
        static uint8_t openapi_resp[262144];
        size_t n = api_handle_request("GET", "/api/v1/openapi", NULL, 0,
                                      openapi_resp, sizeof(openapi_resp));
        const char *body = api_test_body(openapi_resp, n,
                                         sizeof(openapi_resp));
        struct json_value root;
        json_init(&root);
        bool ok = n > 0 && body && json_read(&root, body, strlen(body));
        ok = ok && strcmp(json_get_str(json_get(&root, "schema")),
                          "zcl.openapi.v1") == 0;
        ok = ok && strcmp(json_get_str(json_get(&root, "openapi")),
                          "3.1.0") == 0;
        ok = ok && strcmp(json_get_str(json_get(json_get(&root, "info"),
                                                "version")),
                          "v1") == 0;
        ok = ok && strcmp(json_get_str(json_get(json_at(json_get(&root,
                                      "servers"), 0), "url")),
                          "/api/v1") == 0;
        ok = ok && strcmp(json_get_str(json_get(json_get(&root,
                          "x-zcl-crypto-policy"),
                          "service_auth_primary_digest")),
                          "SHA3-512") == 0;
        ok = ok && strcmp(json_get_str(json_get(json_get(&root,
                          "x-zcl-crypto-policy"),
                          "service_auth_secondary_digest")),
                          "GOST R 34.11-2012-512") == 0;
        const struct json_value *openapi_layer =
            json_get(&root, "x-zcl-layer-model");
        ok = ok && openapi_layer &&
             strcmp(json_get_str(json_get(openapi_layer, "schema")),
                    "zcl.rest_layer_model.v1") == 0;
        ok = ok && openapi_layer &&
             strcmp(json_get_str(json_get(openapi_layer, "base_layer")),
                    "zclassic_l1") == 0;
        ok = ok && openapi_layer &&
             strcmp(json_get_str(json_get(openapi_layer,
                                          "application_protocol_umbrella")),
                    "zlsp") == 0;
        ok = ok && openapi_layer &&
             api_test_find_named(json_get(openapi_layer,
                                          "application_protocols"),
                                 "zlsp") != NULL;
        ok = ok && openapi_layer &&
             api_test_find_named(json_get(openapi_layer,
                                          "application_protocols"),
                                 "zslp") != NULL;
        ok = ok && openapi_layer &&
             api_test_find_named(json_get(openapi_layer,
                                          "application_protocols"),
                                 "znam") != NULL;
        ok = ok && openapi_layer &&
             api_test_find_named(json_get(openapi_layer,
                                          "application_protocols"),
                                 "script_contracts") != NULL;
        ok = ok && json_get_int(json_get(&root,
                          "x-route-contract-count")) ==
                          (int64_t)api_route_contract_count();

        const struct json_value *hodl =
            api_test_openapi_get(&root, "/api/v1/hodl");
        const struct json_value *bootstrap =
            api_test_openapi_get(&root, "/api/v1/bootstrap");
        const struct json_value *legacy_bootstrap =
            api_test_openapi_get(&root, "/api/v1/bootstrapstatus");
        const struct json_value *wallet =
            api_test_openapi_get(&root, "/api/v1/wallet");
        const struct json_value *events =
            api_test_openapi_get(&root, "/api/v1/events");
        const struct json_value *zslp =
            api_test_openapi_get(&root, "/api/v1/zslp/tokens");
        const struct json_value *protocols =
            api_test_openapi_get(&root, "/api/v1/protocols");
        const struct json_value *service_catalog =
            api_test_openapi_get(&root, "/api/v1/service-catalog");
        const struct json_value *service_operations =
            api_test_openapi_get(&root, "/api/v1/service-operations");
        const struct json_value *service_catalog_show =
            api_test_openapi_get(&root, "/api/v1/service-catalog/{service}");
        const struct json_value *service_operation_show =
            api_test_openapi_get(&root,
                                 "/api/v1/service-operations/{operation_id}");
        const struct json_value *protocol_show =
            api_test_openapi_get(&root, "/api/v1/protocols/{name}");
        const struct json_value *names =
            api_test_openapi_get(&root, "/api/v1/names/{name}");
        const struct json_value *names_services =
            api_test_openapi_get(&root,
                                 "/api/v1/names/{name}/services");
        const struct json_value *swap_chains =
            api_test_openapi_get(&root, "/api/v1/swaps/chains");
        const struct json_value *block_show =
            api_test_openapi_get(&root, "/api/v1/blocks/{height_or_hash}");
        const struct json_value *legacy_name =
            api_test_openapi_get(&root, "/api/v1/name/{name}");
        const struct json_value *supply =
            api_test_openapi_get(&root, "/api/v1/supply");
        const struct json_value *openapi =
            api_test_openapi_get(&root, "/api/v1/openapi");
        const struct json_value *health_openapi =
            api_test_openapi_get(&root, "/api/v1/health");

        ok = ok && health_openapi &&
             strcmp(json_get_str(json_get(health_openapi,
                    "x-zcl-command-path")), "ops.health") == 0;

        ok = ok && hodl &&
             strcmp(json_get_str(json_get(hodl, "x-resource")),
                    "hodl") == 0;
        ok = ok && hodl &&
             strcmp(json_get_str(json_get(hodl, "x-crud-operation")),
                    "read") == 0;
        ok = ok && hodl &&
             strcmp(json_get_str(json_get(hodl, "x-resource-scope")),
                    "singleton") == 0;
        ok = ok && hodl &&
             strcmp(json_get_str(json_get(hodl, "x-crud-name")),
                    "read_singleton") == 0;
        ok = ok && hodl &&
             strcmp(json_get_str(json_get(hodl, "x-response-schema")),
                    "zcl.hodl_wave.v1") == 0;
        ok = ok && bootstrap &&
             strcmp(json_get_str(json_get(bootstrap, "x-resource")),
                    "bootstrap") == 0;
        ok = ok && bootstrap &&
             strcmp(json_get_str(json_get(bootstrap, "x-crud-name")),
                    "read_singleton") == 0;
        ok = ok && bootstrap &&
             strcmp(json_get_str(json_get(bootstrap, "x-response-schema")),
                    "zcl.bootstrap_status.v1") == 0;
        ok = ok && bootstrap &&
             strcmp(json_get_str(json_get(json_get(bootstrap,
                    "x-zcl-telemetry"), "freshness_source")),
                    "network_bootstrap") == 0;
        const struct json_value *bootstrap_openapi_binding =
            bootstrap ? json_get(bootstrap, "x-zcl-service-binding") : NULL;
        ok = ok && bootstrap_openapi_binding &&
             strcmp(json_get_str(json_get(bootstrap_openapi_binding,
                                          "operation_id")),
                    "bootstrap.read_bootstrap_status") == 0;
        ok = ok && bootstrap_openapi_binding &&
             strcmp(json_get_str(json_get(bootstrap_openapi_binding,
                                          "service")),
                    "bootstrap") == 0;
        ok = ok && legacy_bootstrap &&
             strcmp(json_get_str(json_get(legacy_bootstrap,
                                          "x-legacy-alias-of")),
                    "/api/v1/bootstrap") == 0;
        ok = ok && hodl &&
             strcmp(json_get_str(json_get(hodl, "x-auth-policy")),
                    "public") == 0;
        ok = ok && hodl &&
             strcmp(json_get_str(json_get(json_get(hodl,
                    "x-zcl-telemetry"), "counter")),
                    "zcl_api_requests_total") == 0;
        ok = ok && hodl &&
             strcmp(json_get_str(json_get(json_get(hodl,
                    "x-zcl-crypto-policy"), "service_auth_primary_digest")),
                    "SHA3-512") == 0;
        ok = ok && hodl &&
             strcmp(json_get_str(json_get(json_get(hodl,
                    "x-zcl-crypto-policy"),
                    "service_auth_secondary_digest")),
                    "GOST R 34.11-2012-512") == 0;
        const struct json_value *hodl_200 =
            json_get(json_get(hodl, "responses"), "200");
        ok = ok && strcmp(json_get_str(json_get(json_get(json_get(
            json_get(hodl_200, "content"), "engine/application/json"), "schema"),
            "$ref")), "#/components/schemas/zcl.hodl_wave.v1") == 0;

        ok = ok && wallet && json_get_bool(json_get(wallet, "x-private"));
        ok = ok && wallet && json_size(json_get(wallet, "security")) == 1;
        ok = ok && events &&
             api_test_openapi_has_param(events, "limit", "query");
        ok = ok && events &&
             api_test_openapi_has_param(events, "type", "query");
        ok = ok && events &&
             strcmp(json_get_str(json_get(events, "x-crud-name")),
                    "read_collection") == 0;
        ok = ok && zslp &&
             strcmp(json_get_str(json_get(zslp,
                    "x-zcl-application-protocol")), "zslp") == 0;
        ok = ok && zslp &&
             strcmp(json_get_str(json_get(zslp, "x-zcl-base-layer")),
                    "zclassic_l1") == 0;
        ok = ok && zslp &&
             strcmp(json_get_str(json_get(zslp, "x-zcl-layer")),
                    "zclassic23_application_layer") == 0;
        ok = ok && zslp &&
             strcmp(json_get_str(json_get(zslp,
                    "x-zcl-protocol-family")), "token") == 0;
        ok = ok && zslp &&
             strcmp(json_get_str(json_get(zslp,
                    "x-zcl-protocol-anchor-kind")), "op_return") == 0;
        ok = ok && zslp &&
             api_test_array_has_str(json_get(zslp, "x-zcl-protocol-crud"),
                                    "read_collection");
        ok = ok && zslp &&
             api_test_array_has_str(json_get(zslp,
                    "x-zcl-protocol-object-types"), "token_genesis");
        ok = ok && zslp &&
             strcmp(json_get_str(json_get(zslp,
                    "x-zcl-protocol-construction-status")),
                    "transaction_builders_active") == 0;
        ok = ok && zslp &&
             strcmp(json_get_str(json_get(zslp,
                    "x-zcl-mutation-authority")),
                    "operator_wallet_transaction") == 0;
        ok = ok && protocols &&
             strcmp(json_get_str(json_get(protocols, "x-response-schema")),
                    "zcl.application_protocols.index.v2") == 0;
        ok = ok && service_catalog &&
             strcmp(json_get_str(json_get(service_catalog,
                                          "x-response-schema")),
                    "zcl.service_catalog.v2") == 0;
        ok = ok && service_catalog &&
             strcmp(json_get_str(json_get(service_catalog,
                                          "x-crud-name")),
                    "read_singleton") == 0;
        ok = ok && service_operations &&
             strcmp(json_get_str(json_get(service_operations,
                                          "x-response-schema")),
                    "zcl.service_operations.index.v2") == 0;
        ok = ok && service_operations &&
             strcmp(json_get_str(json_get(service_operations,
                                          "x-crud-name")),
                    "read_collection") == 0;
        ok = ok && service_operations &&
             api_test_openapi_has_param(service_operations, "service",
                                        "query");
        ok = ok && service_operations &&
             api_test_openapi_has_param(service_operations, "write_safety",
                                        "query");
        ok = ok && service_operations &&
             api_test_openapi_has_param(service_operations,
                                        "preferred_interface", "query");
        ok = ok && service_operations &&
             api_test_openapi_has_param(service_operations, "status",
                                        "query");
        ok = ok && service_operations &&
             api_test_openapi_has_param(service_operations, "surface",
                                        "query");
        const struct json_value *service_operations_openapi_filter =
            service_operations ? json_get(service_operations,
                                          "x-zcl-filter-contract") : NULL;
        const struct json_value *service_operations_openapi_allowed =
            service_operations_openapi_filter ?
            json_get(service_operations_openapi_filter, "allowed_filters") :
            NULL;
        ok = ok && service_operations_openapi_filter &&
             strcmp(json_get_str(json_get(service_operations_openapi_filter,
                                          "schema")),
                    "zcl.query_filter_contract.v1") == 0;
        ok = ok && service_operations_openapi_filter &&
             json_get_bool(json_get(service_operations_openapi_filter,
                                    "unknown_filters_error"));
        ok = ok && service_operations_openapi_allowed &&
             strcmp(json_get_str(json_get(
                        service_operations_openapi_allowed, "surface")),
                    "rest,rpc") == 0;
        ok = ok && service_catalog_show &&
             strcmp(json_get_str(json_get(service_catalog_show,
                                          "x-response-schema")),
                    "zcl.service_contract.v2") == 0;
        ok = ok && service_catalog_show &&
             strcmp(json_get_str(json_get(service_catalog_show,
                                          "x-crud-name")),
                    "read_item") == 0;
        ok = ok && service_catalog_show &&
             api_test_openapi_has_param(service_catalog_show, "service",
                                        "path");
        ok = ok && service_operation_show &&
             strcmp(json_get_str(json_get(service_operation_show,
                                          "x-response-schema")),
                    "zcl.service_operation.v2") == 0;
        ok = ok && service_operation_show &&
             strcmp(json_get_str(json_get(service_operation_show,
                                          "x-crud-name")),
                    "read_item") == 0;
        ok = ok && service_operation_show &&
             api_test_openapi_has_param(service_operation_show,
                                        "operation_id", "path");
        ok = ok && protocol_show &&
             strcmp(json_get_str(json_get(protocol_show, "x-crud-name")),
                    "read_item") == 0;
        ok = ok && protocol_show &&
             api_test_openapi_has_param(protocol_show, "name", "path");
        ok = ok && names &&
             strcmp(json_get_str(json_get(names,
                    "x-zcl-application-protocol")), "znam") == 0;
        ok = ok && names &&
             api_test_array_has_str(json_get(names,
                    "x-zcl-protocol-object-types"), "service_record");
        ok = ok && names &&
             api_test_array_has_str(json_get(names,
                    "x-zcl-protocol-ux-surfaces"), "identity_profile");
        ok = ok && names &&
             strcmp(json_get_str(json_get(names, "x-zcl-reorg-model")),
                    "rebuild_name_state_from_confirmed_chain_after_disconnect")
             == 0;
        ok = ok && names &&
             strstr(json_get_str(json_get(names, "x-zcl-privacy-model")),
                    "public") != NULL;
        ok = ok && names_services &&
             strcmp(json_get_str(json_get(names_services,
                    "x-response-schema")),
                    "zcl.names.service_directory.v1") == 0;
        ok = ok && names_services &&
             strcmp(json_get_str(json_get(names_services,
                    "x-crud-name")), "read_subcollection") == 0;
        ok = ok && names_services &&
             strcmp(json_get_str(json_get(names_services,
                    "x-resource-scope")), "subcollection") == 0;
        ok = ok && names_services &&
             strcmp(json_get_str(json_get(names_services,
                    "x-zcl-application-protocol")), "znam") == 0;
        ok = ok && names_services &&
             api_test_openapi_has_param(names_services, "name", "path");
        const struct json_value *names_services_openapi_path_contract =
            names_services ? json_get(names_services,
                                      "x-zcl-path-param-contract") : NULL;
        const struct json_value *names_services_openapi_path_params =
            names_services_openapi_path_contract ?
            json_get(names_services_openapi_path_contract, "params") : NULL;
        const struct json_value *names_services_openapi_name_contract =
            names_services_openapi_path_params ?
            json_get(names_services_openapi_path_params, "name") : NULL;
        ok = ok && names_services_openapi_path_contract &&
             strcmp(json_get_str(json_get(
                        names_services_openapi_path_contract, "schema")),
                    "zcl.path_param_contract.v1") == 0;
        ok = ok && names_services_openapi_name_contract &&
             strcmp(json_get_str(json_get(
                        names_services_openapi_name_contract, "validator")),
                    "znam_validate_name") == 0;
        ok = ok && names_services_openapi_name_contract &&
             json_get_int(json_get(names_services_openapi_name_contract,
                                   "min_length")) == 1;
        ok = ok && names_services &&
             api_test_openapi_has_param(names_services, "service", "query");
        ok = ok && names_services &&
             api_test_openapi_has_param(names_services, "service_contract",
                                        "query");
        ok = ok && names_services &&
             api_test_openapi_has_param(names_services, "transport",
                                        "query");
        ok = ok && names_services &&
             api_test_openapi_has_param(names_services, "endpoint_kind",
                                        "query");
        ok = ok && names_services &&
             api_test_openapi_has_param(names_services, "valid", "query");
        ok = ok && names_services &&
             api_test_openapi_has_param(names_services, "endpoint_only",
                                        "query");
        const struct json_value *names_services_openapi_filter =
            names_services ? json_get(names_services,
                                      "x-zcl-filter-contract") : NULL;
        const struct json_value *names_services_openapi_allowed =
            names_services_openapi_filter ?
            json_get(names_services_openapi_filter, "allowed_filters") :
            NULL;
        ok = ok && names_services_openapi_filter &&
             strcmp(json_get_str(json_get(names_services_openapi_filter,
                                          "schema")),
                    "zcl.query_filter_contract.v1") == 0;
        ok = ok && names_services_openapi_filter &&
             json_get_bool(json_get(names_services_openapi_filter,
                                    "unknown_filters_error"));
        ok = ok && names_services_openapi_allowed &&
             strcmp(json_get_str(json_get(names_services_openapi_allowed,
                                          "valid")),
                    "true,false") == 0;
        const struct json_value *names_services_openapi_binding =
            names_services ? json_get(names_services,
                                      "x-zcl-service-binding") : NULL;
        ok = ok && names_services_openapi_binding &&
             strcmp(json_get_str(json_get(names_services_openapi_binding,
                                          "operation_id")),
                    "znam_names.resolve_service_directory") == 0;
        ok = ok && names_services_openapi_binding &&
             strcmp(json_get_str(json_get(names_services_openapi_binding,
                                          "output_schema")),
                    "zcl.names.service_directory.v1") == 0;
        const struct json_value *names_openapi_path_contract =
            names ? json_get(names, "x-zcl-path-param-contract") : NULL;
        const struct json_value *names_openapi_name_contract =
            names_openapi_path_contract ?
            json_get(json_get(names_openapi_path_contract, "params"),
                     "name") : NULL;
        ok = ok && names_openapi_name_contract &&
             strcmp(json_get_str(json_get(names_openapi_name_contract,
                                          "contract_name")),
                    "znam_name") == 0;
        ok = ok && names_openapi_name_contract &&
             strcmp(json_get_str(json_get(names_openapi_name_contract,
                                          "pattern")),
                    "^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$") == 0;
        ok = ok && swap_chains &&
             strcmp(json_get_str(json_get(swap_chains,
                    "x-zcl-application-protocol")),
                    "script_contracts") == 0;
        ok = ok && swap_chains &&
             strstr(json_get_str(json_get(swap_chains,
                    "x-zcl-source-anchor")), "HTLC atomic swaps") != NULL;
        ok = ok && swap_chains &&
             strstr(json_get_str(json_get(swap_chains,
                    "x-zcl-crypto-model")),
                    "legacy_valid_zclassic_script") != NULL;
        ok = ok && block_show &&
             api_test_openapi_has_param(block_show, "height_or_hash", "path");
        ok = ok && block_show &&
             strcmp(json_get_str(json_get(block_show, "x-crud-name")),
                    "read_item") == 0;
        ok = ok && block_show &&
             strcmp(json_get_str(json_at(json_get(block_show,
                                                  "x-id-params"), 0)),
                    "height_or_hash") == 0;
        ok = ok && legacy_name &&
             strcmp(json_get_str(json_get(legacy_name,
                                          "x-legacy-alias-of")),
                    "/api/v1/names/{name}") == 0;
        ok = ok && supply &&
             strcmp(json_get_str(json_get(supply,
                                          "x-compat-response-schema")),
                    "zcl.supply_legacy_number.v1") == 0;
        ok = ok && openapi &&
             strcmp(json_get_str(json_get(openapi, "x-response-schema")),
                    "zcl.openapi.v1") == 0;

        const struct json_value *components = json_get(&root, "components");
        const struct json_value *schemas = json_get(components, "schemas");
        const struct json_value *security =
            json_get(components, "securitySchemes");
        const struct json_value *error_schema =
            json_get(schemas, "zcl.rest_error.v1");
        const struct json_value *error_properties =
            json_get(error_schema, "properties");
        ok = ok && json_get(schemas, "zcl.wallet_status.v1") != NULL;
        ok = ok && error_schema != NULL;
        ok = ok && strcmp(json_get_str(json_get(error_schema, "type")),
                          "object") == 0;
        ok = ok && json_get(error_properties, "schema") != NULL;
        ok = ok && json_get(error_properties, "api_version") != NULL;
        ok = ok && json_get(error_properties, "error") != NULL;
        ok = ok && json_size(json_get(error_schema, "required")) == 3;
        ok = ok && strcmp(json_get_str(json_get(json_get(schemas,
                                      "zcl.supply_legacy_number.v1"),
                                      "type")),
                          "number") == 0;
        ok = ok && json_get(security, "operatorAuth") != NULL;
        ok = ok && json_get(security, "serviceHash512Auth") != NULL;
        json_free(&root);

        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    return failures;
}
