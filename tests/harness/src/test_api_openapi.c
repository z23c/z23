/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * API OpenAPI document: the generated spec must stay derived from the route
 * contract table rather than hand-maintained.
 */

#include "test/api_test_fixtures.h"
#include "../../../engine/controllers/src/api_controller_internal.h"

struct openapi_str_field {
    const struct json_value *obj;
    const char *key;
    const char *want;
};

struct openapi_nested_field {
    const struct json_value *obj;
    const char *parent;
    const char *child;
    const char *want;
};

struct openapi_substr_field {
    const struct json_value *obj;
    const char *key;
    const char *needle;
};

struct openapi_array_field {
    const struct json_value *obj;
    const char *key;
    const char *want;
};

struct openapi_param_field {
    const struct json_value *operation;
    const char *name;
    const char *location;
};

static const struct json_value *openapi_child_or_null(
    const struct json_value *obj, const char *key)
{
    return obj ? json_get(obj, key) : NULL;
}

static const struct json_value *openapi_path_name_contract(
    const struct json_value *path_contract)
{
    return path_contract
               ? json_get(json_get(path_contract, "params"), "name")
               : NULL;
}

static bool openapi_guarded_string_fields_ok(
    bool ok, const struct openapi_str_field *rows, size_t count)
{
    for (size_t i = 0; i < count; i++) {
        ok = ok && rows[i].obj &&
             strcmp(json_get_str(json_get(rows[i].obj, rows[i].key)),
                    rows[i].want) == 0;
    }
    return ok;
}

static bool openapi_nested_string_fields_ok(
    bool ok, const struct openapi_nested_field *rows, size_t count)
{
    for (size_t i = 0; i < count; i++) {
        ok = ok && rows[i].obj &&
             strcmp(json_get_str(json_get(json_get(rows[i].obj,
                                                   rows[i].parent),
                                          rows[i].child)),
                    rows[i].want) == 0;
    }
    return ok;
}

static bool openapi_substr_fields_ok(bool ok,
                                     const struct openapi_substr_field *rows,
                                     size_t count)
{
    for (size_t i = 0; i < count; i++) {
        ok = ok && rows[i].obj &&
             strstr(json_get_str(json_get(rows[i].obj, rows[i].key)),
                    rows[i].needle) != NULL;
    }
    return ok;
}

static bool openapi_array_string_fields_ok(
    bool ok, const struct openapi_array_field *rows, size_t count)
{
    for (size_t i = 0; i < count; i++) {
        ok = ok && rows[i].obj &&
             api_test_array_has_str(json_get(rows[i].obj, rows[i].key),
                                    rows[i].want);
    }
    return ok;
}

static bool openapi_operation_params_ok(
    bool ok, const struct openapi_param_field *rows, size_t count)
{
    for (size_t i = 0; i < count; i++) {
        ok = ok && rows[i].operation &&
             api_test_openapi_has_param(rows[i].operation, rows[i].name,
                                        rows[i].location);
    }
    return ok;
}

static bool openapi_document_header_ok(struct json_value *root,
                                       size_t n, const char *body)
{
    bool ok = n > 0 && body && json_read(root, body, strlen(body));
    ok = ok && strcmp(json_get_str(json_get(root, "schema")),
                      "zcl.openapi.v1") == 0;
    ok = ok && strcmp(json_get_str(json_get(root, "openapi")),
                      "3.1.0") == 0;
    ok = ok && strcmp(json_get_str(json_get(json_get(root, "info"),
                                            "version")),
                      "v1") == 0;
    ok = ok && strcmp(json_get_str(json_get(json_at(json_get(root,
                                  "servers"), 0), "url")),
                      "/api/v1") == 0;
    ok = ok && strcmp(json_get_str(json_get(json_get(root,
                      "x-zcl-crypto-policy"),
                      "service_auth_primary_digest")),
                      "SHA3-512") == 0;
    ok = ok && strcmp(json_get_str(json_get(json_get(root,
                      "x-zcl-crypto-policy"),
                      "service_auth_secondary_digest")),
                      "GOST R 34.11-2012-512") == 0;
    return ok;
}

static bool openapi_layer_protocols_ok(bool ok,
                                       const struct json_value *root,
                                       const struct json_value *layer)
{
    static const char *const names[] = {
        "zlsp", "zslp", "znam", "script_contracts"
    };
    size_t count = sizeof names / sizeof names[0];
    for (size_t i = 0; i < count; i++) {
        ok = ok && layer &&
             api_test_find_named(json_get(layer, "application_protocols"),
                                 names[i]) != NULL;
    }
    return ok &&
           json_get_int(json_get(root, "x-route-contract-count")) ==
           (int64_t)api_route_contract_count();
}

static bool openapi_filter_contract_ok(bool ok,
                                       const struct json_value *operation,
                                       const char *allowed_key,
                                       const char *allowed_want)
{
    const struct json_value *filter =
        openapi_child_or_null(operation, "x-zcl-filter-contract");
    const struct json_value *allowed =
        openapi_child_or_null(filter, "allowed_filters");
    ok = ok && filter &&
         strcmp(json_get_str(json_get(filter, "schema")),
                "zcl.query_filter_contract.v1") == 0;
    ok = ok && filter &&
         json_get_bool(json_get(filter, "unknown_filters_error"));
    ok = ok && allowed &&
         strcmp(json_get_str(json_get(allowed, allowed_key)),
                allowed_want) == 0;
    return ok;
}

static bool openapi_wallet_operation_ok(bool ok,
                                        const struct json_value *wallet)
{
    ok = ok && wallet && json_get_bool(json_get(wallet, "x-private"));
    ok = ok && wallet && json_size(json_get(wallet, "security")) == 1;
    return ok;
}

static bool openapi_hodl_response_ref_ok(bool ok,
                                        const struct json_value *hodl)
{
    const struct json_value *hodl_200 =
        json_get(json_get(hodl, "responses"), "200");
    return ok && strcmp(json_get_str(json_get(json_get(json_get(
               json_get(hodl_200, "content"), "engine/application/json"),
               "schema"), "$ref")),
               "#/components/schemas/zcl.hodl_wave.v1") == 0;
}

static bool openapi_block_id_param_ok(bool ok,
                                     const struct json_value *block_show)
{
    return ok && block_show &&
           strcmp(json_get_str(json_at(json_get(block_show, "x-id-params"),
                                       0)),
                  "height_or_hash") == 0;
}

static bool openapi_names_services_path_ok(
    bool ok, const struct json_value *names_services)
{
    const struct json_value *names_services_openapi_path_contract =
        openapi_child_or_null(names_services, "x-zcl-path-param-contract");
    const struct json_value *names_services_openapi_path_params =
        openapi_child_or_null(names_services_openapi_path_contract,
                              "params");
    const struct json_value *names_services_openapi_name_contract =
        openapi_child_or_null(names_services_openapi_path_params, "name");
    const struct openapi_str_field rows[] = {
        { names_services_openapi_path_contract, "schema",
          "zcl.path_param_contract.v1" },
        { names_services_openapi_name_contract, "validator",
          "znam_validate_name" },
    };
    ok = openapi_guarded_string_fields_ok(
        ok, rows, sizeof rows / sizeof rows[0]);
    ok = ok && names_services_openapi_name_contract &&
         json_get_int(json_get(names_services_openapi_name_contract,
                               "min_length")) == 1;
    return ok;
}

static bool openapi_names_path_contract_ok(bool ok,
                                          const struct json_value *names)
{
    const struct json_value *names_openapi_path_contract =
        openapi_child_or_null(names, "x-zcl-path-param-contract");
    const struct json_value *names_openapi_name_contract =
        openapi_path_name_contract(names_openapi_path_contract);
    const struct openapi_str_field rows[] = {
        { names_openapi_name_contract, "contract_name", "znam_name" },
        { names_openapi_name_contract, "pattern",
          "^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$" },
    };
    return openapi_guarded_string_fields_ok(
        ok, rows, sizeof rows / sizeof rows[0]);
}

static bool openapi_components_ok(bool ok, const struct json_value *root)
{
    const struct json_value *components = json_get(root, "components");
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
    return ok;
}

static bool openapi_extensions_case(const char *input, const char *expected)
{
    struct json_value contract = {0}, operation = {0};
    char output[4096];
    bool ok = json_read(&contract, input, strlen(input));
    json_set_object(&operation);
    if (ok)
        api_app_protocol_push_openapi_extensions(&contract, &operation);
    size_t n = json_write(&operation, output, sizeof(output));
    ok = ok && n < sizeof(output) && strcmp(output, expected) == 0;
    json_free(&operation);
    json_free(&contract);
    return ok;
}

static int openapi_extensions_mapping_test(void)
{
    static const char input[] =
        "{\"layer\":\"1\",\"base_layer\":\"2\",\"application_protocol\":\"3\","
        "\"protocol_family\":\"4\",\"source_anchor\":\"5\",\"protocol_anchor_kind\":\"6\","
        "\"read_model\":\"7\",\"protocol_crud\":[\"r\"],\"protocol_object_types\":null,"
        "\"protocol_ux_surfaces\":false,\"protocol_construction_status\":\"8\","
        "\"mutation_authority\":\"9\",\"write_semantics\":\"10\",\"consensus_boundary\":\"11\","
        "\"projection_model\":\"12\",\"reorg_model\":\"13\",\"crypto_model\":\"14\","
        "\"transport_model\":\"15\",\"privacy_model\":\"16\",\"diagnostics_surface\":\"17\"}";
    static const char expected[] =
        "{\"x-zcl-layer\":\"1\",\"x-zcl-base-layer\":\"2\",\"x-zcl-application-protocol\":\"3\","
        "\"x-zcl-protocol-family\":\"4\",\"x-zcl-source-anchor\":\"5\",\"x-zcl-protocol-anchor-kind\":\"6\","
        "\"x-zcl-read-model\":\"7\",\"x-zcl-protocol-crud\":[\"r\"],\"x-zcl-protocol-object-types\":null,"
        "\"x-zcl-protocol-ux-surfaces\":false,\"x-zcl-protocol-construction-status\":\"8\","
        "\"x-zcl-mutation-authority\":\"9\",\"x-zcl-write-semantics\":\"10\",\"x-zcl-consensus-boundary\":\"11\","
        "\"x-zcl-projection-model\":\"12\",\"x-zcl-reorg-model\":\"13\",\"x-zcl-crypto-model\":\"14\","
        "\"x-zcl-transport-model\":\"15\",\"x-zcl-privacy-model\":\"16\",\"x-zcl-diagnostics-surface\":\"17\"}";
    static const char sparse[] =
        "{\"layer\":\"\",\"base_layer\":42,\"protocol_family\":false,"
        "\"protocol_crud\":\"\",\"protocol_object_types\":{},\"privacy_model\":\"public\"}";
    static const char sparse_expected[] =
        "{\"x-zcl-protocol-crud\":\"\",\"x-zcl-protocol-object-types\":{},\"x-zcl-privacy-model\":\"public\"}";
    printf("api: OpenAPI extension mapping and omission... ");
    bool ok = openapi_extensions_case(input, expected) &&
              openapi_extensions_case(sparse, sparse_expected);
    if (ok) printf("OK\n"); else printf("FAIL\n");
    return ok ? 0 : 1;
}

int api_openapi_focused_tests(void)
{
    int failures = openapi_extensions_mapping_test();

    printf("api: OpenAPI document is generated from route contracts... ");
    {
        static uint8_t openapi_resp[262144];
        size_t n = api_handle_request("GET", "/api/v1/openapi", NULL, 0,
                                      openapi_resp, sizeof(openapi_resp));
        const char *body = api_test_body(openapi_resp, n,
                                         sizeof(openapi_resp));
        struct json_value root;
        json_init(&root);
        bool ok = openapi_document_header_ok(&root, n, body);
        const struct json_value *openapi_layer =
            json_get(&root, "x-zcl-layer-model");
        const struct openapi_str_field layer_fields[] = {
            { openapi_layer, "schema", "zcl.rest_layer_model.v1" },
            { openapi_layer, "base_layer", "zclassic_l1" },
            { openapi_layer, "application_protocol_umbrella", "zlsp" },
        };
        ok = openapi_guarded_string_fields_ok(
            ok, layer_fields, sizeof layer_fields / sizeof layer_fields[0]);
        ok = openapi_layer_protocols_ok(ok, &root, openapi_layer);

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

        const struct openapi_str_field singleton_fields[] = {
            { health_openapi, "x-zcl-command-path", "ops.health" },
            { hodl, "x-resource", "hodl" },
            { hodl, "x-crud-operation", "read" },
            { hodl, "x-resource-scope", "singleton" },
            { hodl, "x-crud-name", "read_singleton" },
            { hodl, "x-response-schema", "zcl.hodl_wave.v1" },
            { bootstrap, "x-resource", "bootstrap" },
            { bootstrap, "x-crud-name", "read_singleton" },
            { bootstrap, "x-response-schema", "zcl.bootstrap_status.v1" },
        };
        ok = openapi_guarded_string_fields_ok(
            ok, singleton_fields,
            sizeof singleton_fields / sizeof singleton_fields[0]);
        const struct openapi_nested_field bootstrap_freshness[] = {
            { bootstrap, "x-zcl-telemetry", "freshness_source",
              "network_bootstrap" },
        };
        ok = openapi_nested_string_fields_ok(
            ok, bootstrap_freshness,
            sizeof bootstrap_freshness / sizeof bootstrap_freshness[0]);
        const struct json_value *bootstrap_openapi_binding =
            openapi_child_or_null(bootstrap, "x-zcl-service-binding");
        const struct openapi_str_field bootstrap_binding_fields[] = {
            { bootstrap_openapi_binding, "operation_id",
              "bootstrap.read_bootstrap_status" },
            { bootstrap_openapi_binding, "service", "bootstrap" },
            { legacy_bootstrap, "x-legacy-alias-of", "/api/v1/bootstrap" },
            { hodl, "x-auth-policy", "public" },
        };
        ok = openapi_guarded_string_fields_ok(
            ok, bootstrap_binding_fields,
            sizeof bootstrap_binding_fields /
                sizeof bootstrap_binding_fields[0]);
        const struct openapi_nested_field hodl_policy_fields[] = {
            { hodl, "x-zcl-telemetry", "counter",
              "zcl_api_requests_total" },
            { hodl, "x-zcl-crypto-policy", "service_auth_primary_digest",
              "SHA3-512" },
            { hodl, "x-zcl-crypto-policy",
              "service_auth_secondary_digest",
              "GOST R 34.11-2012-512" },
        };
        ok = openapi_nested_string_fields_ok(
            ok, hodl_policy_fields,
            sizeof hodl_policy_fields / sizeof hodl_policy_fields[0]);
        ok = openapi_hodl_response_ref_ok(ok, hodl);
        ok = openapi_wallet_operation_ok(ok, wallet);
        const struct openapi_param_field event_params[] = {
            { events, "limit", "query" },
            { events, "type", "query" },
        };
        ok = openapi_operation_params_ok(
            ok, event_params, sizeof event_params / sizeof event_params[0]);
        const struct openapi_str_field event_crud[] = {
            { events, "x-crud-name", "read_collection" },
        };
        ok = openapi_guarded_string_fields_ok(
            ok, event_crud, sizeof event_crud / sizeof event_crud[0]);
        const struct openapi_str_field zslp_head[] = {
            { zslp, "x-zcl-application-protocol", "zslp" },
            { zslp, "x-zcl-base-layer", "zclassic_l1" },
            { zslp, "x-zcl-layer", "zclassic23_application_layer" },
            { zslp, "x-zcl-protocol-family", "token" },
            { zslp, "x-zcl-protocol-anchor-kind", "op_return" },
        };
        ok = openapi_guarded_string_fields_ok(
            ok, zslp_head, sizeof zslp_head / sizeof zslp_head[0]);
        const struct openapi_array_field zslp_arrays[] = {
            { zslp, "x-zcl-protocol-crud", "read_collection" },
            { zslp, "x-zcl-protocol-object-types", "token_genesis" },
        };
        ok = openapi_array_string_fields_ok(
            ok, zslp_arrays, sizeof zslp_arrays / sizeof zslp_arrays[0]);
        const struct openapi_str_field zslp_tail[] = {
            { zslp, "x-zcl-protocol-construction-status",
              "transaction_builders_active" },
            { zslp, "x-zcl-mutation-authority",
              "operator_wallet_transaction" },
        };
        ok = openapi_guarded_string_fields_ok(
            ok, zslp_tail, sizeof zslp_tail / sizeof zslp_tail[0]);
        const struct openapi_str_field catalog_index[] = {
            { protocols, "x-response-schema",
              "zcl.application_protocols.index.v2" },
            { service_catalog, "x-response-schema",
              "zcl.service_catalog.v2" },
            { service_catalog, "x-crud-name", "read_singleton" },
            { service_operations, "x-response-schema",
              "zcl.service_operations.index.v2" },
            { service_operations, "x-crud-name", "read_collection" },
        };
        ok = openapi_guarded_string_fields_ok(
            ok, catalog_index, sizeof catalog_index / sizeof catalog_index[0]);
        const struct openapi_param_field service_operation_params[] = {
            { service_operations, "service", "query" },
            { service_operations, "write_safety", "query" },
            { service_operations, "preferred_interface", "query" },
            { service_operations, "status", "query" },
            { service_operations, "surface", "query" },
        };
        ok = openapi_operation_params_ok(
            ok, service_operation_params,
            sizeof service_operation_params /
                sizeof service_operation_params[0]);
        ok = openapi_filter_contract_ok(ok, service_operations, "surface",
                                        "rest,rpc");
        const struct openapi_str_field catalog_show_fields[] = {
            { service_catalog_show, "x-response-schema",
              "zcl.service_contract.v2" },
            { service_catalog_show, "x-crud-name", "read_item" },
        };
        ok = openapi_guarded_string_fields_ok(
            ok, catalog_show_fields,
            sizeof catalog_show_fields / sizeof catalog_show_fields[0]);
        const struct openapi_param_field catalog_show_param[] = {
            { service_catalog_show, "service", "path" },
        };
        ok = openapi_operation_params_ok(
            ok, catalog_show_param,
            sizeof catalog_show_param / sizeof catalog_show_param[0]);
        const struct openapi_str_field operation_show_fields[] = {
            { service_operation_show, "x-response-schema",
              "zcl.service_operation.v2" },
            { service_operation_show, "x-crud-name", "read_item" },
        };
        ok = openapi_guarded_string_fields_ok(
            ok, operation_show_fields,
            sizeof operation_show_fields / sizeof operation_show_fields[0]);
        const struct openapi_param_field operation_show_param[] = {
            { service_operation_show, "operation_id", "path" },
        };
        ok = openapi_operation_params_ok(
            ok, operation_show_param,
            sizeof operation_show_param / sizeof operation_show_param[0]);
        const struct openapi_str_field protocol_show_fields[] = {
            { protocol_show, "x-crud-name", "read_item" },
        };
        ok = openapi_guarded_string_fields_ok(
            ok, protocol_show_fields,
            sizeof protocol_show_fields / sizeof protocol_show_fields[0]);
        const struct openapi_param_field protocol_show_param[] = {
            { protocol_show, "name", "path" },
        };
        ok = openapi_operation_params_ok(
            ok, protocol_show_param,
            sizeof protocol_show_param / sizeof protocol_show_param[0]);
        const struct openapi_str_field names_protocol[] = {
            { names, "x-zcl-application-protocol", "znam" },
        };
        ok = openapi_guarded_string_fields_ok(
            ok, names_protocol,
            sizeof names_protocol / sizeof names_protocol[0]);
        const struct openapi_array_field names_arrays[] = {
            { names, "x-zcl-protocol-object-types", "service_record" },
            { names, "x-zcl-protocol-ux-surfaces", "identity_profile" },
        };
        ok = openapi_array_string_fields_ok(
            ok, names_arrays, sizeof names_arrays / sizeof names_arrays[0]);
        const struct openapi_str_field names_reorg[] = {
            { names, "x-zcl-reorg-model",
              "rebuild_name_state_from_confirmed_chain_after_disconnect" },
        };
        ok = openapi_guarded_string_fields_ok(
            ok, names_reorg, sizeof names_reorg / sizeof names_reorg[0]);
        const struct openapi_substr_field names_privacy[] = {
            { names, "x-zcl-privacy-model", "public" },
        };
        ok = openapi_substr_fields_ok(
            ok, names_privacy, sizeof names_privacy / sizeof names_privacy[0]);
        const struct openapi_str_field names_services_fields[] = {
            { names_services, "x-response-schema",
              "zcl.names.service_directory.v1" },
            { names_services, "x-crud-name", "read_subcollection" },
            { names_services, "x-resource-scope", "subcollection" },
            { names_services, "x-zcl-application-protocol", "znam" },
        };
        ok = openapi_guarded_string_fields_ok(
            ok, names_services_fields,
            sizeof names_services_fields / sizeof names_services_fields[0]);
        const struct openapi_param_field names_services_name_param[] = {
            { names_services, "name", "path" },
        };
        ok = openapi_operation_params_ok(
            ok, names_services_name_param,
            sizeof names_services_name_param /
                sizeof names_services_name_param[0]);
        ok = openapi_names_services_path_ok(ok, names_services);
        const struct openapi_param_field names_services_query_params[] = {
            { names_services, "service", "query" },
            { names_services, "service_contract", "query" },
            { names_services, "transport", "query" },
            { names_services, "endpoint_kind", "query" },
            { names_services, "valid", "query" },
            { names_services, "endpoint_only", "query" },
        };
        ok = openapi_operation_params_ok(
            ok, names_services_query_params,
            sizeof names_services_query_params /
                sizeof names_services_query_params[0]);
        ok = openapi_filter_contract_ok(ok, names_services, "valid",
                                        "true,false");
        const struct json_value *names_services_openapi_binding =
            openapi_child_or_null(names_services, "x-zcl-service-binding");
        const struct openapi_str_field names_services_binding_fields[] = {
            { names_services_openapi_binding, "operation_id",
              "znam_names.resolve_service_directory" },
            { names_services_openapi_binding, "output_schema",
              "zcl.names.service_directory.v1" },
        };
        ok = openapi_guarded_string_fields_ok(
            ok, names_services_binding_fields,
            sizeof names_services_binding_fields /
                sizeof names_services_binding_fields[0]);
        ok = openapi_names_path_contract_ok(ok, names);
        const struct openapi_str_field swap_protocol[] = {
            { swap_chains, "x-zcl-application-protocol",
              "script_contracts" },
        };
        ok = openapi_guarded_string_fields_ok(
            ok, swap_protocol, sizeof swap_protocol / sizeof swap_protocol[0]);
        const struct openapi_substr_field swap_anchors[] = {
            { swap_chains, "x-zcl-source-anchor", "HTLC atomic swaps" },
            { swap_chains, "x-zcl-crypto-model",
              "legacy_valid_zclassic_script" },
        };
        ok = openapi_substr_fields_ok(
            ok, swap_anchors, sizeof swap_anchors / sizeof swap_anchors[0]);
        const struct openapi_param_field block_param[] = {
            { block_show, "height_or_hash", "path" },
        };
        ok = openapi_operation_params_ok(
            ok, block_param, sizeof block_param / sizeof block_param[0]);
        const struct openapi_str_field block_crud[] = {
            { block_show, "x-crud-name", "read_item" },
        };
        ok = openapi_guarded_string_fields_ok(
            ok, block_crud, sizeof block_crud / sizeof block_crud[0]);
        ok = openapi_block_id_param_ok(ok, block_show);
        const struct openapi_str_field tail_fields[] = {
            { legacy_name, "x-legacy-alias-of", "/api/v1/names/{name}" },
            { supply, "x-compat-response-schema",
              "zcl.supply_legacy_number.v1" },
            { openapi, "x-response-schema", "zcl.openapi.v1" },
        };
        ok = openapi_guarded_string_fields_ok(
            ok, tail_fields, sizeof tail_fields / sizeof tail_fields[0]);
        ok = openapi_components_ok(ok, &root);
        json_free(&root);

        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    return failures;
}
