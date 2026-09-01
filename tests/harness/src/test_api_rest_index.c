/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * API REST index: the v1 discovery document that explains the first call and
 * the CRUD shape of every resource.
 */

#include "test/api_test_fixtures.h"

int api_rest_index_focused_tests(void)
{
    int failures = 0;

    printf("api: REST index explains v1 first call and CRUD shape... ");
    {
        static uint8_t index_resp[262144];
        size_t n = api_handle_request("GET", "/api/v1", NULL, 0,
                                      index_resp, sizeof(index_resp));
        const char *body = api_test_body(index_resp, n, sizeof(index_resp));
        struct json_value root;
        json_init(&root);
        bool ok = n > 0 && body && json_read(&root, body, strlen(body));
        ok = ok && strcmp(json_get_str(json_get(&root, "schema")),
                          "zcl.rest_index.v2") == 0;
        ok = ok && strcmp(json_get_str(json_get(&root, "api_version")),
                          "v1") == 0;
        ok = ok && strcmp(json_get_str(json_get(&root, "base_path")),
                          "/api/v1") == 0;
        ok = ok && strcmp(json_get_str(json_get(&root, "compat_base_path")),
                          "/api") == 0;
        ok = ok && strcmp(json_get_str(json_get(&root, "first_call")),
                          "/api/v1/agent") == 0;
        ok = ok && strcmp(json_get_str(json_get(json_get(&root, "aliases"),
                                                "protocols")),
                          "/api/v1/protocols") == 0;
        ok = ok && strcmp(json_get_str(json_get(json_get(&root, "aliases"),
                                                "service_catalog")),
                          "/api/v1/service-catalog") == 0;
        ok = ok && strcmp(json_get_str(json_get(json_get(&root, "aliases"),
                                                "service_operations")),
                          "/api/v1/service-operations") == 0;
        ok = ok && strcmp(json_get_str(json_get(json_get(&root, "aliases"),
                                                "bootstrap")),
                          "/api/v1/bootstrap") == 0;
        ok = ok && strcmp(json_get_str(json_get(json_get(&root, "aliases"),
                                                "bootstrapstatus")),
                          "/api/v1/bootstrap") == 0;
        ok = ok && json_get(json_get(&root, "crud"), "read_collection") != NULL;
        ok = ok && json_get(json_get(&root, "crud"), "read_item") != NULL;
        ok = ok && json_get(json_get(&root, "crud"),
                            "read_singleton") != NULL;
        ok = ok && json_get(json_get(&root, "crud"),
                            "read_subcollection") != NULL;
        ok = ok && json_get(json_get(&root, "crud"),
                            "contract_fields") != NULL;
        const struct json_value *layer_model =
            json_get(&root, "layer_model");
        ok = ok && layer_model &&
             strcmp(json_get_str(json_get(layer_model, "schema")),
                    "zcl.rest_layer_model.v1") == 0;
        ok = ok && layer_model &&
             strcmp(json_get_str(json_get(layer_model, "base_layer")),
                    "zclassic_l1") == 0;
        ok = ok && layer_model &&
             strcmp(json_get_str(json_get(layer_model, "service_layer")),
                    "zclassic23_application_layer") == 0;
        ok = ok && layer_model &&
             strcmp(json_get_str(json_get(layer_model,
                                          "service_layer_alias")),
                    "zclassic23_l2") == 0;
        ok = ok && layer_model &&
             strcmp(json_get_str(json_get(layer_model,
                                          "application_protocol_umbrella")),
                    "zlsp") == 0;
        ok = ok && layer_model &&
             strcmp(json_get_str(json_get(layer_model,
                                          "consensus_authority")),
                    "local_consensus_reducer") == 0;
        ok = ok && layer_model &&
             strstr(json_get_str(json_get(layer_model,
                                          "crud_service_rule")),
                    "transaction-construction requests") != NULL;
        ok = ok && layer_model &&
             strstr(json_get_str(json_get(layer_model,
                                          "consensus_boundary")),
                    "must not change block") != NULL;
        const struct json_value *protocols =
            layer_model ? json_get(layer_model, "application_protocols") : NULL;
        const struct json_value *zlsp_protocol =
            api_test_find_named(protocols, "zlsp");
        const struct json_value *zslp_protocol =
            api_test_find_named(protocols, "zslp");
        const struct json_value *znam_protocol =
            api_test_find_named(protocols, "znam");
        const struct json_value *script_protocol =
            api_test_find_named(protocols, "script_contracts");
        const struct json_value *swap_protocol =
            api_test_find_named(protocols, "atomic_swaps");
        ok = ok && protocols && protocols->type == JSON_ARR &&
             json_size(protocols) >= 7;
        ok = ok && zlsp_protocol &&
             strcmp(json_get_str(json_get(zlsp_protocol, "status")),
                    "design") == 0;
        ok = ok && zlsp_protocol &&
             strcmp(json_get_str(json_get(zlsp_protocol, "family")),
                    "application_protocol_framework") == 0;
        ok = ok && zlsp_protocol &&
             strcmp(json_get_str(json_get(zlsp_protocol, "anchor_kind")),
                    "base_layer_transaction_contract") == 0;
        ok = ok && zlsp_protocol &&
             api_test_array_has_str(json_get(zlsp_protocol,
                                             "crud_capabilities"),
                                    "construct_transaction");
        ok = ok && zlsp_protocol &&
             api_test_array_has_str(json_get(zlsp_protocol,
                                             "ux_surfaces"),
                                    "agent_command_center");
        ok = ok && zslp_protocol &&
             strcmp(json_get_str(json_get(zslp_protocol, "schema")),
                    "zcl.application_protocol_contract.v2") == 0;
        ok = ok && zslp_protocol &&
             strcmp(json_get_str(json_get(zslp_protocol, "status")),
                    "active") == 0;
        ok = ok && zslp_protocol &&
             strcmp(json_get_str(json_get(zslp_protocol, "base_layer")),
                    "zclassic_l1") == 0;
        ok = ok && zslp_protocol &&
             strcmp(json_get_str(json_get(zslp_protocol, "family")),
                    "token") == 0;
        ok = ok && zslp_protocol &&
             strcmp(json_get_str(json_get(zslp_protocol, "anchor_kind")),
                    "op_return") == 0;
        ok = ok && zslp_protocol &&
             strcmp(json_get_str(json_get(zslp_protocol, "rest_resource")),
                    "/api/v1/zslp/tokens") == 0;
        ok = ok && zslp_protocol &&
             api_test_array_has_str(json_get(zslp_protocol,
                                             "crud_capabilities"),
                                    "read_item");
        ok = ok && zslp_protocol &&
             strcmp(json_get_str(json_get(zslp_protocol,
                                          "construction_status")),
                    "transaction_builders_active") == 0;
        ok = ok && zslp_protocol &&
             strcmp(json_get_str(json_get(zslp_protocol,
                                          "consensus_boundary")),
                    "interprets_or_constructs_valid_zcl_transactions_only")
             == 0;
        ok = ok && zslp_protocol &&
             api_test_array_has_str(json_get(zslp_protocol,
                                             "object_types"),
                                    "token_genesis");
        ok = ok && zslp_protocol &&
             strcmp(json_get_str(json_get(zslp_protocol,
                                          "projection_model")),
                    "confirmed_op_return_projection_at_served_frontier") == 0;
        ok = ok && znam_protocol &&
             api_test_array_has_str(json_get(znam_protocol, "object_types"),
                                    "service_record");
        ok = ok && znam_protocol &&
             api_test_array_has_str(json_get(znam_protocol, "ux_surfaces"),
                                    "identity_profile");
        ok = ok && znam_protocol &&
             strstr(json_get_str(json_get(znam_protocol, "crypto_model")),
                    "owner_authority") != NULL;
        ok = ok && script_protocol &&
             strstr(json_get_str(json_get(script_protocol, "crypto_model")),
                    "legacy_valid_zclassic_script") != NULL;
        ok = ok && znam_protocol &&
             strcmp(json_get_str(json_get(znam_protocol, "status")),
                    "active") == 0;
        ok = ok && znam_protocol &&
             strcmp(json_get_str(json_get(znam_protocol, "anchor")),
                    "OP_RETURN name registry transactions") == 0;
        ok = ok && script_protocol &&
             strcmp(json_get_str(json_get(script_protocol, "status")),
                    "active") == 0;
        ok = ok && script_protocol &&
             strcmp(json_get_str(json_get(script_protocol, "anchor_kind")),
                    "standard_script") == 0;
        ok = ok && script_protocol &&
             strcmp(json_get_str(json_get(script_protocol,
                                          "mutation_authority")),
                    "operator_wallet_transaction") == 0;
        ok = ok && script_protocol &&
             strstr(json_get_str(json_get(script_protocol, "anchor")),
                    "HTLC atomic swaps") != NULL;
        ok = ok && swap_protocol &&
             strcmp(json_get_str(json_get(swap_protocol, "status")),
                    "in_progress") == 0;
        const struct json_value *resources = json_get(&root, "resources");
        const struct json_value *bootstrap_resource =
            api_test_find_named(resources, "bootstrap");
        const struct json_value *zslp_resource =
            api_test_find_named(resources, "zslp_tokens");
        const struct json_value *protocols_resource =
            api_test_find_named(resources, "protocols");
        const struct json_value *service_catalog_resource =
            api_test_find_named(resources, "service_catalog");
        const struct json_value *service_operations_resource =
            api_test_find_named(resources, "service_operations");
        const struct json_value *name_services_resource =
            api_test_find_named(resources, "name_services");
        ok = ok && resources && json_size(resources) >= 4;
        ok = ok && bootstrap_resource &&
             strcmp(json_get_str(json_get(bootstrap_resource, "collection")),
                    "/api/v1/bootstrap") == 0;
        ok = ok && protocols_resource &&
             strcmp(json_get_str(json_get(protocols_resource, "collection")),
                    "/api/v1/protocols") == 0;
        ok = ok && protocols_resource &&
             strcmp(json_get_str(json_get(protocols_resource, "item")),
                    "/api/v1/protocols/{name}") == 0;
        ok = ok && service_catalog_resource &&
             strcmp(json_get_str(json_get(service_catalog_resource,
                                          "collection")),
                    "/api/v1/service-catalog") == 0;
        ok = ok && service_catalog_resource &&
             strcmp(json_get_str(json_get(service_catalog_resource, "item")),
                    "/api/v1/service-catalog/{service}") == 0;
        ok = ok && service_operations_resource &&
             strcmp(json_get_str(json_get(service_operations_resource,
                                          "collection")),
                    "/api/v1/service-operations") == 0;
        ok = ok && service_operations_resource &&
             strcmp(json_get_str(json_get(service_operations_resource, "item")),
                    "/api/v1/service-operations/{operation_id}") == 0;
        ok = ok && name_services_resource &&
             strcmp(json_get_str(json_get(name_services_resource, "item")),
                    "/api/v1/names/{name}/services") == 0;
        ok = ok && zslp_resource &&
             strcmp(json_get_str(json_get(zslp_resource, "collection")),
                    "/api/v1/zslp/tokens") == 0;
        const struct json_value *routes = json_get(&root, "route_contracts");
        ok = ok && routes &&
             json_size(routes) == api_route_contract_count();
        ok = ok && json_get_int(json_get(&root, "route_contract_count")) ==
             (int64_t)api_route_contract_count();
        const struct json_value *hodl =
            api_test_find_contract(routes, "/api/v1/hodl");
        const struct json_value *bootstrap =
            api_test_find_contract(routes, "/api/v1/bootstrap");
        const struct json_value *legacy_bootstrap =
            api_test_find_contract(routes, "/api/v1/bootstrapstatus");
        const struct json_value *wallet =
            api_test_find_contract(routes, "/api/v1/wallet");
        const struct json_value *zslp =
            api_test_find_contract(routes, "/api/v1/zslp/tokens");
        const struct json_value *protocols_route =
            api_test_find_contract(routes, "/api/v1/protocols");
        const struct json_value *service_catalog_route =
            api_test_find_contract(routes, "/api/v1/service-catalog");
        const struct json_value *service_catalog_show =
            api_test_find_contract(routes, "/api/v1/service-catalog/{service}");
        const struct json_value *service_operations_route =
            api_test_find_contract(routes, "/api/v1/service-operations");
        const struct json_value *service_operation_show =
            api_test_find_contract(routes,
                                  "/api/v1/service-operations/{operation_id}");
        const struct json_value *protocol_show =
            api_test_find_contract(routes, "/api/v1/protocols/{name}");
        const struct json_value *names =
            api_test_find_contract(routes, "/api/v1/names/{name}");
        const struct json_value *names_services =
            api_test_find_contract(routes, "/api/v1/names/{name}/services");
        const struct json_value *legacy_name =
            api_test_find_contract(routes, "/api/v1/name/{name}");
        const struct json_value *swap_chains =
            api_test_find_contract(routes, "/api/v1/swaps/chains");
        const struct json_value *legacy_swap_chains =
            api_test_find_contract(routes, "/api/v1/swap_chains");
        const struct json_value *events =
            api_test_find_contract(routes, "/api/v1/events");
        const struct json_value *supply =
            api_test_find_contract(routes, "/api/v1/supply");
        const struct json_value *block_show =
            api_test_find_contract(routes, "/api/v1/blocks/{height_or_hash}");
        const struct json_value *legacy_block_show =
            api_test_find_contract(routes, "/api/v1/block/{height_or_hash}");
        const struct json_value *tx_show =
            api_test_find_contract(routes, "/api/v1/transactions/{txid}");
        const struct json_value *legacy_tx_show =
            api_test_find_contract(routes, "/api/v1/tx/{txid}");
        const struct json_value *address_show =
            api_test_find_contract(routes, "/api/v1/addresses/{address}");
        const struct json_value *legacy_address_show =
            api_test_find_contract(routes, "/api/v1/address/{address}");
        ok = ok && hodl && strcmp(json_get_str(json_get(hodl,
                                    "response_schema")),
                                  "zcl.hodl_wave.v1") == 0;
        ok = ok && bootstrap &&
             strcmp(json_get_str(json_get(bootstrap, "response_schema")),
                    "zcl.bootstrap_status.v1") == 0;
        ok = ok && bootstrap &&
             strcmp(json_get_str(json_get(bootstrap, "crud_name")),
                    "read_singleton") == 0;
        ok = ok && bootstrap &&
             strcmp(json_get_str(json_get(bootstrap, "freshness")),
                    "network_bootstrap") == 0;
        const struct json_value *bootstrap_binding =
            bootstrap ? json_get(bootstrap, "service_binding") : NULL;
        ok = ok && bootstrap &&
             strcmp(json_get_str(json_get(bootstrap, "service_contract")),
                    "bootstrap") == 0;
        ok = ok && bootstrap &&
             strcmp(json_get_str(json_get(bootstrap,
                                          "service_catalog_route")),
                    "/api/v1/service-catalog/bootstrap") == 0;
        ok = ok && bootstrap &&
             strcmp(json_get_str(json_get(bootstrap,
                                          "service_operation_id")),
                    "bootstrap.read_bootstrap_status") == 0;
        ok = ok && bootstrap &&
             strcmp(json_get_str(json_get(bootstrap,
                                          "service_operation_route")),
                    "/api/v1/service-operations/"
                    "bootstrap.read_bootstrap_status") == 0;
        ok = ok && bootstrap_binding &&
             strcmp(json_get_str(json_get(bootstrap_binding,
                                          "operation_id")),
                    "bootstrap.read_bootstrap_status") == 0;
        ok = ok && bootstrap_binding &&
             strcmp(json_get_str(json_get(bootstrap_binding,
                                          "agent_preferred_interface")),
                    "rest") == 0;
        ok = ok && bootstrap_binding &&
             json_get_bool(json_get(bootstrap_binding, "public_read"));
        ok = ok && bootstrap && !json_get_bool(json_get(bootstrap,
                                                        "private"));
        ok = ok && legacy_bootstrap &&
             strcmp(json_get_str(json_get(legacy_bootstrap,
                                          "legacy_alias_of")),
                    "/api/v1/bootstrap") == 0;
        ok = ok && legacy_bootstrap &&
             strcmp(json_get_str(json_get(legacy_bootstrap,
                                          "service_operation_id")),
                    "bootstrap.read_bootstrap_status") == 0;
        ok = ok && hodl && strcmp(json_get_str(json_get(hodl,
                                    "error_schema")),
                                  "zcl.rest_error.v1") == 0;
        ok = ok && hodl && strcmp(json_get_str(json_get(hodl,
                                    "crud_operation")),
                                  "read") == 0;
        ok = ok && hodl && strcmp(json_get_str(json_get(hodl,
                                    "resource_scope")),
                                  "singleton") == 0;
        ok = ok && hodl && strcmp(json_get_str(json_get(hodl,
                                    "crud_name")),
                                  "read_singleton") == 0;
        ok = ok && hodl && json_get_bool(json_get(hodl,
                                                  "freshness_scoped"));
        ok = ok && wallet && json_get_bool(json_get(wallet, "private"));
        ok = ok && wallet && strcmp(json_get_str(json_get(wallet, "auth")),
                                    "operator_private") == 0;
        ok = ok && wallet && strcmp(json_get_str(json_get(wallet,
                                    "auth_policy")),
                                    "operator_private") == 0;
        ok = ok && hodl && json_get_bool(json_get(hodl,
                                    "gateway_auth_compatible"));
        ok = ok && hodl && strcmp(json_get_str(json_get(hodl,
                                    "preferred_service_auth")),
                                  "hash512_sha3_gost_commitments") == 0;
        const struct json_value *hodl_telemetry =
            json_get(hodl, "telemetry");
        ok = ok && hodl_telemetry &&
             strcmp(json_get_str(json_get(hodl_telemetry, "counter")),
                    "zcl_api_requests_total") == 0;
        ok = ok && hodl_telemetry &&
             strcmp(json_get_str(json_get(hodl_telemetry,
                                          "latency_histogram")),
                    "zcl_api_request_duration_seconds") == 0;
        const struct json_value *hodl_crypto =
            json_get(hodl, "crypto_policy");
        ok = ok && hodl_crypto &&
             strcmp(json_get_str(json_get(hodl_crypto,
                                          "service_auth_primary_digest")),
                    "SHA3-512") == 0;
        ok = ok && hodl_crypto &&
             strcmp(json_get_str(json_get(hodl_crypto,
                                          "service_auth_secondary_digest")),
                    "GOST R 34.11-2012-512") == 0;
        ok = ok && hodl_crypto &&
             json_get_int(json_get(hodl_crypto, "hash_output_bits")) == 512;
        ok = ok && hodl_crypto &&
             json_get_bool(json_get(hodl_crypto, "requires_all_digests"));
        ok = ok && hodl_crypto &&
             !json_get_bool(json_get(hodl_crypto,
                                     "signature_scheme_claimed"));
        ok = ok && zslp && api_test_contract_has_query(zslp, "limit");
        ok = ok && zslp && json_get_bool(json_get(zslp, "pagination"));
        ok = ok && zslp && strcmp(json_get_str(json_get(zslp,
                                    "crud_name")),
                                  "read_collection") == 0;
        ok = ok && zslp &&
             strcmp(json_get_str(json_get(zslp,
                                    "application_protocol")),
                    "zslp") == 0;
        ok = ok && zslp &&
             strcmp(json_get_str(json_get(zslp, "base_layer")),
                    "zclassic_l1") == 0;
        ok = ok && zslp &&
             strcmp(json_get_str(json_get(zslp, "protocol_family")),
                    "token") == 0;
        ok = ok && zslp &&
             strcmp(json_get_str(json_get(zslp, "protocol_anchor_kind")),
                    "op_return") == 0;
        ok = ok && zslp &&
             api_test_array_has_str(json_get(zslp, "protocol_crud"),
                                    "read_collection");
        ok = ok && zslp &&
             strcmp(json_get_str(json_get(zslp,
                                    "protocol_construction_status")),
                    "transaction_builders_active") == 0;
        ok = ok && zslp &&
             strcmp(json_get_str(json_get(zslp,
                                    "mutation_authority")),
                    "operator_wallet_transaction") == 0;
        ok = ok && zslp &&
             strcmp(json_get_str(json_get(zslp, "layer")),
                    "zclassic23_application_layer") == 0;
        ok = ok && zslp &&
             strcmp(json_get_str(json_get(zslp, "source_anchor")),
                    "OP_RETURN token transactions") == 0;
        ok = ok && protocols_route &&
             strcmp(json_get_str(json_get(protocols_route,
                                    "response_schema")),
                    "zcl.application_protocols.index.v2") == 0;
        ok = ok && protocols_route &&
             strcmp(json_get_str(json_get(protocols_route,
                                    "application_protocol")),
                    "zlsp") == 0;
        ok = ok && protocols_route &&
             strcmp(json_get_str(json_get(protocols_route,
                                    "protocol_family")),
                    "application_protocol_framework") == 0;
        ok = ok && service_catalog_route &&
             strcmp(json_get_str(json_get(service_catalog_route,
                                    "response_schema")),
                    "zcl.service_catalog.v2") == 0;
        ok = ok && service_catalog_route &&
             strcmp(json_get_str(json_get(service_catalog_route,
                                    "crud_name")),
                    "read_singleton") == 0;
        ok = ok && service_catalog_route &&
             strcmp(json_get_str(json_get(service_catalog_route,
                                    "freshness")),
                    "static") == 0;
        ok = ok && service_catalog_show &&
             strcmp(json_get_str(json_get(service_catalog_show,
                                    "response_schema")),
                    "zcl.service_contract.v2") == 0;
        ok = ok && service_catalog_show &&
             strcmp(json_get_str(json_get(service_catalog_show,
                                    "crud_name")),
                    "read_item") == 0;
        ok = ok && service_catalog_show &&
             api_test_contract_has_id_param(service_catalog_show, "service");
        ok = ok && service_operations_route &&
             strcmp(json_get_str(json_get(service_operations_route,
                                    "response_schema")),
                    "zcl.service_operations.index.v2") == 0;
        ok = ok && service_operations_route &&
             strcmp(json_get_str(json_get(service_operations_route,
                                    "crud_name")),
                    "read_collection") == 0;
        ok = ok && service_operations_route &&
             api_test_contract_has_query(service_operations_route, "service");
        ok = ok && service_operations_route &&
             api_test_contract_has_query(service_operations_route,
                                         "write_safety");
        ok = ok && service_operations_route &&
             api_test_contract_has_query(service_operations_route,
                                         "preferred_interface");
        ok = ok && service_operations_route &&
             api_test_contract_has_query(service_operations_route, "status");
        ok = ok && service_operations_route &&
             api_test_contract_has_query(service_operations_route, "surface");
        const struct json_value *service_operations_filter_contract =
            service_operations_route ?
            json_get(service_operations_route, "filter_contract") : NULL;
        const struct json_value *service_operations_allowed =
            service_operations_filter_contract ?
            json_get(service_operations_filter_contract, "allowed_filters") :
            NULL;
        ok = ok && service_operations_filter_contract &&
             strcmp(json_get_str(json_get(
                        service_operations_filter_contract, "schema")),
                    "zcl.query_filter_contract.v1") == 0;
        ok = ok && service_operations_filter_contract &&
             json_get_bool(json_get(service_operations_filter_contract,
                                    "unknown_filters_error"));
        ok = ok && service_operations_allowed &&
             strcmp(json_get_str(json_get(service_operations_allowed,
                                          "interface")),
                    "alias_for_preferred_interface") == 0;
        ok = ok && service_operation_show &&
             strcmp(json_get_str(json_get(service_operation_show,
                                    "response_schema")),
                    "zcl.service_operation.v2") == 0;
        ok = ok && service_operation_show &&
             strcmp(json_get_str(json_get(service_operation_show,
                                    "crud_name")),
                    "read_item") == 0;
        ok = ok && service_operation_show &&
             api_test_contract_has_id_param(service_operation_show,
                                            "operation_id");
        ok = ok && protocol_show &&
             strcmp(json_get_str(json_get(protocol_show, "crud_name")),
                    "read_item") == 0;
        ok = ok && protocol_show &&
             api_test_contract_has_id_param(protocol_show, "name");
        ok = ok && events && api_test_contract_has_query(events, "limit");
        ok = ok && events && api_test_contract_has_query(events, "type");
        ok = ok && events && strcmp(json_get_str(json_get(events,
                                    "resource_scope")),
                                    "collection") == 0;
        ok = ok && events && strcmp(json_get_str(json_get(events,
                                    "freshness")),
                                    "event_projection") == 0;
        ok = ok && supply && strcmp(json_get_str(json_get(supply,
                                    "response_schema")),
                                    "zcl.supply.v1") == 0;
        ok = ok && supply && strcmp(json_get_str(json_get(supply,
                                    "compat_response_schema")),
                                    "zcl.supply_legacy_number.v1") == 0;
        ok = ok && block_show && json_get_bool(json_get(block_show,
                                                        "canonical"));
        ok = ok && block_show &&
             strcmp(json_get_str(json_get(block_show, "crud_name")),
                    "read_item") == 0;
        ok = ok && block_show &&
             api_test_contract_has_id_param(block_show, "height_or_hash");
        ok = ok && legacy_block_show &&
             strcmp(json_get_str(json_get(legacy_block_show,
                                          "legacy_alias_of")),
                    "/api/v1/blocks/{height_or_hash}") == 0;
        ok = ok && tx_show && strcmp(json_get_str(json_get(tx_show,
                                    "response_schema")),
                                    "zcl.transactions.show.v1") == 0;
        ok = ok && legacy_tx_show &&
             strcmp(json_get_str(json_get(legacy_tx_show,
                                          "legacy_alias_of")),
                    "/api/v1/transactions/{txid}") == 0;
        ok = ok && address_show &&
             strcmp(json_get_str(json_get(address_show, "freshness")),
                    "utxo_projection") == 0;
        ok = ok && legacy_address_show &&
             strcmp(json_get_str(json_get(legacy_address_show,
                                          "legacy_alias_of")),
                    "/api/v1/addresses/{address}") == 0;
        ok = ok && names && json_get_bool(json_get(names, "canonical"));
        ok = ok && names && strcmp(json_get_str(json_get(names,
                                    "resource_scope")),
                                   "item") == 0;
        ok = ok && names_services &&
             strcmp(json_get_str(json_get(names_services,
                                    "response_schema")),
                    "zcl.names.service_directory.v1") == 0;
        ok = ok && names_services &&
             strcmp(json_get_str(json_get(names_services,
                                    "crud_name")),
                    "read_subcollection") == 0;
        ok = ok && names_services &&
             strcmp(json_get_str(json_get(names_services,
                                    "resource_scope")),
                    "subcollection") == 0;
        ok = ok && names_services &&
             strcmp(json_get_str(json_get(names_services,
                                    "application_protocol")),
                    "znam") == 0;
        ok = ok && names_services &&
             api_test_contract_has_id_param(names_services, "name");
        const struct json_value *names_services_path_contract =
            names_services ? json_get(names_services,
                                      "path_param_contract") : NULL;
        const struct json_value *names_services_path_params =
            names_services_path_contract ?
            json_get(names_services_path_contract, "params") : NULL;
        const struct json_value *names_services_name_contract =
            names_services_path_params ?
            json_get(names_services_path_params, "name") : NULL;
        ok = ok && names_services_path_contract &&
             strcmp(json_get_str(json_get(names_services_path_contract,
                                          "schema")),
                    "zcl.path_param_contract.v1") == 0;
        ok = ok && names_services_name_contract &&
             strcmp(json_get_str(json_get(names_services_name_contract,
                                          "contract_name")),
                    "znam_name") == 0;
        ok = ok && names_services_name_contract &&
             strcmp(json_get_str(json_get(names_services_name_contract,
                                          "validator")),
                    "znam_validate_name") == 0;
        ok = ok && names_services_name_contract &&
             json_get_int(json_get(names_services_name_contract,
                                   "max_length")) == 63;
        ok = ok && names_services &&
             api_test_contract_has_query(names_services, "service");
        ok = ok && names_services &&
             api_test_contract_has_query(names_services, "service_contract");
        ok = ok && names_services &&
             api_test_contract_has_query(names_services, "transport");
        ok = ok && names_services &&
             api_test_contract_has_query(names_services, "endpoint_kind");
        ok = ok && names_services &&
             api_test_contract_has_query(names_services, "valid");
        ok = ok && names_services &&
             api_test_contract_has_query(names_services, "endpoint_only");
        const struct json_value *names_services_filter_contract =
            names_services ? json_get(names_services, "filter_contract") :
            NULL;
        const struct json_value *names_services_allowed =
            names_services_filter_contract ?
            json_get(names_services_filter_contract, "allowed_filters") :
            NULL;
        ok = ok && names_services_filter_contract &&
             strcmp(json_get_str(json_get(names_services_filter_contract,
                                          "schema")),
                    "zcl.query_filter_contract.v1") == 0;
        ok = ok && names_services_filter_contract &&
             json_get_bool(json_get(names_services_filter_contract,
                                    "unknown_filters_error"));
        ok = ok && names_services_allowed &&
             strcmp(json_get_str(json_get(names_services_allowed,
                                          "contract")),
                    "alias_for_service_contract") == 0;
        const struct json_value *names_services_binding =
            names_services ? json_get(names_services, "service_binding")
                           : NULL;
        ok = ok && names_services &&
             strcmp(json_get_str(json_get(names_services,
                                          "service_contract")),
                    "znam_names") == 0;
        ok = ok && names_services &&
             strcmp(json_get_str(json_get(names_services,
                                          "service_catalog_route")),
                    "/api/v1/service-catalog/znam_names") == 0;
        ok = ok && names_services &&
             strcmp(json_get_str(json_get(names_services,
                                          "service_operation_id")),
                    "znam_names.resolve_service_directory") == 0;
        ok = ok && names_services &&
             strcmp(json_get_str(json_get(names_services,
                                          "service_operation_route")),
                    "/api/v1/service-operations/"
                    "znam_names.resolve_service_directory") == 0;
        ok = ok && names_services_binding &&
             strcmp(json_get_str(json_get(names_services_binding,
                                          "output_schema")),
                    "zcl.names.service_directory.v1") == 0;
        ok = ok && names_services_binding &&
             strcmp(json_get_str(json_get(names_services_binding,
                                          "authority")),
                    "confirmed_chain_projection") == 0;
        ok = ok && names &&
             strcmp(json_get_str(json_get(names,
                                    "application_protocol")),
                    "znam") == 0;
        ok = ok && names &&
             api_test_array_has_str(json_get(names,
                                             "protocol_object_types"),
                                    "service_record");
        ok = ok && names &&
             api_test_array_has_str(json_get(names,
                                             "protocol_ux_surfaces"),
                                    "identity_profile");
        ok = ok && names &&
             strcmp(json_get_str(json_get(names, "reorg_model")),
                    "rebuild_name_state_from_confirmed_chain_after_disconnect")
             == 0;
        ok = ok && names &&
             strstr(json_get_str(json_get(names, "privacy_model")),
                    "public") != NULL;
        ok = ok && names && api_test_contract_has_id_param(names, "name");
        const struct json_value *names_path_contract =
            names ? json_get(names, "path_param_contract") : NULL;
        const struct json_value *names_path_name =
            names_path_contract ?
            json_get(json_get(names_path_contract, "params"), "name") :
            NULL;
        ok = ok && names_path_contract &&
             strcmp(json_get_str(json_get(names_path_contract, "schema")),
                    "zcl.path_param_contract.v1") == 0;
        ok = ok && names_path_name &&
             strcmp(json_get_str(json_get(names_path_name, "pattern")),
                    "^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$") == 0;
        ok = ok && legacy_name &&
             !json_get_bool(json_get(legacy_name, "canonical"));
        const struct json_value *legacy_name_path_contract =
            legacy_name ? json_get(legacy_name, "path_param_contract") :
            NULL;
        const struct json_value *legacy_name_path_name =
            legacy_name_path_contract ?
            json_get(json_get(legacy_name_path_contract, "params"), "name") :
            NULL;
        ok = ok && legacy_name_path_name &&
             strcmp(json_get_str(json_get(legacy_name_path_name,
                                          "validator")),
                    "znam_validate_name") == 0;
        ok = ok && legacy_name &&
             strcmp(json_get_str(json_get(legacy_name, "legacy_alias_of")),
                    "/api/v1/names/{name}") == 0;
        ok = ok && swap_chains && json_get_bool(json_get(swap_chains,
                                                         "canonical"));
        ok = ok && swap_chains &&
             strcmp(json_get_str(json_get(swap_chains,
                                    "application_protocol")),
                    "script_contracts") == 0;
        ok = ok && swap_chains &&
             strstr(json_get_str(json_get(swap_chains,
                                          "source_anchor")),
                    "HTLC atomic swaps") != NULL;
        ok = ok && swap_chains &&
             api_test_array_has_str(json_get(swap_chains,
                                             "protocol_object_types"),
                                    "contract_template");
        ok = ok && swap_chains &&
             strstr(json_get_str(json_get(swap_chains, "crypto_model")),
                    "hashlocks_timelocks") != NULL;
        ok = ok && legacy_swap_chains &&
             strcmp(json_get_str(json_get(legacy_swap_chains,
                                          "legacy_alias_of")),
                    "/api/v1/swaps/chains") == 0;
        ok = ok && strcmp(json_get_str(json_get(json_get(&root,
                                                "drilldown"),
                                                "bootstrap")),
                          "/api/v1/bootstrap") == 0;
        ok = ok && strcmp(json_get_str(json_get(json_get(&root,
                                                "drilldown"),
                                                "service_catalog")),
                          "/api/v1/service-catalog") == 0;
        ok = ok && strcmp(json_get_str(json_get(json_get(&root,
                                                "drilldown"),
                                                "service_operations")),
                          "/api/v1/service-operations") == 0;
        ok = ok && strcmp(json_get_str(json_get(json_get(&root, "cli"),
                                                "api_command")),
                          "z23 api") == 0;
        ok = ok && strcmp(json_get_str(json_get(json_get(&root, "cli"),
                                                "app_protocols_command")),
                          "z23 appprotocols") == 0;
        ok = ok && strcmp(json_get_str(json_get(json_get(&root, "cli"),
                                                "service_catalog_command")),
                          "z23 servicecatalog") == 0;
        ok = ok && strcmp(json_get_str(json_get(json_get(&root, "cli"),
                                                "service_operations_command")),
                          "z23 serviceoperations [operation_id|key=value...]") == 0;
        ok = ok && strcmp(json_get_str(json_get(json_get(&root, "cli"),
                                                "first_command")),
                          "z23 agent") == 0;
        ok = ok && strcmp(json_get_str(json_get(json_get(&root, "cli"),
                                                "drilldown_command")),
                          "z23 healthcheck") == 0;
        ok = ok && strcmp(json_get_str(json_get(json_get(&root, "cli"),
                                                "milestone_command")),
                          "z23 milestone") == 0;
        ok = ok && strcmp(json_get_str(json_get(json_get(&root, "cli"),
                                                "refold_command")),
                          "z23 refold") == 0;
        ok = ok && json_get(json_get(&root, "cli"),
                            "compat_command") == NULL;
        json_free(&root);

        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    return failures;
}
