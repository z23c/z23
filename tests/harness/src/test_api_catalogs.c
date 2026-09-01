/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * API catalog resources: bootstrap status, the protocol registry overlay
 * contracts, and the service catalog of sovereign UX operations.
 */

#include "test/api_test_fixtures.h"

int api_catalog_focused_tests(void)
{
    int failures = 0;

    printf("api: bootstrap status is a first-class REST resource... ");
    {
        static uint8_t bootstrap_resp[262144];

        rpc_net_set_connman(NULL);
        rpc_net_set_boot_context(NULL, NULL);
        reducer_frontier_provable_tip_reset();

        size_t n = api_handle_request("GET", "/api/v1/bootstrap", NULL, 0,
                                      bootstrap_resp,
                                      sizeof(bootstrap_resp));
        const char *body = api_test_body(bootstrap_resp, n,
                                         sizeof(bootstrap_resp));
        struct json_value root;
        json_init(&root);
        bool ok = n > 0 && body && json_read(&root, body, strlen(body));
        ok = ok && strcmp(json_get_str(json_get(&root, "schema")),
                          "zcl.bootstrap_status.v1") == 0;
        ok = ok && json_get_int(json_get(&root, "schema_version")) == 1;
        ok = ok && !json_get_bool(json_get(&root, "ok"));
        ok = ok && strcmp(json_get_str(json_get(&root, "readiness")),
                          "blocked") == 0;
        ok = ok && strcmp(json_get_str(json_get(&root,
                          "fresh_node_next_action")),
                          "fix_named_blockers_before_advertising_bootstrap") == 0;
        ok = ok && !json_get_bool(json_get(&root,
                                           "serving_p2p_bootstrap"));
        ok = ok && !json_get_bool(json_get(&root,
                                           "zclassic23_fast_sync_compatible"));
        ok = ok && json_get(&root, "binary") != NULL;
        ok = ok && strcmp(json_get_str(json_get(json_get(&root, "binary"),
                                                "build_commit")),
                          zcl_build_commit()) == 0;
        const char *subver =
            json_get_str(json_get(json_get(&root, "binary"),
                                  "advertised_subver"));
        ok = ok && subver && subver[0] != '\0';
        ok = ok && json_get_int(json_get(json_get(&root, "p2p"),
                                         "protocolversion")) > 0;
        ok = ok && strcmp(json_get_str(json_get(json_get(&root,
                          "legacy_p2p_bootstrap"), "schema")),
                          "zcl.bootstrap.p2p.v1") == 0;
        ok = ok && strcmp(json_get_str(json_get(json_get(&root,
                          "beta6_snapshot_bootstrap"), "schema")),
                          "zclassicd.bootstrap.snapshot.v3") == 0;
        const struct json_value *zcl23_bootstrap =
            json_get(&root, "zclassic23_bootstrap");
        ok = ok && zcl23_bootstrap &&
             strcmp(json_get_str(json_get(zcl23_bootstrap, "schema")),
                    "zcl.bootstrap.zclassic23.v1") == 0;
        ok = ok && !json_get_bool(json_get(zcl23_bootstrap, "serving"));
        ok = ok && !json_get_bool(json_get(zcl23_bootstrap,
                         "preferred_for_fresh_zclassic23"));
        ok = ok && strcmp(json_get_str(json_get(zcl23_bootstrap,
                         "route_preference")),
                          "direct_p2p_then_znam_onion_fallback") == 0;
        ok = ok && strcmp(json_get_str(json_get(zcl23_bootstrap,
                         "endpoint_record_schema")),
                          "zcl.names.service_record.v1") == 0;
        ok = ok && api_test_array_has_str(json_get(zcl23_bootstrap,
                         "fresh_node_flow"),
                         "resolve_znam_service_directory_if_direct_p2p_fails");
        ok = ok && strcmp(json_get_str(json_get(json_get(&root,
                          "snapshot_loader"), "schema")),
                          "zcl.snapshot_loader.v1") == 0;
        ok = ok && strcmp(json_get_str(json_get(json_get(json_get(&root,
                          "snapshot_loader"), "authority"), "schema")),
                          "zcl.snapshot_loader_authority.v1") == 0;
        ok = ok && !json_get_bool(json_get(json_get(json_get(&root,
                          "snapshot_loader"), "authority"),
                          "progress_store_open"));
        ok = ok && api_test_array_has_str(json_get(&root, "blockers"),
                                          "p2p_not_initialized");
        ok = ok && api_test_array_has_str(json_get(&root, "blockers"),
                                          "provable_tip_not_published");
        ok = ok && strcmp(json_get_str(json_get(&root,
                                                "source_projection")),
                          "network_bootstrap") == 0;
        json_free(&root);

        n = api_handle_request("GET", "/api/v1/bootstrapstatus", NULL, 0,
                               bootstrap_resp, sizeof(bootstrap_resp));
        body = api_test_body(bootstrap_resp, n, sizeof(bootstrap_resp));
        json_init(&root);
        ok = ok && n > 0 && body && json_read(&root, body, strlen(body));
        ok = ok && strcmp(json_get_str(json_get(&root, "schema")),
                          "zcl.bootstrap_status.v1") == 0;
        json_free(&root);

        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("api: protocol registry endpoints expose overlay contracts... ");
    {
        static uint8_t protocols_resp[262144];
        size_t n = api_handle_request("GET", "/api/v1/protocols", NULL, 0,
                                      protocols_resp, sizeof(protocols_resp));
        const char *body = api_test_body(protocols_resp, n,
                                         sizeof(protocols_resp));
        struct json_value root;
        json_init(&root);
        bool ok = n > 0 && body && json_read(&root, body, strlen(body));
        ok = ok && strcmp(json_get_str(json_get(&root, "schema")),
                          "zcl.application_protocols.index.v2") == 0;
        ok = ok && strcmp(json_get_str(json_get(&root, "base_layer")),
                          "zclassic_l1") == 0;
        ok = ok && strcmp(json_get_str(json_get(&root, "service_layer")),
                          "zclassic23_application_layer") == 0;
        const struct json_value *protocols = json_get(&root, "protocols");
        ok = ok && protocols && json_get_int(json_get(&root,
                          "protocol_count")) == (int64_t)json_size(protocols);
        const struct json_value *zslp =
            api_test_find_named(protocols, "zslp");
        const struct json_value *znam =
            api_test_find_named(protocols, "znam");
        const struct json_value *market =
            api_test_find_named(protocols, "market");
        ok = ok && zslp &&
             api_test_array_has_str(json_get(zslp, "crud_capabilities"),
                                    "read_collection");
        ok = ok && zslp &&
             strcmp(json_get_str(json_get(zslp, "anchor_kind")),
                    "op_return") == 0;
        ok = ok && zslp &&
             api_test_array_has_str(json_get(zslp, "object_types"),
                                    "token_transfer");
        ok = ok && znam &&
             api_test_array_has_str(json_get(znam, "ux_surfaces"),
                                    "node_service_directory");
        ok = ok && market &&
             api_test_array_has_str(json_get(market, "object_types"),
                                    "content_descriptor");
        ok = ok && market &&
             strstr(json_get_str(json_get(market, "transport_model")),
                    "direct_p2p") != NULL;
        json_free(&root);

        n = api_handle_request("GET", "/api/v1/protocols/script_contracts",
                               NULL, 0, protocols_resp,
                               sizeof(protocols_resp));
        body = api_test_body(protocols_resp, n, sizeof(protocols_resp));
        json_init(&root);
        ok = ok && n > 0 && body && json_read(&root, body, strlen(body));
        ok = ok && strcmp(json_get_str(json_get(&root, "schema")),
                          "zcl.application_protocol_contract.v2") == 0;
        ok = ok && strcmp(json_get_str(json_get(&root, "name")),
                          "script_contracts") == 0;
        ok = ok && strcmp(json_get_str(json_get(&root, "anchor_kind")),
                          "standard_script") == 0;
        ok = ok && api_test_array_has_str(json_get(&root,
                          "crud_capabilities"), "construct_contract");
        ok = ok && strcmp(json_get_str(json_get(&root,
                          "construction_status")),
                          "htlc_builders_and_zcl_settlement_active") == 0;
        ok = ok && api_test_array_has_str(json_get(&root,
                          "object_types"), "contract_template");
        ok = ok && api_test_array_has_str(json_get(&root,
                          "ux_surfaces"), "script_preview");
        ok = ok && strstr(json_get_str(json_get(&root, "crypto_model")),
                          "legacy_valid_zclassic_script") != NULL;
        json_free(&root);

        n = api_handle_request("GET", "/api/v1/protocols/not_real",
                               NULL, 0, protocols_resp,
                               sizeof(protocols_resp));
        protocols_resp[n < sizeof(protocols_resp) ? n :
                       sizeof(protocols_resp) - 1] = '\0';
        ok = ok && strstr((char *)protocols_resp,
                          "HTTP/1.1 404 Not Found") != NULL;

        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("api: service catalog exposes sovereign UX contracts... ");
    {
        static uint8_t catalog_resp[262144];
        size_t n = api_handle_request("GET", "/api/v1/service-catalog",
                                      NULL, 0, catalog_resp,
                                      sizeof(catalog_resp));
        const char *body = api_test_body(catalog_resp, n,
                                         sizeof(catalog_resp));
        const char *catalog_body = body;
        struct json_value root;
        json_init(&root);
        bool ok = n > 0 && body && json_read(&root, body, strlen(body));
        ok = ok && strcmp(json_get_str(json_get(&root, "schema")),
                          "zcl.service_catalog.v2") == 0;
        ok = ok && strcmp(json_get_str(json_get(&root, "base_layer")),
                          "zclassic_l1") == 0;
        ok = ok && strcmp(json_get_str(json_get(&root, "service_layer")),
                          "zclassic23_application_layer") == 0;
        ok = ok && strcmp(json_get_str(json_get(&root,
                          "runtime_health_route")),
                          "/api/v1/services") == 0;
        ok = ok && strcmp(json_get_str(json_get(&root,
                          "application_protocols_route")),
                          "/api/v1/protocols") == 0;
        ok = ok && strcmp(json_get_str(json_get(&root, "member_route")),
                          "/api/v1/service-catalog/{service}") == 0;
        ok = ok && strcmp(json_get_str(json_get(&root, "operation_route")),
                          "/api/v1/service-operations/{operation_id}") == 0;
        ok = ok && strcmp(json_get_str(json_get(&root,
                          "operation_collection_route")),
                          "/api/v1/service-operations") == 0;
        ok = ok && strcmp(json_get_str(json_get(&root,
                          "operation_schema")),
                          "zcl.service_operation.v2") == 0;
        ok = ok && strcmp(json_get_str(json_get(&root,
                          "runtime_probe_schema")),
                          "zcl.service_runtime_probe.v1") == 0;
        ok = ok && strstr(json_get_str(json_get(&root,
                          "consensus_boundary")),
                          "legacy consensus") != NULL;
        const struct json_value *ux = json_get(&root, "sovereign_ux");
        ok = ok && ux &&
             strcmp(json_get_str(json_get(ux, "schema")),
                    "zcl.sovereign_ux_contract.v2") == 0;
        ok = ok && ux &&
             strcmp(json_get_str(json_get(ux, "base_layer")),
                    "zclassic_l1") == 0;
        ok = ok && ux &&
             api_test_array_has_str(json_get(ux, "flow"),
                                    "resolve_znam_name");
        ok = ok && ux &&
             api_test_array_has_str(json_get(ux, "flow"),
                                    "read_name_service_directory");
        ok = ok && ux &&
             api_test_array_has_str(json_get(ux, "flow"),
                                    "prefer_direct_p2p_when_handshaked");
        ok = ok && ux &&
             strcmp(json_get_str(json_get(json_get(ux, "routes"),
                                          "service_catalog")),
                    "/api/v1/service-catalog") == 0;
        ok = ok && ux &&
             strcmp(json_get_str(json_get(json_get(ux, "routes"), "names")),
                    "/api/v1/names/{name}") == 0;
        ok = ok && ux &&
             strcmp(json_get_str(json_get(json_get(ux, "routes"),
                                          "name_services")),
                    "/api/v1/names/{name}/services") == 0;
        const struct json_value *services = json_get(&root, "services");
        ok = ok && services && services->type == JSON_ARR &&
             json_get_int(json_get(&root, "service_count")) ==
             (int64_t)json_size(services);
        const struct json_value *runtime_probes =
            json_get(&root, "runtime_probes");
        ok = ok && runtime_probes && runtime_probes->type == JSON_ARR &&
             json_get_int(json_get(&root, "runtime_probe_count")) ==
             (int64_t)json_size(runtime_probes);
        ok = ok && runtime_probes &&
             json_size(runtime_probes) == json_size(services);
        const struct json_value *bootstrap_matrix_probe =
            api_test_find_str_field(runtime_probes, "service", "bootstrap");
        ok = ok && bootstrap_matrix_probe &&
             strcmp(json_get_str(json_get(bootstrap_matrix_probe,
                                          "route")),
                    "/api/v1/bootstrap") == 0;
        ok = ok && bootstrap_matrix_probe &&
             strcmp(json_get_str(json_get(bootstrap_matrix_probe,
                                          "operation_id")),
                    "bootstrap.read_bootstrap_status") == 0;
        ok = ok && bootstrap_matrix_probe &&
             strcmp(json_get_str(json_get(bootstrap_matrix_probe,
                                          "service_catalog_route")),
                    "/api/v1/service-catalog/bootstrap") == 0;

        const struct json_value *bootstrap =
            api_test_find_named(services, "bootstrap");
        const struct json_value *names =
            api_test_find_named(services, "znam_names");
        const struct json_value *onion =
            api_test_find_named(services, "onion_directory");
        const struct json_value *files =
            api_test_find_named(services, "file_services");
        const struct json_value *contracts =
            api_test_find_named(services, "script_contracts");
        ok = ok && bootstrap &&
             strcmp(json_get_str(json_get(bootstrap, "rest_collection")),
                    "/api/v1/bootstrap") == 0;
        ok = ok && bootstrap &&
             strcmp(json_get_str(json_get(bootstrap, "schema")),
                    "zcl.service_contract.v2") == 0;
        ok = ok && bootstrap &&
             strcmp(json_get_str(json_get(bootstrap, "self_route")),
                    "/api/v1/service-catalog/bootstrap") == 0;
        ok = ok && bootstrap &&
             api_test_array_has_str(json_get(bootstrap, "transports"),
                                    "p2p");
        ok = ok && bootstrap &&
             api_test_array_has_str(json_get(bootstrap,
                                             "depends_on_services"),
                                    "full_node");
        ok = ok && bootstrap &&
             strcmp(json_get_str(json_get(bootstrap, "read_model")),
                    "network_bootstrap_status_and_peer_projection") == 0;
        const struct json_value *bootstrap_probe =
            json_get(bootstrap, "runtime_probe");
        ok = ok && bootstrap_probe &&
             strcmp(json_get_str(json_get(bootstrap_probe, "schema")),
                    "zcl.service_runtime_probe.v1") == 0;
        ok = ok && bootstrap_probe &&
             strcmp(json_get_str(json_get(bootstrap_probe, "route")),
                    "/api/v1/bootstrap") == 0;
        ok = ok && bootstrap_probe &&
             strcmp(json_get_str(json_get(bootstrap_probe, "operation_id")),
                    "bootstrap.read_bootstrap_status") == 0;
        ok = ok && bootstrap_probe &&
             strcmp(json_get_str(json_get(bootstrap_probe,
                                          "operation_route")),
                    "/api/v1/service-operations/"
                    "bootstrap.read_bootstrap_status") == 0;
        ok = ok && bootstrap_probe &&
             strcmp(json_get_str(json_get(bootstrap_probe,
                                          "expected_schema")),
                    "zcl.bootstrap_status.v1") == 0;
        ok = ok && bootstrap_probe &&
             strcmp(json_get_str(json_get(bootstrap_probe, "freshness")),
                    "network_bootstrap") == 0;
        ok = ok && bootstrap_probe &&
             strstr(json_get_str(json_get(bootstrap_probe,
                                          "success_signal")),
                    "zclassic23_fast_sync_compatible") != NULL;
        ok = ok && bootstrap_probe &&
             strcmp(json_get_str(json_get(bootstrap_probe,
                                          "failure_next_action")),
                    "inspect_peer_bootstrap_readiness") == 0;
        ok = ok && !json_get_bool(json_get(bootstrap_probe,
                                           "operator_private"));
        const struct json_value *bootstrap_summary =
            json_get(bootstrap, "operation_summary");
        ok = ok && bootstrap_summary &&
             json_get_int(json_get(bootstrap_summary, "operation_count")) == 3;
        ok = ok && bootstrap_summary &&
             json_get_int(json_get(bootstrap_summary,
                                   "public_read_count")) == 2;
        ok = ok && bootstrap_summary &&
             json_get_int(json_get(bootstrap_summary,
                                   "operator_private_count")) == 1;
        ok = ok && bootstrap_summary &&
             json_get_int(json_get(bootstrap_summary,
                                   "destructive_count")) == 0;
        ok = ok && bootstrap_summary &&
             json_get_int(json_get(bootstrap_summary,
                                   "preferred_rest_count")) == 2;
        ok = ok && bootstrap_summary &&
             json_get_int(json_get(bootstrap_summary,
                                   "preferred_rpc_count")) == 1;
        const struct json_value *bootstrap_status_op =
            api_test_find_str_field(json_get(bootstrap, "operations"),
                                    "operation",
                                    "read_bootstrap_status");
        ok = ok && bootstrap_status_op &&
             strcmp(json_get_str(json_get(bootstrap_status_op, "schema")),
                    "zcl.service_operation.v2") == 0;
        ok = ok && bootstrap_status_op &&
             strcmp(json_get_str(json_get(bootstrap_status_op,
                                          "operation_id")),
                    "bootstrap.read_bootstrap_status") == 0;
        ok = ok && bootstrap_status_op &&
             strcmp(json_get_str(json_get(bootstrap_status_op, "self_route")),
                    "/api/v1/service-operations/bootstrap.read_bootstrap_status")
             == 0;
        ok = ok && bootstrap_status_op &&
             strcmp(json_get_str(json_get(bootstrap_status_op,
                                          "service_catalog_route")),
                    "/api/v1/service-catalog/bootstrap") == 0;
        ok = ok && bootstrap_status_op &&
             strcmp(json_get_str(json_get(bootstrap_status_op, "rest_route")),
                    "/api/v1/bootstrap") == 0;
        /* rpc_method is the native RPC/CLI surface for this operation. */
        ok = ok && bootstrap_status_op &&
             strcmp(json_get_str(json_get(bootstrap_status_op,
                                          "rpc_method")),
                    "bootstrapstatus") == 0;
        ok = ok && bootstrap_status_op &&
             strcmp(json_get_str(json_get(bootstrap_status_op,
                                          "execution_surface")),
                    "rest") == 0;
        ok = ok && bootstrap_status_op &&
             strcmp(json_get_str(json_get(bootstrap_status_op,
                                          "write_safety")),
                    "public_read_only") == 0;
        ok = ok && bootstrap_status_op &&
             strcmp(json_get_str(json_get(bootstrap_status_op,
                                          "agent_preferred_interface")),
                    "rest") == 0;
        ok = ok && bootstrap_status_op &&
             strcmp(json_get_str(json_get(bootstrap_status_op,
                                          "agent_next_step")),
                    "call_rest_route_and_validate_output_schema") == 0;
        ok = ok && json_get_bool(json_get(bootstrap_status_op,
                                          "rest_callable"));
        ok = ok && json_get_bool(json_get(bootstrap_status_op,
                                          "rpc_callable"));
        const struct json_value *bootstrap_peers_op =
            api_test_find_str_field(json_get(bootstrap, "operations"),
                                    "operation", "list_peer_projection");
        ok = ok && bootstrap_peers_op &&
             strcmp(json_get_str(json_get(bootstrap_peers_op,
                                          "operation_id")),
                    "bootstrap.list_peer_projection") == 0;
        ok = ok && bootstrap_peers_op &&
             strcmp(json_get_str(json_get(bootstrap_peers_op, "rest_route")),
                    "/api/v1/peers") == 0;
        ok = ok && bootstrap_peers_op &&
             strcmp(json_get_str(json_get(bootstrap_peers_op,
                                          "output_schema")),
                    "zcl.peers.index.v1") == 0;
        ok = ok && bootstrap_peers_op &&
             json_get_bool(json_get(bootstrap_peers_op, "rest_callable"));
        ok = ok && bootstrap_peers_op &&
             !json_get_bool(json_get(bootstrap_peers_op, "rpc_callable"));
        ok = ok && names &&
             strcmp(json_get_str(json_get(names, "application_protocol")),
                    "znam") == 0;
        ok = ok && names &&
             api_test_array_has_str(json_get(names, "crud_capabilities"),
                                    "construct_transaction");
        ok = ok && names &&
             api_test_array_has_str(json_get(names, "crud_capabilities"),
                                    "read_subcollection");
        ok = ok && names &&
             api_test_array_has_str(json_get(names, "depends_on_services"),
                                    "full_node");
        ok = ok && names &&
             strcmp(json_get_str(json_get(names, "write_model")),
                    "construct_znam_op_return_transactions") == 0;
        ok = ok && names &&
             strstr(json_get_str(json_get(names, "verified_by")),
                    "op_return") != NULL;
        const struct json_value *name_services_op =
            api_test_find_str_field(json_get(names, "operations"),
                                    "operation",
                                    "resolve_service_directory");
        ok = ok && name_services_op &&
             strcmp(json_get_str(json_get(name_services_op,
                                          "operation_id")),
                    "znam_names.resolve_service_directory") == 0;
        ok = ok && name_services_op &&
             strcmp(json_get_str(json_get(name_services_op, "rest_route")),
                    "/api/v1/names/{name}/services") == 0;
        ok = ok && name_services_op &&
             strcmp(json_get_str(json_get(name_services_op,
                                          "crud_capability")),
                    "read_subcollection") == 0;
        ok = ok && name_services_op &&
             strcmp(json_get_str(json_get(name_services_op,
                                          "output_schema")),
                    "zcl.names.service_directory.v1") == 0;
        ok = ok && name_services_op &&
             strcmp(json_get_str(json_get(name_services_op,
                                          "agent_preferred_interface")),
                    "rest") == 0;
        ok = ok && name_services_op &&
             json_get_bool(json_get(name_services_op, "rest_callable"));
        ok = ok && name_services_op &&
             !json_get_bool(json_get(name_services_op, "rpc_callable"));
        const struct json_value *name_register_op =
            api_test_find_str_field(json_get(names, "operations"),
                                    "operation",
                                    "construct_name_register");
        ok = ok && name_register_op &&
             strcmp(json_get_str(json_get(name_register_op, "rpc_method")),
                    "name_register") == 0;
        ok = ok && name_register_op &&
             strcmp(json_get_str(json_get(name_register_op,
                                          "operation_id")),
                    "znam_names.construct_name_register") == 0;
        ok = ok && name_register_op &&
             strcmp(json_get_str(json_get(name_register_op, "self_route")),
                    "/api/v1/service-operations/"
                    "znam_names.construct_name_register") == 0;
        ok = ok && name_register_op &&
             strcmp(json_get_str(json_get(name_register_op,
                                          "service_catalog_route")),
                    "/api/v1/service-catalog/znam_names") == 0;
        ok = ok && name_register_op &&
             strcmp(json_get_str(json_get(name_register_op,
                                          "write_safety")),
                    "operator_private_destructive") == 0;
        ok = ok && name_register_op &&
             strcmp(json_get_str(json_get(name_register_op,
                                          "agent_preferred_interface")),
                    "rpc") == 0;
        ok = ok && name_register_op &&
             strcmp(json_get_str(json_get(name_register_op,
                                          "agent_next_step")),
                    "review_destructive_write_safety_then_call_rpc_method") == 0;
        ok = ok && !json_get_bool(json_get(name_register_op,
                                           "rest_callable"));
        ok = ok && json_get_bool(json_get(name_register_op,
                                          "rpc_callable"));
        ok = ok && name_register_op &&
             json_get_bool(json_get(name_register_op, "destructive"));
        ok = ok && onion &&
             strcmp(json_get_str(json_get(onion, "rest_collection")),
                    "/api/v1/onion/announcements") == 0;
        ok = ok && onion &&
             api_test_array_has_str(json_get(onion, "transports"),
                                    "onion");
        ok = ok && onion &&
             api_test_array_has_str(json_get(onion, "depends_on_services"),
                                    "znam_names");
        ok = ok && files &&
             strcmp(json_get_str(json_get(files, "rest_item")),
                    "/api/v1/files/{sha3}") == 0;
        ok = ok && files &&
             api_test_array_has_str(json_get(files, "object_types"),
                                    "chunk");
        ok = ok && contracts &&
             strcmp(json_get_str(json_get(contracts,
                                          "application_protocol")),
                    "script_contracts") == 0;
        ok = ok && contracts &&
             strstr(json_get_str(json_get(contracts, "trust_model")),
                    "no_consensus_extension") != NULL;
        json_free(&root);

        static uint8_t ops_resp[262144];
        n = api_handle_request("GET", "/api/v1/service-operations",
                               NULL, 0, ops_resp, sizeof(ops_resp));
        body = api_test_body(ops_resp, n, sizeof(ops_resp));
        json_init(&root);
        ok = ok && n > 0 && body && json_read(&root, body, strlen(body));
        ok = ok && strcmp(json_get_str(json_get(&root, "schema")),
                          "zcl.service_operations.index.v2") == 0;
        ok = ok && strcmp(json_get_str(json_get(&root, "catalog_route")),
                          "/api/v1/service-catalog") == 0;
        ok = ok && strcmp(json_get_str(json_get(&root,
                          "service_member_route")),
                          "/api/v1/service-catalog/{service}") == 0;
        ok = ok && strcmp(json_get_str(json_get(&root, "member_route")),
                          "/api/v1/service-operations/{operation_id}") == 0;
        ok = ok && strcmp(json_get_str(json_get(&root,
                          "operation_schema")),
                          "zcl.service_operation.v2") == 0;
        const struct json_value *operations = json_get(&root, "operations");
        ok = ok && operations && operations->type == JSON_ARR &&
             json_get_int(json_get(&root, "operation_count")) ==
             (int64_t)json_size(operations);
        const struct json_value *summary = json_get(&root, "summary");
        const struct json_value *service_facets =
            json_get(&root, "service_facets");
        const struct json_value *interface_facets =
            json_get(&root, "preferred_interface_facets");
        const struct json_value *safety_facets =
            json_get(&root, "write_safety_facets");
        ok = ok && summary &&
             json_get_int(json_get(summary, "operation_count")) ==
             (int64_t)json_size(operations);
        ok = ok && service_facets && service_facets->type == JSON_ARR &&
             json_get_int(json_get(summary, "service_count")) ==
             (int64_t)json_size(service_facets);
        ok = ok && json_get_int(json_get(summary, "rest_callable_count")) > 0;
        ok = ok && json_get_int(json_get(summary, "rpc_callable_count")) > 0;
        ok = ok && json_get_int(json_get(summary, "destructive_count")) > 0;
        const struct json_value *znam_facet =
            api_test_find_str_field(service_facets, "service", "znam_names");
        ok = ok && znam_facet &&
             json_get_int(json_get(znam_facet, "operation_count")) == 4;
        ok = ok && znam_facet &&
             json_get_int(json_get(znam_facet, "public_read_count")) == 3;
        ok = ok && znam_facet &&
             json_get_int(json_get(znam_facet, "destructive_count")) == 1;
        ok = ok && znam_facet &&
             json_get_int(json_get(znam_facet,
                                   "preferred_rest_count")) == 3;
        ok = ok && znam_facet &&
             json_get_int(json_get(znam_facet,
                                   "preferred_rpc_count")) == 1;
        const struct json_value *rest_facet =
            api_test_find_named(interface_facets, "rest");
        const struct json_value *rpc_facet =
            api_test_find_named(interface_facets, "rpc");
        ok = ok && rest_facet &&
             json_get_int(json_get(rest_facet, "operation_count")) > 0;
        ok = ok && rpc_facet &&
             json_get_int(json_get(rpc_facet, "operation_count")) > 0;
        const struct json_value *destructive_facet =
            api_test_find_named(safety_facets,
                                "operator_private_destructive");
        ok = ok && destructive_facet &&
             json_get_int(json_get(destructive_facet,
                                   "operation_count")) > 0;
        const struct json_value *resolve_op =
            api_test_find_str_field(operations, "operation_id",
                                    "znam_names.resolve_name");
        ok = ok && resolve_op &&
             strcmp(json_get_str(json_get(resolve_op, "service")),
                    "znam_names") == 0;
        ok = ok && resolve_op &&
             strcmp(json_get_str(json_get(resolve_op,
                                          "agent_preferred_interface")),
                    "rest") == 0;
        const struct json_value *resolve_services_op =
            api_test_find_str_field(operations, "operation_id",
                                    "znam_names.resolve_service_directory");
        ok = ok && resolve_services_op &&
             strcmp(json_get_str(json_get(resolve_services_op,
                                          "rest_route")),
                    "/api/v1/names/{name}/services") == 0;
        ok = ok && resolve_services_op &&
             strcmp(json_get_str(json_get(resolve_services_op,
                                          "output_schema")),
                    "zcl.names.service_directory.v1") == 0;
        ok = ok && resolve_services_op &&
             strcmp(json_get_str(json_get(resolve_services_op,
                                          "agent_preferred_interface")),
                    "rest") == 0;
        const struct json_value *register_op =
            api_test_find_str_field(operations, "operation_id",
                                    "znam_names.construct_name_register");
        ok = ok && register_op &&
             strcmp(json_get_str(json_get(register_op,
                                          "agent_preferred_interface")),
                    "rpc") == 0;
        ok = ok && register_op &&
             json_get_bool(json_get(register_op, "destructive"));
        static uint8_t filtered_ops_resp[131072];
        n = api_handle_request(
            "GET",
            "/api/v1/service-operations?service=znam_names&"
            "write_safety=public_read_only&preferred_interface=rest&"
            "surface=rest&status=active",
            NULL, 0, filtered_ops_resp, sizeof(filtered_ops_resp));
        body = api_test_body(filtered_ops_resp, n,
                             sizeof(filtered_ops_resp));
        struct json_value filtered_root;
        json_init(&filtered_root);
        ok = ok && n > 0 && body &&
             json_read(&filtered_root, body, strlen(body));
        const struct json_value *filters =
            json_get(&filtered_root, "filters");
        const struct json_value *filtered_ops =
            json_get(&filtered_root, "operations");
        const struct json_value *filtered_summary =
            json_get(&filtered_root, "summary");
        const struct json_value *filter_contract =
            json_get(&filtered_root, "filter_contract");
        const struct json_value *allowed_filters =
            filter_contract ? json_get(filter_contract, "allowed_filters") :
            NULL;
        ok = ok && filters && json_get_bool(json_get(filters, "active"));
        ok = ok && filters &&
             strcmp(json_get_str(json_get(filters, "service")),
                    "znam_names") == 0;
        ok = ok && filters &&
             strcmp(json_get_str(json_get(filters, "write_safety")),
                    "public_read_only") == 0;
        ok = ok && filters &&
             strcmp(json_get_str(json_get(filters,
                                          "preferred_interface")),
                    "rest") == 0;
        ok = ok && filters &&
             strcmp(json_get_str(json_get(filters, "surface")),
                    "rest") == 0;
        ok = ok && filtered_ops && filtered_ops->type == JSON_ARR &&
             json_size(filtered_ops) == 3;
        ok = ok && filtered_summary &&
             json_get_int(json_get(filtered_summary,
                                   "operation_count")) == 3;
        ok = ok && filtered_summary &&
             json_get_int(json_get(filtered_summary,
                                   "destructive_count")) == 0;
        ok = ok && api_test_find_str_field(filtered_ops, "operation_id",
                                           "znam_names.list_names");
        ok = ok && api_test_find_str_field(filtered_ops, "operation_id",
                                           "znam_names.resolve_name");
        ok = ok && api_test_find_str_field(
            filtered_ops, "operation_id",
            "znam_names.resolve_service_directory");
        ok = ok && filter_contract &&
             strcmp(json_get_str(json_get(filter_contract, "schema")),
                    "zcl.query_filter_contract.v1") == 0;
        ok = ok && filter_contract &&
             json_get_bool(json_get(filter_contract,
                                    "unknown_filters_error"));
        ok = ok && allowed_filters &&
             strcmp(json_get_str(json_get(allowed_filters,
                                          "preferred_interface")),
                    "rest,rpc,native_or_planned") == 0;
        ok = ok && allowed_filters &&
             strcmp(json_get_str(json_get(allowed_filters, "interface")),
                    "alias_for_preferred_interface") == 0;
        json_free(&filtered_root);

        n = api_handle_request("GET",
                               "/api/v1/service-operations?"
                               "write_safety=unsafe",
                               NULL, 0, filtered_ops_resp,
                               sizeof(filtered_ops_resp));
        filtered_ops_resp[n < sizeof(filtered_ops_resp)
                              ? n : sizeof(filtered_ops_resp) - 1] = '\0';
        ok = ok && strstr((char *)filtered_ops_resp,
                          "HTTP/1.1 400 Bad Request") != NULL;
        ok = ok && strstr((char *)filtered_ops_resp,
                          "invalid_service_operation_filter") != NULL;
        n = api_handle_request("GET",
                               "/api/v1/service-operations?"
                               "servce=bootstrap",
                               NULL, 0, filtered_ops_resp,
                               sizeof(filtered_ops_resp));
        filtered_ops_resp[n < sizeof(filtered_ops_resp)
                              ? n : sizeof(filtered_ops_resp) - 1] = '\0';
        ok = ok && strstr((char *)filtered_ops_resp,
                          "HTTP/1.1 400 Bad Request") != NULL;
        ok = ok && strstr((char *)filtered_ops_resp,
                          "unknown filter 'servce'") != NULL;
        {
            static uint8_t index_resp[262144];
            struct json_value index_root;
            struct json_value catalog_root;
            size_t in = api_handle_request("GET", "/api/v1", NULL, 0,
                                           index_resp, sizeof(index_resp));
            const char *index_body =
                api_test_body(index_resp, in, sizeof(index_resp));
            json_init(&index_root);
            json_init(&catalog_root);
            ok = ok && in > 0 && index_body &&
                 json_read(&index_root, index_body, strlen(index_body));
            ok = ok && catalog_body &&
                 json_read(&catalog_root, catalog_body,
                           strlen(catalog_body));
            ok = ok && api_test_runtime_probes_consistent(
                &catalog_root, operations,
                json_get(&index_root, "route_contracts"));
            ok = ok && api_test_rest_service_operations_bound(
                operations, json_get(&index_root, "route_contracts"));
            json_free(&catalog_root);
            json_free(&index_root);
        }
        json_free(&root);

        static uint8_t show_resp[65536];
        n = api_handle_request("GET",
                               "/api/v1/service-catalog/znam_names",
                               NULL, 0, show_resp, sizeof(show_resp));
        body = api_test_body(show_resp, n, sizeof(show_resp));
        json_init(&root);
        ok = ok && n > 0 && body && json_read(&root, body, strlen(body));
        ok = ok && strcmp(json_get_str(json_get(&root, "schema")),
                          "zcl.service_contract.v2") == 0;
        ok = ok && strcmp(json_get_str(json_get(&root, "name")),
                          "znam_names") == 0;
        ok = ok && strcmp(json_get_str(json_get(&root, "catalog_route")),
                          "/api/v1/service-catalog") == 0;
        ok = ok && strcmp(json_get_str(json_get(&root, "operation_route")),
                          "/api/v1/service-operations/{operation_id}") == 0;
        ok = ok && strcmp(json_get_str(json_get(&root,
                          "operation_collection_route")),
                          "/api/v1/service-operations") == 0;
        ok = ok && strcmp(json_get_str(json_get(&root, "self_route")),
                          "/api/v1/service-catalog/znam_names") == 0;
        ok = ok && api_test_array_has_str(json_get(&root,
                          "crud_capabilities"), "construct_transaction");
        ok = ok && api_test_array_has_str(json_get(&root,
                          "crud_capabilities"), "read_subcollection");
        ok = ok && api_test_array_has_str(json_get(&root,
                          "depends_on_services"), "full_node");
        ok = ok && json_get_int(json_get(&root, "operation_count")) >= 4;
        const struct json_value *znam_summary =
            json_get(&root, "operation_summary");
        ok = ok && znam_summary &&
             json_get_int(json_get(znam_summary, "operation_count")) == 4;
        ok = ok && znam_summary &&
             json_get_int(json_get(znam_summary, "public_read_count")) == 3;
        ok = ok && znam_summary &&
             json_get_int(json_get(znam_summary,
                                   "operator_private_count")) == 1;
        ok = ok && znam_summary &&
             json_get_int(json_get(znam_summary, "destructive_count")) == 1;
        ok = ok && znam_summary &&
             json_get_int(json_get(znam_summary,
                                   "rest_callable_count")) == 3;
        ok = ok && znam_summary &&
             json_get_int(json_get(znam_summary,
                                   "rpc_callable_count")) == 3;
        ok = ok && znam_summary &&
             json_get_int(json_get(znam_summary,
                                   "preferred_rest_count")) == 3;
        ok = ok && znam_summary &&
             json_get_int(json_get(znam_summary,
                                   "preferred_rpc_count")) == 1;
        ok = ok && strcmp(json_get_str(json_get(&root, "read_model")),
                          "znam_projection_confirmed_chain_records") == 0;
        ok = ok && strcmp(json_get_str(json_get(&root, "write_model")),
                          "construct_znam_op_return_transactions") == 0;
        const struct json_value *znam_probe =
            json_get(&root, "runtime_probe");
        ok = ok && znam_probe &&
             strcmp(json_get_str(json_get(znam_probe, "schema")),
                    "zcl.service_runtime_probe.v1") == 0;
        ok = ok && znam_probe &&
             strcmp(json_get_str(json_get(znam_probe, "route")),
                    "/api/v1/names") == 0;
        ok = ok && znam_probe &&
             strcmp(json_get_str(json_get(znam_probe, "operation_id")),
                    "znam_names.list_names") == 0;
        ok = ok && znam_probe &&
             strcmp(json_get_str(json_get(znam_probe, "expected_schema")),
                    "zcl.names.index.v1") == 0;
        ok = ok && znam_probe &&
             strcmp(json_get_str(json_get(znam_probe, "freshness")),
                    "znam_projection") == 0;
        ok = ok && !json_get_bool(json_get(znam_probe,
                                           "operator_private"));
        name_register_op =
            api_test_find_str_field(json_get(&root, "operations"),
                                    "operation",
                                    "construct_name_register");
        ok = ok && name_register_op &&
             strcmp(json_get_str(json_get(name_register_op, "effect")),
                    "construct_or_broadcast_znam_op_return_transaction") == 0;
        ok = ok && strstr(json_get_str(json_get(&root, "verified_by")),
                          "op_return") != NULL;
        json_free(&root);

        n = api_handle_request("GET",
                               "/api/v1/service-operations/"
                               "znam_names.resolve_name",
                               NULL, 0, show_resp, sizeof(show_resp));
        body = api_test_body(show_resp, n, sizeof(show_resp));
        json_init(&root);
        ok = ok && n > 0 && body && json_read(&root, body, strlen(body));
        ok = ok && strcmp(json_get_str(json_get(&root, "schema")),
                          "zcl.service_operation.v2") == 0;
        ok = ok && strcmp(json_get_str(json_get(&root, "operation_id")),
                          "znam_names.resolve_name") == 0;
        ok = ok && strcmp(json_get_str(json_get(&root, "self_route")),
                          "/api/v1/service-operations/"
                          "znam_names.resolve_name") == 0;
        ok = ok && strcmp(json_get_str(json_get(&root,
                                                "service_catalog_route")),
                          "/api/v1/service-catalog/znam_names") == 0;
        ok = ok && strcmp(json_get_str(json_get(&root, "service")),
                          "znam_names") == 0;
        ok = ok && strcmp(json_get_str(json_get(&root, "operation")),
                          "resolve_name") == 0;
        ok = ok && strcmp(json_get_str(json_get(&root, "rest_route")),
                          "/api/v1/names/{name}") == 0;
        ok = ok && strcmp(json_get_str(json_get(&root, "catalog_route")),
                          "/api/v1/service-catalog") == 0;
        ok = ok && strcmp(json_get_str(json_get(&root, "operation_route")),
                          "/api/v1/service-operations/{operation_id}") == 0;
        ok = ok && strcmp(json_get_str(json_get(&root,
                                                "execution_surface")),
                          "rest") == 0;
        ok = ok && strcmp(json_get_str(json_get(&root, "write_safety")),
                          "public_read_only") == 0;
        ok = ok && strcmp(json_get_str(json_get(&root,
                                                "agent_preferred_interface")),
                          "rest") == 0;
        ok = ok && strcmp(json_get_str(json_get(&root, "agent_next_step")),
                          "call_rest_route_and_validate_output_schema") == 0;
        ok = ok && json_get_bool(json_get(&root, "rest_callable"));
        ok = ok && json_get_bool(json_get(&root, "rpc_callable"));
        ok = ok && json_get_bool(json_get(&root, "public_read"));
        ok = ok && !json_get_bool(json_get(&root, "destructive"));
        json_free(&root);

        n = api_handle_request("GET",
                               "/api/v1/service-operations/"
                               "znam_names.resolve_service_directory",
                               NULL, 0, show_resp, sizeof(show_resp));
        body = api_test_body(show_resp, n, sizeof(show_resp));
        json_init(&root);
        ok = ok && n > 0 && body && json_read(&root, body, strlen(body));
        ok = ok && strcmp(json_get_str(json_get(&root, "operation_id")),
                          "znam_names.resolve_service_directory") == 0;
        ok = ok && strcmp(json_get_str(json_get(&root, "operation")),
                          "resolve_service_directory") == 0;
        ok = ok && strcmp(json_get_str(json_get(&root,
                                                "crud_capability")),
                          "read_subcollection") == 0;
        ok = ok && strcmp(json_get_str(json_get(&root, "rest_route")),
                          "/api/v1/names/{name}/services") == 0;
        ok = ok && strcmp(json_get_str(json_get(&root,
                                                "output_schema")),
                          "zcl.names.service_directory.v1") == 0;
        ok = ok && strcmp(json_get_str(json_get(&root,
                                                "agent_preferred_interface")),
                          "rest") == 0;
        ok = ok && json_get_bool(json_get(&root, "rest_callable"));
        ok = ok && !json_get_bool(json_get(&root, "rpc_callable"));
        json_free(&root);

        n = api_handle_request("GET",
                               "/api/v1/service-operations/"
                               "znam_names.not_real",
                               NULL, 0, show_resp, sizeof(show_resp));
        show_resp[n < sizeof(show_resp) ? n : sizeof(show_resp) - 1] = '\0';
        ok = ok && strstr((char *)show_resp,
                          "HTTP/1.1 404 Not Found") != NULL;

        n = api_handle_request("GET", "/api/v1/service-catalog/not_real",
                               NULL, 0, show_resp, sizeof(show_resp));
        show_resp[n < sizeof(show_resp) ? n : sizeof(show_resp) - 1] = '\0';
        ok = ok && strstr((char *)show_resp,
                          "HTTP/1.1 404 Not Found") != NULL;

        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    return failures;
}
