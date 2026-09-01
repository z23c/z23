/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * API ZNAM name routes: the name list payload under oversized input and the
 * name show record set (service, address, and text records).
 */

#include "test/api_test_fixtures.h"

int api_znam_routes_focused_tests(void)
{
    int failures = 0;

    printf("api: json route emits oversized names payload safely... ");
    {
        char dbdir[256];
        char dbpath[320];
        struct node_db ndb;
        memset(&ndb, 0, sizeof(ndb));
        snprintf(dbdir, sizeof(dbdir), ".zcl_test_api_names_%d",
                 (int)getpid());
        mkdir(dbdir, 0755);
        snprintf(dbpath, sizeof(dbpath), "%s/node.db", dbdir);

        bool ok = node_db_open(&ndb, dbpath);
        for (int i = 0; ok && i < 100; i++) {
            struct znam_entry e;
            memset(&e, 0, sizeof(e));
            snprintf(e.name, sizeof(e.name), "api-name-%03d", i);
            snprintf(e.owner_address, sizeof(e.owner_address),
                     "owner-address-for-api-route-%03d", i);
            e.target_type = ZNAM_TYPE_CONTENT;
            snprintf(e.target_value, sizeof(e.target_value),
                     "sha3:%064d:%064d", i, 1000 + i);
            memset(e.reg_txid, (uint8_t)(i + 1), sizeof(e.reg_txid));
            e.reg_height = i + 1;
            ok = db_znam_save(&ndb, &e);
        }

        if (ok) {
            uint8_t big_resp[65536];
            rpc_name_set_state(&ndb);
            size_t n = api_handle_request("GET", "/api/names", NULL, 0,
                                          big_resp, sizeof(big_resp));
            big_resp[n < sizeof(big_resp) ? n : sizeof(big_resp) - 1] = '\0';
            const char *body = api_test_body(big_resp, n, sizeof(big_resp));
            struct json_value root;
            json_init(&root);
            ok = n > 16384 &&
                 strstr((char *)big_resp, "HTTP/1.1 200 OK") != NULL &&
                 body && json_read(&root, body, strlen(body));
            const struct json_value *names =
                ok ? json_get(&root, "names") : NULL;
            const struct json_value *links =
                ok ? json_get(&root, "_links") : NULL;
            const struct json_value *verification =
                ok ? json_get(&root, "zcl_verification") : NULL;
            const struct json_value *last =
                api_test_find_str_field(names, "name", "api-name-099");
            ok = ok && strcmp(json_get_str(json_get(&root, "schema")),
                              "zcl.names.index.v1") == 0;
            ok = ok && json_get_int(json_get(&root, "limit")) == 100;
            ok = ok && json_get_int(json_get(&root, "count")) == 100;
            ok = ok && !json_get_bool(json_get(&root, "filtered"));
            ok = ok && json_size(names) == 100 && last != NULL;
            ok = ok && strcmp(json_get_str(json_get(&root,
                                                    "source_projection")),
                              "znam_projection") == 0;
            ok = ok && links &&
                 strcmp(json_get_str(json_get(links, "collection")),
                        "/api/v1/names") == 0;
            ok = ok && strcmp(json_get_str(json_get(links, "read")),
                              "/api/v1/names/{name}") == 0;
            ok = ok && strcmp(json_get_str(json_get(links, "protocol")),
                              "/api/v1/protocols/znam") == 0;
            ok = ok && strcmp(json_get_str(json_get(links, "delete")),
                              "not_supported_by_znam_v1") == 0;
            ok = ok && verification &&
                 strcmp(json_get_str(json_get(verification, "base_layer")),
                        "zclassic_l1") == 0;
            ok = ok &&
                 strcmp(json_get_str(json_get(verification,
                                              "consensus_boundary")),
                        "legacy_zclassic_consensus_unchanged") == 0;
            json_free(&root);

            if (ok) {
                struct rpc_table names_rpc;
                struct json_value params = {0};
                struct json_value rpc_result = {0};
                const struct json_value *rpc_names;
                const struct json_value *rpc_verification;
                const struct rpc_command *cmd;

                rpc_table_init(&names_rpc);
                register_name_rpc_commands(&names_rpc);
                cmd = rpc_table_find(&names_rpc, "name_list");
                json_set_array(&params);
                ok = cmd && cmd->actor(&params, false, &rpc_result);
                rpc_names = ok ? json_get(&rpc_result, "names") : NULL;
                rpc_verification =
                    ok ? json_get(&rpc_result, "zcl_verification") : NULL;
                ok = ok &&
                     strcmp(json_get_str(json_get(&rpc_result, "schema")),
                            "zcl.names.index.v1") == 0;
                ok = ok &&
                     json_get_int(json_get(&rpc_result, "limit")) == 100;
                ok = ok &&
                     json_get_int(json_get(&rpc_result, "count")) == 100;
                ok = ok && !json_get_bool(json_get(&rpc_result, "filtered"));
                ok = ok && json_size(rpc_names) == 100;
                ok = ok && rpc_verification &&
                     strcmp(json_get_str(json_get(rpc_verification,
                                                  "base_layer")),
                            "zclassic_l1") == 0;
                json_free(&params);
                json_free(&rpc_result);
            }

            if (ok) {
                struct rpc_table names_rpc;
                struct json_value params = {0};
                struct json_value owner = {0};
                struct json_value rpc_result = {0};
                const struct json_value *rpc_names;
                const struct json_value *match;
                const struct rpc_command *cmd;

                rpc_table_init(&names_rpc);
                register_name_rpc_commands(&names_rpc);
                cmd = rpc_table_find(&names_rpc, "name_list");
                json_set_array(&params);
                json_set_str(&owner, "owner-address-for-api-route-042");
                json_push_back(&params, &owner);
                json_free(&owner);
                ok = cmd && cmd->actor(&params, false, &rpc_result);
                rpc_names = ok ? json_get(&rpc_result, "names") : NULL;
                match = api_test_find_str_field(rpc_names, "name",
                                                "api-name-042");
                ok = ok &&
                     strcmp(json_get_str(json_get(&rpc_result, "schema")),
                            "zcl.names.index.v1") == 0;
                ok = ok && json_get_bool(json_get(&rpc_result, "filtered"));
                ok = ok &&
                     strcmp(json_get_str(json_get(&rpc_result, "owner")),
                            "owner-address-for-api-route-042") == 0;
                ok = ok && json_get_int(json_get(&rpc_result, "count")) == 1;
                ok = ok && json_size(rpc_names) == 1 && match != NULL;
                json_free(&params);
                json_free(&rpc_result);
            }
            rpc_name_set_state(NULL);
            node_db_close(&ndb);
        }

        char cmd[384];
        snprintf(cmd, sizeof(cmd), "rm -rf %s", dbdir);
        system(cmd);

    if (ok) printf("OK\n");
    else { printf("FAIL\n"); failures++; }
    }

    printf("api: name show includes service and address records... ");
    {
        char dbdir[256];
        char dbpath[320];
        struct node_db ndb;
        memset(&ndb, 0, sizeof(ndb));
        snprintf(dbdir, sizeof(dbdir), ".zcl_test_api_name_show_%d",
                 (int)getpid());
        mkdir(dbdir, 0755);
        snprintf(dbpath, sizeof(dbpath), "%s/node.db", dbdir);

        bool opened = node_db_open(&ndb, dbpath);
        bool ok = opened;
        if (ok) {
            struct znam_entry e;
            memset(&e, 0, sizeof(e));
            snprintf(e.name, sizeof(e.name), "alice");
            snprintf(e.owner_address, sizeof(e.owner_address),
                     "t1owner-for-name-show");
            e.target_type = ZNAM_TYPE_BTC;
            snprintf(e.target_value, sizeof(e.target_value),
                     "1primary-target-address");
            memset(e.reg_txid, 0x42, sizeof(e.reg_txid));
            e.reg_height = 42;
            memset(e.last_update_txid, 0x43, sizeof(e.last_update_txid));
            ok = db_znam_save(&ndb, &e);
        }
        ok = ok && db_znam_text_save(&ndb, "alice", "url",
                                     "https://alice.example");
        ok = ok && db_znam_text_save(&ndb, "alice", "service.onion",
                                     "aliceexample.onion:8033");
        ok = ok && db_znam_text_save(&ndb, "alice", "service.p2p",
                                     "192.0.2.10:8033");
        ok = ok && db_znam_text_save(&ndb, "alice", "svc.direct_p2p",
                                     "missing-port");
        ok = ok && db_znam_text_save(&ndb, "alice", "bootstrap",
                                     "198.51.100.20:8033");
        ok = ok && db_znam_text_save(&ndb, "alice", "service.unknown",
                                     "unknown-service-metadata");
        ok = ok && db_znam_addr_save(&ndb, "alice", ZNAM_TYPE_LTC,
                                     "LaliceAddress");
        ok = ok && db_znam_addr_save(&ndb, "alice", ZNAM_TYPE_BTC,
                                     "1aliceAddress");

        if (ok) {
            uint8_t resp[65536];
            rpc_name_set_state(&ndb);
            size_t n = api_handle_request("GET", "/api/v1/names/alice",
                                          NULL, 0, resp, sizeof(resp));
            rpc_name_set_state(NULL);
            const char *body = api_test_body(resp, n, sizeof(resp));
            struct json_value root;
            json_init(&root);
            ok = n > 0 && body && json_read(&root, body, strlen(body));
            const struct json_value *texts =
                ok ? json_get(&root, "text_records") : NULL;
            const struct json_value *services =
                ok ? json_get(&root, "service_records") : NULL;
            const struct json_value *addrs =
                ok ? json_get(&root, "address_records") : NULL;
            const struct json_value *directory =
                ok ? json_get(&root, "service_directory") : NULL;
            const struct json_value *dir_records =
                directory ? json_get(directory, "records") : NULL;
            const struct json_value *dir_endpoints =
                directory ? json_get(directory, "endpoints") : NULL;
            const struct json_value *links =
                ok ? json_get(&root, "_links") : NULL;
            const struct json_value *verification =
                ok ? json_get(&root, "zcl_verification") : NULL;
            const struct json_value *url =
                api_test_find_str_field(texts, "key", "url");
            const struct json_value *svc =
                api_test_find_str_field(services, "key", "service.onion");
            const struct json_value *svc_p2p =
                api_test_find_str_field(services, "key", "service.p2p");
            const struct json_value *svc_bad_p2p =
                api_test_find_str_field(services, "key", "svc.direct_p2p");
            const struct json_value *svc_bootstrap =
                api_test_find_str_field(services, "key", "bootstrap");
            const struct json_value *svc_unknown =
                api_test_find_str_field(services, "key", "service.unknown");
            const struct json_value *svc_probe =
                svc ? json_get(svc, "runtime_probe") : NULL;
            const struct json_value *svc_p2p_probe =
                svc_p2p ? json_get(svc_p2p, "runtime_probe") : NULL;
            const struct json_value *svc_p2p_validation =
                svc_p2p ? json_get(svc_p2p, "endpoint_validation") : NULL;
            const struct json_value *svc_p2p_routing =
                svc_p2p ? json_get(svc_p2p, "endpoint_routing") : NULL;
            const struct json_value *svc_bad_p2p_validation =
                svc_bad_p2p ? json_get(svc_bad_p2p,
                                       "endpoint_validation") : NULL;
            const struct json_value *svc_bad_p2p_routing =
                svc_bad_p2p ? json_get(svc_bad_p2p,
                                       "endpoint_routing") : NULL;
            const struct json_value *svc_bootstrap_probe =
                svc_bootstrap ? json_get(svc_bootstrap,
                                         "runtime_probe") : NULL;
            const struct json_value *svc_resolution =
                svc ? json_get(svc, "contract_resolution") : NULL;
            const struct json_value *svc_validation =
                svc ? json_get(svc, "endpoint_validation") : NULL;
            const struct json_value *svc_routing =
                svc ? json_get(svc, "endpoint_routing") : NULL;
            const struct json_value *svc_unknown_resolution =
                svc_unknown ? json_get(svc_unknown,
                                       "contract_resolution") : NULL;
            const struct json_value *svc_unknown_validation =
                svc_unknown ? json_get(svc_unknown,
                                       "endpoint_validation") : NULL;
            const struct json_value *dir_svc =
                api_test_find_str_field(dir_records, "key", "service.onion");
            const struct json_value *dir_endpoint =
                api_test_find_str_field(dir_endpoints, "key", "service.p2p");
            const struct json_value *btc =
                api_test_find_str_field(addrs, "type", "bitcoin");
            const struct json_value *ltc =
                api_test_find_str_field(addrs, "type", "litecoin");
            const struct json_value *routing_plan =
                directory ? json_get(directory, "routing_plan") : NULL;
            ok = ok && strcmp(json_get_str(json_get(&root, "schema")),
                              "zcl.names.show.v1") == 0;
            ok = ok && strcmp(json_get_str(json_get(&root, "name")),
                              "alice") == 0;
            ok = ok && json_get_int(json_get(&root, "target_type")) ==
                       ZNAM_TYPE_BTC;
            ok = ok && strcmp(json_get_str(json_get(&root, "type")),
                              "bitcoin") == 0;
            ok = ok && json_size(texts) == 6 &&
                       json_get_int(json_get(&root, "text_record_count")) == 6;
            ok = ok && json_size(services) == 5 &&
                       json_get_int(json_get(&root,
                                             "service_record_count")) == 5;
            ok = ok && json_size(addrs) == 2 &&
                       json_get_int(json_get(&root,
                                             "address_record_count")) == 2;
            ok = ok && url &&
                 strcmp(json_get_str(json_get(url, "value")),
                        "https://alice.example") == 0;
            ok = ok && svc &&
                 strcmp(json_get_str(json_get(svc, "value")),
                        "aliceexample.onion:8033") == 0;
            ok = ok && strcmp(json_get_str(json_get(svc, "schema")),
                              "zcl.names.service_record.v1") == 0;
            ok = ok && strcmp(json_get_str(json_get(svc, "service_name")),
                              "onion_directory") == 0;
            ok = ok && strcmp(json_get_str(json_get(svc,
                                                    "service_contract")),
                              "onion_directory") == 0;
            ok = ok && strcmp(json_get_str(json_get(svc,
                                                    "service_catalog_route")),
                              "/api/v1/service-catalog/onion_directory") == 0;
            ok = ok && strcmp(json_get_str(json_get(svc,
                                                    "recommended_operation_id")),
                              "onion_directory.list_onion_announcements") == 0;
            ok = ok && strcmp(json_get_str(json_get(svc,
                                                    "service_operation_route")),
                              "/api/v1/service-operations/"
                              "onion_directory.list_onion_announcements") == 0;
            ok = ok && json_get_bool(json_get(svc,
                                              "service_contract_known"));
            ok = ok && json_get_bool(json_get(svc,
                                              "service_operation_required"));
            ok = ok && json_get_bool(json_get(svc,
                                              "service_operation_known"));
            ok = ok && strcmp(json_get_str(json_get(svc,
                                                    "contract_resolution_status")),
                              "resolved") == 0;
            ok = ok && svc_resolution &&
                 strcmp(json_get_str(json_get(svc_resolution, "schema")),
                        "zcl.names.service_contract_resolution.v1") == 0;
            ok = ok && svc_resolution &&
                 strcmp(json_get_str(json_get(svc_resolution, "status")),
                        "resolved") == 0;
            ok = ok && svc_resolution &&
                 json_get_bool(json_get(svc_resolution,
                                        "service_contract_known"));
            ok = ok && svc_resolution &&
                 json_get_bool(json_get(svc_resolution,
                                        "operation_required"));
            ok = ok && svc_resolution &&
                 json_get_bool(json_get(svc_resolution,
                                        "service_operation_known"));
            ok = ok && svc_resolution &&
                 strcmp(json_get_str(json_get(svc_resolution,
                                              "next_action")),
                        "run_runtime_probe_before_routing") == 0;
            ok = ok && svc_probe &&
                 strcmp(json_get_str(json_get(svc_probe, "schema")),
                        "zcl.service_runtime_probe.v1") == 0;
            ok = ok && strcmp(json_get_str(json_get(svc_probe, "route")),
                              "/api/v1/onion/announcements") == 0;
            ok = ok && strcmp(json_get_str(json_get(svc_probe,
                                                    "operation_id")),
                              "onion_directory.list_onion_announcements") == 0;
            ok = ok && strcmp(json_get_str(json_get(svc_probe,
                                                    "expected_schema")),
                              "zcl.onion_announcements.index.v1") == 0;
            ok = ok && strcmp(json_get_str(json_get(svc, "transport")),
                              "onion") == 0;
            ok = ok && json_get_int(json_get(svc,
                                             "routing_priority")) == 30;
            ok = ok && json_get_bool(json_get(svc,
                                              "endpoint_hint_valid"));
            ok = ok && svc_validation &&
                 strcmp(json_get_str(json_get(svc_validation, "schema")),
                        "zcl.names.endpoint_validation.v1") == 0;
            ok = ok && svc_validation &&
                 strcmp(json_get_str(json_get(svc_validation, "status")),
                        "valid_endpoint_hint") == 0;
            ok = ok && svc_validation &&
                 json_get_bool(json_get(svc_validation, "accepted"));
            ok = ok && svc_validation &&
                 strcmp(json_get_str(json_get(svc_validation, "reason")),
                        "onion_host_hint_present") == 0;
            ok = ok && svc_routing &&
                 strcmp(json_get_str(json_get(svc_routing, "schema")),
                        "zcl.names.endpoint_routing.v1") == 0;
            ok = ok && svc_routing &&
                 json_get_int(json_get(svc_routing, "priority")) == 30;
            ok = ok && svc_routing &&
                 strcmp(json_get_str(json_get(svc_routing,
                                              "preferred_transport")),
                        "onion") == 0;
            ok = ok && svc_routing &&
                 strcmp(json_get_str(json_get(svc_routing,
                                              "fallback_transport")),
                        "direct_p2p_if_directory_advertises_it") == 0;
            ok = ok && json_get_bool(json_get(svc, "chain_verified"));
            ok = ok && svc_p2p &&
                 strcmp(json_get_str(json_get(svc_p2p, "service_name")),
                        "direct_p2p") == 0;
            ok = ok && strcmp(json_get_str(json_get(svc_p2p,
                                                    "service_contract")),
                              "bootstrap") == 0;
            ok = ok && strcmp(json_get_str(json_get(svc_p2p,
                                                    "recommended_operation_id")),
                              "bootstrap.inspect_peer_bootstrap_readiness") == 0;
            ok = ok && strcmp(json_get_str(json_get(svc_p2p,
                                                    "service_operation_route")),
                              "/api/v1/service-operations/"
                              "bootstrap.inspect_peer_bootstrap_readiness") == 0;
            ok = ok && svc_p2p_probe &&
                 strcmp(json_get_str(json_get(svc_p2p_probe, "route")),
                        "/api/v1/bootstrap") == 0;
            ok = ok && strcmp(json_get_str(json_get(svc_p2p_probe,
                                                    "operation_id")),
                              "bootstrap.read_bootstrap_status") == 0;
            ok = ok && strcmp(json_get_str(json_get(svc_p2p,
                                                    "next_action")),
                              "connect_direct_p2p_and_verify_peer_readiness") == 0;
            ok = ok && strcmp(json_get_str(json_get(svc_p2p, "transport")),
                              "p2p") == 0;
            ok = ok && json_get_int(json_get(svc_p2p,
                                             "routing_priority")) == 10;
            ok = ok && json_get_bool(json_get(svc_p2p,
                                              "endpoint_hint_valid"));
            ok = ok && svc_p2p_validation &&
                 strcmp(json_get_str(json_get(svc_p2p_validation, "status")),
                        "valid_endpoint_hint") == 0;
            ok = ok && svc_p2p_validation &&
                 strcmp(json_get_str(json_get(svc_p2p_validation, "reason")),
                        "host_port_hint_present") == 0;
            ok = ok && svc_p2p_routing &&
                 strcmp(json_get_str(json_get(svc_p2p_routing,
                                              "preferred_transport")),
                        "p2p") == 0;
            ok = ok && svc_p2p_routing &&
                 strcmp(json_get_str(json_get(svc_p2p_routing,
                                              "fallback_transport")),
                        "onion") == 0;
            ok = ok && svc_bad_p2p &&
                 strcmp(json_get_str(json_get(svc_bad_p2p,
                                              "service_name")),
                        "direct_p2p") == 0;
            ok = ok && svc_bad_p2p &&
                 !json_get_bool(json_get(svc_bad_p2p,
                                         "endpoint_hint_valid"));
            ok = ok && svc_bad_p2p_validation &&
                 strcmp(json_get_str(json_get(svc_bad_p2p_validation,
                                              "status")),
                        "invalid_endpoint_hint") == 0;
            ok = ok && svc_bad_p2p_validation &&
                 !json_get_bool(json_get(svc_bad_p2p_validation,
                                         "accepted"));
            ok = ok && svc_bad_p2p_validation &&
                 strcmp(json_get_str(json_get(svc_bad_p2p_validation,
                                              "reason")),
                        "missing_host_port") == 0;
            ok = ok && svc_bad_p2p_routing &&
                 json_get_int(json_get(svc_bad_p2p_routing,
                                       "priority")) == 10;
            ok = ok && svc_bootstrap &&
                 strcmp(json_get_str(json_get(svc_bootstrap,
                                              "service_name")),
                        "bootstrap") == 0;
            ok = ok && strcmp(json_get_str(json_get(svc_bootstrap,
                                                    "recommended_operation_id")),
                              "bootstrap.read_bootstrap_status") == 0;
            ok = ok && strcmp(json_get_str(json_get(svc_bootstrap,
                                                    "service_operation_route")),
                              "/api/v1/service-operations/"
                              "bootstrap.read_bootstrap_status") == 0;
            ok = ok && svc_bootstrap_probe &&
                 strcmp(json_get_str(json_get(svc_bootstrap_probe, "route")),
                        "/api/v1/bootstrap") == 0;
            ok = ok && strcmp(json_get_str(json_get(svc_bootstrap_probe,
                                                    "expected_schema")),
                              "zcl.bootstrap_status.v1") == 0;
            ok = ok && strcmp(json_get_str(json_get(svc_bootstrap,
                                                    "endpoint_kind")),
                              "bootstrap_hint") == 0;
            ok = ok && svc_unknown &&
                 strcmp(json_get_str(json_get(svc_unknown,
                                              "service_contract")),
                        "unknown") == 0;
            ok = ok && !json_get_bool(json_get(svc_unknown,
                                               "service_contract_known"));
            ok = ok && !json_get_bool(json_get(svc_unknown,
                                               "service_operation_required"));
            ok = ok && !json_get_bool(json_get(svc_unknown,
                                               "service_operation_known"));
            ok = ok && strcmp(json_get_str(json_get(svc_unknown,
                                                    "contract_resolution_status")),
                              "service_unknown") == 0;
            ok = ok && svc_unknown_validation &&
                 strcmp(json_get_str(json_get(svc_unknown_validation,
                                              "status")),
                        "not_endpoint") == 0;
            ok = ok && svc_unknown_resolution &&
                 strcmp(json_get_str(json_get(svc_unknown_resolution,
                                              "status")),
                        "service_unknown") == 0;
            ok = ok && svc_unknown_resolution &&
                 !json_get_bool(json_get(svc_unknown_resolution,
                                         "service_contract_known"));
            ok = ok && svc_unknown_resolution &&
                 !json_get_bool(json_get(svc_unknown_resolution,
                                         "operation_required"));
            ok = ok && svc_unknown_resolution &&
                 strcmp(json_get_str(json_get(svc_unknown_resolution,
                                              "next_action")),
                        "inspect_service_catalog_before_trusting_chain_hint") == 0;
            ok = ok && btc &&
                 strcmp(json_get_str(json_get(btc, "address")),
                        "1aliceAddress") == 0;
            ok = ok && ltc &&
                 strcmp(json_get_str(json_get(ltc, "address")),
                        "LaliceAddress") == 0;
            ok = ok && directory &&
                 strcmp(json_get_str(json_get(directory, "schema")),
                        "zcl.names.service_directory.v1") == 0;
            ok = ok && json_get_bool(json_get(directory, "has_services"));
            ok = ok && json_get_int(json_get(directory,
                                             "service_record_count")) == 5;
            ok = ok && json_get_int(json_get(directory,
                                             "endpoint_count")) == 4;
            ok = ok && json_get_int(json_get(directory,
                                             "valid_endpoint_count")) == 3;
            ok = ok && json_get_int(json_get(directory,
                                             "invalid_endpoint_count")) == 1;
            ok = ok && json_get_bool(json_get(directory,
                                              "supports_onion"));
            ok = ok && json_get_bool(json_get(directory,
                                              "supports_direct_p2p"));
            ok = ok && json_get_bool(json_get(directory,
                                              "supports_bootstrap"));
            ok = ok && json_size(dir_records) == 5 && dir_svc != NULL;
            ok = ok && json_size(dir_endpoints) == 4 && dir_endpoint != NULL;
            ok = ok && routing_plan &&
                 strcmp(json_get_str(json_get(routing_plan, "schema")),
                        "zcl.names.service_routing_plan.v1") == 0;
            ok = ok && routing_plan &&
                 strcmp(json_get_str(json_get(routing_plan, "strategy")),
                        "prefer_valid_direct_p2p_then_bootstrap_then_onion")
                    == 0;
            ok = ok && routing_plan &&
                 strcmp(json_get_str(json_get(routing_plan,
                                              "preferred_transport")),
                        "p2p") == 0;
            ok = ok && routing_plan &&
                 strcmp(json_get_str(json_get(routing_plan,
                                              "fallback_transport")),
                        "onion") == 0;
            ok = ok && routing_plan &&
                 json_get_int(json_get(routing_plan,
                                       "valid_endpoint_count")) == 3;
            ok = ok && routing_plan &&
                 json_get_int(json_get(routing_plan,
                                       "invalid_endpoint_count")) == 1;
            ok = ok && routing_plan &&
                 json_get_bool(json_get(routing_plan,
                                        "requires_runtime_probe"));
            ok = ok && strcmp(json_get_str(json_get(directory,
                                                    "transport_model")),
                              "records_advertise_tor_or_p2p_endpoints") == 0;
            ok = ok && strcmp(json_get_str(json_get(directory,
                                                    "service_contract_route")),
                              "/api/v1/service-catalog/{service}") == 0;
            ok = ok && strcmp(json_get_str(json_get(directory,
                                                    "operation_contract_route")),
                              "/api/v1/service-operations/{operation_id}") == 0;
            ok = ok && strcmp(json_get_str(json_get(directory,
                                                    "runtime_probe_schema")),
                              "zcl.service_runtime_probe.v1") == 0;
            ok = ok && strcmp(json_get_str(json_get(directory,
                                                    "runtime_probe_contract_field")),
                              "runtime_probe") == 0;
            ok = ok && links &&
                 strcmp(json_get_str(json_get(links, "self")),
                        "/api/v1/names/alice") == 0;
            ok = ok && links &&
                 strcmp(json_get_str(json_get(links, "services")),
                        "/api/v1/names/alice/services") == 0;
            ok = ok && strcmp(json_get_str(json_get(links, "collection")),
                              "/api/v1/names") == 0;
            ok = ok && strcmp(json_get_str(json_get(links,
                                                    "service_directory")),
                              "/api/v1/names/{name}/services") == 0;
            ok = ok && verification &&
                 strcmp(json_get_str(json_get(verification, "anchor")),
                        "confirmed_znam_op_return") == 0;
            ok = ok &&
                 strcmp(json_get_str(json_get(verification,
                                              "mutation_authority")),
                        "confirmed_chain_history") == 0;
            json_free(&root);

            {
                uint8_t svc_resp[65536];
                struct json_value svc_root;
                rpc_name_set_state(&ndb);
                size_t sn = api_handle_request(
                    "GET", "/api/v1/names/alice/services",
                    NULL, 0, svc_resp, sizeof(svc_resp));
                rpc_name_set_state(NULL);
                const char *svc_body =
                    api_test_body(svc_resp, sn, sizeof(svc_resp));
                json_init(&svc_root);
                ok = ok && sn > 0 && svc_body &&
                     json_read(&svc_root, svc_body, strlen(svc_body));
                const struct json_value *svc_records =
                    ok ? json_get(&svc_root, "records") : NULL;
                const struct json_value *svc_endpoints =
                    ok ? json_get(&svc_root, "endpoints") : NULL;
                const struct json_value *svc_onion =
                    api_test_find_str_field(svc_records, "key",
                                            "service.onion");
                const struct json_value *svc_filter_contract =
                    ok ? json_get(&svc_root, "filter_contract") : NULL;
                const struct json_value *svc_allowed_filters =
                    svc_filter_contract ?
                    json_get(svc_filter_contract, "allowed_filters") : NULL;
                ok = ok &&
                     strcmp(json_get_str(json_get(&svc_root, "schema")),
                            "zcl.names.service_directory.v1") == 0;
                ok = ok &&
                     strcmp(json_get_str(json_get(&svc_root, "name")),
                            "alice") == 0;
                ok = ok &&
                     strcmp(json_get_str(json_get(&svc_root, "self_route")),
                            "/api/v1/names/alice/services") == 0;
                ok = ok &&
                     strcmp(json_get_str(json_get(&svc_root, "name_route")),
                            "/api/v1/names/alice") == 0;
                ok = ok &&
                     strcmp(json_get_str(json_get(&svc_root,
                                                  "operation_id")),
                            "znam_names.resolve_service_directory") == 0;
                ok = ok &&
                     strcmp(json_get_str(json_get(&svc_root,
                                                  "operation_route")),
                            "/api/v1/service-operations/"
                            "znam_names.resolve_service_directory") == 0;
                ok = ok &&
                     strcmp(json_get_str(json_get(&svc_root,
                                                  "source_projection")),
                            "znam_projection") == 0;
                ok = ok &&
                     json_get_int(json_get(&svc_root,
                                           "service_record_count")) == 5;
                ok = ok &&
                     json_get_int(json_get(&svc_root,
                                           "endpoint_count")) == 4;
                ok = ok &&
                     json_get_int(json_get(&svc_root,
                                           "valid_endpoint_count")) == 3;
                ok = ok &&
                     json_get_int(json_get(&svc_root,
                                           "invalid_endpoint_count")) == 1;
                ok = ok && svc_records && json_size(svc_records) == 5;
                ok = ok && svc_endpoints && json_size(svc_endpoints) == 4;
                ok = ok && svc_onion &&
                     strcmp(json_get_str(json_get(svc_onion,
                                                  "contract_resolution_status")),
                            "resolved") == 0;
                ok = ok &&
                     strcmp(json_get_str(json_get(&svc_root,
                                                  "next_action")),
                            "use_records_then_run_runtime_probe_before_routing")
                     == 0;
                ok = ok && svc_filter_contract &&
                     strcmp(json_get_str(json_get(svc_filter_contract,
                                                  "schema")),
                            "zcl.query_filter_contract.v1") == 0;
                ok = ok && svc_filter_contract &&
                     json_get_bool(json_get(svc_filter_contract,
                                            "unknown_filters_error"));
                ok = ok && svc_allowed_filters &&
                     strcmp(json_get_str(json_get(svc_allowed_filters,
                                                  "transport")),
                            "p2p,onion,p2p_or_onion,unspecified,none") == 0;
                ok = ok && svc_allowed_filters &&
                     strcmp(json_get_str(json_get(svc_allowed_filters,
                                                  "contract")),
                            "alias_for_service_contract") == 0;
                json_free(&svc_root);
            }

            {
                uint8_t filtered_resp[65536];
                struct json_value filtered_root;
                rpc_name_set_state(&ndb);
                size_t fn = api_handle_request(
                    "GET",
                    "/api/v1/names/alice/services?"
                    "transport=p2p&valid=true&endpoint_only=true",
                    NULL, 0, filtered_resp, sizeof(filtered_resp));
                rpc_name_set_state(NULL);
                const char *filtered_body =
                    api_test_body(filtered_resp, fn, sizeof(filtered_resp));
                json_init(&filtered_root);
                ok = ok && fn > 0 && filtered_body &&
                     json_read(&filtered_root, filtered_body,
                               strlen(filtered_body));
                const struct json_value *filters =
                    ok ? json_get(&filtered_root, "filters") : NULL;
                const struct json_value *filtered_records =
                    ok ? json_get(&filtered_root, "records") : NULL;
                const struct json_value *filtered_endpoints =
                    ok ? json_get(&filtered_root, "endpoints") : NULL;
                const struct json_value *filtered_p2p =
                    api_test_find_str_field(filtered_records, "key",
                                            "service.p2p");
                const struct json_value *filtered_plan =
                    ok ? json_get(&filtered_root, "routing_plan") : NULL;
                ok = ok &&
                     strcmp(json_get_str(json_get(&filtered_root, "schema")),
                            "zcl.names.service_directory.v1") == 0;
                ok = ok && filters &&
                     json_get_bool(json_get(filters, "active"));
                ok = ok && filters &&
                     strcmp(json_get_str(json_get(filters, "transport")),
                            "p2p") == 0;
                ok = ok && filters &&
                     json_get_bool(json_get(filters, "valid"));
                ok = ok && filters &&
                     json_get_bool(json_get(filters, "endpoint_only"));
                ok = ok &&
                     json_get_int(json_get(&filtered_root,
                                           "service_record_count")) == 1;
                ok = ok &&
                     json_get_int(json_get(&filtered_root,
                                           "endpoint_count")) == 1;
                ok = ok &&
                     json_get_int(json_get(&filtered_root,
                                           "valid_endpoint_count")) == 1;
                ok = ok &&
                     json_get_int(json_get(&filtered_root,
                                           "invalid_endpoint_count")) == 0;
                ok = ok && json_get_bool(json_get(&filtered_root,
                                                  "supports_direct_p2p"));
                ok = ok && !json_get_bool(json_get(&filtered_root,
                                                   "supports_onion"));
                ok = ok && !json_get_bool(json_get(&filtered_root,
                                                   "supports_bootstrap"));
                ok = ok && filtered_records &&
                     json_size(filtered_records) == 1 && filtered_p2p;
                ok = ok && filtered_endpoints &&
                     json_size(filtered_endpoints) == 1;
                ok = ok && filtered_plan &&
                     strcmp(json_get_str(json_get(filtered_plan,
                                                  "preferred_transport")),
                            "p2p") == 0;
                ok = ok && filtered_plan &&
                     strcmp(json_get_str(json_get(filtered_plan,
                                                  "fallback_transport")),
                            "bootstrap") == 0;
                ok = ok &&
                     strcmp(json_get_str(json_get(&filtered_root,
                                                  "source_projection")),
                            "znam_projection") == 0;
                json_free(&filtered_root);
            }

            {
                uint8_t invalid_resp[8192];
                struct json_value invalid_root;
                rpc_name_set_state(&ndb);
                size_t in = api_handle_request(
                    "GET", "/api/v1/names/alice/services?valid=maybe",
                    NULL, 0, invalid_resp, sizeof(invalid_resp));
                rpc_name_set_state(NULL);
                invalid_resp[in < sizeof(invalid_resp) ? in :
                             sizeof(invalid_resp) - 1] = '\0';
                const char *invalid_body =
                    api_test_body(invalid_resp, in, sizeof(invalid_resp));
                json_init(&invalid_root);
                ok = ok && in > 0 &&
                     strstr((char *)invalid_resp, "400 Bad Request") != NULL &&
                     invalid_body &&
                     json_read(&invalid_root, invalid_body,
                               strlen(invalid_body));
                const struct json_value *allowed =
                    ok ? json_get(&invalid_root, "allowed_filters") : NULL;
                ok = ok &&
                     strcmp(json_get_str(json_get(&invalid_root, "schema")),
                            "zcl.rest_error.v1") == 0;
                ok = ok &&
                     strcmp(json_get_str(json_get(&invalid_root, "error")),
                            "invalid_name_service_filter") == 0;
                ok = ok && allowed &&
                     strcmp(json_get_str(json_get(allowed, "valid")),
                            "true,false") == 0;
                json_free(&invalid_root);

                rpc_name_set_state(&ndb);
                in = api_handle_request(
                    "GET", "/api/v1/names/alice/services?tranport=p2p",
                    NULL, 0, invalid_resp, sizeof(invalid_resp));
                rpc_name_set_state(NULL);
                invalid_resp[in < sizeof(invalid_resp) ? in :
                             sizeof(invalid_resp) - 1] = '\0';
                invalid_body =
                    api_test_body(invalid_resp, in, sizeof(invalid_resp));
                json_init(&invalid_root);
                ok = ok && in > 0 &&
                     strstr((char *)invalid_resp, "400 Bad Request") != NULL &&
                     invalid_body &&
                     json_read(&invalid_root, invalid_body,
                               strlen(invalid_body));
                ok = ok &&
                     strcmp(json_get_str(json_get(&invalid_root, "error")),
                            "invalid_name_service_filter") == 0;
                ok = ok &&
                     strstr(json_get_str(json_get(&invalid_root, "message")),
                            "unknown filter 'tranport'") != NULL;
                json_free(&invalid_root);
            }
        }

        rpc_name_set_state(NULL);
        if (opened)
            node_db_close(&ndb);
        char cmd[384];
        snprintf(cmd, sizeof(cmd), "rm -rf %s", dbdir);
        system(cmd);

        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    return failures;
}
