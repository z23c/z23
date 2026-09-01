/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * API route table: fixed and dynamic resource routes, route<->command parity,
 * version prefix handling, and the endpoint edge cases around them.
 */

#include "test/api_test_fixtures.h"

int api_route_table_focused_tests(void)
{
    int failures = 0;
    uint8_t resp[8192];

    printf("api: milestone endpoint returns node-computed ASCII bars... ");
    {
        uint8_t agent_resp[65536];
        size_t agent_n = api_handle_request("GET", "/api/v1/agent", NULL, 0,
                                            agent_resp, sizeof(agent_resp));
        const char *agent_body = api_test_body(agent_resp, agent_n,
                                               sizeof(agent_resp));
        struct json_value agent_root;
        json_init(&agent_root);
        bool agent_ok = agent_n > 0 && agent_body &&
            json_read(&agent_root, agent_body, strlen(agent_body));

        size_t n = api_handle_request("GET", "/api/v1/milestone", NULL, 0,
                                      resp, sizeof(resp));
        const char *body = api_test_body(resp, n, sizeof(resp));
        struct json_value root;
        json_init(&root);
        bool ok = n > 0 && body && json_read(&root, body, strlen(body));
        const struct json_value *ascii = json_get(&root, "ascii");
        const struct json_value *bars = json_get(&root, "bars");
        const struct json_value *criteria = json_get(&root, "criteria");
        const struct json_value *operator_proofs =
            json_get(&root, "operator_proofs");
        const struct json_value *proof_items =
            operator_proofs ? json_get(operator_proofs, "items") : NULL;
        const struct json_value *cold_start =
            proof_items ? json_at(proof_items, 2) : NULL;
        const struct json_value *soak =
            proof_items ? json_at(proof_items, 5) : NULL;
        const struct json_value *live = json_get(&root, "live");
        const char *live_source = json_get_str(json_get(live, "source"));
        ok = ok && strcmp(json_get_str(json_get(&root, "schema")),
                          "zcl.milestone_status.v2") == 0;
        ok = ok && strcmp(json_get_str(json_get(&root, "milestone")),
                          "v1 MVP") == 0;
        ok = ok && json_get_int(json_get(&root,
                          "mvp_readiness_score")) == 4;
        ok = ok && json_get_int(json_get(&root, "target_score")) == 8;
        ok = ok && ascii && strstr(json_get_str(json_get(ascii, "goals")),
                                   "goals [#####-----] 4/8") != NULL;
        ok = ok && bars && strcmp(json_get_str(json_get(json_get(bars,
                          "subgoals"), "bar")), "[########--]") == 0;
        ok = ok && criteria && json_size(criteria) == 8;
        ok = ok && operator_proofs &&
            strcmp(json_get_str(json_get(operator_proofs, "schema")),
                   "zcl.mvp_operator_proofs.v1") == 0;
        ok = ok && json_get_int(json_get(operator_proofs,
                                         "accepted_count")) == 4;
        ok = ok && json_get_int(json_get(operator_proofs,
                                         "pending_count")) == 4;
        ok = ok && proof_items && json_size(proof_items) == 8;
        ok = ok && cold_start &&
            strcmp(json_get_str(json_get(cold_start, "key")),
                   "cold_start_sync") == 0;
        ok = ok && cold_start &&
            strcmp(json_get_str(json_get(cold_start, "proof_command")),
                   "make mvp-coldstart-to-tip-local") == 0;
        ok = ok && soak &&
            strcmp(json_get_str(json_get(soak, "key")),
                   "seven_day_soak") == 0;
        ok = ok && soak &&
            strcmp(json_get_str(json_get(soak, "proof_scope")),
                   "live_window") == 0;
        ok = ok && soak &&
            strcmp(json_get_str(json_get(soak, "primary_blocker")),
                   "clean_168h_soak_window_pending") == 0;
        bool live_full_agent = live_source &&
            strcmp(live_source, "agent_cached_summary") == 0;
        bool live_agent_fallback = live_source &&
            strcmp(live_source,
                   "agent_cached_summary_with_fallbacks") == 0;
        ok = ok && live && (live_full_agent || live_agent_fallback);
        ok = ok && strcmp(json_get_str(json_get(live, "source_schema")),
                          "zcl.public_status.v3") == 0;
        ok = ok && json_get_bool(json_get(live,
                                          "agent_summary_available"));
        ok = ok && json_get_bool(json_get(live, "agent_fields_complete")) ==
            live_full_agent;
        if (live_full_agent)
            ok = ok && strcmp(json_get_str(json_get(live,
                                                    "fallback_source")),
                              "none") == 0;
        if (live_agent_fallback)
            ok = ok && strcmp(json_get_str(json_get(live,
                                                    "fallback_source")),
                              "none") != 0;
        ok = ok && json_get(live, "agent_status") != NULL;
        ok = ok && json_get(live, "readiness_status") != NULL;
        ok = ok && json_get(live, "height_contract_status") != NULL;
        int64_t agent_served =
            json_get_int(json_get(&agent_root, "served_height"));
        if (ok && agent_ok && live_full_agent && agent_served > 0) {
            const struct json_value *agent_peers =
                json_get(&agent_root, "peers");
            const struct json_value *agent_services =
                json_get(&agent_root, "services");
            bool agent_onion =
                json_get_bool(json_get(agent_services, "tor_enabled")) &&
                json_get_bool(json_get(agent_services, "tor_ready")) &&
                json_get_bool(json_get(agent_services,
                                       "onion_service_ready"));

            ok = ok && json_get_int(json_get(live, "served_height")) ==
                json_get_int(json_get(&agent_root, "served_height"));
            ok = ok && json_get_int(json_get(live, "indexed_height")) ==
                json_get_int(json_get(&agent_root, "indexed_height"));
            ok = ok && json_get_int(json_get(live, "header_height")) ==
                json_get_int(json_get(&agent_root, "header_height"));
            ok = ok && json_get_int(json_get(live, "peer_best_height")) ==
                json_get_int(json_get(&agent_root, "peer_best_height"));
            ok = ok && json_get_int(json_get(live, "target_height")) ==
                json_get_int(json_get(&agent_root, "target_height"));
            ok = ok && json_get_int(json_get(live, "gap")) ==
                json_get_int(json_get(&agent_root, "gap"));
            ok = ok && json_get_int(json_get(live, "peers")) ==
                json_get_int(json_get(agent_peers, "total"));
            ok = ok && json_get_bool(json_get(live, "tor_enabled")) ==
                json_get_bool(json_get(agent_services, "tor_enabled"));
            ok = ok && json_get_bool(json_get(live, "onion_ready")) ==
                agent_onion;
            ok = ok && strcmp(json_get_str(json_get(live, "sync_state")),
                              json_get_str(json_get(&agent_root,
                                                    "sync_state"))) == 0;
        }
        json_free(&agent_root);
        json_free(&root);

        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("api: refold endpoint reports anchor readiness... ");
    {
        size_t n = api_handle_request("GET", "/api/v1/refold", NULL, 0,
                                      resp, sizeof(resp));
        const char *body = api_test_body(resp, n, sizeof(resp));
        struct json_value root;
        json_init(&root);
        bool ok = n > 0 && body && json_read(&root, body, strlen(body));
        const struct json_value *snap = json_get(&root, "anchor_snapshot");
        const struct json_value *commands = json_get(&root, "commands");
        ok = ok && strcmp(json_get_str(json_get(&root, "schema")),
                          "zcl.refold_status.v2") == 0;
        ok = ok && strcmp(json_get_str(json_get(&root, "api_version")),
                          "v1") == 0;
        ok = ok && strstr(json_get_str(json_get(&root, "purpose")),
                          "UTXO anchor rebuild") != NULL;
        ok = ok && strstr(json_get_str(json_get(&root, "plain_english")),
                          "borrowed snapshot seed") != NULL;
        ok = ok && strcmp(json_get_str(json_get(&root,
                                                "internal_mechanism")),
                          "-refold-from-anchor") == 0;
        ok = ok && !json_get_bool(json_get(&root, "ready_for_refold"));
        ok = ok && strcmp(json_get_str(json_get(&root, "primary_blocker")),
                          "missing_verified_anchor_snapshot") == 0;
        ok = ok && snap && json_get(snap, "path") != NULL;
        ok = ok && commands &&
             strcmp(json_get_str(json_get(commands, "native")),
                    "z23 refold") == 0;
        json_free(&root);

        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("api: unsupported version reports supported versions... ");
    {
        size_t n = api_handle_request("GET", "/api/v2/agent", NULL, 0,
                                      resp, sizeof(resp));
        const char *body = api_test_body(resp, n, sizeof(resp));
        struct json_value root;
        json_init(&root);
        bool ok = n > 0 && strstr((char *)resp,
                                  "HTTP/1.1 400 Bad Request") != NULL;
        ok = ok && body && json_read(&root, body, strlen(body));
        ok = ok && strcmp(json_get_str(json_get(&root, "schema")),
                          "zcl.rest_error.v1") == 0;
        ok = ok && strcmp(json_get_str(json_get(&root, "api_version")),
                          "v1") == 0;
        ok = ok && strcmp(json_get_str(json_get(&root, "error")),
                          "unsupported_api_version") == 0;
        ok = ok && strcmp(json_get_str(json_get(&root,
                          "requested_version")), "v2") == 0;
        const struct json_value *supported =
            ok ? json_get(&root, "supported_versions") : NULL;
        ok = ok && json_size(supported) == 1;
        ok = ok && strcmp(json_get_str(json_at(supported, 0)), "v1") == 0;
        ok = ok && strcmp(json_get_str(json_get(&root, "base_path")),
                          "/api/v1") == 0;
        json_free(&root);

        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("api: resource route table exposes controller-style names... ");
    {
        bool saw_agent = false;
        bool saw_milestone = false;
        bool saw_refold = false;
        bool saw_blocks = false;
        bool saw_factoids = false;
        size_t count = api_resource_route_count();
        for (size_t i = 0; i < count; i++) {
            const char *resource = api_resource_route_resource_at(i);
            const char *action = api_resource_route_action_at(i);
            if (!resource || !action)
                continue;
            if (strcmp(resource, "agent") == 0 &&
                strcmp(action, "show") == 0)
                saw_agent = true;
            if (strcmp(resource, "milestone") == 0 &&
                strcmp(action, "show") == 0)
                saw_milestone = true;
            if (strcmp(resource, "refold") == 0 &&
                strcmp(action, "show") == 0)
                saw_refold = true;
            if (strcmp(resource, "blocks") == 0 &&
                strcmp(action, "index") == 0)
                saw_blocks = true;
            if (strcmp(resource, "factoids") == 0 &&
                strcmp(action, "show") == 0)
                saw_factoids = true;
        }
        bool ok = count >= 18 && saw_agent && saw_milestone && saw_refold &&
                  saw_blocks && saw_factoids;
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("api: every fixed route has a non-NULL command_path... ");
    {
        size_t count = api_resource_route_count();
        bool ok = count > 0;
        for (size_t i = 0; i < count; i++) {
            const char *command_path = api_resource_route_command_path_at(i);
            if (!command_path || !command_path[0]) {
                ok = false;
                break;
            }
        }
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("api: route<->command parity holds for known pairs... ");
    {
        bool saw_health_ops_health = false;
        bool saw_refold_recovery_status = false;
        bool saw_none_reason = false;
        size_t count = api_resource_route_count();
        for (size_t i = 0; i < count; i++) {
            const char *resource = api_resource_route_resource_at(i);
            const char *action = api_resource_route_action_at(i);
            const char *command_path = api_resource_route_command_path_at(i);
            if (!resource || !action || !command_path)
                continue;
            if (strcmp(resource, "health") == 0 &&
                strcmp(action, "show") == 0 &&
                strcmp(command_path, "ops.health") == 0)
                saw_health_ops_health = true;
            if (strcmp(resource, "refold") == 0 &&
                strcmp(action, "show") == 0 &&
                strcmp(command_path, "ops.recovery.status") == 0)
                saw_refold_recovery_status = true;
            if (strncmp(command_path, "none:", 5) == 0)
                saw_none_reason = true;
        }
        bool ok = saw_health_ops_health && saw_refold_recovery_status &&
                  saw_none_reason;
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("api: dynamic resource routes expose REST member metadata... ");
    {
        bool saw_block = false;
        bool saw_legacy_block = false;
        bool saw_tx = false;
        bool saw_legacy_tx = false;
        bool saw_address = false;
        bool saw_legacy_address = false;
        bool saw_token = false;
        bool saw_transfer = false;
        bool saw_file = false;
        bool saw_name = false;
        bool saw_legacy_name = false;
        bool saw_service_operation = false;
        size_t count = api_dynamic_resource_route_count();
        for (size_t i = 0; i < count; i++) {
            const char *pattern = api_dynamic_resource_route_pattern_at(i);
            const char *resource = api_dynamic_resource_route_resource_at(i);
            const char *action = api_dynamic_resource_route_action_at(i);
            if (!pattern || !resource || !action)
                continue;
            if (strcmp(pattern, "/api/blocks/{height_or_hash}") == 0 &&
                strcmp(resource, "blocks") == 0 &&
                strcmp(action, "show") == 0)
                saw_block = true;
            if (strcmp(pattern, "/api/block/{height_or_hash}") == 0 &&
                strcmp(resource, "blocks") == 0 &&
                strcmp(action, "show") == 0)
                saw_legacy_block = true;
            if (strcmp(pattern, "/api/transactions/{txid}") == 0 &&
                strcmp(resource, "transactions") == 0 &&
                strcmp(action, "show") == 0)
                saw_tx = true;
            if (strcmp(pattern, "/api/tx/{txid}") == 0 &&
                strcmp(resource, "transactions") == 0 &&
                strcmp(action, "show") == 0)
                saw_legacy_tx = true;
            if (strcmp(pattern, "/api/addresses/{address}") == 0 &&
                strcmp(resource, "addresses") == 0 &&
                strcmp(action, "show") == 0)
                saw_address = true;
            if (strcmp(pattern, "/api/address/{address}") == 0 &&
                strcmp(resource, "addresses") == 0 &&
                strcmp(action, "show") == 0)
                saw_legacy_address = true;
            if (strcmp(pattern, "/api/zslp/tokens/{token_id}") == 0 &&
                strcmp(resource, "zslp_tokens") == 0 &&
                strcmp(action, "show") == 0)
                saw_token = true;
            if (strcmp(pattern, "/api/zslp/tokens/{token_id}/transfers") == 0 &&
                strcmp(resource, "zslp_token_transfers") == 0 &&
                strcmp(action, "index") == 0)
                saw_transfer = true;
            if (strcmp(pattern, "/api/files/{sha3}") == 0 &&
                strcmp(resource, "files") == 0 &&
                strcmp(action, "show") == 0)
                saw_file = true;
            if (strcmp(pattern, "/api/names/{name}") == 0 &&
                strcmp(resource, "names") == 0 &&
                strcmp(action, "show") == 0)
                saw_name = true;
            if (strcmp(pattern, "/api/name/{name}") == 0 &&
                strcmp(resource, "names") == 0 &&
                strcmp(action, "show") == 0)
                saw_legacy_name = true;
            if (strcmp(pattern, "/api/service-operations/{operation_id}") == 0 &&
                strcmp(resource, "service_operations") == 0 &&
                strcmp(action, "show") == 0)
                saw_service_operation = true;
        }
        bool ok = count >= 16 && saw_block && saw_legacy_block && saw_tx &&
                  saw_legacy_tx && saw_address && saw_legacy_address &&
                  saw_token && saw_transfer && saw_file && saw_name &&
                  saw_legacy_name && saw_service_operation;
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("api: lookup resources emit REST schemas and freshness... ");
    {
        reducer_frontier_provable_tip_reset();
        reducer_frontier_provable_tip_set(11);
        api_test_set_rpc_call(api_test_lookup_rpc);

        size_t n = api_handle_request("GET", "/api/v1/blocks/10", NULL, 0,
                                      resp, sizeof(resp));
        const char *body = api_test_body(resp, n, sizeof(resp));
        struct json_value root;
        json_init(&root);
        bool ok = n > 0 && body && json_read(&root, body, strlen(body));
        ok = ok && strcmp(json_get_str(json_get(&root, "schema")),
                          "zcl.blocks.show.v1") == 0;
        ok = ok && api_test_expect_freshness(&root, "served_height",
                                             11, 11, true);
        ok = ok && json_get_int(json_get(&root, "height")) == 10;
        ok = ok && json_get_int(json_get(&root, "num_tx")) == 2;
        ok = ok && json_get_int(json_get(&root, "tx_returned")) == 2;
        ok = ok && !json_get_bool(json_get(&root, "tx_truncated"));
        ok = ok && strcmp(json_get_str(json_at(json_get(&root, "tx"), 0)),
                          API_TEST_TXID) == 0;
        json_free(&root);

        n = api_handle_request("GET", "/api/v1/block/10", NULL, 0,
                               resp, sizeof(resp));
        body = api_test_body(resp, n, sizeof(resp));
        json_init(&root);
        ok = ok && n > 0 && body && json_read(&root, body, strlen(body));
        ok = ok && strcmp(json_get_str(json_get(&root, "schema")),
                          "zcl.blocks.show.v1") == 0;
        ok = ok && json_get_int(json_get(&root, "height")) == 10;
        json_free(&root);

        n = api_handle_request("GET",
                               "/api/v1/transactions/" API_TEST_TXID,
                               NULL, 0, resp, sizeof(resp));
        body = api_test_body(resp, n, sizeof(resp));
        json_init(&root);
        ok = ok && n > 0 && body && json_read(&root, body, strlen(body));
        ok = ok && strcmp(json_get_str(json_get(&root, "schema")),
                          "zcl.transactions.show.v1") == 0;
        ok = ok && api_test_expect_freshness(&root, "served_height",
                                             11, 11, true);
        ok = ok && strcmp(json_get_str(json_get(&root, "txid")),
                          API_TEST_TXID) == 0;
        const struct json_value *vout = json_get(&root, "vout");
        const struct json_value *vin = json_get(&root, "vin");
        ok = ok && json_get_int(json_get(&root, "vout_returned")) == 1;
        ok = ok && strcmp(json_get_str(json_get(json_at(vout, 0),
                                                "address")),
                          API_TEST_ADDR) == 0;
        ok = ok && json_get_int(json_get(json_at(vin, 0), "vout")) == 1;
        json_free(&root);

        n = api_handle_request("GET", "/api/v1/addresses/" API_TEST_ADDR,
                               NULL, 0, resp, sizeof(resp));
        body = api_test_body(resp, n, sizeof(resp));
        json_init(&root);
        ok = ok && n > 0 && body && json_read(&root, body, strlen(body));
        ok = ok && strcmp(json_get_str(json_get(&root, "schema")),
                          "zcl.addresses.show.v1") == 0;
        ok = ok && api_test_expect_freshness(&root, "utxo_projection",
                                             11, 11, true);
        ok = ok && json_get_int(json_get(&root, "balance_sat")) ==
                  123456789;
        ok = ok && json_get_int(json_get(&root, "utxo_count")) == 1;
        const struct json_value *utxos = json_get(&root, "utxos");
        ok = ok && strcmp(json_get_str(json_get(json_at(utxos, 0),
                                                "txid")),
                          API_TEST_TXID) == 0;
        json_free(&root);

        n = api_handle_request("GET", "/api/v1/address/" API_TEST_ADDR,
                               NULL, 0, resp, sizeof(resp));
        body = api_test_body(resp, n, sizeof(resp));
        json_init(&root);
        ok = ok && n > 0 && body && json_read(&root, body, strlen(body));
        ok = ok && strcmp(json_get_str(json_get(&root, "schema")),
                          "zcl.addresses.show.v1") == 0;
        ok = ok && json_get_int(json_get(&root, "balance_sat")) ==
                  123456789;
        json_free(&root);

        n = api_handle_request("GET", "/api/tx/" API_TEST_TXID,
                               NULL, 0, resp, sizeof(resp));
        body = api_test_body(resp, n, sizeof(resp));
        json_init(&root);
        ok = ok && n > 0 && body && json_read(&root, body, strlen(body));
        ok = ok && strcmp(json_get_str(json_get(&root, "schema")),
                          "zcl.transactions.show.v1") == 0;
        json_free(&root);

        api_test_set_rpc_call(NULL);
        reducer_frontier_provable_tip_reset();

        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("api: events resource emits REST envelope and freshness... ");
    {
        event_log_init();
        progress_store_close();
        reducer_frontier_provable_tip_reset();
        api_set_state(NULL, NULL, NULL, NULL, NULL);
        event_emitf(EV_NODE_READY, 0, "height=4 peers=1");

        size_t n = api_handle_request("GET",
                                      "/api/events?limit=5&type=sys.",
                                      NULL, 0, resp, sizeof(resp));
        const char *body = api_test_body(resp, n, sizeof(resp));
        struct json_value root;
        json_init(&root);
        bool ok = n > 0 && body && json_read(&root, body, strlen(body));
        ok = ok && strcmp(json_get_str(json_get(&root, "schema")),
                          "zcl.events.index.v1") == 0;
        ok = ok && api_test_expect_freshness(&root, "event_projection",
                                             0, 0, true);
        ok = ok && strcmp(json_get_str(json_get(&root, "type")),
                          "sys.") == 0;
        ok = ok && json_get_int(json_get(&root, "limit")) == 5;
        const struct json_value *events = json_get(&root, "events");
        ok = ok && events && json_size(events) == 1;
        ok = ok && strcmp(json_get_str(json_get(json_at(events, 0),
                                                "type")),
                          "sys.ready") == 0;
        json_free(&root);

        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("api: empty block ID not routed... ");
    {
        size_t n = api_handle_request("GET", "/api/block/", NULL, 0,
                                       resp, sizeof(resp));
        resp[n < sizeof(resp) ? n : sizeof(resp) - 1] = '\0';
        bool ok = (n > 0);
        if (ok) printf("OK (got response, %zu bytes)\n", n);
        else { printf("FAIL\n"); failures++; }
    }

    printf("api: zero-length response buffer returns 0... ");
    {
        size_t n = api_handle_request("GET", "/api/blocks", NULL, 0, resp, 0);
        bool ok = (n == 0);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    return failures;
}
