/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * API status surfaces: node status tip identity, download statistics, binary
 * identity, the public status summary, and the agent summary aliases.
 */

#include "test/api_test_fixtures.h"

int api_status_focused_tests(void)
{
    int failures = 0;
    uint8_t resp[8192];

    printf("api: node status tip identity follows provable tip... ");
    {
        test_reset_shared_globals();
        struct main_state ms;
        struct block_index *blocks[4] = {0};
        bool ok = api_test_build_chain(&ms, blocks, 4);
        reducer_frontier_provable_tip_set(1);
        api_set_state(&ms, NULL, NULL, NULL, api_test_datadir());

        char hstar_hex[65] = {0};
        char active_hex[65] = {0};
        if (blocks[1] && blocks[1]->phashBlock)
            uint256_get_hex(blocks[1]->phashBlock, hstar_hex);
        if (blocks[3] && blocks[3]->phashBlock)
            uint256_get_hex(blocks[3]->phashBlock, active_hex);
        char expected[96];
        char forbidden[96];
        snprintf(expected, sizeof(expected), "\"tip_hash\":\"%s\"",
                 hstar_hex);
        snprintf(forbidden, sizeof(forbidden), "\"tip_hash\":\"%s\"",
                 active_hex);

        size_t n = api_handle_request("GET", "/api/node/status", NULL, 0,
                                      resp, sizeof(resp));
        resp[n < sizeof(resp) ? n : sizeof(resp) - 1] = '\0';
        ok = ok && n > 0;
        ok = ok && strstr((char *)resp, "\"tip_height\":1") != NULL;
        ok = ok && strstr((char *)resp, expected) != NULL;
        ok = ok && strstr((char *)resp, forbidden) == NULL;
        const char *body = api_test_body(resp, n, sizeof(resp));
        struct json_value root;
        json_init(&root);
        ok = ok && body && json_read(&root, body, strlen(body));
        ok = ok && strcmp(json_get_str(json_get(&root, "schema")),
                          "zcl.node_status.v1") == 0;
        ok = ok && api_test_expect_freshness(&root, "served_tip",
                                             1, 1, true);
        const struct json_value *chain = json_get(&root, "chain");
        ok = ok && chain != NULL;
        ok = ok && json_get_int(json_get(chain, "tip_height")) == 1;
        ok = ok && strcmp(json_get_str(json_get(chain, "tip_hash")),
                          hstar_hex) == 0;
        const struct json_value *errors = json_get(&root, "errors");
        ok = ok && errors && json_get(errors, "recent") != NULL;
        json_free(&root);

        api_set_state(NULL, NULL, NULL, NULL, NULL);
        reducer_frontier_provable_tip_reset();
        main_state_free(&ms);
        test_reset_shared_globals();

        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("api: node/status, public status, and health download blocks "
           "gained the throughput fields they were missing... ");
    {
        test_reset_shared_globals();
        struct main_state ms;
        struct block_index *blocks[2] = {0};
        bool ok = api_test_build_chain(&ms, blocks, 2);
        reducer_frontier_provable_tip_set(1);
        api_set_state(&ms, NULL, NULL, NULL, api_test_datadir());

        static const char *routes[] = {
            "/api/node/status", "/api/status", "/api/health",
        };
        for (size_t i = 0; i < sizeof(routes) / sizeof(routes[0]); i++) {
            size_t n = api_handle_request("GET", routes[i], NULL, 0,
                                          resp, sizeof(resp));
            const char *body = api_test_body(resp, n, sizeof(resp));
            struct json_value root;
            json_init(&root);
            ok = ok && n > 0 && body && json_read(&root, body, strlen(body));
            const struct json_value *download =
                ok ? json_get(&root, "download") : NULL;
            ok = ok && download != NULL;
            /* The pre-existing abbreviated fields must still be present
             * (behavior-preserving)... */
            ok = ok && json_get(download, "requested") != NULL;
            ok = ok && json_get(download, "received") != NULL;
            ok = ok && json_get(download, "timed_out") != NULL;
            ok = ok && json_get(download, "in_flight") != NULL;
            ok = ok && json_get(download, "queued") != NULL;
            /* ...and the throughput fields that used to be missing on
             * these three endpoints must now be there too (additive
             * fix, drift closed by the shared download_stats_push_json
             * serializer). */
            ok = ok && json_get(download, "bytes_downloaded") != NULL;
            ok = ok && json_get(download, "mbps_avg") != NULL;
            ok = ok && json_get(download, "gb_downloaded") != NULL;
            json_free(&root);
            if (!ok) {
                fprintf(stderr, "  route %s missing a download field\n",
                        routes[i]);
                break;
            }
        }
        /* /api/health additionally keeps its queue_backed_up field. */
        {
            size_t n = api_handle_request("GET", "/api/health", NULL, 0,
                                          resp, sizeof(resp));
            const char *body = api_test_body(resp, n, sizeof(resp));
            struct json_value root;
            json_init(&root);
            ok = ok && n > 0 && body && json_read(&root, body, strlen(body));
            const struct json_value *download =
                ok ? json_get(&root, "download") : NULL;
            ok = ok && download &&
                 json_get(download, "queue_backed_up") != NULL;
            json_free(&root);
        }

        api_set_state(NULL, NULL, NULL, NULL, NULL);
        reducer_frontier_provable_tip_reset();
        main_state_free(&ms);
        test_reset_shared_globals();

        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("api: downloadstats REST exposes throughput alongside its "
           "existing full diagnostics (site1/site2 drift closed)... ");
    {
        test_reset_shared_globals();

        size_t n = api_handle_request("GET", "/api/downloadstats", NULL, 0,
                                      resp, sizeof(resp));
        const char *body = api_test_body(resp, n, sizeof(resp));
        struct json_value root;
        json_init(&root);
        bool ok = n > 0 && body && json_read(&root, body, strlen(body));
        ok = ok && strcmp(json_get_str(json_get(&root, "schema")),
                          "zcl.downloadstats.v1") == 0;
        /* Core counts (always present). */
        ok = ok && json_get(&root, "requested") != NULL;
        ok = ok && json_get(&root, "received") != NULL;
        ok = ok && json_get(&root, "timed_out") != NULL;
        ok = ok && json_get(&root, "in_flight") != NULL;
        ok = ok && json_get(&root, "queued") != NULL;
        /* Diagnostics this endpoint already had. */
        ok = ok && json_get(&root, "orphaned") != NULL;
        ok = ok && json_get(&root, "accounting_drift") != NULL;
        ok = ok && json_get(&root, "last_assign_result") != NULL;
        /* Throughput fields it was MISSING before the consolidation. */
        ok = ok && json_get(&root, "bytes_downloaded") != NULL;
        ok = ok && json_get(&root, "mbps_avg") != NULL;
        ok = ok && json_get(&root, "gb_downloaded") != NULL;
        json_free(&root);

        test_reset_shared_globals();

        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("api: download_stats_snapshot_collect(full=false) is a "
           "counts-consistent subset of full=true (shared collector)... ");
    {
        struct download_stats_snapshot full_snap = {0};
        struct download_stats_snapshot thin_snap = {0};
        download_stats_snapshot_collect(&full_snap, true);
        download_stats_snapshot_collect(&thin_snap, false);

        bool ok = full_snap.requested == thin_snap.requested;
        ok = ok && full_snap.received == thin_snap.received;
        ok = ok && full_snap.timed_out == thin_snap.timed_out;
        ok = ok && full_snap.in_flight == thin_snap.in_flight;
        ok = ok && full_snap.queued == thin_snap.queued;
        ok = ok && full_snap.bytes_downloaded == thin_snap.bytes_downloaded;
        ok = ok && full_snap.mbps_avg == thin_snap.mbps_avg;

        struct json_value full_obj;
        struct json_value thin_obj;
        json_init(&full_obj);
        json_set_object(&full_obj);
        download_stats_push_json(&full_obj, &full_snap, true);
        json_init(&thin_obj);
        json_set_object(&thin_obj);
        download_stats_push_json(&thin_obj, &thin_snap, false);
        /* full=true carries extended diagnostics full=false does not. */
        ok = ok && json_get(&full_obj, "last_assign_result") != NULL;
        ok = ok && json_get(&full_obj, "queued_forward") != NULL;
        ok = ok && json_get(&full_obj, "queued_history") != NULL;
        ok = ok && json_get(&full_obj, "in_flight_forward") != NULL;
        ok = ok && json_get(&full_obj, "in_flight_history") != NULL;
        ok = ok && json_get(&thin_obj, "last_assign_result") == NULL;
        /* Both push the same core + throughput fields. */
        ok = ok && json_get(&full_obj, "bytes_downloaded") != NULL;
        ok = ok && json_get(&thin_obj, "bytes_downloaded") != NULL;
        json_free(&full_obj);
        json_free(&thin_obj);

        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("api: node identity exposes source SHA-256 + Git trace; "
           "bootstrapstatus keeps client_name... ");
    {
        /* Invoke the registered actor directly (bypassing
         * rpc_table_execute()'s RPC-server warmup gate, same pattern as
         * the existing name_list RPC tests above) so this test does not
         * depend on set_rpc_warmup_finished() having been called. */
        struct rpc_table misc_tbl;
        struct rpc_table net_tbl;
        struct json_value params;
        struct json_value result = {0};
        const struct rpc_command *cmd;

        rpc_table_init(&misc_tbl);
        register_misc_rpc_commands(&misc_tbl);
        rpc_table_init(&net_tbl);
        register_net_rpc_commands(&net_tbl);
        rpc_net_set_connman(NULL);

        json_init(&params);
        json_set_array(&params);

        cmd = rpc_table_find(&misc_tbl, "getinfo");
        bool ok = cmd && cmd->actor(&params, false, &result);
        ok = ok && json_get(&result, "version") != NULL;
        ok = ok && strcmp(json_get_str(json_get(&result, "subversion")),
                          CLIENT_NAME) == 0;
        ok = ok && strcmp(json_get_str(json_get(&result, "build_commit")),
                          zcl_build_commit()) == 0;
        ok = ok && strcmp(json_get_str(json_get(&result,
                                                "source_id_sha256")),
                          zcl_build_source_id_sha256()) == 0;
        ok = ok && json_get_int(json_get(&result, "protocolversion")) ==
                       PROTOCOL_VERSION;
        json_free(&result);

        json_init(&result);
        cmd = rpc_table_find(&net_tbl, "getnetworkinfo");
        ok = ok && cmd && cmd->actor(&params, false, &result);
        ok = ok && strcmp(json_get_str(json_get(&result, "subversion")),
                          CLIENT_NAME) == 0;
        ok = ok && strcmp(json_get_str(json_get(&result, "build_commit")),
                          zcl_build_commit()) == 0;
        ok = ok && strcmp(json_get_str(json_get(&result,
                                                "source_id_sha256")),
                          zcl_build_source_id_sha256()) == 0;
        json_free(&result);

        json_init(&result);
        cmd = rpc_table_find(&net_tbl, "bootstrapstatus");
        ok = ok && cmd && cmd->actor(&params, false, &result);
        const struct json_value *binary =
            ok ? json_get(&result, "binary") : NULL;
        ok = ok && binary != NULL;
        /* Pre-existing field name preserved (behavior-preserving)... */
        ok = ok && strcmp(json_get_str(json_get(binary, "client_name")),
                          CLIENT_NAME) == 0;
        /* ...alongside the shared helper's "subversion" name and the
         * build_commit it already carried. */
        ok = ok && strcmp(json_get_str(json_get(binary, "subversion")),
                          CLIENT_NAME) == 0;
        ok = ok && strcmp(json_get_str(json_get(binary, "build_commit")),
                          zcl_build_commit()) == 0;
        ok = ok && strcmp(json_get_str(json_get(binary,
                                                "source_id_sha256")),
                          zcl_build_source_id_sha256()) == 0;
        json_free(&result);

        json_free(&params);
        rpc_net_set_connman(NULL);

        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("api: public status exposes compact summary shape... ");
    {
        test_reset_shared_globals();
        struct main_state ms;
        struct block_index *blocks[3] = {0};
        bool ok = api_test_build_chain(&ms, blocks, 3);
        reducer_frontier_provable_tip_set(2);
        rpc_agent_set_boot_context("canonical", "full",
                                   "/tmp/zcl-canonical", 18232, 8033,
                                   8443, 18034);
        api_set_state(&ms, NULL, NULL, NULL, api_test_datadir());

        size_t n = api_handle_request("GET", "/api/status", NULL, 0,
                                      resp, sizeof(resp));
        const char *body = api_test_body(resp, n, sizeof(resp));
        struct json_value root;
        json_init(&root);
        ok = ok && n > 0 && body && json_read(&root, body, strlen(body));
        ok = ok && strcmp(json_get_str(json_get(&root, "schema")),
                          "zcl.public_status.v3") == 0;
        ok = ok && strcmp(json_get_str(json_get(&root, "build_commit")),
                          zcl_build_commit()) == 0;
        ok = ok && api_test_expect_freshness(&root, "served_tip",
                                             2, 2, true);
        ok = ok && json_get(&root, "status") != NULL;
        ok = ok && json_get(&root, "height") != NULL;
        ok = ok && json_get(&root, "recommended_endpoints") != NULL;
        ok = ok && api_test_expect_readiness_shape(&root);
        ok = ok && api_test_expect_security_posture_shape(&root);
        ok = ok && api_test_expect_lane_safety_fields(
            &root, "canonical", false, false, true, "dev",
            "observe_only_or_use_dev_lane");
        json_free(&root);

        api_set_state(NULL, NULL, NULL, NULL, NULL);
        reducer_frontier_provable_tip_reset();
        main_state_free(&ms);
        test_reset_shared_globals();

        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("api: /api/v1/agent and compat aliases compact summary... ");
    {
        test_reset_shared_globals();
        struct main_state ms;
        struct block_index *blocks[3] = {0};
        struct bsp_decision decision;
        bool ok = api_test_build_chain(&ms, blocks, 3);
        memset(&decision, 0, sizeof(decision));
        decision.result = BSP_DECISION_USE_SOURCE;
        decision.selected_source = BSP_SOURCE_P2P;
        decision.local_height = 2;
        decision.target_height = 2;
        decision.projection_height = 2;
        node_health_test_set_chain_advance_decision_override(&decision);
        reducer_frontier_provable_tip_set(2);
        api_set_state(&ms, NULL, NULL, NULL, api_test_datadir());

        size_t n = api_handle_request("GET", "/api/v1/agent", NULL, 0,
                                      resp, sizeof(resp));
        const char *body = api_test_body(resp, n, sizeof(resp));
        struct json_value root;
        json_init(&root);
        ok = ok && n > 0 && body && json_read(&root, body, strlen(body));
        ok = ok && strcmp(json_get_str(json_get(&root, "schema")),
                          "zcl.public_status.v3") == 0;
        ok = ok && strcmp(json_get_str(json_get(&root, "api_version")),
                          "v1") == 0;
        ok = ok && strcmp(json_get_str(json_get(&root, "build_commit")),
                          zcl_build_commit()) == 0;
        ok = ok && api_test_expect_freshness(&root, "served_tip",
                                             2, 2, true);
        ok = ok && api_test_expect_readiness_shape(&root);
        ok = ok && api_test_expect_security_posture_shape(&root);
        ok = ok && api_test_expect_lane_safety_fields(
            &root, "canonical", false, false, true, "dev",
            "observe_only_or_use_dev_lane");
        const struct json_value *height_contract =
            json_get(&root, "height_contract");
        ok = ok && height_contract && height_contract->type == JSON_OBJ;
        ok = ok && strcmp(json_get_str(json_get(height_contract,
                                                "schema")),
                          "zcl.height_contract.v1") == 0;
        ok = ok && strcmp(json_get_str(json_get(height_contract,
                                                "status")),
                          "current") == 0;
        ok = ok && !json_get_bool(json_get(height_contract,
                                           "normal_lookahead"));
        ok = ok && json_get_int(json_get(height_contract,
                                         "served_tip_height")) == 2;
        ok = ok && json_get_int(json_get(height_contract,
                                         "active_tip_height")) == 2;
        ok = ok && json_get_int(json_get(height_contract,
                                         "header_tip_height")) == 2;
        ok = ok && strcmp(json_get_str(json_get(height_contract,
                                                "external_height_is")),
                          "served_tip_height") == 0;
        const struct json_value *resources =
            json_get(&root, "resources");
        ok = ok && resources && resources->type == JSON_OBJ;
        ok = ok && strcmp(json_get_str(json_get(resources, "schema")),
                          "zcl.node_resources.v1") == 0;
        ok = ok && json_get(resources, "rss_mb") != NULL;
        ok = ok && json_get(resources, "cgroup_memory_available") != NULL;
        ok = ok && json_get(resources, "cgroup_memory_current_mb") != NULL;
        ok = ok && json_get(resources, "cgroup_memory_high_mb") != NULL;
        ok = ok && json_get(resources, "cgroup_memory_max_mb") != NULL;
        ok = ok && json_get(resources,
                            "cgroup_memory_stat_available") != NULL;
        ok = ok && json_get(resources, "cgroup_memory_anon_mb") != NULL;
        ok = ok && json_get(resources, "cgroup_memory_file_mb") != NULL;
        ok = ok && json_get(resources,
                            "cgroup_memory_working_set_mb") != NULL;
        ok = ok && json_get(resources,
                            "cgroup_memory_reclaimable_mb") != NULL;
        ok = ok && json_get(resources, "cgroup_memory_watch") != NULL;
        ok = ok && json_get(resources, "memory_pressure") != NULL;
        ok = ok && json_get(resources, "memory_pressure_detail") != NULL;
        ok = ok && json_get(resources, "pressure_basis") != NULL;
        ok = ok && json_get(resources, "uptime_seconds") != NULL;
        const struct json_value *lane =
            json_get(&root, "operator_lane");
        ok = ok && lane && lane->type == JSON_OBJ;
        ok = ok && strcmp(json_get_str(json_get(lane, "schema")),
                          "zcl.operator_lane.v1") == 0;
        ok = ok && strcmp(json_get_str(json_get(lane, "lane")),
                          "canonical") == 0;
        ok = ok && json_get_bool(json_get(lane, "canonical"));
        ok = ok && !json_get_bool(json_get(lane, "development"));
        ok = ok && strcmp(json_get_str(json_get(lane,
                                                "restart_policy")),
                          "operator_gated") == 0;
        ok = ok && !json_get_bool(json_get(lane,
                                           "automation_restart_ok"));
        ok = ok && !json_get_bool(json_get(lane,
                                           "automation_deploy_ok"));
        ok = ok && json_get_bool(json_get(lane,
                                          "requires_operator_confirmation"));
        const struct json_value *safety =
            json_get(lane, "deployment_safety");
        ok = ok && safety && safety->type == JSON_OBJ;
        ok = ok && strcmp(json_get_str(json_get(safety, "schema")),
                          "zcl.operator_deployment_safety.v1") == 0;
        ok = ok && json_get_bool(json_get(safety,
                                          "protects_public_endpoint"));
        ok = ok && !json_get_bool(json_get(safety,
                                           "automation_deploy_ok"));
        ok = ok && strcmp(json_get_str(json_get(safety,
                                                "safe_default_action")),
                          "observe_only_or_use_dev_lane") == 0;
        const struct json_value *restart_watchdog =
            json_get(&root, "restart_watchdog");
        ok = ok && restart_watchdog && restart_watchdog->type == JSON_OBJ;
        ok = ok && strcmp(json_get_str(json_get(restart_watchdog,
                                                "schema")),
                          "zcl.restart_watchdog.v1") == 0;
        ok = ok && json_get(restart_watchdog, "status") != NULL;
        ok = ok && json_get(restart_watchdog,
                            "last_restart_autonomous") != NULL;
        ok = ok && json_get(restart_watchdog,
                            "last_restart_reason") != NULL;
        ok = ok && json_get(restart_watchdog,
                            "no_progress_restarts") != NULL;
        json_free(&root);

        reducer_frontier_provable_tip_set(1);
        n = api_handle_request("GET", "/api/v1/agent", NULL, 0,
                               resp, sizeof(resp));
        body = api_test_body(resp, n, sizeof(resp));
        json_init(&root);
        ok = ok && n > 0 && body && json_read(&root, body, strlen(body));
        height_contract = json_get(&root, "height_contract");
        ok = ok && height_contract && height_contract->type == JSON_OBJ;
        ok = ok && strcmp(json_get_str(json_get(height_contract,
                                                "status")),
                          "normal_lookahead") == 0;
        ok = ok && json_get_bool(json_get(height_contract,
                                          "normal_lookahead"));
        ok = ok && json_get_int(json_get(height_contract,
                                         "served_tip_height")) == 1;
        ok = ok && json_get_int(json_get(height_contract,
                                         "active_tip_height")) == 2;
        ok = ok && json_get_int(json_get(height_contract,
                                         "target_height")) == 2;
        ok = ok && json_get_int(json_get(height_contract,
                                         "served_gap_blocks")) == 1;
        ok = ok && json_get(height_contract,
                            "external_height_semantics") != NULL;
        ok = ok && json_get(height_contract,
                            "active_tip_semantics") != NULL;
        json_free(&root);
        reducer_frontier_provable_tip_set(2);

        n = api_handle_request("GET", "/api/v1/node", NULL, 0,
                               resp, sizeof(resp));
        body = api_test_body(resp, n, sizeof(resp));
        json_init(&root);
        ok = ok && n > 0 && body && json_read(&root, body, strlen(body));
        ok = ok && strcmp(json_get_str(json_get(&root, "schema")),
                          "zcl.public_status.v3") == 0;
        ok = ok && strcmp(json_get_str(json_get(&root, "build_commit")),
                          zcl_build_commit()) == 0;
        ok = ok && strcmp(json_get_str(json_get(&root,
                                                "source_projection")),
                          "served_tip") == 0;
        json_free(&root);

        n = api_handle_request("GET", "/api/agent", NULL, 0,
                               resp, sizeof(resp));
        body = api_test_body(resp, n, sizeof(resp));
        json_init(&root);
        ok = ok && n > 0 && body && json_read(&root, body, strlen(body));
        ok = ok && strcmp(json_get_str(json_get(&root, "schema")),
                          "zcl.public_status.v3") == 0;
        ok = ok && strcmp(json_get_str(json_get(&root, "build_commit")),
                          zcl_build_commit()) == 0;
        ok = ok && strcmp(json_get_str(json_get(&root,
                                                "source_projection")),
                          "served_tip") == 0;
        json_free(&root);

        api_set_state(NULL, NULL, NULL, NULL, NULL);
        rpc_agent_set_boot_context(NULL, NULL, NULL, 0, 0, 0, 0);
        node_health_test_set_chain_advance_decision_override(NULL);
        reducer_frontier_provable_tip_reset();
        main_state_free(&ms);
        test_reset_shared_globals();

        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    return failures;
}
