/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * API health gates: agent impact mapping, the health blocking reason, served
 * gap grading, durable tip publication, and the frontier caps on hodl,
 * deep stats, and factoids.
 */

#include "test/api_test_fixtures.h"

int api_health_gate_focused_tests(void)
{
    int failures = 0;
    uint8_t resp[8192];

    printf("api: agentimpact maps block source policy to focused gates... ");
    {
        const char *params_json =
            "[\"app/services/src/block_source_policy.c\","
            "\"app/services/include/services/block_source_policy.h\"]";
        struct json_value params, result;
        json_init(&params);
        json_init(&result);
        bool ok = json_read(&params, params_json, strlen(params_json));
        ok = ok && rpc_agent_impact(&params, false, &result);
        ok = ok && strcmp(json_get_str(json_get(&result, "schema")),
                          "zcl.agent_impact.v2") == 0;
        ok = ok && json_get_int(json_get(&result, "files_count")) == 2;
        ok = ok && json_get_int(json_get(&result,
                                         "relevant_test_groups_count")) == 3;
        const struct json_value *groups =
            json_get(&result, "relevant_test_groups");
        ok = ok && api_test_array_has_str(groups,
                                          "block_source_policy");
        ok = ok && api_test_array_has_str(groups,
                                          "block_source_policy_status_json");
        ok = ok && api_test_array_has_str(groups, "make_lint_gates");
        const struct json_value *commands =
            json_get(&result, "recommended_commands");
        ok = ok && api_test_array_has_str(
            commands, "make t ONLY=block_source_policy");
        json_free(&params);
        json_free(&result);

        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("api: agentimpact maps ZNAM service directory filters... ");
    {
        const char *params_json =
            "[\"app/controllers/src/"
            "name_service_directory_filter_controller.c\"]";
        struct json_value params, result;
        json_init(&params);
        json_init(&result);
        bool ok = json_read(&params, params_json, strlen(params_json));
        ok = ok && rpc_agent_impact(&params, false, &result);
        ok = ok && strcmp(json_get_str(json_get(&result, "schema")),
                          "zcl.agent_impact.v2") == 0;
        ok = ok && json_get_int(json_get(&result, "files_count")) == 1;
        ok = ok && json_get_int(json_get(&result,
                                         "relevant_test_groups_count")) == 4;
        const struct json_value *groups =
            json_get(&result, "relevant_test_groups");
        ok = ok && api_test_array_has_str(groups, "znam");
        ok = ok && api_test_array_has_str(groups, "protocols");
        ok = ok && api_test_array_has_str(groups, "api");
        ok = ok && api_test_array_has_str(groups, "make_lint_gates");
        const struct json_value *commands =
            json_get(&result, "recommended_commands");
        ok = ok && api_test_array_has_str(commands, "make t ONLY=api");
        json_free(&params);
        json_free(&result);

        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("api: agentimpact maps json library to focused gates... ");
    {
        const char *params_json =
            "[\"lib/json/include/json/json.h\","
            "\"lib/test/src/test_json.c\"]";
        struct json_value params, result;
        json_init(&params);
        json_init(&result);
        bool ok = json_read(&params, params_json, strlen(params_json));
        ok = ok && rpc_agent_impact(&params, false, &result);
        ok = ok && strcmp(json_get_str(json_get(&result, "schema")),
                          "zcl.agent_impact.v2") == 0;
        ok = ok && json_get_int(json_get(&result, "files_count")) == 2;
        ok = ok && json_get_int(json_get(&result,
                                         "relevant_test_groups_count")) == 7;
        const struct json_value *groups =
            json_get(&result, "relevant_test_groups");
        ok = ok && api_test_array_has_str(groups, "json");
        ok = ok && api_test_array_has_str(groups, "rpc");
        ok = ok && api_test_array_has_str(groups, "api");
        ok = ok && api_test_array_has_str(groups, "syncdiag_rpc");
        ok = ok && api_test_array_has_str(groups, "zcode_package_registry");
        ok = ok && api_test_array_has_str(groups, "zcode_swarm_net");
        ok = ok && api_test_array_has_str(groups, "make_lint_gates");
        json_free(&params);
        json_free(&result);

        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("api: public status names health blocking reason... ");
    {
        test_reset_shared_globals();
        blocker_reset_for_testing();
        agent_security_posture_test_override_review_required(0);
        alerts_shutdown();
        unsetenv("ZCL_ALERTS_DISABLE");
        unsetenv("ZCL_ALERT_WEBHOOK_URL");
        alerts_init();
        alerts_reset();
        event_emitf(EV_OPERATOR_NEEDED, 0, "chain_integrity_failed");

        struct main_state ms;
        struct block_index *blocks[3] = {0};
        bool ok = api_test_build_chain(&ms, blocks, 3);
        reducer_frontier_provable_tip_set(2);
        api_set_state(&ms, NULL, NULL, NULL, api_test_datadir());

        size_t n = api_handle_request("GET", "/api/status", NULL, 0,
                                      resp, sizeof(resp));
        const char *body = api_test_body(resp, n, sizeof(resp));
        struct json_value root;
        json_init(&root);
        ok = ok && n > 0 && body && json_read(&root, body, strlen(body));
        ok = ok && strcmp(json_get_str(json_get(&root, "schema")),
                          "zcl.public_status.v3") == 0;
        ok = ok && strcmp(json_get_str(json_get(&root, "status")),
                          "blocked") == 0;
        ok = ok && !json_get_bool(json_get(&root, "healthy"));
        ok = ok && !json_get_bool(json_get(&root, "serving"));
        ok = ok && json_get_bool(json_get(&root, "operator_needed"));
        ok = ok && strcmp(json_get_str(json_get(&root,
                                                "primary_blocker")),
                          "operator_needed:chain_integrity_failed") == 0;
        ok = ok && strcmp(json_get_str(json_get(&root, "summary")),
                          "node has an active health blocker") == 0;
        ok = ok && strcmp(json_get_str(json_get(&root, "next_endpoint")),
                          "/api/v1/health") == 0;
        json_free(&root);

        n = api_handle_request("GET", "/api/v1/agent", NULL, 0,
                               resp, sizeof(resp));
        body = api_test_body(resp, n, sizeof(resp));
        json_init(&root);
        ok = ok && n > 0 && body && json_read(&root, body, strlen(body));
        ok = ok && strcmp(json_get_str(json_get(&root,
                                                "primary_blocker")),
                          "operator_needed:chain_integrity_failed") == 0;
        json_free(&root);

        alerts_shutdown();
        api_set_state(NULL, NULL, NULL, NULL, NULL);
        reducer_frontier_provable_tip_reset();
        main_state_free(&ms);
        agent_security_posture_test_override_review_required(-1);
        test_reset_shared_globals();

        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("api: public status treats small served gap as healthy... ");
    {
        test_reset_shared_globals();
        blocker_reset_for_testing();
        agent_security_posture_test_override_review_required(0);
        struct main_state ms;
        struct connman cm = {0};
        struct net_address addr = {0};
        struct p2p_node *node = NULL;
        struct block_index *blocks[ZCL_NODE_HEALTH_LAG_WARN_BLOCKS + 3] = {0};
        struct bsp_decision decision;
        const int served = 1;
        const int target = ZCL_NODE_HEALTH_LAG_WARN_BLOCKS;
        bool ok = api_test_build_chain(&ms, blocks, target + 1);
        ok = ok && api_test_init_connman_peer(&cm, &addr, &node, target);

        memset(&decision, 0, sizeof(decision));
        decision.result = BSP_DECISION_USE_SOURCE;
        decision.selected_source = BSP_SOURCE_P2P;
        decision.local_height = target;
        decision.target_height = target;
        decision.projection_height = target;
        struct bsp_source_status *p2p =
            &decision.sources[BSP_SOURCE_P2P];
        p2p->source = BSP_SOURCE_P2P;
        p2p->available = true;
        p2p->healthy = true;
        p2p->selectable = true;
        p2p->height = target;

        if (ok) {
            (void)node;
            reducer_frontier_provable_tip_set(served);
            /* A green public status means the node is synced, and being synced
             * requires it to have proven it holds the bodies for its own
             * history. This case is about the served-gap threshold, so state
             * the archive fact rather than depend on the health snapshot
             * upgrading itself unconditionally. */
            ok = body_history_test_publish_proven(target);
            node_health_test_set_log_head_override(target);
            node_health_test_set_chain_advance_decision_override(&decision);
            sync_set_state(SYNC_IDLE, "api status reset");
            sync_set_state(SYNC_FINDING_PEERS, "api status");
            sync_set_state(SYNC_HEADERS_DOWNLOAD, "api status");
            api_set_state(&ms, NULL, NULL, NULL, api_test_datadir());

            size_t n = api_handle_request("GET", "/api/status", NULL, 0,
                                          resp, sizeof(resp));
            const char *body = api_test_body(resp, n, sizeof(resp));
            struct json_value root;
            json_init(&root);
            ok = ok && n > 0 && body && json_read(&root, body, strlen(body));
            ok = ok && strcmp(json_get_str(json_get(&root, "status")),
                              "healthy") == 0;
            ok = ok && json_get_bool(json_get(&root, "healthy"));
            ok = ok && json_get_bool(json_get(&root, "serving"));
            ok = ok && !json_get_bool(json_get(&root, "operator_needed"));
            ok = ok && json_get_int(json_get(&root, "height")) == served;
            ok = ok && json_get_int(json_get(&root, "target_height")) ==
                target;
            ok = ok && json_get_int(json_get(&root, "gap")) ==
                target - served;
            ok = ok && strcmp(json_get_str(json_get(&root,
                                                    "primary_blocker")),
                              "none") == 0;
            ok = ok && json_get_int(json_get(&root, "served_height")) ==
                served;
            ok = ok && strcmp(json_get_str(json_get(&root,
                                                    "source_projection")),
                              "served_tip") == 0;
            ok = ok && json_get(&root, "freshness") != NULL;
            json_free(&root);

            agent_security_posture_test_override_review_required(1);
            n = api_handle_request("GET", "/api/status", NULL, 0,
                                   resp, sizeof(resp));
            body = api_test_body(resp, n, sizeof(resp));
            json_init(&root);
            ok = ok && n > 0 && body &&
                 json_read(&root, body, strlen(body));
            ok = ok && strcmp(json_get_str(json_get(&root, "status")),
                              "blocked") == 0;
            ok = ok && !json_get_bool(json_get(&root, "healthy"));
            ok = ok && !json_get_bool(json_get(&root, "serving"));
            ok = ok && strcmp(json_get_str(json_get(&root,
                                                    "primary_blocker")),
                              "review_required_test") == 0;
            json_free(&root);

            n = api_handle_request("GET", "/api/health", NULL, 0,
                                   resp, sizeof(resp));
            body = api_test_body(resp, n, sizeof(resp));
            json_init(&root);
            ok = ok && strstr((char *)resp,
                              "503 Service Unavailable") != NULL;
            ok = ok && body && json_read(&root, body, strlen(body));
            ok = ok && !json_get_bool(json_get(&root, "healthy"));
            ok = ok && !json_get_bool(json_get(&root, "serving"));
            ok = ok && api_test_expect_security_posture_shape(&root);
            json_free(&root);
            agent_security_posture_test_override_review_required(0);

            /* A transient worker/dependency blocker is operational warning
             * evidence, not authority to withdraw an already validated
             * public frontier.  Permanent chain-authority blockers still
             * hard-gate serving and /health. */
            struct blocker_record transient;
            ok = ok && blocker_init(
                &transient, "peer_floor.test_transient", "peer_floor",
                BLOCKER_TRANSIENT, "temporary peer assignment gap");
            ok = ok && blocker_set(&transient) == 0;
            n = api_handle_request("GET", "/api/health", NULL, 0,
                                   resp, sizeof(resp));
            body = api_test_body(resp, n, sizeof(resp));
            json_init(&root);
            ok = ok && strstr((char *)resp, "200 OK") != NULL;
            ok = ok && body && json_read(&root, body, strlen(body));
            ok = ok && json_get_bool(json_get(&root, "healthy"));
            ok = ok && json_get_bool(json_get(&root, "serving"));
            const struct json_value *health_status =
                json_get(&root, "status");
            ok = ok && health_status && json_get_bool(json_get(
                health_status, "warning"));
            ok = ok && strcmp(json_get_str(json_get(
                health_status, "typed_blocker_warning")),
                "peer_floor.test_transient") == 0;
            json_free(&root);

            n = api_handle_request("GET", "/api/status", NULL, 0,
                                   resp, sizeof(resp));
            body = api_test_body(resp, n, sizeof(resp));
            json_init(&root);
            ok = ok && body && json_read(&root, body, strlen(body));
            ok = ok && strcmp(json_get_str(json_get(&root, "status")),
                              "healthy") == 0;
            ok = ok && json_get_bool(json_get(&root, "serving"));
            ok = ok && json_get_bool(json_get(&root, "warning"));
            ok = ok && strcmp(json_get_str(json_get(
                &root, "typed_blocker_warning")),
                "peer_floor.test_transient") == 0;
            json_free(&root);
            blocker_clear("peer_floor.test_transient");

            struct blocker_record permanent;
            ok = ok && blocker_init(
                &permanent, "chain.test_authority_failure", "chain",
                BLOCKER_PERMANENT, "test chain authority failure");
            ok = ok && blocker_set(&permanent) == 0;
            n = api_handle_request("GET", "/api/health", NULL, 0,
                                   resp, sizeof(resp));
            body = api_test_body(resp, n, sizeof(resp));
            json_init(&root);
            ok = ok && strstr((char *)resp,
                              "503 Service Unavailable") != NULL;
            ok = ok && body && json_read(&root, body, strlen(body));
            ok = ok && !json_get_bool(json_get(&root, "healthy"));
            ok = ok && !json_get_bool(json_get(&root, "serving"));
            health_status = json_get(&root, "status");
            ok = ok && health_status && strcmp(json_get_str(json_get(
                health_status, "blocking_reason")),
                "chain.test_authority_failure") == 0;
            json_free(&root);
            blocker_clear("chain.test_authority_failure");
        }

        node_health_test_set_chain_advance_decision_override(NULL);
        node_health_test_set_log_head_override(-2);
        api_set_state(NULL, NULL, NULL, NULL, NULL);
        reducer_frontier_provable_tip_reset();
        main_state_free(&ms);
        rpc_net_set_connman(NULL);
        net_manager_free(&cm.manager);
        agent_security_posture_test_override_review_required(-1);
        test_reset_shared_globals();

        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("api: agent clears recovered chain-advance operator latch... ");
    {
        test_reset_shared_globals();
        blocker_reset_for_testing();
        agent_security_posture_test_override_review_required(0);
        alerts_shutdown();
        unsetenv("ZCL_ALERTS_DISABLE");
        unsetenv("ZCL_ALERT_WEBHOOK_URL");
        alerts_init();
        alerts_reset();
        event_emitf(EV_OPERATOR_NEEDED, 0,
                    "condition=chain_advance_local_recovery_gate attempts=5");

        struct main_state ms;
        struct connman cm = {0};
        struct net_address addr = {0};
        struct p2p_node *node = NULL;
        struct block_index *blocks[3] = {0};
        bool ok = api_test_build_chain(&ms, blocks, 3);
        ok = ok && api_test_init_connman_peer(&cm, &addr, &node, 2);

        if (ok) {
            (void)node;
            reducer_frontier_provable_tip_set(2);
            ok = ok && sync_set_state(SYNC_IDLE,
                                      "api agent latch reset");
            ok = ok && sync_set_state(SYNC_FINDING_PEERS,
                                      "api agent latch");
            ok = ok && sync_set_state(SYNC_HEADERS_DOWNLOAD,
                                      "api agent latch");
            ok = ok && sync_set_state(SYNC_AT_TIP,
                                      "api agent latch");
            node_health_test_set_log_head_override(2);
            api_set_state(&ms, NULL, NULL, NULL, api_test_datadir());

            size_t n = api_handle_request("GET", "/api/v1/agent", NULL, 0,
                                          resp, sizeof(resp));
            const char *body = api_test_body(resp, n, sizeof(resp));
            struct json_value root;
            json_init(&root);
            ok = n > 0 && body && json_read(&root, body, strlen(body));
            ok = ok && strcmp(json_get_str(json_get(&root, "status")),
                              "healthy") == 0;
            ok = ok && json_get_bool(json_get(&root, "healthy"));
            ok = ok && !json_get_bool(json_get(&root, "operator_needed"));
            ok = ok && strcmp(json_get_str(json_get(&root,
                                                    "primary_blocker")),
                              "none") == 0;
            ok = ok && json_get_bool(json_get(&root,
                                              "operator_latch_recovered"));
            json_free(&root);
        }

        ok = ok && !alerts_operator_needed(NULL, 0, NULL);
        alerts_shutdown();
        node_health_test_set_log_head_override(-2);
        api_set_state(NULL, NULL, NULL, NULL, NULL);
        reducer_frontier_provable_tip_reset();
        main_state_free(&ms);
        rpc_net_set_connman(NULL);
        net_manager_free(&cm.manager);
        agent_security_posture_test_override_review_required(-1);
        test_reset_shared_globals();

        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("api: public status still degrades material served gap... ");
    {
        test_reset_shared_globals();
        blocker_reset_for_testing();
        agent_security_posture_test_override_review_required(0);
        struct main_state ms;
        struct connman cm;
        struct net_address addr;
        struct p2p_node *node = NULL;
        struct block_index *blocks[ZCL_NODE_HEALTH_LAG_WARN_BLOCKS + 3] = {0};
        struct bsp_decision decision;
        const int served = 1;
        const int target = ZCL_NODE_HEALTH_LAG_WARN_BLOCKS + 2;
        bool ok = api_test_build_chain(&ms, blocks, target + 1);
        ok = ok && api_test_init_connman_peer(&cm, &addr, &node, target);

        memset(&decision, 0, sizeof(decision));
        decision.result = BSP_DECISION_USE_SOURCE;
        decision.selected_source = BSP_SOURCE_P2P;
        decision.local_height = target;
        decision.target_height = target;
        decision.projection_height = target;
        struct bsp_source_status *p2p =
            &decision.sources[BSP_SOURCE_P2P];
        p2p->source = BSP_SOURCE_P2P;
        p2p->available = true;
        p2p->healthy = true;
        p2p->selectable = true;
        p2p->height = target;

        if (ok) {
            (void)node;
            reducer_frontier_provable_tip_set(served);
            /* This case grades the SERVED GAP, so hold the archive fact
             * constant — an unproven archive would degrade the status for its
             * own reason and stop testing the gap. */
            ok = body_history_test_publish_proven(target);
            node_health_test_set_log_head_override(target);
            node_health_test_set_chain_advance_decision_override(&decision);
            sync_set_state(SYNC_IDLE, "api status reset");
            sync_set_state(SYNC_FINDING_PEERS, "api status");
            sync_set_state(SYNC_HEADERS_DOWNLOAD, "api status");
            api_set_state(&ms, NULL, NULL, NULL, api_test_datadir());

            size_t n = api_handle_request("GET", "/api/status", NULL, 0,
                                          resp, sizeof(resp));
            const char *body = api_test_body(resp, n, sizeof(resp));
            struct json_value root;
            json_init(&root);
            ok = ok && n > 0 && body && json_read(&root, body, strlen(body));
            ok = ok && strcmp(json_get_str(json_get(&root, "status")),
                              "degraded") == 0;
            ok = ok && json_get_bool(json_get(&root, "operator_needed"));
            ok = ok && json_get_int(json_get(&root, "height")) == served;
            ok = ok && json_get_int(json_get(&root, "target_height")) ==
                target;
            ok = ok && json_get_int(json_get(&root, "gap")) ==
                target - served;
            ok = ok && strcmp(json_get_str(json_get(&root,
                                                    "primary_blocker")),
                              "download_queue_idle") == 0;
            ok = ok && json_get_int(json_get(&root, "served_height")) ==
                served;
            ok = ok && strcmp(json_get_str(json_get(&root,
                                                    "source_projection")),
                              "served_tip") == 0;
            ok = ok && json_get(&root, "freshness") != NULL;
            json_free(&root);
        }

        node_health_test_set_chain_advance_decision_override(NULL);
        node_health_test_set_log_head_override(-2);
        api_set_state(NULL, NULL, NULL, NULL, NULL);
        reducer_frontier_provable_tip_reset();
        main_state_free(&ms);
        rpc_net_set_connman(NULL);
        net_manager_free(&cm.manager);
        agent_security_posture_test_override_review_required(-1);
        test_reset_shared_globals();

        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("api: public status uses durable tip before H* publication... ");
    {
        test_reset_shared_globals();
        blocker_reset_for_testing();
        agent_security_posture_test_override_review_required(0);
        struct main_state ms;
        struct connman cm;
        struct net_address addr;
        struct p2p_node *node = NULL;
        struct block_index *blocks[4] = {0};
        struct bsp_decision decision;
        char dbdir[256];
        snprintf(dbdir, sizeof(dbdir), ".zcl_test_api_durable_status_%d",
                 (int)getpid());
        mkdir(dbdir, 0755);

        bool ok = api_test_build_chain(&ms, blocks, 4);
        ok = ok && api_test_init_connman_peer(&cm, &addr, &node, 3);
        ok = ok && api_test_seed_durable_tip(dbdir, 2);

        memset(&decision, 0, sizeof(decision));
        decision.result = BSP_DECISION_USE_SOURCE;
        decision.selected_source = BSP_SOURCE_P2P;
        decision.local_height = 2;
        decision.target_height = 3;
        decision.projection_height = 2;
        struct bsp_source_status *p2p =
            &decision.sources[BSP_SOURCE_P2P];
        p2p->source = BSP_SOURCE_P2P;
        p2p->available = true;
        p2p->healthy = true;
        p2p->selectable = true;
        p2p->height = 3;

        if (ok) {
            (void)node;
            reducer_frontier_provable_tip_reset();
            /* This case is about which TIP the status document reports before
             * H* is published, not about archive completeness — so state the
             * archive fact and let the tip assertions be the subject. */
            ok = body_history_test_publish_proven(3);
            node_health_test_set_log_head_override(-2);
            node_health_test_set_chain_advance_decision_override(&decision);
            sync_set_state(SYNC_IDLE, "api status durable reset");
            sync_set_state(SYNC_FINDING_PEERS, "api status durable");
            sync_set_state(SYNC_HEADERS_DOWNLOAD, "api status durable");
            api_set_state(&ms, NULL, NULL, NULL, dbdir);

            size_t n = api_handle_request("GET", "/api/status", NULL, 0,
                                          resp, sizeof(resp));
            const char *body = api_test_body(resp, n, sizeof(resp));
            struct json_value root;
            json_init(&root);
            ok = ok && n > 0 && body && json_read(&root, body, strlen(body));
            ok = ok && strcmp(json_get_str(json_get(&root, "status")),
                              "healthy") == 0;
            ok = ok && json_get_int(json_get(&root, "height")) == 2;
            ok = ok && json_get_int(json_get(&root, "target_height")) == 3;
            ok = ok && json_get_int(json_get(&root, "gap")) == 1;
            ok = ok && strcmp(json_get_str(json_get(&root,
                                                    "primary_blocker")),
                              "none") == 0;
            ok = ok && json_get_int(json_get(&root, "served_height")) == 2;
            ok = ok && json_get_int(json_get(&root, "indexed_height")) >= 2;
            ok = ok && json_get_bool(json_get(&root, "fresh"));
            ok = ok && strcmp(json_get_str(json_get(&root,
                                                    "source_projection")),
                              "served_tip") == 0;
            ok = ok && strcmp(json_get_str(json_get(&root, "blocker")),
                              "none") == 0;
            json_free(&root);
        }

        node_health_test_set_chain_advance_decision_override(NULL);
        node_health_test_set_log_head_override(-2);
        api_set_state(NULL, NULL, NULL, NULL, NULL);
        reducer_frontier_provable_tip_reset();
        progress_store_close();
        main_state_free(&ms);
        rpc_net_set_connman(NULL);
        net_manager_free(&cm.manager);
        char cmd[384];
        snprintf(cmd, sizeof(cmd), "rm -rf %s", dbdir);
        system(cmd);
        agent_security_posture_test_override_review_required(-1);

        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("api: hodl caps to served frontier and refreshes when H* advances... ");
    {
        char dbdir[256];
        char dbpath[320];
        struct node_db ndb;
        memset(&ndb, 0, sizeof(ndb));
        snprintf(dbdir, sizeof(dbdir), ".zcl_test_api_hodl_%d",
                 (int)getpid());
        mkdir(dbdir, 0755);
        snprintf(dbpath, sizeof(dbpath), "%s/node.db", dbdir);

        api_stop_cache();
        bool ok = node_db_open(&ndb, dbpath);
        ok = ok && api_test_save_model_block(&ndb, 7, 0x71);
        ok = ok && api_test_save_model_block(&ndb, 8, 0x72);
        ok = ok && api_test_save_model_utxo(&ndb, 6, 0x61, 5000000000LL);
        ok = ok && api_test_seed_durable_tip(dbdir, 7);
        reducer_frontier_provable_tip_reset();
        api_set_state(NULL, NULL, NULL, &ndb, dbdir);

        size_t n = api_handle_request("GET", "/api/hodl", NULL, 0,
                                      resp, sizeof(resp));
        resp[n < sizeof(resp) ? n : sizeof(resp) - 1] = '\0';
        const char *body = api_test_body(resp, n, sizeof(resp));
        struct json_value root;
        json_init(&root);
        ok = ok && n > 0 && body && json_read(&root, body, strlen(body));
        ok = ok && strstr((char *)resp, "HTTP/1.1 200 OK") != NULL &&
             strstr((char *)resp, "please retry") == NULL &&
             strstr((char *)resp, "refreshing") == NULL;
        ok = ok && strcmp(json_get_str(json_get(&root, "schema")),
                          "zcl.hodl_wave.v1") == 0;
        ok = ok && json_get_int(json_get(&root, "height")) == 7;
        ok = ok && json_get_int(json_get(&root, "served_tip_height")) == 7;
        ok = ok && json_get_int(json_get(&root, "indexed_tip_height")) == 8;
        ok = ok && json_get_int(json_get(&root, "block_tip_height")) == 8;
        ok = ok && json_get_int(json_get(&root, "utxo_tip_height")) == 6;
        ok = ok && api_test_expect_freshness(&root, "utxo_projection",
                                             7, 8, true);
        json_free(&root);

        reducer_frontier_provable_tip_set(8);
        n = api_handle_request("GET", "/api/hodl", NULL, 0,
                               resp, sizeof(resp));
        resp[n < sizeof(resp) ? n : sizeof(resp) - 1] = '\0';
        body = api_test_body(resp, n, sizeof(resp));
        json_init(&root);
        ok = ok && n > 0 && body && json_read(&root, body, strlen(body));
        ok = ok && strstr((char *)resp, "HTTP/1.1 200 OK") != NULL &&
             strstr((char *)resp, "please retry") == NULL &&
             strstr((char *)resp, "refreshing") == NULL;
        ok = ok && json_get_int(json_get(&root, "height")) == 8;
        ok = ok && json_get_int(json_get(&root, "served_tip_height")) == 8;
        ok = ok && json_get_int(json_get(&root, "indexed_tip_height")) == 8;
        ok = ok && json_get_int(json_get(&root, "block_tip_height")) == 8;
        ok = ok && api_test_expect_freshness(&root, "utxo_projection",
                                             8, 8, true);
        json_free(&root);

        api_set_state(NULL, NULL, NULL, NULL, NULL);
        api_stop_cache();
        reducer_frontier_provable_tip_reset();
        progress_store_close();
        node_db_close(&ndb);

        char cmd[384];
        snprintf(cmd, sizeof(cmd), "rm -rf %s", dbdir);
        system(cmd);

        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("api: deep stats suppressed envelope has schema and freshness... ");
    {
        char dbdir[256];
        char dbpath[320];
        struct node_db ndb;
        uint8_t stats_resp[65536];
        memset(&ndb, 0, sizeof(ndb));
        test_make_tmpdir(dbdir, sizeof(dbdir), "api_health",
                         "deep_stats");
        snprintf(dbpath, sizeof(dbpath), "%s/node.db", dbdir);

        progress_store_close();
        reducer_frontier_provable_tip_reset();
        bool ok = node_db_open(&ndb, dbpath);
        api_set_state(NULL, NULL, NULL, &ndb, dbdir);

        size_t n = compute_deep_stats(stats_resp, sizeof(stats_resp));
        const char *body = api_test_body(stats_resp, n, sizeof(stats_resp));
        struct json_value root;
        json_init(&root);
        ok = ok && n > 0 && body && json_read(&root, body, strlen(body));
        ok = ok && strcmp(json_get_str(json_get(&root, "schema")),
                          "zcl.stats.deep.v1") == 0;
        ok = ok && api_test_expect_freshness(&root, "served_height",
                                             0, 0, true);
        ok = ok && !json_get_bool(json_get(&root, "history_index_usable"));
        ok = ok && json_get_bool(json_get(&root,
                                          "unsafe_sections_suppressed"));
        ok = ok && strcmp(json_get_str(json_get(&root, "reason")),
                          "blocks projection is empty") == 0;
        ok = ok && json_get(json_get(&root, "utxo"), "count") != NULL;
        ok = ok && json_get(json_get(&root, "index"), "blocks") != NULL;
        json_free(&root);

        api_set_state(NULL, NULL, NULL, NULL, NULL);
        progress_store_close();
        reducer_frontier_provable_tip_reset();
        node_db_close(&ndb);

        test_rm_rf_recursive(dbdir);

        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("api: factoids caps JSON to served frontier instead of 503... ");
    {
        char dbdir[256];
        char dbpath[320];
        struct node_db ndb;
        memset(&ndb, 0, sizeof(ndb));
        snprintf(dbdir, sizeof(dbdir), ".zcl_test_api_factoids_%d",
                 (int)getpid());
        mkdir(dbdir, 0755);
        snprintf(dbpath, sizeof(dbpath), "%s/node.db", dbdir);

        api_stop_cache();
        bool ok = node_db_open(&ndb, dbpath);
        ok = ok && api_test_save_model_block(&ndb, 7, 0x81);
        ok = ok && api_test_save_model_block(&ndb, 8, 0x82);
        ok = ok && api_test_save_model_utxo(&ndb, 6, 0x83, 2500000000LL);
        ok = ok && api_test_seed_durable_tip(dbdir, 7);
        reducer_frontier_provable_tip_reset();
        api_set_state(NULL, NULL, NULL, &ndb, dbdir);

        size_t n = api_handle_request("GET", "/api/factoids", NULL, 0,
                                      resp, sizeof(resp));
        resp[n < sizeof(resp) ? n : sizeof(resp) - 1] = '\0';
        const char *body = api_test_body(resp, n, sizeof(resp));
        struct json_value root;
        json_init(&root);
        ok = ok && n > 0 &&
             strstr((char *)resp, "HTTP/1.1 200 OK") != NULL &&
             strstr((char *)resp, "Explorer index is ahead") == NULL &&
             body && json_read(&root, body, strlen(body));
        ok = ok && json_get_int(json_get(&root, "chain_height")) == 7;
        ok = ok && json_get_int(json_get(&root, "served_height")) == 7;
        ok = ok && json_get_int(json_get(&root, "indexed_height")) == 8;
        ok = ok && json_get_bool(json_get(&root, "index_capped"));
        json_free(&root);

        reducer_frontier_provable_tip_set(8);
        n = api_handle_request("GET", "/api/factoids", NULL, 0,
                               resp, sizeof(resp));
        resp[n < sizeof(resp) ? n : sizeof(resp) - 1] = '\0';
        body = api_test_body(resp, n, sizeof(resp));
        json_init(&root);
        ok = ok && n > 0 && body && json_read(&root, body, strlen(body));
        ok = ok && json_get_int(json_get(&root, "chain_height")) == 8;
        ok = ok && json_get_int(json_get(&root, "served_height")) == 8;
        ok = ok && json_get_int(json_get(&root, "indexed_height")) == 8;
        ok = ok && !json_get_bool(json_get(&root, "index_capped"));
        json_free(&root);

        api_set_state(NULL, NULL, NULL, NULL, NULL);
        api_stop_cache();
        reducer_frontier_provable_tip_reset();
        progress_store_close();
        node_db_close(&ndb);

        char cmd[384];
        snprintf(cmd, sizeof(cmd), "rm -rf %s", dbdir);
        system(cmd);

        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    return failures;
}
