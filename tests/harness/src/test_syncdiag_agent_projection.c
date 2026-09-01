/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * agent projection cases: bounded optional detail, stale mirror suppression, stalled catch-up and idle download flags, fast-cache-miss detail retention, and one-block-lookahead chain-ok classification.
 */

#include "test/syncdiag_rpc_fixture.h"

int syncdiag_cases_agent_projection(void)
{
    int failures = 0;

    printf("api: native RPC agent bounds optional detail when budget is spent... ");
    {
        struct rpc_table tbl;
        rpc_table_init(&tbl);
        register_event_rpc_commands(&tbl);
        if (rpc_is_in_warmup(NULL, 0))
            set_rpc_warmup_finished();

        setenv("ZCL_AGENT_TEST_ELAPSED_OFFSET_MS", "200", 1);
        struct json_value params;
        json_init(&params);
        json_set_array(&params);

        struct json_value result;
        json_init(&result);

        bool executed = rpc_table_execute(&tbl, "agent", &params, &result);
        const struct json_value *first_call =
            json_get(&result, "first_call");
        bool ok = executed && result.type == JSON_OBJ;
        ok = ok && strcmp(json_get_str(json_get(&result, "schema")),
                          "zcl.public_status.v3") == 0;
        ok = ok && json_get_bool(json_get(&result, "partial_result"));
        ok = ok && strstr(json_get_str(json_get(&result, "partial_reason")),
                          "optional_detail_budget_guard:resources") != NULL;
        ok = ok && strcmp(json_get_str(json_get(&result,
                          "deferred_components")),
                          "resources,restart_watchdog") == 0;
        ok = ok && first_call && first_call->type == JSON_OBJ;
        ok = ok && json_get_bool(json_get(first_call, "partial_result"));
        ok = ok && strstr(json_get_str(json_get(first_call,
                          "partial_reason")),
                          "optional_detail_budget_guard:resources") != NULL;
        ok = ok && json_get(&result, "resources") == NULL;
        ok = ok && json_get(&result, "restart_watchdog") == NULL;
        ok = ok && json_get(&result, "readiness") != NULL;
        ok = ok && json_get(&result, "height_contract") != NULL;
        ok = ok && json_get(&result, "mirror_contract") != NULL;
        ok = ok && json_get(&result, "download") != NULL;

        unsetenv("ZCL_AGENT_TEST_ELAPSED_OFFSET_MS");
        json_free(&params);
        json_free(&result);

        if (ok) printf("OK\n");
        else    { printf("FAIL\n"); failures++; }
    }

    printf("api: native RPC agent suppresses stale mirror latch... ");
    {
        struct rpc_table tbl;
        rpc_table_init(&tbl);
        register_event_rpc_commands(&tbl);
        if (rpc_is_in_warmup(NULL, 0))
            set_rpc_warmup_finished();

        alerts_shutdown();
        unsetenv("ZCL_ALERTS_DISABLE");
        event_log_init();
        alerts_init();
        alerts_reset();
        legacy_mirror_sync_reset_for_test();
        struct legacy_mirror_sync_stats stats = {0};
        stats.enabled = true;
        stats.running = true;
        stats.reachable = true;
        stats.legacy_height = 100;
        stats.legacy_headers = 100;
        stats.local_height = 99;
        snprintf(stats.zclassic23_hash, sizeof(stats.zclassic23_hash),
                 "%064x", 1);
        snprintf(stats.zclassicd_hash, sizeof(stats.zclassicd_hash),
                 "%064x", 2);
        legacy_mirror_sync_test_set_stats(&stats, NULL);
        event_emitf(EV_OPERATOR_NEEDED, 0,
                    "chain_advance_hash-disagreement height=99");

        struct json_value params;
        json_init(&params);
        json_set_array(&params);

        struct json_value result;
        json_init(&result);

        bool executed = rpc_table_execute(&tbl, "agent", &params, &result);
        const struct json_value *operator_latch =
            json_get(&result, "operator_latch");
        const struct json_value *mirror_contract =
            json_get(&result, "mirror_contract");
        bool ok = executed && result.type == JSON_OBJ;
        ok = ok && operator_latch && operator_latch->type == JSON_OBJ;
        ok = ok && json_get_bool(json_get(operator_latch, "active"));
        ok = ok && !json_get_bool(json_get(operator_latch,
                                           "operator_action_required"));
        ok = ok && json_get_bool(json_get(operator_latch,
                                          "suppressed_by_mirror_contract"));
        ok = ok && strstr(json_get_str(json_get(operator_latch, "detail")),
                          "chain_advance_hash-disagreement") != NULL;
        ok = ok && mirror_contract && mirror_contract->type == JSON_OBJ;
        ok = ok && strcmp(json_get_str(json_get(mirror_contract,
                                                "schema")),
                          "zcl.mirror_status.v2") == 0;
        ok = ok && !json_get_bool(json_get(mirror_contract,
                                           "operator_action_required"));
        const char *primary =
            json_get_str(json_get(&result, "primary_blocker"));
        ok = ok && (!primary || strstr(primary, "operator_needed") == NULL);

        json_free(&params);
        json_free(&result);
        alerts_shutdown();
        legacy_mirror_sync_reset_for_test();

        if (ok) printf("OK\n");
        else    { printf("FAIL\n"); failures++; }
    }

    printf("api: native RPC agent flags stalled catch-up telemetry... ");
    {
        struct connman cm;
        struct node_signals sigs;
        struct main_state ms;
        struct block_index tip, best_header;
        struct uint256 h_tip, h_hdr, h_inflight, h_queued;
        struct rpc_table tbl;
        struct json_value params;
        struct json_value result;

        chain_params_select(CHAIN_MAIN);
        memset(&cm, 0, sizeof(cm));
        memset(&sigs, 0, sizeof(sigs));
        memset(&ms, 0, sizeof(ms));
        memset(&tip, 0, sizeof(tip));
        memset(&best_header, 0, sizeof(best_header));
        memset(&h_tip, 0, sizeof(h_tip));
        memset(&h_hdr, 0, sizeof(h_hdr));
        memset(&h_inflight, 0, sizeof(h_inflight));
        memset(&h_queued, 0, sizeof(h_queued));

        bool ok = connman_init(&cm, chain_params_get(), &sigs);
        main_state_init(&ms);
        block_index_init(&tip);
        block_index_init(&best_header);
        syncdiag_set_hash(&h_tip, 0x41);
        syncdiag_set_hash(&h_hdr, 0x42);
        tip.phashBlock = &h_tip;
        tip.nHeight = 100;
        tip.nTime = (uint32_t)platform_time_wall_time_t();
        tip.nStatus = BLOCK_HAVE_DATA | BLOCK_VALID_TREE;
        best_header.phashBlock = &h_hdr;
        best_header.nHeight = 125;
        best_header.pprev = &tip;
        best_header.nTime = tip.nTime;
        best_header.nStatus = BLOCK_VALID_TREE;
        ok = ok && active_chain_move_window_tip(&ms.chain_active, &tip);
        ms.pindex_best_header = &best_header;

        struct p2p_node *peer =
            syncdiag_add_peer(&cm, 44, false, PEER_HANDSHAKE_COMPLETE);
        ok = ok && peer != NULL;
        if (peer)
            peer->starting_height = 125;

        struct download_manager *dm = msg_get_download_mgr();
        dl_drain_for_backpressure(dm);
        syncdiag_set_hash(&h_inflight, 0x51);
        syncdiag_set_hash(&h_queued, 0x52);
        int32_t queued_h = 102;
        ok = ok && dl_mark_requested(dm, &h_inflight, 101, 44);
        ok = ok && dl_queue_blocks(dm, &h_queued, &queued_h, 1) == 1;

        rpc_table_init(&tbl);
        register_event_rpc_commands(&tbl);
        if (rpc_is_in_warmup(NULL, 0))
            set_rpc_warmup_finished();
        rpc_net_set_connman(&cm);
        sync_monitor_set_context(&cm, dm, &ms);
        reducer_frontier_provable_tip_set(100);
        sync_monitor_test_set_tip_advance_ts(
            (int64_t)platform_time_wall_time_t() - 180);
        sync_set_state(SYNC_IDLE, "agent stalled reset");
        sync_set_state(SYNC_FINDING_PEERS, "agent stalled");
        sync_set_state(SYNC_HEADERS_DOWNLOAD, "agent stalled");
        sync_set_state(SYNC_BLOCKS_DOWNLOAD, "agent stalled");

        json_init(&params);
        json_set_array(&params);
        json_init(&result);
        ok = ok && rpc_table_execute(&tbl, "agent", &params, &result);
        const struct json_value *download = json_get(&result, "download");
        const struct json_value *health = json_get(&result, "health");
        ok = ok && result.type == JSON_OBJ;
        ok = ok && strcmp(json_get_str(json_get(&result, "status")),
                          "degraded") == 0;
        ok = ok && strcmp(json_get_str(json_get(&result,
                                                "primary_blocker")),
                          "catchup_stalled") == 0;
        ok = ok && json_get_bool(json_get(&result, "operator_needed"));
        ok = ok && strcmp(json_get_str(json_get(&result, "next")),
                          "z23 getsyncdiag") == 0;
        ok = ok && json_get_int(json_get(&result, "gap")) == 25;
        ok = ok && download && download->type == JSON_OBJ;
        ok = ok && json_get_bool(json_get(download, "active"));
        ok = ok && json_get_bool(json_get(download, "catchup_stalled"));
        ok = ok && json_get_int(json_get(download,
                                          "catchup_stall_seconds")) >= 120;
        ok = ok && json_get(download, "request_timeout_seconds") != NULL;
        ok = ok && json_get(download,
                            "oldest_in_flight_age_seconds") != NULL;
        ok = ok && json_get(download, "overdue_in_flight") != NULL;
        ok = ok && json_get(download, "in_flight_peer_count") != NULL;
        ok = ok && json_get(download, "queue_peer_avoid_count") != NULL;
        ok = ok && json_get(download,
                            "queue_peer_avoid_max_seconds") != NULL;
        ok = ok && json_get(download, "assign_attempts") != NULL;
        ok = ok && json_get(download, "assign_successes") != NULL;
        ok = ok && json_get(download, "assign_zero_results") != NULL;
        ok = ok && json_get(download, "dispatch_wakes") != NULL;
        ok = ok && json_get(download, "message_cycles") != NULL;
        ok = ok && json_get(download, "message_send_calls") != NULL;
        ok = ok && json_get(download, "message_process_calls") != NULL;
        ok = ok && json_get(download, "message_recv_ready") != NULL;
        ok = ok && json_get(download, "message_idle_waits") != NULL;
        ok = ok && json_get(download, "message_wakes") != NULL;
        ok = ok && json_get(download, "last_assign_result") != NULL;
        ok = ok && json_get_int(json_get(download, "in_flight")) >= 1;
        ok = ok && json_get_int(json_get(download, "queued")) >= 1;
        ok = ok && health && health->type == JSON_OBJ;
        ok = ok && strstr(json_get_str(json_get(health,
                                                "warning_reasons")),
                          "catchup_stalled") != NULL;

        json_free(&params);
        json_free(&result);
        dl_drain_for_backpressure(dm);
        sync_monitor_set_context(NULL, NULL, NULL);
        rpc_net_set_connman(NULL);
        reducer_frontier_provable_tip_reset();
        sync_monitor_test_set_tip_advance_ts(0);
        sync_set_state(SYNC_IDLE, "agent stalled cleanup");
        main_state_free(&ms);
        connman_free(&cm);

        if (ok) printf("OK\n");
        else    { printf("FAIL\n"); failures++; }
    }

    printf("api: native RPC agent flags idle download dispatch... ");
    {
        struct connman cm;
        struct node_signals sigs;
        struct main_state ms;
        struct block_index tip, best_header;
        struct uint256 h_tip, h_hdr, h_queued;
        struct rpc_table tbl;
        struct json_value params;
        struct json_value result;

        chain_params_select(CHAIN_MAIN);
        memset(&cm, 0, sizeof(cm));
        memset(&sigs, 0, sizeof(sigs));
        memset(&ms, 0, sizeof(ms));
        memset(&tip, 0, sizeof(tip));
        memset(&best_header, 0, sizeof(best_header));
        memset(&h_tip, 0, sizeof(h_tip));
        memset(&h_hdr, 0, sizeof(h_hdr));
        memset(&h_queued, 0, sizeof(h_queued));

        bool ok = connman_init(&cm, chain_params_get(), &sigs);
        main_state_init(&ms);
        block_index_init(&tip);
        block_index_init(&best_header);
        syncdiag_set_hash(&h_tip, 0x61);
        syncdiag_set_hash(&h_hdr, 0x62);
        tip.phashBlock = &h_tip;
        tip.nHeight = 100;
        tip.nTime = (uint32_t)platform_time_wall_time_t();
        tip.nStatus = BLOCK_HAVE_DATA | BLOCK_VALID_TREE;
        best_header.phashBlock = &h_hdr;
        best_header.nHeight = 125;
        best_header.pprev = &tip;
        best_header.nTime = tip.nTime;
        best_header.nStatus = BLOCK_VALID_TREE;
        ok = ok && active_chain_move_window_tip(&ms.chain_active, &tip);
        ms.pindex_best_header = &best_header;

        struct p2p_node *peer =
            syncdiag_add_peer(&cm, 45, false, PEER_HANDSHAKE_COMPLETE);
        ok = ok && peer != NULL;
        if (peer)
            peer->starting_height = 125;

        struct download_manager *dm = msg_get_download_mgr();
        dl_drain_for_backpressure(dm);
        syncdiag_set_hash(&h_queued, 0x63);
        int32_t queued_h = 101;
        ok = ok && dl_queue_blocks(dm, &h_queued, &queued_h, 1) == 1;

        rpc_table_init(&tbl);
        register_event_rpc_commands(&tbl);
        if (rpc_is_in_warmup(NULL, 0))
            set_rpc_warmup_finished();
        rpc_net_set_connman(&cm);
        sync_monitor_set_context(&cm, dm, &ms);
        reducer_frontier_provable_tip_set(100);
        sync_monitor_test_set_tip_advance_ts(
            (int64_t)platform_time_wall_time_t() - 45);
        sync_set_state(SYNC_IDLE, "agent dispatch idle reset");
        sync_set_state(SYNC_FINDING_PEERS, "agent dispatch idle");
        sync_set_state(SYNC_HEADERS_DOWNLOAD, "agent dispatch idle");
        sync_set_state(SYNC_BLOCKS_DOWNLOAD, "agent dispatch idle");

        json_init(&params);
        json_set_array(&params);
        json_init(&result);
        ok = ok && rpc_table_execute(&tbl, "agent", &params, &result);
        const struct json_value *download = json_get(&result, "download");
        const struct json_value *health = json_get(&result, "health");
        ok = ok && result.type == JSON_OBJ;
        ok = ok && strcmp(json_get_str(json_get(&result, "status")),
                          "degraded") == 0;
        ok = ok && strcmp(json_get_str(json_get(&result,
                                                "primary_blocker")),
                          "download_dispatch_idle") == 0;
        ok = ok && json_get_bool(json_get(&result, "operator_needed"));
        ok = ok && strcmp(json_get_str(json_get(&result, "next")),
                          "z23 getsyncdiag") == 0;
        ok = ok && json_get_int(json_get(&result, "gap")) == 25;
        ok = ok && download && download->type == JSON_OBJ;
        ok = ok && json_get_bool(json_get(download, "active"));
        ok = ok && !json_get_bool(json_get(download, "catchup_stalled"));
        ok = ok && json_get_bool(json_get(download, "dispatch_idle"));
        ok = ok && json_get_bool(json_get(download, "dispatch_stalled"));
        ok = ok && json_get_int(json_get(download,
                                          "dispatch_idle_seconds")) >= 30;
        ok = ok && json_get_int(json_get(download, "in_flight")) == 0;
        ok = ok && json_get_int(json_get(download, "queued")) >= 1;
        ok = ok && json_get(download, "queue_peer_avoid_count") != NULL;
        ok = ok && json_get(download,
                            "queue_peer_avoid_max_seconds") != NULL;
        ok = ok && health && health->type == JSON_OBJ;
        ok = ok && strcmp(json_get_str(json_get(health,
                                                "blocking_reason")),
                          "download_dispatch_idle") == 0;
        ok = ok && strstr(json_get_str(json_get(health,
                                                "warning_reasons")),
                          "download_dispatch_idle") != NULL;

        json_free(&params);
        json_free(&result);
        dl_drain_for_backpressure(dm);
        sync_monitor_set_context(NULL, NULL, NULL);
        rpc_net_set_connman(NULL);
        reducer_frontier_provable_tip_reset();
        sync_monitor_test_set_tip_advance_ts(0);
        sync_set_state(SYNC_IDLE, "agent dispatch idle cleanup");
        main_state_free(&ms);
        connman_free(&cm);

        if (ok) printf("OK\n");
        else    { printf("FAIL\n"); failures++; }
    }

    printf("api: native RPC agent keeps projection detail on fast cache miss... ");
    {
        struct connman cm;
        struct node_signals sigs;
        struct main_state ms;
        struct block_index tip;
        struct uint256 h_tip;
        struct node_db ndb;
        struct db_block blk;
        uint8_t solution[] = {0x01, 0x02, 0x03};
        struct rpc_table tbl;
        struct json_value params;
        struct json_value result;
        const int served_height = ZCL_NODE_HEALTH_LAG_WARN_BLOCKS + 10;
        const int projection_height = 5;

        chain_params_select(CHAIN_MAIN);
        memset(&cm, 0, sizeof(cm));
        memset(&sigs, 0, sizeof(sigs));
        memset(&ms, 0, sizeof(ms));
        memset(&tip, 0, sizeof(tip));
        memset(&h_tip, 0, sizeof(h_tip));
        memset(&ndb, 0, sizeof(ndb));
        memset(&blk, 0, sizeof(blk));

        bool ok = node_db_open(&ndb, ":memory:");
        ok = ok && connman_init(&cm, chain_params_get(), &sigs);
        main_state_init(&ms);
        block_index_init(&tip);
        syncdiag_set_hash(&h_tip, 0x71);
        tip.phashBlock = &h_tip;
        tip.nHeight = served_height;
        tip.nTime = (uint32_t)platform_time_wall_time_t();
        tip.nStatus = BLOCK_HAVE_DATA | BLOCK_VALID_TREE;
        ok = ok && active_chain_move_window_tip(&ms.chain_active, &tip);
        ms.pindex_best_header = &tip;

        struct p2p_node *peer =
            syncdiag_add_peer(&cm, 46, false, PEER_HANDSHAKE_COMPLETE);
        ok = ok && peer != NULL;
        if (peer)
            peer->starting_height = served_height;

        memset(blk.hash, 0xA5, sizeof(blk.hash));
        memset(blk.prev_hash, 0x5A, sizeof(blk.prev_hash));
        memset(blk.merkle_root, 0xC3, sizeof(blk.merkle_root));
        memset(blk.nonce, 0x3C, sizeof(blk.nonce));
        blk.height = projection_height;
        blk.version = 4;
        blk.time = 1700000000;
        blk.bits = 0x1d00ffff;
        blk.solution = solution;
        blk.solution_len = sizeof(solution);
        blk.status = 5;
        blk.file_num = 1;
        blk.data_pos = 8192;
        blk.num_tx = 1;
        ok = ok && db_block_save(&ndb, &blk);

        struct download_manager *dm = msg_get_download_mgr();
        dl_drain_for_backpressure(dm);
        block_source_policy_reset_for_test();
        block_source_policy_init(&cm, &ms, &ndb);

        rpc_table_init(&tbl);
        register_event_rpc_commands(&tbl);
        if (rpc_is_in_warmup(NULL, 0))
            set_rpc_warmup_finished();
        rpc_net_set_connman(&cm);
        sync_monitor_set_context(&cm, dm, &ms);
        reducer_frontier_provable_tip_set(served_height);
        sync_set_state(SYNC_IDLE, "agent projection lag");

        json_init(&params);
        json_set_array(&params);
        json_init(&result);
        ok = ok && rpc_table_execute(&tbl, "agent", &params, &result);
        const struct json_value *indexer = json_get(&result, "indexer");
        const struct json_value *health = json_get(&result, "health");
        ok = ok && result.type == JSON_OBJ;
        ok = ok && strcmp(json_get_str(json_get(&result, "status")),
                          "healthy") == 0;
        ok = ok && strcmp(json_get_str(json_get(&result,
                                                "primary_blocker")),
                          "none") == 0;
        ok = ok && strcmp(json_get_str(json_get(&result, "next")),
                          "none") == 0;
        ok = ok && !json_get_bool(json_get(&result, "operator_needed"));
        ok = ok && json_get_bool(json_get(&result,
                                          "provable_tip_published"));
        ok = ok && json_get_int(json_get(&result, "served_height")) ==
            served_height;
        ok = ok && json_get_int(json_get(&result, "indexed_height")) ==
            served_height;
        ok = ok && json_get_int(json_get(&result, "index_gap")) == 0;
        ok = ok && strcmp(json_get_str(json_get(&result, "sync_state")),
                          "idle") == 0;
        const struct json_value *readiness = json_get(&result, "readiness");
        ok = ok && readiness && readiness->type == JSON_OBJ;
        ok = ok && strcmp(json_get_str(json_get(readiness, "schema")),
                          "zcl.agent_readiness.v1") == 0;
        ok = ok && strcmp(json_get_str(json_get(readiness, "status")),
                          "ready") == 0;
        ok = ok && strcmp(json_get_str(json_get(&result,
                                                "readiness_status")),
                          "ready") == 0;
        ok = ok && json_get_bool(json_get(readiness,
                                          "chain_serving_ready"));
        ok = ok && json_get_bool(json_get(&result,
                                          "chain_serving_ready"));
        ok = ok && json_get_bool(json_get(readiness,
                                          "index_projection_ready"));
        ok = ok && json_get_bool(json_get(&result,
                                          "index_projection_ready"));
        ok = ok && json_get_bool(json_get(readiness,
                                          "agent_work_ready"));
        ok = ok && json_get_bool(json_get(&result,
                                          "agent_work_ready"));
        ok = ok && !json_get_bool(json_get(readiness,
                                           "operator_action_required"));
        ok = ok && !json_get_bool(json_get(&result,
                                           "operator_action_required"));
        ok = ok && json_get_int(json_get(readiness, "tip_gap_blocks")) == 0;
        ok = ok && json_get_int(json_get(readiness, "index_gap_blocks")) == 0;
        ok = ok && strcmp(json_get_str(json_get(readiness,
                                                "next_action")),
                          "none") == 0;
        ok = ok && strcmp(json_get_str(json_get(&result,
                                                "readiness_next_action")),
                          "none") == 0;
        ok = ok && indexer && indexer->type == JSON_OBJ;
        ok = ok && !json_get_bool(json_get(indexer,
                                           "block_source_status_cached"));
        ok = ok && json_get_int(json_get(indexer, "height")) ==
            served_height;
        ok = ok && json_get_int(json_get(indexer, "projection_height")) ==
            -1;
        ok = ok && json_get_int(json_get(indexer, "lag")) == -1;
        ok = ok && json_get_int(json_get(indexer, "projection_lag")) == -1;
        ok = ok && !json_get_bool(json_get(indexer, "projection_deferred"));
        ok = ok && strcmp(json_get_str(json_get(indexer,
                                                "projection_state")),
                          "cached_status_unavailable") == 0;
        ok = ok && json_get(indexer, "catchup_active") != NULL;
        ok = ok && json_get(indexer, "catchup_height") != NULL;
        ok = ok && health && health->type == JSON_OBJ;
        ok = ok && strstr(json_get_str(json_get(health,
                                                "warning_reasons")),
                          "block_source_status_busy") != NULL;

        json_free(&result);
        json_init(&result);

        struct bsp_decision stale_decision;
        memset(&stale_decision, 0, sizeof(stale_decision));
        (void)block_source_policy_local_header_refill_needed(
            served_height - 1, served_height, 0, 0, 2, false,
            &stale_decision);
        ok = ok && stale_decision.projection_height == 0;
        ok = ok && stale_decision.projection_lag == 0;
        ok = ok && stale_decision.projection_state[0] == '\0';
        sync_set_state(SYNC_HEADERS_DOWNLOAD, "agent stale cache");

        ok = ok && rpc_table_execute(&tbl, "agent", &params, &result);
        indexer = json_get(&result, "indexer");
        health = json_get(&result, "health");
        ok = ok && result.type == JSON_OBJ;
        ok = ok && strcmp(json_get_str(json_get(&result, "status")),
                          "healthy") == 0;
        ok = ok && json_get_int(json_get(&result, "served_height")) ==
            served_height;
        ok = ok && json_get_int(json_get(&result, "indexed_height")) ==
            served_height;
        ok = ok && json_get_int(json_get(&result, "index_gap")) == 0;
        ok = ok && strcmp(json_get_str(json_get(&result, "sync_state")),
                          "headers_download") == 0;
        ok = ok && indexer && indexer->type == JSON_OBJ;
        ok = ok && !json_get_bool(json_get(indexer,
                                           "block_source_status_cached"));
        ok = ok && json_get_int(json_get(indexer, "height")) ==
            served_height;
        ok = ok && json_get_int(json_get(indexer, "projection_height")) ==
            -1;
        ok = ok && strcmp(json_get_str(json_get(indexer,
                                                "projection_state")),
                          "cached_status_inconsistent") == 0;
        ok = ok && health && health->type == JSON_OBJ;
        ok = ok && strstr(json_get_str(json_get(health,
                                                "warning_reasons")),
                          "block_source_status_stale") != NULL;

        json_free(&params);
        json_free(&result);
        sync_set_state(SYNC_IDLE, "agent stale cache cleanup");
        sync_monitor_set_context(NULL, NULL, NULL);
        rpc_net_set_connman(NULL);
        reducer_frontier_provable_tip_reset();
        block_source_policy_reset_for_test();
        dl_drain_for_backpressure(dm);
        main_state_free(&ms);
        connman_free(&cm);
        node_db_close(&ndb);

        if (ok) printf("OK\n");
        else    { printf("FAIL\n"); failures++; }
    }

    printf("api: agentdiagnose treats one-block lookahead as chain-ok... ");
    {
        char dir[256];
        struct connman cm;
        struct node_signals sigs;
        struct main_state ms;
        struct block_index tip;
        struct uint256 h_tip;
        struct rpc_table tbl;
        struct json_value params;
        struct json_value result;
        const int served_height = 100;
        const int target_height = 101;

        chain_params_select(CHAIN_MAIN);
        test_fmt_tmpdir(dir, sizeof(dir), "syncdiag", "diagnose_lookahead");
        test_cleanup_tmpdir(dir);
        mkdir("./test-tmp", 0777);
        mkdir(dir, 0777);

        memset(&cm, 0, sizeof(cm));
        memset(&sigs, 0, sizeof(sigs));
        memset(&ms, 0, sizeof(ms));
        memset(&tip, 0, sizeof(tip));
        memset(&h_tip, 0, sizeof(h_tip));

        peer_lifecycle_reset_for_test();
        legacy_mirror_sync_reset_for_test();
        bool ok = progress_store_open(dir);
        ok = ok && syncdiag_seed_lookahead_reducer_progress(served_height);
        ok = ok && connman_init(&cm, chain_params_get(), &sigs);
        main_state_init(&ms);
        block_index_init(&tip);
        syncdiag_set_hash(&h_tip, 0x81);
        tip.phashBlock = &h_tip;
        tip.nHeight = target_height;
        tip.nTime = (uint32_t)platform_time_wall_time_t();
        tip.nStatus = BLOCK_HAVE_DATA | BLOCK_VALID_TREE;
        ok = ok && block_map_insert(&ms.map_block_index, tip.phashBlock,
                                    &tip);
        ok = ok && active_chain_move_window_tip(&ms.chain_active, &tip);
        ms.pindex_best_header = &tip;
        ok = ok && tip_finalize_stage_init(&ms);

        struct p2p_node *peer =
            syncdiag_add_peer(&cm, 47, false, PEER_HANDSHAKE_COMPLETE);
        ok = ok && peer != NULL;
        if (peer) {
            peer->starting_height = target_height;
            syncdiag_note_peer_lifecycle_active(
                peer, PEER_LIFECYCLE_SOURCE_ADDRMAN);
        }
        struct p2p_node flaky;
        memset(&flaky, 0, sizeof(flaky));
        syncdiag_set_ipv4(&flaky.addr, 149, 50, 116, 7, 20022);
        flaky.id = 404;
        flaky.state = PEER_CONNECTING;
        snprintf(flaky.addr_name, sizeof(flaky.addr_name),
                 "149.50.116.7:20022");
        peer_lifecycle_note_connected(&flaky,
                                      PEER_LIFECYCLE_SOURCE_ADDRMAN);
        peer_lifecycle_note_disconnected(&flaky, "cleanup");

        struct download_manager *dm = msg_get_download_mgr();
        dl_drain_for_backpressure(dm);
        rpc_table_init(&tbl);
        register_event_rpc_commands(&tbl);
        if (rpc_is_in_warmup(NULL, 0))
            set_rpc_warmup_finished();
        rpc_net_set_connman(&cm);
        sync_monitor_set_context(&cm, dm, &ms);
        reducer_frontier_provable_tip_set(served_height);
        sync_set_state(SYNC_IDLE, "diagnose lookahead");
        struct legacy_mirror_sync_stats mirror_stats = {0};
        mirror_stats.enabled = true;
        mirror_stats.running = true;
        mirror_stats.reachable = true;
        mirror_stats.legacy_height = target_height;
        mirror_stats.legacy_headers = target_height;
        mirror_stats.local_height = target_height;
        mirror_stats.best_header_height = target_height;
        mirror_stats.target_height = target_height;
        uint256_get_hex(&h_tip, mirror_stats.zclassic23_hash);
        snprintf(mirror_stats.zclassicd_hash,
                 sizeof(mirror_stats.zclassicd_hash), "%s",
                 mirror_stats.zclassic23_hash);
        legacy_mirror_sync_test_set_stats(&mirror_stats, &ms);

        json_init(&params);
        json_set_array(&params);
        json_init(&result);
        ok = ok && rpc_table_execute(&tbl, "agentdiagnose", &params,
                                     &result);

        const struct json_value *findings = json_get(&result, "findings");
        const struct json_value *chain_finding =
            find_object_with_str(findings, "name", "chain_serving");
        const struct json_value *peer_finding =
            find_object_with_str(findings, "name", "peer_lifecycle");
        const struct json_value *mirror_finding =
            find_object_with_str(findings, "name", "mirror");
        const struct json_value *default_first_call =
            json_get(&result, "first_call");
        const struct json_value *default_omitted =
            json_get(&result, "omitted_sections");
        const struct json_value *default_primary_host =
            json_get(&result, "peer_primary_host_issue");
        ok = ok && result.type == JSON_OBJ;
        ok = ok && strcmp(json_get_str(json_get(&result, "schema")),
                          "zcl.agent_diagnose.v2") == 0;
        ok = ok && strcmp(json_get_str(json_get(&result, "method")),
                          "agentdiagnose") == 0;
        ok = ok && strcmp(json_get_str(json_get(&result,
                                                "native_command")),
                          "z23 agentdiagnose") == 0;
        ok = ok && strcmp(json_get_str(json_get(&result,
                                                "contract_source")),
                          "agent_contracts.def") == 0;
        ok = ok && strcmp(json_get_str(json_get(&result, "detail_mode")),
                          "brief") == 0;
        ok = ok && !json_get_bool(json_get(&result,
                                           "embedded_drilldowns"));
        ok = ok && json_get_int(json_get(&result, "gap")) == 1;
        ok = ok && json_get_bool(json_get(&result,
                                          "chain_serving_ready"));
        ok = ok && json_get_bool(json_get(&result, "normal_lookahead"));
        ok = ok && strcmp(json_get_str(json_get(&result,
                                                "chain_readiness_status")),
                          "ready") == 0;
        ok = ok && strcmp(json_get_str(json_get(&result,
                                                "height_contract_status")),
                          "normal_lookahead") == 0;
        ok = ok && json_get_int(json_get(&result,
                                         "peer_incident_count")) == 1;
        ok = ok && json_get_int(json_get(&result,
                                         "peer_host_incident_count")) >= 1;
        ok = ok && json_get_int(json_get(&result,
                                         "peer_host_count_returned")) >= 1;
        ok = ok && default_primary_host != NULL;
        ok = ok && strcmp(json_get_str(json_get(default_primary_host,
                                                "object_completeness")),
                          "compact") == 0;
        ok = ok && strcmp(json_get_str(json_get(default_primary_host,
                                                "full_detail_command")),
                          "z23 peerincidents") == 0;
        ok = ok && json_get(&result, "peer_primary_host") != NULL;
        ok = ok && json_get(&result,
                            "peer_primary_host_issue_class") != NULL;
        ok = ok && json_get(&result,
                            "peer_primary_host_next_action") != NULL;
        ok = ok && strcmp(json_get_str(json_get(&result,
                                                "peer_incident_severity")),
                          "info") == 0;
        ok = ok && !json_get_bool(json_get(&result,
                                           "peer_stability_blocker"));
        ok = ok && strcmp(json_get_str(json_get(&result,
                                                "peer_bootstrap_readiness")),
                          "ready") == 0;
        ok = ok && strcmp(json_get_str(json_get(&result,
                                                "peer_fast_sync_readiness")),
                          "ready") == 0;
        ok = ok && !json_get_bool(json_get(&result,
                                           "peer_bootstrap_blocker"));
        ok = ok && !json_get_bool(json_get(&result,
                                           "peer_fast_sync_blocker"));
        ok = ok && json_get_int(json_get(&result,
                                         "peer_material_incident_count")) == 0;
        ok = ok && json_get_int(json_get(&result,
                                         "peer_informational_incident_count"))
            == 1;
        ok = ok && strstr(json_get_str(json_get(&result,
                                                "peer_incident_summary")),
                          "minor peer lifecycle incidents") != NULL;
        ok = ok && strcmp(json_get_str(json_get(&result, "verdict")),
                          "healthy") == 0;
        ok = ok && strcmp(json_get_str(json_get(&result,
                                                "safe_next_action")),
                          "monitor_agent_and_liveness") == 0;
        ok = ok && strcmp(json_get_str(json_get(&result,
                                                "mirror_status")),
                          "healthy") == 0;
        ok = ok && strcmp(json_get_str(json_get(&result,
                                                "mirror_severity")),
                          "ok") == 0;
        ok = ok && json_get_bool(json_get(&result,
                                          "mirror_advisory_only"));
        ok = ok && !json_get_bool(json_get(&result,
                                           "mirror_operator_action_required"));
        ok = ok && chain_finding && strcmp(json_get_str(json_get(
            chain_finding, "severity")), "ok") == 0;
        ok = ok && peer_finding && strcmp(json_get_str(json_get(
            peer_finding, "severity")), "info") == 0;
        ok = ok && mirror_finding && strcmp(json_get_str(json_get(
            mirror_finding, "severity")), "ok") == 0;
        ok = ok && json_get(&result, "agent") == NULL;
        ok = ok && json_get(&result, "healthcheck") == NULL;
        ok = ok && json_get(&result, "peer_incidents") == NULL;
        ok = ok && json_get(&result, "mirror") == NULL;
        ok = ok && json_get(&result, "timeline") == NULL;
        ok = ok && default_omitted &&
            json_array_has_str(default_omitted, "timeline");
        ok = ok && default_first_call &&
            strcmp(json_get_str(json_get(default_first_call, "source")),
                   "bounded_status_peer_mirror_brief") == 0;
        ok = ok && default_first_call &&
            strcmp(json_get_str(json_get(default_first_call,
                                         "full_mode_command")),
                   "z23 agentdiagnose full") == 0;

        json_free(&result);

        struct json_value full_params;
        json_init(&full_params);
        json_set_array(&full_params);
        struct json_value full_arg;
        json_init(&full_arg);
        json_set_str(&full_arg, "full");
        json_push_back(&full_params, &full_arg);
        json_free(&full_arg);
        json_init(&result);
        ok = ok && rpc_table_execute(&tbl, "agentdiagnose",
                                     &full_params, &result);
        const struct json_value *agent = json_get(&result, "agent");
        const struct json_value *height_contract =
            agent ? json_get(agent, "height_contract") : NULL;
        ok = ok && strcmp(json_get_str(json_get(&result, "detail_mode")),
                          "full") == 0;
        ok = ok && json_get_bool(json_get(&result,
                                          "embedded_drilldowns"));
        ok = ok && agent != NULL;
        ok = ok && json_get(&result, "healthcheck") != NULL;
        ok = ok && json_get(&result, "peer_incidents") != NULL;
        ok = ok && json_get(&result, "mirror") != NULL;
        ok = ok && json_get(&result, "timeline") != NULL;
        ok = ok && height_contract && json_get_bool(json_get(
            height_contract, "normal_lookahead"));
        json_free(&result);
        json_free(&full_params);

        struct json_value bounded_health;
        json_init(&bounded_health);
        ok = ok && rpc_table_execute(&tbl, "healthcheck", &params,
                                     &bounded_health);
        const struct json_value *bounded_checks =
            json_get(&bounded_health, "checks");
        ok = ok && bounded_health.type == JSON_OBJ;
        ok = ok && strcmp(json_get_str(json_get(&bounded_health,
                                                "height_contract_status")),
                          "normal_lookahead") == 0;
        ok = ok && json_get_bool(json_get(&bounded_health,
                                          "normal_lookahead"));
        ok = ok && json_get_bool(json_get(&bounded_health,
                                          "chain_serving_ready"));
        ok = ok && !json_get_bool(json_get(&bounded_health,
                                           "sync_fsm_at_tip"));
        ok = ok && bounded_checks && bounded_checks->type == JSON_OBJ;
        ok = ok && strcmp(json_get_str(json_get(bounded_checks,
                                                "height_contract_status")),
                          "normal_lookahead") == 0;
        ok = ok && json_get_bool(json_get(bounded_checks,
                                          "normal_lookahead"));
        ok = ok && json_get_bool(json_get(bounded_checks, "synced"));
        ok = ok && !json_get_bool(json_get(bounded_checks,
                                           "sync_fsm_at_tip"));
        ok = ok && json_get_bool(json_get(bounded_checks,
                                          "serving_ready"));
        json_free(&bounded_health);

        struct json_value brief_params;
        json_init(&brief_params);
        json_set_array(&brief_params);
        struct json_value brief_arg;
        json_init(&brief_arg);
        json_set_str(&brief_arg, "brief");
        json_push_back(&brief_params, &brief_arg);
        json_free(&brief_arg);
        json_init(&result);
        ok = ok && rpc_table_execute(&tbl, "agentdiagnose",
                                     &brief_params, &result);
        const struct json_value *brief_first_call =
            json_get(&result, "first_call");
        const struct json_value *brief_omitted =
            json_get(&result, "omitted_sections");
        ok = ok && result.type == JSON_OBJ;
        ok = ok && strcmp(json_get_str(json_get(&result, "schema")),
                          "zcl.agent_diagnose.v2") == 0;
        ok = ok && strcmp(json_get_str(json_get(&result, "detail_mode")),
                          "brief") == 0;
        ok = ok && !json_get_bool(json_get(&result,
                                           "embedded_drilldowns"));
        ok = ok && strcmp(json_get_str(json_get(&result, "verdict")),
                          "healthy") == 0;
        ok = ok && strcmp(json_get_str(json_get(&result,
                                                "safe_next_action")),
                          "monitor_agent_and_liveness") == 0;
        ok = ok && strcmp(json_get_str(json_get(&result,
                                                "mirror_status")),
                          "healthy") == 0;
        ok = ok && json_get(&result, "agent") == NULL;
        ok = ok && json_get(&result, "healthcheck") == NULL;
        ok = ok && json_get(&result, "peer_incidents") == NULL;
        ok = ok && json_get(&result, "mirror") == NULL;
        ok = ok && json_get(&result, "timeline") == NULL;
        ok = ok && brief_omitted &&
            json_array_has_str(brief_omitted, "timeline");
        ok = ok && brief_first_call &&
            strcmp(json_get_str(json_get(brief_first_call, "source")),
                   "bounded_status_peer_mirror_brief") == 0;
        ok = ok && brief_first_call &&
            strcmp(json_get_str(json_get(brief_first_call,
                                         "full_mode_command")),
                   "z23 agentdiagnose full") == 0;
        json_free(&result);
        json_free(&brief_params);

        peer_lifecycle_reset_for_test();
        struct p2p_node limited_peer;
        memset(&limited_peer, 0, sizeof(limited_peer));
        syncdiag_set_ipv4(&limited_peer.addr, 203, 0, 113, 88, 8033);
        limited_peer.id = 407;
        limited_peer.state = PEER_HANDSHAKE_COMPLETE;
        limited_peer.services = 0;
        limited_peer.starting_height = target_height;
        snprintf(limited_peer.addr_name, sizeof(limited_peer.addr_name),
                 "203.0.113.88:8033");
        snprintf(limited_peer.sub_ver, sizeof(limited_peer.sub_ver),
                 "%s", "/LimitedPeer:0.1.0/");
        syncdiag_note_peer_lifecycle_active(
            &limited_peer, PEER_LIFECYCLE_SOURCE_ADDRMAN);

        json_init(&result);
        ok = ok && rpc_table_execute(&tbl, "agentdiagnose", &params,
                                     &result);
        findings = json_get(&result, "findings");
        peer_finding = find_object_with_str(findings, "name",
                                            "peer_lifecycle");
        ok = ok && strcmp(json_get_str(json_get(&result, "verdict")),
                          "attention_needed") == 0;
        ok = ok && strcmp(json_get_str(json_get(&result,
                                                "safe_next_action")),
                          "inspect_peer_lifecycle_bootstrap_readiness") == 0;
        ok = ok && strcmp(json_get_str(json_get(&result,
                                                "peer_bootstrap_readiness")),
                          "no_bootstrap_useful_peer") == 0;
        ok = ok && strcmp(json_get_str(json_get(&result,
                                                "peer_fast_sync_readiness")),
                          "no_bootstrap_useful_peer") == 0;
        ok = ok && json_get_bool(json_get(&result,
                                          "peer_bootstrap_blocker"));
        ok = ok && json_get_bool(json_get(&result,
                                          "peer_fast_sync_blocker"));
        ok = ok && strcmp(json_get_str(json_get(&result,
                                                "peer_incident_severity")),
                          "attention") == 0;
        ok = ok && json_get_bool(json_get(&result,
                                          "peer_stability_blocker"));
        ok = ok && strstr(json_get_str(json_get(&result,
                                                "peer_incident_summary")),
                          "no currently bootstrap-useful peer") != NULL;
        ok = ok && peer_finding && strcmp(json_get_str(json_get(
            peer_finding, "severity")), "attention") == 0;
        ok = ok && peer_finding && strcmp(json_get_str(json_get(
            peer_finding, "next_action")),
            "inspect_peer_lifecycle_bootstrap_readiness") == 0;
        json_free(&result);

        peer_lifecycle_reset_for_test();
        if (peer)
            syncdiag_note_peer_lifecycle_active(
                peer, PEER_LIFECYCLE_SOURCE_ADDRMAN);

        tip.nHeight = served_height + 2;
        ms.pindex_best_header = &tip;
        ok = ok && active_chain_move_window_tip(&ms.chain_active, &tip);
        if (peer)
            peer->starting_height = target_height;
        mirror_stats.legacy_height = tip.nHeight;
        mirror_stats.legacy_headers = tip.nHeight;
        mirror_stats.local_height = tip.nHeight;
        mirror_stats.best_header_height = tip.nHeight;
        mirror_stats.target_height = tip.nHeight;
        legacy_mirror_sync_test_set_stats(&mirror_stats, &ms);

        json_init(&result);
        ok = ok && rpc_table_execute(&tbl, "agentdiagnose", &params,
                                     &result);
        findings = json_get(&result, "findings");
        chain_finding = find_object_with_str(findings, "name",
                                             "chain_serving");
        ok = ok && json_get_int(json_get(&result, "gap")) == 2;
        ok = ok && json_get_bool(json_get(&result,
                                          "chain_serving_ready"));
        ok = ok && !json_get_bool(json_get(&result, "normal_lookahead"));
        ok = ok && strcmp(json_get_str(json_get(&result,
                                                "chain_readiness_status")),
                          "ready") == 0;
        ok = ok && strcmp(json_get_str(json_get(&result,
                                                "height_contract_status")),
                          "minor_lag") == 0;
        ok = ok && strcmp(json_get_str(json_get(&result, "verdict")),
                          "healthy") == 0;
        ok = ok && strcmp(json_get_str(json_get(&result,
                                                "safe_next_action")),
                          "monitor_agent_and_liveness") == 0;
        ok = ok && chain_finding && strcmp(json_get_str(json_get(
            chain_finding, "severity")), "ok") == 0;

        json_free(&result);

        mirror_stats.reachable = false;
        legacy_mirror_sync_test_set_stats(&mirror_stats, &ms);
        json_init(&result);
        ok = ok && rpc_table_execute(&tbl, "agentdiagnose", &params,
                                     &result);
        findings = json_get(&result, "findings");
        mirror_finding = find_object_with_str(findings, "name",
                                              "mirror");
        ok = ok && strcmp(json_get_str(json_get(&result, "verdict")),
                          "healthy") == 0;
        ok = ok && strcmp(json_get_str(json_get(&result,
                                                "safe_next_action")),
                          "monitor_agent_and_liveness") == 0;
        ok = ok && strcmp(json_get_str(json_get(&result,
                                                "mirror_status")),
                          "observing") == 0;
        ok = ok && strcmp(json_get_str(json_get(&result,
                                                "mirror_severity")),
                          "info") == 0;
        ok = ok && json_get_bool(json_get(&result,
                                          "mirror_advisory_only"));
        ok = ok && !json_get_bool(json_get(&result,
                                           "mirror_operator_action_required"));
        ok = ok && mirror_finding && strcmp(json_get_str(json_get(
            mirror_finding, "severity")), "info") == 0;

        json_free(&result);

        mirror_stats.reachable = true;
        legacy_mirror_sync_test_set_stats(&mirror_stats, &ms);
        peer_lifecycle_reset_for_test();
        struct p2p_node zigma_a;
        struct p2p_node zigma_b;
        memset(&zigma_a, 0, sizeof(zigma_a));
        syncdiag_set_ipv4(&zigma_a.addr, 40, 160, 53, 56, 45474);
        zigma_a.id = 405;
        zigma_a.inbound = true;
        zigma_a.state = PEER_HANDSHAKE_COMPLETE;
        zigma_a.services = NODE_NETWORK;
        snprintf(zigma_a.addr_name, sizeof(zigma_a.addr_name),
                 "40.160.53.56:45474");
        snprintf(zigma_a.sub_ver, sizeof(zigma_a.sub_ver),
                 "%s", "/Zigma:0.1.0/");
        peer_lifecycle_note_connected(&zigma_a,
                                      PEER_LIFECYCLE_SOURCE_INBOUND);
        peer_lifecycle_note_version_received(&zigma_a, zigma_a.services,
                                             target_height,
                                             zigma_a.sub_ver);
        peer_lifecycle_note_handshake_complete(&zigma_a);
        peer_lifecycle_note_active(&zigma_a);
        peer_lifecycle_note_disconnected(&zigma_a, "cleanup");
        peer_lifecycle_note_connected(&zigma_a,
                                      PEER_LIFECYCLE_SOURCE_INBOUND);
        peer_lifecycle_note_version_received(&zigma_a, zigma_a.services,
                                             target_height,
                                             zigma_a.sub_ver);
        peer_lifecycle_note_handshake_complete(&zigma_a);
        peer_lifecycle_note_active(&zigma_a);

        memset(&zigma_b, 0, sizeof(zigma_b));
        syncdiag_set_ipv4(&zigma_b.addr, 40, 160, 53, 56, 39030);
        zigma_b.id = 406;
        zigma_b.inbound = true;
        zigma_b.state = PEER_CONNECTING;
        zigma_b.services = NODE_NETWORK;
        snprintf(zigma_b.addr_name, sizeof(zigma_b.addr_name),
                 "40.160.53.56:39030");
        snprintf(zigma_b.sub_ver, sizeof(zigma_b.sub_ver),
                 "%s", "/Zigma:0.1.0/");
        peer_lifecycle_note_connected(&zigma_b,
                                      PEER_LIFECYCLE_SOURCE_INBOUND);
        peer_lifecycle_note_timeout(&zigma_b, "handshake_timeout");

        json_init(&result);
        ok = ok && rpc_table_execute(&tbl, "agentdiagnose", &params,
                                     &result);
        findings = json_get(&result, "findings");
        peer_finding = find_object_with_str(findings, "name",
                                            "peer_lifecycle");
        ok = ok && strcmp(json_get_str(json_get(&result, "verdict")),
                          "attention_needed") == 0;
        ok = ok && strcmp(json_get_str(json_get(&result,
                                                "safe_next_action")),
                          "inspect_peer_timeline_for_reconnect_timeouts") == 0;
        ok = ok && strcmp(json_get_str(json_get(&result,
                                                "peer_incident_severity")),
                          "attention") == 0;
        ok = ok && json_get_bool(json_get(&result,
                                          "peer_stability_blocker"));
        ok = ok && strcmp(json_get_str(json_get(&result,
                                                "peer_bootstrap_readiness")),
                          "ready") == 0;
        ok = ok && strcmp(json_get_str(json_get(&result,
                                                "peer_fast_sync_readiness")),
                          "no_zclassic23_fast_sync_peer") == 0;
        ok = ok && !json_get_bool(json_get(&result,
                                           "peer_bootstrap_blocker"));
        ok = ok && json_get_bool(json_get(&result,
                                          "peer_fast_sync_blocker"));
        ok = ok && json_get_int(json_get(&result,
                                         "duplicate_host_group_count")) == 1;
        ok = ok && json_get_int(json_get(&result,
                                         "peer_host_incident_count")) == 1;
        ok = ok && json_get_int(json_get(&result,
                                         "peer_host_count_returned")) == 1;
        ok = ok && strcmp(json_get_str(json_get(&result,
                                                "peer_primary_host")),
                          "40.160.53.56") == 0;
        ok = ok && strcmp(json_get_str(json_get(&result,
                                                "peer_primary_host_issue_class")),
                          "reconnect_timeout_pressure") == 0;
        ok = ok && strcmp(json_get_str(json_get(&result,
                                                "peer_primary_host_next_action")),
                          "inspect_peer_timeline_for_reconnect_timeouts") == 0;
        ok = ok && strcmp(json_get_str(json_get(&result,
                                                "peer_primary_host_direction")),
                          "inbound") == 0;
        ok = ok && !json_get_bool(json_get(&result,
                                           "peer_primary_host_mixed_direction"));
        ok = ok && strcmp(json_get_str(json_get(&result,
            "peer_primary_host_bootstrap_readiness")),
            "useful") == 0;
        ok = ok && strcmp(json_get_str(json_get(&result,
            "peer_primary_host_fast_sync_readiness")),
            "missing_zclassic23_fast_sync") == 0;
        ok = ok && json_get_int(json_get(&result,
                                         "peer_primary_host_incident_score"))
            > 0;
        const struct json_value *primary_host_issue =
            json_get(&result, "peer_primary_host_issue");
        ok = ok && primary_host_issue &&
            strcmp(json_get_str(json_get(primary_host_issue, "schema")),
                   "zcl.peer_primary_host_issue.v1") == 0;
        ok = ok && primary_host_issue &&
            strcmp(json_get_str(json_get(primary_host_issue, "host")),
                   "40.160.53.56") == 0;
        ok = ok && primary_host_issue &&
            strcmp(json_get_str(json_get(primary_host_issue, "next_action")),
                   "inspect_peer_timeline_for_reconnect_timeouts") == 0;
        ok = ok && primary_host_issue &&
            strcmp(json_get_str(json_get(primary_host_issue, "direction")),
                   "inbound") == 0;
        ok = ok && primary_host_issue &&
            !json_get_bool(json_get(primary_host_issue, "mixed_direction"));
        ok = ok && primary_host_issue &&
            strcmp(json_get_str(json_get(primary_host_issue,
                                         "object_completeness")),
                   "compact") == 0;
        ok = ok && primary_host_issue &&
            strcmp(json_get_str(json_get(primary_host_issue,
                                         "full_detail_command")),
                   "z23 peerincidents") == 0;
        ok = ok && primary_host_issue &&
            json_get(primary_host_issue, "current_open_direction") == NULL;
        ok = ok && primary_host_issue &&
            json_get(primary_host_issue, "current_handshaked_direction") == NULL;
        ok = ok && primary_host_issue &&
            strcmp(json_get_str(json_get(primary_host_issue,
                                         "bootstrap_readiness")),
                   "useful") == 0;
        ok = ok && primary_host_issue &&
            strcmp(json_get_str(json_get(primary_host_issue,
                                         "fast_sync_readiness")),
                   "missing_zclassic23_fast_sync") == 0;
        ok = ok && json_get_int(json_get(&result,
                                         "peer_material_incident_count")) >= 1;
        ok = ok && json_get_int(json_get(&result,
                                         "peer_material_group_count")) >= 1;
        ok = ok && peer_finding && strcmp(json_get_str(json_get(
            peer_finding, "severity")), "attention") == 0;
        ok = ok && peer_finding && strcmp(json_get_str(json_get(
            peer_finding, "next_action")),
            "inspect_peer_timeline_for_reconnect_timeouts") == 0;

        json_free(&result);

        peer_lifecycle_reset_for_test();
        if (peer)
            syncdiag_note_peer_lifecycle_active(
                peer, PEER_LIFECYCLE_SOURCE_ADDRMAN);
        memset(&mirror_stats, 0, sizeof(mirror_stats));
        mirror_stats.enabled = true;
        mirror_stats.running = true;
        mirror_stats.reachable = true;
        mirror_stats.legacy_height = target_height;
        mirror_stats.legacy_headers = target_height;
        mirror_stats.local_height = target_height;
        mirror_stats.best_header_height = target_height;
        mirror_stats.target_height = target_height;
        snprintf(mirror_stats.last_blocker_id,
                 sizeof(mirror_stats.last_blocker_id),
                 "hash-disagreement");
        mirror_stats.last_blocker_class = BLOCKER_TRANSIENT;
        legacy_mirror_sync_test_set_stats(&mirror_stats, &ms);

        json_init(&result);
        ok = ok && rpc_table_execute(&tbl, "agentdiagnose", &params,
                                     &result);
        findings = json_get(&result, "findings");
        mirror_finding = find_object_with_str(findings, "name",
                                              "mirror");
        ok = ok && strcmp(json_get_str(json_get(&result, "verdict")),
                          "attention_needed") == 0;
        ok = ok && strcmp(json_get_str(json_get(&result,
                                                "safe_next_action")),
                          "inspect_condition_engine_and_operator_latch") == 0;
        ok = ok && strcmp(json_get_str(json_get(&result,
                                                "mirror_status")),
                          "blocked") == 0;
        ok = ok && strcmp(json_get_str(json_get(&result,
                                                "mirror_severity")),
                          "attention") == 0;
        ok = ok && json_get_bool(json_get(&result,
                                          "mirror_operator_action_required"));
        ok = ok && mirror_finding && strcmp(json_get_str(json_get(
            mirror_finding, "severity")), "attention") == 0;
        chain_finding = find_object_with_str(findings, "name",
                                             "chain_serving");
        ok = ok && chain_finding && strcmp(json_get_str(json_get(
            chain_finding, "severity")), "attention") == 0;

        json_free(&params);
        json_free(&result);
        dl_drain_for_backpressure(dm);
        sync_monitor_set_context(NULL, NULL, NULL);
        rpc_net_set_connman(NULL);
        reducer_frontier_provable_tip_reset();
        tip_finalize_stage_shutdown();
        progress_store_close();
        block_source_policy_reset_for_test();
        peer_lifecycle_reset_for_test();
        legacy_mirror_sync_reset_for_test();
        main_state_free(&ms);
        connman_free(&cm);
        test_cleanup_tmpdir(dir);

        if (ok) printf("OK\n");
        else    { printf("FAIL\n"); failures++; }
    }


    return failures;
}
