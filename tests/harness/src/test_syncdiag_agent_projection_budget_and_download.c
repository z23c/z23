/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * agent projection sibling: bounded optional detail under a spent
 * budget, stale operator-needed mirror-latch suppression, stalled
 * catch-up and idle download-dispatch telemetry, and fast-cache-miss
 * detail retention across a sync-state transition. Each scenario
 * builds its own fixture (inline or via a private context struct),
 * calls the RPC, asserts on the result, and frees what it owns; the
 * assertion helpers above each scenario are private to that scenario
 * and add no file-scope mutable state of their own.
 */

#include "test/syncdiag_rpc_fixture.h"
#include "test/test_syncdiag_agent_projection_priv.h"

static bool sd_agent_budget_bound_partial_result(const struct json_value *result,
                                        bool executed)
{
    const struct json_value *first_call =
        json_get(result, "first_call");
    bool ok = executed && result->type == JSON_OBJ;
    ok = ok && strcmp(json_get_str(json_get(result, "schema")),
                      "zcl.public_status.v3") == 0;
    ok = ok && json_get_bool(json_get(result, "partial_result"));
    ok = ok && strstr(json_get_str(json_get(result, "partial_reason")),
                      "optional_detail_budget_guard:resources") != NULL;
    ok = ok && strcmp(json_get_str(json_get(result,
                      "deferred_components")),
                      "resources,restart_watchdog") == 0;
    ok = ok && first_call && first_call->type == JSON_OBJ;
    ok = ok && json_get_bool(json_get(first_call, "partial_result"));
    ok = ok && strstr(json_get_str(json_get(first_call,
                      "partial_reason")),
                      "optional_detail_budget_guard:resources") != NULL;
    return ok;
}

static bool sd_agent_budget_bound_deferred_and_always_on(const struct json_value *result,
                                        bool ok)
{
    ok = ok && json_get(result, "resources") == NULL;
    ok = ok && json_get(result, "restart_watchdog") == NULL;
    ok = ok && json_get(result, "readiness") != NULL;
    ok = ok && json_get(result, "height_contract") != NULL;
    ok = ok && json_get(result, "mirror_contract") != NULL;
    ok = ok && json_get(result, "download") != NULL;
    return ok;
}

/* case: agent bounds optional detail (resources, restart_watchdog) when
 * the per-call budget is already spent, while still returning the
 * always-on sections. */
bool sd_agent_budget_bound_scenario(void)
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
    bool ok = sd_agent_budget_bound_partial_result(&result, executed);
    ok = sd_agent_budget_bound_deferred_and_always_on(&result, ok);

    unsetenv("ZCL_AGENT_TEST_ELAPSED_OFFSET_MS");
    json_free(&params);
    json_free(&result);
    return ok;
}

static bool sd_agent_stale_mirror_latch_asserts(const struct json_value *result,
                                                bool executed)
{
    const struct json_value *operator_latch =
        json_get(result, "operator_latch");
    const struct json_value *mirror_contract =
        json_get(result, "mirror_contract");
    bool ok = executed && result->type == JSON_OBJ;
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
        json_get_str(json_get(result, "primary_blocker"));
    ok = ok && (!primary || strstr(primary, "operator_needed") == NULL);
    return ok;
}

/* case: agent suppresses a stale operator-needed latch once the mirror
 * contract itself reports the same hash-disagreement condition. */
bool sd_agent_stale_mirror_latch_scenario(void)
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
    bool ok = sd_agent_stale_mirror_latch_asserts(&result, executed);

    json_free(&params);
    json_free(&result);
    alerts_shutdown();
    legacy_mirror_sync_reset_for_test();
    return ok;
}

static bool sd_agent_stalled_catchup_status_and_download(const struct json_value *result)
{
    bool ok = true;
    const struct json_value *download = json_get(result, "download");
    ok = ok && result->type == JSON_OBJ;
    ok = ok && strcmp(json_get_str(json_get(result, "status")),
                      "degraded") == 0;
    ok = ok && strcmp(json_get_str(json_get(result,
                                            "primary_blocker")),
                      "catchup_stalled") == 0;
    ok = ok && json_get_bool(json_get(result, "operator_needed"));
    ok = ok && strcmp(json_get_str(json_get(result, "next")),
                      "z23 getsyncdiag") == 0;
    ok = ok && json_get_int(json_get(result, "gap")) == 25;
    ok = ok && download && download->type == JSON_OBJ;
    ok = ok && json_get_bool(json_get(download, "active"));
    ok = ok && json_get_bool(json_get(download, "catchup_stalled"));
    ok = ok && json_get_int(json_get(download,
                                      "catchup_stall_seconds")) >= 120;
    ok = ok && json_get(download, "request_timeout_seconds") != NULL;
    return ok;
}

static bool sd_agent_stalled_catchup_download_counters(const struct json_value *result)
{
    bool ok = true;
    const struct json_value *download = json_get(result, "download");
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
    return ok;
}

static bool sd_agent_stalled_catchup_in_flight_and_health(const struct json_value *result)
{
    bool ok = true;
    const struct json_value *download = json_get(result, "download");
    const struct json_value *health = json_get(result, "health");
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
    return ok;
}


struct sd_agent_stalled_catchup_ctx {
    struct connman cm;
    struct node_signals sigs;
    struct main_state ms;
    struct block_index tip, best_header;
    struct uint256 h_tip, h_hdr, h_inflight, h_queued;
    struct rpc_table tbl;
    struct json_value params;
    struct json_value result;
    struct download_manager *dm;
};

static bool sd_agent_stalled_catchup_setup(
    struct sd_agent_stalled_catchup_ctx *ctx)
{
    chain_params_select(CHAIN_MAIN);
    memset(&ctx->cm, 0, sizeof(ctx->cm));
    memset(&ctx->sigs, 0, sizeof(ctx->sigs));
    memset(&ctx->ms, 0, sizeof(ctx->ms));
    memset(&ctx->tip, 0, sizeof(ctx->tip));
    memset(&ctx->best_header, 0, sizeof(ctx->best_header));
    memset(&ctx->h_tip, 0, sizeof(ctx->h_tip));
    memset(&ctx->h_hdr, 0, sizeof(ctx->h_hdr));
    memset(&ctx->h_inflight, 0, sizeof(ctx->h_inflight));
    memset(&ctx->h_queued, 0, sizeof(ctx->h_queued));

    bool ok = connman_init(&ctx->cm, chain_params_get(), &ctx->sigs);
    main_state_init(&ctx->ms);
    block_index_init(&ctx->tip);
    block_index_init(&ctx->best_header);
    syncdiag_set_hash(&ctx->h_tip, 0x41);
    syncdiag_set_hash(&ctx->h_hdr, 0x42);
    ctx->tip.phashBlock = &ctx->h_tip;
    ctx->tip.nHeight = 100;
    ctx->tip.nTime = (uint32_t)platform_time_wall_time_t();
    ctx->tip.nStatus = BLOCK_HAVE_DATA | BLOCK_VALID_TREE;
    ctx->best_header.phashBlock = &ctx->h_hdr;
    ctx->best_header.nHeight = 125;
    ctx->best_header.pprev = &ctx->tip;
    ctx->best_header.nTime = ctx->tip.nTime;
    ctx->best_header.nStatus = BLOCK_VALID_TREE;
    ok = ok && active_chain_move_window_tip(&ctx->ms.chain_active,
                                            &ctx->tip);
    ctx->ms.pindex_best_header = &ctx->best_header;
    return ok;
}

static bool sd_agent_stalled_catchup_download_fixture(
    struct sd_agent_stalled_catchup_ctx *ctx, bool ok)
{
    struct p2p_node *peer =
        syncdiag_add_peer(&ctx->cm, 44, false, PEER_HANDSHAKE_COMPLETE);
    ok = ok && peer != NULL;
    if (peer)
        peer->starting_height = 125;

    ctx->dm = msg_get_download_mgr();
    dl_drain_for_backpressure(ctx->dm);
    syncdiag_set_hash(&ctx->h_inflight, 0x51);
    syncdiag_set_hash(&ctx->h_queued, 0x52);
    int32_t queued_h = 102;
    ok = ok && dl_mark_requested(ctx->dm, &ctx->h_inflight, 101, 44);
    ok = ok && dl_queue_blocks(ctx->dm, &ctx->h_queued, &queued_h, 1) == 1;
    return ok;
}

static bool sd_agent_stalled_catchup_rpc_setup(
    struct sd_agent_stalled_catchup_ctx *ctx)
{
    rpc_table_init(&ctx->tbl);
    register_event_rpc_commands(&ctx->tbl);
    if (rpc_is_in_warmup(NULL, 0))
        set_rpc_warmup_finished();
    rpc_net_set_connman(&ctx->cm);
    sync_monitor_set_context(&ctx->cm, ctx->dm, &ctx->ms);
    reducer_frontier_provable_tip_set(100);
    sync_monitor_test_set_tip_advance_ts(
        (int64_t)platform_time_wall_time_t() - 180);
    sync_set_state(SYNC_IDLE, "agent stalled reset");
    sync_set_state(SYNC_FINDING_PEERS, "agent stalled");
    sync_set_state(SYNC_HEADERS_DOWNLOAD, "agent stalled");
    sync_set_state(SYNC_BLOCKS_DOWNLOAD, "agent stalled");
    return true;
}

static bool sd_agent_stalled_catchup_call(
    struct sd_agent_stalled_catchup_ctx *ctx, bool ok)
{
    json_init(&ctx->params);
    json_set_array(&ctx->params);
    json_init(&ctx->result);
    ok = ok && rpc_table_execute(&ctx->tbl, "agent", &ctx->params,
                                 &ctx->result);
    ok = sd_agent_stalled_catchup_status_and_download(&ctx->result) && ok;
    ok = sd_agent_stalled_catchup_download_counters(&ctx->result) && ok;
    ok = sd_agent_stalled_catchup_in_flight_and_health(&ctx->result) && ok;
    return ok;
}

/* case: agent flags catch-up as stalled when in-flight blocks age past
 * the request timeout with no tip advance, surfacing the download
 * telemetry and a health warning reason. */
bool sd_agent_stalled_catchup_scenario(void)
{
    struct sd_agent_stalled_catchup_ctx ctx;
    bool ok = sd_agent_stalled_catchup_setup(&ctx);
    ok = sd_agent_stalled_catchup_download_fixture(&ctx, ok);
    ok = sd_agent_stalled_catchup_rpc_setup(&ctx) && ok;
    ok = sd_agent_stalled_catchup_call(&ctx, ok);

    json_free(&ctx.params);
    json_free(&ctx.result);
    dl_drain_for_backpressure(ctx.dm);
    sync_monitor_set_context(NULL, NULL, NULL);
    rpc_net_set_connman(NULL);
    reducer_frontier_provable_tip_reset();
    sync_monitor_test_set_tip_advance_ts(0);
    sync_set_state(SYNC_IDLE, "agent stalled cleanup");
    main_state_free(&ctx.ms);
    connman_free(&ctx.cm);
    return ok;
}

static bool sd_agent_dispatch_idle_status_and_download(const struct json_value *result)
{
    bool ok = true;
    const struct json_value *download = json_get(result, "download");
    ok = ok && result->type == JSON_OBJ;
    ok = ok && strcmp(json_get_str(json_get(result, "status")),
                      "degraded") == 0;
    ok = ok && strcmp(json_get_str(json_get(result,
                                            "primary_blocker")),
                      "download_dispatch_idle") == 0;
    ok = ok && json_get_bool(json_get(result, "operator_needed"));
    ok = ok && strcmp(json_get_str(json_get(result, "next")),
                      "z23 getsyncdiag") == 0;
    ok = ok && json_get_int(json_get(result, "gap")) == 25;
    ok = ok && download && download->type == JSON_OBJ;
    ok = ok && json_get_bool(json_get(download, "active"));
    ok = ok && !json_get_bool(json_get(download, "catchup_stalled"));
    ok = ok && json_get_bool(json_get(download, "dispatch_idle"));
    ok = ok && json_get_bool(json_get(download, "dispatch_stalled"));
    return ok;
}

static bool sd_agent_dispatch_idle_counters_and_health(const struct json_value *result)
{
    bool ok = true;
    const struct json_value *download = json_get(result, "download");
    const struct json_value *health = json_get(result, "health");
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
    return ok;
}


struct sd_agent_dispatch_idle_ctx {
    struct connman cm;
    struct node_signals sigs;
    struct main_state ms;
    struct block_index tip, best_header;
    struct uint256 h_tip, h_hdr, h_queued;
    struct rpc_table tbl;
    struct json_value params;
    struct json_value result;
    struct download_manager *dm;
};

static bool sd_agent_dispatch_idle_setup(
    struct sd_agent_dispatch_idle_ctx *ctx)
{
    chain_params_select(CHAIN_MAIN);
    memset(&ctx->cm, 0, sizeof(ctx->cm));
    memset(&ctx->sigs, 0, sizeof(ctx->sigs));
    memset(&ctx->ms, 0, sizeof(ctx->ms));
    memset(&ctx->tip, 0, sizeof(ctx->tip));
    memset(&ctx->best_header, 0, sizeof(ctx->best_header));
    memset(&ctx->h_tip, 0, sizeof(ctx->h_tip));
    memset(&ctx->h_hdr, 0, sizeof(ctx->h_hdr));
    memset(&ctx->h_queued, 0, sizeof(ctx->h_queued));

    bool ok = connman_init(&ctx->cm, chain_params_get(), &ctx->sigs);
    main_state_init(&ctx->ms);
    block_index_init(&ctx->tip);
    block_index_init(&ctx->best_header);
    syncdiag_set_hash(&ctx->h_tip, 0x61);
    syncdiag_set_hash(&ctx->h_hdr, 0x62);
    ctx->tip.phashBlock = &ctx->h_tip;
    ctx->tip.nHeight = 100;
    ctx->tip.nTime = (uint32_t)platform_time_wall_time_t();
    ctx->tip.nStatus = BLOCK_HAVE_DATA | BLOCK_VALID_TREE;
    ctx->best_header.phashBlock = &ctx->h_hdr;
    ctx->best_header.nHeight = 125;
    ctx->best_header.pprev = &ctx->tip;
    ctx->best_header.nTime = ctx->tip.nTime;
    ctx->best_header.nStatus = BLOCK_VALID_TREE;
    ok = ok && active_chain_move_window_tip(&ctx->ms.chain_active,
                                            &ctx->tip);
    ctx->ms.pindex_best_header = &ctx->best_header;
    return ok;
}

static bool sd_agent_dispatch_idle_download_fixture(
    struct sd_agent_dispatch_idle_ctx *ctx, bool ok)
{
    struct p2p_node *peer =
        syncdiag_add_peer(&ctx->cm, 45, false, PEER_HANDSHAKE_COMPLETE);
    ok = ok && peer != NULL;
    if (peer)
        peer->starting_height = 125;

    ctx->dm = msg_get_download_mgr();
    dl_drain_for_backpressure(ctx->dm);
    syncdiag_set_hash(&ctx->h_queued, 0x63);
    int32_t queued_h = 101;
    ok = ok && dl_queue_blocks(ctx->dm, &ctx->h_queued, &queued_h, 1) == 1;
    return ok;
}

static bool sd_agent_dispatch_idle_rpc_setup(
    struct sd_agent_dispatch_idle_ctx *ctx)
{
    rpc_table_init(&ctx->tbl);
    register_event_rpc_commands(&ctx->tbl);
    if (rpc_is_in_warmup(NULL, 0))
        set_rpc_warmup_finished();
    rpc_net_set_connman(&ctx->cm);
    sync_monitor_set_context(&ctx->cm, ctx->dm, &ctx->ms);
    reducer_frontier_provable_tip_set(100);
    sync_monitor_test_set_tip_advance_ts(
        (int64_t)platform_time_wall_time_t() - 45);
    sync_set_state(SYNC_IDLE, "agent dispatch idle reset");
    sync_set_state(SYNC_FINDING_PEERS, "agent dispatch idle");
    sync_set_state(SYNC_HEADERS_DOWNLOAD, "agent dispatch idle");
    sync_set_state(SYNC_BLOCKS_DOWNLOAD, "agent dispatch idle");
    return true;
}

static bool sd_agent_dispatch_idle_call(
    struct sd_agent_dispatch_idle_ctx *ctx, bool ok)
{
    json_init(&ctx->params);
    json_set_array(&ctx->params);
    json_init(&ctx->result);
    ok = ok && rpc_table_execute(&ctx->tbl, "agent", &ctx->params,
                                 &ctx->result);
    ok = sd_agent_dispatch_idle_status_and_download(&ctx->result) && ok;
    ok = sd_agent_dispatch_idle_counters_and_health(&ctx->result) && ok;
    return ok;
}

/* case: agent flags download dispatch as idle when nothing is in
 * flight and the queue has sat unassigned past the idle threshold with
 * no tip advance. */
bool sd_agent_dispatch_idle_scenario(void)
{
    struct sd_agent_dispatch_idle_ctx ctx;
    bool ok = sd_agent_dispatch_idle_setup(&ctx);
    ok = sd_agent_dispatch_idle_download_fixture(&ctx, ok);
    ok = sd_agent_dispatch_idle_rpc_setup(&ctx) && ok;
    ok = sd_agent_dispatch_idle_call(&ctx, ok);

    json_free(&ctx.params);
    json_free(&ctx.result);
    dl_drain_for_backpressure(ctx.dm);
    sync_monitor_set_context(NULL, NULL, NULL);
    rpc_net_set_connman(NULL);
    reducer_frontier_provable_tip_reset();
    sync_monitor_test_set_tip_advance_ts(0);
    sync_set_state(SYNC_IDLE, "agent dispatch idle cleanup");
    main_state_free(&ctx.ms);
    connman_free(&ctx.cm);
    return ok;
}

static bool sd_agent_cache_miss_phase1_status(const struct json_value *result,
                                             int served_height)
{
    bool ok = true;
    const struct json_value *readiness = json_get(result, "readiness");
    ok = ok && result->type == JSON_OBJ;
    ok = ok && strcmp(json_get_str(json_get(result, "status")),
                      "healthy") == 0;
    ok = ok && strcmp(json_get_str(json_get(result,
                                            "primary_blocker")),
                      "none") == 0;
    ok = ok && strcmp(json_get_str(json_get(result, "next")),
                      "none") == 0;
    ok = ok && !json_get_bool(json_get(result, "operator_needed"));
    ok = ok && json_get_bool(json_get(result,
                                      "provable_tip_published"));
    ok = ok && json_get_int(json_get(result, "served_height")) ==
        served_height;
    ok = ok && json_get_int(json_get(result, "indexed_height")) ==
        served_height;
    ok = ok && json_get_int(json_get(result, "index_gap")) == 0;
    ok = ok && strcmp(json_get_str(json_get(result, "sync_state")),
                      "idle") == 0;
    ok = ok && readiness && readiness->type == JSON_OBJ;
    return ok;
}

static bool sd_agent_cache_miss_phase1_readiness(const struct json_value *result)
{
    bool ok = true;
    const struct json_value *readiness = json_get(result, "readiness");
    ok = ok && strcmp(json_get_str(json_get(readiness, "schema")),
                      "zcl.agent_readiness.v1") == 0;
    ok = ok && strcmp(json_get_str(json_get(readiness, "status")),
                      "ready") == 0;
    ok = ok && strcmp(json_get_str(json_get(result,
                                            "readiness_status")),
                      "ready") == 0;
    ok = ok && json_get_bool(json_get(readiness,
                                      "chain_serving_ready"));
    ok = ok && json_get_bool(json_get(result,
                                      "chain_serving_ready"));
    ok = ok && json_get_bool(json_get(readiness,
                                      "index_projection_ready"));
    ok = ok && json_get_bool(json_get(result,
                                      "index_projection_ready"));
    ok = ok && json_get_bool(json_get(readiness,
                                      "agent_work_ready"));
    ok = ok && json_get_bool(json_get(result,
                                      "agent_work_ready"));
    ok = ok && !json_get_bool(json_get(readiness,
                                       "operator_action_required"));
    ok = ok && !json_get_bool(json_get(result,
                                       "operator_action_required"));
    ok = ok && json_get_int(json_get(readiness, "tip_gap_blocks")) == 0;
    return ok;
}

static bool sd_agent_cache_miss_phase1_indexer(const struct json_value *result,
                                             int served_height)
{
    bool ok = true;
    const struct json_value *indexer = json_get(result, "indexer");
    const struct json_value *readiness = json_get(result, "readiness");
    ok = ok && json_get_int(json_get(readiness, "index_gap_blocks")) == 0;
    ok = ok && strcmp(json_get_str(json_get(readiness,
                                            "next_action")),
                      "none") == 0;
    ok = ok && strcmp(json_get_str(json_get(result,
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
    return ok;
}

static bool sd_agent_cache_miss_phase1_health(const struct json_value *result)
{
    bool ok = true;
    const struct json_value *indexer = json_get(result, "indexer");
    const struct json_value *health = json_get(result, "health");
    ok = ok && json_get(indexer, "catchup_active") != NULL;
    ok = ok && json_get(indexer, "catchup_height") != NULL;
    ok = ok && health && health->type == JSON_OBJ;
    ok = ok && strstr(json_get_str(json_get(health,
                                            "warning_reasons")),
                      "block_source_status_busy") != NULL;
    return ok;
}


static bool sd_agent_cache_miss_phase2_status_and_indexer(const struct json_value *result,
                                             int served_height)
{
    bool ok = true;
    const struct json_value *indexer = json_get(result, "indexer");
    ok = ok && result->type == JSON_OBJ;
    ok = ok && strcmp(json_get_str(json_get(result, "status")),
                      "healthy") == 0;
    ok = ok && json_get_int(json_get(result, "served_height")) ==
        served_height;
    ok = ok && json_get_int(json_get(result, "indexed_height")) ==
        served_height;
    ok = ok && json_get_int(json_get(result, "index_gap")) == 0;
    ok = ok && strcmp(json_get_str(json_get(result, "sync_state")),
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
    return ok;
}

static bool sd_agent_cache_miss_phase2_health(const struct json_value *result)
{
    bool ok = true;
    const struct json_value *health = json_get(result, "health");
    ok = ok && health && health->type == JSON_OBJ;
    ok = ok && strstr(json_get_str(json_get(health,
                                            "warning_reasons")),
                      "block_source_status_stale") != NULL;
    return ok;
}


struct sd_agent_cache_miss_ctx {
    struct connman cm;
    struct node_signals sigs;
    struct main_state ms;
    struct block_index tip;
    struct uint256 h_tip;
    struct node_db ndb;
    struct rpc_table tbl;
    struct json_value params;
    struct json_value result;
    struct download_manager *dm;
    int served_height;
};

static bool sd_agent_cache_miss_setup(struct sd_agent_cache_miss_ctx *ctx)
{
    struct db_block blk;
    uint8_t solution[] = {0x01, 0x02, 0x03};
    const int projection_height = 5;
    ctx->served_height = ZCL_NODE_HEALTH_LAG_WARN_BLOCKS + 10;

    chain_params_select(CHAIN_MAIN);
    memset(&ctx->cm, 0, sizeof(ctx->cm));
    memset(&ctx->sigs, 0, sizeof(ctx->sigs));
    memset(&ctx->ms, 0, sizeof(ctx->ms));
    memset(&ctx->tip, 0, sizeof(ctx->tip));
    memset(&ctx->h_tip, 0, sizeof(ctx->h_tip));
    memset(&ctx->ndb, 0, sizeof(ctx->ndb));
    memset(&blk, 0, sizeof(blk));

    bool ok = node_db_open(&ctx->ndb, ":memory:");
    ok = ok && connman_init(&ctx->cm, chain_params_get(), &ctx->sigs);
    main_state_init(&ctx->ms);
    block_index_init(&ctx->tip);
    syncdiag_set_hash(&ctx->h_tip, 0x71);
    ctx->tip.phashBlock = &ctx->h_tip;
    ctx->tip.nHeight = ctx->served_height;
    ctx->tip.nTime = (uint32_t)platform_time_wall_time_t();
    ctx->tip.nStatus = BLOCK_HAVE_DATA | BLOCK_VALID_TREE;
    ok = ok && active_chain_move_window_tip(&ctx->ms.chain_active,
                                            &ctx->tip);
    ctx->ms.pindex_best_header = &ctx->tip;

    struct p2p_node *peer =
        syncdiag_add_peer(&ctx->cm, 46, false, PEER_HANDSHAKE_COMPLETE);
    ok = ok && peer != NULL;
    if (peer)
        peer->starting_height = ctx->served_height;

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
    ok = ok && db_block_save(&ctx->ndb, &blk);

    ctx->dm = msg_get_download_mgr();
    dl_drain_for_backpressure(ctx->dm);
    block_source_policy_reset_for_test();
    block_source_policy_init(&ctx->cm, &ctx->ms, &ctx->ndb);

    rpc_table_init(&ctx->tbl);
    register_event_rpc_commands(&ctx->tbl);
    if (rpc_is_in_warmup(NULL, 0))
        set_rpc_warmup_finished();
    rpc_net_set_connman(&ctx->cm);
    sync_monitor_set_context(&ctx->cm, ctx->dm, &ctx->ms);
    reducer_frontier_provable_tip_set(ctx->served_height);
    sync_set_state(SYNC_IDLE, "agent projection lag");

    json_init(&ctx->params);
    json_set_array(&ctx->params);
    return ok;
}

static bool sd_agent_cache_miss_phase1(struct sd_agent_cache_miss_ctx *ctx,
                                       bool ok)
{
    json_init(&ctx->result);
    ok = ok && rpc_table_execute(&ctx->tbl, "agent", &ctx->params,
                                 &ctx->result);
    ok = sd_agent_cache_miss_phase1_status(&ctx->result, ctx->served_height)
        && ok;
    ok = sd_agent_cache_miss_phase1_readiness(&ctx->result) && ok;
    ok = sd_agent_cache_miss_phase1_indexer(&ctx->result, ctx->served_height)
        && ok;
    ok = sd_agent_cache_miss_phase1_health(&ctx->result) && ok;
    return ok;
}

static bool sd_agent_cache_miss_phase2(struct sd_agent_cache_miss_ctx *ctx,
                                       bool ok)
{
    json_free(&ctx->result);
    json_init(&ctx->result);

    struct bsp_decision stale_decision;
    memset(&stale_decision, 0, sizeof(stale_decision));
    (void)block_source_policy_local_header_refill_needed(
        ctx->served_height - 1, ctx->served_height, 0, 0, 2, false,
        &stale_decision);
    ok = ok && stale_decision.projection_height == 0;
    ok = ok && stale_decision.projection_lag == 0;
    ok = ok && stale_decision.projection_state[0] == '\0';
    sync_set_state(SYNC_HEADERS_DOWNLOAD, "agent stale cache");

    ok = ok && rpc_table_execute(&ctx->tbl, "agent", &ctx->params,
                                 &ctx->result);
    ok = sd_agent_cache_miss_phase2_status_and_indexer(&ctx->result, ctx->served_height)
        && ok;
    ok = sd_agent_cache_miss_phase2_health(&ctx->result) && ok;
    return ok;
}

/* case: agent keeps full projection detail (readiness, indexer,
 * health) when the block-source status cache misses busy, then again
 * when a stale decision leaves the cache inconsistent during headers
 * download. */
bool sd_agent_cache_miss_scenario(void)
{
    struct sd_agent_cache_miss_ctx ctx;
    bool ok = sd_agent_cache_miss_setup(&ctx);
    ok = sd_agent_cache_miss_phase1(&ctx, ok);
    ok = sd_agent_cache_miss_phase2(&ctx, ok);

    json_free(&ctx.params);
    json_free(&ctx.result);
    sync_set_state(SYNC_IDLE, "agent stale cache cleanup");
    sync_monitor_set_context(NULL, NULL, NULL);
    rpc_net_set_connman(NULL);
    reducer_frontier_provable_tip_reset();
    block_source_policy_reset_for_test();
    dl_drain_for_backpressure(ctx.dm);
    main_state_free(&ctx.ms);
    connman_free(&ctx.cm);
    node_db_close(&ctx.ndb);
    return ok;
}
