/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * agent projection cases: bounded optional detail, stale mirror
 * suppression, stalled catch-up and idle download flags, fast-cache-miss
 * detail retention, and one-block-lookahead chain-ok classification.
 *
 * Each of the six scenarios below is its own static function that
 * builds its fixture, calls the RPC, asserts on the result, and frees
 * what it owns; syncdiag_cases_agent_projection() runs all six through
 * a shared sd_report() helper. Scenarios whose assertion chain would
 * exceed the complexity cap are further split into named assert
 * helpers, one per section or sub-case of the RPC result, that take
 * the parsed RPC result as a parameter and derive whatever nested
 * fields they need locally; the largest
 * scenario (the one-block-lookahead narrative, which runs nine RPC
 * calls against one mutating fixture) is split into named phase
 * functions that thread a running `ok` and a shared context struct —
 * no helper adds file-scope mutable state.
 */

#include "test/syncdiag_rpc_fixture.h"

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
static bool sd_agent_budget_bound_scenario(void)
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
static bool sd_agent_stale_mirror_latch_scenario(void)
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
static bool sd_agent_stalled_catchup_scenario(void)
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
static bool sd_agent_dispatch_idle_scenario(void)
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
static bool sd_agent_cache_miss_scenario(void)
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

/* Fixture for the one-block-lookahead diagnose narrative: a tip at
 * served_height+1, one addrman-sourced peer already handshaked, one
 * flaky peer that connected and disconnected, and a mirror reporting
 * itself in lockstep with the tip. */
struct sd_diag_lookahead_ctx {
    char dir[256];
    struct connman cm;
    struct node_signals sigs;
    struct main_state ms;
    struct block_index tip;
    struct uint256 h_tip;
    struct rpc_table tbl;
    struct json_value params;
    struct json_value result;
    struct download_manager *dm;
    struct legacy_mirror_sync_stats mirror_stats;
    struct p2p_node *peer;
    int served_height;
    int target_height;
};

static bool sd_diag_lookahead_setup(struct sd_diag_lookahead_ctx *ctx)
{
    ctx->served_height = 100;
    ctx->target_height = 101;

    chain_params_select(CHAIN_MAIN);
    test_fmt_tmpdir(ctx->dir, sizeof(ctx->dir), "syncdiag",
                    "diagnose_lookahead");
    test_cleanup_tmpdir(ctx->dir);
    mkdir("./test-tmp", 0777);
    mkdir(ctx->dir, 0777);

    memset(&ctx->cm, 0, sizeof(ctx->cm));
    memset(&ctx->sigs, 0, sizeof(ctx->sigs));
    memset(&ctx->ms, 0, sizeof(ctx->ms));
    memset(&ctx->tip, 0, sizeof(ctx->tip));
    memset(&ctx->h_tip, 0, sizeof(ctx->h_tip));

    peer_lifecycle_reset_for_test();
    legacy_mirror_sync_reset_for_test();
    bool ok = progress_store_open(ctx->dir);
    ok = ok && syncdiag_seed_lookahead_reducer_progress(ctx->served_height);
    ok = ok && connman_init(&ctx->cm, chain_params_get(), &ctx->sigs);
    main_state_init(&ctx->ms);
    block_index_init(&ctx->tip);
    syncdiag_set_hash(&ctx->h_tip, 0x81);
    ctx->tip.phashBlock = &ctx->h_tip;
    ctx->tip.nHeight = ctx->target_height;
    ctx->tip.nTime = (uint32_t)platform_time_wall_time_t();
    ctx->tip.nStatus = BLOCK_HAVE_DATA | BLOCK_VALID_TREE;
    ok = ok && block_map_insert(&ctx->ms.map_block_index,
                                ctx->tip.phashBlock, &ctx->tip);
    ok = ok && active_chain_move_window_tip(&ctx->ms.chain_active,
                                            &ctx->tip);
    ctx->ms.pindex_best_header = &ctx->tip;
    ok = ok && tip_finalize_stage_init(&ctx->ms);

    ctx->peer = syncdiag_add_peer(&ctx->cm, 47, false,
                                  PEER_HANDSHAKE_COMPLETE);
    ok = ok && ctx->peer != NULL;
    if (ctx->peer) {
        ctx->peer->starting_height = ctx->target_height;
        syncdiag_note_peer_lifecycle_active(
            ctx->peer, PEER_LIFECYCLE_SOURCE_ADDRMAN);
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

    ctx->dm = msg_get_download_mgr();
    dl_drain_for_backpressure(ctx->dm);
    rpc_table_init(&ctx->tbl);
    register_event_rpc_commands(&ctx->tbl);
    if (rpc_is_in_warmup(NULL, 0))
        set_rpc_warmup_finished();
    rpc_net_set_connman(&ctx->cm);
    sync_monitor_set_context(&ctx->cm, ctx->dm, &ctx->ms);
    reducer_frontier_provable_tip_set(ctx->served_height);
    sync_set_state(SYNC_IDLE, "diagnose lookahead");
    memset(&ctx->mirror_stats, 0, sizeof(ctx->mirror_stats));
    ctx->mirror_stats.enabled = true;
    ctx->mirror_stats.running = true;
    ctx->mirror_stats.reachable = true;
    ctx->mirror_stats.legacy_height = ctx->target_height;
    ctx->mirror_stats.legacy_headers = ctx->target_height;
    ctx->mirror_stats.local_height = ctx->target_height;
    ctx->mirror_stats.best_header_height = ctx->target_height;
    ctx->mirror_stats.target_height = ctx->target_height;
    uint256_get_hex(&ctx->h_tip, ctx->mirror_stats.zclassic23_hash);
    snprintf(ctx->mirror_stats.zclassicd_hash,
             sizeof(ctx->mirror_stats.zclassicd_hash), "%s",
             ctx->mirror_stats.zclassic23_hash);
    legacy_mirror_sync_test_set_stats(&ctx->mirror_stats, &ctx->ms);

    json_init(&ctx->params);
    json_set_array(&ctx->params);
    return ok;
}

static bool sd_diag_phaseA_contract(const struct json_value *result)
{
    bool ok = true;
    ok = ok && result->type == JSON_OBJ;
    ok = ok && strcmp(json_get_str(json_get(result, "schema")),
                      "zcl.agent_diagnose.v2") == 0;
    ok = ok && strcmp(json_get_str(json_get(result, "method")),
                      "agentdiagnose") == 0;
    ok = ok && strcmp(json_get_str(json_get(result,
                                            "native_command")),
                      "z23 agentdiagnose") == 0;
    ok = ok && strcmp(json_get_str(json_get(result,
                                            "contract_source")),
                      "agent_contracts.def") == 0;
    ok = ok && strcmp(json_get_str(json_get(result, "detail_mode")),
                      "brief") == 0;
    ok = ok && !json_get_bool(json_get(result,
                                       "embedded_drilldowns"));
    ok = ok && json_get_int(json_get(result, "gap")) == 1;
    ok = ok && json_get_bool(json_get(result,
                                      "chain_serving_ready"));
    ok = ok && json_get_bool(json_get(result, "normal_lookahead"));
    ok = ok && strcmp(json_get_str(json_get(result,
                                            "chain_readiness_status")),
                      "ready") == 0;
    ok = ok && strcmp(json_get_str(json_get(result,
                                            "height_contract_status")),
                      "normal_lookahead") == 0;
    return ok;
}

static bool sd_diag_phaseA_peer_primary_host(const struct json_value *result)
{
    bool ok = true;
    const struct json_value *default_primary_host =
        json_get(result, "peer_primary_host_issue");
    ok = ok && json_get_int(json_get(result,
                                     "peer_incident_count")) == 1;
    ok = ok && json_get_int(json_get(result,
                                     "peer_host_incident_count")) >= 1;
    ok = ok && json_get_int(json_get(result,
                                     "peer_host_count_returned")) >= 1;
    ok = ok && default_primary_host != NULL;
    ok = ok && strcmp(json_get_str(json_get(default_primary_host,
                                            "object_completeness")),
                      "compact") == 0;
    ok = ok && strcmp(json_get_str(json_get(default_primary_host,
                                            "full_detail_command")),
                      "z23 peerincidents") == 0;
    ok = ok && json_get(result, "peer_primary_host") != NULL;
    ok = ok && json_get(result,
                        "peer_primary_host_issue_class") != NULL;
    ok = ok && json_get(result,
                        "peer_primary_host_next_action") != NULL;
    ok = ok && strcmp(json_get_str(json_get(result,
                                            "peer_incident_severity")),
                      "info") == 0;
    ok = ok && !json_get_bool(json_get(result,
                                       "peer_stability_blocker"));
    ok = ok && strcmp(json_get_str(json_get(result,
                                            "peer_bootstrap_readiness")),
                      "ready") == 0;
    return ok;
}

static bool sd_diag_phaseA_peer_readiness_and_mirror(const struct json_value *result)
{
    bool ok = true;
    ok = ok && strcmp(json_get_str(json_get(result,
                                            "peer_fast_sync_readiness")),
                      "ready") == 0;
    ok = ok && !json_get_bool(json_get(result,
                                       "peer_bootstrap_blocker"));
    ok = ok && !json_get_bool(json_get(result,
                                       "peer_fast_sync_blocker"));
    ok = ok && json_get_int(json_get(result,
                                     "peer_material_incident_count")) == 0;
    ok = ok && json_get_int(json_get(result,
                                     "peer_informational_incident_count"))
        == 1;
    ok = ok && strstr(json_get_str(json_get(result,
                                            "peer_incident_summary")),
                      "minor peer lifecycle incidents") != NULL;
    ok = ok && strcmp(json_get_str(json_get(result, "verdict")),
                      "healthy") == 0;
    ok = ok && strcmp(json_get_str(json_get(result,
                                            "safe_next_action")),
                      "monitor_agent_and_liveness") == 0;
    ok = ok && strcmp(json_get_str(json_get(result,
                                            "mirror_status")),
                      "healthy") == 0;
    ok = ok && strcmp(json_get_str(json_get(result,
                                            "mirror_severity")),
                      "ok") == 0;
    ok = ok && json_get_bool(json_get(result,
                                      "mirror_advisory_only"));
    ok = ok && !json_get_bool(json_get(result,
                                       "mirror_operator_action_required"));
    return ok;
}

static bool sd_diag_phaseA_findings_and_brief_omissions(const struct json_value *result)
{
    bool ok = true;
    const struct json_value *findings = json_get(result, "findings");
    const struct json_value *chain_finding =
        find_object_with_str(findings, "name", "chain_serving");
    const struct json_value *peer_finding =
        find_object_with_str(findings, "name", "peer_lifecycle");
    const struct json_value *mirror_finding =
        find_object_with_str(findings, "name", "mirror");
    ok = ok && chain_finding && strcmp(json_get_str(json_get(
        chain_finding, "severity")), "ok") == 0;
    ok = ok && peer_finding && strcmp(json_get_str(json_get(
        peer_finding, "severity")), "info") == 0;
    ok = ok && mirror_finding && strcmp(json_get_str(json_get(
        mirror_finding, "severity")), "ok") == 0;
    ok = ok && json_get(result, "agent") == NULL;
    ok = ok && json_get(result, "healthcheck") == NULL;
    ok = ok && json_get(result, "peer_incidents") == NULL;
    ok = ok && json_get(result, "mirror") == NULL;
    ok = ok && json_get(result, "timeline") == NULL;
    return ok;
}

static bool sd_diag_phaseA_first_call_and_omitted_sections(const struct json_value *result)
{
    bool ok = true;
    const struct json_value *default_first_call =
        json_get(result, "first_call");
    const struct json_value *default_omitted =
        json_get(result, "omitted_sections");
    ok = ok && default_omitted &&
        json_array_has_str(default_omitted, "timeline");
    ok = ok && default_first_call &&
        strcmp(json_get_str(json_get(default_first_call, "source")),
               "bounded_status_peer_mirror_brief") == 0;
    ok = ok && default_first_call &&
        strcmp(json_get_str(json_get(default_first_call,
                                     "full_mode_command")),
               "z23 agentdiagnose full") == 0;
    return ok;
}


static bool sd_diag_lookahead_phaseA(struct sd_diag_lookahead_ctx *ctx,
                                     bool ok)
{
    json_init(&ctx->result);
    ok = ok && rpc_table_execute(&ctx->tbl, "agentdiagnose", &ctx->params,
                                 &ctx->result);
    ok = sd_diag_phaseA_contract(&ctx->result) && ok;
    ok = sd_diag_phaseA_peer_primary_host(&ctx->result) && ok;
    ok = sd_diag_phaseA_peer_readiness_and_mirror(&ctx->result) && ok;
    ok = sd_diag_phaseA_findings_and_brief_omissions(&ctx->result) && ok;
    ok = sd_diag_phaseA_first_call_and_omitted_sections(&ctx->result) && ok;
    json_free(&ctx->result);
    return ok;
}

static bool sd_diag_lookahead_phaseB_asserts(const struct json_value *result,
                                             bool ok)
{
    const struct json_value *agent = json_get(result, "agent");
    const struct json_value *height_contract =
        agent ? json_get(agent, "height_contract") : NULL;
    ok = ok && strcmp(json_get_str(json_get(result, "detail_mode")),
                      "full") == 0;
    ok = ok && json_get_bool(json_get(result,
                                      "embedded_drilldowns"));
    ok = ok && agent != NULL;
    ok = ok && json_get(result, "healthcheck") != NULL;
    ok = ok && json_get(result, "peer_incidents") != NULL;
    ok = ok && json_get(result, "mirror") != NULL;
    ok = ok && json_get(result, "timeline") != NULL;
    ok = ok && height_contract && json_get_bool(json_get(
        height_contract, "normal_lookahead"));
    return ok;
}

/* case: agentdiagnose's full mode embeds every section the brief mode
 * omits. */
static bool sd_diag_lookahead_phaseB(struct sd_diag_lookahead_ctx *ctx,
                                     bool ok)
{
    struct json_value full_params;
    json_init(&full_params);
    json_set_array(&full_params);
    struct json_value full_arg;
    json_init(&full_arg);
    json_set_str(&full_arg, "full");
    json_push_back(&full_params, &full_arg);
    json_free(&full_arg);
    json_init(&ctx->result);
    ok = ok && rpc_table_execute(&ctx->tbl, "agentdiagnose",
                                 &full_params, &ctx->result);
    ok = sd_diag_lookahead_phaseB_asserts(&ctx->result, ok);
    json_free(&ctx->result);
    json_free(&full_params);
    return ok;
}

static bool sd_diag_lookahead_phaseC_asserts(
    const struct json_value *bounded_health, bool ok)
{
    const struct json_value *bounded_checks =
        json_get(bounded_health, "checks");
    ok = ok && bounded_health->type == JSON_OBJ;
    ok = ok && strcmp(json_get_str(json_get(bounded_health,
                                            "height_contract_status")),
                      "normal_lookahead") == 0;
    ok = ok && json_get_bool(json_get(bounded_health,
                                      "normal_lookahead"));
    ok = ok && json_get_bool(json_get(bounded_health,
                                      "chain_serving_ready"));
    ok = ok && !json_get_bool(json_get(bounded_health,
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
    return ok;
}

/* case: healthcheck reports the same normal-lookahead posture through
 * its own bounded contract. */
static bool sd_diag_lookahead_phaseC(struct sd_diag_lookahead_ctx *ctx,
                                     bool ok)
{
    struct json_value bounded_health;
    json_init(&bounded_health);
    ok = ok && rpc_table_execute(&ctx->tbl, "healthcheck", &ctx->params,
                                 &bounded_health);
    ok = sd_diag_lookahead_phaseC_asserts(&bounded_health, ok);
    json_free(&bounded_health);
    return ok;
}

static bool sd_diag_phaseD_verdict_and_brief_omissions(const struct json_value *result)
{
    bool ok = true;
    ok = ok && result->type == JSON_OBJ;
    ok = ok && strcmp(json_get_str(json_get(result, "schema")),
                      "zcl.agent_diagnose.v2") == 0;
    ok = ok && strcmp(json_get_str(json_get(result, "detail_mode")),
                      "brief") == 0;
    ok = ok && !json_get_bool(json_get(result,
                                       "embedded_drilldowns"));
    ok = ok && strcmp(json_get_str(json_get(result, "verdict")),
                      "healthy") == 0;
    ok = ok && strcmp(json_get_str(json_get(result,
                                            "safe_next_action")),
                      "monitor_agent_and_liveness") == 0;
    ok = ok && strcmp(json_get_str(json_get(result,
                                            "mirror_status")),
                      "healthy") == 0;
    ok = ok && json_get(result, "agent") == NULL;
    ok = ok && json_get(result, "healthcheck") == NULL;
    ok = ok && json_get(result, "peer_incidents") == NULL;
    return ok;
}

static bool sd_diag_phaseD_omitted_sections_and_first_call(const struct json_value *result)
{
    bool ok = true;
    const struct json_value *brief_first_call =
        json_get(result, "first_call");
    const struct json_value *brief_omitted =
        json_get(result, "omitted_sections");
    ok = ok && json_get(result, "mirror") == NULL;
    ok = ok && json_get(result, "timeline") == NULL;
    ok = ok && brief_omitted &&
        json_array_has_str(brief_omitted, "timeline");
    ok = ok && brief_first_call &&
        strcmp(json_get_str(json_get(brief_first_call, "source")),
               "bounded_status_peer_mirror_brief") == 0;
    ok = ok && brief_first_call &&
        strcmp(json_get_str(json_get(brief_first_call,
                                     "full_mode_command")),
               "z23 agentdiagnose full") == 0;
    return ok;
}


/* case: agentdiagnose's brief mode still applies to a second call after
 * the full-mode round-trip, and omits the same sections. */
static bool sd_diag_lookahead_phaseD(struct sd_diag_lookahead_ctx *ctx,
                                     bool ok)
{
    struct json_value brief_params;
    json_init(&brief_params);
    json_set_array(&brief_params);
    struct json_value brief_arg;
    json_init(&brief_arg);
    json_set_str(&brief_arg, "brief");
    json_push_back(&brief_params, &brief_arg);
    json_free(&brief_arg);
    json_init(&ctx->result);
    ok = ok && rpc_table_execute(&ctx->tbl, "agentdiagnose",
                                 &brief_params, &ctx->result);
    ok = sd_diag_phaseD_verdict_and_brief_omissions(&ctx->result) && ok;
    ok = sd_diag_phaseD_omitted_sections_and_first_call(&ctx->result) && ok;
    json_free(&ctx->result);
    json_free(&brief_params);
    return ok;
}

static bool sd_diag_lookahead_phaseE_verdict_and_readiness(const struct json_value *result)
{
    bool ok = true;
    ok = ok && strcmp(json_get_str(json_get(result, "verdict")),
                      "attention_needed") == 0;
    ok = ok && strcmp(json_get_str(json_get(result,
                                            "safe_next_action")),
                      "inspect_peer_lifecycle_bootstrap_readiness") == 0;
    ok = ok && strcmp(json_get_str(json_get(result,
                                            "peer_bootstrap_readiness")),
                      "no_bootstrap_useful_peer") == 0;
    ok = ok && strcmp(json_get_str(json_get(result,
                                            "peer_fast_sync_readiness")),
                      "no_bootstrap_useful_peer") == 0;
    ok = ok && json_get_bool(json_get(result,
                                      "peer_bootstrap_blocker"));
    ok = ok && json_get_bool(json_get(result,
                                      "peer_fast_sync_blocker"));
    return ok;
}

static bool sd_diag_lookahead_phaseE_peer_finding(const struct json_value *result)
{
    bool ok = true;
    const struct json_value *findings = json_get(result, "findings");
    const struct json_value *peer_finding =
        find_object_with_str(findings, "name", "peer_lifecycle");
    ok = ok && strcmp(json_get_str(json_get(result,
                                            "peer_incident_severity")),
                      "attention") == 0;
    ok = ok && json_get_bool(json_get(result,
                                      "peer_stability_blocker"));
    ok = ok && strstr(json_get_str(json_get(result,
                                            "peer_incident_summary")),
                      "no currently bootstrap-useful peer") != NULL;
    ok = ok && peer_finding && strcmp(json_get_str(json_get(
        peer_finding, "severity")), "attention") == 0;
    ok = ok && peer_finding && strcmp(json_get_str(json_get(
        peer_finding, "next_action")),
        "inspect_peer_lifecycle_bootstrap_readiness") == 0;
    return ok;
}

/* case: with no bootstrap-useful peer, agentdiagnose flags attention on
 * peer lifecycle bootstrap readiness. */
static bool sd_diag_lookahead_phaseE(struct sd_diag_lookahead_ctx *ctx,
                                     bool ok)
{
    peer_lifecycle_reset_for_test();
    struct p2p_node limited_peer;
    memset(&limited_peer, 0, sizeof(limited_peer));
    syncdiag_set_ipv4(&limited_peer.addr, 203, 0, 113, 88, 8033);
    limited_peer.id = 407;
    limited_peer.state = PEER_HANDSHAKE_COMPLETE;
    limited_peer.services = 0;
    limited_peer.starting_height = ctx->target_height;
    snprintf(limited_peer.addr_name, sizeof(limited_peer.addr_name),
             "203.0.113.88:8033");
    snprintf(limited_peer.sub_ver, sizeof(limited_peer.sub_ver),
             "%s", "/LimitedPeer:0.1.0/");
    syncdiag_note_peer_lifecycle_active(
        &limited_peer, PEER_LIFECYCLE_SOURCE_ADDRMAN);

    json_init(&ctx->result);
    ok = ok && rpc_table_execute(&ctx->tbl, "agentdiagnose", &ctx->params,
                                 &ctx->result);
    ok = sd_diag_lookahead_phaseE_verdict_and_readiness(&ctx->result) && ok;
    ok = sd_diag_lookahead_phaseE_peer_finding(&ctx->result) && ok;
    json_free(&ctx->result);
    return ok;
}

static bool sd_diag_lookahead_phaseF_asserts(const struct json_value *result,
                                             bool ok)
{
    const struct json_value *findings = json_get(result, "findings");
    const struct json_value *chain_finding =
        find_object_with_str(findings, "name", "chain_serving");
    ok = ok && json_get_int(json_get(result, "gap")) == 2;
    ok = ok && json_get_bool(json_get(result,
                                      "chain_serving_ready"));
    ok = ok && !json_get_bool(json_get(result, "normal_lookahead"));
    ok = ok && strcmp(json_get_str(json_get(result,
                                            "chain_readiness_status")),
                      "ready") == 0;
    ok = ok && strcmp(json_get_str(json_get(result,
                                            "height_contract_status")),
                      "minor_lag") == 0;
    ok = ok && strcmp(json_get_str(json_get(result, "verdict")),
                      "healthy") == 0;
    ok = ok && strcmp(json_get_str(json_get(result,
                                            "safe_next_action")),
                      "monitor_agent_and_liveness") == 0;
    ok = ok && chain_finding && strcmp(json_get_str(json_get(
        chain_finding, "severity")), "ok") == 0;
    return ok;
}

/* case: a two-block lag from the served frontier still reads as a
 * healthy minor_lag, not an alarm. */
static bool sd_diag_lookahead_phaseF(struct sd_diag_lookahead_ctx *ctx,
                                     bool ok)
{
    peer_lifecycle_reset_for_test();
    if (ctx->peer)
        syncdiag_note_peer_lifecycle_active(
            ctx->peer, PEER_LIFECYCLE_SOURCE_ADDRMAN);

    ctx->tip.nHeight = ctx->served_height + 2;
    ctx->ms.pindex_best_header = &ctx->tip;
    ok = ok && active_chain_move_window_tip(&ctx->ms.chain_active,
                                            &ctx->tip);
    if (ctx->peer)
        ctx->peer->starting_height = ctx->target_height;
    ctx->mirror_stats.legacy_height = ctx->tip.nHeight;
    ctx->mirror_stats.legacy_headers = ctx->tip.nHeight;
    ctx->mirror_stats.local_height = ctx->tip.nHeight;
    ctx->mirror_stats.best_header_height = ctx->tip.nHeight;
    ctx->mirror_stats.target_height = ctx->tip.nHeight;
    legacy_mirror_sync_test_set_stats(&ctx->mirror_stats, &ctx->ms);

    json_init(&ctx->result);
    ok = ok && rpc_table_execute(&ctx->tbl, "agentdiagnose", &ctx->params,
                                 &ctx->result);
    ok = sd_diag_lookahead_phaseF_asserts(&ctx->result, ok);
    json_free(&ctx->result);
    return ok;
}

static bool sd_diag_lookahead_phaseG_asserts(const struct json_value *result,
                                             bool ok)
{
    const struct json_value *findings = json_get(result, "findings");
    const struct json_value *mirror_finding =
        find_object_with_str(findings, "name", "mirror");
    ok = ok && strcmp(json_get_str(json_get(result, "verdict")),
                      "healthy") == 0;
    ok = ok && strcmp(json_get_str(json_get(result,
                                            "safe_next_action")),
                      "monitor_agent_and_liveness") == 0;
    ok = ok && strcmp(json_get_str(json_get(result,
                                            "mirror_status")),
                      "observing") == 0;
    ok = ok && strcmp(json_get_str(json_get(result,
                                            "mirror_severity")),
                      "info") == 0;
    ok = ok && json_get_bool(json_get(result,
                                      "mirror_advisory_only"));
    ok = ok && !json_get_bool(json_get(result,
                                       "mirror_operator_action_required"));
    ok = ok && mirror_finding && strcmp(json_get_str(json_get(
        mirror_finding, "severity")), "info") == 0;
    return ok;
}

/* case: an unreachable mirror still reads as advisory-only "observing",
 * not a blocking condition. */
static bool sd_diag_lookahead_phaseG(struct sd_diag_lookahead_ctx *ctx,
                                     bool ok)
{
    ctx->mirror_stats.reachable = false;
    legacy_mirror_sync_test_set_stats(&ctx->mirror_stats, &ctx->ms);
    json_init(&ctx->result);
    ok = ok && rpc_table_execute(&ctx->tbl, "agentdiagnose", &ctx->params,
                                 &ctx->result);
    ok = sd_diag_lookahead_phaseG_asserts(&ctx->result, ok);
    json_free(&ctx->result);
    return ok;
}

static bool sd_diag_phaseH_verdict_and_primary_host(const struct json_value *result)
{
    bool ok = true;
    ok = ok && strcmp(json_get_str(json_get(result, "verdict")),
                      "attention_needed") == 0;
    ok = ok && strcmp(json_get_str(json_get(result,
                                            "safe_next_action")),
                      "inspect_peer_timeline_for_reconnect_timeouts") == 0;
    ok = ok && strcmp(json_get_str(json_get(result,
                                            "peer_incident_severity")),
                      "attention") == 0;
    ok = ok && json_get_bool(json_get(result,
                                      "peer_stability_blocker"));
    ok = ok && strcmp(json_get_str(json_get(result,
                                            "peer_bootstrap_readiness")),
                      "ready") == 0;
    ok = ok && strcmp(json_get_str(json_get(result,
                                            "peer_fast_sync_readiness")),
                      "no_zclassic23_fast_sync_peer") == 0;
    ok = ok && !json_get_bool(json_get(result,
                                       "peer_bootstrap_blocker"));
    ok = ok && json_get_bool(json_get(result,
                                      "peer_fast_sync_blocker"));
    ok = ok && json_get_int(json_get(result,
                                     "duplicate_host_group_count")) == 1;
    ok = ok && json_get_int(json_get(result,
                                     "peer_host_incident_count")) == 1;
    ok = ok && json_get_int(json_get(result,
                                     "peer_host_count_returned")) == 1;
    ok = ok && strcmp(json_get_str(json_get(result,
                                            "peer_primary_host")),
                      "40.160.53.56") == 0;
    return ok;
}

static bool sd_diag_phaseH_primary_host_issue_class(const struct json_value *result)
{
    bool ok = true;
    const struct json_value *primary_host_issue =
        json_get(result, "peer_primary_host_issue");
    ok = ok && strcmp(json_get_str(json_get(result,
                                            "peer_primary_host_issue_class")),
                      "reconnect_timeout_pressure") == 0;
    ok = ok && strcmp(json_get_str(json_get(result,
                                            "peer_primary_host_next_action")),
                      "inspect_peer_timeline_for_reconnect_timeouts") == 0;
    ok = ok && strcmp(json_get_str(json_get(result,
                                            "peer_primary_host_direction")),
                      "inbound") == 0;
    ok = ok && !json_get_bool(json_get(result,
                                       "peer_primary_host_mixed_direction"));
    ok = ok && strcmp(json_get_str(json_get(result,
        "peer_primary_host_bootstrap_readiness")),
        "useful") == 0;
    ok = ok && strcmp(json_get_str(json_get(result,
        "peer_primary_host_fast_sync_readiness")),
        "missing_zclassic23_fast_sync") == 0;
    ok = ok && json_get_int(json_get(result,
                                     "peer_primary_host_incident_score"))
        > 0;
    ok = ok && primary_host_issue &&
        strcmp(json_get_str(json_get(primary_host_issue, "schema")),
               "zcl.peer_primary_host_issue.v1") == 0;
    ok = ok && primary_host_issue &&
        strcmp(json_get_str(json_get(primary_host_issue, "host")),
               "40.160.53.56") == 0;
    return ok;
}

static bool sd_diag_phaseH_primary_host_issue_detail(const struct json_value *result)
{
    bool ok = true;
    const struct json_value *primary_host_issue =
        json_get(result, "peer_primary_host_issue");
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
    return ok;
}

static bool sd_diag_phaseH_findings_and_direction(const struct json_value *result)
{
    bool ok = true;
    const struct json_value *findings = json_get(result, "findings");
    const struct json_value *peer_finding =
        find_object_with_str(findings, "name", "peer_lifecycle");
    const struct json_value *primary_host_issue =
        json_get(result, "peer_primary_host_issue");
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
    ok = ok && json_get_int(json_get(result,
                                     "peer_material_incident_count")) >= 1;
    ok = ok && json_get_int(json_get(result,
                                     "peer_material_group_count")) >= 1;
    ok = ok && peer_finding && strcmp(json_get_str(json_get(
        peer_finding, "severity")), "attention") == 0;
    ok = ok && peer_finding && strcmp(json_get_str(json_get(
        peer_finding, "next_action")),
        "inspect_peer_timeline_for_reconnect_timeouts") == 0;
    return ok;
}


/* case: two reconnecting peers at the same duplicate host raise a
 * material peer-lifecycle incident, driving agentdiagnose to
 * "attention_needed" with a compact primary-host-issue drilldown. */
static bool sd_diag_lookahead_phaseH(struct sd_diag_lookahead_ctx *ctx,
                                     bool ok)
{
    ctx->mirror_stats.reachable = true;
    legacy_mirror_sync_test_set_stats(&ctx->mirror_stats, &ctx->ms);
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
                                         ctx->target_height,
                                         zigma_a.sub_ver);
    peer_lifecycle_note_handshake_complete(&zigma_a);
    peer_lifecycle_note_active(&zigma_a);
    peer_lifecycle_note_disconnected(&zigma_a, "cleanup");
    peer_lifecycle_note_connected(&zigma_a,
                                  PEER_LIFECYCLE_SOURCE_INBOUND);
    peer_lifecycle_note_version_received(&zigma_a, zigma_a.services,
                                         ctx->target_height,
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

    json_init(&ctx->result);
    ok = ok && rpc_table_execute(&ctx->tbl, "agentdiagnose", &ctx->params,
                                 &ctx->result);
    ok = sd_diag_phaseH_verdict_and_primary_host(&ctx->result) && ok;
    ok = sd_diag_phaseH_primary_host_issue_class(&ctx->result) && ok;
    ok = sd_diag_phaseH_primary_host_issue_detail(&ctx->result) && ok;
    ok = sd_diag_phaseH_findings_and_direction(&ctx->result) && ok;
    json_free(&ctx->result);
    return ok;
}

static bool sd_diag_lookahead_phaseI_asserts(const struct json_value *result,
                                             bool ok)
{
    const struct json_value *findings = json_get(result, "findings");
    const struct json_value *mirror_finding =
        find_object_with_str(findings, "name", "mirror");
    ok = ok && strcmp(json_get_str(json_get(result, "verdict")),
                      "attention_needed") == 0;
    ok = ok && strcmp(json_get_str(json_get(result,
                                            "safe_next_action")),
                      "inspect_condition_engine_and_operator_latch") == 0;
    ok = ok && strcmp(json_get_str(json_get(result,
                                            "mirror_status")),
                      "blocked") == 0;
    ok = ok && strcmp(json_get_str(json_get(result,
                                            "mirror_severity")),
                      "attention") == 0;
    ok = ok && json_get_bool(json_get(result,
                                      "mirror_operator_action_required"));
    ok = ok && mirror_finding && strcmp(json_get_str(json_get(
        mirror_finding, "severity")), "attention") == 0;
    const struct json_value *chain_finding =
        find_object_with_str(findings, "name", "chain_serving");
    ok = ok && chain_finding && strcmp(json_get_str(json_get(
        chain_finding, "severity")), "attention") == 0;
    return ok;
}

/* case: a hash-disagreement mirror blocker also drives agentdiagnose to
 * attention_needed, with both the mirror and chain-serving findings
 * marked attention. */
static bool sd_diag_lookahead_phaseI(struct sd_diag_lookahead_ctx *ctx,
                                     bool ok)
{
    peer_lifecycle_reset_for_test();
    if (ctx->peer)
        syncdiag_note_peer_lifecycle_active(
            ctx->peer, PEER_LIFECYCLE_SOURCE_ADDRMAN);
    memset(&ctx->mirror_stats, 0, sizeof(ctx->mirror_stats));
    ctx->mirror_stats.enabled = true;
    ctx->mirror_stats.running = true;
    ctx->mirror_stats.reachable = true;
    ctx->mirror_stats.legacy_height = ctx->target_height;
    ctx->mirror_stats.legacy_headers = ctx->target_height;
    ctx->mirror_stats.local_height = ctx->target_height;
    ctx->mirror_stats.best_header_height = ctx->target_height;
    ctx->mirror_stats.target_height = ctx->target_height;
    snprintf(ctx->mirror_stats.last_blocker_id,
             sizeof(ctx->mirror_stats.last_blocker_id),
             "hash-disagreement");
    ctx->mirror_stats.last_blocker_class = BLOCKER_TRANSIENT;
    legacy_mirror_sync_test_set_stats(&ctx->mirror_stats, &ctx->ms);

    json_init(&ctx->result);
    ok = ok && rpc_table_execute(&ctx->tbl, "agentdiagnose", &ctx->params,
                                 &ctx->result);
    ok = sd_diag_lookahead_phaseI_asserts(&ctx->result, ok);
    json_free(&ctx->result);
    return ok;
}

/* case: agentdiagnose classifies the one-block-lookahead served/target
 * gap as chain-ok across brief, full, and repeated-brief detail modes,
 * then walks through a two-block lag, a peer with no bootstrap-useful
 * connection, an unreachable mirror, a duplicate reconnecting-host
 * peer incident, and a hash-disagreement mirror blocker. */
static bool sd_diag_lookahead_scenario(void)
{
    struct sd_diag_lookahead_ctx ctx;
    bool ok = sd_diag_lookahead_setup(&ctx);

    ok = sd_diag_lookahead_phaseA(&ctx, ok);
    ok = sd_diag_lookahead_phaseB(&ctx, ok);
    ok = sd_diag_lookahead_phaseC(&ctx, ok);
    ok = sd_diag_lookahead_phaseD(&ctx, ok);
    ok = sd_diag_lookahead_phaseE(&ctx, ok);
    ok = sd_diag_lookahead_phaseF(&ctx, ok);
    ok = sd_diag_lookahead_phaseG(&ctx, ok);
    ok = sd_diag_lookahead_phaseH(&ctx, ok);
    ok = sd_diag_lookahead_phaseI(&ctx, ok);

    json_free(&ctx.params);
    dl_drain_for_backpressure(ctx.dm);
    sync_monitor_set_context(NULL, NULL, NULL);
    rpc_net_set_connman(NULL);
    reducer_frontier_provable_tip_reset();
    tip_finalize_stage_shutdown();
    progress_store_close();
    block_source_policy_reset_for_test();
    peer_lifecycle_reset_for_test();
    legacy_mirror_sync_reset_for_test();
    main_state_free(&ctx.ms);
    connman_free(&ctx.cm);
    test_cleanup_tmpdir(ctx.dir);
    return ok;
}

static void sd_report(const char *desc, bool ok, int *failures)
{
    printf("%s", desc);
    if (ok)
        printf("OK\n");
    else {
        printf("FAIL\n");
        (*failures)++;
    }
}

int syncdiag_cases_agent_projection(void)
{
    int failures = 0;

    sd_report("api: native RPC agent bounds optional detail when budget "
              "is spent... ",
              sd_agent_budget_bound_scenario(), &failures);
    sd_report("api: native RPC agent suppresses stale mirror latch... ",
              sd_agent_stale_mirror_latch_scenario(), &failures);
    sd_report("api: native RPC agent flags stalled catch-up "
              "telemetry... ",
              sd_agent_stalled_catchup_scenario(), &failures);
    sd_report("api: native RPC agent flags idle download dispatch... ",
              sd_agent_dispatch_idle_scenario(), &failures);
    sd_report("api: native RPC agent keeps projection detail on fast "
              "cache miss... ",
              sd_agent_cache_miss_scenario(), &failures);
    sd_report("api: agentdiagnose treats one-block lookahead as "
              "chain-ok... ",
              sd_diag_lookahead_scenario(), &failures);

    return failures;
}
