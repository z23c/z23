/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * agent projection sibling: the one-block-lookahead agentdiagnose
 * narrative, which runs nine RPC calls against one mutating fixture
 * (struct sd_diag_lookahead_ctx) to classify a chain that is one block
 * behind its mirror as chain-ok rather than degraded. The scenario is
 * split into named phase functions that thread a running `ok` and the
 * shared context struct; the assertion helpers above each phase are
 * private to that phase and add no file-scope mutable state of their
 * own.
 */

#include "test/syncdiag_rpc_fixture.h"
#include "test/test_syncdiag_agent_projection_priv.h"

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
bool sd_diag_lookahead_scenario(void)
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
