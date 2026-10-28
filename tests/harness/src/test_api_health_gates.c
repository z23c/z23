/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * API health gates: agent impact mapping, the health blocking reason, served
 * gap grading, durable tip publication, and the frontier caps on hodl,
 * deep stats, and factoids.
 */

#include "test/api_test_fixtures.h"

/* Fixture cleanup without a shell: the path is absolute and may contain
 * spaces. A directory that is already gone counts as success, but only when
 * the directory itself is verified absent: the remover can also report
 * ENOENT for a nested entry while the root remains. */
static bool fixture_rm_ok(const char *dir)
{
    if (test_rm_rf_recursive(dir) == 0)
        return true;
    if (errno != ENOENT)
        return false;
    struct stat st;
    errno = 0;
    return lstat(dir, &st) != 0 && errno == ENOENT;
}

static bool agent_impact_groups(const char *params_json,
                                int files_count,
                                int groups_count,
                                const char **groups,
                                const char *command)
{
    struct json_value params, result;
    json_init(&params);
    json_init(&result);
    bool ok = json_read(&params, params_json, strlen(params_json));
    ok = ok && rpc_agent_impact(&params, false, &result);
    ok = ok && strcmp(json_get_str(json_get(&result, "schema")),
                      "zcl.agent_impact.v2") == 0;
    ok = ok && json_get_int(json_get(&result, "files_count")) == files_count;
    ok = ok && json_get_int(json_get(&result,
                                     "relevant_test_groups_count")) ==
        groups_count;
    const struct json_value *groups_json =
        json_get(&result, "relevant_test_groups");
    for (int i = 0; i < groups_count; i++)
        ok = ok && api_test_array_has_str(groups_json, groups[i]);
    if (command) {
        const struct json_value *commands =
            json_get(&result, "recommended_commands");
        ok = ok && api_test_array_has_str(commands, command);
    }
    json_free(&params);
    json_free(&result);
    return ok;
}

static bool status_blocked_on_chain_integrity(bool ok, uint8_t *resp,
                                              size_t cap)
{
    size_t n = api_handle_request("GET", "/api/status", NULL, 0, resp, cap);
    const char *body = api_test_body(resp, n, cap);
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
    return ok;
}

static bool agent_blocked_on_chain_integrity(bool ok, uint8_t *resp,
                                             size_t cap)
{
    size_t n = api_handle_request("GET", "/api/v1/agent", NULL, 0,
                                  resp, cap);
    const char *body = api_test_body(resp, n, cap);
    struct json_value root;
    json_init(&root);
    ok = ok && n > 0 && body && json_read(&root, body, strlen(body));
    ok = ok && strcmp(json_get_str(json_get(&root,
                                            "primary_blocker")),
                      "operator_needed:chain_integrity_failed") == 0;
    json_free(&root);
    return ok;
}

static bool public_status_names_blocking_reason(uint8_t *resp, size_t cap)
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

    ok = status_blocked_on_chain_integrity(ok, resp, cap);
    ok = agent_blocked_on_chain_integrity(ok, resp, cap);

    alerts_shutdown();
    api_set_state(NULL, NULL, NULL, NULL, NULL);
    reducer_frontier_provable_tip_reset();
    main_state_free(&ms);
    agent_security_posture_test_override_review_required(-1);
    test_reset_shared_globals();
    return ok;
}

static bool small_gap_healthy_fields(const struct json_value *root,
                                     int served, int target)
{
    bool ok = strcmp(json_get_str(json_get(root, "status")),
                     "healthy") == 0;
    ok = ok && json_get_bool(json_get(root, "healthy"));
    ok = ok && json_get_bool(json_get(root, "serving"));
    ok = ok && !json_get_bool(json_get(root, "operator_needed"));
    ok = ok && json_get_int(json_get(root, "height")) == served;
    ok = ok && json_get_int(json_get(root, "target_height")) ==
        target;
    ok = ok && json_get_int(json_get(root, "gap")) ==
        target - served;
    ok = ok && strcmp(json_get_str(json_get(root,
                                            "primary_blocker")),
                      "none") == 0;
    ok = ok && json_get_int(json_get(root, "served_height")) ==
        served;
    ok = ok && strcmp(json_get_str(json_get(root,
                                            "source_projection")),
                      "served_tip") == 0;
    ok = ok && json_get(root, "freshness") != NULL;
    return ok;
}

static bool small_gap_review_required_status(bool ok, uint8_t *resp,
                                             size_t cap)
{
    size_t n = api_handle_request("GET", "/api/status", NULL, 0,
                                  resp, cap);
    const char *body = api_test_body(resp, n, cap);
    struct json_value root;
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
    return ok;
}

static bool small_gap_review_required_health(bool ok, uint8_t *resp,
                                             size_t cap)
{
    size_t n = api_handle_request("GET", "/api/health", NULL, 0,
                                  resp, cap);
    const char *body = api_test_body(resp, n, cap);
    struct json_value root;
    json_init(&root);
    ok = ok && strstr((char *)resp,
                      "503 Service Unavailable") != NULL;
    ok = ok && body && json_read(&root, body, strlen(body));
    ok = ok && !json_get_bool(json_get(&root, "healthy"));
    ok = ok && !json_get_bool(json_get(&root, "serving"));
    ok = ok && api_test_expect_security_posture_shape(&root);
    json_free(&root);
    return ok;
}

static bool small_gap_transient_health(bool ok, uint8_t *resp, size_t cap)
{
    struct blocker_record transient;
    ok = ok && blocker_init(
        &transient, "peer_floor.test_transient", "peer_floor",
        BLOCKER_TRANSIENT, "temporary peer assignment gap");
    ok = ok && blocker_set(&transient) == 0;
    size_t n = api_handle_request("GET", "/api/health", NULL, 0,
                                  resp, cap);
    const char *body = api_test_body(resp, n, cap);
    struct json_value root;
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
    return ok;
}

static bool small_gap_transient_status(bool ok, uint8_t *resp, size_t cap)
{
    size_t n = api_handle_request("GET", "/api/status", NULL, 0,
                                  resp, cap);
    const char *body = api_test_body(resp, n, cap);
    struct json_value root;
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
    return ok;
}

static bool small_gap_permanent_health(bool ok, uint8_t *resp, size_t cap)
{
    struct blocker_record permanent;
    ok = ok && blocker_init(
        &permanent, "chain.test_authority_failure", "chain",
        BLOCKER_PERMANENT, "test chain authority failure");
    ok = ok && blocker_set(&permanent) == 0;
    size_t n = api_handle_request("GET", "/api/health", NULL, 0,
                                  resp, cap);
    const char *body = api_test_body(resp, n, cap);
    struct json_value root;
    json_init(&root);
    ok = ok && strstr((char *)resp,
                      "503 Service Unavailable") != NULL;
    ok = ok && body && json_read(&root, body, strlen(body));
    ok = ok && !json_get_bool(json_get(&root, "healthy"));
    ok = ok && !json_get_bool(json_get(&root, "serving"));
    const struct json_value *health_status = json_get(&root, "status");
    ok = ok && health_status && strcmp(json_get_str(json_get(
        health_status, "blocking_reason")),
        "chain.test_authority_failure") == 0;
    json_free(&root);
    return ok;
}

static bool typed_blocker_beats_review(bool ok, uint8_t *resp, size_t cap)
{
    agent_security_posture_test_override_review_required(1);
    size_t n = api_handle_request("GET", "/api/status", NULL, 0, resp, cap);
    const char *body = api_test_body(resp, n, cap);
    struct json_value root = {0};
    ok = ok && body && json_read(&root, body, strlen(body));
    const char *primary = json_get_str(json_get(&root, "primary_blocker"));
    const char *next = json_get_str(json_get(&root, "next_endpoint"));
    ok = ok && primary && strcmp(primary, "chain.test_authority_failure") == 0;
    ok = ok && next && strcmp(next, "/api/v1/health") == 0;
    json_free(&root);
    agent_security_posture_test_override_review_required(0);
    return ok;
}

static bool public_status_small_served_gap(uint8_t *resp, size_t cap)
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
                                      resp, cap);
        const char *body = api_test_body(resp, n, cap);
        struct json_value root;
        json_init(&root);
        ok = ok && n > 0 && body && json_read(&root, body, strlen(body));
        ok = ok && small_gap_healthy_fields(&root, served, target);
        json_free(&root);

        agent_security_posture_test_override_review_required(1);
        ok = small_gap_review_required_status(ok, resp, cap);
        ok = small_gap_review_required_health(ok, resp, cap);
        agent_security_posture_test_override_review_required(0);

        /* A transient worker/dependency blocker is operational warning
         * evidence, not authority to withdraw an already validated
         * public frontier.  Permanent chain-authority blockers still
         * hard-gate serving and /health. */
        ok = small_gap_transient_health(ok, resp, cap);
        ok = small_gap_transient_status(ok, resp, cap);
        blocker_clear("peer_floor.test_transient");

        ok = small_gap_permanent_health(ok, resp, cap);
        ok = typed_blocker_beats_review(ok, resp, cap);
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
    return ok;
}

static bool agent_latch_document(uint8_t *resp, size_t cap)
{
    size_t n = api_handle_request("GET", "/api/v1/agent", NULL, 0,
                                  resp, cap);
    const char *body = api_test_body(resp, n, cap);
    struct json_value root;
    json_init(&root);
    bool ok = n > 0 && body && json_read(&root, body, strlen(body));
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
    return ok;
}

static bool agent_clears_recovered_latch(uint8_t *resp, size_t cap)
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
        ok = agent_latch_document(resp, cap);
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
    return ok;
}

static bool material_gap_fields(const struct json_value *root,
                                int served, int target)
{
    bool ok = strcmp(json_get_str(json_get(root, "status")),
                     "degraded") == 0;
    ok = ok && json_get_bool(json_get(root, "operator_needed"));
    ok = ok && json_get_int(json_get(root, "height")) == served;
    ok = ok && json_get_int(json_get(root, "target_height")) ==
        target;
    ok = ok && json_get_int(json_get(root, "gap")) ==
        target - served;
    ok = ok && strcmp(json_get_str(json_get(root,
                                            "primary_blocker")),
                      "download_queue_idle") == 0;
    ok = ok && json_get_int(json_get(root, "served_height")) ==
        served;
    ok = ok && strcmp(json_get_str(json_get(root,
                                            "source_projection")),
                      "served_tip") == 0;
    ok = ok && json_get(root, "freshness") != NULL;
    return ok;
}

static bool public_status_material_served_gap(uint8_t *resp, size_t cap)
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
                                      resp, cap);
        const char *body = api_test_body(resp, n, cap);
        struct json_value root;
        json_init(&root);
        ok = ok && n > 0 && body && json_read(&root, body, strlen(body));
        ok = ok && material_gap_fields(&root, served, target);
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
    return ok;
}

static bool durable_tip_fields(const struct json_value *root)
{
    bool ok = strcmp(json_get_str(json_get(root, "status")),
                     "healthy") == 0;
    ok = ok && json_get_int(json_get(root, "height")) == 2;
    ok = ok && json_get_int(json_get(root, "target_height")) == 3;
    ok = ok && json_get_int(json_get(root, "gap")) == 1;
    ok = ok && strcmp(json_get_str(json_get(root,
                                            "primary_blocker")),
                      "none") == 0;
    ok = ok && json_get_int(json_get(root, "served_height")) == 2;
    ok = ok && json_get_int(json_get(root, "indexed_height")) >= 2;
    ok = ok && json_get_bool(json_get(root, "fresh"));
    ok = ok && strcmp(json_get_str(json_get(root,
                                            "source_projection")),
                      "served_tip") == 0;
    ok = ok && strcmp(json_get_str(json_get(root, "blocker")),
                      "none") == 0;
    return ok;
}

static bool public_status_durable_tip(uint8_t *resp, size_t cap)
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
    test_make_tmpdir(dbdir, sizeof(dbdir), "api_health",
                     "durable_status");

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
                                      resp, cap);
        const char *body = api_test_body(resp, n, cap);
        struct json_value root;
        json_init(&root);
        ok = ok && n > 0 && body && json_read(&root, body, strlen(body));
        ok = ok && durable_tip_fields(&root);
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
    ok &= fixture_rm_ok(dbdir);
    agent_security_posture_test_override_review_required(-1);
    return ok;
}

static bool hodl_http_json(bool ok, uint8_t *resp, size_t cap,
                           struct json_value *root)
{
    size_t n = api_handle_request("GET", "/api/hodl", NULL, 0, resp, cap);
    resp[n < cap ? n : cap - 1] = '\0';
    const char *body = api_test_body(resp, n, cap);
    json_init(root);
    ok = ok && n > 0 && body && json_read(root, body, strlen(body));
    ok = ok && strstr((char *)resp, "HTTP/1.1 200 OK") != NULL &&
         strstr((char *)resp, "please retry") == NULL &&
         strstr((char *)resp, "refreshing") == NULL;
    return ok;
}

static bool hodl_durable_tip_document(const struct json_value *root)
{
    bool ok = strcmp(json_get_str(json_get(root, "schema")),
                     "zcl.hodl_wave.v1") == 0;
    ok = ok && json_get_int(json_get(root, "height")) == 7;
    ok = ok && json_get_int(json_get(root, "served_tip_height")) == 7;
    ok = ok && json_get_int(json_get(root, "indexed_tip_height")) == 8;
    ok = ok && json_get_int(json_get(root, "block_tip_height")) == 8;
    ok = ok && json_get_int(json_get(root, "utxo_tip_height")) == 6;
    ok = ok && api_test_expect_freshness(root, "utxo_projection",
                                         7, 8, true);
    return ok;
}

static bool hodl_advanced_tip_document(const struct json_value *root)
{
    bool ok = json_get_int(json_get(root, "height")) == 8;
    ok = ok && json_get_int(json_get(root, "served_tip_height")) == 8;
    ok = ok && json_get_int(json_get(root, "indexed_tip_height")) == 8;
    ok = ok && json_get_int(json_get(root, "block_tip_height")) == 8;
    ok = ok && api_test_expect_freshness(root, "utxo_projection",
                                         8, 8, true);
    return ok;
}

static bool hodl_frontier_refreshes(uint8_t *resp, size_t cap)
{
    char dbdir[256];
    char dbpath[320];
    struct node_db ndb;
    memset(&ndb, 0, sizeof(ndb));
    test_make_tmpdir(dbdir, sizeof(dbdir), "api_health", "hodl");
    snprintf(dbpath, sizeof(dbpath), "%s/node.db", dbdir);

    api_stop_cache();
    bool ok = node_db_open(&ndb, dbpath);
    ok = ok && api_test_save_model_block(&ndb, 7, 0x71);
    ok = ok && api_test_save_model_block(&ndb, 8, 0x72);
    ok = ok && api_test_save_model_utxo(&ndb, 6, 0x61, 5000000000LL);
    ok = ok && api_test_seed_durable_tip(dbdir, 7);
    reducer_frontier_provable_tip_reset();
    api_set_state(NULL, NULL, NULL, &ndb, dbdir);

    struct json_value root;
    ok = hodl_http_json(ok, resp, cap, &root);
    ok = ok && hodl_durable_tip_document(&root);
    json_free(&root);

    reducer_frontier_provable_tip_set(8);
    ok = hodl_http_json(ok, resp, cap, &root);
    ok = ok && hodl_advanced_tip_document(&root);
    json_free(&root);

    api_set_state(NULL, NULL, NULL, NULL, NULL);
    api_stop_cache();
    reducer_frontier_provable_tip_reset();
    progress_store_close();
    node_db_close(&ndb);

    ok &= fixture_rm_ok(dbdir);
    return ok;
}

static bool deep_stats_suppressed_envelope(void)
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
    return ok;
}

static bool factoids_capped_document(bool ok, uint8_t *resp, size_t cap)
{
    size_t n = api_handle_request("GET", "/api/factoids", NULL, 0,
                                  resp, cap);
    resp[n < cap ? n : cap - 1] = '\0';
    const char *body = api_test_body(resp, n, cap);
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
    return ok;
}

static bool factoids_uncapped_document(bool ok, uint8_t *resp, size_t cap)
{
    size_t n = api_handle_request("GET", "/api/factoids", NULL, 0,
                                  resp, cap);
    resp[n < cap ? n : cap - 1] = '\0';
    const char *body = api_test_body(resp, n, cap);
    struct json_value root;
    json_init(&root);
    ok = ok && n > 0 && body && json_read(&root, body, strlen(body));
    ok = ok && json_get_int(json_get(&root, "chain_height")) == 8;
    ok = ok && json_get_int(json_get(&root, "served_height")) == 8;
    ok = ok && json_get_int(json_get(&root, "indexed_height")) == 8;
    ok = ok && !json_get_bool(json_get(&root, "index_capped"));
    json_free(&root);
    return ok;
}

static bool factoids_served_frontier(uint8_t *resp, size_t cap)
{
    char dbdir[256];
    char dbpath[320];
    struct node_db ndb;
    memset(&ndb, 0, sizeof(ndb));
    test_make_tmpdir(dbdir, sizeof(dbdir), "api_health", "factoids");
    snprintf(dbpath, sizeof(dbpath), "%s/node.db", dbdir);

    api_stop_cache();
    bool ok = node_db_open(&ndb, dbpath);
    ok = ok && api_test_save_model_block(&ndb, 7, 0x81);
    ok = ok && api_test_save_model_block(&ndb, 8, 0x82);
    ok = ok && api_test_save_model_utxo(&ndb, 6, 0x83, 2500000000LL);
    ok = ok && api_test_seed_durable_tip(dbdir, 7);
    reducer_frontier_provable_tip_reset();
    api_set_state(NULL, NULL, NULL, &ndb, dbdir);

    ok = factoids_capped_document(ok, resp, cap);
    reducer_frontier_provable_tip_set(8);
    ok = factoids_uncapped_document(ok, resp, cap);

    api_set_state(NULL, NULL, NULL, NULL, NULL);
    api_stop_cache();
    reducer_frontier_provable_tip_reset();
    progress_store_close();
    node_db_close(&ndb);

    ok &= fixture_rm_ok(dbdir);
    return ok;
}

int api_health_gate_focused_tests(void)
{
    int failures = 0;
    uint8_t resp[8192];

    printf("api: agentimpact maps block source policy to focused gates... ");
    {
        const char *params_json =
            "[\"engine/services/src/block_source_policy.c\","
            "\"engine/services/include/services/block_source_policy.h\"]";
        const char *groups[] = {
            "block_source_policy",
            "block_source_policy_status_json",
            "make_lint_gates",
        };
        bool ok = agent_impact_groups(params_json, 2, 3, groups,
                                      "make t ONLY=block_source_policy");

        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("api: agentimpact maps ZNAM service directory filters... ");
    {
        const char *params_json =
            "[\"contexts/naming/controllers/src/"
            "name_service_directory_filter_controller.c\"]";
        const char *groups[] = {
            "znam",
            "protocols",
            "api",
            "make_lint_gates",
        };
        bool ok = agent_impact_groups(params_json, 1, 4, groups,
                                      "make t ONLY=api");

        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("api: agentimpact maps json library to focused gates... ");
    {
        const char *params_json =
            "[\"platform/modules/json/include/json/json.h\","
            "\"tests/harness/src/test_json.c\"]";
        const char *groups[] = {
            "json",
            "rpc",
            "api",
            "syncdiag_rpc",
            "zcode_package_registry",
            "zcode_swarm_net",
            "make_lint_gates",
        };
        bool ok = agent_impact_groups(params_json, 2, 7, groups, NULL);

        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("api: public status names health blocking reason... ");
    {
        bool ok = public_status_names_blocking_reason(resp, sizeof(resp));

        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("api: public status treats small served gap as healthy... ");
    {
        bool ok = public_status_small_served_gap(resp, sizeof(resp));

        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("api: agent clears recovered chain-advance operator latch... ");
    {
        bool ok = agent_clears_recovered_latch(resp, sizeof(resp));

        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("api: public status still degrades material served gap... ");
    {
        bool ok = public_status_material_served_gap(resp, sizeof(resp));

        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("api: public status uses durable tip before H* publication... ");
    {
        bool ok = public_status_durable_tip(resp, sizeof(resp));

        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("api: hodl caps to served frontier and refreshes when H* advances... ");
    {
        bool ok = hodl_frontier_refreshes(resp, sizeof(resp));

        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("api: deep stats suppressed envelope has schema and freshness... ");
    {
        bool ok = deep_stats_suppressed_envelope();

        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("api: factoids caps JSON to served frontier instead of 503... ");
    {
        bool ok = factoids_served_frontier(resp, sizeof(resp));

        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    return failures;
}
