/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * API status surfaces: node status tip identity, download statistics, binary
 * identity, the public status summary, and the agent summary aliases.
 */

#include "test/api_test_fixtures.h"

enum {
    API_STATUS_FIELD_PRESENT = 1,
    API_STATUS_FIELD_ABSENT,
    API_STATUS_FIELD_STR,
    API_STATUS_FIELD_INT,
    API_STATUS_FIELD_BOOL,
    API_STATUS_FIELD_TYPE
};

struct api_status_field {
    const char *key;
    int kind;
    const char *str;
    int64_t num;
    const char *(*fn)(void);
};

static bool api_status_match_field(const struct json_value *obj,
                                   const struct api_status_field *field,
                                   bool ok)
{
    const struct json_value *v;
    const char *got;
    const char *expect;
    bool want;

    if (!ok)
        return ok;
    v = field->key ? json_get(obj, field->key) : obj;
    if (field->kind == API_STATUS_FIELD_PRESENT)
        return v != NULL;
    if (field->kind == API_STATUS_FIELD_ABSENT)
        return v == NULL;
    if (field->kind == API_STATUS_FIELD_STR) {
        got = json_get_str(v);
        expect = field->fn ? field->fn() : field->str;
        return strcmp(got, expect) == 0;
    }
    if (field->kind == API_STATUS_FIELD_INT)
        return json_get_int(v) == field->num;
    if (field->kind == API_STATUS_FIELD_BOOL) {
        want = field->num != 0;
        return json_get_bool(v) == want;
    }
    if (field->kind == API_STATUS_FIELD_TYPE)
        return v != NULL && v->type == (enum json_type)field->num;
    return false;
}

static bool api_status_match_fields(const struct json_value *obj,
                                    const struct api_status_field *fields,
                                    size_t count, bool ok)
{
    for (size_t i = 0; i < count; i++)
        ok = api_status_match_field(obj, &fields[i], ok);
    return ok;
}

static bool api_status_load_response(uint8_t *resp, size_t n, size_t cap,
                                     struct json_value *root, bool ok)
{
    const char *body = api_test_body(resp, n, cap);

    json_init(root);
    if (!ok)
        return ok;
    return n > 0 && body && json_read(root, body, strlen(body));
}

static const struct json_value *api_status_json_if_ok(
    const struct json_value *obj, const char *key, bool ok)
{
    return ok ? json_get(obj, key) : NULL;
}

static void api_status_copy_block_hash(const struct block_index *block,
                                       char hex[65])
{
    if (block && block->phashBlock)
        uint256_get_hex(block->phashBlock, hex);
}

static void api_status_terminate_response(uint8_t *resp, size_t n,
                                          size_t cap)
{
    resp[n < cap ? n : cap - 1] = '\0';
}

static void api_status_release_provable_chain(struct main_state *ms)
{
    api_set_state(NULL, NULL, NULL, NULL, NULL);
    reducer_frontier_provable_tip_reset();
    main_state_free(ms);
    test_reset_shared_globals();
}

static bool api_status_rpc_actor_ok(const struct rpc_command *cmd,
                                    struct json_value *params,
                                    struct json_value *result, bool ok)
{
    return ok && cmd && cmd->actor(params, false, result);
}

static bool api_status_snap_cores_match(
    const struct download_stats_snapshot *full,
    const struct download_stats_snapshot *thin)
{
    bool ok = full->requested == thin->requested;

    ok = ok && full->received == thin->received;
    ok = ok && full->timed_out == thin->timed_out;
    ok = ok && full->in_flight == thin->in_flight;
    ok = ok && full->queued == thin->queued;
    ok = ok && full->bytes_downloaded == thin->bytes_downloaded;
    ok = ok && full->mbps_avg == thin->mbps_avg;
    return ok;
}

static bool api_status_route_download_fields(uint8_t *resp, size_t cap,
                                             const char *route, bool ok)
{
    static const struct api_status_field fields[] = {
        { NULL, API_STATUS_FIELD_PRESENT, NULL, 0, NULL },
        /* The abbreviated fields must be present... */
        { "requested", API_STATUS_FIELD_PRESENT, NULL, 0, NULL },
        { "received", API_STATUS_FIELD_PRESENT, NULL, 0, NULL },
        { "timed_out", API_STATUS_FIELD_PRESENT, NULL, 0, NULL },
        { "in_flight", API_STATUS_FIELD_PRESENT, NULL, 0, NULL },
        { "queued", API_STATUS_FIELD_PRESENT, NULL, 0, NULL },
        /* ...and the throughput fields from the shared
         * download_stats_push_json serializer. */
        { "bytes_downloaded", API_STATUS_FIELD_PRESENT, NULL, 0, NULL },
        { "mbps_avg", API_STATUS_FIELD_PRESENT, NULL, 0, NULL },
        { "gb_downloaded", API_STATUS_FIELD_PRESENT, NULL, 0, NULL },
    };
    size_t n = api_handle_request("GET", route, NULL, 0, resp, cap);
    struct json_value root;
    const struct json_value *download;

    ok = api_status_load_response(resp, n, cap, &root, ok);
    download = api_status_json_if_ok(&root, "download", ok);
    ok = api_status_match_fields(download, fields,
                                 sizeof(fields) / sizeof(fields[0]), ok);
    json_free(&root);
    return ok;
}

static bool api_status_probe_download_routes(uint8_t *resp, size_t cap,
                                             struct main_state *ms,
                                             const char **missing_route)
{
    static const char *routes[] = {
        "/api/node/status", "/api/status", "/api/health",
    };
    struct block_index *blocks[2] = {0};
    bool ok;

    test_reset_shared_globals();
    ok = api_test_build_chain(ms, blocks, 2);
    reducer_frontier_provable_tip_set(1);
    api_set_state(ms, NULL, NULL, NULL, api_test_datadir());
    for (size_t i = 0; i < sizeof(routes) / sizeof(routes[0]); i++) {
        ok = api_status_route_download_fields(resp, cap, routes[i], ok);
        if (!ok) {
            *missing_route = routes[i];
            break;
        }
    }
    return ok;
}

static bool api_status_health_queue_backed_up(uint8_t *resp, size_t cap,
                                              bool ok)
{
    static const struct api_status_field fields[] = {
        { NULL, API_STATUS_FIELD_PRESENT, NULL, 0, NULL },
        { "queue_backed_up", API_STATUS_FIELD_PRESENT, NULL, 0, NULL },
    };
    size_t n;
    struct json_value root;
    const struct json_value *download;

    /* /api/health additionally keeps its queue_backed_up field. */
    n = api_handle_request("GET", "/api/health", NULL, 0, resp, cap);
    ok = api_status_load_response(resp, n, cap, &root, ok);
    download = api_status_json_if_ok(&root, "download", ok);
    ok = api_status_match_fields(download, fields,
                                 sizeof(fields) / sizeof(fields[0]), ok);
    json_free(&root);
    return ok;
}

static bool api_status_node_tip_identity_ok(uint8_t *resp, size_t cap)
{
    struct main_state ms;
    struct block_index *blocks[4] = {0};
    char hstar_hex[65] = {0};
    char active_hex[65] = {0};
    char expected[96];
    char forbidden[96];
    struct json_value root;
    const struct json_value *chain;
    const struct json_value *errors;
    const struct api_status_field schema = {
        "schema", API_STATUS_FIELD_STR, "zcl.node_status.v1", 0, NULL
    };
    const struct api_status_field error_fields[] = {
        { NULL, API_STATUS_FIELD_PRESENT, NULL, 0, NULL },
        { "recent", API_STATUS_FIELD_PRESENT, NULL, 0, NULL },
    };
    size_t n;
    bool ok;

    test_reset_shared_globals();
    ok = api_test_build_chain(&ms, blocks, 4);
    reducer_frontier_provable_tip_set(1);
    api_set_state(&ms, NULL, NULL, NULL, api_test_datadir());

    api_status_copy_block_hash(blocks[1], hstar_hex);
    api_status_copy_block_hash(blocks[3], active_hex);
    snprintf(expected, sizeof(expected), "\"tip_hash\":\"%s\"",
             hstar_hex);
    snprintf(forbidden, sizeof(forbidden), "\"tip_hash\":\"%s\"",
             active_hex);

    n = api_handle_request("GET", "/api/node/status", NULL, 0, resp, cap);
    api_status_terminate_response(resp, n, cap);
    ok = ok && n > 0;
    ok = ok && strstr((char *)resp, "\"tip_height\":1") != NULL;
    ok = ok && strstr((char *)resp, expected) != NULL;
    ok = ok && strstr((char *)resp, forbidden) == NULL;
    ok = api_status_load_response(resp, n, cap, &root, ok);
    ok = api_status_match_field(&root, &schema, ok);
    ok = ok && api_test_expect_freshness(&root, "served_tip",
                                         1, 1, true);
    chain = json_get(&root, "chain");
    {
        const struct api_status_field chain_fields[] = {
            { NULL, API_STATUS_FIELD_PRESENT, NULL, 0, NULL },
            { "tip_height", API_STATUS_FIELD_INT, NULL, 1, NULL },
            { "tip_hash", API_STATUS_FIELD_STR, hstar_hex, 0, NULL },
        };
        ok = api_status_match_fields(chain, chain_fields,
                                     sizeof(chain_fields) /
                                     sizeof(chain_fields[0]), ok);
    }
    errors = json_get(&root, "errors");
    ok = api_status_match_fields(errors, error_fields,
                                 sizeof(error_fields) /
                                 sizeof(error_fields[0]), ok);
    json_free(&root);
    api_status_release_provable_chain(&ms);
    return ok;
}

static bool api_status_downloadstats_shape_ok(uint8_t *resp, size_t cap)
{
    static const struct api_status_field before[] = {
        { "schema", API_STATUS_FIELD_STR, "zcl.downloadstats.v1", 0, NULL },
        /* Core counts (always present). */
        { "requested", API_STATUS_FIELD_PRESENT, NULL, 0, NULL },
        { "received", API_STATUS_FIELD_PRESENT, NULL, 0, NULL },
        { "timed_out", API_STATUS_FIELD_PRESENT, NULL, 0, NULL },
        { "in_flight", API_STATUS_FIELD_PRESENT, NULL, 0, NULL },
        { "queued", API_STATUS_FIELD_PRESENT, NULL, 0, NULL },
        /* Diagnostics this endpoint already had. */
        { "orphaned", API_STATUS_FIELD_PRESENT, NULL, 0, NULL },
        { "accounting_drift", API_STATUS_FIELD_PRESENT, NULL, 0, NULL },
        { "last_assign_result", API_STATUS_FIELD_PRESENT, NULL, 0, NULL },
        { "peer_download_total", API_STATUS_FIELD_PRESENT, NULL, 0, NULL },
        { "peer_download_truncated", API_STATUS_FIELD_PRESENT, NULL, 0, NULL },
    };
    static const struct api_status_field peer_type = {
        NULL, API_STATUS_FIELD_TYPE, NULL, JSON_ARR, NULL
    };
    static const struct api_status_field after[] = {
        /* Throughput fields. */
        { "bytes_downloaded", API_STATUS_FIELD_PRESENT, NULL, 0, NULL },
        { "mbps_avg", API_STATUS_FIELD_PRESENT, NULL, 0, NULL },
        { "gb_downloaded", API_STATUS_FIELD_PRESENT, NULL, 0, NULL },
    };
    struct json_value root;
    const struct json_value *peer_downloads;
    size_t n;
    bool ok;

    test_reset_shared_globals();
    n = api_handle_request("GET", "/api/downloadstats", NULL, 0, resp, cap);
    ok = api_status_load_response(resp, n, cap, &root, true);
    ok = api_status_match_fields(&root, before,
                                 sizeof(before) / sizeof(before[0]), ok);
    peer_downloads = json_get(&root, "peer_downloads");
    ok = api_status_match_field(peer_downloads, &peer_type, ok);
    ok = api_status_match_fields(&root, after,
                                 sizeof(after) / sizeof(after[0]), ok);
    json_free(&root);
    test_reset_shared_globals();
    return ok;
}

static bool api_status_snapshot_subset_ok(void)
{
    static const struct api_status_field full_diag[] = {
        { "last_assign_result", API_STATUS_FIELD_PRESENT, NULL, 0, NULL },
        { "queued_forward", API_STATUS_FIELD_PRESENT, NULL, 0, NULL },
        { "queued_history", API_STATUS_FIELD_PRESENT, NULL, 0, NULL },
        { "in_flight_forward", API_STATUS_FIELD_PRESENT, NULL, 0, NULL },
        { "in_flight_history", API_STATUS_FIELD_PRESENT, NULL, 0, NULL },
    };
    static const struct api_status_field thin_last_assign = {
        "last_assign_result", API_STATUS_FIELD_ABSENT, NULL, 0, NULL
    };
    static const struct api_status_field bytes_downloaded = {
        "bytes_downloaded", API_STATUS_FIELD_PRESENT, NULL, 0, NULL
    };
    struct download_stats_snapshot full_snap = {0};
    struct download_stats_snapshot thin_snap = {0};
    struct json_value full_obj;
    struct json_value thin_obj;
    bool ok;

    download_stats_snapshot_collect(&full_snap, true);
    download_stats_snapshot_collect(&thin_snap, false);
    ok = api_status_snap_cores_match(&full_snap, &thin_snap);

    json_init(&full_obj);
    json_set_object(&full_obj);
    download_stats_push_json(&full_obj, &full_snap, true);
    json_init(&thin_obj);
    json_set_object(&thin_obj);
    download_stats_push_json(&thin_obj, &thin_snap, false);
    /* full=true carries extended diagnostics full=false does not. */
    ok = api_status_match_fields(&full_obj, full_diag,
                                 sizeof(full_diag) / sizeof(full_diag[0]),
                                 ok);
    ok = api_status_match_field(&thin_obj, &thin_last_assign, ok);
    /* Both push the same core + throughput fields. */
    ok = api_status_match_field(&full_obj, &bytes_downloaded, ok);
    ok = api_status_match_field(&thin_obj, &bytes_downloaded, ok);
    json_free(&full_obj);
    json_free(&thin_obj);
    return ok;
}

static bool api_status_binary_identity_ok(void)
{
    /* Invoke the registered actor directly (bypassing rpc_table_execute()'s
     * RPC-server warmup gate, as the name_list RPC tests above do). */
    static const struct api_status_field getinfo_fields[] = {
        { "version", API_STATUS_FIELD_PRESENT, NULL, 0, NULL },
        { "subversion", API_STATUS_FIELD_STR, CLIENT_NAME, 0, NULL },
        { "build_commit", API_STATUS_FIELD_STR, NULL, 0, zcl_build_commit },
        { "source_id_sha256", API_STATUS_FIELD_STR, NULL, 0,
          zcl_build_source_id_sha256 },
        { "protocolversion", API_STATUS_FIELD_INT, NULL, PROTOCOL_VERSION,
          NULL },
    };
    static const struct api_status_field netinfo_fields[] = {
        { "subversion", API_STATUS_FIELD_STR, CLIENT_NAME, 0, NULL },
        { "build_commit", API_STATUS_FIELD_STR, NULL, 0, zcl_build_commit },
        { "source_id_sha256", API_STATUS_FIELD_STR, NULL, 0,
          zcl_build_source_id_sha256 },
    };
    static const struct api_status_field binary_fields[] = {
        { NULL, API_STATUS_FIELD_PRESENT, NULL, 0, NULL },
        /* Field name preserved... */
        { "client_name", API_STATUS_FIELD_STR, CLIENT_NAME, 0, NULL },
        /* ...alongside the shared helper's "subversion" name and the
         * build_commit it already carried. */
        { "subversion", API_STATUS_FIELD_STR, CLIENT_NAME, 0, NULL },
        { "build_commit", API_STATUS_FIELD_STR, NULL, 0, zcl_build_commit },
        { "source_id_sha256", API_STATUS_FIELD_STR, NULL, 0,
          zcl_build_source_id_sha256 },
    };
    struct rpc_table misc_tbl;
    struct rpc_table net_tbl;
    struct json_value params;
    struct json_value result = {0};
    const struct rpc_command *cmd;
    const struct json_value *binary;
    bool ok;

    rpc_table_init(&misc_tbl);
    register_misc_rpc_commands(&misc_tbl);
    rpc_table_init(&net_tbl);
    register_net_rpc_commands(&net_tbl);
    rpc_net_set_connman(NULL);

    json_init(&params);
    json_set_array(&params);

    cmd = rpc_table_find(&misc_tbl, "getinfo");
    ok = api_status_rpc_actor_ok(cmd, &params, &result, true);
    ok = api_status_match_fields(&result, getinfo_fields,
                                 sizeof(getinfo_fields) /
                                 sizeof(getinfo_fields[0]), ok);
    json_free(&result);

    json_init(&result);
    cmd = rpc_table_find(&net_tbl, "getnetworkinfo");
    ok = api_status_rpc_actor_ok(cmd, &params, &result, ok);
    ok = api_status_match_fields(&result, netinfo_fields,
                                 sizeof(netinfo_fields) /
                                 sizeof(netinfo_fields[0]), ok);
    json_free(&result);

    json_init(&result);
    cmd = rpc_table_find(&net_tbl, "bootstrapstatus");
    ok = api_status_rpc_actor_ok(cmd, &params, &result, ok);
    binary = api_status_json_if_ok(&result, "binary", ok);
    ok = api_status_match_fields(binary, binary_fields,
                                 sizeof(binary_fields) /
                                 sizeof(binary_fields[0]), ok);
    json_free(&result);

    json_free(&params);
    rpc_net_set_connman(NULL);
    return ok;
}

static bool api_status_public_status_shape_ok(uint8_t *resp, size_t cap)
{
    static const struct api_status_field head[] = {
        { "schema", API_STATUS_FIELD_STR, "zcl.public_status.v3", 0, NULL },
        { "build_commit", API_STATUS_FIELD_STR, NULL, 0, zcl_build_commit },
    };
    static const struct api_status_field present[] = {
        { "status", API_STATUS_FIELD_PRESENT, NULL, 0, NULL },
        { "height", API_STATUS_FIELD_PRESENT, NULL, 0, NULL },
        { "recommended_endpoints", API_STATUS_FIELD_PRESENT, NULL, 0, NULL },
    };
    struct main_state ms;
    struct block_index *blocks[3] = {0};
    struct json_value root;
    size_t n;
    bool ok;

    test_reset_shared_globals();
    ok = api_test_build_chain(&ms, blocks, 3);
    reducer_frontier_provable_tip_set(2);
    rpc_agent_set_boot_context("canonical", "full",
                               "/tmp/zcl-canonical", 18232, 8033,
                               8443, 18034);
    api_set_state(&ms, NULL, NULL, NULL, api_test_datadir());

    n = api_handle_request("GET", "/api/status", NULL, 0, resp, cap);
    ok = api_status_load_response(resp, n, cap, &root, ok);
    ok = api_status_match_fields(&root, head,
                                 sizeof(head) / sizeof(head[0]), ok);
    ok = ok && api_test_expect_freshness(&root, "served_tip",
                                         2, 2, true);
    ok = api_status_match_fields(&root, present,
                                 sizeof(present) / sizeof(present[0]), ok);
    ok = ok && api_test_expect_readiness_shape(&root);
    ok = ok && api_test_expect_security_posture_shape(&root);
    ok = ok && api_test_expect_lane_safety_fields(
        &root, "canonical", false, false, true, "dev",
        "observe_only_or_use_dev_lane");
    json_free(&root);

    api_status_release_provable_chain(&ms);
    return ok;
}

static bool api_status_agent_alias_summary_ok(uint8_t *resp, size_t cap)
{
    static const struct api_status_field head_fields[] = {
        { "schema", API_STATUS_FIELD_STR, "zcl.public_status.v3", 0, NULL },
        { "api_version", API_STATUS_FIELD_STR, "v1", 0, NULL },
        { "build_commit", API_STATUS_FIELD_STR, NULL, 0, zcl_build_commit },
    };
    static const struct api_status_field height_current[] = {
        { NULL, API_STATUS_FIELD_TYPE, NULL, JSON_OBJ, NULL },
        { "schema", API_STATUS_FIELD_STR, "zcl.height_contract.v1", 0, NULL },
        { "status", API_STATUS_FIELD_STR, "current", 0, NULL },
        { "normal_lookahead", API_STATUS_FIELD_BOOL, NULL, false, NULL },
        { "served_tip_height", API_STATUS_FIELD_INT, NULL, 2, NULL },
        { "active_tip_height", API_STATUS_FIELD_INT, NULL, 2, NULL },
        { "header_tip_height", API_STATUS_FIELD_INT, NULL, 2, NULL },
        { "external_height_is", API_STATUS_FIELD_STR, "served_tip_height",
          0, NULL },
    };
    static const struct api_status_field resource_fields[] = {
        { NULL, API_STATUS_FIELD_TYPE, NULL, JSON_OBJ, NULL },
        { "schema", API_STATUS_FIELD_STR, "zcl.node_resources.v1", 0, NULL },
        { "rss_mb", API_STATUS_FIELD_PRESENT, NULL, 0, NULL },
        { "cgroup_memory_available", API_STATUS_FIELD_PRESENT, NULL, 0, NULL },
        { "cgroup_memory_current_mb", API_STATUS_FIELD_PRESENT, NULL, 0,
          NULL },
        { "cgroup_memory_high_mb", API_STATUS_FIELD_PRESENT, NULL, 0, NULL },
        { "cgroup_memory_max_mb", API_STATUS_FIELD_PRESENT, NULL, 0, NULL },
        { "cgroup_memory_stat_available", API_STATUS_FIELD_PRESENT, NULL, 0,
          NULL },
        { "cgroup_memory_anon_mb", API_STATUS_FIELD_PRESENT, NULL, 0, NULL },
        { "cgroup_memory_file_mb", API_STATUS_FIELD_PRESENT, NULL, 0, NULL },
        { "cgroup_memory_working_set_mb", API_STATUS_FIELD_PRESENT, NULL, 0,
          NULL },
        { "cgroup_memory_reclaimable_mb", API_STATUS_FIELD_PRESENT, NULL, 0,
          NULL },
        { "cgroup_memory_watch", API_STATUS_FIELD_PRESENT, NULL, 0, NULL },
        { "memory_pressure", API_STATUS_FIELD_PRESENT, NULL, 0, NULL },
        { "memory_pressure_detail", API_STATUS_FIELD_PRESENT, NULL, 0, NULL },
        { "pressure_basis", API_STATUS_FIELD_PRESENT, NULL, 0, NULL },
        { "uptime_seconds", API_STATUS_FIELD_PRESENT, NULL, 0, NULL },
    };
    static const struct api_status_field lane_fields[] = {
        { NULL, API_STATUS_FIELD_TYPE, NULL, JSON_OBJ, NULL },
        { "schema", API_STATUS_FIELD_STR, "zcl.operator_lane.v1", 0, NULL },
        { "lane", API_STATUS_FIELD_STR, "canonical", 0, NULL },
        { "canonical", API_STATUS_FIELD_BOOL, NULL, true, NULL },
        { "development", API_STATUS_FIELD_BOOL, NULL, false, NULL },
        { "restart_policy", API_STATUS_FIELD_STR, "operator_gated", 0, NULL },
        { "automation_restart_ok", API_STATUS_FIELD_BOOL, NULL, false, NULL },
        { "automation_deploy_ok", API_STATUS_FIELD_BOOL, NULL, false, NULL },
        { "requires_operator_confirmation", API_STATUS_FIELD_BOOL, NULL, true,
          NULL },
    };
    static const struct api_status_field safety_fields[] = {
        { NULL, API_STATUS_FIELD_TYPE, NULL, JSON_OBJ, NULL },
        { "schema", API_STATUS_FIELD_STR,
          "zcl.operator_deployment_safety.v1", 0, NULL },
        { "protects_public_endpoint", API_STATUS_FIELD_BOOL, NULL, true,
          NULL },
        { "automation_deploy_ok", API_STATUS_FIELD_BOOL, NULL, false, NULL },
        { "safe_default_action", API_STATUS_FIELD_STR,
          "observe_only_or_use_dev_lane", 0, NULL },
    };
    static const struct api_status_field watchdog_fields[] = {
        { NULL, API_STATUS_FIELD_TYPE, NULL, JSON_OBJ, NULL },
        { "schema", API_STATUS_FIELD_STR, "zcl.restart_watchdog.v1", 0,
          NULL },
        { "status", API_STATUS_FIELD_PRESENT, NULL, 0, NULL },
        { "last_restart_autonomous", API_STATUS_FIELD_PRESENT, NULL, 0,
          NULL },
        { "last_restart_reason", API_STATUS_FIELD_PRESENT, NULL, 0, NULL },
        { "no_progress_restarts", API_STATUS_FIELD_PRESENT, NULL, 0, NULL },
    };
    static const struct api_status_field height_lookahead[] = {
        { NULL, API_STATUS_FIELD_TYPE, NULL, JSON_OBJ, NULL },
        { "status", API_STATUS_FIELD_STR, "normal_lookahead", 0, NULL },
        { "normal_lookahead", API_STATUS_FIELD_BOOL, NULL, true, NULL },
        { "served_tip_height", API_STATUS_FIELD_INT, NULL, 1, NULL },
        { "active_tip_height", API_STATUS_FIELD_INT, NULL, 2, NULL },
        { "target_height", API_STATUS_FIELD_INT, NULL, 2, NULL },
        { "served_gap_blocks", API_STATUS_FIELD_INT, NULL, 1, NULL },
        { "external_height_semantics", API_STATUS_FIELD_PRESENT, NULL, 0,
          NULL },
        { "active_tip_semantics", API_STATUS_FIELD_PRESENT, NULL, 0, NULL },
    };
    static const struct api_status_field alias_fields[] = {
        { "schema", API_STATUS_FIELD_STR, "zcl.public_status.v3", 0, NULL },
        { "build_commit", API_STATUS_FIELD_STR, NULL, 0, zcl_build_commit },
        { "source_projection", API_STATUS_FIELD_STR, "served_tip", 0, NULL },
    };
    struct main_state ms;
    struct block_index *blocks[3] = {0};
    struct bsp_decision decision;
    struct json_value root;
    const struct json_value *height_contract;
    const struct json_value *resources;
    const struct json_value *lane;
    const struct json_value *safety;
    const struct json_value *restart_watchdog;
    size_t n;
    bool ok;

    test_reset_shared_globals();
    ok = api_test_build_chain(&ms, blocks, 3);
    memset(&decision, 0, sizeof(decision));
    decision.result = BSP_DECISION_USE_SOURCE;
    decision.selected_source = BSP_SOURCE_P2P;
    decision.local_height = 2;
    decision.target_height = 2;
    decision.projection_height = 2;
    node_health_test_set_chain_advance_decision_override(&decision);
    reducer_frontier_provable_tip_set(2);
    api_set_state(&ms, NULL, NULL, NULL, api_test_datadir());

    n = api_handle_request("GET", "/api/v1/agent", NULL, 0, resp, cap);
    ok = api_status_load_response(resp, n, cap, &root, ok);
    ok = api_status_match_fields(&root, head_fields,
                                 sizeof(head_fields) / sizeof(head_fields[0]),
                                 ok);
    ok = ok && api_test_expect_freshness(&root, "served_tip",
                                         2, 2, true);
    ok = ok && api_test_expect_readiness_shape(&root);
    ok = ok && api_test_expect_security_posture_shape(&root);
    ok = ok && api_test_expect_lane_safety_fields(
        &root, "canonical", false, false, true, "dev",
        "observe_only_or_use_dev_lane");
    height_contract = json_get(&root, "height_contract");
    ok = api_status_match_fields(height_contract, height_current,
                                 sizeof(height_current) /
                                 sizeof(height_current[0]), ok);
    resources = json_get(&root, "resources");
    ok = api_status_match_fields(resources, resource_fields,
                                 sizeof(resource_fields) /
                                 sizeof(resource_fields[0]), ok);
    lane = json_get(&root, "operator_lane");
    ok = api_status_match_fields(lane, lane_fields,
                                 sizeof(lane_fields) / sizeof(lane_fields[0]),
                                 ok);
    safety = json_get(lane, "deployment_safety");
    ok = api_status_match_fields(safety, safety_fields,
                                 sizeof(safety_fields) /
                                 sizeof(safety_fields[0]), ok);
    restart_watchdog = json_get(&root, "restart_watchdog");
    ok = api_status_match_fields(restart_watchdog, watchdog_fields,
                                 sizeof(watchdog_fields) /
                                 sizeof(watchdog_fields[0]), ok);
    json_free(&root);

    reducer_frontier_provable_tip_set(1);
    n = api_handle_request("GET", "/api/v1/agent", NULL, 0, resp, cap);
    ok = api_status_load_response(resp, n, cap, &root, ok);
    height_contract = json_get(&root, "height_contract");
    ok = api_status_match_fields(height_contract, height_lookahead,
                                 sizeof(height_lookahead) /
                                 sizeof(height_lookahead[0]), ok);
    json_free(&root);
    reducer_frontier_provable_tip_set(2);

    n = api_handle_request("GET", "/api/v1/node", NULL, 0, resp, cap);
    ok = api_status_load_response(resp, n, cap, &root, ok);
    ok = api_status_match_fields(&root, alias_fields,
                                 sizeof(alias_fields) /
                                 sizeof(alias_fields[0]), ok);
    json_free(&root);

    n = api_handle_request("GET", "/api/agent", NULL, 0, resp, cap);
    ok = api_status_load_response(resp, n, cap, &root, ok);
    ok = api_status_match_fields(&root, alias_fields,
                                 sizeof(alias_fields) /
                                 sizeof(alias_fields[0]), ok);
    json_free(&root);

    api_set_state(NULL, NULL, NULL, NULL, NULL);
    rpc_agent_set_boot_context(NULL, NULL, NULL, 0, 0, 0, 0);
    node_health_test_set_chain_advance_decision_override(NULL);
    reducer_frontier_provable_tip_reset();
    main_state_free(&ms);
    test_reset_shared_globals();
    return ok;
}

int api_status_focused_tests(void)
{
    int failures = 0;
    uint8_t resp[8192];

    printf("api: node status tip identity follows provable tip... ");
    if (api_status_node_tip_identity_ok(resp, sizeof(resp)))
        printf("OK\n");
    else { printf("FAIL\n"); failures++; }

    printf("api: node/status, public status, and health download blocks "
           "gained the throughput fields they were missing... ");
    {
        struct main_state ms;
        const char *missing_route = NULL;
        bool ok = api_status_probe_download_routes(resp, sizeof(resp), &ms,
                                                   &missing_route);

        if (missing_route)
            fprintf(stderr, "  route %s missing a download field\n",
                    missing_route);
        ok = api_status_health_queue_backed_up(resp, sizeof(resp), ok);
        api_status_release_provable_chain(&ms);

        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("api: downloadstats REST exposes throughput alongside its "
           "existing full diagnostics (site1/site2 drift closed)... ");
    if (api_status_downloadstats_shape_ok(resp, sizeof(resp)))
        printf("OK\n");
    else { printf("FAIL\n"); failures++; }

    printf("api: download_stats_snapshot_collect(full=false) is a "
           "counts-consistent subset of full=true (shared collector)... ");
    if (api_status_snapshot_subset_ok())
        printf("OK\n");
    else { printf("FAIL\n"); failures++; }

    printf("api: node identity exposes source SHA-256 + Git trace; "
           "bootstrapstatus keeps client_name... ");
    if (api_status_binary_identity_ok())
        printf("OK\n");
    else { printf("FAIL\n"); failures++; }

    printf("api: public status exposes compact summary shape... ");
    if (api_status_public_status_shape_ok(resp, sizeof(resp)))
        printf("OK\n");
    else { printf("FAIL\n"); failures++; }

    printf("api: /api/v1/agent and compat aliases compact summary... ");
    if (api_status_agent_alias_summary_ok(resp, sizeof(resp)))
        printf("OK\n");
    else { printf("FAIL\n"); failures++; }

    return failures;
}
