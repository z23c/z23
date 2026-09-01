/* Copyright 2026 Rhett Creighton - Apache License 2.0 */
#include "controllers/agent_height_contract.h"

#include "json/json.h"
#include "services/node_health_service.h"

#include <stdbool.h>

static bool height_contract_normal_lookahead(
    const struct agent_height_contract_input *in)
{
    if (!in)
        return false;
    return in->served_gap_blocks == 1 &&
           (in->reducer_log_head_gap_blocks < 0 ||
            in->reducer_log_head_gap_blocks <= 1);
}

static const char *height_contract_status(
    const struct agent_height_contract_input *in)
{
    if (!in)
        return "unknown";
    if (in->served_gap_blocks <= 0)
        return "current";
    if (height_contract_normal_lookahead(in))
        return "normal_lookahead";
    if (in->served_gap_blocks <= ZCL_NODE_HEALTH_LAG_WARN_BLOCKS)
        return "minor_lag";
    return "lagging";
}

void agent_push_height_contract_json(
    struct json_value *out,
    const char *key,
    const struct agent_height_contract_input *in)
{
    if (!out || !in)
        return;

    struct json_value obj = {0};
    json_set_object(&obj);
    json_push_kv_str(&obj, "schema", "zcl.height_contract.v1");
    json_push_kv_int(&obj, "schema_version", 1);
    json_push_kv_str(&obj, "status", height_contract_status(in));
    json_push_kv_bool(&obj, "normal_lookahead",
                      height_contract_normal_lookahead(in));
    json_push_kv_int(&obj, "served_tip_height",
                     in->served_tip_height);
    json_push_kv_int(&obj, "active_tip_height",
                     in->active_tip_height);
    json_push_kv_int(&obj, "header_tip_height",
                     in->header_tip_height);
    json_push_kv_int(&obj, "peer_best_height", in->peer_best_height);
    json_push_kv_int(&obj, "target_height", in->target_height);
    json_push_kv_int(&obj, "served_gap_blocks",
                     in->served_gap_blocks);
    json_push_kv_int(&obj, "reducer_log_head", in->reducer_log_head);
    json_push_kv_int(&obj, "reducer_log_head_gap_blocks",
                     in->reducer_log_head_gap_blocks);
    json_push_kv_str(&obj, "external_height_is", "served_tip_height");
    json_push_kv_str(
        &obj, "external_height_semantics",
        "getblockcount, getblockchaininfo.blocks, and P2P start_height serve H* (the provable reducer frontier)");
    json_push_kv_str(
        &obj, "active_tip_semantics",
        "active_tip_height is the sync-window lookahead tip and can be one block above served_tip_height while tip_finalize waits for a canonical successor");
    json_push_kv(out, key && key[0] ? key : "height_contract", &obj);
    json_free(&obj);
}

void agent_push_height_contract_fields_json(
    struct json_value *out,
    const char *key,
    int64_t served_tip_height,
    int64_t active_tip_height,
    int64_t header_tip_height,
    int64_t peer_best_height,
    int64_t target_height,
    int64_t served_gap_blocks,
    int64_t reducer_log_head,
    int64_t reducer_log_head_gap_blocks)
{
    struct agent_height_contract_input in = {
        .served_tip_height = served_tip_height,
        .active_tip_height = active_tip_height,
        .header_tip_height = header_tip_height,
        .peer_best_height = peer_best_height,
        .target_height = target_height,
        .served_gap_blocks = served_gap_blocks,
        .reducer_log_head = reducer_log_head,
        .reducer_log_head_gap_blocks = reducer_log_head_gap_blocks,
    };
    agent_push_height_contract_json(out, key, &in);
}
