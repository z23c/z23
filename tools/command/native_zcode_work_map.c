/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: Reverify bounded task-map bytes from existing workspace CAS. */
#include "command/native_zcode_work_map.h"
#include "command/native_command.h"
#include "base/hex.h"

#include "base/log_macros.h"
#include "sha3/sha3.h"
#include "vcs/vcs_object.h"
#include "models/build_fabric.h"

#include <stdlib.h>
#include <string.h>

struct zcl_result zcl_native_work_map_evaluate(
    struct node_db *ndb, const char *workspace, const char *task_root,
    const char *candidate_root, const char *policy_root, const char *action_id,
    int64_t now, struct build_fabric_proof_evaluation *out)
{
    if (out) memset(out, 0, sizeof(*out));
    if (!out || !task_root || !candidate_root || !policy_root || !action_id)
        return ZCL_ERR(-1, "map evidence requires exact task, candidate, policy and action");
    struct db_build_action action;
    if (!db_build_action_find(ndb, action_id, &action))
        return ZCL_ERR(-1, "map evidence action is unavailable");
    if (strcmp(task_root, action.task_root_sha3) != 0 ||
        strcmp(candidate_root, action.candidate_root_sha3) != 0 ||
        strcmp(policy_root, action.proof_policy_root_sha3) != 0)
        return ZCL_ERR(-1, "map evidence action does not bind the requested identity");
    struct build_fabric_proof_evaluation observed = {0};
    struct zcl_result result = build_fabric_proof_evaluate_readonly(
        ndb, workspace, action_id, now, &observed);
    if (result.ok) *out = observed;
    return result;
}

enum zcl_work_map_result zcl_native_work_map_load(
    const char *workspace, const uint8_t root[32],
    struct zcl_work_map_node *nodes, size_t capacity, size_t *count)
{
    if (count) *count = 0;
    if (!workspace || !workspace[0] || !root || !nodes || !count) {
        LOG_ERROR("work_map", "CAS read requires workspace, root and output");
        return ZCL_WORK_MAP_BOUNDS;
    }
    uint8_t *wire = NULL;
    size_t length = 0;
    int loaded = vcs_object_load_raw_bounded(
        workspace, root, ZCL_WORK_MAP_WIRE_MAX, &wire, &length);
    if (loaded != 0) {
        free(wire);
        LOG_ERROR("work_map", "bounded CAS map read failed: code=%d", loaded);
        return loaded == -2 ? ZCL_WORK_MAP_BOUNDS : ZCL_WORK_MAP_OBJECT;
    }
    uint8_t checked[32];
    sha3_256(wire, length, checked);
    enum zcl_work_map_result result = ZCL_WORK_MAP_IDENTITY;
    if (memcmp(root, checked, 32) == 0)
        result = zcl_work_map_parse(wire, length, nodes, capacity, count);
    else
        LOG_ERROR("work_map", "CAS map bytes do not match the requested root");
    free(wire);
    return result;
}

static void map_fail(struct zcl_command_reply *reply, const char *code,
                     const char *message)
{
    zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
        ZCL_COMMAND_EXIT_INVALID, code, "map", false, false, message,
        "map definition is inert; acceptance requires separate evidence");
}

static bool map_page_number(const struct json_value *input, const char *key,
                            int64_t fallback, int64_t maximum, size_t *out)
{
    const struct json_value *value = json_get(input, key);
    int64_t number = value ? json_get_int(value) : fallback;
    if ((value && value->type != JSON_INT) || number < 0 || number > maximum)
        return false;
    *out = (size_t)number;
    return true;
}

static bool map_dependencies(struct json_value *row,
                             const struct zcl_work_map_node *node)
{
    struct json_value deps, value;
    json_init(&deps); json_set_array(&deps);
    json_init(&value);
    bool ok = true;
    for (size_t i = 0; ok && i < node->dependency_count; i++) {
        json_set_int(&value, node->dependencies[i]);
        ok = json_push_back(&deps, &value);
    }
    ok = ok && json_push_kv(row, "dependencies", &deps);
    json_free(&value); json_free(&deps);
    return ok;
}

static bool map_row(struct json_value *rows,
                    const struct zcl_work_map_node *node, size_t index)
{
    struct json_value row;
    json_init(&row); json_set_object(&row);
    char root[65];
    zcl_hex_encode(node->task_root, 32, root);
    const char *kind = node->kind == ZCL_WORK_MAP_LOOP ? "loop" :
        node->kind == ZCL_WORK_MAP_FEATURE ? "feature" : "milestone";
    bool ok = map_dependencies(&row, node) &&
        json_push_kv_int(&row, "index", (int64_t)index) &&
        json_push_kv_str(&row, "task_root", root) &&
        json_push_kv_str(&row, "kind", kind) &&
        json_push_kv_int(&row, "parent", node->parent == ZCL_WORK_MAP_NO_PARENT
            ? -1 : node->parent) &&
        json_push_kv_str(&row, "status", "UNKNOWN") &&
        json_push_kv_str(&row, "reason", "acceptance_not_observed") &&
        json_push_back(rows, &row);
    json_free(&row);
    return ok;
}

static bool map_render(struct zcl_command_reply *reply, const char *root,
                        const struct zcl_work_map_node *nodes, size_t count,
                        size_t offset, size_t limit)
{
    struct json_value rows;
    json_init(&rows); json_set_array(&rows);
    size_t end = offset + limit;
    if (end > count) end = count;
    bool ok = true;
    for (size_t i = offset; ok && i < end; i++)
        ok = map_row(&rows, &nodes[i], i);
    ok = ok && json_push_kv_str(&reply->data, "map_root", root) &&
        json_push_kv_int(&reply->data, "total", (int64_t)count) &&
        json_push_kv_int(&reply->data, "returned", (int64_t)(end - offset)) &&
        json_push_kv_int(&reply->data, "next_offset", end < count ? (int64_t)end : -1) &&
        json_push_kv_str(&reply->data, "definition_coverage", "complete") &&
        json_push_kv_str(&reply->data, "acceptance_coverage", "unobserved") &&
        json_push_kv(&reply->data, "nodes", &rows);
    json_free(&rows);
    return ok;
}

void zcl_native_handle_zcode_work_map(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    if (!request || !reply) return;
    const struct json_value *workspace_value = json_get(request->input, "workspace");
    const char *workspace = json_get_str(workspace_value);
    if (workspace_value && workspace_value->type != JSON_STR) {
        map_fail(reply, "WORK_MAP_INPUT", "workspace must be a string");
        return;
    }
    const char *root = json_get_str(json_get(request->input, "map_root"));
    size_t offset = 0, limit = 0;
    uint8_t address[32];
    if (!root || !zcl_hex_decode_lower(root, address, sizeof(address)) ||
        !map_page_number(request->input, "offset", 0, ZCL_WORK_MAP_MAX_NODES, &offset) ||
        !map_page_number(request->input, "limit", 4, 4, &limit) || limit == 0) {
        map_fail(reply, "WORK_MAP_INPUT", "requires exact map_root, bounded offset and limit 1..4");
        return;
    }
    struct zcl_work_map_node nodes[ZCL_WORK_MAP_MAX_NODES];
    size_t count = 0;
    enum zcl_work_map_result result = zcl_native_work_map_load(
        workspace && workspace[0] ? workspace : ".", address, nodes,
        ZCL_WORK_MAP_MAX_NODES, &count);
    if (result != ZCL_WORK_MAP_OK) {
        map_fail(reply, "WORK_MAP_UNAVAILABLE", "complete map bytes could not be verified");
        (void)json_push_kv_int(&reply->data, "map_refusal", result);
        return;
    }
    if (offset > count) {
        map_fail(reply, "WORK_MAP_OFFSET", "offset exceeds the complete map");
        return;
    }
    if (!map_render(reply, root, nodes, count, offset, limit))
        map_fail(reply, "WORK_MAP_OUTPUT", "bounded map page could not be rendered");
}
