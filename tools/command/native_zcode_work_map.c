/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: Reverify bounded task-map bytes from existing workspace CAS. */
#include "command/native_zcode_work_map.h"
#include "command/native_command.h"
#include "base/hex.h"

#include "base/log_macros.h"
#include "sha3/sha3.h"
#include "vcs/vcs_object.h"
#include "models/build_fabric.h"
#include "vcs/zcode_dev.h"
#include "platform/time_compat.h"

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

static bool map_root_field(struct json_value *row, const char *key,
                            const uint8_t root[32])
{
    char hex[65];
    zcl_hex_encode(root, 32, hex);
    return json_push_kv_str(row, key, hex);
}

/* Two displayed roots plus one successor probe. These are local index
 * observations, not candidate validation, a snapshot, or acceptance. */
static bool map_candidate_roots(struct json_value *row, struct node_db *ndb,
                                 const uint8_t task_root[32])
{
    char task[65], cursor[65] = "";
    zcl_hex_encode(task_root, 32, task);
    struct json_value roots, value;
    json_init(&roots); json_set_array(&roots);
    json_init(&value);
    int result = 0;
    bool ok = true;
    for (size_t i = 0; ok && i < 3; i++) {
        result = db_build_task_candidate_next(ndb, task, cursor, cursor);
        if (result <= 0 || i == 2) break;
        json_set_str(&value, cursor);
        ok = json_push_back(&roots, &value);
    }
    if (result < 0)
        ok = ok && json_push_kv_str(row, "candidate_resolution", "query_failed");
    else
        ok = ok && json_push_kv_str(row, "candidate_resolution", "local_index") &&
            json_push_kv(row, "candidate_roots", &roots) &&
            json_push_kv_bool(row, "candidate_more", result > 0);
    json_free(&value); json_free(&roots);
    return ok;
}

static bool map_candidate_metadata(struct json_value *row,
    const char *datadir, const uint8_t task_root[32])
{
    sqlite3 *db = NULL;
    struct node_db ndb = {0};
    enum zcl_node_db_ro_status status = ZCL_NODE_DB_RO_NO_DATADIR;
    if (datadir && datadir[0])
        status = zcl_native_node_db_open_readonly(datadir, &db, &ndb, NULL, 0);
    bool ok = json_push_kv_int(row, "candidate_ledger_status", status);
    if (status == ZCL_NODE_DB_RO_OK)
        ok = ok && map_candidate_roots(row, &ndb, task_root);
    else
        ok = ok && json_push_kv_str(row, "candidate_resolution", "unobserved");
    zcl_native_node_db_close_readonly(&db, &ndb);
    return ok;
}

static bool map_task_read(const char *workspace, const uint8_t root[32],
                          struct vcs_zcode_task_v1 *task)
{
    uint8_t *wire = NULL, checked[32];
    size_t length = 0;
    bool verified = vcs_object_load_raw_bounded(workspace, root,
        VCS_ZCODE_TASK_WIRE_BYTES, &wire, &length) == 0 &&
        vcs_zcode_task_parse(wire, length, task) == VCS_ZCODE_DEV_OK &&
        vcs_zcode_task_root(task, checked) == VCS_ZCODE_DEV_OK &&
        memcmp(root, checked, 32) == 0;
    free(wire);
    return verified;
}

static bool map_task_metadata(struct json_value *row,
    const char *workspace, const char *datadir, const uint8_t root[32], int64_t now)
{
    struct vcs_zcode_task_v1 task;
    if (!map_task_read(workspace, root, &task))
        return json_push_kv_str(row, "task_resolution", "unobserved");
    return json_push_kv_str(row, "task_resolution", "verified") &&
        map_root_field(row, "source_root", task.source_root) &&
        map_root_field(row, "goal_root", task.goal_root) &&
        map_root_field(row, "acceptance_tests_root", task.acceptance_tests_root) &&
        map_root_field(row, "proof_policy_root", task.proof_policy_root) &&
        map_candidate_metadata(row, datadir, root) &&
        json_push_kv_str(row, "review_resolution", "unobserved") &&
        json_push_kv_bool(row, "task_expired", now >= task.expires_unix);
}

static bool map_row(struct json_value *rows,
                    const struct zcl_work_map_node *node, size_t index,
                    const char *workspace, const char *datadir, int64_t now)
{
    struct json_value row;
    json_init(&row); json_set_object(&row);
    char root[65];
    zcl_hex_encode(node->task_root, 32, root);
    const char *kind = node->kind == ZCL_WORK_MAP_LOOP ? "loop" :
        node->kind == ZCL_WORK_MAP_FEATURE ? "feature" : "milestone";
    bool ok = map_dependencies(&row, node) &&
        map_task_metadata(&row, workspace, datadir, node->task_root, now) &&
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

static bool map_observation(struct json_value *data, int64_t now)
{
    return json_push_kv_str(data, "definition_coverage", "complete") &&
        json_push_kv_str(data, "acceptance_coverage", "unobserved") &&
        json_push_kv_int(data, "observed_unix", now) &&
        json_push_kv_str(data, "task_resolution_scope", "requested_page");
}

struct map_selection {
    const char *action_id;
    size_t node_index;
};

static bool map_selection_parse(const struct json_value *input, size_t count,
                                 struct map_selection *selection)
{
    const struct json_value *action = json_get(input, "action_id");
    const struct json_value *node = json_get(input, "node_index");
    *selection = (struct map_selection){0};
    if (!action && !node) return true;
    if (!action || action->type != JSON_STR || !node) return false;
    selection->action_id = json_get_str(action);
    uint8_t root[32];
    return zcl_hex_decode_lower(selection->action_id, root, 32) &&
        map_page_number(input, "node_index", 0, ZCL_WORK_MAP_MAX_NODES,
                        &selection->node_index) && selection->node_index < count;
}

static struct zcl_result map_selected_read(struct node_db *ndb,
    const char *workspace, const struct zcl_work_map_node *node,
    const char *action_id, int64_t now, struct db_build_action *action,
    struct build_fabric_proof_evaluation *evaluation)
{
    struct vcs_zcode_task_v1 task;
    if (!map_task_read(workspace, node->task_root, &task))
        return ZCL_ERR(-1, "selected task CAS object is unavailable or corrupt");
    if (now >= task.expires_unix)
        return ZCL_ERR(-1, "selected task is expired");
    if (!db_build_action_find(ndb, action_id, action))
        return ZCL_ERR(-1, "selected action is unavailable");
    char task_root[65], policy_root[65];
    zcl_hex_encode(node->task_root, 32, task_root);
    zcl_hex_encode(task.proof_policy_root, 32, policy_root);
    return zcl_native_work_map_evaluate(ndb, workspace, task_root,
        action->candidate_root_sha3, policy_root, action_id, now, evaluation);
}

static bool map_selected_facts(struct json_value *observed,
    const struct db_build_action *action,
    const struct build_fabric_proof_evaluation *evaluation)
{
    return json_push_kv_str(observed, "evidence_resolution", "evaluated") &&
        json_push_kv_str(observed, "action_root", action->action_id) &&
        json_push_kv_str(observed, "candidate_root", action->candidate_root_sha3) &&
        json_push_kv_str(observed, "proof_policy_root", action->proof_policy_root_sha3) &&
        json_push_kv_bool(observed, "policy_satisfied", evaluation->policy_satisfied) &&
        json_push_kv_int(observed, "valid_receipts", evaluation->valid_receipts) &&
        json_push_kv_str(observed, "derived_proof_set_root", evaluation->proof_set_root_sha3) &&
        json_push_kv_str(observed, "proof_set_retention", "unobserved");
}

static bool map_selected_observation(struct json_value *data,
    const char *workspace, const char *datadir,
    const struct zcl_work_map_node *nodes, const struct map_selection *selection,
    int64_t now)
{
    if (!selection->action_id) return true;
    sqlite3 *db = NULL;
    struct node_db ndb = {0};
    struct db_build_action action = {0};
    struct build_fabric_proof_evaluation evaluation = {0};
    enum zcl_node_db_ro_status status = ZCL_NODE_DB_RO_NO_DATADIR;
    if (datadir && datadir[0])
        status = zcl_native_node_db_open_readonly(datadir, &db, &ndb, NULL, 0);
    struct zcl_result result = status == ZCL_NODE_DB_RO_OK
        ? map_selected_read(&ndb, workspace, &nodes[selection->node_index],
            selection->action_id, now, &action, &evaluation)
        : ZCL_ERR(-1, "selected evidence ledger is unavailable");
    zcl_native_node_db_close_readonly(&db, &ndb);
    struct json_value observed;
    json_init(&observed); json_set_object(&observed);
    bool ok = json_push_kv_int(&observed, "node_index", (int64_t)selection->node_index) &&
        json_push_kv_str(&observed, "observation_scope", "selected_action") &&
        json_push_kv_int(&observed, "observed_unix", now) &&
        json_push_kv_bool(&observed, "acceptance_qualified", false);
    if (result.ok)
        ok = ok && map_selected_facts(&observed, &action, &evaluation);
    else
        ok = ok && json_push_kv_str(&observed, "evidence_resolution", "unavailable") &&
            json_push_kv_str(&observed, "reason", result.message);
    ok = ok && json_push_kv(data, "selected_evidence", &observed);
    json_free(&observed);
    return ok;
}

static bool map_page_fit(struct json_value *data, const struct json_value *base,
    const struct json_value *rows, size_t offset, size_t count)
{
    size_t returned = json_size(rows);
    for (;;) {
        json_set_object(data);
        bool ok = true;
        for (size_t i = 0; ok && i < json_size(base); i++)
            ok = json_push_kv(data, base->keys[i], &base->children[i]);
        struct json_value page;
        json_init(&page); json_set_array(&page);
        for (size_t i = 0; ok && i < returned; i++)
            ok = json_push_back(&page, json_at(rows, i));
        size_t end = offset + returned;
        ok = ok && json_push_kv_int(data, "returned", (int64_t)returned) &&
            json_push_kv_int(data, "next_offset", end < count ? (int64_t)end : -1) &&
            json_push_kv(data, "nodes", &page);
        json_free(&page);
        if (!ok) return false;
        if (json_write(data, NULL, 0) < 4096) return true;
        if (returned <= 1) return false;
        returned--;
    }
}

static bool map_render(struct zcl_command_reply *reply, const char *root,
                        const char *workspace, const char *datadir,
                        const struct zcl_work_map_node *nodes, size_t count,
                        size_t offset, size_t limit, const struct map_selection *selection)
{
    int64_t now = platform_time_wall_unix();
    struct json_value rows, base;
    json_init(&rows); json_set_array(&rows);
    json_init(&base); json_set_object(&base);
    size_t end = offset + limit;
    if (end > count) end = count;
    bool ok = true;
    for (size_t i = offset; ok && i < end; i++)
        ok = map_row(&rows, &nodes[i], i, workspace, datadir, now);
    ok = ok && json_push_kv_str(&base, "map_root", root) &&
        json_push_kv_int(&base, "total", (int64_t)count) &&
        map_observation(&base, now) &&
        map_selected_observation(&base, workspace, datadir, nodes, selection, now) &&
        map_page_fit(&reply->data, &base, &rows, offset, count);
    json_free(&base);
    json_free(&rows);
    return ok;
}

static bool map_input_paths(const struct json_value *input,
                            const char **workspace, const char **datadir)
{
    const struct json_value *w = json_get(input, "workspace");
    const struct json_value *d = json_get(input, "proof_datadir");
    if ((w && w->type != JSON_STR) || (d && d->type != JSON_STR))
        return false;
    *workspace = json_get_str(w);
    *datadir = json_get_str(d);
    if (!*workspace || !(*workspace)[0]) *workspace = ".";
    return true;
}

void zcl_native_handle_zcode_work_map(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    if (!request || !reply) return;
    const char *workspace, *datadir;
    if (!map_input_paths(request->input, &workspace, &datadir)) {
        map_fail(reply, "WORK_MAP_INPUT", "workspace and proof_datadir must be strings");
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
        workspace, address, nodes,
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
    struct map_selection selection;
    if (!map_selection_parse(request->input, count, &selection)) {
        map_fail(reply, "WORK_MAP_INPUT", "action_id and in-range node_index must be supplied together");
        return;
    }
    if (!map_render(reply, root, workspace, datadir,
                    nodes, count, offset, limit, &selection)) {
        json_set_object(&reply->data);
        map_fail(reply, "WORK_MAP_OUTPUT", "bounded map page could not be rendered");
    }
}
