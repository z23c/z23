/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: ZCODE dev-loop read views — the rebuilt CAS task index
 * (zcode.tasks), the expert-lane promotion shortcut (zcode.accept), and the
 * exact async-proof evidence evaluation (zcode.evidence) — sharing the
 * canonical-root and ledger primitives declared by native_zcode_dev_priv.h. */

#include "command/native_command.h"
#include "command/native_zcode_dev_priv.h"

#include "controllers/rpc_client.h"
#include "base/hex.h"
#include "base/serialize_le.h"
#include "crypto/sha3.h"
#include "config/runtime.h"
#include "config/command_catalog.h"
#include "hotswap/hotswap_service.h"
#include "json/json.h"
#include "models/database.h"
#include "models/database_owner_lease.h"
#include "platform/directory_compat.h"
#include "platform/directory_transaction.h"
#include "platform/positioned_file.h"
#include "platform/private_directory.h"
#include "platform/private_file.h"
#include "platform/rng.h"
#include "platform/time_compat.h"
#include "services/build_fabric_service.h"
#include "services/build_fabric_async.h"
#include "services/build_fabric_worker.h"
#include "services/zcode_agent_context_service.h"
#include "services/zcode_lane_service.h"
#include "services/zcode_lane_view_service.h"
#include "util/log_macros.h"
#include "util/safe_alloc.h"
#include "vcs/build_action.h"
#include "vcs/build_artifact_manifest.h"
#include "vcs/package_accept.h"
#include "vcs/package_index.h"
#include "vcs/vcs.h"
#include "vcs/vcs_object.h"
#include "vcs/zcode_dev.h"
#include "vcs/zcode_lane.h"
#include "vcs/package_manifest.h"
#include "vcs/package_mapping.h"
#include "vcs/package_deps.h"
#include "vcs/package_recipe.h"
#include "vcs/package_store.h"
#include "vcs/source_package_transport.h"
#include "vcs/vcs_devloop.h"
#include "vcs/zcode_work_context.h"
#include "vcs/zcode_work_node.h"
#include "vcs/zcode_action_input.h"
#include "vcs/zcode_write_scope.h"
#include "vcs/zcode_patch.h"
#include "vcs/zcode_candidate_bundle.h"
#include "vcs/zcode_task_authority.h"
#include "vcs/zcode_task_authority_bundle.h"
#include "vcs/zcode_task_index.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#if !defined(_WIN32)
#include <sys/stat.h>
#include <unistd.h>
#endif

#define ZDEV_TASKS_MAX_ROWS 3
#define ZDEV_TASKS_DETAIL_CANDIDATES 4
#define ZDEV_TASKS_DETAIL_SCOPE_PATHS 16
#define ZDEV_TASKS_DETAIL_SCOPE_JSON_BYTES 2048
#define ZDEV_TASKS_MULTIROW_WORKSPACE_MAX 256
#define ZDEV_TASKS_WORKSPACE_JSON_MAX 1024

static size_t zdev_json_escaped_size(const char *value)
{
    size_t size = 0;
    for (const unsigned char *p = (const unsigned char *)value; *p; p++) {
        if (*p == '"' || *p == '\\')
            size += 2;
        else if (*p <= 0x1f)
            size += 6;
        else
            size++;
    }
    return size;
}

static void zdev_task_safe_next(struct json_value *parent,
                                const char *workspace,
                                const char *task_root)
{
    struct json_value next;
    struct json_value next_args;
    json_init(&next);
    json_init(&next_args);
    json_set_object(&next);
    json_set_object(&next_args);
    (void)json_push_kv_str(&next, "command", "zcode.work.status");
    (void)json_push_kv_str(&next_args, "workspace", workspace);
    (void)json_push_kv_str(&next_args, "work", task_root);
    (void)json_push_kv(&next, "input", &next_args);
    (void)json_push_kv(parent, "safe_next", &next);
    json_free(&next_args);
    json_free(&next);
}

/* The non-detail summary fields every rendered row always carries. */
static void zdev_task_row_summary(
    struct json_value *row, const struct vcs_zcode_task_index_entry *e,
    const char *workspace)
{
    char work_id[32];
    (void)snprintf(work_id, sizeof(work_id), "work-%.12s",
                   e->task_root_hex);
    const char *blocker_class = "none_from_cas";
    if (e->expired)
        blocker_class = "expired";
    else if (strcmp(e->state, VCS_ZCODE_TASK_STATE_REPAIR_NEEDED) == 0)
        blocker_class = "repair_needed";
    json_set_object(row);
    (void)json_push_kv_str(row, "work_id", work_id);
    (void)json_push_kv_str(row, "task_root", e->task_root_hex);
    (void)json_push_kv_str(row, "source_root", e->source_root_hex);
    (void)json_push_kv_str(row, "write_scope_root",
                           e->write_scope_root_hex);
    (void)json_push_kv_str(row, "latest_candidate_source_root",
                           e->latest_candidate_source_root_hex);
    (void)json_push_kv_str(row, "latest_patch_root",
                           e->latest_patch_root_hex);
    (void)json_push_kv_int(row, "expires_unix", e->expires_unix);
    (void)json_push_kv_bool(row, "expired", e->expired);
    (void)json_push_kv_str(row, "state", e->state);
    (void)json_push_kv_int(row, "candidate_count",
                           (int64_t)e->candidate_count);
    (void)json_push_kv_int(row, "receipt_count",
                           (int64_t)e->receipt_count);
    (void)json_push_kv_int(row, "passing_receipt_count",
                           (int64_t)e->passing_receipt_count);
    (void)json_push_kv_int(row, "review_count",
                           (int64_t)e->review_count);
    (void)json_push_kv_str(row, "assignment_status", "UNOBSERVED");
    (void)json_push_kv_str(row, "active_execution", "UNOBSERVED");
    (void)json_push_kv_str(row, "blocker_class", blocker_class);
    zdev_task_safe_next(row, workspace, e->task_root_hex);
}

/* The bounded, paginated claimed-write-path list for one detail row. */
/* Render up to the bounded page of claimed paths starting at scope_offset,
 * returning how many were rendered. */
static size_t zdev_task_row_claimed_paths_page(
    struct json_value *claimed_paths,
    const struct vcs_zcode_write_scope_v1 *scope, size_t scope_offset)
{
    size_t claimed_rendered = 0;
    size_t claimed_json_bytes = 0;
    if (!scope) return 0;
    for (size_t i = scope_offset; i < scope->count; i++) {
        size_t path_bytes = zdev_json_escaped_size(scope->paths[i]);
        if (claimed_rendered >= ZDEV_TASKS_DETAIL_SCOPE_PATHS ||
            path_bytes > ZDEV_TASKS_DETAIL_SCOPE_JSON_BYTES -
                claimed_json_bytes)
            break;
        struct json_value path;
        json_init(&path);
        json_set_str(&path, scope->paths[i]);
        (void)json_push_back(claimed_paths, &path);
        json_free(&path);
        claimed_rendered++;
        claimed_json_bytes += path_bytes;
    }
    return claimed_rendered;
}

/* Render the claimed_write_paths_next continuation once more paths remain
 * beyond this rendered page. */
static void zdev_task_row_claimed_paths_next(
    struct json_value *row, const char *workspace,
    const struct vcs_zcode_task_index_entry *e, size_t claimed_end)
{
    struct json_value next, input;
    json_init(&next); json_set_object(&next);
    json_init(&input); json_set_object(&input);
    (void)json_push_kv_str(&next, "command", "zcode.tasks");
    (void)json_push_kv_str(&input, "workspace", workspace);
    (void)json_push_kv_str(&input, "task_root", e->task_root_hex);
    (void)json_push_kv_bool(&input, "details", true);
    (void)json_push_kv_int(&input, "scope_offset", (int64_t)claimed_end);
    (void)json_push_kv(&next, "input", &input);
    (void)json_push_kv(row, "claimed_write_paths_next", &next);
    json_free(&input); json_free(&next);
}

static void zdev_task_row_claimed_paths(
    struct json_value *row, const char *workspace,
    const struct vcs_zcode_task_index_entry *e,
    const struct vcs_zcode_write_scope_v1 *scope, size_t scope_offset)
{
    struct json_value claimed_paths;
    json_init(&claimed_paths);
    json_set_array(&claimed_paths);
    size_t claimed_rendered =
        zdev_task_row_claimed_paths_page(&claimed_paths, scope, scope_offset);
    (void)json_push_kv(row, "claimed_write_paths", &claimed_paths);
    (void)json_push_kv_int(row, "claimed_write_paths_total",
                           scope ? (int64_t)scope->count : 0);
    (void)json_push_kv_int(row, "claimed_write_paths_rendered",
                           (int64_t)claimed_rendered);
    (void)json_push_kv_int(row, "claimed_write_paths_offset",
                           (int64_t)scope_offset);
    size_t claimed_end = scope_offset + claimed_rendered;
    bool more = scope && claimed_end < scope->count;
    (void)json_push_kv_bool(row, "claimed_write_paths_truncated",
                            scope && (scope_offset > 0 || more));
    (void)json_push_kv_int(row, "claimed_write_paths_next_offset",
                           more ? (int64_t)claimed_end : -1);
    if (more)
        zdev_task_row_claimed_paths_next(row, workspace, e, claimed_end);
    json_free(&claimed_paths);
}

/* The bounded candidate list for one detail row. */
static void zdev_task_row_candidates(
    struct json_value *row, const struct vcs_zcode_task_index *index,
    const struct vcs_zcode_task_index_entry *e)
{
    struct json_value candidates;
    json_init(&candidates);
    json_set_array(&candidates);
    size_t candidate_items = 0;
    size_t task_candidates = 0;
    for (size_t c = 0; c < vcs_zcode_task_index_candidate_count(index); c++) {
        const struct vcs_zcode_task_candidate_entry *candidate =
            vcs_zcode_task_index_candidate_at(index, c);
        if (strcmp(candidate->task_root_hex, e->task_root_hex) != 0)
            continue;
        task_candidates++;
        if (candidate_items >= ZDEV_TASKS_DETAIL_CANDIDATES)
            continue;
        struct json_value entry;
        json_init(&entry);
        json_set_object(&entry);
        (void)json_push_kv_str(&entry, "candidate_root",
                               candidate->candidate_root_hex);
        (void)json_push_kv_str(&entry, "author_pubkey",
                               candidate->author_pubkey_hex);
        (void)json_push_kv_int(&entry, "sequence",
                               (int64_t)candidate->sequence);
        (void)json_push_kv_int(&entry, "created_unix",
                               candidate->created_unix);
        (void)json_push_back(&candidates, &entry);
        json_free(&entry);
        candidate_items++;
    }
    (void)json_push_kv(row, "candidates", &candidates);
    (void)json_push_kv_bool(row, "candidate_items_truncated",
                            task_candidates > candidate_items);
    json_free(&candidates);
}

/* The extra fields only a details=true single-row response carries. */
static void zdev_task_row_detail(
    struct json_value *row, const struct vcs_zcode_task_index *index,
    const struct vcs_zcode_task_index_entry *e, const char *workspace,
    const struct vcs_zcode_write_scope_v1 *scope, size_t scope_offset)
{
    bool context_ambiguous = false;
    const struct vcs_zcode_task_context_entry *context =
        vcs_zcode_task_index_context_for_task(
            index, e->task_root_hex, &context_ambiguous);
    (void)json_push_kv_str(row, "latest_candidate_root",
                           e->latest_candidate_root_hex);
    (void)json_push_kv_str(row, "agent_context_root",
                           context ? context->context_root_hex : "");
    (void)json_push_kv_bool(row, "agent_context_ambiguous",
                            context_ambiguous);
    (void)json_push_kv_str(row, "latest_receipt_action_root",
                           e->latest_action_root_hex);
    (void)json_push_kv_str(row, "latest_work_receipt_root",
                           e->latest_work_receipt_hex);
    (void)json_push_kv_str(row, "latest_lane_proof_set_root",
                           e->latest_proof_set_root_hex);
    (void)json_push_kv_str(row, "latest_lane_receipt_root",
                           e->latest_lane_receipt_hex);
    (void)json_push_kv_str(row, "goal_root", e->goal_root_hex);
    (void)json_push_kv_str(row, "proof_policy_root",
                           e->proof_policy_root_hex);
    (void)json_push_kv_str(row, "toolchain_capsule_root",
                           e->toolchain_capsule_root_hex);
    zdev_task_row_claimed_paths(row, workspace, e, scope, scope_offset);
    (void)json_push_kv_int(row, "app_run_receipt_count",
                           (int64_t)e->app_run_receipt_count);
    zdev_task_row_candidates(row, index, e);
}

static void zdev_task_row_json(struct json_value *row,
                               const struct vcs_zcode_task_index *index,
                               const struct vcs_zcode_task_index_entry *e,
                               const char *workspace, bool details,
                               const struct vcs_zcode_write_scope_v1 *scope,
                               size_t scope_offset)
{
    zdev_task_row_summary(row, e, workspace);
    if (!details) return;
    zdev_task_row_detail(row, index, e, workspace, scope, scope_offset);
}

static bool zdev_tasks_validate_workspace(
    const struct zcl_command_request *request, char workspace[ZDEV_PATH_MAX],
    struct zcl_command_reply *reply)
{
    const char *workspace_arg = zdev_str(request->input, "workspace");
    if (!workspace_arg || !platform_directory_canonical_real(
            workspace_arg, workspace, ZDEV_PATH_MAX)) {
        zcl_command_reply_fail(
            reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INVALID,
            "BAD_WORKSPACE", "validate", false, false,
            "workspace must resolve to an existing directory", "zcode.tasks");
        return false;
    }
    if (zdev_json_escaped_size(workspace) > ZDEV_TASKS_WORKSPACE_JSON_MAX) {
        zcl_command_reply_fail(
            reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INVALID,
            "WORKSPACE_RESPONSE_BOUND", "validate", false, false,
            "the canonical workspace path is too large for a bounded task view",
            "zcode.tasks");
        return false;
    }
    return true;
}

/* Normalize details/scope_offset/limit, refusing incompatible combinations. */
static bool zdev_tasks_parse_options(
    const struct zcl_command_request *request, size_t workspace_json_size,
    bool *details, int64_t *scope_offset, int64_t *limit,
    struct zcl_command_reply *reply)
{
    *details = json_get_bool(json_get(request->input, "details"));
    const struct json_value *scope_offset_value =
        json_get(request->input, "scope_offset");
    *scope_offset = zdev_int(request->input, "scope_offset", 0);
    if ((scope_offset_value && !*details) || *scope_offset < 0 ||
        *scope_offset >= VCS_ZCODE_WRITE_SCOPE_MAX_PATHS) {
        zcl_command_reply_fail(
            reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INVALID,
            "BAD_SCOPE_OFFSET", "validate", false, false,
            "scope_offset requires details=true and must be in 0..63",
            "zcode.tasks");
        return false;
    }
    *limit = zdev_int(request->input, "limit", ZDEV_TASKS_MAX_ROWS);
    if (*limit < 1) *limit = 1;
    if (*limit > ZDEV_TASKS_MAX_ROWS) *limit = ZDEV_TASKS_MAX_ROWS;
    if (*details && *limit > 1) *limit = 1;
    if (workspace_json_size > ZDEV_TASKS_MULTIROW_WORKSPACE_MAX && *limit > 1)
        *limit = 1;
    return true;
}

/* Loads and validates the exact write scope a single detail row claims, so
 * its claimed-path pagination can offset into real CAS bytes. */
static bool zdev_tasks_load_detail_scope(
    const char *workspace, const struct vcs_zcode_task_index_entry *row,
    int64_t scope_offset, struct vcs_zcode_write_scope_v1 *out,
    struct vcs_zcode_task_index *index, struct zcl_command_reply *reply)
{
    uint8_t scope_root_bytes[32];
    if (!zcl_hex_decode_lower(row->write_scope_root_hex, scope_root_bytes,
                              sizeof(scope_root_bytes)) ||
        !zdev_load_write_scope(workspace, scope_root_bytes, out)) {
        char scope_root[65];
        (void)snprintf(scope_root, sizeof(scope_root), "%s",
                       row->write_scope_root_hex);
        vcs_zcode_task_index_free(index);
        zcl_command_reply_fail(
            reply, ZCL_COMMAND_STATUS_BLOCKED, ZCL_COMMAND_EXIT_BLOCKED,
            "TASK_SCOPE_INCOMPLETE", "coordinate", false, false,
            "the task's exact write-scope object is absent, corrupt, or no longer agrees with its CAS root",
            scope_root);
        return false;
    }
    if ((size_t)scope_offset >= out->count) {
        vcs_zcode_task_index_free(index);
        zcl_command_reply_fail(
            reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INVALID,
            "BAD_SCOPE_OFFSET", "validate", false, false,
            "scope_offset must select an existing claimed path",
            "zcode.tasks");
        return false;
    }
    return true;
}

/* Resolve the single-row detail scope (if a detail row was requested) and
 * render every matched row into the caller's array. */
static bool zdev_tasks_render_rows(
    struct vcs_zcode_task_index *index,
    const struct vcs_zcode_task_index_entry **rows, size_t rendered,
    const char *workspace, bool details, int64_t scope_offset,
    struct json_value *arr, struct zcl_command_reply *reply)
{
    struct vcs_zcode_write_scope_v1 detail_scope;
    const struct vcs_zcode_write_scope_v1 *detail_scope_ptr = NULL;
    if (details && rendered == 1) {
        if (!zdev_tasks_load_detail_scope(
                workspace, rows[0], scope_offset, &detail_scope, index,
                reply))
            return false;
        detail_scope_ptr = &detail_scope;
    }
    json_init(arr);
    json_set_array(arr);
    for (size_t i = 0; i < rendered; i++) {
        struct json_value row;
        json_init(&row);
        zdev_task_row_json(&row, index, rows[i], workspace, details,
                           details ? detail_scope_ptr : NULL,
                           (size_t)scope_offset);
        (void)json_push_back(arr, &row);
        json_free(&row);
    }
    return true;
}

static void zdev_tasks_render_summary(
    struct zcl_command_reply *reply, const struct vcs_zcode_task_index *index,
    size_t total, size_t rendered, int64_t limit, bool details)
{
    (void)json_push_kv_int(&reply->data, "total_matches", (int64_t)total);
    (void)json_push_kv_int(&reply->data, "rendered", (int64_t)rendered);
    (void)json_push_kv_bool(&reply->data, "items_truncated", total > rendered);
    (void)json_push_kv_int(&reply->data, "tasks_scanned",
                           (int64_t)vcs_zcode_task_index_task_count(index));
    (void)json_push_kv_int(&reply->data, "candidates_scanned",
                           (int64_t)vcs_zcode_task_index_candidate_count(index));
    (void)json_push_kv_int(&reply->data, "limit", limit);
    (void)json_push_kv_bool(&reply->data, "details", details);
    (void)json_push_kv_str(&reply->data, "authority",
                           "REBUILT_CAS_TASK_PROJECTION");
    if (total == 0)
        (void)zcl_command_reply_add_next(
            reply, "discover.describe", "{\"path\":\"zcode.work.start\"}",
            "No matching task; inspect the required work-start input.");
}

void zcl_native_handle_zcode_tasks(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    if (!request || !reply) return;
    char workspace[ZDEV_PATH_MAX];
    if (!zdev_tasks_validate_workspace(request, workspace, reply))
        return;
    bool details; int64_t scope_offset, limit;
    if (!zdev_tasks_parse_options(
            request, zdev_json_escaped_size(workspace), &details,
            &scope_offset, &limit, reply))
        return;
    struct vcs_zcode_task_index *index = vcs_zcode_task_index_build(
        workspace, (int64_t)platform_time_wall_unix());
    if (!index) {
        zcl_command_reply_fail(
            reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INTERNAL,
            "INDEX_BUILD", "execute", false, false,
            "the dev-task index could not be built from the workspace CAS",
            "zcode.tasks");
        return;
    }
    struct vcs_zcode_task_search search = {
        .task_root = zdev_str(request->input, "task_root"),
        .source_root = zdev_str(request->input, "source_root"),
        .author = zdev_str(request->input, "author"),
        .state = zdev_str(request->input, "state"),
    };
    const struct vcs_zcode_task_index_entry *rows[ZDEV_TASKS_MAX_ROWS];
    size_t total = vcs_zcode_task_index_search(index, &search, rows,
                                               (size_t)limit);
    size_t rendered = total < (size_t)limit ? total : (size_t)limit;
    struct json_value arr;
    if (!zdev_tasks_render_rows(index, rows, rendered, workspace, details,
                               scope_offset, &arr, reply))
        return;
    (void)json_push_kv(&reply->data, "tasks", &arr);
    json_free(&arr);
    zdev_tasks_render_summary(reply, index, total, rendered, limit, details);
    vcs_zcode_task_index_free(index);
}

/* Validate accept input and resolve the requested lane target. */
static bool zdev_accept_validate_input(
    const struct zcl_command_request *request, char workspace[ZDEV_PATH_MAX],
    uint8_t action_root[32], int *target, struct zcl_command_reply *reply)
{
    const char *workspace_arg = zdev_str(request->input, "workspace");
    const char *action_id = zdev_str(request->input, "action_id");
    const char *lane = zdev_str(request->input, "lane");
    *target = lane && strcmp(lane, "CANDIDATE") == 0
        ? VCS_ZCODE_LANE_CANDIDATE : 0;
    if (!workspace_arg || !platform_directory_canonical_real(
            workspace_arg, workspace, ZDEV_PATH_MAX) ||
        !action_id || !zcl_hex_decode_lower(action_id, action_root, 32) ||
        !*target) {
        zcl_command_reply_fail(
            reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INVALID,
            "BAD_ACCEPT_INPUT", "validate", false, false,
            "workspace and action_id are required; the expert lane may only be CANDIDATE; use zcode work accept for human PROVEN acceptance",
            "zcode.accept");
        return false;
    }
    return true;
}

void zcl_native_handle_zcode_accept(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    if (!request || !reply) return;
    char workspace[ZDEV_PATH_MAX];
    uint8_t action_root[32];
    int target;
    if (!zdev_accept_validate_input(
            request, workspace, action_root, &target, reply))
        return;
    const char *action_id = zdev_str(request->input, "action_id");
    const char *datadir = zdev_str(request->input, "datadir");
    if (!datadir || !datadir[0]) datadir = zcl_native_command_datadir();
    struct node_db ndb = {0};
    if (!zdev_open_db(datadir, &ndb)) {
        zcl_command_reply_fail(
            reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_FAILED,
            "DATABASE_OPEN_FAILED", "accept", true, false,
            "the ZBuild ledger could not be opened", "zcode.accept");
        return;
    }
    struct db_build_worker signer;
    uint8_t secret[32], pubkey[32];
    struct zcl_result identity = build_fabric_worker_identity_load(
        datadir, &signer, secret, pubkey);
    struct zcode_lane_status status;
    struct zcl_result accepted = identity.ok
        ? zcode_lane_advance(&ndb, workspace, action_id, target,
              (int64_t)platform_time_wall_unix(), secret, pubkey, &status)
        : identity;
    memset(secret, 0, sizeof(secret));
    node_db_close(&ndb);
    if (!accepted.ok) {
        zcl_command_reply_fail(
            reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_FAILED,
            "LANE_PROMOTION_REFUSED", "accept", false, false,
            accepted.message, "zcode.accept");
        return;
    }
    zdev_push_lane(&reply->data, &status);
    (void)json_push_kv_str(&reply->data, "authority",
                           "OPERATOR_SIGNED_PROOF_POLICY");
}

/* Build the exact live-forwardable evidence-evaluation RPC parameters. */
static bool zdev_evidence_build_params(
    const char *workspace_arg, const char *datadir, const char *action_id,
    struct json_value *params)
{
    json_init(params); json_set_object(params);
    return workspace_arg && datadir && action_id &&
        json_push_kv_str(params, "workspace", workspace_arg) &&
        json_push_kv_str(params, "datadir", datadir) &&
        json_push_kv_str(params, "action_id", action_id);
}

/* Validate the local (non-forwarded) evidence request and open whichever
 * ledger (owned runtime handle, or a freshly opened one) it targets. */
static bool zdev_evidence_open(
    const char *workspace_arg, const char *datadir, const char *action_id,
    char workspace[ZDEV_PATH_MAX], struct node_db **ndb_out, bool *owned,
    struct node_db *local_ndb, struct zcl_command_reply *reply)
{
    uint8_t action_check[32];
    if (!workspace_arg || !platform_directory_canonical_real(
            workspace_arg, workspace, ZDEV_PATH_MAX) || !datadir ||
        !action_id || !zcl_hex_decode_lower(action_id, action_check, 32)) {
        zcl_command_reply_fail(
            reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INVALID,
            "BAD_EVIDENCE_INPUT", "validate", false, false,
            "workspace must resolve and action_id must be 64 lowercase hex",
            "zcode.evidence");
        return false;
    }
    char db_path[ZDEV_PATH_MAX];
    int n = snprintf(db_path, sizeof(db_path), "%s/node.db", datadir);
    *ndb_out = zdev_runtime_owns_ledger(datadir)
        ? app_runtime_node_db() : local_ndb;
    *owned = *ndb_out != local_ndb;
    if (n <= 0 || (size_t)n >= sizeof(db_path) ||
        (!*owned && !node_db_open_existing_runtime(
            *ndb_out, db_path, "zcode.evidence"))) {
        zcl_command_reply_fail(
            reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_FAILED,
            "DATABASE_OPEN_FAILED", "evaluate", true, false,
            "the ZBuild ledger could not be opened", "zcode.evidence");
        return false;
    }
    return true;
}

static void zdev_evidence_render_basic(
    struct zcl_command_reply *reply, const char *action_id,
    const struct build_fabric_proof_evaluation *evaluation)
{
    (void)json_push_kv_str(&reply->data, "action_id", action_id);
    (void)json_push_kv_int(&reply->data, "valid_receipts",
                           (int64_t)evaluation->valid_receipts);
    (void)json_push_kv_int(&reply->data, "approved_distinct_signers",
                           (int64_t)evaluation->approved_distinct_signers);
    (void)json_push_kv_int(&reply->data, "matching_receipts",
                           (int64_t)evaluation->matching_receipts);
    (void)json_push_kv_int(&reply->data, "compile_receipts",
                           (int64_t)evaluation->compile_receipts);
    (void)json_push_kv_int(&reply->data, "test_receipts",
                           (int64_t)evaluation->test_receipts);
    (void)json_push_kv_int(&reply->data, "fuzz_receipts",
                           (int64_t)evaluation->fuzz_receipts);
    (void)json_push_kv_int(&reply->data, "review_receipts",
                           (int64_t)evaluation->review_receipts);
    (void)json_push_kv_bool(&reply->data, "local_reproduced",
                            evaluation->local_reproduced);
    (void)json_push_kv_bool(&reply->data, "quorum_satisfied",
                            evaluation->quorum_satisfied);
    (void)json_push_kv_bool(&reply->data, "compile_satisfied",
                            evaluation->compile_satisfied);
    (void)json_push_kv_bool(&reply->data, "test_satisfied",
                            evaluation->test_satisfied);
    (void)json_push_kv_bool(&reply->data, "fuzz_satisfied",
                            evaluation->fuzz_satisfied);
    (void)json_push_kv_bool(&reply->data, "review_satisfied",
                            evaluation->review_satisfied);
    (void)json_push_kv_bool(&reply->data, "release_identity_satisfied",
                            evaluation->release_identity_satisfied);
    (void)json_push_kv_bool(&reply->data, "policy_satisfied",
                            evaluation->policy_satisfied);
    (void)json_push_kv_str(&reply->data, "output_root",
                           evaluation->output_root_sha3);
    (void)json_push_kv_str(&reply->data, "proof_set_root",
                           evaluation->proof_set_root_sha3);
    (void)json_push_kv_str(&reply->data, "authority",
        evaluation->local_reproduced ? "LOCAL_REPRODUCTION" :
        evaluation->quorum_satisfied ? "APPROVED_SIGNER_QUORUM" :
        "UNTRUSTED");
}

/* Renders one named async-proof-stage timing metric object. */
static bool zdev_evidence_render_metric(
    struct json_value *latency, const char *name,
    const struct build_fabric_timing_metric *metric)
{
    struct json_value out;
    json_init(&out); json_set_object(&out);
    bool ok = json_push_kv_int(&out, "measured_count",
                               (int64_t)metric->measured_count) &&
        json_push_kv_int(&out, "missing_count",
                         (int64_t)metric->missing_count) &&
        json_push_kv_int(&out, "min_us", metric->min_us) &&
        json_push_kv_int(&out, "max_us", metric->max_us) &&
        json_push_kv_int(&out, "mean_us", metric->mean_us) &&
        json_push_kv_int(&out, "p50_us", metric->p50_us) &&
        json_push_kv_int(&out, "p95_us", metric->p95_us) &&
        json_push_kv(latency, name, &out);
    json_free(&out);
    return ok;
}

/* Push the scalar (non-per-stage) latency fields; returns whether every
 * push succeeded. */
static bool zdev_evidence_render_latency_scalars(
    struct json_value *latency, const struct build_fabric_proof_timings *timings)
{
    return json_push_kv_int(
            latency, "local_submit_us", timings->local_submit_us) &&
        json_push_kv_int(latency, "peer_discovery_us",
                         timings->peer_discovery_us) &&
        json_push_kv_int(latency, "transfer_us", timings->transfer_us) &&
        json_push_kv_int(latency, "remote_queue_us",
                         timings->remote_queue_us) &&
        json_push_kv_int(latency, "remote_execution_us",
                         timings->remote_execution_us) &&
        json_push_kv_int(latency, "receipt_verification_us",
                         timings->receipt_verification_us) &&
        json_push_kv_int(latency, "total_background_proof_us",
                         timings->total_background_proof_us) &&
        json_push_kv_int(latency, "total_events",
                           (int64_t)timings->total_events) &&
        json_push_kv_int(latency, "failure_events",
                           (int64_t)timings->failure_events) &&
        json_push_kv_int(latency, "retry_events",
                           (int64_t)timings->retry_events);
}

static void zdev_evidence_render_latency(
    struct zcl_command_reply *reply,
    const struct build_fabric_proof_timings *timings)
{
    struct json_value latency;
    json_init(&latency); json_set_object(&latency);
    bool rendered = zdev_evidence_render_latency_scalars(&latency, timings);
    const struct build_fabric_timing_metric *ms[] = {
        &timings->metric_local_submit, &timings->metric_peer_discovery,
        &timings->metric_transfer, &timings->metric_remote_queue,
        &timings->metric_remote_execution,
        &timings->metric_receipt_verification,
        &timings->metric_total_background_proof};
    const char *mn[] = {"local_submit", "peer_discovery", "transfer",
        "remote_queue", "remote_execution", "receipt_verification",
        "total_background_proof"};
    for (size_t i = 0; rendered && i < sizeof(ms) / sizeof(ms[0]); i++)
        rendered = zdev_evidence_render_metric(&latency, mn[i], ms[i]);
    rendered = rendered && json_push_kv(&reply->data, "latency", &latency);
    json_free(&latency);
    if (!rendered)
        zdev_fail(reply, "TIMING_OUTPUT_FAILED",
                  "async proof timing report exceeded its bound");
}

void zcl_native_zcode_evidence_exact(
    const char *workspace_arg, const char *datadir_arg, const char *action_id,
    struct zcl_command_reply *reply)
{
    if (!reply) return;
    const char *datadir = datadir_arg;
    if (!datadir || !datadir[0]) datadir = zcl_native_command_datadir();
    struct json_value params;
    bool rendered = zdev_evidence_build_params(
        workspace_arg, datadir, action_id, &params);
    if (!rendered) {
        json_free(&params);
        zcl_command_reply_fail(
            reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INVALID,
            "BAD_EVIDENCE_INPUT", "validate", false, false,
            "workspace must resolve and action_id must be 64 lowercase hex",
            "zcode.evidence");
        return;
    }
    bool forwarded = zdev_forward_live_input(
            &params, datadir, "zcode_work_evidence",
            "LIVE_EVIDENCE_FAILED", "evaluate", "zcode.evidence", reply);
    json_free(&params);
    if (forwarded) return;
    char workspace[ZDEV_PATH_MAX];
    struct node_db local_ndb = {0}; struct node_db *ndb; bool owned;
    if (!zdev_evidence_open(workspace_arg, datadir, action_id, workspace,
                            &ndb, &owned, &local_ndb, reply))
        return;
    struct build_fabric_proof_evaluation evaluation;
    struct zcl_result result = build_fabric_proof_evaluate(
        ndb, workspace, action_id,
        (int64_t)platform_time_wall_unix(), &evaluation);
    struct build_fabric_proof_timings timings;
    struct zcl_result timed = build_fabric_proof_timings(
        ndb, action_id, &timings);
    if (!owned) node_db_close(ndb);
    if (!result.ok) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
            ZCL_COMMAND_EXIT_FAILED, "EVIDENCE_EVALUATION_FAILED",
            "evaluate", true, false, result.message, "zcode.evidence");
        return;
    }
    zdev_evidence_render_basic(reply, action_id, &evaluation);
    (void)json_push_kv_bool(&reply->data, "async_timings_available", timed.ok);
    if (timed.ok)
        zdev_evidence_render_latency(reply, &timings);
    else if (!json_push_kv_str(&reply->data, "async_timings_unavailable_reason",
                               timed.message))
        zdev_fail(reply, "TIMING_OUTPUT_FAILED",
                  "async proof timing refusal could not be rendered");
}
