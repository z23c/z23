/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: human-first orchestration over existing ZCODE development owners.
 * HOT_FORK strictly exercises caller-owned input normalization and byte totals. */

#include "base/checked.h"
#include "json/json.h"
#include "vcs/package_prepare.h"

#ifndef ZCL_HOTFORK_ZWORK_INPUT_CORE
#include "command/native_command.h"
#include "command/native_zcode_discovery.h"
#include "native_zcode_work_priv.h"

#include "base/cleanse.h"
#include "base/hex.h"
#include "base/log_macros.h"
#include "config/runtime.h"
#include "crypto/ed25519.h"
#include "hotswap/hotswap_service.h"
#include "models/build_fabric.h"
#include "models/build_proof_event.h"
#include "models/database.h"
#include "platform/directory_compat.h"
#include "platform/positioned_file.h"
#include "platform/private_directory.h"
#include "platform/state_root.h"
#include "platform/time_compat.h"
#include "services/build_fabric_service.h"
#include "services/build_fabric_worker.h"
#include "services/package_lifecycle.h"
#include "services/zcode_goal_context_calc_service.h"
#include "services/zcode_goal_context_service.h"
#include "services/zcode_lane_service.h"
#include "sha3/sha3.h"
#include "util/safe_alloc.h"
#include "util/file_tree_ops.h"
#include "vcs/package_recipe.h"
#include "vcs/package_index.h"
#include "vcs/package_manifest.h"
#include "vcs/package_publish.h"
#include "vcs/package_release.h"
#include "vcs/package_reuse.h"
#include "vcs/package_swarm_node.h"
#include "vcs/build_action.h"
#include "vcs/vcs.h"
#include "vcs/vcs_devloop.h"
#include "vcs/vcs_object.h"
#include "vcs/zcode_dev.h"
#include "vcs/zcode_dev_product.h"
#include "vcs/zcode_patch.h"
#include "vcs/zcode_task_index.h"
#include "vcs/zcode_work_swarm.h"
#endif

#include <stdio.h>
#include <string.h>
#ifndef ZCL_HOTFORK_ZWORK_INPUT_CORE
#include <limits.h>
#include <stdlib.h>
#if !defined(_WIN32)
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#endif
#endif

#ifdef ZCL_HOTFORK_ZWORK_INPUT_CORE
/* The HOT_FORK capsule compiles this translation unit by itself and never
 * sees the family's private header, so the shared input core is declared
 * here for that build alone. */
const char *zwork_str(const struct json_value *input, const char *key);
bool zwork_bool(const struct json_value *input, const char *key);
int64_t zwork_int(const struct json_value *input, const char *key,
                  int64_t fallback);
bool zwork_scopes(const struct vcs_package_prepared *prepared,
                  bool include_package_metadata, char out[1024]);
uint64_t zwork_source_bytes(const struct vcs_package_prepared *prepared);
#endif

#ifndef ZCL_HOTFORK_ZWORK_INPUT_CORE
bool zwork_task_path(char out[ZWORK_PATH_MAX], const char *task,
                     const char *suffix)
{
#if defined(_WIN32)
    char state[ZWORK_PATH_MAX];
    int n = platform_state_root(state, sizeof(state))
        ? snprintf(out, ZWORK_PATH_MAX, "%s/zcode-workspaces/%.64s%s",
                   state, task, suffix ? suffix : "") : -1;
#else
    int n = snprintf(out, ZWORK_PATH_MAX,
                     "/tmp/zclassic23-zcode-workspaces/%lu/%.64s%s",
                     (unsigned long)getuid(), task, suffix ? suffix : "");
#endif
    return n > 0 && n < ZWORK_PATH_MAX;
}

#endif

const char *zwork_str(const struct json_value *input, const char *key)
{
    const struct json_value *value = input ? json_get(input, key) : NULL;
    return value && value->type == JSON_STR ? json_get_str(value) : NULL;
}

bool zwork_bool(const struct json_value *input, const char *key)
{
    const struct json_value *value = input ? json_get(input, key) : NULL;
    return value && value->type == JSON_BOOL && json_get_bool(value);
}

#ifndef ZCL_HOTFORK_ZWORK_INPUT_CORE
bool zwork_open_build_ledger(
    struct node_db *ndb, const char *path, const char *reason,
    bool allow_create)
{
    if (!ndb || !path || !path[0] || !reason || !reason[0]) return false;
    struct platform_positioned_file existing;
    platform_positioned_file_init(&existing);
    bool present = platform_positioned_file_open(&existing, path);
    platform_positioned_file_close(&existing);
    if (present)
        return node_db_open_existing_runtime(ndb, path, reason);
    return allow_create && node_db_open(ndb, path);
}

struct node_db *zwork_runtime_ledger(const char *db_path)
{
    struct node_db *owned = app_runtime_node_db();
    return db_path && app_runtime_node_db_handle_open(owned) &&
           strcmp(db_path, owned->path) == 0
        ? owned : NULL;
}
#endif

int64_t zwork_int(
    const struct json_value *input, const char *key, int64_t fallback)
{
    const struct json_value *value = input ? json_get(input, key) : NULL;
    return value && value->type == JSON_INT ? json_get_int(value) : fallback;
}

#ifndef ZCL_HOTFORK_ZWORK_INPUT_CORE
void zwork_fail(struct zcl_command_reply *reply, const char *code,
                const char *phase, const char *detail, bool retryable,
                bool mutated)
{
    zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                           ZCL_COMMAND_EXIT_INVALID, code, phase, retryable,
                           mutated, detail, "zcode.work");
}

/* zcode.improve owns task-conflict classification and the exact CAS handoff.
 * The human-first wrapper may preserve only those two named coordination
 * refusals; every other planner failure keeps the ordinary compact error.
 * Round-tripping through a fixed buffer both preserves the exact data object
 * and prevents a future inner handler from expanding this exception into an
 * unbounded second response surface. */
bool zwork_coordination_handoff(
    const struct zcl_command_reply *inner, const char *expected_workspace,
    struct zcl_command_reply *reply)
{
    if (!inner || !reply || inner->status != ZCL_COMMAND_STATUS_BLOCKED ||
        inner->exit_code != ZCL_COMMAND_EXIT_BLOCKED ||
        inner->data.type != JSON_OBJ)
        return false;
    bool active = strcmp(inner->error.code, "ACTIVE_TASK_CONFLICT") == 0;
    bool incomplete = strcmp(inner->error.code,
                             "TASK_CONFLICT_SCAN_INCOMPLETE") == 0;
    const char *kind = json_get_str(json_get(&inner->data, "conflict_kind"));
    const char *assignment = json_get_str(json_get(
        &inner->data, "assignment_status"));
    const char *execution = json_get_str(json_get(
        &inner->data, "active_execution"));
    if ((!active && !incomplete) || !kind || !assignment || !execution ||
        strcmp(assignment, "UNOBSERVED") != 0 ||
        strcmp(execution, "UNOBSERVED") != 0 ||
        (incomplete && strcmp(kind, "INCOMPLETE") != 0) ||
        (active && strcmp(kind, "DUPLICATE_ACTIVE_WORK") != 0 &&
         strcmp(kind, "WRITE_SCOPE_OVERLAP") != 0))
        return false;

    const struct json_value *task_value = json_get(&inner->data, "task_root");
    const char *task_root = task_value && task_value->type == JSON_STR
        ? json_get_str(task_value) : NULL;
    uint8_t decoded_task_root[32];
    if ((active && (!task_root ||
                    !zcl_hex_decode_lower(task_root, decoded_task_root, 32u) ||
                    inner->next_count != 1u ||
                    strcmp(inner->next[0].command, "zcode.tasks") != 0)) ||
        (incomplete && ((task_root && task_root[0]) ||
                        inner->next_count != 0u)))
        return false;

    if (active) {
        struct json_value input;
        json_init(&input);
        bool typed = json_read(&input, inner->next[0].input_json,
                               strlen(inner->next[0].input_json));
        const char *next_task = typed
            ? json_get_str(json_get(&input, "task_root")) : NULL;
        const char *next_workspace = typed
            ? json_get_str(json_get(&input, "workspace")) : NULL;
        uint8_t decoded_next_task[32];
        typed = typed && input.type == JSON_OBJ &&
            input.num_children == 3u && next_task && next_workspace &&
            next_workspace[0] && expected_workspace &&
            strcmp(next_workspace, expected_workspace) == 0 &&
            zcl_hex_decode_lower(next_task, decoded_next_task, 32u) &&
            strcmp(next_task, task_root) == 0 &&
            json_get_bool(json_get(&input, "details"));
        json_free(&input);
        if (!typed)
            return false;
    }

    char data_wire[ZCL_COMMAND_ROOT_BUDGET];
    size_t data_len = json_write(&inner->data, data_wire, sizeof(data_wire));
    struct json_value exact;
    json_init(&exact);
    if (data_len == 0 || data_len >= sizeof(data_wire) ||
        !json_read(&exact, data_wire, data_len)) {
        json_free(&exact);
        return false;
    }
    json_free(&reply->data);
    reply->data = exact;
    reply->status = inner->status;
    reply->exit_code = inner->exit_code;
    reply->error = inner->error;
    return !active || zcl_command_reply_add_next(
        reply, inner->next[0].command, inner->next[0].input_json,
        inner->next[0].reason);
}

char *zwork_hex_alloc(const uint8_t *bytes, size_t len,
                      const char *label)
{
    if (!bytes || len > (SIZE_MAX - 1u) / 2u) return NULL;
    char *hex = zcl_malloc(len * 2u + 1u, label);
    if (hex) zcl_hex_encode(bytes, len, hex);
    return hex;
}

bool zwork_bind_accepted_publication(
    const char *workspace, const struct vcs_zcode_task_index_entry *entry,
    const struct zcl_command_reply *accepted_reply,
    char candidate_workspace[ZWORK_PATH_MAX],
    struct vcs_devloop_accepted_candidate_result *publication)
{
    if (!candidate_workspace || !publication) return false;
    candidate_workspace[0] = '\0';
    memset(publication, 0, sizeof(*publication));
    const struct json_value *accepted_value = accepted_reply
        ? json_get(&accepted_reply->data, "lane_receipt_root") : NULL;
    const char *accepted_hex = accepted_value &&
            accepted_value->type == JSON_STR
        ? json_get_str(accepted_value) : NULL;
    uint8_t accepted_root[32], source_root[32];
    if (!workspace || !entry || !accepted_hex ||
        entry->latest_candidate_sequence == 0 ||
        entry->latest_candidate_sequence > UINT32_MAX ||
        !zcl_hex_decode_lower(accepted_hex, accepted_root, 32) ||
        !zcl_hex_decode_lower(entry->latest_candidate_source_root_hex,
                              source_root, 32))
        return false;
    char candidate_path[ZWORK_PATH_MAX];
    char suffix[48];
    int n = snprintf(suffix, sizeof(suffix), "/attempt-%u",
                     (uint32_t)entry->latest_candidate_sequence);
    if (n <= 0 || (size_t)n >= sizeof(suffix) ||
        !zwork_task_path(candidate_path, entry->task_root_hex, suffix) ||
        !platform_directory_canonical_real(
            candidate_path, candidate_workspace, ZWORK_PATH_MAX))
        return false;
    vcs_devloop_publication_bind_accepted_candidate(
        workspace, candidate_workspace, accepted_root, source_root,
        platform_time_wall_unix(), publication);
    return publication->ok;
}
#endif

static bool zwork_scope_add(char out[1024], const char *path)
{
    if (!path || !path[0]) return false;
    const char *slash = strchr(path, '/');
    size_t len = slash ? (size_t)(slash - path) : strlen(path);
    if (len == 0 || len > 255) return false;
    char part[256];
    memcpy(part, path, len); part[len] = '\0';
    const char *at = out;
    while (*at) {
        const char *end = strchr(at, ',');
        size_t have = end ? (size_t)(end - at) : strlen(at);
        if (have == len && memcmp(at, part, len) == 0) return true;
        if (!end) break;
        at = end + 1;
    }
    size_t used = strlen(out);
    size_t need = len + (used ? 1u : 0u);
    if (need >= sizeof(char[1024]) - used) return false;
    if (used) out[used++] = ',';
    memcpy(out + used, part, len + 1u);
    return true;
}

static bool zwork_c23_path(const char *path)
{
    size_t len = path ? strlen(path) : 0;
    return len >= 2u && path[len - 2u] == '.' &&
           (path[len - 1u] == 'c' || path[len - 1u] == 'h');
}

static bool zwork_recipe_path(const struct vcs_package_recipe *recipe,
                              const char *path)
{
    const struct vcs_package_recipe_strings *lists[] = {
        &recipe->public_headers, &recipe->sources, &recipe->test_sources,
    };
    for (size_t i = 0; i < sizeof(lists) / sizeof(lists[0]); i++)
        for (size_t j = 0; j < lists[i]->count; j++)
            if (strcmp(lists[i]->items[j], path) == 0) return true;
    return false;
}

bool zwork_scopes(const struct vcs_package_prepared *prepared,
                  bool include_package_metadata, char out[1024])
{
    out[0] = '\0';
    const struct vcs_package_recipe_strings *lists[] = {
        &prepared->recipe.public_headers, &prepared->recipe.sources,
        &prepared->recipe.test_sources,
    };
    for (size_t i = 0; i < sizeof(lists) / sizeof(lists[0]); i++)
        for (size_t j = 0; j < lists[i]->count; j++)
            if (!zwork_scope_add(out, lists[i]->items[j])) return false;
    for (size_t i = 0; i < prepared->manifest.count; i++)
        if (zwork_c23_path(prepared->manifest.files[i].path) &&
            !zwork_scope_add(out, prepared->manifest.files[i].path))
            return false;
    if (include_package_metadata &&
        !zwork_scope_add(out, VCS_PACKAGE_DEPS_META_PATH)) return false;
    return out[0] != '\0';
}

uint64_t zwork_source_bytes(
    const struct vcs_package_prepared *prepared)
{
    uint64_t total = 0;
    for (size_t i = 0; i < prepared->manifest.count; i++) {
        const struct vcs_package_file *file = &prepared->manifest.files[i];
        if (!zwork_c23_path(file->path) &&
            !zwork_recipe_path(&prepared->recipe, file->path))
            continue;
        if (!zcl_u64_add(total, file->size, &total)) return 0;
    }
    return total;
}

#ifndef ZCL_HOTFORK_ZWORK_INPUT_CORE
bool zwork_regular_package_config(const char *workspace)
{
    char path[ZWORK_PATH_MAX];
    int n = snprintf(path, sizeof(path), "%s/%s", workspace,
                     VCS_PACKAGE_DEPS_META_PATH);
    if (n <= 0 || (size_t)n >= sizeof(path))
        return false;
    struct platform_positioned_file file;
    platform_positioned_file_init(&file);
    bool regular = platform_positioned_file_open(&file, path);
    platform_positioned_file_close(&file);
    return regular;
}

bool zwork_prepare(const char *workspace,
                   struct vcs_package_prepared *prepared,
                   char *detail, size_t detail_cap)
{
    static const uint8_t pubkey[33] = {
        0x02, 0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb,
        0xac, 0x55, 0xa0, 0x62, 0x95, 0xce, 0x87, 0x0b,
        0x07, 0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28,
        0xd9, 0x59, 0xf2, 0x81, 0x5b, 0x16, 0xf8, 0x17, 0x98,
    };
    struct vcs_package_prepare_options options = {
        .dir = workspace, .publisher_sequence = 1,
        .reward_address = "", .chain_id = "zclassic-main",
    };
    memcpy(options.publisher_pubkey, pubkey, sizeof(pubkey));
    return vcs_package_prepare(&options, prepared, detail, detail_cap) ==
           VCS_PACKAGE_PREPARE_OK;
}

bool zwork_read_bounded_regular(const char *path, size_t maximum,
                                uint8_t **out, size_t *out_len)
{
    if (!path || !out || !out_len || maximum == 0) {
        LOG_ERROR(ZWORK_LOG, "reuse read received invalid arguments");
        return false;
    }
    *out = NULL; *out_len = 0;
    struct platform_positioned_file file;
    struct platform_positioned_file_snapshot before, after;
    platform_positioned_file_init(&file);
    if (!platform_positioned_file_open(&file, path) ||
        !platform_positioned_file_snapshot(&file, &before) ||
        before.size == 0 || before.size > maximum) {
        LOG_ERROR(ZWORK_LOG, "reuse object is not one bounded regular file: %s",
                  path);
        platform_positioned_file_close(&file); return false;
    }
    size_t len = (size_t)before.size;
    uint8_t *bytes = zcl_malloc(len + 1u, "zcode.work.reuse_read");
    if (!bytes) { platform_positioned_file_close(&file); return false; }
    size_t off = 0;
    while (off < len) {
        int64_t n = platform_positioned_file_read(
            &file, bytes + off, len - off, off);
        if (n <= 0) {
            LOG_ERROR(ZWORK_LOG, "reuse object read failed: %s", path);
            free(bytes); platform_positioned_file_close(&file); return false;
        }
        off += (size_t)n;
    }
    if (!platform_positioned_file_snapshot(&file, &after) ||
        !platform_positioned_file_snapshot_equal(&before, &after)) {
        LOG_ERROR(ZWORK_LOG, "reuse object changed while read: %s", path);
        platform_positioned_file_close(&file);
        free(bytes); return false;
    }
    platform_positioned_file_close(&file);
    bytes[len] = 0; *out = bytes; *out_len = len; return true;
}

bool zwork_add_next(struct zcl_command_reply *reply,
                    const char *command,
                    const struct json_value *input,
                    const char *reason)
{
    char wire[sizeof(reply->next[0].input_json)];
    size_t n = input ? json_write(input, wire, sizeof(wire)) : 0;
    return n > 0 && n < sizeof(wire) &&
        zcl_command_reply_add_next(reply, command, wire, reason);
}

void zcl_native_handle_zcode_work_context(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    if (!request || !reply || !request->input ||
        request->input->type != JSON_OBJ || request->input->num_children != 0) {
        if (reply) zcl_command_reply_fail(
            reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INVALID,
            "BAD_WORK_CONTEXT_INPUT", "status", false, false,
            "zcode work context accepts no input keys", "zcode.work.context");
        return;
    }
    struct zcl_hotswap_service_lease lease = {0};
    const struct zcode_goal_context_calc_service_v1 *service =
        zcl_hotswap_service_acquire(ZCODE_GOAL_CONTEXT_CALC_SERVICE_ID, &lease);
    if (!service) service = zcode_goal_context_calc_service_builtin();
    struct zcode_goal_context_view_v1 view;
    bool rendered = service->render_status(&view) && view.valid &&
        view.capability[0] && view.next_action[0];
    zcl_hotswap_service_release(&lease);
    if (!rendered) {
        zcl_command_reply_fail(
            reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INVALID,
            "WORK_CONTEXT_VIEW_FAILED", "render", false, false,
            "the pure goal-context view refused bounded status",
            "zcode.work.context");
        return;
    }
    (void)json_push_kv_bool(&reply->data, "ready", true);
    (void)json_push_kv_str(&reply->data, "capability", view.capability);
    (void)json_push_kv_str(&reply->data, "service_id",
                           ZCODE_GOAL_CONTEXT_CALC_SERVICE_ID);
    (void)json_push_kv_int(&reply->data, "service_generation",
                           zcl_hotswap_service_generation());
    (void)json_push_kv_bool(&reply->data, "codeindex_reads_static", true);
    (void)json_push_kv_bool(&reply->data, "clock_measurement_static", true);
    (void)json_push_kv_bool(&reply->data, "workspace_writes_swappable", false);
    (void)json_push_kv_bool(&reply->data, "task_creation_swappable", false);
    (void)json_push_kv_str(&reply->data, "agent_next_action",
                           view.next_action);
}

const struct vcs_zcode_task_index_entry *zwork_resolve(
    const struct vcs_zcode_task_index *index, const char *work, bool *ambiguous)
{
    *ambiguous = false;
    size_t count = vcs_zcode_task_index_task_count(index);
    if (count == 0) return NULL;
    if (!work || !work[0] || strcmp(work, "latest") == 0) {
        const struct vcs_zcode_task_index_entry *best =
            vcs_zcode_task_index_task_at(index, 0);
        for (size_t i = 1; i < count; i++) {
            const struct vcs_zcode_task_index_entry *at =
                vcs_zcode_task_index_task_at(index, i);
            if (at->expires_unix > best->expires_unix ||
                (at->expires_unix == best->expires_unix &&
                 strcmp(at->task_root_hex, best->task_root_hex) > 0))
                best = at;
        }
        return best;
    }
    const char *prefix = strncmp(work, "work-", 5) == 0 ? work + 5 : work;
    size_t prefix_len = strlen(prefix);
    if (prefix_len < 8 || prefix_len > 64) return NULL;
    const struct vcs_zcode_task_index_entry *match = NULL;
    for (size_t i = 0; i < count; i++) {
        const struct vcs_zcode_task_index_entry *at =
            vcs_zcode_task_index_task_at(index, i);
        if (strncmp(at->task_root_hex, prefix, prefix_len) != 0) continue;
        if (match) { *ambiguous = true; return NULL; }
        match = at;
    }
    return match;
}

static void zwork_accept_inner(const char *workspace, const char *datadir,
                               const char *action_id, const char *lane,
                               struct zcl_command_reply *reply)
{
    int target = lane && strcmp(lane, "CANDIDATE") == 0
        ? VCS_ZCODE_LANE_CANDIDATE
        : lane && strcmp(lane, "PROVEN") == 0
            ? VCS_ZCODE_LANE_PROVEN : 0;
    char db_path[ZWORK_PATH_MAX];
    int n = snprintf(db_path, sizeof(db_path), "%s/node.db", datadir);
    struct node_db local_ndb = {0};
    struct node_db *ndb = n > 0 && (size_t)n < sizeof(db_path)
        ? zwork_runtime_ledger(db_path) : NULL;
    bool owned = ndb != NULL;
    if (!owned) ndb = &local_ndb;
    struct db_build_worker signer;
    uint8_t secret[32] = {0}, pubkey[32] = {0};
    struct zcode_lane_status status;
    bool opened = target != 0 && n > 0 && (size_t)n < sizeof(db_path) &&
        (owned || zwork_open_build_ledger(
            ndb, db_path, "zcode.work.accept", false));
    int64_t now = (int64_t)platform_time_wall_unix();
    struct zcl_result result = opened
        ? build_fabric_worker_identity_load(
              datadir, &signer, secret, pubkey)
        : ZCL_ERR(-1, "human acceptance ledger could not be opened");
    /* Acceptance is signed by this node's own operator identity, which lives
     * in this datadir. A requester node runs no build worker on purpose — it
     * must not be able to prove its own work — so nothing else ever enrolls
     * that key here, and without this the last human step of the journey
     * refuses every candidate with an unapproved signer. Enrollment is
     * first-use only: an identity the operator revoked or let expire keeps
     * refusing. */
    if (result.ok) {
        signer.last_seen_at = now;
        result = build_fabric_worker_enroll_local(ndb, &signer, now);
    }
    if (result.ok)
        result = zcode_lane_advance(
            ndb, workspace, action_id, target, now, secret, pubkey, &status);
    memory_cleanse(secret, sizeof(secret));
    if (opened && !owned) node_db_close(ndb);
    if (!result.ok) {
        zwork_fail(reply, "LANE_PROMOTION_REFUSED", "accept",
                   result.message, false, false);
        return;
    }
    (void)json_push_kv_str(&reply->data, "lane", status.lane_name);
    (void)json_push_kv_str(&reply->data, "source_root",
                           status.source_root_sha3);
    (void)json_push_kv_str(&reply->data, "task_root",
                           status.task_root_sha3);
    (void)json_push_kv_str(&reply->data, "candidate_root",
                           status.candidate_root_sha3);
    (void)json_push_kv_str(&reply->data, "proof_policy_root",
                           status.proof_policy_root_sha3);
    (void)json_push_kv_str(&reply->data, "proof_set_root",
                           status.proof_set_root_sha3);
    (void)json_push_kv_str(&reply->data, "lane_receipt_root",
                           status.receipt_root_sha3);
    (void)json_push_kv_str(&reply->data, "prior_lane_receipt_root",
                           status.prior_receipt_root_sha3);
    (void)json_push_kv_str(&reply->data, "signer_pubkey",
                           status.signer_pubkey);
    reply->status = ZCL_COMMAND_STATUS_PASSED;
    reply->exit_code = ZCL_COMMAND_EXIT_OK;
}

static void zwork_lane_inner(const char *workspace, const char *datadir,
                             const char *source_root,
                             struct zcl_command_reply *reply)
{
    struct json_value input;
    json_init(&input); json_set_object(&input);
    bool ok = json_push_kv_str(&input, "workspace", workspace) &&
        json_push_kv_str(&input, "datadir", datadir) &&
        json_push_kv_str(&input, "source_root", source_root);
    if (ok) {
        struct zcl_command_request request = { .input = &input };
        zcl_native_handle_zcode_lane(&request, reply);
    }
    json_free(&input);
    if (!ok)
        zwork_fail(reply, "LANE_INPUT_FAILED", "compose",
                   "existing lane lookup input could not be composed",
                   false, false);
}

static void zwork_evidence_inner(const char *workspace, const char *datadir,
                                 const char *action_id,
                                 struct zcl_command_reply *reply)
{
    struct json_value input;
    json_init(&input); json_set_object(&input);
    bool ok = json_push_kv_str(&input, "workspace", workspace) &&
        json_push_kv_str(&input, "datadir", datadir) &&
        json_push_kv_str(&input, "action_id", action_id);
    if (ok) {
        struct zcl_command_request request = { .input = &input };
        zcl_native_handle_zcode_evidence(&request, reply);
    }
    json_free(&input);
    if (!ok)
        zwork_fail(reply, "EVIDENCE_INPUT_FAILED", "compose",
                   "existing evidence evaluation input could not be composed",
                   false, false);
}

static bool zwork_review_load_objects(
    const char *workspace, const struct vcs_zcode_task_index_entry *entry,
    struct vcs_zcode_task_v1 *task,
    struct vcs_zcode_candidate_v1 *candidate)
{
    uint8_t root[32], *wire = NULL;
    size_t wire_len = 0;
    bool ok = zcl_hex_decode_lower(entry->task_root_hex, root, 32) &&
        vcs_object_load_raw(workspace, root, &wire, &wire_len) == 0 &&
        vcs_zcode_task_parse(wire, wire_len, task) == VCS_ZCODE_DEV_OK;
    free(wire); wire = NULL; wire_len = 0;
    if (!ok || !zcl_hex_decode_lower(entry->latest_candidate_root_hex,
                                     root, 32) ||
        vcs_object_load_raw(workspace, root, &wire, &wire_len) != 0 ||
        vcs_zcode_candidate_parse(wire, wire_len, candidate) !=
            VCS_ZCODE_DEV_OK) {
        free(wire);
        return false;
    }
    free(wire);
    return vcs_zcode_candidate_validate_for_task(
               task, candidate, platform_time_wall_unix()) ==
           VCS_ZCODE_DEV_OK;
}

static bool zwork_review_action(
    struct node_db *ndb, const struct db_build_action *base,
    const struct db_build_job *base_job, int64_t now,
    struct db_build_action *review)
{
    memset(review, 0, sizeof(*review));
    review->sequence = base->sequence + 1;
    (void)snprintf(review->kind, sizeof(review->kind), "%s",
                   VCS_BUILD_ACTION_KIND_REVIEW_V1);
    (void)snprintf(review->state, sizeof(review->state), "SNAPSHOTTED");
    (void)snprintf(review->input_root_sha3,
                   sizeof(review->input_root_sha3), "%s",
                   base->candidate_root_sha3);
    (void)snprintf(review->task_root_sha3,
                   sizeof(review->task_root_sha3), "%s",
                   base->task_root_sha3);
    (void)snprintf(review->candidate_root_sha3,
                   sizeof(review->candidate_root_sha3), "%s",
                   base->candidate_root_sha3);
    (void)snprintf(review->proof_policy_root_sha3,
                   sizeof(review->proof_policy_root_sha3), "%s",
                   base->proof_policy_root_sha3);
    (void)snprintf(review->target, sizeof(review->target), "%s",
                   VCS_BUILD_TARGET_V1);
    uint8_t flags[32], environment[32];
    if (!vcs_build_action_v1_fixed_flags_root_for_kind(
            review->kind, flags) ||
        !vcs_build_action_v1_fixed_environment_root_for_kind(
            review->kind, environment))
        return false;
    zcl_hex_encode(flags, 32, review->flags_sha3);
    zcl_hex_encode(environment, 32, review->environment_sha3);
    (void)snprintf(review->virtual_workdir,
                   sizeof(review->virtual_workdir), "%s",
                   VCS_BUILD_REVIEW_VIRTUAL_ROOT_V1);
    (void)snprintf(review->declared_outputs,
                   sizeof(review->declared_outputs), "%s",
                   VCS_BUILD_REVIEW_OUTPUT_V1);
    (void)snprintf(review->resource_policy,
                   sizeof(review->resource_policy), "%s",
                   VCS_BUILD_REVIEW_RESOURCE_POLICY_V1);
    review->created_at = review->updated_at = now;
    struct db_build_job job = *base_job;
    job.job_id[0] = '\0';
    (void)snprintf(job.state, sizeof(job.state), "PLANNED");
    job.outcome[0] = '\0';
    job.created_at = job.updated_at = now;
    if (!build_fabric_action_id(&job, review, review->action_id).ok ||
        !build_fabric_job_id(&job, review->action_id, job.job_id).ok)
        return false;
    (void)snprintf(review->job_id, sizeof(review->job_id), "%s", job.job_id);
    return db_build_job_save(ndb, &job) && db_build_action_save(ndb, review);
}

static bool zwork_review_receipt(
    struct node_db *ndb, const char *workspace,
    const struct vcs_zcode_task_v1 *task,
    const struct vcs_zcode_candidate_v1 *candidate,
    const struct db_build_action *action, const uint8_t proof_set_root[32],
    const uint8_t review_root[32], const uint8_t secret[32],
    const uint8_t pubkey[32], int64_t now, char receipt_root[65])
{
    struct vcs_zcode_work_request_v1 request = {
        .request_id = (uint64_t)now,
        .work_kind = VCS_ZCODE_WORK_REVIEW,
        .target = VCS_ZCODE_WORK_TARGET_LINUX_X86_64_V3,
        .max_cpu_seconds = task->max_cpu_seconds,
        .max_memory_bytes = task->max_memory_bytes,
        .max_output_bytes = task->max_output_bytes,
        .deadline_unix = task->expires_unix - 1,
    };
    uint8_t task_root[32], candidate_root[32], action_root[32];
    if (vcs_zcode_task_root(task, task_root) != VCS_ZCODE_DEV_OK ||
        vcs_zcode_candidate_root(candidate, candidate_root) !=
            VCS_ZCODE_DEV_OK ||
        !zcl_hex_decode_lower(action->action_id, action_root, 32))
        return false;
    memcpy(request.task_root, task_root, 32);
    memcpy(request.candidate_root, candidate_root, 32);
    memcpy(request.action_root, action_root, 32);
    memcpy(request.input_root, candidate_root, 32);
    memcpy(request.context_root, proof_set_root, 32);
    memcpy(request.proof_policy_root, task->proof_policy_root, 32);
    memcpy(request.toolchain_capsule_root,
           task->toolchain_capsule_root, 32);
    if (!vcs_zcode_work_request_seal(&request, secret, pubkey))
        return false;
    struct vcs_zcode_work_result_v1 result = {0};
    result.request_id = request.request_id;
    memcpy(result.task_root, task_root, 32);
    memcpy(result.candidate_root, candidate_root, 32);
    memcpy(result.action_root, action_root, 32);
    memcpy(result.output_root, review_root, 32);
    struct vcs_zcode_work_receipt_v1 *receipt = &result.receipt;
    receipt->schema_version = VCS_ZCODE_DEV_VERSION;
    memcpy(receipt->task_root, task_root, 32);
    memcpy(receipt->candidate_root, candidate_root, 32);
    memcpy(receipt->action_root, action_root, 32);
    memcpy(receipt->input_root, candidate_root, 32);
    memcpy(receipt->output_root, review_root, 32);
    memcpy(receipt->proof_policy_root, task->proof_policy_root, 32);
    memcpy(receipt->toolchain_capsule_root,
           task->toolchain_capsule_root, 32);
    static const char lease_domain[] = "zcl.zcode.review.manual.lease.v1";
    struct sha3_256_ctx sha;
    sha3_256_init(&sha);
    sha3_256_write(&sha, (const uint8_t *)lease_domain,
                   sizeof(lease_domain));
    sha3_256_write(&sha, review_root, 32);
    sha3_256_finalize(&sha, receipt->lease_id);
    memcpy(receipt->evidence_root, proof_set_root, 32);
    static const char confinement[] =
        "zcode-review:manual;candidate=read-only;accept=0;publish=0";
    sha3_256((const uint8_t *)confinement, sizeof(confinement),
             receipt->confinement_root);
    receipt->work_kind = VCS_ZCODE_WORK_REVIEW;
    receipt->status = VCS_ZCODE_WORK_PASS;
    receipt->started_unix = now > 0 ? now - 1 : 0;
    receipt->finished_unix = now;
    if (vcs_zcode_work_receipt_seal(receipt, secret, pubkey) !=
        VCS_ZCODE_DEV_OK)
        return false;
    return build_fabric_receipt_observe_remote(
               ndb, workspace, &request, &result, now, receipt_root).ok;
}

// long-function-ok:review-authority-transaction — object, action, receipt and
// evidence evaluation must remain one fail-closed operation over one candidate.
void zcl_native_handle_zcode_work_review(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    if (!request || !reply) return;
    const char *workspace_arg = zwork_str(request->input, "workspace");
    const char *work = zwork_str(request->input, "work");
    const char *adapter = zwork_str(request->input, "adapter");
    const char *verdict_text = zwork_str(request->input, "verdict");
    const char *findings = zwork_str(request->input, "findings");
    if (!workspace_arg || !workspace_arg[0]) workspace_arg = ".";
    if (!adapter || !adapter[0]) adapter = "manual";
    uint8_t verdict = verdict_text && strcmp(verdict_text, "approve") == 0
        ? VCS_ZCODE_REVIEW_APPROVE
        : verdict_text && strcmp(verdict_text, "request_changes") == 0
        ? VCS_ZCODE_REVIEW_REQUEST_CHANGES
        : verdict_text && strcmp(verdict_text, "reject") == 0
        ? VCS_ZCODE_REVIEW_REJECT : 0;
    if (strcmp(adapter, "manual") != 0 || verdict == 0 || !findings ||
        findings[0] == '\0' || strlen(findings) > 4096u) {
        zwork_fail(reply, strcmp(adapter, "manual") != 0
                         ? "REVIEW_ADAPTER_UNAVAILABLE" : "BAD_REVIEW_INPUT",
                   "review", "manual review requires a closed verdict and 1..4096 bytes of findings",
                   false, false);
        return;
    }
    char workspace[ZWORK_PATH_MAX];
    if (!platform_directory_canonical_real(
            workspace_arg, workspace, sizeof(workspace))) {
        zwork_fail(reply, "BAD_WORKSPACE", "resolve",
                   "workspace must resolve to an existing directory",
                   false, false);
        return;
    }
    int64_t now = platform_time_wall_unix();
    struct vcs_zcode_task_index *index =
        vcs_zcode_task_index_build(workspace, now);
    bool ambiguous = false;
    const struct vcs_zcode_task_index_entry *entry = index
        ? zwork_resolve(index, work, &ambiguous) : NULL;
    struct vcs_zcode_task_v1 task;
    struct vcs_zcode_candidate_v1 candidate;
    if (!entry || entry->expired || !entry->latest_action_root_hex[0] ||
        !zwork_review_load_objects(workspace, entry, &task, &candidate)) {
        zwork_fail(reply, ambiguous ? "AMBIGUOUS_WORK" : "WORK_NOT_REVIEWABLE",
                   "review", "a current candidate with signed non-review evidence is required",
                   false, false);
        vcs_zcode_task_index_free(index);
        return;
    }
    char datadir[ZWORK_PATH_MAX], reviewer_dir[ZWORK_PATH_MAX], db_path[ZWORK_PATH_MAX];
    int dn = zwork_task_path(datadir, entry->task_root_hex, "/zbuild")
        ? (int)strlen(datadir) : -1;
    int rn = snprintf(reviewer_dir, sizeof(reviewer_dir), "%s/reviewer", datadir);
    int bn = snprintf(db_path, sizeof(db_path), "%s/node.db", datadir);
    struct node_db ndb = {0};
    struct db_build_action base_action, review_action;
    struct db_build_job base_job;
    struct build_fabric_proof_evaluation before = {0}, after = {0};
    struct db_build_worker reviewer;
    uint8_t secret[32] = {0}, pubkey[32] = {0};
    bool opened = dn > 0 && (size_t)dn < sizeof(datadir) && rn > 0 &&
        (size_t)rn < sizeof(reviewer_dir) && bn > 0 &&
        (size_t)bn < sizeof(db_path) && zwork_open_build_ledger(
            &ndb, db_path, "zcode.work.review", true);
    const char *failed_stage = opened ? "base_action" : "scratch_ledger";
    bool ready = opened && db_build_action_find(
        &ndb, entry->latest_action_root_hex, &base_action);
    if (ready) failed_stage = "base_job";
    ready = ready && db_build_job_find(&ndb, base_action.job_id, &base_job);
    if (ready) failed_stage = "non_review_proof_set";
    ready = ready && build_fabric_proof_evaluate(
        &ndb, workspace, entry->latest_action_root_hex, now, &before).ok &&
        before.valid_receipts > 0 && before.review_receipts == 0;
    if (ready) failed_stage = "reviewer_directory";
#if defined(_WIN32)
    ready = ready && platform_private_directory_ensure(reviewer_dir);
#else
    ready = ready && zcl_mkdir_p(reviewer_dir, 0700).ok;
#endif
    if (ready) failed_stage = "reviewer_identity";
    ready = ready && build_fabric_worker_identity_load(
        reviewer_dir, &reviewer, secret, pubkey).ok;
    if (ready) failed_stage = "reviewer_independence";
    ready = ready && memcmp(pubkey, candidate.author_pubkey, 32) != 0;
    if (ready) failed_stage = "reviewer_approval";
    ready = ready && build_fabric_worker_approve(&ndb, &reviewer, now).ok;
    uint8_t proof_set_root[32], findings_root[32], review_root[32];
    struct vcs_zcode_review_v1 review = {
        .schema_version = VCS_ZCODE_DEV_VERSION,
        .verdict = verdict,
        .sequence = 1,
        .created_unix = now,
    };
    if (ready) failed_stage = "proof_set_root";
    ready = ready && zcl_hex_decode_lower(
        before.proof_set_root_sha3, proof_set_root, 32);
    if (ready) {
        (void)vcs_zcode_task_root(&task, review.task_root);
        (void)vcs_zcode_candidate_root(&candidate, review.candidate_root);
        memcpy(review.proof_policy_root, task.proof_policy_root, 32);
        memcpy(review.proof_set_root, proof_set_root, 32);
        sha3_256((const uint8_t *)findings, strlen(findings), findings_root);
        memcpy(review.findings_root, findings_root, 32);
        memcpy(review.reviewer_pubkey, pubkey, 32);
    }
    uint8_t review_wire[VCS_ZCODE_REVIEW_WIRE_BYTES];
    if (ready) failed_stage = "findings_store";
    ready = ready && vcs_object_put_addressed(
        workspace, findings_root, (const uint8_t *)findings, strlen(findings));
    if (ready) failed_stage = "review_wire";
    ready = ready && vcs_zcode_review_serialize(
        &review, review_wire) == VCS_ZCODE_DEV_OK &&
        vcs_zcode_review_root(&review, review_root) == VCS_ZCODE_DEV_OK;
    if (ready) failed_stage = "review_store";
    ready = ready && vcs_object_put_addressed(
        workspace, review_root, review_wire, sizeof(review_wire));
    if (ready) failed_stage = "review_action";
    ready = ready && zwork_review_action(
        &ndb, &base_action, &base_job, now, &review_action);
    char receipt_root[65] = {0};
    if (ready) failed_stage = "review_receipt";
    ready = ready && zwork_review_receipt(
        &ndb, workspace, &task, &candidate, &review_action,
        proof_set_root, review_root, secret, pubkey, now, receipt_root);
    if (ready) failed_stage = "proof_re_evaluation";
    ready = ready && build_fabric_proof_evaluate(
        &ndb, workspace, entry->latest_action_root_hex, now, &after).ok;
    memory_cleanse(secret, sizeof(secret));
    if (opened) node_db_close(&ndb);
    if (!ready) {
        char detail[256];
        (void)snprintf(detail, sizeof(detail),
                       "review stopped at %s; prior canonical evidence is preserved",
                       failed_stage);
        zwork_fail(reply, before.review_receipts > 0 ? "REVIEW_ALREADY_PRESENT" :
                   "REVIEW_EXECUTION_FAILED", failed_stage,
                   before.review_receipts > 0
                     ? "the candidate already has a trusted review; conflicting-review support is not yet complete"
                     : detail,
                   true, opened);
        vcs_zcode_task_index_free(index);
        return;
    }
    char review_hex[65], reviewer_hex[65];
    zcl_hex_encode(review_root, 32, review_hex);
    zcl_hex_encode(pubkey, 32, reviewer_hex);
    char work_id[32];
    (void)snprintf(work_id, sizeof(work_id), "work-%.12s",
                   entry->task_root_hex);
    bool rendered = json_push_kv_str(&reply->data, "work_id", work_id) &&
        json_push_kv_str(&reply->data, "adapter", "manual") &&
        json_push_kv_str(&reply->data, "verdict", verdict_text) &&
        json_push_kv_bool(&reply->data, "independent_reviewer", true) &&
        json_push_kv_int(&reply->data, "review_receipts",
                         (int64_t)after.review_receipts) &&
        json_push_kv_bool(&reply->data, "review_satisfied",
                          after.review_satisfied) &&
        json_push_kv_bool(&reply->data, "policy_satisfied",
                          after.policy_satisfied) &&
        json_push_kv_str(&reply->data, "review_root", review_hex) &&
        json_push_kv_str(&reply->data, "work_receipt_root", receipt_root) &&
        json_push_kv_str(&reply->data, "reviewer_pubkey", reviewer_hex) &&
        json_push_kv_str(&reply->data, "proof_set_reviewed",
                         before.proof_set_root_sha3) &&
        json_push_kv_str(&reply->data, "next_safe_command",
                         "zcode work status");
    vcs_zcode_task_index_free(index);
    if (!rendered)
        zwork_fail(reply, "REVIEW_OUTPUT_FAILED", "render",
                   "review result could not be rendered", false, true);
}

/* The workspace index deliberately projects every valid signed receipt, but
 * acceptance authority lives in the task-local build ledger. Resolve the
 * action whose independently re-evaluated proof policy is satisfied; an
 * unrelated later display receipt must never redirect acceptance. */
static bool zwork_accept_action_resolve(
    const char *workspace, const char *datadir,
    const struct vcs_zcode_task_index_entry *entry,
    char out[BUILD_FABRIC_ID_HEX + 1])
{
    if (!workspace || !datadir || !entry || !out) return false;
    out[0] = '\0';
    char db_path[ZWORK_PATH_MAX];
    int n = snprintf(db_path, sizeof(db_path), "%s/node.db", datadir);
    struct node_db local = {0};
    struct node_db *ndb = n > 0 && (size_t)n < sizeof(db_path)
        ? zwork_runtime_ledger(db_path) : NULL;
    bool owned = ndb != NULL;
    if (!owned) ndb = &local;
    bool opened = n > 0 && (size_t)n < sizeof(db_path) &&
        (owned || node_db_open_existing_runtime(
            ndb, db_path, "zcode.work.accept.action"));
    struct db_build_action actions[64];
    int count = opened ? db_build_candidate_actions(
        ndb, entry->task_root_hex, entry->latest_candidate_root_hex,
        entry->proof_policy_root_hex, actions,
        sizeof(actions) / sizeof(actions[0])) : 0;
    int64_t now = (int64_t)platform_time_wall_unix();
    for (int i = 0; i < count; i++) {
        struct build_fabric_proof_evaluation facts = {0};
        if (build_fabric_proof_evaluate_readonly(
                ndb, workspace, actions[i].action_id, now, &facts).ok &&
            facts.policy_satisfied &&
            (!out[0] || strcmp(actions[i].action_id, out) < 0))
            (void)snprintf(out, BUILD_FABRIC_ID_HEX + 1, "%s",
                           actions[i].action_id);
    }
    if (!owned && opened) node_db_close(ndb);
    return out[0] != '\0';
}

void zcl_native_handle_zcode_work_accept(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    if (!request || !reply) return;
    const char *workspace_arg = zwork_str(request->input, "workspace");
    const char *work = zwork_str(request->input, "work");
    const char *confirmed_identity =
        zwork_str(request->input, "confirmation_identity");
    const char *proof_datadir = zwork_str(request->input, "datadir");
    bool details = zwork_bool(request->input, "details");
    if (zcl_native_forward_live_command(
            request, proof_datadir, "zcode_work_accept",
            "LIVE_WORK_ACCEPT_FAILED", "accept", "zcode.work.accept",
            reply))
        return;
    if (!workspace_arg || !workspace_arg[0]) workspace_arg = ".";
    char workspace[ZWORK_PATH_MAX];
    if (!platform_directory_canonical_real(
            workspace_arg, workspace, sizeof(workspace))) {
        zwork_fail(reply, "BAD_WORKSPACE", "resolve",
                   "workspace must resolve to an existing directory",
                   false, false);
        return;
    }
    struct vcs_zcode_task_index *index = vcs_zcode_task_index_build(
        workspace, platform_time_wall_unix());
    bool ambiguous = false;
    const struct vcs_zcode_task_index_entry *entry = index
        ? zwork_resolve(index, work, &ambiguous) : NULL;
    bool ready = entry && !entry->expired &&
        (strcmp(entry->state, VCS_ZCODE_TASK_STATE_EVIDENCE_READY) == 0 ||
         strcmp(entry->state,
                VCS_ZCODE_TASK_STATE_CANDIDATE_PROOFS_READY) == 0 ||
         strcmp(entry->state, VCS_ZCODE_TASK_STATE_PROVEN) == 0);
    if (!ready || !entry->latest_action_root_hex[0] ||
        !entry->latest_candidate_source_root_hex[0]) {
        zwork_fail(reply, ambiguous ? "AMBIGUOUS_WORK" :
                     "WORK_NOT_READY_FOR_ACCEPTANCE", "accept",
                   entry && entry->expired ? "task expired" :
                   "the latest candidate lacks verified passing evidence",
                   false, false);
        vcs_zcode_task_index_free(index); return;
    }
    char datadir[ZWORK_PATH_MAX];
    int n = proof_datadir && proof_datadir[0]
        ? (platform_directory_canonical_real(
               proof_datadir, datadir, sizeof(datadir))
            ? (int)strlen(datadir) : -1)
        : (zwork_task_path(datadir, entry->task_root_hex, "/zbuild")
            ? (int)strlen(datadir) : -1);
    if (n <= 0 || (size_t)n >= sizeof(datadir)) {
        zwork_fail(reply, "ACCEPT_PATH_FAILED", "resolve",
                   proof_datadir && proof_datadir[0]
                     ? "explicit proof datadir must resolve to an existing directory"
                     : "task-local ZBuild path is too long", false, false);
        vcs_zcode_task_index_free(index); return;
    }
    char acceptance_action[BUILD_FABRIC_ID_HEX + 1];
    if (!zwork_accept_action_resolve(
            workspace, datadir, entry, acceptance_action)) {
        zwork_fail(reply, "PROOF_PROFILE_INCOMPLETE", "evidence",
                   "no canonical action currently satisfies the exact proof profile",
                   true, false);
        vcs_zcode_task_index_free(index); return;
    }
    char acceptance_hex[65] = {0};
    if (confirmed_identity) {
        char db_path[ZWORK_PATH_MAX];
        int dbn = snprintf(db_path, sizeof(db_path), "%s/node.db", datadir);
        struct node_db local_identity_db = {0};
        struct node_db *identity_db = dbn > 0 &&
                (size_t)dbn < sizeof(db_path)
            ? zwork_runtime_ledger(db_path) : NULL;
        bool identity_owned = identity_db != NULL;
        if (!identity_owned) identity_db = &local_identity_db;
        struct build_fabric_proof_evaluation identity_facts;
        bool identity_ready = dbn > 0 && (size_t)dbn < sizeof(db_path) &&
            (identity_owned || node_db_open_existing_runtime(
                identity_db, db_path, "zcode.work.accept.confirmation"));
        if (identity_ready) {
            identity_ready = build_fabric_proof_evaluate_readonly(
                identity_db, workspace, acceptance_action,
                (int64_t)platform_time_wall_unix(), &identity_facts).ok;
            if (!identity_owned) node_db_close(identity_db);
        }
        uint8_t task_root[32], candidate_root[32], policy_root[32];
        uint8_t proof_root[32], acceptance_root[32], supplied_root[32];
        identity_ready = identity_ready &&
            zcl_hex_decode_lower(entry->task_root_hex, task_root, 32) &&
            zcl_hex_decode_lower(entry->latest_candidate_root_hex,
                                 candidate_root, 32) &&
            zcl_hex_decode_lower(entry->proof_policy_root_hex,
                                 policy_root, 32) &&
            zcl_hex_decode_lower(identity_facts.proof_set_root_sha3,
                                 proof_root, 32) &&
            vcs_zcode_acceptance_plan_root(
                task_root, candidate_root, policy_root, proof_root,
                acceptance_root) == VCS_ZCODE_DEV_OK;
        if (identity_ready)
            zcl_hex_encode(acceptance_root, 32, acceptance_hex);
        if (!identity_ready ||
            !zcl_hex_decode_lower(confirmed_identity, supplied_root, 32) ||
            memcmp(supplied_root, acceptance_root, 32) != 0) {
            zwork_fail(reply, "CONFIRMATION_IDENTITY_STALE", "accept",
                       "the confirmed native decision no longer matches the exact candidate proof set",
                       false, false);
            vcs_zcode_task_index_free(index); return;
        }
    }
    struct zcl_command_reply lane_reply;
    zcl_command_reply_init(&lane_reply, "zcl.zcode_lane.v1");
    zwork_lane_inner(workspace, datadir,
                     entry->latest_candidate_source_root_hex, &lane_reply);
    const struct json_value *lane_value = lane_reply.status ==
            ZCL_COMMAND_STATUS_PASSED
        ? json_get(&lane_reply.data, "lane") : NULL;
    const char *lane = lane_value && lane_value->type == JSON_STR
        ? json_get_str(lane_value) : NULL;
    if (!lane) {
        zwork_fail(reply, "LANE_STATE_MISSING", "accept",
                   lane_reply.error.message[0] ? lane_reply.error.message :
                   "the signed FRONTIER lane could not be reloaded",
                   true, false);
        zcl_command_reply_free(&lane_reply);
        vcs_zcode_task_index_free(index); return;
    }
    bool already_proven = strcmp(lane, "PROVEN") == 0;
    struct zcl_command_reply final_reply;
    zcl_command_reply_init(&final_reply, "zcl.zcode_accept.v1");
    if (already_proven) {
        json_copy(&final_reply.data, &lane_reply.data);
        final_reply.status = ZCL_COMMAND_STATUS_PASSED;
    } else {
        struct zcl_command_reply evidence;
        zcl_command_reply_init(&evidence, "zcl.zcode_evidence.v1");
        zwork_evidence_inner(workspace, datadir,
                             acceptance_action, &evidence);
        const struct json_value *satisfied = evidence.status ==
                ZCL_COMMAND_STATUS_PASSED
            ? json_get(&evidence.data, "policy_satisfied") : NULL;
        if (!satisfied || !json_get_bool(satisfied)) {
            zwork_fail(reply, "PROOF_PROFILE_INCOMPLETE", "evidence",
                       evidence.status == ZCL_COMMAND_STATUS_PASSED
                         ? "the exact proof profile is not yet satisfied; preserved evidence remains inspectable"
                         : evidence.error.message,
                       true, false);
            zcl_command_reply_free(&evidence);
            zcl_command_reply_free(&final_reply);
            zcl_command_reply_free(&lane_reply);
            vcs_zcode_task_index_free(index); return;
        }
        zcl_command_reply_free(&evidence);
        if (strcmp(lane, "FRONTIER") == 0) {
            struct zcl_command_reply candidate;
            zcl_command_reply_init(&candidate, "zcl.zcode_accept.v1");
            zwork_accept_inner(workspace, datadir,
                               acceptance_action,
                               "CANDIDATE", &candidate);
            if (candidate.status != ZCL_COMMAND_STATUS_PASSED) {
                zwork_fail(reply, "CANDIDATE_ACCEPTANCE_REFUSED", "accept",
                           candidate.error.message, false, false);
                zcl_command_reply_free(&candidate);
                zcl_command_reply_free(&final_reply);
                zcl_command_reply_free(&lane_reply);
                vcs_zcode_task_index_free(index); return;
            }
            zcl_command_reply_free(&candidate);
        }
        zwork_accept_inner(workspace, datadir,
                           acceptance_action, "PROVEN",
                           &final_reply);
    }
    if (final_reply.status != ZCL_COMMAND_STATUS_PASSED) {
        zwork_fail(reply, "PROVEN_ACCEPTANCE_REFUSED", "accept",
                   final_reply.error.message, false, true);
    } else {
        char retained_candidate_workspace[ZWORK_PATH_MAX] = {0};
        struct vcs_devloop_accepted_candidate_result publication;
        if (!zwork_bind_accepted_publication(
                workspace, entry, &final_reply, retained_candidate_workspace,
                &publication)) {
            zwork_fail(reply, "ACCEPTED_PUBLICATION_BIND_FAILED", "publish",
                       publication.error[0] ? publication.error :
                       "the retained candidate or accepted-work identity could not enter dev.publication",
                       true, true);
            zcl_command_reply_free(&final_reply);
            zcl_command_reply_free(&lane_reply);
            vcs_zcode_task_index_free(index);
            return;
        }
        struct json_value expert;
        json_init(&expert); json_copy(&expert, &final_reply.data);
        const struct json_value *accepted_root_value =
            json_get(&final_reply.data, "lane_receipt_root");
        const char *accepted_work_root = accepted_root_value &&
                accepted_root_value->type == JSON_STR
            ? json_get_str(accepted_root_value) : NULL;
        char publication_job_hex[65], publication_progress_hex[65];
        char publication_commit_hex[65], publication_proof_hex[65];
        zcl_hex_encode(publication.publication_job_root, 32,
                       publication_job_hex);
        zcl_hex_encode(publication.publication_progress_root, 32,
                       publication_progress_hex);
        zcl_hex_encode(publication.vcs_commit_root, 32,
                       publication_commit_hex);
        zcl_hex_encode(publication.proof_receipt_root, 32,
                       publication_proof_hex);
        char work_id[32];
        (void)snprintf(work_id, sizeof(work_id), "work-%.12s",
                       entry->task_root_hex);
        struct json_value next_input;
        json_init(&next_input); json_set_object(&next_input);
        bool ok = accepted_work_root &&
            json_push_kv_str(&expert, "accepted_work_root",
                             accepted_work_root) &&
            json_push_kv_str(&reply->data, "work_id", work_id) &&
            json_push_kv_str(&reply->data, "goal_decision", "accepted") &&
            json_push_kv_str(&reply->data, "state", "PROVEN") &&
            json_push_kv_str(&reply->data, "stage", "Accepted") &&
            (!details || !confirmed_identity ||
             json_push_kv_str(&reply->data, "confirmation_identity",
                              acceptance_hex)) &&
            json_push_kv_bool(&reply->data, "confirmation_identity_checked",
                              confirmed_identity != NULL) &&
            json_push_kv_bool(&reply->data, "idempotent", already_proven) &&
            json_push_kv_str(&reply->data, "authoritative_workspace",
                             "unchanged") &&
            json_push_kv_str(&reply->data, "publication_status",
                             "ACCEPTED_LANE_BOUND") &&
            json_push_kv_bool(&reply->data, "publication_reused",
                              publication.reused) &&
            json_push_kv_str(&reply->data, "next_safe_command",
                             "zcode work publish") &&
            json_push_kv_bool(&reply->data, "details_available", true) &&
            (!details || (
                json_push_kv_str(&reply->data, "publication_workspace",
                                 workspace) &&
                json_push_kv_str(&reply->data, "candidate_workspace",
                                 retained_candidate_workspace) &&
                json_push_kv_str(&reply->data, "publication_job_root",
                                 publication_job_hex) &&
                json_push_kv_str(&reply->data, "publication_progress_root",
                                 publication_progress_hex) &&
                json_push_kv_str(&reply->data, "publication_commit_root",
                                 publication_commit_hex) &&
                json_push_kv_str(
                    &reply->data, "publication_proof_receipt_root",
                    publication_proof_hex) &&
                json_push_kv(&reply->data, "expert", &expert))) &&
            json_push_kv_str(&next_input, "workspace", workspace) &&
            json_push_kv_str(&next_input, "work", work_id) &&
            json_push_kv_str(&next_input, "datadir", datadir) &&
            json_push_kv_str(&next_input, "job_root",
                             publication_job_hex) &&
            zwork_add_next(
                reply, "zcode.work.publish", &next_input,
                "advance the accepted exact source through its existing publication job");
        json_free(&next_input);
        json_free(&expert);
        if (!ok)
            zwork_fail(reply, "ACCEPT_OUTPUT_FAILED", "render",
                       "human acceptance summary could not be rendered",
                       false, !already_proven);
    }
    zcl_command_reply_free(&final_reply);
    zcl_command_reply_free(&lane_reply);
    vcs_zcode_task_index_free(index);
}

/* A job locator never grants acceptance. Follow its existing, root-checked
 * progress chain back to the exact accepted lane before invoking its owner. */
static bool zwork_publication_bound(
    const char *workspace, const uint8_t job_root[32],
    const struct vcs_zcode_accepted_work_v1 *accepted,
    enum vcs_devloop_publication_phase *phase)
{
    struct vcs_devloop_publication_job job;
    struct vcs_devloop_publication_receipt progress;
    uint8_t progress_root[32];
    if (!vcs_devloop_publication_job_load(workspace, job_root, &job) ||
        !vcs_devloop_publication_job_is_queued(workspace, job_root) ||
        memcmp(job.source_tree_root,
               accepted->candidate.candidate_source_root, 32) != 0 ||
        !vcs_devloop_publication_progress_load(
            workspace, job_root, &progress, progress_root))
        return false;
    *phase = progress.phase;
    for (unsigned i = 0; i < VCS_DEVLOOP_PUBLICATION_PHASE_SOURCE_REPRODUCED;
         i++) {
        if (memcmp(progress.job_root, job_root, 32) != 0) return false;
        if (progress.phase == VCS_DEVLOOP_PUBLICATION_PHASE_ACCEPTED_LANE_BOUND) {
            if (memcmp(progress.artifact_root,
                       accepted->accepted_work_root, 32) != 0 ||
                !vcs_devloop_publication_receipt_load(
                    workspace, progress.predecessor_receipt_root, &progress))
                return false;
            const uint8_t zero[32] = {0};
            return progress.phase == VCS_DEVLOOP_PUBLICATION_PHASE_WAITING_ACCEPTANCE &&
                memcmp(progress.job_root, job_root, 32) == 0 &&
                memcmp(progress.predecessor_receipt_root, zero, 32) == 0;
        }
        if (progress.phase <= VCS_DEVLOOP_PUBLICATION_PHASE_ACCEPTED_LANE_BOUND ||
            progress.phase > VCS_DEVLOOP_PUBLICATION_PHASE_SOURCE_REPRODUCED)
            return false;
        enum vcs_devloop_publication_phase prior_phase = progress.phase;
        if (!vcs_devloop_publication_receipt_load(
                workspace, progress.predecessor_receipt_root, &progress) ||
            progress.phase != prior_phase - 1)
            return false;
    }
    return false;
}

void zcl_native_handle_zcode_work_publish(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    if (!request || !reply) return;
    const char *workspace_arg = zwork_str(request->input, "workspace");
    const char *work = zwork_str(request->input, "work");
    const char *proof_datadir = zwork_str(request->input, "datadir");
    const char *job_hex = zwork_str(request->input, "job_root");
    bool details = zwork_bool(request->input, "details");
    if (zcl_native_forward_live_command(
            request, proof_datadir, "zcode_work_publish",
            "LIVE_WORK_PUBLISH_FAILED", "publish", "zcode.work.publish",
            reply))
        return;
    char workspace[ZWORK_PATH_MAX], datadir[ZWORK_PATH_MAX];
    uint8_t job_root[32];
    if (!platform_directory_canonical_real(
            workspace_arg && workspace_arg[0] ? workspace_arg : ".",
            workspace, sizeof(workspace)) ||
        !job_hex || !zcl_hex_decode_lower(job_hex, job_root, 32)) {
        zwork_fail(reply, "BAD_PUBLICATION_INPUT", "resolve",
                   "use the exact publication continuation returned by work accept",
                   false, false);
        return;
    }
    struct vcs_zcode_task_index *index = vcs_zcode_task_index_build(
        workspace, platform_time_wall_unix());
    bool ambiguous = false;
    const struct vcs_zcode_task_index_entry *entry = index
        ? zwork_resolve(index, work, &ambiguous) : NULL;
    if (!entry || entry->expired ||
        strcmp(entry->state, VCS_ZCODE_TASK_STATE_PROVEN) != 0) {
        zwork_fail(reply, ambiguous ? "AMBIGUOUS_WORK" : "WORK_NOT_ACCEPTED",
                   "verify", "the current exact work must already be accepted",
                   false, false);
        vcs_zcode_task_index_free(index);
        return;
    }
    bool path_ok = proof_datadir && proof_datadir[0]
        ? platform_directory_canonical_real(proof_datadir, datadir, sizeof(datadir))
        : zwork_task_path(datadir, entry->task_root_hex, "/zbuild");
    char db_path[ZWORK_PATH_MAX];
    int n = path_ok ? snprintf(db_path, sizeof(db_path), "%s/node.db", datadir) : -1;
    struct node_db local = {0};
    struct node_db *ndb = n > 0 && (size_t)n < sizeof(db_path)
        ? zwork_runtime_ledger(db_path) : NULL;
    bool owned = ndb != NULL;
    if (!owned) ndb = &local;
    bool opened = n > 0 && (size_t)n < sizeof(db_path) &&
        (owned || node_db_open_existing_runtime(ndb, db_path, "zcode.work.publish"));
    struct zcode_accepted_work_status accepted;
    uint8_t task_root[32], candidate_root[32], policy_root[32];
    bool verified = opened && zcode_accepted_work_find(
        ndb, workspace, entry->latest_candidate_source_root_hex,
        (int64_t)platform_time_wall_unix(), false, &accepted).ok &&
        zcl_hex_decode_lower(entry->task_root_hex, task_root, 32) &&
        zcl_hex_decode_lower(entry->latest_candidate_root_hex, candidate_root, 32) &&
        zcl_hex_decode_lower(entry->proof_policy_root_hex, policy_root, 32) &&
        memcmp(task_root, accepted.accepted.task_root, 32) == 0 &&
        memcmp(candidate_root, accepted.accepted.candidate_root, 32) == 0 &&
        memcmp(policy_root, accepted.accepted.proof_policy_root, 32) == 0;
    if (opened && !owned) node_db_close(ndb);
    enum vcs_devloop_publication_phase phase = 0;
    if (!verified || !zwork_publication_bound(
            workspace, job_root, &accepted.accepted, &phase)) {
        zwork_fail(reply, "WORK_PUBLICATION_MISMATCH", "verify",
                   "the queued publication must bind this exact currently accepted work",
                   false, false);
        vcs_zcode_task_index_free(index);
        return;
    }
    char work_id[32];
    (void)snprintf(work_id, sizeof(work_id), "work-%.12s", entry->task_root_hex);
    vcs_zcode_task_index_free(index);

    struct zcl_dev_publication_input publication = {
        .source_root = workspace,
        .workspace = workspace,
        .datadir = datadir,
        .job_root = job_hex,
        .details = details,
    };
    struct zcl_command_reply inner;
    zcl_command_reply_init(&inner, "zcl.zcode_work_publish.v1");
    bool collect = phase == VCS_DEVLOOP_PUBLICATION_PHASE_PROVIDER_ANNOUNCED ||
                   phase == VCS_DEVLOOP_PUBLICATION_PHASE_STORAGE_ACKNOWLEDGED;
    if (collect) zcl_dev_publication_collect(&publication, &inner);
    else zcl_dev_publication_advance(&publication, &inner);
    if (inner.status != ZCL_COMMAND_STATUS_PASSED) {
        reply->status = inner.status;
        reply->exit_code = inner.exit_code;
        reply->error = inner.error;
        zcl_command_reply_free(&inner);
        return;
    }
    if (!collect && !zwork_bool(&inner.data, "acceptance_reverified")) {
        zcl_command_reply_free(&inner);
        zwork_fail(reply, "WORK_PUBLICATION_MISMATCH", "verify",
                   "publication could not reverify the current accepted work",
                   true, false);
        return;
    }
    const char *status = zwork_str(&inner.data, "status");
    const char *next_action = zwork_str(&inner.data, "next_action");
    const char *next_safe = zwork_str(&inner.data, "next_safe_command");
    const char *schema = NULL;
    if (!collect && phase != VCS_DEVLOOP_PUBLICATION_PHASE_SOURCE_REPRODUCED) {
        if (next_safe && strcmp(next_safe, "zcode package dev publish plan") == 0)
            schema = "zcode.package.dev.publish.plan";
        else if (next_safe && strcmp(next_safe, "zcode passport plan") == 0)
            schema = "zcode.passport.plan";
        else if (next_safe && strcmp(next_safe, "zcode workspace manifest plan") == 0)
            schema = "zcode.workspace.manifest.plan";
        else if (next_safe && strcmp(next_safe, "zcode network publish") == 0)
            schema = "zcode.network.publish";
    }
    bool rendered = status &&
        json_push_kv_str(&reply->data, "work_id", work_id) &&
        json_push_kv_str(&reply->data, "status", status) &&
        json_push_kv_str(&reply->data, "stage", "Publishing") &&
        json_push_kv_str(&reply->data, "next_action", next_action ? next_action :
            strcmp(status, "SOURCE_REPRODUCED") == 0
                ? "Keep this accepted package available to other nodes."
                : "Continue collecting independent storage and source reproduction evidence.") &&
        json_push_kv_str(&reply->data, "next_safe_command",
                         schema ? next_safe : "zcode work status") &&
        json_push_kv_bool(&reply->data, "acceptance_reverified", true) &&
        json_push_kv_bool(&reply->data, "details_available", true);
    const char *fields[] = {"receipt_reused", "receipt_written", "network_called",
        "wallet_called", "package_written", "mapping_cache_written", "storage_acks",
        "reproduced", "physical_independence_attested"};
    for (size_t i = 0; rendered && i < sizeof(fields) / sizeof(fields[0]); i++) {
        const struct json_value *value = json_get(&inner.data, fields[i]);
        if (value) rendered = json_push_kv(&reply->data, fields[i], value);
    }
    rendered = rendered && (!details || (
        json_push_kv_str(&reply->data, "publication_job_root", job_hex) &&
        json_push_kv(&reply->data, "expert", &inner.data)));
    struct json_value next_input;
    json_init(&next_input); json_set_object(&next_input);
    if (schema) {
        rendered = rendered && json_push_kv_str(&next_input, "path", schema) &&
            zwork_add_next(reply, "discover.schema", &next_input,
                           "inspect the publisher inputs required by the existing next step");
    } else {
        rendered = rendered &&
            json_push_kv_str(&next_input, "workspace", workspace) &&
            json_push_kv_str(&next_input, "datadir", datadir) &&
            json_push_kv_str(&next_input, "work", work_id) &&
            zwork_add_next(reply, "zcode.work.status", &next_input,
                           "inspect this accepted work and its current publication continuation");
    }
    zcl_command_reply_free(&inner);
    json_free(&next_input);
    if (!rendered)
        zwork_fail(reply, "PUBLICATION_OUTPUT_FAILED", "render",
                   "the publication continuation exceeded its output bound", false, true);
}
#endif
