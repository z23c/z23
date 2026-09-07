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

/* Only the two named coordination refusals may cross into the human-first
 * reply, and only when the planner itself observed neither an assignment nor
 * a running execution behind the conflict it names. */
static bool zwork_handoff_refusal(const struct zcl_command_reply *inner,
                                  bool active, bool incomplete)
{
    const char *kind = json_get_str(json_get(&inner->data, "conflict_kind"));
    const char *assignment = json_get_str(json_get(
        &inner->data, "assignment_status"));
    const char *execution = json_get_str(json_get(
        &inner->data, "active_execution"));
    return (active || incomplete) && kind && assignment && execution &&
        strcmp(assignment, "UNOBSERVED") == 0 &&
        strcmp(execution, "UNOBSERVED") == 0 &&
        (!incomplete || strcmp(kind, "INCOMPLETE") == 0) &&
        (!active || strcmp(kind, "DUPLICATE_ACTIVE_WORK") == 0 ||
         strcmp(kind, "WRITE_SCOPE_OVERLAP") == 0);
}

/* An active conflict must name one decodable task and exactly one task
 * continuation; an incomplete scan must name neither. */
static bool zwork_handoff_shape(const struct zcl_command_reply *inner,
                                bool active, bool incomplete,
                                const char **task_root_out)
{
    const struct json_value *task_value = json_get(&inner->data, "task_root");
    const char *task_root = task_value && task_value->type == JSON_STR
        ? json_get_str(task_value) : NULL;
    uint8_t decoded_task_root[32];
    *task_root_out = task_root;
    return (!active ||
            (task_root &&
             zcl_hex_decode_lower(task_root, decoded_task_root, 32u) &&
             inner->next_count == 1u &&
             strcmp(inner->next[0].command, "zcode.tasks") == 0)) &&
        (!incomplete ||
         (!(task_root && task_root[0]) && inner->next_count == 0u));
}

/* The offered continuation is preserved only when it is exactly the typed
 * three-field lookup of the same task in the same workspace. */
static bool zwork_handoff_next_typed(const struct zcl_command_reply *inner,
                                     const char *task_root,
                                     const char *expected_workspace)
{
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
    return typed;
}

/* Round-tripping through a fixed buffer both preserves the exact data object
 * and prevents a future inner handler from expanding this exception into an
 * unbounded second response surface. */
static bool zwork_handoff_adopt(const struct zcl_command_reply *inner,
                                struct zcl_command_reply *reply, bool active)
{
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

/* zcode.improve owns task-conflict classification and the exact CAS handoff.
 * The human-first wrapper may preserve only those two named coordination
 * refusals; every other planner failure keeps the ordinary compact error. */
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
    const char *task_root = NULL;
    if (!zwork_handoff_refusal(inner, active, incomplete) ||
        !zwork_handoff_shape(inner, active, incomplete, &task_root))
        return false;
    if (active &&
        !zwork_handoff_next_typed(inner, task_root, expected_workspace))
        return false;
    return zwork_handoff_adopt(inner, reply, active);
}

char *zwork_hex_alloc(const uint8_t *bytes, size_t len,
                      const char *label)
{
    if (!bytes || len > (SIZE_MAX - 1u) / 2u) return NULL;
    char *hex = zcl_malloc(len * 2u + 1u, label);
    if (hex) zcl_hex_encode(bytes, len, hex);
    return hex;
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

#endif
