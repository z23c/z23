/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Typed adapters for ZCODE create, use, and immutable improve tasks. */

#include "command/native_command.h"

#include "controllers/rpc_client.h"
#include "base/hex.h"
#include "base/serialize_le.h"
#include "crypto/sha3.h"
#include "config/runtime.h"
#include "hotswap/hotswap_service.h"
#include "json/json.h"
#include "models/database.h"
#include "models/database_owner_lease.h"
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
#include <sys/stat.h>
#include <unistd.h>

#define ZDEV_PATH_MAX 4096

static void zdev_fail(struct zcl_command_reply *reply, const char *code,
                      const char *detail);

static const char *zdev_str(const struct json_value *input, const char *key)
{
    const struct json_value *v = input ? json_get(input, key) : NULL;
    return v ? json_get_str(v) : NULL;
}

/* A native command may target the running full node's existing ledger or a
 * new, isolated ZBuild fixture.  Existing node.db files are runtime-owned:
 * reopening one must never run the boot-only quick-check/quarantine,
 * migration, or crash-cleanup ceremony while the daemon still owns its
 * canonical connection.  Only an absent scratch ledger may be boot-created. */
static bool zdev_open_build_ledger(
    struct node_db *ndb, const char *path, const char *reason)
{
    if (!ndb || !path || !path[0] || !reason || !reason[0]) return false;
    if (access(path, F_OK) == 0)
        return node_db_open_existing_runtime(ndb, path, reason);
    return node_db_open(ndb, path);
}

static bool zdev_runtime_owns_ledger(const char *datadir)
{
    struct node_db *owned = app_runtime_node_db();
    if (!owned || !app_runtime_node_db_handle_open(owned) ||
        !datadir || !datadir[0])
        return false;
    char expected[ZDEV_PATH_MAX];
    int n = snprintf(expected, sizeof(expected), "%s/node.db", datadir);
    return n > 0 && (size_t)n < sizeof(expected) &&
           strcmp(expected, owned->path) == 0;
}

/* A live node.db is never mutated by a one-shot CLI process. Forward the exact
 * canonical input to the authenticated daemon, where the same handler
 * revalidates it and commits through app_runtime_node_db(). Ownership comes
 * from the database lease, not an RPC-cookie convention: credential-directory
 * nodes deliberately have no <datadir>/.cookie. */
bool zcl_native_forward_live_command(
    const struct zcl_command_request *request, const char *datadir,
    const char *rpc_method, const char *fallback_code,
    const char *fallback_phase, const char *evidence,
    struct zcl_command_reply *reply)
{
    if (!request || !request->input || !datadir || !datadir[0] ||
        zdev_runtime_owns_ledger(datadir))
        return false;
    char db_path[ZDEV_PATH_MAX];
    int dn = snprintf(db_path, sizeof(db_path), "%s/node.db", datadir);
    if (dn <= 0 || (size_t)dn >= sizeof(db_path)) {
        zcl_command_reply_fail(
            reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_FAILED,
            "LIVE_OWNER_PROBE_FAILED", "ownership", false, false,
            "the selected database pathname could not be represented",
            evidence);
        return true;
    }
    enum node_db_owner_lease_probe owner =
        node_db_owner_lease_probe(db_path);
    if (owner == NODE_DB_OWNER_LEASE_UNOWNED ||
        owner == NODE_DB_OWNER_LEASE_OWNED_SELF)
        return false;
    if (owner == NODE_DB_OWNER_LEASE_PROBE_ERROR) {
        zcl_command_reply_fail(
            reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_FAILED,
            "LIVE_OWNER_PROBE_FAILED", "ownership", true, false,
            "the selected database owner could not be determined",
            evidence);
        return true;
    }
    int64_t encode_started_us = platform_time_monotonic_us();
    struct json_value params;
    json_init(&params); json_set_array(&params);
    bool built = json_push_back(&params, request->input);
    size_t needed = built ? json_write(&params, NULL, 0) : 0;
    char *wire = needed > 0 && needed < 256u * 1024u
        ? zcl_malloc(needed + 1u, "zcode.live_rpc") : NULL;
    if (!wire || json_write(&params, wire, needed + 1u) != needed) {
        free(wire); json_free(&params);
        zcl_command_reply_fail(
            reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_FAILED,
            "LIVE_ADMISSION_ENCODE_FAILED", "encode", false, false,
            "canonical live command input could not be encoded", evidence);
        return true;
    }
    json_free(&params);
    int64_t encode_us = platform_time_monotonic_us() - encode_started_us;
    zcl_native_bridge_ensure_rpc();
    int64_t rpc_started_us = platform_time_monotonic_us();
    char *raw = node_rpc_call(rpc_method, wire);
    int64_t rpc_us = platform_time_monotonic_us() - rpc_started_us;
    size_t response_bytes = raw ? strlen(raw) : 0;
    free(wire);
    int64_t decode_started_us = platform_time_monotonic_us();
    struct json_value body;
    bool parsed = raw && json_read(&body, raw, strlen(raw)) &&
                  body.type == JSON_OBJ;
    free(raw);
    if (!parsed) {
        json_free(&body);
        zcl_command_reply_fail(
            reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_FAILED,
            "LIVE_ADMISSION_UNAVAILABLE", "transport", true, false,
            "the selected full node did not answer the canonical command",
            evidence);
        return true;
    }
    const struct json_value *ok = json_get(&body, "ok");
    const struct json_value *data = json_get(&body, "data");
    if (ok && ok->type == JSON_BOOL && json_get_bool(ok) &&
        data && data->type == JSON_OBJ) {
        json_free(&reply->data);
        json_init(&reply->data);
        json_copy(&reply->data, data);
        (void)json_push_kv_int(&reply->data, "live_rpc_encode_us",
                               encode_us < 0 ? 0 : encode_us);
        (void)json_push_kv_int(&reply->data, "live_rpc_admission_us",
                               rpc_us < 0 ? 0 : rpc_us);
        (void)json_push_kv_int(&reply->data, "live_rpc_decode_us",
            platform_time_monotonic_us() - decode_started_us);
        (void)json_push_kv_int(&reply->data, "live_rpc_request_bytes",
                               (int64_t)needed);
        (void)json_push_kv_int(&reply->data, "live_rpc_response_bytes",
                               (int64_t)response_bytes);
    } else {
        const char *code = json_get_str(json_get(&body, "code"));
        const char *phase = json_get_str(json_get(&body, "phase"));
        const char *message = json_get_str(json_get(&body, "message"));
        const char *remote_evidence =
            json_get_str(json_get(&body, "evidence"));
        zcl_command_reply_fail(
            reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_FAILED,
            code && code[0] ? code : fallback_code,
            phase && phase[0] ? phase : fallback_phase,
            json_get_bool(json_get(&body, "retryable")),
            json_get_bool(json_get(&body, "mutated")),
            message && message[0] ? message :
                "the selected full node refused canonical admission",
            remote_evidence && remote_evidence[0]
                ? remote_evidence : evidence);
    }
    json_free(&body);
    return true;
}

static int64_t zdev_int(const struct json_value *input, const char *key,
                        int64_t fallback)
{
    const struct json_value *v = input ? json_get(input, key) : NULL;
    return v ? json_get_int(v) : fallback;
}

static void zdev_fail(struct zcl_command_reply *reply, const char *code,
                      const char *detail)
{
    zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                           ZCL_COMMAND_EXIT_INVALID, code, "validate", false,
                           false, detail, "zcode.improve");
}

static bool zdev_root(const struct json_value *input, const char *key,
                      uint8_t out[32], struct zcl_command_reply *reply)
{
    const char *value = zdev_str(input, key);
    if (value && zcl_hex_decode_lower(value, out, 32)) return true;
    char detail[128];
    (void)snprintf(detail, sizeof(detail), "%s must be 64 lowercase hex",
                   key);
    zdev_fail(reply, "BAD_ROOT", detail);
    return false;
}

static const char *zdev_task_mismatch_field(
    const char *workspace, const uint8_t planned_root[32],
    const struct vcs_zcode_task_v1 *actual)
{
    uint8_t *wire = NULL;
    size_t wire_len = 0;
    struct vcs_zcode_task_v1 planned;
    bool loaded = workspace && planned_root && actual &&
        vcs_object_load_raw_bounded(
            workspace, planned_root, VCS_ZCODE_TASK_WIRE_BYTES,
            &wire, &wire_len) == 0 &&
        vcs_zcode_task_parse(wire, wire_len, &planned) == VCS_ZCODE_DEV_OK;
    free(wire);
    if (!loaded) return "planned task object";
#define ZDEV_TASK_ROOT_DIFF(field) \
    if (memcmp(planned.field, actual->field, 32) != 0) return #field
    ZDEV_TASK_ROOT_DIFF(source_root);
    ZDEV_TASK_ROOT_DIFF(dependency_lock_root);
    ZDEV_TASK_ROOT_DIFF(toolchain_capsule_root);
    ZDEV_TASK_ROOT_DIFF(write_scope_root);
    ZDEV_TASK_ROOT_DIFF(acceptance_tests_root);
    ZDEV_TASK_ROOT_DIFF(proof_policy_root);
    ZDEV_TASK_ROOT_DIFF(model_policy_root);
    ZDEV_TASK_ROOT_DIFF(goal_root);
#undef ZDEV_TASK_ROOT_DIFF
#define ZDEV_TASK_VALUE_DIFF(field) \
    if (planned.field != actual->field) return #field
    ZDEV_TASK_VALUE_DIFF(schema_version);
    ZDEV_TASK_VALUE_DIFF(capabilities);
    ZDEV_TASK_VALUE_DIFF(max_changed_files);
    ZDEV_TASK_VALUE_DIFF(max_patch_bytes);
    ZDEV_TASK_VALUE_DIFF(max_context_bytes);
    ZDEV_TASK_VALUE_DIFF(max_cpu_seconds);
    ZDEV_TASK_VALUE_DIFF(max_memory_bytes);
    ZDEV_TASK_VALUE_DIFF(max_output_bytes);
    ZDEV_TASK_VALUE_DIFF(expires_unix);
#undef ZDEV_TASK_VALUE_DIFF
    return "canonical task bytes";
}

static void zdev_push_root(struct json_value *out, const char *key,
                           const uint8_t root[32])
{
    char hex[65];
    zcl_hex_encode(root, 32, hex);
    (void)json_push_kv_str(out, key, hex);
}

static uint8_t *zdev_hex_wire(const struct json_value *input, const char *key,
                              size_t max_bytes, size_t *len_out)
{
    *len_out = 0;
    const char *hex = zdev_str(input, key);
    size_t hex_len = hex ? strlen(hex) : 0;
    if (hex_len == 0 || (hex_len & 1u) != 0 ||
        hex_len > max_bytes * 2u)
        return NULL;
    size_t len = hex_len / 2u;
    uint8_t *wire = zcl_malloc(len, "zcode.improve.authority_wire");
    if (!wire || !zcl_hex_decode_lower(hex, wire, len)) {
        free(wire); return NULL;
    }
    *len_out = len;
    return wire;
}

static bool zdev_open_db(const char *datadir, struct node_db *ndb)
{
    char db_path[ZDEV_PATH_MAX];
    int n = datadir
        ? snprintf(db_path, sizeof(db_path), "%s/node.db", datadir) : -1;
    return n > 0 && (size_t)n < sizeof(db_path) &&
           node_db_open(ndb, db_path);
}

static bool zdev_capture_source_root(
    const char *workspace, uint8_t out[32], struct zcl_command_reply *reply)
{
    int captured = vcs_tree_capture_path(workspace, out);
    if (captured != VCS_OK) {
        zdev_fail(reply, "SOURCE_CAPTURE_FAILED",
                  "workspace changed or its source tree could not enter CAS");
        return false;
    }
    return true;
}

static bool zdev_capture_write_scope(
    const char *workspace, const char *csv, uint8_t out[32],
    struct zcl_command_reply *reply)
{
    size_t csv_len = csv ? strlen(csv) : 0;
    if (csv_len == 0 || csv_len > 4096u || csv[0] == ',' ||
        csv[csv_len - 1u] == ',' || strstr(csv, ",,") != NULL) {
        zdev_fail(reply, "BAD_WRITE_SCOPE",
                  "write_scope_csv must be a nonempty comma-separated path-prefix list");
        return false;
    }
    char copy[4097]; memcpy(copy, csv, csv_len + 1u);
    struct vcs_zcode_write_scope_v1 scope;
    vcs_zcode_write_scope_init(&scope);
    char *save = NULL;
    for (char *path = strtok_r(copy, ",", &save); path;
         path = strtok_r(NULL, ",", &save)) {
        if (vcs_zcode_write_scope_add(&scope, path) !=
            VCS_ZCODE_WRITE_SCOPE_OK) {
            zdev_fail(reply, "BAD_WRITE_SCOPE",
                      "write scope paths must be canonical, unique, and bounded");
            return false;
        }
    }
    uint8_t *wire = NULL; size_t wire_len = 0;
    if (vcs_zcode_write_scope_serialize(&scope, &wire, &wire_len) !=
            VCS_ZCODE_WRITE_SCOPE_OK ||
        vcs_zcode_write_scope_root(&scope, out) !=
            VCS_ZCODE_WRITE_SCOPE_OK ||
        !vcs_object_store_init(workspace) ||
        !vcs_object_put_addressed(workspace, out, wire, wire_len)) {
        free(wire);
        zdev_fail(reply, "WRITE_SCOPE_CAS_FAILED",
                  "canonical write scope could not enter workspace CAS");
        return false;
    }
    uint8_t *checked_wire = NULL; size_t checked_len = 0;
    uint8_t checked_root[32];
    struct vcs_zcode_write_scope_v1 checked;
    bool verified = vcs_object_load_raw(
            workspace, out, &checked_wire, &checked_len) == 0 &&
        checked_len == wire_len && memcmp(checked_wire, wire, wire_len) == 0 &&
        vcs_zcode_write_scope_parse(checked_wire, checked_len, &checked) ==
            VCS_ZCODE_WRITE_SCOPE_OK &&
        vcs_zcode_write_scope_root(&checked, checked_root) ==
            VCS_ZCODE_WRITE_SCOPE_OK && memcmp(checked_root, out, 32) == 0;
    free(checked_wire); free(wire);
    if (!verified) {
        zdev_fail(reply, "WRITE_SCOPE_CAS_FAILED",
                  "write scope CAS readback verification failed");
        return false;
    }
    return true;
}

static bool zdev_paths_overlap(const char *a, const char *b)
{
    size_t alen = strlen(a), blen = strlen(b);
    bool a_contains_b = blen >= alen && memcmp(a, b, alen) == 0 &&
        (blen == alen || b[alen] == '/');
    bool b_contains_a = alen >= blen && memcmp(b, a, blen) == 0 &&
        (alen == blen || a[blen] == '/');
    return a_contains_b || b_contains_a;
}

static bool zdev_candidate_input_path(
    const char *candidate_arg, const char *fixed_path, const char *claimed,
    char out[VCS_PATH_MAX + 1u], struct zcl_command_reply *reply)
{
    const char *selected = claimed;
    char candidate[ZDEV_PATH_MAX], fixed[ZDEV_PATH_MAX];
    if (fixed_path) {
        if (!candidate_arg || !realpath(candidate_arg, candidate) ||
            !realpath(fixed_path, fixed)) {
            zdev_fail(reply, "BAD_FIXED_INPUT",
                      "fixed input must resolve inside candidate_workspace");
            return false;
        }
        size_t candidate_len = strlen(candidate);
        if (strncmp(candidate, fixed, candidate_len) != 0 ||
            fixed[candidate_len] != '/' || fixed[candidate_len + 1u] == '\0') {
            zdev_fail(reply, "FIXED_INPUT_OUTSIDE_CANDIDATE",
                      "fixed input authority is limited to candidate_workspace");
            return false;
        }
        const char *derived = fixed + candidate_len + 1u;
        if (claimed && strcmp(claimed, derived) != 0) {
            zdev_fail(reply, "FIXED_INPUT_PATH_MISMATCH",
                      "fixed_input_relpath does not match fixed_input_path");
            return false;
        }
        selected = derived;
    }
    if (!selected || !vcs_package_path_valid(selected) ||
        strlen(selected) > VCS_PATH_MAX) {
        zdev_fail(reply, "BAD_FIXED_INPUT_PATH",
                  "fixed_input_relpath must be a canonical candidate path");
        return false;
    }
    (void)snprintf(out, VCS_PATH_MAX + 1u, "%s", selected);
    return true;
}

static bool zdev_load_write_scope(
    const char *workspace, const uint8_t root[32],
    struct vcs_zcode_write_scope_v1 *out)
{
    uint8_t *wire = NULL; size_t wire_len = 0;
    bool ok = vcs_object_load_raw(workspace, root, &wire, &wire_len) == 0 &&
        vcs_zcode_write_scope_parse(wire, wire_len, out) ==
            VCS_ZCODE_WRITE_SCOPE_OK;
    if (ok) {
        uint8_t checked[32];
        ok = vcs_zcode_write_scope_root(out, checked) ==
                VCS_ZCODE_WRITE_SCOPE_OK && memcmp(checked, root, 32) == 0;
    }
    free(wire);
    return ok;
}

static bool zdev_capture_candidate(
    const char *workspace, const char *candidate_arg,
    const struct vcs_zcode_task_v1 *task, uint8_t candidate_root[32],
    uint8_t patch_root[32], uint8_t source_sha256[32],
    uint32_t *changed_files, uint64_t *patch_bytes,
    struct zcl_command_reply *reply)
{
    char candidate_workspace[ZDEV_PATH_MAX]; struct stat st;
    if (!candidate_arg || !realpath(candidate_arg, candidate_workspace) ||
        stat(candidate_workspace, &st) != 0 || !S_ISDIR(st.st_mode) ||
        zdev_paths_overlap(workspace, candidate_workspace)) {
        zdev_fail(reply, "BAD_CANDIDATE_WORKSPACE",
                  "candidate_workspace must be an existing non-overlapping directory");
        return false;
    }
    if (vcs_tree_capture_into(candidate_workspace, workspace,
                              candidate_root) != VCS_OK) {
        zdev_fail(reply, "CANDIDATE_CAPTURE_FAILED",
                  "candidate workspace could not enter the requester's CAS");
        return false;
    }
    struct vcs_manifest base, candidate;
    if (!vcs_tree_load(workspace, task->source_root, &base)) {
        zdev_fail(reply, "BASE_SOURCE_STALE",
                  "planned source manifest is absent or corrupt");
        return false;
    }
    if (!vcs_tree_load(workspace, candidate_root, &candidate)) {
        vcs_manifest_free(&base);
        zdev_fail(reply, "CANDIDATE_SOURCE_CORRUPT",
                  "captured candidate manifest failed CAS verification");
        return false;
    }
    struct vcs_zcode_write_scope_v1 scope;
    if (!zdev_load_write_scope(workspace, task->write_scope_root, &scope)) {
        vcs_manifest_free(&candidate); vcs_manifest_free(&base);
        zdev_fail(reply, "WRITE_SCOPE_STALE",
                  "planned write scope is absent or corrupt");
        return false;
    }
    struct vcs_zcode_patch_v1 patch;
    enum vcs_zcode_patch_result derived = vcs_zcode_patch_derive(
        &base, task->source_root, &candidate, candidate_root, &scope,
        task->max_changed_files, task->max_patch_bytes, &patch);
    if (derived != VCS_ZCODE_PATCH_OK) {
        vcs_manifest_free(&candidate); vcs_manifest_free(&base);
        zdev_fail(reply,
                  derived == VCS_ZCODE_PATCH_SCOPE ? "PATCH_OUTSIDE_SCOPE" :
                  derived == VCS_ZCODE_PATCH_LIMIT ? "PATCH_LIMIT_EXCEEDED" :
                  "PATCH_DERIVATION_FAILED",
                  vcs_zcode_patch_result_string(derived));
        return false;
    }
    *changed_files = (uint32_t)patch.count;
    *patch_bytes = patch.content_bytes;
    uint8_t *wire = NULL; size_t wire_len = 0;
    bool stored = vcs_zcode_patch_serialize(&patch, &wire, &wire_len) ==
            VCS_ZCODE_PATCH_OK &&
        vcs_zcode_patch_root(&patch, patch_root) == VCS_ZCODE_PATCH_OK &&
        vcs_object_put_addressed(workspace, patch_root, wire, wire_len);
    if (stored) {
        uint8_t *checked_wire = NULL; size_t checked_len = 0;
        struct vcs_zcode_patch_v1 checked;
        uint8_t checked_root[32];
        bool parsed = false;
        stored = vcs_object_load_raw(workspace, patch_root, &checked_wire,
                                     &checked_len) == 0 &&
            checked_len == wire_len &&
            memcmp(checked_wire, wire, wire_len) == 0;
        if (stored) {
            parsed = vcs_zcode_patch_parse(checked_wire, checked_len,
                                           &checked) == VCS_ZCODE_PATCH_OK;
            stored = parsed && vcs_zcode_patch_root(&checked, checked_root) ==
                VCS_ZCODE_PATCH_OK && memcmp(checked_root, patch_root, 32) == 0;
        }
        if (parsed) vcs_zcode_patch_free(&checked);
        free(checked_wire);
    }
    uint8_t *manifest_wire = NULL; size_t manifest_len = 0;
    if (stored)
        stored = vcs_manifest_serialize(&candidate, &manifest_wire,
                                        &manifest_len);
    if (stored) {
        vcs_source_manifest_id(manifest_wire, manifest_len, source_sha256);
    }
    free(manifest_wire); free(wire);
    vcs_zcode_patch_free(&patch);
    vcs_manifest_free(&candidate); vcs_manifest_free(&base);
    if (!stored) {
        zdev_fail(reply, "PATCH_CAS_FAILED",
                  "canonical patch CAS readback verification failed");
        return false;
    }
    uint8_t current_base[32];
    if (vcs_tree_capture_path(workspace, current_base) != VCS_OK ||
        memcmp(current_base, task->source_root, 32) != 0) {
        zdev_fail(reply, "BASE_SOURCE_STALE",
                  "base workspace changed during candidate admission");
        return false;
    }
    return true;
}

static void zdev_push_lane(struct json_value *out,
                           const struct zcode_lane_status *status)
{
    (void)json_push_kv_str(out, "lane", status->lane_name);
    (void)json_push_kv_str(out, "source_root", status->source_root_sha3);
    (void)json_push_kv_str(out, "task_root", status->task_root_sha3);
    (void)json_push_kv_str(out, "candidate_root", status->candidate_root_sha3);
    (void)json_push_kv_str(out, "proof_policy_root",
                           status->proof_policy_root_sha3);
    (void)json_push_kv_str(out, "proof_set_root",
                           status->proof_set_root_sha3);
    (void)json_push_kv_str(out, "lane_receipt_root",
                           status->receipt_root_sha3);
    (void)json_push_kv_str(out, "prior_lane_receipt_root",
                           status->prior_receipt_root_sha3);
    (void)json_push_kv_str(out, "signer_pubkey", status->signer_pubkey);
    (void)json_push_kv_int(out, "created_unix", status->created_at);
    (void)json_push_kv_str(out, "lane_view_service_id",
                           ZCODE_LANE_VIEW_SERVICE_ID);
    (void)json_push_kv_int(out, "lane_view_service_generation",
                           status->view_service_generation);
    (void)json_push_kv_str(out, "capability", status->capability);
    (void)json_push_kv_str(out, "agent_next_action", status->next_action);
}

void zcl_native_handle_zcode_lane_guide(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    if (!request || !reply || !request->input ||
        request->input->type != JSON_OBJ || request->input->num_children != 0) {
        if (reply) zcl_command_reply_fail(
            reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INVALID,
            "BAD_LANE_GUIDE_INPUT", "guide", false, false,
            "zcode package dev promotion-guide accepts no input keys",
            "zcode.package.dev.promotion-guide");
        return;
    }
    struct zcl_hotswap_service_lease lease = {0};
    const struct zcode_lane_view_service_v1 *service =
        zcl_hotswap_service_acquire(ZCODE_LANE_VIEW_SERVICE_ID, &lease);
    if (!service) service = zcode_lane_view_service_builtin();
    struct zcode_lane_view_result_v1 view;
    uint32_t generation = zcl_hotswap_service_generation();
    bool rendered = service->render(ZCODE_LANE_VIEW_GUIDE, &view) &&
        view.valid && view.lane_name[0] && view.capability[0] &&
        view.next_action[0];
    zcl_hotswap_service_release(&lease);
    if (!rendered) {
        zcl_command_reply_fail(
            reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INVALID,
            "LANE_GUIDE_VIEW_FAILED", "render", false, false,
            "the pure lane view refused its frozen guide",
            "zcode.package.dev.promotion-guide");
        return;
    }
    (void)json_push_kv_bool(&reply->data, "ready", true);
    (void)json_push_kv_str(&reply->data, "lanes", view.lane_name);
    (void)json_push_kv_str(&reply->data, "capability", view.capability);
    (void)json_push_kv_str(&reply->data, "lane_view_service_id",
                           ZCODE_LANE_VIEW_SERVICE_ID);
    (void)json_push_kv_int(&reply->data, "lane_view_service_generation",
                           generation);
    (void)json_push_kv_bool(&reply->data, "cas_reads_static", true);
    (void)json_push_kv_bool(&reply->data, "database_projection_static", true);
    (void)json_push_kv_bool(&reply->data, "signature_verification_static", true);
    (void)json_push_kv_bool(&reply->data, "proof_evaluation_static", true);
    (void)json_push_kv_bool(&reply->data, "promotion_writes_swappable", false);
    (void)json_push_kv_str(&reply->data, "agent_next_action",
                           view.next_action);
}

static void zdev_push_agent_context(
    struct json_value *out, const struct zcode_agent_context_status *context)
{
    (void)json_push_kv_str(out, "agent_context_root",
                           context->context_root_sha3);
    (void)json_push_kv_str(out, "agent_context_source_tree_root",
                           context->source_tree_root_sha3);
    (void)json_push_kv_str(out, "agent_context_symbol",
                           context->resolved_symbol);
    (void)json_push_kv_int(out, "agent_context_files",
                           (int64_t)context->file_count);
    (void)json_push_kv_int(out, "agent_context_excerpt_bytes",
                           (int64_t)context->excerpt_bytes);
    (void)json_push_kv_int(out, "agent_context_wire_bytes",
                           (int64_t)context->wire_bytes);
    (void)json_push_kv_bool(out, "agent_context_truncated",
                            context->truncated);
}

void zcl_native_handle_zcode_create(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    if (!request || !reply) return;
    const char *mode = zdev_str(request->input, "mode");
    if (mode && strcmp(mode, "plan") == 0) {
        zcl_native_handle_zcode_package_publish_plan(request, reply);
        return;
    }
    if (mode && strcmp(mode, "commit") == 0) {
        zcl_native_handle_zcode_package_publish_commit(request, reply);
        return;
    }
    zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                           ZCL_COMMAND_EXIT_INVALID, "BAD_MODE", "normalize",
                           false, false, "mode must be plan or commit",
                           "zcode.create");
}

void zcl_native_handle_zcode_use(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    if (!request || !reply) return;
    if (zdev_str(request->input, "plan_id"))
        zcl_native_handle_zcode_package_add_commit(request, reply);
    else
        zcl_native_handle_zcode_package_add_plan(request, reply);
}

void zcl_native_handle_zcode_evidence(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    if (!request || !reply) return;
    const char *workspace_arg = zdev_str(request->input, "workspace");
    const char *action_id = zdev_str(request->input, "action_id");
    const char *datadir = zdev_str(request->input, "datadir");
    if (!datadir || !datadir[0]) datadir = zcl_native_command_datadir();
    if (zcl_native_forward_live_command(
            request, datadir, "zcode_work_evidence",
            "LIVE_EVIDENCE_FAILED", "evaluate", "zcode.evidence", reply))
        return;
    char workspace[ZDEV_PATH_MAX];
    uint8_t action_check[32];
    if (!workspace_arg || !realpath(workspace_arg, workspace) || !datadir ||
        !action_id || !zcl_hex_decode_lower(action_id, action_check, 32)) {
        zcl_command_reply_fail(
            reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INVALID,
            "BAD_EVIDENCE_INPUT", "validate", false, false,
            "workspace must resolve and action_id must be 64 lowercase hex",
            "zcode.evidence");
        return;
    }
    char db_path[ZDEV_PATH_MAX];
    int n = snprintf(db_path, sizeof(db_path), "%s/node.db", datadir);
    struct node_db local_ndb = {0};
    struct node_db *ndb = zdev_runtime_owns_ledger(datadir)
        ? app_runtime_node_db() : &local_ndb;
    bool owned = ndb != &local_ndb;
    if (n <= 0 || (size_t)n >= sizeof(db_path) ||
        (!owned && !node_db_open_existing_runtime(
            ndb, db_path, "zcode.evidence"))) {
        zcl_command_reply_fail(
            reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_FAILED,
            "DATABASE_OPEN_FAILED", "evaluate", true, false,
            "the ZBuild ledger could not be opened", "zcode.evidence");
        return;
    }
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
    (void)json_push_kv_str(&reply->data, "action_id", action_id);
    (void)json_push_kv_int(&reply->data, "valid_receipts",
                           (int64_t)evaluation.valid_receipts);
    (void)json_push_kv_int(&reply->data, "approved_distinct_signers",
                           (int64_t)evaluation.approved_distinct_signers);
    (void)json_push_kv_int(&reply->data, "matching_receipts",
                           (int64_t)evaluation.matching_receipts);
    (void)json_push_kv_int(&reply->data, "compile_receipts",
                           (int64_t)evaluation.compile_receipts);
    (void)json_push_kv_int(&reply->data, "test_receipts",
                           (int64_t)evaluation.test_receipts);
    (void)json_push_kv_int(&reply->data, "fuzz_receipts",
                           (int64_t)evaluation.fuzz_receipts);
    (void)json_push_kv_int(&reply->data, "review_receipts",
                           (int64_t)evaluation.review_receipts);
    (void)json_push_kv_bool(&reply->data, "local_reproduced",
                            evaluation.local_reproduced);
    (void)json_push_kv_bool(&reply->data, "quorum_satisfied",
                            evaluation.quorum_satisfied);
    (void)json_push_kv_bool(&reply->data, "compile_satisfied",
                            evaluation.compile_satisfied);
    (void)json_push_kv_bool(&reply->data, "test_satisfied",
                            evaluation.test_satisfied);
    (void)json_push_kv_bool(&reply->data, "fuzz_satisfied",
                            evaluation.fuzz_satisfied);
    (void)json_push_kv_bool(&reply->data, "review_satisfied",
                            evaluation.review_satisfied);
    (void)json_push_kv_bool(&reply->data, "release_identity_satisfied",
                            evaluation.release_identity_satisfied);
    (void)json_push_kv_bool(&reply->data, "policy_satisfied",
                            evaluation.policy_satisfied);
    (void)json_push_kv_str(&reply->data, "output_root",
                           evaluation.output_root_sha3);
    (void)json_push_kv_str(&reply->data, "proof_set_root",
                           evaluation.proof_set_root_sha3);
    (void)json_push_kv_str(&reply->data, "authority",
        evaluation.local_reproduced ? "LOCAL_REPRODUCTION" :
        evaluation.quorum_satisfied ? "APPROVED_SIGNER_QUORUM" :
        "UNTRUSTED");
    (void)json_push_kv_bool(&reply->data, "async_timings_available", timed.ok);
    if (timed.ok) {
        struct json_value latency;
        json_init(&latency); json_set_object(&latency);
        bool rendered = json_push_kv_int(
                &latency, "local_submit_us", timings.local_submit_us) &&
            json_push_kv_int(&latency, "peer_discovery_us",
                             timings.peer_discovery_us) &&
            json_push_kv_int(&latency, "transfer_us", timings.transfer_us) &&
            json_push_kv_int(&latency, "remote_queue_us",
                             timings.remote_queue_us) &&
            json_push_kv_int(&latency, "remote_execution_us",
                             timings.remote_execution_us) &&
            json_push_kv_int(&latency, "receipt_verification_us",
                             timings.receipt_verification_us) &&
            json_push_kv_int(&latency, "total_background_proof_us",
                             timings.total_background_proof_us) &&
            json_push_kv(&reply->data, "latency", &latency);
        json_free(&latency);
        if (!rendered)
            zdev_fail(reply, "TIMING_OUTPUT_FAILED",
                      "async proof timing report exceeded its bound");
    }
}

void zcl_native_handle_zcode_accept(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    if (!request || !reply) return;
    const char *workspace_arg = zdev_str(request->input, "workspace");
    const char *action_id = zdev_str(request->input, "action_id");
    const char *lane = zdev_str(request->input, "lane");
    const char *datadir = zdev_str(request->input, "datadir");
    if (!datadir || !datadir[0]) datadir = zcl_native_command_datadir();
    int target = lane && strcmp(lane, "CANDIDATE") == 0
        ? VCS_ZCODE_LANE_CANDIDATE : 0;
    char workspace[ZDEV_PATH_MAX];
    uint8_t action_root[32];
    if (!workspace_arg || !realpath(workspace_arg, workspace) ||
        !action_id || !zcl_hex_decode_lower(action_id, action_root, 32) ||
        !target) {
        zcl_command_reply_fail(
            reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INVALID,
            "BAD_ACCEPT_INPUT", "validate", false, false,
            "workspace and action_id are required; the expert lane may only be CANDIDATE; use zcode work accept for human PROVEN acceptance",
            "zcode.accept");
        return;
    }
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

void zcl_native_handle_zcode_lane(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    if (!request || !reply) return;
    const char *workspace_arg = zdev_str(request->input, "workspace");
    const char *source_root = zdev_str(request->input, "source_root");
    const char *datadir = zdev_str(request->input, "datadir");
    if (!datadir || !datadir[0]) datadir = zcl_native_command_datadir();
    char workspace[ZDEV_PATH_MAX];
    uint8_t root[32];
    if (!workspace_arg || !realpath(workspace_arg, workspace) ||
        !source_root || !zcl_hex_decode_lower(source_root, root, 32)) {
        zcl_command_reply_fail(
            reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INVALID,
            "BAD_LANE_INPUT", "validate", false, false,
            "workspace and a 64-hex source_root are required", "zcode.lane");
        return;
    }
    sqlite3 *db = NULL;
    struct node_db ndb = {0};
    if (!zcl_native_node_db_require_readonly(
            datadir, reply, "the ZCODE lane ledger", &db, &ndb))
        return;
    struct zcode_lane_status status;
    struct zcl_result found = zcode_lane_find(
        &ndb, workspace, source_root, &status);
    zcl_native_node_db_close_readonly(&db, &ndb);
    if (!found.ok) {
        zcl_command_reply_fail(
            reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_FAILED,
            "LANE_NOT_FOUND", "lookup", false, false,
            found.message, "zcode.lane");
        return;
    }
    zdev_push_lane(&reply->data, &status);
    (void)json_push_kv_str(&reply->data, "authority",
                           "SIGNED_CAS_RECEIPT");
}

#define ZDEV_TASKS_MAX_ROWS 256

static void zdev_task_row_json(struct json_value *row,
                               const struct vcs_zcode_task_index *index,
                               const struct vcs_zcode_task_index_entry *e)
{
    json_set_object(row);
    (void)json_push_kv_str(row, "task_root", e->task_root_hex);
    (void)json_push_kv_str(row, "source_root", e->source_root_hex);
    (void)json_push_kv_str(row, "goal_root", e->goal_root_hex);
    (void)json_push_kv_str(row, "proof_policy_root",
                           e->proof_policy_root_hex);
    (void)json_push_kv_str(row, "toolchain_capsule_root",
                           e->toolchain_capsule_root_hex);
    (void)json_push_kv_int(row, "expires_unix", e->expires_unix);
    (void)json_push_kv_bool(row, "expired", e->expired);
    (void)json_push_kv_str(row, "state", e->state);
    (void)json_push_kv_int(row, "candidate_count",
                           (int64_t)e->candidate_count);
    struct json_value candidates;
    json_init(&candidates);
    json_set_array(&candidates);
    for (size_t c = 0; c < vcs_zcode_task_index_candidate_count(index); c++) {
        const struct vcs_zcode_task_candidate_entry *candidate =
            vcs_zcode_task_index_candidate_at(index, c);
        if (strcmp(candidate->task_root_hex, e->task_root_hex) != 0)
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
    }
    (void)json_push_kv(row, "candidates", &candidates);
    json_free(&candidates);
}

void zcl_native_handle_zcode_tasks(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    if (!request || !reply) return;
    const char *workspace_arg = zdev_str(request->input, "workspace");
    char workspace[ZDEV_PATH_MAX];
    if (!workspace_arg || !realpath(workspace_arg, workspace)) {
        zcl_command_reply_fail(
            reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INVALID,
            "BAD_WORKSPACE", "validate", false, false,
            "workspace must resolve to an existing directory", "zcode.tasks");
        return;
    }
    int64_t limit = zdev_int(request->input, "limit", 100);
    if (limit < 1) limit = 1;
    if (limit > ZDEV_TASKS_MAX_ROWS) limit = ZDEV_TASKS_MAX_ROWS;
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
    json_init(&arr);
    json_set_array(&arr);
    for (size_t i = 0; i < rendered; i++) {
        struct json_value row;
        json_init(&row);
        zdev_task_row_json(&row, index, rows[i]);
        (void)json_push_back(&arr, &row);
        json_free(&row);
    }
    (void)json_push_kv(&reply->data, "tasks", &arr);
    json_free(&arr);
    (void)json_push_kv_int(&reply->data, "total_matches", (int64_t)total);
    (void)json_push_kv_int(&reply->data, "rendered", (int64_t)rendered);
    (void)json_push_kv_bool(&reply->data, "items_truncated", total > rendered);
    (void)json_push_kv_int(&reply->data, "tasks_scanned",
                           (int64_t)vcs_zcode_task_index_task_count(index));
    (void)json_push_kv_int(&reply->data, "candidates_scanned",
                           (int64_t)vcs_zcode_task_index_candidate_count(index));
    (void)json_push_kv_int(&reply->data, "limit", limit);
    (void)json_push_kv_str(&reply->data, "authority",
                           "CAS_TASK_AND_CANDIDATE_WIRES");
    vcs_zcode_task_index_free(index);
}

// long-function-ok:one-task-admission — canonical objects, CAS writes, and
// the ZBuild ledger commit form one fail-closed local admission transaction;
// no candidate or proof is claimed by this planning command.
void zcl_native_handle_zcode_improve(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    if (!request || !reply) return;
    int64_t submit_started_us = platform_time_monotonic_us();
    const char *workspace_arg = zdev_str(request->input, "workspace");
    const char *datadir = zdev_str(request->input, "datadir");
    if (!datadir || !datadir[0]) datadir = zcl_native_command_datadir();
    const char *goal = zdev_str(request->input, "goal");
    const char *policy_hex = zdev_str(request->input, "proof_policy_hex");
    const char *lock_hex = zdev_str(request->input, "dependency_lock_hex");
    const char *recipe_hex = zdev_str(request->input, "acceptance_recipe_hex");
    const char *mode_arg = zdev_str(request->input, "mode");
    const char *mode = mode_arg;
    if (!mode || !mode[0]) mode = "admit";
    bool plan_only = strcmp(mode, "plan") == 0;
    bool explicit_admit = mode_arg && strcmp(mode_arg, "admit") == 0;
    if (!plan_only && strcmp(mode, "admit") != 0) {
        zdev_fail(reply, "BAD_MODE", "mode must be plan or admit");
        return;
    }
    if (!plan_only && zcl_native_forward_live_command(
            request, datadir, "zcode_work_admit",
            "LIVE_ADMISSION_FAILED", "admit", "zcode.improve", reply))
        return;
    const char *context_symbol = zdev_str(request->input, "context_symbol");
    const char *planned_task_root =
        zdev_str(request->input, "planned_task_root");
    const char *planned_context_root =
        zdev_str(request->input, "planned_context_root");
    const char *write_scope_csv =
        zdev_str(request->input, "write_scope_csv");
    const char *action_kind = zdev_str(request->input, "action_kind");
    if (!action_kind || !action_kind[0])
        action_kind = VCS_BUILD_ACTION_KIND_V1;
    bool package_action =
        strcmp(action_kind, VCS_BUILD_ACTION_KIND_PACKAGE_V1) == 0;
    uint8_t work_kind = vcs_build_action_v1_work_kind(action_kind);
    if (work_kind != VCS_ZCODE_WORK_BUILD &&
        work_kind != VCS_ZCODE_WORK_TEST &&
        work_kind != VCS_ZCODE_WORK_FUZZ) {
        zdev_fail(reply, "BAD_ACTION_KIND",
                  "action_kind must name the fixed compile, recipe-package, test, or fuzz executor");
        return;
    }
    const char *fixed_input = zdev_str(request->input, "fixed_input_path");
    if (!fixed_input)
        fixed_input = zdev_str(request->input, "preprocessed_path");
    const char *fixed_input_relpath =
        zdev_str(request->input, "fixed_input_relpath");
    const char *candidate_workspace =
        zdev_str(request->input, "candidate_workspace");
    if (!workspace_arg || !datadir || !goal || !goal[0] ||
        strlen(goal) > 4096 || !policy_hex ||
        (plan_only && (!context_symbol || !context_symbol[0])) ||
        (explicit_admit &&
         (!context_symbol || !context_symbol[0] || !planned_task_root ||
          !planned_task_root[0] || !planned_context_root ||
          !planned_context_root[0])) ||
        ((plan_only || explicit_admit) &&
         (!write_scope_csv || !write_scope_csv[0] ||
          !lock_hex || !lock_hex[0] || !recipe_hex || !recipe_hex[0])) ||
        (explicit_admit &&
         (!candidate_workspace || !candidate_workspace[0])) ||
        (!plan_only && !package_action && !fixed_input &&
         !fixed_input_relpath)) {
        zdev_fail(reply, "MISSING_INPUT",
                  plan_only
                    ? "plan requires workspace, goal, proof policy, lock/recipe wires, and context_symbol"
                    : "explicit admit requires planned roots, candidate_workspace, context symbol, and a candidate-relative fixed input");
        return;
    }
    if (package_action &&
        ((fixed_input && fixed_input[0]) ||
         (fixed_input_relpath && fixed_input_relpath[0]))) {
        zdev_fail(reply, "BAD_ACTION_INPUT",
                  "recipe-package actions derive the whole candidate tree and accept no fixed executable");
        return;
    }
    char workspace[ZDEV_PATH_MAX];
    if (!realpath(workspace_arg, workspace)) {
        zdev_fail(reply, "BAD_WORKSPACE", "workspace must resolve to an existing directory");
        return;
    }
    struct vcs_zcode_proof_policy_v1 policy;
    uint8_t policy_wire[VCS_ZCODE_PROOF_POLICY_WIRE_BYTES];
    if (strlen(policy_hex) != sizeof(policy_wire) * 2u ||
        !zcl_hex_decode_lower(policy_hex, policy_wire, sizeof(policy_wire)) ||
        vcs_zcode_proof_policy_parse(policy_wire, sizeof(policy_wire),
                                     &policy) != VCS_ZCODE_DEV_OK ||
        !(policy.required_proofs & VCS_ZCODE_PROOF_COMPILE) ||
        (work_kind == VCS_ZCODE_WORK_TEST &&
         !(policy.required_proofs & VCS_ZCODE_PROOF_TEST)) ||
        (work_kind == VCS_ZCODE_WORK_FUZZ &&
         !(policy.required_proofs & VCS_ZCODE_PROOF_FUZZ))) {
        zdev_fail(reply, "BAD_PROOF_POLICY",
                  "proof_policy_hex must require compile and the requested proof kind");
        return;
    }
    uint8_t policy_root[32];
    if (vcs_zcode_proof_policy_root(&policy, policy_root) !=
        VCS_ZCODE_DEV_OK) {
        zdev_fail(reply, "BAD_PROOF_POLICY", "proof policy root refused");
        return;
    }
    struct vcs_zcode_task_v1 task = { .schema_version = VCS_ZCODE_DEV_VERSION };
    if (plan_only || explicit_admit) {
        if (!zdev_capture_source_root(workspace, task.source_root, reply))
            return;
        const char *claimed_source = zdev_str(request->input, "source_root");
        if (claimed_source && claimed_source[0]) {
            uint8_t claimed_root[32];
            if (!zcl_hex_decode_lower(claimed_source, claimed_root, 32) ||
                memcmp(claimed_root, task.source_root, 32) != 0) {
                zdev_fail(reply, "SOURCE_ROOT_MISMATCH",
                          "source_root does not match the captured workspace tree");
                return;
            }
        }
    } else if (!zdev_root(request->input, "source_root",
                          task.source_root, reply)) {
        return;
    }
    if (plan_only || explicit_admit) {
        size_t lock_len = 0, recipe_len = 0;
        uint8_t *lock_wire = zdev_hex_wire(
            request->input, "dependency_lock_hex",
            VCS_PACKAGE_LOCK_MAX_WIRE_BYTES, &lock_len);
        uint8_t *recipe_wire = zdev_hex_wire(
            request->input, "acceptance_recipe_hex",
            VCS_PACKAGE_RECIPE_MAX_WIRE_BYTES, &recipe_len);
        enum vcs_zcode_task_authority_result authority =
            lock_wire && recipe_wire
                ? vcs_zcode_task_authority_store(
                      workspace, lock_wire, lock_len, recipe_wire, recipe_len,
                      task.dependency_lock_root, task.acceptance_tests_root)
                : VCS_ZCODE_TASK_AUTHORITY_NULL;
        free(recipe_wire); free(lock_wire);
        if (authority != VCS_ZCODE_TASK_AUTHORITY_OK) {
            zdev_fail(reply, "TASK_AUTHORITY_REFUSED",
                vcs_zcode_task_authority_result_string(authority));
            return;
        }
        const char *claimed_lock =
            zdev_str(request->input, "dependency_lock_root");
        const char *claimed_recipe =
            zdev_str(request->input, "acceptance_tests_root");
        uint8_t claimed[32];
        if ((claimed_lock && claimed_lock[0] &&
             (!zcl_hex_decode_lower(claimed_lock, claimed, 32) ||
              memcmp(claimed, task.dependency_lock_root, 32) != 0)) ||
            (claimed_recipe && claimed_recipe[0] &&
             (!zcl_hex_decode_lower(claimed_recipe, claimed, 32) ||
              memcmp(claimed, task.acceptance_tests_root, 32) != 0))) {
            zdev_fail(reply, "TASK_AUTHORITY_ROOT_MISMATCH",
                      "claimed lock/acceptance roots do not match their wires");
            return;
        }
    } else if (!zdev_root(request->input, "dependency_lock_root",
                          task.dependency_lock_root, reply) ||
               !zdev_root(request->input, "acceptance_tests_root",
                          task.acceptance_tests_root, reply)) {
        return;
    }
    if (!zdev_root(request->input, "model_policy_root",
                   task.model_policy_root, reply))
        return;
    if (plan_only || explicit_admit) {
        if (!zdev_capture_write_scope(
                workspace, write_scope_csv, task.write_scope_root, reply))
            return;
        const char *claimed_scope =
            zdev_str(request->input, "write_scope_root");
        if (claimed_scope && claimed_scope[0]) {
            uint8_t claimed_root[32];
            if (!zcl_hex_decode_lower(claimed_scope, claimed_root, 32) ||
                memcmp(claimed_root, task.write_scope_root, 32) != 0) {
                zdev_fail(reply, "WRITE_SCOPE_ROOT_MISMATCH",
                          "write_scope_root does not match write_scope_csv");
                return;
            }
        }
    } else if (!zdev_root(request->input, "write_scope_root",
                          task.write_scope_root, reply)) {
        return;
    }
    memcpy(task.proof_policy_root, policy_root, 32);
    sha3_256((const uint8_t *)goal, strlen(goal), task.goal_root);
    struct vcs_toolchain_capsule_v1 capsule;
    if (!vcs_toolchain_capsule_v1_capture_gcc(&capsule) ||
        !vcs_toolchain_capsule_v1_root(&capsule,
                                       task.toolchain_capsule_root)) {
        zdev_fail(reply, "TOOLCHAIN_CAPTURE_FAILED",
                  "the fixed GCC toolchain capsule could not be captured");
        return;
    }
    task.capabilities = VCS_ZCODE_TASK_CAP_V1_MASK;
    task.max_changed_files = (uint32_t)zdev_int(
        request->input, "max_changed_files", 64);
    task.max_patch_bytes = (uint64_t)zdev_int(
        request->input, "max_patch_bytes", 16 * 1024 * 1024);
    task.max_context_bytes = (uint64_t)zdev_int(
        request->input, "max_context_bytes", 16 * 1024 * 1024);
    task.max_cpu_seconds = (uint32_t)zdev_int(
        request->input, "max_cpu_seconds", 600);
    task.max_memory_bytes = (uint64_t)zdev_int(
        request->input, "max_memory_bytes", UINT64_C(2048) * 1024u * 1024u);
    task.max_output_bytes = (uint64_t)zdev_int(
        request->input, "max_output_bytes", VCS_BUILD_ARTIFACT_MAX_BYTES);
    task.expires_unix = zdev_int(request->input, "expires_unix", 0);
    int64_t now = (int64_t)platform_time_wall_unix();
    if (vcs_zcode_task_validate_at(&task, now) != VCS_ZCODE_DEV_OK) {
        zdev_fail(reply, "TASK_INVALID", "task limits, capabilities, roots, or expiry are invalid");
        return;
    }
    enum vcs_zcode_task_authority_result task_authority =
        vcs_zcode_task_authority_validate(workspace, &task);
    if (task_authority != VCS_ZCODE_TASK_AUTHORITY_OK) {
        zdev_fail(reply, "TASK_AUTHORITY_STALE",
            vcs_zcode_task_authority_result_string(task_authority));
        return;
    }
    uint8_t task_wire[VCS_ZCODE_TASK_WIRE_BYTES], task_root[32];
    if (vcs_zcode_task_serialize(&task, task_wire) != VCS_ZCODE_DEV_OK ||
        vcs_zcode_task_root(&task, task_root) != VCS_ZCODE_DEV_OK) {
        zdev_fail(reply, "TASK_INVALID", "canonical task serialization failed");
        return;
    }
    uint8_t expected_task_root[32];
    if (explicit_admit &&
        (!zcl_hex_decode_lower(planned_task_root, expected_task_root, 32) ||
         memcmp(expected_task_root, task_root, 32) != 0)) {
        char detail[160];
        const char *field = zcl_hex_decode_lower(
            planned_task_root, expected_task_root, 32)
            ? zdev_task_mismatch_field(workspace, expected_task_root, &task)
            : "planned_task_root encoding";
        (void)snprintf(detail, sizeof(detail),
                       "admit parameters changed planned %s", field);
        zdev_fail(reply, "PLANNED_TASK_MISMATCH",
                  detail);
        return;
    }
    if (!vcs_object_store_init(workspace) ||
        !vcs_object_put_addressed(workspace, policy_root, policy_wire,
                                  sizeof(policy_wire)) ||
        !vcs_object_put_addressed(workspace, task.goal_root,
                                  (const uint8_t *)goal, strlen(goal)) ||
        !vcs_object_put_addressed(workspace, task_root, task_wire,
                                  sizeof(task_wire))) {
        zdev_fail(reply, "CAS_WRITE_FAILED",
                  "canonical task handoff could not be stored atomically");
        return;
    }
    struct zcode_agent_context_status agent_context = {0};
    bool agent_context_ready = false;
    if (context_symbol && context_symbol[0]) {
        struct zcl_result captured = zcode_agent_context_capture(
            workspace, &task, task_root, context_symbol, &agent_context);
        if (!captured.ok) {
            zdev_fail(reply, "AGENT_CONTEXT_FAILED", captured.message);
            return;
        }
        agent_context_ready = true;
    }
    uint8_t expected_context_root[32], actual_context_root[32];
    if (explicit_admit &&
        (!zcl_hex_decode_lower(planned_context_root,
                               expected_context_root, 32) ||
         !zcl_hex_decode_lower(agent_context.context_root_sha3,
                               actual_context_root, 32) ||
         memcmp(expected_context_root, actual_context_root, 32) != 0)) {
        zdev_fail(reply, "PLANNED_CONTEXT_MISMATCH",
                  "current source context does not match planned_context_root");
        return;
    }
    if (plan_only) {
        zdev_push_root(&reply->data, "task_root", task_root);
        zdev_push_root(&reply->data, "proof_policy_root", policy_root);
        zdev_push_root(&reply->data, "toolchain_capsule_root",
                       task.toolchain_capsule_root);
        zdev_push_root(&reply->data, "model_policy_root",
                       task.model_policy_root);
        zdev_push_root(&reply->data, "dependency_lock_root",
                       task.dependency_lock_root);
        zdev_push_root(&reply->data, "acceptance_tests_root",
                       task.acceptance_tests_root);
        zdev_push_root(&reply->data, "source_root", task.source_root);
        zdev_push_root(&reply->data, "write_scope_root",
                       task.write_scope_root);
        zdev_push_agent_context(&reply->data, &agent_context);
        (void)json_push_kv_str(&reply->data, "mode", "plan");
        (void)json_push_kv_str(&reply->data, "state",
                               "AWAITING_CANDIDATE");
        (void)json_push_kv_str(&reply->data, "authority",
                               "TASK_CONTEXT_AND_SCOPE_ROOTS");
        (void)json_push_kv_str(
            &reply->data, "next",
            "give the immutable task, agent_context, and write_scope roots to the user-selected adapter, then call mode=admit with its candidate roots; no model or tool authority is implied");
        return;
    }
    struct vcs_zcode_candidate_v1 candidate = {
        .schema_version = VCS_ZCODE_DEV_VERSION,
        .sequence = (uint64_t)zdev_int(request->input, "candidate_sequence", 1),
        .created_unix = zdev_int(
            request->input, "candidate_created_unix", now),
    };
    memcpy(candidate.task_root, task_root, 32);
    memcpy(candidate.base_source_root, task.source_root, 32);
    uint8_t source_sha_check[32]; char source_sha_hex[65];
    uint32_t changed_files = 0; uint64_t patch_bytes = 0;
    if (explicit_admit) {
        if (!zdev_capture_candidate(
                workspace, candidate_workspace, &task,
                candidate.candidate_source_root, candidate.patch_root,
                source_sha_check, &changed_files, &patch_bytes, reply)) {
            return;
        }
        const char *claimed_patch = zdev_str(request->input, "patch_root");
        const char *claimed_source =
            zdev_str(request->input, "candidate_source_root");
        uint8_t claim[32];
        if ((claimed_patch && claimed_patch[0] &&
             (!zcl_hex_decode_lower(claimed_patch, claim, 32) ||
              memcmp(claim, candidate.patch_root, 32) != 0)) ||
            (claimed_source && claimed_source[0] &&
             (!zcl_hex_decode_lower(claimed_source, claim, 32) ||
              memcmp(claim, candidate.candidate_source_root, 32) != 0))) {
            zdev_fail(reply, "CANDIDATE_ROOT_MISMATCH",
                      "claimed candidate roots do not match the captured workspace");
            return;
        }
        zcl_hex_encode(source_sha_check, 32, source_sha_hex);
        const char *claimed_sha =
            zdev_str(request->input, "candidate_source_sha256");
        if (claimed_sha && claimed_sha[0] &&
            (!zcl_hex_decode_lower(claimed_sha, claim, 32) ||
             memcmp(claim, source_sha_check, 32) != 0)) {
            zdev_fail(reply, "CANDIDATE_SHA256_MISMATCH",
                      "candidate_source_sha256 does not match the canonical candidate manifest");
            return;
        }
    } else if (!zdev_root(request->input, "patch_root", candidate.patch_root,
                          reply) ||
               !zdev_root(request->input, "candidate_source_root",
                          candidate.candidate_source_root, reply)) {
        return;
    }
    if (!zdev_root(request->input, "adapter_policy_root",
                   candidate.adapter_policy_root, reply) ||
        !zdev_root(request->input, "author_pubkey", candidate.author_pubkey,
                   reply)) {
        return;
    }
    uint8_t candidate_wire[VCS_ZCODE_CANDIDATE_WIRE_BYTES];
    uint8_t candidate_root[32];
    if (vcs_zcode_candidate_validate_for_task(&task, &candidate, now) !=
            VCS_ZCODE_DEV_OK ||
        vcs_zcode_candidate_serialize(&candidate, candidate_wire) !=
            VCS_ZCODE_DEV_OK ||
        vcs_zcode_candidate_root(&candidate, candidate_root) !=
            VCS_ZCODE_DEV_OK) {
        zdev_fail(reply, "CANDIDATE_INVALID",
                  "canonical candidate serialization failed");
        return;
    }
    task_authority = vcs_zcode_task_authority_validate_for_candidate(
        workspace, &task, &candidate);
    if (task_authority != VCS_ZCODE_TASK_AUTHORITY_OK) {
        zdev_fail(reply, "CANDIDATE_RECIPE_REFUSED",
            vcs_zcode_task_authority_result_string(task_authority));
        return;
    }
    char input_path[VCS_PATH_MAX + 1u] = {0};
    uint8_t *input_wire = NULL; size_t input_len = 0; uint8_t input_root[32];
    enum vcs_zcode_action_input_result input_result;
    const char *input_schema;
    if (package_action) {
        struct vcs_zcode_package_action_input_v1 package_input;
        input_result = vcs_zcode_package_action_input_derive(
            workspace, task_root, candidate_root, &task, &candidate,
            &package_input);
        input_len = VCS_ZCODE_PACKAGE_ACTION_INPUT_WIRE_BYTES;
        input_wire = zcl_malloc(input_len, "zcode.package_action_input");
        if (input_result == VCS_ZCODE_ACTION_INPUT_OK && !input_wire)
            input_result = VCS_ZCODE_ACTION_INPUT_ALLOC;
        if (input_result == VCS_ZCODE_ACTION_INPUT_OK)
            input_result = vcs_zcode_package_action_input_serialize(
                &package_input, input_wire);
        if (input_result == VCS_ZCODE_ACTION_INPUT_OK)
            input_result = vcs_zcode_package_action_input_root(
                &package_input, input_root);
        input_schema = "zcl.zcode.package_action_input.v1";
    } else {
        if (!zdev_candidate_input_path(
                candidate_workspace, fixed_input, fixed_input_relpath,
                input_path, reply))
            return;
        struct vcs_zcode_action_input_v1 bound_input;
        input_result = vcs_zcode_action_input_derive_cas(
            workspace, task_root, candidate_root, &task, &candidate,
            work_kind, input_path, &bound_input);
        if (input_result == VCS_ZCODE_ACTION_INPUT_OK)
            input_result = vcs_zcode_action_input_serialize(
                &bound_input, &input_wire, &input_len);
        if (input_result == VCS_ZCODE_ACTION_INPUT_OK)
            input_result = vcs_zcode_action_input_root(
                &bound_input, input_root);
        vcs_zcode_action_input_free(&bound_input);
        input_schema = "zcl.zcode.action_input.v1";
    }
    if (input_result == VCS_ZCODE_ACTION_INPUT_OK &&
        input_len > task.max_context_bytes)
        input_result = VCS_ZCODE_ACTION_INPUT_LIMIT;
    uint8_t candidate_current[32];
    bool candidate_stable = !explicit_admit ||
        (vcs_tree_capture_into(candidate_workspace, workspace,
                               candidate_current) == VCS_OK &&
         memcmp(candidate_current, candidate.candidate_source_root, 32) == 0);
    if (input_result != VCS_ZCODE_ACTION_INPUT_OK || !candidate_stable) {
        free(input_wire);
        zdev_fail(reply,
                  candidate_stable ? "CANDIDATE_INPUT_REFUSED" :
                                     "CANDIDATE_SOURCE_STALE",
                  candidate_stable
                    ? vcs_zcode_action_input_result_string(input_result)
                    : "candidate workspace changed during action input capture");
        return;
    }
    if (!vcs_object_put_addressed(workspace, input_root, input_wire,
                                  input_len) ||
        !vcs_object_put_addressed(workspace, candidate_root, candidate_wire,
                                  sizeof(candidate_wire))) {
        free(input_wire);
        zdev_fail(reply, "CAS_WRITE_FAILED", "canonical task inputs could not be stored atomically");
        return;
    }
    free(input_wire);

    const char *source_sha256 = explicit_admit ? source_sha_hex :
        zdev_str(request->input, "candidate_source_sha256");
    if (!explicit_admit && (!source_sha256 ||
        !zcl_hex_decode_lower(source_sha256, source_sha_check, 32))) {
        zdev_fail(reply, "BAD_SOURCE_SHA256",
                  "candidate_source_sha256 must be 64 lowercase hex");
        return;
    }
    struct db_build_job job = {0};
    struct db_build_action action = {0};
    int64_t remote_peer = zdev_int(request->input, "remote_peer", 0);
    if (remote_peer < 0) {
        zdev_fail(reply, "BAD_REMOTE_PEER",
                  "remote_peer must be zero for discovery or a positive peer hint");
        return;
    }
    (void)snprintf(job.source_sha256, sizeof(job.source_sha256), "%s",
                   source_sha256);
    zcl_hex_encode(candidate.candidate_source_root, 32, job.source_cas_sha3);
    zcl_hex_encode(task.toolchain_capsule_root, 32, job.toolchain_sha3);
    const char *profile = zdev_str(request->input, "profile");
    (void)snprintf(job.profile, sizeof(job.profile), "%s",
                   profile && profile[0] ? profile : "dev");
    (void)snprintf(job.state, sizeof(job.state), "PLANNED");
    job.created_at = job.updated_at = now;
    action.sequence = 0;
    (void)snprintf(action.kind, sizeof(action.kind), "%s",
                   action_kind);
    (void)snprintf(action.state, sizeof(action.state), "SNAPSHOTTED");
    zcl_hex_encode(input_root, 32, action.input_root_sha3);
    zcl_hex_encode(task_root, 32, action.task_root_sha3);
    zcl_hex_encode(candidate_root, 32, action.candidate_root_sha3);
    zcl_hex_encode(policy_root, 32, action.proof_policy_root_sha3);
    (void)snprintf(action.target, sizeof(action.target), "%s",
                   VCS_BUILD_TARGET_V1);
    uint8_t fixed_flags[32], fixed_environment[32];
    const char *workdir = NULL, *output = NULL, *resource = NULL;
    if (!vcs_build_action_v1_descriptors(
            action_kind, &workdir, &output, &resource) ||
        !vcs_build_action_v1_fixed_flags_root_for_kind(
            action_kind, fixed_flags) ||
        !vcs_build_action_v1_fixed_environment_root_for_kind(
            action_kind, fixed_environment)) {
        zdev_fail(reply, "ACTION_DESCRIPTOR_FAILED",
                  "fixed action descriptor is unavailable");
        return;
    }
    zcl_hex_encode(fixed_flags, 32, action.flags_sha3);
    zcl_hex_encode(fixed_environment, 32, action.environment_sha3);
    (void)snprintf(action.virtual_workdir, sizeof(action.virtual_workdir),
                   "%s", workdir);
    (void)snprintf(action.declared_outputs, sizeof(action.declared_outputs),
                   "%s", output);
    (void)snprintf(action.resource_policy, sizeof(action.resource_policy),
                   "%s", resource);
    action.created_at = action.updated_at = now;
    if (!build_fabric_action_id(&job, &action, action.action_id).ok ||
        !build_fabric_job_id(&job, action.action_id, job.job_id).ok) {
        zdev_fail(reply, "ACTION_ID_FAILED", "fixed build action identity refused");
        return;
    }
    int64_t request_creation_us =
        platform_time_monotonic_us() - submit_started_us;
    (void)snprintf(action.job_id, sizeof(action.job_id), "%s", job.job_id);
    int64_t ledger_started_us = platform_time_monotonic_us();
    char db_path[ZDEV_PATH_MAX];
    int dbn = snprintf(db_path, sizeof(db_path), "%s/node.db", datadir);
    struct node_db local_ndb = {0};
    struct node_db *ndb = zdev_runtime_owns_ledger(datadir)
        ? app_runtime_node_db() : &local_ndb;
    bool owned = ndb != &local_ndb;
    if (dbn <= 0 || (size_t)dbn >= sizeof(db_path) ||
        (!owned && !zdev_open_build_ledger(
            ndb, db_path, "zcode.improve"))) {
        zdev_fail(reply, "DATABASE_OPEN_FAILED", "cannot open the task's ZBuild ledger");
        return;
    }
    struct zcl_result planned = build_fabric_plan(ndb, &job, &action);
    bool reproduction_needed = owned && package_action &&
        (policy.minimum_compile_receipts >= 2u ||
         policy.minimum_test_receipts >= 2u);
    char reproduction_action_id[BUILD_FABRIC_ID_HEX + 1] = {0};
    char reproduction_job_id[BUILD_FABRIC_ID_HEX + 1] = {0};
    struct zcl_result reproduction_planned = planned;
    if (planned.ok && reproduction_needed)
        reproduction_planned = build_fabric_plan_reproduction(
            ndb, action.action_id,
            VCS_BUILD_PACKAGE_PROFILE_STANDARD_B_V1, now,
            reproduction_action_id, reproduction_job_id);
    struct zcode_lane_status frontier_status = {0};
    struct db_build_worker frontier_signer;
    uint8_t frontier_secret[32] = {0}, frontier_pubkey[32] = {0};
    struct zcl_result admitted = reproduction_planned;
    if (reproduction_planned.ok) {
        admitted = build_fabric_worker_identity_load(
            datadir, &frontier_signer, frontier_secret, frontier_pubkey);
        if (admitted.ok)
            admitted = zcode_lane_advance(
                ndb, workspace, action.action_id, VCS_ZCODE_LANE_FRONTIER,
                now, frontier_secret, frontier_pubkey, &frontier_status);
    }
    memset(frontier_secret, 0, sizeof(frontier_secret));
    /* The runtime-owned action is immutable input for peer proof, not local
     * worker work. Keeping its canonical state SNAPSHOTTED prevents the
     * requester daemon from racing the selected peer and masking missing
     * remote evidence. Offline fixture ledgers retain explicit QUEUED
     * behavior for the local build-fabric interface. */
    struct zcl_result submitted = admitted.ok && owned
        ? ZCL_OK : admitted.ok ? build_fabric_submit(ndb, job.job_id, now)
                               : admitted;
    struct db_build_proof_event proof_request = {0};
    bool proof_request_created = false;
    int64_t request_elapsed_us =
        platform_time_monotonic_us() - submit_started_us;
    struct zcl_result proof_requested = submitted.ok
        ? build_fabric_proof_request(
              ndb, action.action_id, workspace, (uint64_t)remote_peer,
              request_elapsed_us < 0 ? 0 : request_elapsed_us, now,
              &proof_request, &proof_request_created)
        : submitted;
    struct db_build_proof_event reproduction_request = {0};
    bool reproduction_request_created = false;
    struct zcl_result reproduction_requested = proof_requested;
    if (proof_requested.ok && reproduction_needed)
        reproduction_requested = build_fabric_proof_request(
            ndb, reproduction_action_id, workspace, 0,
            request_elapsed_us < 0 ? 0 : request_elapsed_us, now,
            &reproduction_request, &reproduction_request_created);
    int64_t local_submit_us = platform_time_monotonic_us() - submit_started_us;
    int64_t ledger_us = platform_time_monotonic_us() - ledger_started_us;
    if (!owned) node_db_close(ndb);
    if (!planned.ok || !reproduction_planned.ok || !admitted.ok ||
        !submitted.ok || !proof_requested.ok || !reproduction_requested.ok) {
        const char *code = !planned.ok ? "ZBUILD_PLAN_FAILED" :
            !reproduction_planned.ok ? "REPRODUCTION_PLAN_FAILED" :
            !admitted.ok ? "FRONTIER_ADMISSION_FAILED" :
            !submitted.ok ? "ZBUILD_SUBMIT_FAILED" :
            !proof_requested.ok ? "ASYNC_PROOF_REQUEST_FAILED" :
            "REPRODUCTION_REQUEST_FAILED";
        zdev_fail(reply, code,
                  !planned.ok ? planned.message :
                  !reproduction_planned.ok ? reproduction_planned.message :
                  !admitted.ok ? admitted.message :
                  !submitted.ok ? submitted.message :
                  !proof_requested.ok ? proof_requested.message :
                  reproduction_requested.message);
        return;
    }
    LOG_INFO("zcode.proof_perf",
             "schema=zcl.async_proof_perf.v1 action=%s "
             "stage=foreground_return at_unix_us=%lld "
             "request_creation_us=%lld durable_lookup_dedup_us=%lld "
             "local_submit_us=%lld dedup_hit=%d",
             action.action_id, (long long)platform_time_realtime_us(),
             (long long)(request_creation_us < 0 ? 0 : request_creation_us),
             (long long)(ledger_us < 0 ? 0 : ledger_us),
             (long long)(local_submit_us < 0 ? 0 : local_submit_us),
             proof_request_created ? 0 : 1);
    zdev_push_root(&reply->data, "task_root", task_root);
    zdev_push_root(&reply->data, "candidate_root", candidate_root);
    zdev_push_root(&reply->data, "candidate_source_root",
                   candidate.candidate_source_root);
    zdev_push_root(&reply->data, "patch_root", candidate.patch_root);
    zdev_push_root(&reply->data, "proof_policy_root", policy_root);
    zdev_push_root(&reply->data, "toolchain_capsule_root",
                   task.toolchain_capsule_root);
    zdev_push_root(&reply->data, "input_root", input_root);
    if (!package_action)
        (void)json_push_kv_str(&reply->data, "fixed_input_relpath", input_path);
    (void)json_push_kv_str(&reply->data, "input_schema", input_schema);
    (void)json_push_kv_str(&reply->data, "job_id", job.job_id);
    (void)json_push_kv_str(&reply->data, "action_id", action.action_id);
    (void)json_push_kv_str(&reply->data, "action_kind", action_kind);
    (void)json_push_kv_int(&reply->data, "candidate_created_unix",
                           candidate.created_unix);
    (void)json_push_kv_str(&reply->data, "candidate_source_sha256",
                           source_sha256);
    (void)json_push_kv_str(&reply->data, "source_sha256_schema",
                           explicit_admit
                             ? VCS_SOURCE_MANIFEST_ID_SCHEMA
                             : "caller-provided-legacy");
    if (explicit_admit) {
        (void)json_push_kv_int(&reply->data, "changed_files",
                               changed_files);
        (void)json_push_kv_int(&reply->data, "patch_content_bytes",
                               (int64_t)patch_bytes);
    }
    (void)json_push_kv_str(&reply->data, "state",
                           owned ? "SNAPSHOTTED" : "QUEUED");
    (void)json_push_kv_str(&reply->data, "lane", frontier_status.lane_name);
    (void)json_push_kv_str(&reply->data, "lane_receipt_root",
                           frontier_status.receipt_root_sha3);
    if (agent_context_ready)
        zdev_push_agent_context(&reply->data, &agent_context);
    (void)json_push_kv_str(&reply->data, "mode", "admit");
    (void)json_push_kv_str(&reply->data, "async_proof_state",
                           proof_request.state);
    (void)json_push_kv_str(&reply->data, "async_proof_event_root",
                           proof_request.event_root);
    (void)json_push_kv_int(&reply->data, "remote_request_id",
                           (int64_t)proof_request.request_id);
    (void)json_push_kv_bool(&reply->data, "request_deduplicated",
                            !proof_request_created);
    if (reproduction_needed) {
        (void)json_push_kv_str(&reply->data, "reproduction_action_id",
                               reproduction_action_id);
        (void)json_push_kv_str(&reply->data, "reproduction_job_id",
                               reproduction_job_id);
        (void)json_push_kv_str(
            &reply->data, "reproduction_async_proof_event_root",
            reproduction_request.event_root);
        (void)json_push_kv_int(
            &reply->data, "reproduction_remote_request_id",
            (int64_t)reproduction_request.request_id);
        (void)json_push_kv_bool(
            &reply->data, "reproduction_request_deduplicated",
            !reproduction_request_created);
    }
    (void)json_push_kv_int(&reply->data, "foreground_request_creation_us",
                           request_creation_us < 0 ? 0 : request_creation_us);
    (void)json_push_kv_int(&reply->data,
                           "durable_action_lookup_dedup_us",
                           ledger_us < 0 ? 0 : ledger_us);
    (void)json_push_kv_int(&reply->data, "local_submit_us",
                           local_submit_us < 0 ? 0 : local_submit_us);
    (void)json_push_kv_int(&reply->data, "local_first_feedback_us",
                           local_submit_us < 0 ? 0 : local_submit_us);
    (void)json_push_kv_str(&reply->data, "remote_outcome",
                           "BACKGROUND_PENDING");
    (void)json_push_kv_str(
        &reply->data, "next",
        "an enabled local or P2P worker may produce the candidate-bound fixed-action receipt; evidence evaluation, explicit acceptance, and publication remain required");
}


/* ── zcode publish — publish an explicit PROVEN accepted work as a signed release ──
 *
 * The signed lane receipt in the workspace CAS is the acceptance authority:
 * it is reloaded and re-verified (Ed25519 signature, cross-object
 * task/candidate/policy roots, the evaluated proof set) before anything is
 * built — caller claims are never trusted. The ordinary content.v2 package
 * carries a compressed, fully rederivable ZVCS tree plus the exact lane
 * receipt wire, so the signed release binds the accepted source root and,
 * through the receipt, the proof-set and task roots. Its declarative recipe
 * builds only the inert carrier marker; the task's independently verified
 * acceptance recipe remains the authority for the accepted product. Commit
 * runs through the existing
 * zcode.package.publish commit handler: one lifecycle, one store, one
 * rebuildable index. No second package format or task table is created. */

#define ZPUB_PATH_MAX 4400

static void zpub_fail(struct zcl_command_reply *reply, const char *code,
                      const char *detail)
{
    zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                           ZCL_COMMAND_EXIT_INVALID, code, "validate", false,
                           false, detail, "zcode.publish");
}

static bool zpub_load_wire(const char *workspace, const char *hex,
                           uint8_t **wire, size_t *wire_len, uint8_t root[32])
{
    return zcl_hex_decode_lower(hex, root, 32) &&
           vcs_object_load_raw(workspace, root, wire, wire_len) == 0;
}

static bool zpub_load_task(const char *workspace, const char *hex,
                           struct vcs_zcode_task_v1 *out)
{
    uint8_t *wire = NULL, root[32], checked[32];
    size_t len = 0;
    bool ok = zpub_load_wire(workspace, hex, &wire, &len, root) &&
        vcs_zcode_task_parse(wire, len, out) == VCS_ZCODE_DEV_OK &&
        vcs_zcode_task_validate(out) == VCS_ZCODE_DEV_OK &&
        vcs_zcode_task_root(out, checked) == VCS_ZCODE_DEV_OK &&
        memcmp(root, checked, 32) == 0;
    free(wire);
    return ok;
}

static bool zpub_load_candidate(const char *workspace, const char *hex,
                                struct vcs_zcode_candidate_v1 *out)
{
    uint8_t *wire = NULL, root[32], checked[32];
    size_t len = 0;
    bool ok = zpub_load_wire(workspace, hex, &wire, &len, root) &&
        vcs_zcode_candidate_parse(wire, len, out) == VCS_ZCODE_DEV_OK &&
        vcs_zcode_candidate_validate(out) == VCS_ZCODE_DEV_OK &&
        vcs_zcode_candidate_root(out, checked) == VCS_ZCODE_DEV_OK &&
        memcmp(root, checked, 32) == 0;
    free(wire);
    return ok;
}

static bool zpub_load_policy(const char *workspace, const char *hex,
                             struct vcs_zcode_proof_policy_v1 *out)
{
    uint8_t *wire = NULL, root[32], checked[32];
    size_t len = 0;
    bool ok = zpub_load_wire(workspace, hex, &wire, &len, root) &&
        vcs_zcode_proof_policy_parse(wire, len, out) == VCS_ZCODE_DEV_OK &&
        vcs_zcode_proof_policy_validate(out) == VCS_ZCODE_DEV_OK &&
        vcs_zcode_proof_policy_root(out, checked) == VCS_ZCODE_DEV_OK &&
        memcmp(root, checked, 32) == 0;
    free(wire);
    return ok;
}

/* Load the signed lane receipt, re-derive its id, and verify its Ed25519
 * signature against the candidate's pinned work-authority signer. Keeps the
 * exact CAS wire: it is published as the canonical authority file. */
static bool zpub_load_lane_receipt(
    const char *workspace, const char *hex,
    struct vcs_zcode_lane_receipt_v1 *out,
    const uint8_t expected_signer[32],
    uint8_t wire_out[VCS_ZCODE_LANE_WIRE_BYTES])
{
    uint8_t *wire = NULL, root[32], checked[32];
    size_t len = 0;
    bool ok = zpub_load_wire(workspace, hex, &wire, &len, root) &&
        len == VCS_ZCODE_LANE_WIRE_BYTES &&
        vcs_zcode_lane_receipt_parse(wire, len, out) == VCS_ZCODE_DEV_OK &&
        vcs_zcode_lane_receipt_id(out, checked) == VCS_ZCODE_DEV_OK &&
        memcmp(root, checked, 32) == 0 &&
        vcs_zcode_lane_receipt_verify(out, expected_signer) ==
            VCS_ZCODE_DEV_OK;
    if (ok)
        memcpy(wire_out, wire, len);
    free(wire);
    return ok;
}

/* The accepted proof set must re-derive its bound root from CAS bytes. */
static bool zpub_proof_set_valid(
    const char *workspace, const char *hex,
    const struct vcs_zcode_task_v1 *task,
    const struct vcs_zcode_candidate_v1 *candidate)
{
    uint8_t *wire = NULL, root[32], checked[32];
    size_t len = 0, count = 0;
    uint8_t (*roots)[32] =
        zcl_malloc(sizeof(*roots) * VCS_ZCODE_PROOF_SET_MAX_RECEIPTS,
                   "zcode.publish.proof_set");
    bool ok = roots != NULL;
    if (ok)
        ok = zpub_load_wire(workspace, hex, &wire, &len, root) &&
            vcs_zcode_proof_set_parse(
                wire, len, roots, VCS_ZCODE_PROOF_SET_MAX_RECEIPTS,
                &count) == VCS_ZCODE_DEV_OK &&
            vcs_zcode_proof_set_root(
                (const uint8_t (*)[32])roots, count,
                checked) == VCS_ZCODE_DEV_OK &&
            memcmp(root, checked, 32) == 0;
    for (size_t i = 0; ok && i < count; i++) {
        uint8_t *receipt_wire = NULL;
        size_t receipt_len = 0;
        struct vcs_zcode_work_receipt_v1 receipt;
        uint8_t receipt_id[32];
        ok = vcs_object_load_raw(workspace, roots[i], &receipt_wire,
                                 &receipt_len) == 0 &&
            vcs_zcode_work_receipt_parse(receipt_wire, receipt_len,
                                         &receipt) == VCS_ZCODE_DEV_OK &&
            vcs_zcode_work_receipt_validate(&receipt) == VCS_ZCODE_DEV_OK &&
            vcs_zcode_work_receipt_id(&receipt, receipt_id) ==
                VCS_ZCODE_DEV_OK &&
            memcmp(receipt_id, roots[i], 32) == 0 &&
            vcs_zcode_work_receipt_verify(&receipt,
                                          receipt.signer_pubkey) ==
                VCS_ZCODE_DEV_OK &&
            vcs_zcode_work_receipt_validate_for_candidate(
                task, candidate, &receipt, receipt.finished_unix) ==
                VCS_ZCODE_DEV_OK;
        free(receipt_wire);
    }
    free(roots);
    free(wire);
    return ok;
}

/* Write one staged file beneath dir, creating intermediate directories. The
 * relative path is already grammar-validated (canonical, no traversal). */
static bool zpub_stage_file(const char *dir, const char *relpath,
                            const uint8_t *bytes, size_t len)
{
    char path[ZPUB_PATH_MAX];
    int n = snprintf(path, sizeof(path), "%s/%s", dir, relpath);
    if (n <= 0 || (size_t)n >= sizeof(path))
        return false;
    for (char *p = path + strlen(dir) + 1u; *p; p++) {
        if (*p != '/')
            continue;
        *p = '\0';
        bool made = mkdir(path, 0700) == 0 || errno == EEXIST;
        *p = '/';
        if (!made)
            return false;
    }
    FILE *f = fopen(path, "wb");
    if (!f)
        return false;
    bool ok = len == 0 || fwrite(bytes, 1, len, f) == len;
    return fclose(f) == 0 && ok;
}

static bool zpub_stage_transport(
    const char *dir, const struct vcs_source_package_transport *transport)
{
    size_t count = vcs_source_package_transport_file_count(transport);
    for (size_t i = 0; i < count; i++) {
        const char *path = NULL;
        const uint8_t *bytes = NULL;
        size_t len = 0;
        if (!vcs_source_package_transport_file_at(
                transport, i, &path, &bytes, &len) ||
            !zpub_stage_file(dir, path, bytes, len))
            return false;
    }
    return true;
}

static void zpub_stage_cleanup(
    const char *dir, const struct vcs_source_package_transport *transport)
{
    char path[ZPUB_PATH_MAX];
    size_t count = vcs_source_package_transport_file_count(transport);
    size_t base = strlen(dir);
    for (size_t i = 0; i < count; i++) {
        const char *relative = NULL;
        const uint8_t *bytes = NULL;
        size_t len = 0;
        if (!vcs_source_package_transport_file_at(
                transport, i, &relative, &bytes, &len))
            continue;
        int n = snprintf(path, sizeof(path), "%s/%s", dir, relative);
        if (n <= 0 || (size_t)n >= sizeof(path))
            continue;
        (void)unlink(path);
    }
    for (size_t i = 0; i < count; i++) {
        const char *relative = NULL;
        const uint8_t *bytes = NULL;
        size_t len = 0;
        if (!vcs_source_package_transport_file_at(
                transport, i, &relative, &bytes, &len))
            continue;
        int n = snprintf(path, sizeof(path), "%s/%s", dir, relative);
        if (n <= 0 || (size_t)n >= sizeof(path)) continue;
        for (char *p = strrchr(path, '/'); p && (size_t)(p - path) > base;
             p = strrchr(path, '/')) {
            *p = '\0';
            (void)rmdir(path);
        }
    }
    (void)rmdir(dir);
}

/* Publisher lineage from the persisted releases (rebuildable projection):
 * parent = this key's latest release id, sequence = its sequence + 1. A key
 * with no persisted release is a root release (no parent, sequence 1). */
static bool zpub_lineage(const char *zcode_dir, const char *publisher_hex,
                         bool *has_parent, uint8_t parent_root[32],
                         uint64_t *sequence)
{
    struct vcs_package_index *index = vcs_package_index_build(zcode_dir);
    if (!index)
        LOG_FAIL("zcode.publish", "package index build failed for %s",
                 zcode_dir);
    uint64_t max_seq = 0;
    char latest_id[65] = "";
    for (size_t i = 0; i < vcs_package_index_count(index); i++) {
        const struct vcs_package_index_entry *e =
            vcs_package_index_at(index, i);
        if (strcmp(e->publisher_hex, publisher_hex) == 0 &&
            e->publisher_sequence >= max_seq) {
            max_seq = e->publisher_sequence;
            (void)snprintf(latest_id, sizeof(latest_id), "%s",
                           e->release_id_hex);
        }
    }
    vcs_package_index_free(index);
    if (max_seq == UINT64_MAX)
        return false;
    *has_parent = max_seq > 0;
    *sequence = max_seq + 1u;
    return !*has_parent || zcl_hex_decode_lower(latest_id, parent_root, 32);
}

struct zpub_accepted_bundle {
    char workspace[ZDEV_PATH_MAX];
    char datadir[ZPUB_PATH_MAX];
    char acceptance_datadir[ZPUB_PATH_MAX];
    uint8_t source_root[32];
    struct zcode_lane_status lane;
    struct vcs_zcode_task_v1 task;
    struct vcs_zcode_candidate_v1 candidate;
    struct vcs_zcode_proof_policy_v1 policy;
    uint8_t receipt_wire[VCS_ZCODE_LANE_WIRE_BYTES];
    struct vcs_source_package_transport transport;
    bool have_mapping;
    uint8_t mapping_root[32];
    struct vcs_package_mapping_set mapping;
};

static void zpub_bundle_free(struct zpub_accepted_bundle *bundle)
{
    if (!bundle) return;
    vcs_source_package_transport_free(&bundle->transport);
    vcs_package_mapping_set_free(&bundle->mapping);
    memset(bundle, 0, sizeof(*bundle));
    vcs_package_mapping_set_init(&bundle->mapping);
}

static bool zpub_push_hex(struct json_value *out, const char *key,
                          const uint8_t *bytes, size_t len)
{
    if (!out || !key || (!bytes && len > 0) ||
        len > (SIZE_MAX - 1u) / 2u)
        return false;
    char *hex = zcl_malloc(len * 2u + 1u, "zcode.publish.hex");
    if (!hex) return false;
    zcl_hex_encode(bytes, len, hex);
    bool ok = json_push_kv_str(out, key, hex);
    free(hex);
    return ok;
}

static bool zpub_decode_hex(const char *hex, size_t max_bytes,
                            uint8_t **bytes_out, size_t *len_out)
{
    *bytes_out = NULL;
    *len_out = 0;
    size_t hex_len = hex ? strlen(hex) : 0;
    if (hex_len == 0 || (hex_len & 1u) != 0 ||
        hex_len > max_bytes * 2u)
        return false;
    size_t len = hex_len / 2u;
    uint8_t *bytes = zcl_malloc(len, "zcode.publish.input");
    if (!bytes || !zcl_hex_decode_lower(hex, bytes, len)) {
        free(bytes);
        return false;
    }
    *bytes_out = bytes;
    *len_out = len;
    return true;
}

static bool zpub_copy_field(char *out, size_t cap, const char *value)
{
    size_t len = value ? strlen(value) : 0;
    if (!out || cap == 0 || len >= cap)
        return false;
    memcpy(out, value ? value : "", len + 1u);
    return true;
}

static bool zpub_normalize(
    const struct zcl_command_request *request, struct zcl_command_reply *reply,
    struct zpub_accepted_bundle *bundle)
{
    memset(bundle, 0, sizeof(*bundle));
    const char *workspace_arg = zdev_str(request->input, "workspace");
    const char *datadir_arg = zdev_str(request->input, "datadir");
    const char *acceptance_datadir_arg =
        zdev_str(request->input, "acceptance_datadir");
    const char *source_root_arg = zdev_str(request->input, "source_root");
    if (!workspace_arg || !realpath(workspace_arg, bundle->workspace) ||
        !datadir_arg || !realpath(datadir_arg, bundle->datadir) ||
        !realpath(acceptance_datadir_arg && acceptance_datadir_arg[0]
                      ? acceptance_datadir_arg : datadir_arg,
                  bundle->acceptance_datadir) ||
        !source_root_arg ||
        !zcl_hex_decode_lower(source_root_arg, bundle->source_root, 32)) {
        zpub_fail(reply, "BAD_PUBLISH_INPUT",
                  "workspace, datadir, and optional acceptance_datadir must "
                  "resolve to existing directories and source_root must be "
                  "64 lowercase hex");
        return false;
    }
    const char *mapping_arg = zdev_str(
        request->input, "package_mapping_root");
    if (mapping_arg && mapping_arg[0]) {
        bundle->have_mapping =
            zcl_hex_decode_lower(mapping_arg, bundle->mapping_root, 32) &&
            vcs_package_mapping_set_load(
                bundle->workspace, bundle->mapping_root, &bundle->mapping) &&
            memcmp(bundle->mapping.source_tree_root,
                   bundle->source_root, 32) == 0;
        if (!bundle->have_mapping) {
            zpub_bundle_free(bundle);
            zpub_fail(reply, "PACKAGE_MAPPING_INVALID",
                      "package_mapping_root must be one complete immutable "
                      "mapping set for the exact accepted source tree");
            return false;
        }
    }
    return true;
}

static bool zpub_lane_acceptable(
    struct zcl_command_reply *reply, struct zpub_accepted_bundle *bundle,
    struct zcl_result found)
{
    if (!found.ok) {
        zpub_fail(reply, "LANE_NOT_ACCEPTED", found.message);
        return false;
    }
    if (bundle->lane.lane != VCS_ZCODE_LANE_PROVEN) {
        zpub_fail(reply, "LANE_NOT_ACCEPTED",
                  "publication requires the exact PROVEN root produced by "
                  "zcode work accept; FRONTIER and CANDIDATE are not human acceptance");
        return false;
    }
    return true;
}

static bool zpub_find_lane_readonly(
    const struct zcl_command_request *request, struct zcl_command_reply *reply,
    struct zpub_accepted_bundle *bundle)
{
    sqlite3 *db = NULL;
    struct node_db local_ndb = {0};
    struct node_db *ndb = zdev_runtime_owns_ledger(bundle->acceptance_datadir)
        ? app_runtime_node_db() : &local_ndb;
    bool owned = ndb != &local_ndb;
    if (!owned && !zcl_native_node_db_require_readonly(
            bundle->acceptance_datadir, reply, "the ZCODE lane ledger",
            &db, ndb))
        return false;
    struct zcode_accepted_work_status accepted;
    struct zcl_result found = zcode_accepted_work_find(
        ndb, bundle->workspace, zdev_str(request->input, "source_root"),
        (int64_t)platform_time_wall_unix(), false, &accepted);
    if (found.ok)
        found = zcode_lane_find(
            ndb, bundle->workspace,
            zdev_str(request->input, "source_root"), &bundle->lane);
    if (!owned) zcl_native_node_db_close_readonly(&db, ndb);
    return zpub_lane_acceptable(reply, bundle, found);
}

static bool zpub_find_lane_commit(
    const struct zcl_command_request *request, struct zcl_command_reply *reply,
    struct zpub_accepted_bundle *bundle)
{
    struct node_db local_ndb = {0};
    struct node_db *ndb = zdev_runtime_owns_ledger(bundle->acceptance_datadir)
        ? app_runtime_node_db() : &local_ndb;
    bool owned = ndb != &local_ndb;
    if (!owned && !zdev_open_db(bundle->acceptance_datadir, ndb)) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_FAILED, "DATABASE_OPEN_FAILED",
                               "accept", true, false,
                               "the ZBuild ledger could not be opened",
                               "zcode.publish");
        return false;
    }
    struct zcode_accepted_work_status accepted;
    struct zcl_result found = zcode_accepted_work_find(
        ndb, bundle->workspace, zdev_str(request->input, "source_root"),
        (int64_t)platform_time_wall_unix(), true, &accepted);
    if (found.ok)
        found = zcode_lane_find(
            ndb, bundle->workspace,
            zdev_str(request->input, "source_root"), &bundle->lane);
    if (!owned) node_db_close(ndb);
    return zpub_lane_acceptable(reply, bundle, found);
}

static bool zpub_prepare_accepted_objects(
    const struct zcl_command_request *request, struct zcl_command_reply *reply,
    struct zpub_accepted_bundle *bundle)
{
    struct vcs_zcode_lane_receipt_v1 receipt;
    uint8_t proof_set_root[32];
    bool accepted =
        zpub_load_task(bundle->workspace, bundle->lane.task_root_sha3,
                       &bundle->task) &&
        zpub_load_candidate(bundle->workspace,
                            bundle->lane.candidate_root_sha3,
                            &bundle->candidate) &&
        zpub_load_policy(bundle->workspace,
                         bundle->lane.proof_policy_root_sha3,
                         &bundle->policy) &&
        zpub_load_lane_receipt(bundle->workspace,
                               bundle->lane.receipt_root_sha3, &receipt,
                               bundle->candidate.author_pubkey,
                               bundle->receipt_wire) &&
        zcl_hex_decode_lower(bundle->lane.proof_set_root_sha3,
                             proof_set_root, 32) &&
        vcs_zcode_lane_receipt_validate_for_candidate(
            &receipt, &bundle->task, &bundle->candidate,
            &bundle->policy) == VCS_ZCODE_DEV_OK &&
        memcmp(receipt.proof_set_root, proof_set_root, 32) == 0 &&
        memcmp(bundle->candidate.candidate_source_root,
               bundle->source_root, 32) == 0 &&
        memcmp(receipt.source_root, bundle->source_root, 32) == 0;
    if (!accepted) {
        zpub_fail(reply, "LANE_ACCEPTANCE_INVALID",
                  "the lane receipt, signature, proof-set root, task, "
                  "candidate, policy, or source binding failed CAS "
                  "reverification");
        return false;
    }
    if (!zpub_proof_set_valid(bundle->workspace,
                              bundle->lane.proof_set_root_sha3,
                              &bundle->task, &bundle->candidate)) {
        zpub_fail(reply, "PROOF_SET_INVALID",
                  "the accepted proof set or one of its signed work receipts "
                  "does not rederive and bind to this task and candidate");
        return false;
    }

    const char *claimed_task = zdev_str(request->input, "task_root");
    const char *claimed_receipt =
        zdev_str(request->input, "lane_receipt_root");
    if ((claimed_task && claimed_task[0] &&
         strcmp(claimed_task, bundle->lane.task_root_sha3) != 0) ||
        (claimed_receipt && claimed_receipt[0] &&
         strcmp(claimed_receipt, bundle->lane.receipt_root_sha3) != 0)) {
        zpub_fail(reply, "CLAIMED_BINDING_MISMATCH",
                  "task_root or lane_receipt_root does not match the "
                  "verified acceptance");
        return false;
    }
    uint8_t lane_receipt_root[32];
    if (!zcl_hex_decode_lower(bundle->lane.receipt_root_sha3,
                              lane_receipt_root, 32)) {
        zpub_bundle_free(bundle);
        zpub_fail(reply, "LANE_ACCEPTANCE_INVALID",
                  "the verified PROVEN accepted-work root is not canonical");
        return false;
    }
    if (bundle->have_mapping &&
        memcmp(bundle->mapping.lane_receipt_root,
               lane_receipt_root, 32) != 0) {
        zpub_bundle_free(bundle);
        zpub_fail(reply, "PACKAGE_MAPPING_LANE_MISMATCH",
                  "package_mapping_root does not bind the verified PROVEN accepted work");
        return false;
    }

    if (!vcs_source_package_transport_build_accepted(
            bundle->workspace, bundle->source_root,
            lane_receipt_root, (int64_t)platform_time_wall_unix(),
            &bundle->transport)) {
        zpub_bundle_free(bundle);
        zpub_fail(reply, "SOURCE_PACKAGE_FAILED",
                  "the exact accepted ZVCS tree, LICENSE, complete accepted "
                  "work authority, or compressed source carrier could not "
                  "be rederived as one "
                  "bounded canonical content.v2 package");
        return false;
    }

    uint8_t *acceptance_recipe_wire = NULL;
    size_t acceptance_recipe_wire_len = 0;
    uint8_t recipe_checked[32];
    struct vcs_package_recipe recipe;
    vcs_package_recipe_init(&recipe);
    bool recipe_ok =
        vcs_object_load_raw(bundle->workspace,
                            bundle->task.acceptance_tests_root,
                            &acceptance_recipe_wire,
                            &acceptance_recipe_wire_len) == 0 &&
        acceptance_recipe_wire_len <= VCS_PACKAGE_RECIPE_MAX_WIRE_BYTES &&
        vcs_package_recipe_parse(acceptance_recipe_wire,
                                 acceptance_recipe_wire_len,
                                 &recipe) == VCS_PACKAGE_RECIPE_OK &&
        vcs_package_recipe_root(&recipe, recipe_checked) ==
            VCS_PACKAGE_RECIPE_OK &&
        memcmp(recipe_checked, bundle->task.acceptance_tests_root, 32) == 0;
    vcs_package_recipe_free(&recipe);
    free(acceptance_recipe_wire);
    if (!recipe_ok) {
        zpub_bundle_free(bundle);
        zpub_fail(reply, "RECIPE_CAS_INVALID",
                  "the task acceptance recipe is absent, corrupt, or does "
                  "not rederive its CAS root");
        return false;
    }
    return true;
}

static bool zpub_release_body(
    const struct vcs_package_release *release, uint8_t **body_out,
    size_t *body_len_out, uint8_t digest[32])
{
    *body_out = NULL;
    *body_len_out = 0;
    uint8_t *wire = NULL;
    size_t wire_len = 0;
    enum vcs_package_release_error err =
        vcs_package_release_id(release, digest);
    if (err == VCS_PACKAGE_RELEASE_OK)
        err = vcs_package_release_serialize(release, &wire, &wire_len);
    if (err != VCS_PACKAGE_RELEASE_OK ||
        wire_len <= VCS_PACKAGE_RELEASE_SIGNATURE_BYTES) {
        free(wire);
        return false;
    }
    size_t body_len = wire_len - VCS_PACKAGE_RELEASE_SIGNATURE_BYTES;
    uint8_t *body = zcl_malloc(body_len, "zcode.publish.release_body");
    if (!body) {
        free(wire);
        return false;
    }
    memcpy(body, wire, body_len);
    free(wire);
    *body_out = body;
    *body_len_out = body_len;
    return true;
}

static bool zpub_lineage_claims_match(
    const struct json_value *input, bool has_parent,
    const uint8_t parent_root[32], uint64_t sequence)
{
    int64_t seq_claim = zdev_int(input, "publisher_sequence", 0);
    if (seq_claim > 0 && (uint64_t)seq_claim != sequence)
        return false;
    const char *parent_claim = zdev_str(input, "parent_release_root");
    if (!parent_claim || !parent_claim[0])
        return true;
    uint8_t checked[32];
    return has_parent &&
        zcl_hex_decode_lower(parent_claim, checked, 32) &&
        memcmp(checked, parent_root, 32) == 0;
}

static bool zpub_release_lineage_valid(
    const char *zcode_dir, const struct vcs_package_release *release,
    const uint8_t release_id[32])
{
    struct vcs_package_index *index = vcs_package_index_build(zcode_dir);
    if (!index)
        LOG_FAIL("zcode.publish", "package index build failed for %s",
                 zcode_dir);
    char publisher_hex[2 * VCS_PACKAGE_RELEASE_PUBKEY_BYTES + 1u];
    char release_id_hex[65];
    zcl_hex_encode(release->publisher_pubkey,
                   VCS_PACKAGE_RELEASE_PUBKEY_BYTES, publisher_hex);
    zcl_hex_encode(release_id, 32, release_id_hex);
    uint64_t max_seq = 0;
    char latest_id[65] = "";
    bool duplicate = false;
    for (size_t i = 0; i < vcs_package_index_count(index); i++) {
        const struct vcs_package_index_entry *entry =
            vcs_package_index_at(index, i);
        if (strcmp(entry->publisher_hex, publisher_hex) != 0)
            continue;
        if (strcmp(entry->release_id_hex, release_id_hex) == 0)
            duplicate = true;
        if (entry->publisher_sequence > max_seq) {
            max_seq = entry->publisher_sequence;
            (void)snprintf(latest_id, sizeof(latest_id), "%s",
                           entry->release_id_hex);
        }
    }
    vcs_package_index_free(index);
    if (duplicate)
        return true;
    if (max_seq == UINT64_MAX)
        return false;
    if (release->publisher_sequence != max_seq + 1u ||
        release->has_parent != (max_seq > 0))
        return false;
    uint8_t latest_root[32];
    return max_seq == 0 ||
        (zcl_hex_decode_lower(latest_id, latest_root, 32) &&
         memcmp(release->parent_root, latest_root, 32) == 0);
}

static void zpub_common_output(
    struct json_value *out, const struct zpub_accepted_bundle *bundle)
{
    zdev_push_root(out, "source_root", bundle->source_root);
    zdev_push_root(out, "recipe_root", bundle->transport.recipe_root);
    zdev_push_root(out, "acceptance_recipe_root",
                   bundle->task.acceptance_tests_root);
    (void)json_push_kv_str(out, "lane", bundle->lane.lane_name);
    (void)json_push_kv_str(out, "lane_receipt_root",
                           bundle->lane.receipt_root_sha3);
    (void)json_push_kv_str(out, "proof_set_root",
                           bundle->lane.proof_set_root_sha3);
    (void)json_push_kv_str(out, "task_root",
                           bundle->lane.task_root_sha3);
    (void)json_push_kv_str(out, "candidate_root",
                           bundle->lane.candidate_root_sha3);
    (void)json_push_kv_str(
        out, "authority", "SIGNED_LANE_RECEIPT_AND_RELEASE_ENVELOPE");
    (void)json_push_kv_str(out, "source_transport",
                           "vcs_source_bundle.v2");
    (void)json_push_kv_int(out, "source_bundle_bytes",
                           (int64_t)bundle->transport.source_transport_bytes);
    (void)json_push_kv_int(
        out, "source_bytes",
        (int64_t)bundle->transport.bundle_metrics.source_bytes);
    (void)json_push_kv_int(out, "source_files",
                           bundle->transport.bundle_metrics.file_count);
    (void)json_push_kv_int(out, "source_shards",
                           bundle->transport.source.shard_count);
    (void)json_push_kv_int(out, "offline_input_bytes",
                           (int64_t)bundle->transport.offline_input_bytes);
    (void)json_push_kv_int(out, "offline_input_files",
                           bundle->transport.offline_input_count);
    (void)json_push_kv_int(
        out, "carrier_files",
        vcs_source_package_transport_file_count(&bundle->transport));
}

struct zpub_job_binding {
    bool requested;
    uint8_t job_root[32];
    uint64_t bytes_scanned;
    uint32_t new_chunks;
    uint32_t reused_chunks;
};

struct zpub_package_facts {
    char name[VCS_PACKAGE_RELEASE_NAME_MAX + 1u];
    char semver[VCS_PACKAGE_RELEASE_SEMVER_MAX + 1u];
    char license[VCS_PACKAGE_RELEASE_LICENSE_MAX + 1u];
};

enum zpub_package_facts_state {
    ZPUB_PACKAGE_FACTS_INVALID = -1,
    ZPUB_PACKAGE_FACTS_ABSENT = 0,
    ZPUB_PACKAGE_FACTS_PRESENT = 1,
};

static enum zpub_package_facts_state zpub_package_facts_load(
    const struct zpub_accepted_bundle *bundle,
    struct zpub_package_facts *facts)
{
    memset(facts, 0, sizeof(*facts));
    struct vcs_manifest tree;
    if (!vcs_tree_load(bundle->workspace, bundle->source_root, &tree))
        return ZPUB_PACKAGE_FACTS_INVALID;
    const struct vcs_entry *entry = NULL;
    for (size_t i = 0; i < tree.count; i++) {
        if (strcmp(tree.entries[i].path, VCS_PACKAGE_DEPS_META_PATH) == 0) {
            entry = &tree.entries[i];
            break;
        }
    }
    if (!entry) {
        vcs_manifest_free(&tree);
        return ZPUB_PACKAGE_FACTS_ABSENT;
    }
    bool bounded = S_ISREG(entry->mode) && entry->size > 0 &&
        entry->size <= VCS_PACKAGE_DEPS_META_MAX_BYTES;
    uint8_t *wire = NULL;
    size_t wire_len = 0;
    bool loaded = bounded && vcs_object_load_raw_bounded(
        bundle->workspace, entry->blob, VCS_PACKAGE_DEPS_META_MAX_BYTES,
        &wire, &wire_len) == 0 && wire_len == entry->size;
    uint8_t derived[32];
    if (loaded) {
        struct sha3_256_ctx ctx;
        uint8_t tag = VCS_TAG_BLOB;
        sha3_256_init(&ctx);
        sha3_256_write(&ctx, &tag, 1);
        sha3_256_write(&ctx, wire, wire_len);
        sha3_256_finalize(&ctx, derived);
        loaded = memcmp(derived, entry->blob, sizeof(derived)) == 0;
    }
    vcs_manifest_free(&tree);
    struct json_value meta;
    bool parsed = loaded && json_read(
        &meta, (const char *)wire, wire_len) && meta.type == JSON_OBJ;
    const struct json_value *schema = parsed ? json_get(&meta, "schema") : NULL;
    const char *name = parsed ? zdev_str(&meta, "name") : NULL;
    const char *semver = parsed ? zdev_str(&meta, "semver") : NULL;
    const char *license = parsed ? zdev_str(&meta, "license") : NULL;
    const char *language = parsed ? zdev_str(&meta, "language") : NULL;
    bool valid = parsed && schema && schema->type == JSON_INT &&
        json_get_int(schema) == 1 && language && strcmp(language, "c23") == 0 &&
        zpub_copy_field(facts->name, sizeof(facts->name), name) &&
        zpub_copy_field(facts->semver, sizeof(facts->semver), semver) &&
        zpub_copy_field(facts->license, sizeof(facts->license), license);
    if (parsed) json_free(&meta);
    free(wire);
    return valid ? ZPUB_PACKAGE_FACTS_PRESENT : ZPUB_PACKAGE_FACTS_INVALID;
}

static bool zpub_package_fact_matches(const char *requested,
                                      const char *accepted)
{
    return !requested || !requested[0] || strcmp(requested, accepted) == 0;
}

static bool zpub_job_preflight(
    const struct zcl_command_request *request, struct zcl_command_reply *reply,
    const struct zpub_accepted_bundle *bundle,
    struct zpub_job_binding *binding)
{
    memset(binding, 0, sizeof(*binding));
    const char *job_hex = zdev_str(request->input, "publication_job_root");
    if (!job_hex || !job_hex[0])
        return true;
    binding->requested = true;
    struct vcs_devloop_publication_job job;
    struct vcs_devloop_publication_receipt progress, mapping = {0};
    uint8_t progress_root[32];
    bool valid = bundle->have_mapping &&
        zcl_hex_decode_lower(job_hex, binding->job_root, 32) &&
        vcs_devloop_publication_job_load(
            bundle->workspace, binding->job_root, &job) &&
        vcs_devloop_publication_job_is_queued(
            bundle->workspace, binding->job_root) &&
        memcmp(job.source_tree_root, bundle->source_root, 32) == 0 &&
        vcs_devloop_publication_progress_load(
            bundle->workspace, binding->job_root, &progress,
            progress_root);
    if (valid && progress.phase ==
            VCS_DEVLOOP_PUBLICATION_PHASE_PACKAGE_MAPPING_READY) {
        mapping = progress;
    } else if (valid && progress.phase ==
            VCS_DEVLOOP_PUBLICATION_PHASE_RELEASE_PUBLISHED) {
        valid = vcs_devloop_publication_receipt_load(
                bundle->workspace, progress.predecessor_receipt_root,
                &mapping) &&
            mapping.phase ==
                VCS_DEVLOOP_PUBLICATION_PHASE_PACKAGE_MAPPING_READY;
    } else {
        valid = false;
    }
    valid = valid &&
        memcmp(mapping.artifact_root, bundle->mapping_root, 32) == 0;
    if (!valid) {
        zpub_fail(
            reply, "PUBLICATION_JOB_BINDING_INVALID",
            "publication_job_root must be one queued exact-source job at "
            "PACKAGE_MAPPING_READY (or its idempotent RELEASE_PUBLISHED "
            "successor), bound to package_mapping_root");
        return false;
    }
    binding->bytes_scanned = mapping.bytes_scanned;
    binding->new_chunks = mapping.new_chunks;
    binding->reused_chunks = mapping.reused_chunks;
    return true;
}

void zcl_native_handle_zcode_publish_plan(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    if (!request || !reply) return;
    const char *datadir = zdev_str(request->input, "acceptance_datadir");
    if (!datadir || !datadir[0]) datadir = zdev_str(request->input, "datadir");
    if (zcl_native_forward_live_command(
            request, datadir, "zcode_publish_plan_owned",
            "LIVE_PUBLISH_PLAN_FAILED", "plan", "zcode.publish.plan",
            reply))
        return;
    struct zpub_accepted_bundle bundle;
    if (!zpub_normalize(request, reply, &bundle) ||
        !zpub_find_lane_readonly(request, reply, &bundle) ||
        !zpub_prepare_accepted_objects(request, reply, &bundle))
        return;
    struct zpub_job_binding job_binding;
    if (!zpub_job_preflight(request, reply, &bundle, &job_binding)) {
        zpub_bundle_free(&bundle);
        return;
    }

    const char *pubkey_hex = zdev_str(request->input, "publisher_pubkey");
    const char *name = zdev_str(request->input, "name");
    const char *semver = zdev_str(request->input, "semver");
    const char *license = zdev_str(request->input, "license");
    struct zpub_package_facts package_facts;
    enum zpub_package_facts_state package_facts_state =
        zpub_package_facts_load(&bundle, &package_facts);
    if (package_facts_state == ZPUB_PACKAGE_FACTS_INVALID) {
        zpub_bundle_free(&bundle);
        zpub_fail(reply, "PACKAGE_FACTS_INVALID",
                  "the exact accepted zcode-package.json is malformed, "
                  "unreadable, or not C23");
        return;
    }
    if (package_facts_state == ZPUB_PACKAGE_FACTS_PRESENT) {
        if (!zpub_package_fact_matches(name, package_facts.name) ||
            !zpub_package_fact_matches(semver, package_facts.semver) ||
            !zpub_package_fact_matches(license, package_facts.license)) {
            zpub_bundle_free(&bundle);
            zpub_fail(reply, "PACKAGE_FACTS_MISMATCH",
                      "name, semver, and license may not override the exact "
                      "accepted zcode-package.json");
            return;
        }
        name = package_facts.name;
        semver = package_facts.semver;
        license = package_facts.license;
    }
    const char *reward = zdev_str(request->input, "reward_address");
    const char *znam = zdev_str(request->input, "znam");
    struct vcs_package_release release;
    memset(&release, 0, sizeof(release));
    release.schema_version = VCS_PACKAGE_RELEASE_VERSION;
    memcpy(release.package_root, bundle.transport.package_root, 32);
    memcpy(release.recipe_root, bundle.transport.recipe_root, 32);
    bool fields_ok = pubkey_hex &&
        zcl_hex_decode_lower(pubkey_hex, release.publisher_pubkey,
                             sizeof(release.publisher_pubkey)) &&
        zpub_copy_field(release.name, sizeof(release.name), name) &&
        zpub_copy_field(release.semver, sizeof(release.semver), semver) &&
        zpub_copy_field(release.license, sizeof(release.license), license) &&
        zpub_copy_field(release.reward_address,
                        sizeof(release.reward_address), reward);
    if (znam && znam[0]) {
        release.has_znam = true;
        fields_ok = fields_ok &&
            zpub_copy_field(release.znam, sizeof(release.znam), znam);
    }
    char zcode_dir[ZPUB_PATH_MAX];
    int n = snprintf(zcode_dir, sizeof(zcode_dir), "%s/zcode",
                     bundle.datadir);
    fields_ok = fields_ok && n > 0 && (size_t)n < sizeof(zcode_dir) &&
        vcs_package_accept_chain_id(release.chain_id,
                                    sizeof(release.chain_id)) &&
        zpub_lineage(zcode_dir, pubkey_hex, &release.has_parent,
                     release.parent_root, &release.publisher_sequence) &&
        zpub_lineage_claims_match(request->input, release.has_parent,
                                  release.parent_root,
                                  release.publisher_sequence);
    uint8_t *release_body = NULL;
    size_t release_body_len = 0;
    uint8_t digest[32];
    fields_ok = fields_ok &&
        vcs_package_release_validate(&release) == VCS_PACKAGE_RELEASE_OK &&
        zpub_release_body(&release, &release_body, &release_body_len,
                          digest);
    if (!fields_ok) {
        free(release_body);
        zpub_bundle_free(&bundle);
        zpub_fail(reply, "RELEASE_PLAN_FAILED",
                  "publisher key, release fields, chain id, or persisted "
                  "publisher lineage is invalid or stale");
        return;
    }

    bool rendered =
        zpub_push_hex(&reply->data, "package_root",
                      bundle.transport.package_root, 32) &&
        zpub_push_hex(&reply->data, "release_signing_digest",
                      digest, 32) &&
        zpub_push_hex(&reply->data, "release_body_hex",
                      release_body, release_body_len) &&
        json_push_kv_int(&reply->data, "manifest_bytes",
                         (int64_t)bundle.transport.manifest_wire_len) &&
        json_push_kv_int(&reply->data, "recipe_bytes",
                         (int64_t)bundle.transport.recipe_wire_len) &&
        json_push_kv_str(&reply->data, "carrier_material",
                         "rederived_from_accepted_source_at_commit") &&
        json_push_kv_int(&reply->data, "publisher_sequence",
                         (int64_t)release.publisher_sequence) &&
        json_push_kv_bool(&reply->data, "has_parent",
                          release.has_parent) &&
        json_push_kv_str(&reply->data, "signature_status", "unsigned") &&
        json_push_kv_bool(&reply->data, "read_only", true);
    if (rendered && release.has_parent)
        rendered = zpub_push_hex(&reply->data, "parent_release_root",
                                 release.parent_root, 32);
    if (rendered)
        zpub_common_output(&reply->data, &bundle);
    if (rendered) {
        (void)json_push_kv_int(&reply->data, "bytes_scanned",
                               (int64_t)job_binding.bytes_scanned);
        (void)json_push_kv_int(&reply->data, "new_chunks",
                               job_binding.new_chunks);
        (void)json_push_kv_int(&reply->data, "reused_chunks",
                               job_binding.reused_chunks);
        (void)json_push_kv_int(&reply->data, "synthetic_bytes_hashed",
                               (int64_t)bundle.transport.source_transport_bytes +
                               (int64_t)bundle.transport.offline_input_bytes +
                               VCS_ZCODE_LANE_WIRE_BYTES);
        (void)json_push_kv_str(&reply->data, "package_name", release.name);
        (void)json_push_kv_str(&reply->data, "package_version",
                               release.semver);
        (void)json_push_kv_str(&reply->data, "package_license",
                               release.license);
        (void)json_push_kv_str(
            &reply->data, "package_facts",
            package_facts_state == ZPUB_PACKAGE_FACTS_PRESENT
                ? "exact_accepted_source" : "explicit_input");
        if (bundle.have_mapping)
            zdev_push_root(&reply->data, "package_mapping_root",
                           bundle.mapping_root);
        if (job_binding.requested)
            zdev_push_root(&reply->data, "publication_job_root",
                           job_binding.job_root);
    }
    free(release_body);
    zpub_bundle_free(&bundle);
    if (!rendered)
        zpub_fail(reply, "RELEASE_PLAN_OUTPUT",
                  "bounded canonical publication plan could not be rendered");
}

void zcl_native_handle_zcode_publish_commit(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    if (!request || !reply) return;
    const char *datadir = zdev_str(request->input, "acceptance_datadir");
    if (!datadir || !datadir[0]) datadir = zdev_str(request->input, "datadir");
    if (zcl_native_forward_live_command(
            request, datadir, "zcode_publish_commit_owned",
            "LIVE_PUBLISH_COMMIT_FAILED", "publish",
            "zcode.publish.commit", reply))
        return;
    struct zpub_accepted_bundle bundle;
    if (!zpub_normalize(request, reply, &bundle) ||
        !zpub_find_lane_commit(request, reply, &bundle) ||
        !zpub_prepare_accepted_objects(request, reply, &bundle))
        return;
    struct zpub_job_binding job_binding;
    if (!zpub_job_preflight(request, reply, &bundle, &job_binding)) {
        zpub_bundle_free(&bundle);
        return;
    }

    const char *release_hex_input = zdev_str(request->input, "release_hex");
    uint8_t *release_wire = NULL;
    size_t release_wire_len = 0;
    struct vcs_package_release release;
    uint8_t release_id[32];
    bool release_ok =
        zpub_decode_hex(release_hex_input, VCS_PACKAGE_RELEASE_MAX_WIRE_BYTES,
                        &release_wire, &release_wire_len) &&
        vcs_package_release_parse(release_wire, release_wire_len,
                                  &release) == VCS_PACKAGE_RELEASE_OK &&
        vcs_package_release_verify(&release) == VCS_PACKAGE_RELEASE_OK &&
        vcs_package_release_id(&release, release_id) ==
            VCS_PACKAGE_RELEASE_OK &&
        memcmp(release.package_root,
               bundle.transport.package_root, 32) == 0 &&
        memcmp(release.recipe_root,
               bundle.transport.recipe_root, 32) == 0;
    char expected_chain[VCS_PACKAGE_RELEASE_CHAIN_ID_MAX + 1u];
    release_ok = release_ok &&
        vcs_package_accept_chain_id(expected_chain, sizeof(expected_chain)) &&
        strcmp(release.chain_id, expected_chain) == 0;
    char zcode_dir[ZPUB_PATH_MAX];
    int n = snprintf(zcode_dir, sizeof(zcode_dir), "%s/zcode",
                     bundle.datadir);
    release_ok = release_ok && n > 0 && (size_t)n < sizeof(zcode_dir) &&
        zpub_release_lineage_valid(zcode_dir, &release, release_id);
    if (!release_ok) {
        free(release_wire);
        zpub_bundle_free(&bundle);
        zpub_fail(reply, "SIGNED_RELEASE_INVALID",
                  "release_hex must be one canonical verified offline-signed "
                  "envelope binding the accepted package, recipe, chain, "
                  "and current publisher lineage");
        return;
    }

    char staging[ZPUB_PATH_MAX] = {0};
    n = snprintf(staging, sizeof(staging), "%s/.accept-publish-XXXXXX",
                 bundle.datadir);
    bool stage_created = n > 0 && (size_t)n < sizeof(staging) &&
        mkdtemp(staging) != NULL;
    bool staged = stage_created &&
        zpub_stage_transport(staging, &bundle.transport);
    if (!staged) {
        if (stage_created) zpub_stage_cleanup(staging, &bundle.transport);
        free(release_wire);
        zpub_bundle_free(&bundle);
        zpub_fail(reply, "SOURCE_STAGE_FAILED",
                  "verified CAS source bytes could not be staged in the "
                  "explicit datadir");
        return;
    }

    char *release_hex =
        zcl_malloc(release_wire_len * 2u + 1u,
                   "zcode.publish.release_hex");
    char *manifest_hex =
        zcl_malloc(bundle.transport.manifest_wire_len * 2u + 1u,
                   "zcode.publish.manifest_hex");
    char *recipe_hex =
        zcl_malloc(bundle.transport.recipe_wire_len * 2u + 1u,
                   "zcode.publish.recipe_hex");
    if (!release_hex || !manifest_hex || !recipe_hex) {
        zpub_stage_cleanup(staging, &bundle.transport);
        free(release_hex);
        free(manifest_hex);
        free(recipe_hex);
        free(release_wire);
        zpub_bundle_free(&bundle);
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INTERNAL, "ALLOC", "publish",
                               false, false, "hex wire buffers",
                               "zcode.publish");
        return;
    }
    zcl_hex_encode(release_wire, release_wire_len, release_hex);
    zcl_hex_encode(bundle.transport.manifest_wire,
                   bundle.transport.manifest_wire_len,
                   manifest_hex);
    zcl_hex_encode(bundle.transport.recipe_wire,
                   bundle.transport.recipe_wire_len, recipe_hex);

    struct json_value commit_input;
    json_init(&commit_input);
    json_set_object(&commit_input);
    (void)json_push_kv_str(&commit_input, "release_hex", release_hex);
    (void)json_push_kv_str(&commit_input, "manifest_hex", manifest_hex);
    (void)json_push_kv_str(&commit_input, "recipe_hex", recipe_hex);
    (void)json_push_kv_str(&commit_input, "dir", staging);
    (void)json_push_kv_str(&commit_input, "datadir", bundle.datadir);
    const struct json_value *day = json_get(request->input, "day");
    if (day)
        (void)json_push_kv_int(&commit_input, "day", json_get_int(day));
    struct zcl_command_request commit_request = { .input = &commit_input };
    struct zcl_command_reply commit_reply;
    zcl_command_reply_init(&commit_reply, "zcl.zcode_publish_commit.v1");
    zcl_native_handle_zcode_package_publish_commit(
        &commit_request, &commit_reply);
    zpub_stage_cleanup(staging, &bundle.transport);
    json_free(&commit_input);
    free(release_hex);
    free(manifest_hex);
    free(recipe_hex);

    if (commit_reply.exit_code != ZCL_COMMAND_EXIT_OK) {
        char code[72], message[192], evidence[256];
        (void)snprintf(code, sizeof(code), "%s",
                       commit_reply.error.code[0]
                           ? commit_reply.error.code
                           : "PUBLISH_COMMIT_FAILED");
        (void)snprintf(message, sizeof(message), "%s",
                       commit_reply.error.message);
        (void)snprintf(evidence, sizeof(evidence), "%s",
                       commit_reply.error.evidence);
        free(release_wire);
        zcl_command_reply_free(&commit_reply);
        zpub_bundle_free(&bundle);
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INVALID, code, "validate",
                               false, false, message, evidence);
        return;
    }

    uint8_t progress_root[32];
    bool progress_reused = false;
    bool release_repaired = false;
    bool release_bound = !job_binding.requested ||
        (vcs_object_store_init(bundle.workspace) &&
         vcs_object_put_addressed_repair(
             bundle.workspace, release_id, release_wire, release_wire_len,
             &release_repaired));
    bool progressed = release_bound && (!job_binding.requested ||
        vcs_devloop_publication_advance_release(
            bundle.workspace, job_binding.job_root, bundle.mapping_root,
            release_id, progress_root, &progress_reused));
    free(release_wire);
    if (!progressed) {
        char release_id_hex[65];
        zcl_hex_encode(release_id, 32, release_id_hex);
        zcl_command_reply_free(&commit_reply);
        zpub_bundle_free(&bundle);
        zcl_command_reply_fail(
            reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_FAILED,
            "PUBLICATION_PROGRESS_FAILED", "schedule", true, true,
            "the signed package release was published, but its durable job "
            "receipt could not advance; retry the exact idempotent commit",
            release_id_hex);
        return;
    }
    json_copy(&reply->data, &commit_reply.data);
    zcl_command_reply_free(&commit_reply);
    zpub_common_output(&reply->data, &bundle);
    if (job_binding.requested) {
        zdev_push_root(&reply->data, "publication_job_root",
                       job_binding.job_root);
        zdev_push_root(&reply->data, "progress_receipt_root",
                       progress_root);
        zdev_push_root(&reply->data, "release_root", release_id);
        (void)json_push_kv_str(&reply->data, "publication_status",
                               "RELEASE_PUBLISHED");
        (void)json_push_kv_bool(&reply->data, "progress_reused",
                                progress_reused);
        (void)json_push_kv_bool(&reply->data, "release_cas_repaired",
                                release_repaired);
    }
    zpub_bundle_free(&bundle);
}
