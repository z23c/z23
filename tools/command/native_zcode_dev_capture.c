/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: ZCODE dev-loop ledger ownership, live-daemon forwarding, and
 * candidate/write-scope CAS capture shared by native_zcode_dev_command.c's
 * sibling handlers (native_zcode_dev_improve.c, native_zcode_dev_tasks.c,
 * native_zcode_dev_publish.c) through native_zcode_dev_priv.h. A live
 * node.db is never mutated by a one-shot CLI process: an owned ledger is
 * forwarded to the authenticated daemon instead of opened locally. */

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

/* A native command may target the running full node's existing ledger or a
 * new, isolated ZBuild fixture.  Existing node.db files are runtime-owned:
 * reopening one must never run the boot-only quick-check/quarantine,
 * migration, or crash-cleanup ceremony while the daemon still owns its
 * canonical connection.  Only an absent scratch ledger may be boot-created. */
bool zdev_open_build_ledger(
    struct node_db *ndb, const char *path, const char *reason)
{
    if (!ndb || !path || !path[0] || !reason || !reason[0]) return false;
    struct platform_positioned_file existing;
    platform_positioned_file_init(&existing);
    bool present = platform_positioned_file_open(&existing, path);
    platform_positioned_file_close(&existing);
    if (present)
        return node_db_open_existing_runtime(ndb, path, reason);
    return node_db_open(ndb, path);
}

bool zdev_runtime_owns_ledger(const char *datadir)
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

bool zdev_open_db(const char *datadir, struct node_db *ndb)
{
    char db_path[ZDEV_PATH_MAX];
    int n = datadir
        ? snprintf(db_path, sizeof(db_path), "%s/node.db", datadir) : -1;
    return n > 0 && (size_t)n < sizeof(db_path) &&
           node_db_open(ndb, db_path);
}

/* Encode the exact canonical input as one JSON-RPC parameter array. */
static bool zdev_live_encode_params(
    const struct json_value *input, char **wire_out, size_t *needed_out,
    struct zcl_command_reply *reply, const char *evidence)
{
    struct json_value params;
    json_init(&params); json_set_array(&params);
    bool built = json_push_back(&params, input);
    size_t needed = built ? json_write(&params, NULL, 0) : 0;
    char *wire = needed > 0 && needed < 256u * 1024u
        ? zcl_malloc(needed + 1u, "zcode.live_rpc") : NULL;
    bool ok = wire && json_write(&params, wire, needed + 1u) == needed;
    json_free(&params);
    if (!ok) {
        free(wire);
        zcl_command_reply_fail(
            reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_FAILED,
            "LIVE_ADMISSION_ENCODE_FAILED", "encode", false, false,
            "canonical live command input could not be encoded", evidence);
        return false;
    }
    *wire_out = wire;
    *needed_out = needed;
    return true;
}

/* Validate and copy one "next" continuation row from the daemon's reply. */
static bool zdev_live_apply_continuation_item(
    struct zcl_command_reply *reply, const struct json_value *item)
{
    const char *command = json_get_str(json_get(item, "command"));
    const char *input_json = json_get_str(json_get(item, "input_json"));
    const char *reason = json_get_str(json_get(item, "reason"));
    struct json_value next_input;
    json_init(&next_input);
    const struct zcl_command_spec *spec = command
        ? zcl_command_registry_find(zcl_command_catalog(), command, NULL)
        : NULL;
    char why[160];
    bool ok = item && item->type == JSON_OBJ && spec && input_json && reason &&
        strlen(input_json) < sizeof(reply->next[0].input_json) &&
        json_read(&next_input, input_json, strlen(input_json)) &&
        zcl_command_registry_input_validate(
            spec, &next_input, why, sizeof(why)) &&
        zcl_command_reply_add_next(reply, command, input_json, reason);
    json_free(&next_input);
    return ok;
}

/* Validate and copy every "next" continuation the daemon proposed. */
static bool zdev_live_apply_continuation(
    struct zcl_command_reply *reply, const struct json_value *body)
{
    const struct json_value *next = json_get(body, "next");
    if (!next) return true;
    if (next->type != JSON_ARR || json_size(next) > ZCL_COMMAND_MAX_NEXT)
        return false;
    for (size_t i = 0; i < json_size(next); i++) {
        if (!zdev_live_apply_continuation_item(reply, json_at(next, i)))
            return false;
    }
    return true;
}

/* The daemon accepted the forwarded command: copy its data, continuations,
 * and round-trip timings into the caller's reply. */
static void zdev_live_apply_success(
    struct zcl_command_reply *reply, const struct json_value *body,
    const struct json_value *data, int64_t encode_us, int64_t rpc_us,
    int64_t decode_started_us, size_t request_bytes, size_t response_bytes,
    const char *evidence)
{
    if (!zdev_live_apply_continuation(reply, body)) {
        reply->next_count = 0;
        zcl_command_reply_fail(
            reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_FAILED,
            "LIVE_CONTINUATION_INVALID", "decode", true, false,
            "the selected node returned a malformed or over-budget continuation",
            evidence);
        return;
    }
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
                           (int64_t)request_bytes);
    (void)json_push_kv_int(&reply->data, "live_rpc_response_bytes",
                           (int64_t)response_bytes);
}

/* The daemon refused the forwarded command: map its error onto ours. */
static void zdev_live_apply_failure(
    struct zcl_command_reply *reply, const struct json_value *body,
    const char *fallback_code, const char *fallback_phase,
    const char *evidence)
{
    const char *code = json_get_str(json_get(body, "code"));
    const char *phase = json_get_str(json_get(body, "phase"));
    const char *message = json_get_str(json_get(body, "message"));
    const char *remote_evidence = json_get_str(json_get(body, "evidence"));
    zcl_command_reply_fail(
        reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_FAILED,
        code && code[0] ? code : fallback_code,
        phase && phase[0] ? phase : fallback_phase,
        json_get_bool(json_get(body, "retryable")),
        json_get_bool(json_get(body, "mutated")),
        message && message[0] ? message :
            "the selected full node refused canonical admission",
        remote_evidence && remote_evidence[0] ? remote_evidence : evidence);
}

/* Ownership comes from the database lease, not an RPC-cookie convention:
 * credential-directory nodes deliberately have no <datadir>/.cookie. Returns
 * false when the caller owns the ledger itself and must admit locally. */
static bool zdev_live_owner_requires_forward(
    const char *db_path, struct zcl_command_reply *reply,
    const char *evidence, bool *refused)
{
    *refused = false;
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
        *refused = true;
        return true;
    }
    return true;
}

/* A live node.db is never mutated by a one-shot CLI process. Forward the exact
 * canonical input to the authenticated daemon, where the same handler
 * revalidates it and commits through app_runtime_node_db(). */
/* Encode the input and place one blocking RPC call, timing each stage. */
static bool zdev_live_send(
    const struct json_value *input, const char *rpc_method,
    const char *evidence, struct zcl_command_reply *reply, char **raw_out,
    int64_t *encode_us, int64_t *rpc_us, size_t *needed_out,
    size_t *response_bytes_out)
{
    int64_t encode_started_us = platform_time_monotonic_us();
    char *wire = NULL; size_t needed = 0;
    if (!zdev_live_encode_params(input, &wire, &needed, reply, evidence))
        return false;
    *encode_us = platform_time_monotonic_us() - encode_started_us;
    *needed_out = needed;
    zcl_native_bridge_ensure_rpc();
    int64_t rpc_started_us = platform_time_monotonic_us();
    char *raw = node_rpc_call(rpc_method, wire);
    *rpc_us = platform_time_monotonic_us() - rpc_started_us;
    *response_bytes_out = raw ? strlen(raw) : 0;
    free(wire);
    *raw_out = raw;
    return true;
}

/* Decode the daemon's response and dispatch to the success/failure mapper. */
static bool zdev_live_dispatch_response(
    struct zcl_command_reply *reply, char *raw, int64_t encode_us,
    int64_t rpc_us, size_t needed, size_t response_bytes,
    const char *fallback_code, const char *fallback_phase,
    const char *evidence)
{
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
        zdev_live_apply_success(reply, &body, data, encode_us, rpc_us,
                                decode_started_us, needed, response_bytes,
                                evidence);
    } else {
        zdev_live_apply_failure(reply, &body, fallback_code, fallback_phase,
                                evidence);
    }
    json_free(&body);
    return true;
}

bool zdev_forward_live_input(
    const struct json_value *input, const char *datadir,
    const char *rpc_method, const char *fallback_code,
    const char *fallback_phase, const char *evidence,
    struct zcl_command_reply *reply)
{
    if (!input || !datadir || !datadir[0] ||
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
    bool refused = false;
    if (!zdev_live_owner_requires_forward(db_path, reply, evidence, &refused))
        return false;
    if (refused)
        return true;
    char *raw = NULL;
    int64_t encode_us = 0, rpc_us = 0;
    size_t needed = 0, response_bytes = 0;
    if (!zdev_live_send(input, rpc_method, evidence, reply, &raw, &encode_us,
                        &rpc_us, &needed, &response_bytes))
        return true;
    return zdev_live_dispatch_response(
        reply, raw, encode_us, rpc_us, needed, response_bytes, fallback_code,
        fallback_phase, evidence);
}

bool zcl_native_forward_live_command(
    const struct zcl_command_request *request, const char *datadir,
    const char *rpc_method, const char *fallback_code,
    const char *fallback_phase, const char *evidence,
    struct zcl_command_reply *reply)
{
    return zdev_forward_live_input(
        request ? request->input : NULL, datadir, rpc_method, fallback_code,
        fallback_phase, evidence, reply);
}

bool zdev_load_write_scope(
    const char *workspace, const uint8_t root[32],
    struct vcs_zcode_write_scope_v1 *out)
{
    uint8_t *wire = NULL; size_t wire_len = 0;
    bool ok = vcs_object_load_raw_bounded(
            workspace, root, VCS_ZCODE_WRITE_SCOPE_WIRE_MAX,
            &wire, &wire_len) == 0 &&
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

bool zdev_capture_source_root(
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

/* Parse the comma-separated path-prefix list into a canonical write scope. */
static bool zdev_capture_write_scope_parse(
    const char *csv, struct vcs_zcode_write_scope_v1 *scope,
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
    vcs_zcode_write_scope_init(scope);
    char *save = NULL;
    for (char *path = strtok_r(copy, ",", &save); path;
         path = strtok_r(NULL, ",", &save)) {
        if (vcs_zcode_write_scope_add(scope, path) !=
            VCS_ZCODE_WRITE_SCOPE_OK) {
            zdev_fail(reply, "BAD_WRITE_SCOPE",
                      "write scope paths must be canonical, unique, and bounded");
            return false;
        }
    }
    return true;
}

/* Serialize and store the write scope, then verify the CAS readback
 * round-trips and re-derives the same root. */
static bool zdev_capture_write_scope_store(
    const char *workspace, const struct vcs_zcode_write_scope_v1 *scope,
    uint8_t out[32], struct zcl_command_reply *reply)
{
    uint8_t *wire = NULL; size_t wire_len = 0;
    if (vcs_zcode_write_scope_serialize(scope, &wire, &wire_len) !=
            VCS_ZCODE_WRITE_SCOPE_OK ||
        vcs_zcode_write_scope_root(scope, out) !=
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

bool zdev_capture_write_scope(
    const char *workspace, const char *csv, uint8_t out[32],
    struct zcl_command_reply *reply)
{
    struct vcs_zcode_write_scope_v1 scope;
    if (!zdev_capture_write_scope_parse(csv, &scope, reply))
        return false;
    return zdev_capture_write_scope_store(workspace, &scope, out, reply);
}

/* Resolve and capture the candidate workspace tree into the requester's CAS,
 * refusing an overlapping or unresolvable candidate directory. */
static bool zdev_capture_candidate_workspace(
    const char *workspace, const char *candidate_arg,
    uint8_t candidate_root[32], char candidate_workspace[ZDEV_PATH_MAX],
    struct zcl_command_reply *reply)
{
    if (!candidate_arg ||
        !platform_directory_canonical_real(candidate_arg, candidate_workspace,
                                           ZDEV_PATH_MAX) ||
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
    return true;
}

/* Load the planned base source, the captured candidate source, and the
 * planned write scope — the three manifests the derived patch is checked
 * against. Frees whatever it already loaded on any failure. */
static bool zdev_capture_candidate_manifests(
    const char *workspace, const struct vcs_zcode_task_v1 *task,
    const uint8_t candidate_root[32], struct vcs_manifest *base,
    struct vcs_manifest *candidate, struct vcs_zcode_write_scope_v1 *scope,
    struct zcl_command_reply *reply)
{
    if (!vcs_tree_load(workspace, task->source_root, base)) {
        zdev_fail(reply, "BASE_SOURCE_STALE",
                  "planned source manifest is absent or corrupt");
        return false;
    }
    if (!vcs_tree_load(workspace, candidate_root, candidate)) {
        vcs_manifest_free(base);
        zdev_fail(reply, "CANDIDATE_SOURCE_CORRUPT",
                  "captured candidate manifest failed CAS verification");
        return false;
    }
    if (!zdev_load_write_scope(workspace, task->write_scope_root, scope)) {
        vcs_manifest_free(candidate); vcs_manifest_free(base);
        zdev_fail(reply, "WRITE_SCOPE_STALE",
                  "planned write scope is absent or corrupt");
        return false;
    }
    return true;
}

/* Verify the stored patch CAS object round-trips byte-for-byte and that its
 * root re-derives from the reloaded bytes. */
static bool zdev_capture_candidate_patch_verify(
    const char *workspace, const uint8_t patch_root[32],
    const uint8_t *wire, size_t wire_len)
{
    uint8_t *checked_wire = NULL; size_t checked_len = 0;
    struct vcs_zcode_patch_v1 checked;
    uint8_t checked_root[32];
    bool parsed = false;
    bool stored = vcs_object_load_raw(workspace, patch_root, &checked_wire,
                                      &checked_len) == 0 &&
        checked_len == wire_len && memcmp(checked_wire, wire, wire_len) == 0;
    if (stored) {
        parsed = vcs_zcode_patch_parse(checked_wire, checked_len,
                                       &checked) == VCS_ZCODE_PATCH_OK;
        stored = parsed && vcs_zcode_patch_root(&checked, checked_root) ==
            VCS_ZCODE_PATCH_OK && memcmp(checked_root, patch_root, 32) == 0;
    }
    if (parsed) vcs_zcode_patch_free(&checked);
    free(checked_wire);
    return stored;
}

/* Derive the write-scoped patch between base and candidate, store it in CAS,
 * verify the readback, and compute the candidate's canonical source id.
 * Always consumes (frees) base, candidate, and scope. */
static bool zdev_capture_candidate_patch(
    const char *workspace, const struct vcs_zcode_task_v1 *task,
    struct vcs_manifest *base, struct vcs_manifest *candidate,
    const uint8_t candidate_root[32], struct vcs_zcode_write_scope_v1 *scope,
    uint8_t patch_root[32], uint32_t *changed_files, uint64_t *patch_bytes,
    uint8_t source_sha256[32], struct zcl_command_reply *reply)
{
    struct vcs_zcode_patch_v1 patch;
    enum vcs_zcode_patch_result derived = vcs_zcode_patch_derive(
        base, task->source_root, candidate, candidate_root, scope,
        task->max_changed_files, task->max_patch_bytes, &patch);
    if (derived != VCS_ZCODE_PATCH_OK) {
        vcs_manifest_free(candidate); vcs_manifest_free(base);
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
    if (stored)
        stored = zdev_capture_candidate_patch_verify(
            workspace, patch_root, wire, wire_len);
    uint8_t *manifest_wire = NULL; size_t manifest_len = 0;
    if (stored)
        stored = vcs_manifest_serialize(candidate, &manifest_wire,
                                        &manifest_len);
    if (stored)
        vcs_source_manifest_id(manifest_wire, manifest_len, source_sha256);
    free(manifest_wire); free(wire);
    vcs_zcode_patch_free(&patch);
    vcs_manifest_free(candidate); vcs_manifest_free(base);
    if (!stored) {
        zdev_fail(reply, "PATCH_CAS_FAILED",
                  "canonical patch CAS readback verification failed");
        return false;
    }
    return true;
}

bool zdev_capture_candidate(
    const char *workspace, const char *candidate_arg,
    const struct vcs_zcode_task_v1 *task, uint8_t candidate_root[32],
    uint8_t patch_root[32], uint8_t source_sha256[32],
    uint32_t *changed_files, uint64_t *patch_bytes,
    struct zcl_command_reply *reply)
{
    char candidate_workspace[ZDEV_PATH_MAX];
    if (!zdev_capture_candidate_workspace(
            workspace, candidate_arg, candidate_root, candidate_workspace,
            reply))
        return false;
    struct vcs_manifest base, candidate;
    struct vcs_zcode_write_scope_v1 scope;
    if (!zdev_capture_candidate_manifests(
            workspace, task, candidate_root, &base, &candidate, &scope,
            reply))
        return false;
    if (!zdev_capture_candidate_patch(
            workspace, task, &base, &candidate, candidate_root, &scope,
            patch_root, changed_files, patch_bytes, source_sha256, reply))
        return false;
    uint8_t current_base[32];
    if (vcs_tree_capture_path(workspace, current_base) != VCS_OK ||
        memcmp(current_base, task->source_root, 32) != 0) {
        zdev_fail(reply, "BASE_SOURCE_STALE",
                  "base workspace changed during candidate admission");
        return false;
    }
    return true;
}
