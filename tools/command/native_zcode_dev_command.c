/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Typed adapters for ZCODE create, use, lane, and lane-guide
 * commands, plus the small canonical-root/JSON-field readers the sibling
 * dev-loop translation units (native_zcode_dev_capture.c,
 * native_zcode_dev_tasks.c, native_zcode_dev_improve.c,
 * native_zcode_dev_publish.c) share through native_zcode_dev_priv.h. */

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

const char *zdev_str(const struct json_value *input, const char *key)
{
    const struct json_value *v = input ? json_get(input, key) : NULL;
    return v ? json_get_str(v) : NULL;
}

int64_t zdev_int(const struct json_value *input, const char *key,
                 int64_t fallback)
{
    const struct json_value *v = input ? json_get(input, key) : NULL;
    return v ? json_get_int(v) : fallback;
}

void zdev_fail(struct zcl_command_reply *reply, const char *code,
              const char *detail)
{
    zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                           ZCL_COMMAND_EXIT_INVALID, code, "validate", false,
                           false, detail, "zcode.improve");
}

bool zdev_root(const struct json_value *input, const char *key,
              uint8_t out[32], struct zcl_command_reply *reply)
{
    const char *value = zdev_str(input, key);
    char detail[128];
    if (zcl_native_require_hex64(key, value, out, detail, sizeof(detail)))
        return true;
    zdev_fail(reply, "BAD_ROOT", detail);
    return false;
}

void zdev_push_root(struct json_value *out, const char *key,
                    const uint8_t root[32])
{
    char hex[65];
    zcl_hex_encode(root, 32, hex);
    (void)json_push_kv_str(out, key, hex);
}

uint8_t *zdev_hex_wire(const struct json_value *input, const char *key,
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

/* A candidate/base directory prefix-contains check: true when either path is
 * a directory ancestor of the other (or they are equal). Factored so the two
 * comparisons that build it each carry their own bounded complexity. */
static bool zdev_path_is_prefix(const char *prefix, const char *other)
{
    size_t plen = strlen(prefix), olen = strlen(other);
#if defined(_WIN32)
    return olen >= plen && _strnicmp(prefix, other, plen) == 0 &&
        (olen == plen || other[plen] == '/' || other[plen] == '\\');
#else
    return olen >= plen && memcmp(prefix, other, plen) == 0 &&
        (olen == plen || other[plen] == '/');
#endif
}

bool zdev_paths_overlap(const char *a, const char *b)
{
    return zdev_path_is_prefix(a, b) || zdev_path_is_prefix(b, a);
}

/* Resolve fixed_path (an absolute or otherwise located input file) into a
 * path relative to candidate_arg, refusing anything that escapes the
 * candidate workspace or disagrees with an already-claimed relpath. */
static bool zdev_candidate_fixed_relpath(
    const char *candidate_arg, const char *fixed_path, const char *claimed,
    char *out, struct zcl_command_reply *reply)
{
    char candidate[ZDEV_PATH_MAX], fixed[ZDEV_PATH_MAX];
    struct platform_positioned_file input;
    platform_positioned_file_init(&input);
    bool resolved = candidate_arg &&
        platform_directory_canonical_real(candidate_arg, candidate,
                                          sizeof(candidate)) &&
        platform_positioned_file_open(&input, fixed_path) &&
        platform_positioned_file_path(&input, fixed, sizeof(fixed));
    platform_positioned_file_close(&input);
    if (!resolved) {
        zdev_fail(reply, "BAD_FIXED_INPUT",
                  "fixed input must resolve inside candidate_workspace");
        return false;
    }
    size_t candidate_len = strlen(candidate);
#if defined(_WIN32)
    bool prefix_matches = _strnicmp(candidate, fixed, candidate_len) == 0;
    bool child_separator = fixed[candidate_len] == '/' ||
                           fixed[candidate_len] == '\\';
#else
    bool prefix_matches = strncmp(candidate, fixed, candidate_len) == 0;
    bool child_separator = fixed[candidate_len] == '/';
#endif
    if (!prefix_matches || !child_separator ||
        fixed[candidate_len + 1u] == '\0') {
        zdev_fail(reply, "FIXED_INPUT_OUTSIDE_CANDIDATE",
                  "fixed input authority is limited to candidate_workspace");
        return false;
    }
    char *derived = fixed + candidate_len + 1u;
#if defined(_WIN32)
    for (char *p = derived; *p; ++p)
        if (*p == '\\') *p = '/';
#endif
    if (claimed && strcmp(claimed, derived) != 0) {
        zdev_fail(reply, "FIXED_INPUT_PATH_MISMATCH",
                  "fixed_input_relpath does not match fixed_input_path");
        return false;
    }
    (void)snprintf(out, VCS_PATH_MAX + 1u, "%s", derived);
    return true;
}

bool zdev_candidate_input_path(
    const char *candidate_arg, const char *fixed_path, const char *claimed,
    char *out, struct zcl_command_reply *reply)
{
    const char *selected = claimed;
    char derived[VCS_PATH_MAX + 1u];
    if (fixed_path) {
        if (!zdev_candidate_fixed_relpath(
                candidate_arg, fixed_path, claimed, derived, reply))
            return false;
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

void zdev_push_lane(struct json_value *out,
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
    zcl_native_zcode_evidence_exact(
        zdev_str(request->input, "workspace"),
        zdev_str(request->input, "datadir"),
        zdev_str(request->input, "action_id"), reply);
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
    if (!workspace_arg || !platform_directory_canonical_real(
            workspace_arg, workspace, sizeof(workspace)) ||
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
