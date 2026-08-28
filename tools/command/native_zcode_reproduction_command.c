/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: scratch-only portable ZCODE reproduction challenge adapters. */
#include "command/native_command.h"

#include "base/hex.h"
#include "json/json.h"
#include "platform/private_directory.h"
#include "vcs/vcs_object.h"
#include "vcs/zcode_reproduction_request.h"

#include <stdlib.h>
#include <string.h>
#if !defined(_WIN32)
#include <errno.h>
#include <sys/stat.h>
#endif

static const char *zrr_str(const struct json_value *input, const char *key)
{
    const struct json_value *value = input ? json_get(input, key) : NULL;
    return value && value->type == JSON_STR ? json_get_str(value) : NULL;
}

static bool zrr_keys(const struct json_value *input,
                     const char *const *allowed, size_t count)
{
    if (!input || input->type != JSON_OBJ) return false;
    for (size_t i = 0; i < input->num_children; i++) {
        bool known = false;
        for (size_t j = 0; j < count; j++)
            known = known || strcmp(input->keys[i], allowed[j]) == 0;
        if (!known) return false;
    }
    return true;
}

static void zrr_fail(struct zcl_command_reply *reply, const char *code,
                     const char *detail)
{
    zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                           ZCL_COMMAND_EXIT_INVALID, code, "validate", false,
                           false, detail, "zcode.commons.reproduction");
}

static void zrr_hex(struct json_value *data, const char *key,
                    const uint8_t root[32])
{
    char hex[65];
    zcl_hex_encode(root, 32, hex);
    (void)json_push_kv_str(data, key, hex);
}

static bool zrr_parse(const struct zcl_command_request *request,
                      struct zcl_command_reply *reply,
                      struct vcs_zcode_reproduction_request_v1 *out,
                      uint8_t wire[VCS_ZCODE_REPRODUCTION_REQUEST_WIRE_BYTES],
                      uint8_t root[32], const char **workspace_out)
{
    static const char *const keys[] = {
        "workspace", "request_hex", "now_unix"
    };
    const struct json_value *input = request ? request->input : NULL;
    const char *workspace = zrr_str(input, "workspace");
    const char *hex = zrr_str(input, "request_hex");
    const struct json_value *now = input ? json_get(input, "now_unix") : NULL;
    if (!request || !reply || !zrr_keys(input, keys, 3) || !workspace ||
        !hex || strlen(hex) !=
                    VCS_ZCODE_REPRODUCTION_REQUEST_WIRE_BYTES * 2u || !now ||
        now->type != JSON_INT || json_get_int(now) <= 0) {
        zrr_fail(reply, "BAD_REPRODUCTION_CHALLENGE_INPUT",
                 "workspace, exact request_hex and positive now_unix are required");
        return false;
    }
    if (!zcl_native_zcode_workspace_is_explicit_scratch(workspace)) {
        zrr_fail(reply, "UNSAFE_REPRODUCTION_WORKSPACE",
                 "workspace must explicitly name an isolated tmp, test-tmp, or scratch path");
        return false;
    }
    if (!zcl_hex_decode_lower(hex, wire,
                              VCS_ZCODE_REPRODUCTION_REQUEST_WIRE_BYTES)) {
        zrr_fail(reply, "BAD_REPRODUCTION_CHALLENGE_HEX",
                 "request_hex must be exact lowercase canonical bytes");
        return false;
    }
    enum vcs_zcode_reproduction_error error =
        vcs_zcode_reproduction_request_parse(
            wire, VCS_ZCODE_REPRODUCTION_REQUEST_WIRE_BYTES, out);
    int64_t evaluated = json_get_int(now);
    if (error != VCS_ZCODE_REPRODUCTION_OK ||
        evaluated < out->created_unix || evaluated >= out->expires_unix) {
        zrr_fail(reply, "REPRODUCTION_CHALLENGE_REFUSED",
            error == VCS_ZCODE_REPRODUCTION_OK ? "challenge is not fresh"
                : vcs_zcode_reproduction_error_string(error));
        return false;
    }
    error = vcs_zcode_reproduction_request_root(out, root);
    if (error != VCS_ZCODE_REPRODUCTION_OK) {
        zrr_fail(reply, "REPRODUCTION_CHALLENGE_ROOT_REFUSED",
                 vcs_zcode_reproduction_error_string(error));
        return false;
    }
    *workspace_out = workspace;
    return true;
}

static void zrr_render(
    struct json_value *data,
    const struct vcs_zcode_reproduction_request_v1 *request,
    const uint8_t root[32], bool persisted)
{
    (void)json_push_kv_str(data, "mode", "shadow_pre_genesis");
    zrr_hex(data, "reproduction_request_root", root);
    zrr_hex(data, "task_root", request->task_root);
    zrr_hex(data, "candidate_root", request->candidate_root);
    zrr_hex(data, "package_root", request->package_root);
    zrr_hex(data, "release_root", request->release_root);
    zrr_hex(data, "recipe_root", request->recipe_root);
    zrr_hex(data, "dependency_lock_root", request->dependency_lock_root);
    zrr_hex(data, "toolchain_capsule_root",
            request->toolchain_capsule_root);
    zrr_hex(data, "reference_build_root", request->reference_build_root);
    zrr_hex(data, "output_manifest_root", request->output_manifest_root);
    zrr_hex(data, "challenge_nonce", request->challenge_nonce);
    (void)json_push_kv_int(data, "created_unix", request->created_unix);
    (void)json_push_kv_int(data, "expires_unix", request->expires_unix);
    (void)json_push_kv_int(data, "max_cpu_seconds",
                           request->max_cpu_seconds);
    (void)json_push_kv_int(data, "max_processes", request->max_processes);
    (void)json_push_kv_bool(data, "full_confinement_required", true);
    (void)json_push_kv_bool(data, "public_bytes_only", true);
    (void)json_push_kv_bool(data, "persisted", persisted);
    (void)json_push_kv_bool(data, "simulated", true);
    (void)json_push_kv_bool(data, "token_exists", false);
    (void)json_push_kv_bool(data, "funds_moved", false);
    (void)json_push_kv_bool(data, "custody_used", false);
    (void)json_push_kv_bool(data, "genesis_gate_satisfied", false);
}

static void zrr_handle(const struct zcl_command_request *request,
                       struct zcl_command_reply *reply, bool persist)
{
    struct vcs_zcode_reproduction_request_v1 parsed;
    uint8_t wire[VCS_ZCODE_REPRODUCTION_REQUEST_WIRE_BYTES], root[32];
    const char *workspace = NULL;
    if (!zrr_parse(request, reply, &parsed, wire, root, &workspace)) return;
    bool workspace_ready = true;
    if (persist) {
#if defined(_WIN32)
        workspace_ready = platform_private_directory_ensure(workspace);
#else
        workspace_ready = mkdir(workspace, 0700) == 0 || errno == EEXIST;
#endif
    }
    if (!workspace_ready) {
        zrr_fail(reply, "REPRODUCTION_WORKSPACE_CREATE_REFUSED",
                 "explicit scratch workspace root could not be created");
        return;
    }
    if (persist &&
        (!vcs_object_store_init(workspace) ||
         !vcs_object_put_addressed(workspace, root, wire, sizeof(wire)))) {
        zrr_fail(reply, "REPRODUCTION_CHALLENGE_STORE_REFUSED",
                 "scratch CAS refused the canonical request");
        return;
    }
    zrr_render(&reply->data, &parsed, root, persist);
}

void zcl_native_handle_zcode_reproduction_challenge_plan(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    zrr_handle(request, reply, false);
}

void zcl_native_handle_zcode_reproduction_challenge_commit(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    zrr_handle(request, reply, true);
}
