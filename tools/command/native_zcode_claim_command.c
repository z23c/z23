/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: scratch-only plan/commit/show adapters for signed creation_claim.v2. */
#include "command/native_command.h"

#include "base/hex.h"
#include "json/json.h"
#include "platform/private_directory.h"
#include "vcs/vcs_object.h"
#include "vcs/zcode_creation_claim.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#if !defined(_WIN32)
#include <sys/stat.h>
#endif

static const char *zclaim_str(const struct json_value *input, const char *key)
{
    const struct json_value *value = input ? json_get(input, key) : NULL;
    return value && value->type == JSON_STR ? json_get_str(value) : NULL;
}

static bool zclaim_keys(const struct json_value *input,
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

static void zclaim_fail(struct zcl_command_reply *reply, const char *code,
                        const char *detail)
{
    zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                           ZCL_COMMAND_EXIT_INVALID, code, "validate", false,
                           false, detail, "zcode.commons.claim");
}

static void zclaim_hex(struct json_value *data, const char *key,
                       const uint8_t root[32])
{
    char hex[65];
    zcl_hex_encode(root, 32, hex);
    (void)json_push_kv_str(data, key, hex);
}

static void zclaim_render(
    struct json_value *data, const struct vcs_zcode_creation_claim_wire_v2 *claim,
    const uint8_t root[32], bool persisted, const char *next_command)
{
    zclaim_hex(data, "claim_root", root);
    zclaim_hex(data, "recipient_binding_root", claim->recipient_binding_root);
    zclaim_hex(data, "workspace_lineage_root", claim->workspace_lineage_root);
    zclaim_hex(data, "semantic_lineage_root", claim->semantic_lineage_root);
    zclaim_hex(data, "evidence_root", claim->evidence_root);
    zclaim_hex(data, "commons_admission_root", claim->commons_admission_root);
    zclaim_hex(data, "signer_pubkey", claim->signer_pubkey);
    (void)json_push_kv_int(data, "category", claim->category);
    (void)json_push_kv_int(data, "flags", claim->flags);
    (void)json_push_kv_int(data, "maturity_height",
                           (int64_t)claim->maturity_height);
    (void)json_push_kv_int(data, "maturity_mtp", claim->maturity_mtp);
    bool eligible_flags =
        (claim->flags & VCS_ZCODE_CLAIM_V2_REQUIRED_FLAGS) ==
            VCS_ZCODE_CLAIM_V2_REQUIRED_FLAGS &&
        (claim->flags & VCS_ZCODE_CLAIM_V2_INVALIDATING_FLAGS) == 0;
    (void)json_push_kv_bool(data, "signature_verified", true);
    (void)json_push_kv_bool(data, "selection_flags_eligible",
                            eligible_flags);
    (void)json_push_kv_bool(data, "persisted", persisted);
    (void)json_push_kv_bool(data, "simulation_only", true);
    (void)json_push_kv_bool(data, "not_owner_approved", true);
    (void)json_push_kv_bool(data, "issuance_enabled", false);
    (void)json_push_kv_bool(data, "funds_moved", false);
    (void)json_push_kv_bool(data, "custody_used", false);
    (void)json_push_kv_str(data, "next_command", next_command);
}

static bool zclaim_parse_inline(
    const struct zcl_command_request *request, struct zcl_command_reply *reply,
    struct vcs_zcode_creation_claim_wire_v2 *claim,
    uint8_t wire[VCS_ZCODE_CREATION_CLAIM_WIRE_BYTES], uint8_t root[32],
    const char **workspace_out)
{
    static const char *const keys[] = {"workspace", "claim"};
    const struct json_value *input = request ? request->input : NULL;
    const char *workspace = zclaim_str(input, "workspace");
    const char *hex = zclaim_str(input, "claim");
    if (!request || !reply || !zclaim_keys(input, keys, 2) || !workspace ||
        !hex || strlen(hex) != VCS_ZCODE_CREATION_CLAIM_WIRE_BYTES * 2u) {
        zclaim_fail(reply, "BAD_CREATION_CLAIM_INPUT",
                    "workspace and exact signed creation_claim.v2 hex are required");
        return false;
    }
    if (!zcl_native_zcode_workspace_is_explicit_scratch(workspace)) {
        zclaim_fail(reply, "UNSAFE_CREATION_CLAIM_WORKSPACE",
                    "workspace must explicitly name an isolated tmp, test-tmp, or scratch path");
        return false;
    }
    if (!zcl_hex_decode_lower(hex, wire,
                              VCS_ZCODE_CREATION_CLAIM_WIRE_BYTES) ||
        vcs_zcode_creation_claim_wire_v2_decode(
            claim, wire, VCS_ZCODE_CREATION_CLAIM_WIRE_BYTES) !=
            VCS_ZCODE_CREATION_CLAIM_OK ||
        vcs_zcode_creation_claim_wire_v2_root(claim, root) !=
            VCS_ZCODE_CREATION_CLAIM_OK) {
        zclaim_fail(reply, "CREATION_CLAIM_REFUSED",
                    "claim must be exact lowercase canonical bytes with a valid signature");
        return false;
    }
    *workspace_out = workspace;
    return true;
}

static void zclaim_handle_inline(const struct zcl_command_request *request,
                                 struct zcl_command_reply *reply, bool persist)
{
    struct vcs_zcode_creation_claim_wire_v2 claim;
    uint8_t wire[VCS_ZCODE_CREATION_CLAIM_WIRE_BYTES], root[32];
    const char *workspace = NULL;
    if (!zclaim_parse_inline(request, reply, &claim, wire, root, &workspace))
        return;
    bool workspace_ready = true;
    if (persist) {
#if defined(_WIN32)
        workspace_ready = platform_private_directory_ensure(workspace);
#else
        workspace_ready = mkdir(workspace, 0700) == 0 || errno == EEXIST;
#endif
    }
    if (!workspace_ready) {
        zclaim_fail(reply, "CREATION_CLAIM_WORKSPACE_CREATE_REFUSED",
                    "explicit scratch workspace root could not be created");
        return;
    }
    if (persist &&
        (!vcs_object_store_init(workspace) ||
         !vcs_object_put_addressed(workspace, root, wire, sizeof(wire)))) {
        zclaim_fail(reply, "CREATION_CLAIM_STORE_REFUSED",
                    "scratch CAS refused the canonical signed claim");
        return;
    }
    zclaim_render(&reply->data, &claim, root, persist,
                  persist ? "zcode commons backlog"
                          : "zcode commons claim commit");
}

void zcl_native_handle_zcode_commons_claim_plan(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    zclaim_handle_inline(request, reply, false);
}

void zcl_native_handle_zcode_commons_claim_commit(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    zclaim_handle_inline(request, reply, true);
}

void zcl_native_handle_zcode_commons_claim_show(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    static const char *const keys[] = {"workspace", "root"};
    const struct json_value *input = request ? request->input : NULL;
    const char *workspace = zclaim_str(input, "workspace");
    const char *root_hex = zclaim_str(input, "root");
    uint8_t wanted[32];
    if (!request || !reply || !zclaim_keys(input, keys, 2) || !workspace ||
        !root_hex || strlen(root_hex) != 64 ||
        !zcl_hex_decode_lower(root_hex, wanted, sizeof(wanted)) ||
        !zcl_native_zcode_workspace_is_explicit_scratch(workspace)) {
        zclaim_fail(reply, "BAD_CREATION_CLAIM_SHOW_INPUT",
                    "explicit scratch workspace and exact lowercase root are required");
        return;
    }
    uint8_t *wire = NULL; size_t wire_len = 0;
    if (vcs_object_load_raw_bounded(
            workspace, wanted, VCS_ZCODE_CREATION_CLAIM_WIRE_BYTES,
            &wire, &wire_len) != 0) {
        zclaim_fail(reply, "CREATION_CLAIM_NOT_FOUND",
                    "the exact signed claim is absent from scratch CAS");
        return;
    }
    struct vcs_zcode_creation_claim_wire_v2 claim;
    uint8_t actual[32];
    bool valid = wire_len == VCS_ZCODE_CREATION_CLAIM_WIRE_BYTES &&
        vcs_zcode_creation_claim_wire_v2_decode(&claim, wire, wire_len) ==
            VCS_ZCODE_CREATION_CLAIM_OK &&
        vcs_zcode_creation_claim_wire_v2_root(&claim, actual) ==
            VCS_ZCODE_CREATION_CLAIM_OK &&
        memcmp(actual, wanted, sizeof(actual)) == 0;
    free(wire);
    if (!valid) {
        zclaim_fail(reply, "CREATION_CLAIM_CORRUPT",
                    "stored claim bytes failed signature or root verification");
        return;
    }
    zclaim_render(&reply->data, &claim, actual, true,
                  "zcode commons backlog");
}
