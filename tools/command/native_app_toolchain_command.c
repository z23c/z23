/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0
 * Purpose: Read-only semantic compiler-kit verification for release packaging. */
#include "command/native_command.h"
#include "command/native_zcode_package_copy.h"
#include "command/app_toolchain.h"
#include <string.h>
static bool atv_input(const struct json_value *in)
{
    if (!in || in->type != JSON_OBJ || in->num_children != 2) return false;
    unsigned seen = 0;
    for (size_t i = 0; i < 2; ++i) {
        unsigned bit = !strcmp(in->keys[i], "artifact_dir") ? 1u :
            !strcmp(in->keys[i], "descriptor_sha3") ? 2u : 0u;
        const char *text = json_get_str(&in->children[i]);
        if (!bit || (seen & bit) || in->children[i].type != JSON_STR || !text || !*text) return false;
        seen |= bit;
    }
    return seen == 3;
}
void zcl_native_handle_app_toolchain_verify(const struct zcl_command_request *request,
    struct zcl_command_reply *reply)
{
    if (!reply) return;
    if (!request || !atv_input(request->input)) {
        zcl_package_copy_fail(reply, "BAD_INPUT", false,
            "Provide exactly artifact_dir and independently pinned descriptor_sha3.", "app.toolchain.verify");
        return;
    }
    struct app_toolchain kit = {0}; char why[256] = "";
    bool ok = app_toolchain_artifact(&kit, zcl_package_copy_str(request->input, "artifact_dir"),
        zcl_package_copy_str(request->input, "descriptor_sha3"), why, sizeof(why));
    if (!ok) zcl_package_copy_fail(reply, "TOOLCHAIN_ARTIFACT_INVALID", false, why, "app.toolchain.verify");
    else if (!(json_push_kv_bool(&reply->data, "artifact_consistent", true) &&
        json_push_kv_bool(&reply->data, "executed", false) &&
        json_push_kv_bool(&reply->data, "selected", false) &&
        json_push_kv_str(&reply->data, "target", kit.target) &&
        json_push_kv_str(&reply->data, "policy", APP_TOOLCHAIN_POLICY) &&
        json_push_kv_int(&reply->data, "files", (int64_t)kit.manifest.count) &&
        zcl_package_copy_push_root(&reply->data, "tree_root", kit.tree) &&
        zcl_package_copy_push_root(&reply->data, "env_root", kit.env)))
        zcl_package_copy_fail(reply, "OUT_OF_MEMORY", false, "Cannot encode kit observations.", "app.toolchain.verify");
    app_toolchain_free(&kit);
}
