/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0
 * purpose: Expose bounded inert source checks to release packaging callers. */
#include "command/native_command.h"
#include "command/app_installed_source.h"
#include "command/native_zcode_package_copy.h"
#include "base/hex.h"
#include <string.h>

static bool asv_inputs(const struct json_value *input)
{
    static const char *const keys[] = {"app", "artifact_dir", "projection_sha3", "image_file"};
    if (!input || input->type != JSON_OBJ || input->num_children != 4) return false;
    unsigned seen = 0;
    for (size_t i = 0; i < input->num_children; ++i) {
        unsigned bit = 0;
        for (size_t j = 0; j < sizeof(keys) / sizeof(keys[0]); ++j)
            if (!strcmp(input->keys[i], keys[j])) bit = 1u << j;
        const char *value = json_get_str(&input->children[i]);
        if (!bit || (seen & bit) || input->children[i].type != JSON_STR || !value || !*value)
            return false;
        seen |= bit;
    }
    return seen == 15u;
}

static bool asv_result(struct json_value *data, const struct app_installed_source *source)
{
    return json_push_kv_str(data, "app", source->app) &&
        json_push_kv_bool(data, "artifact_consistent", true) &&
        json_push_kv_bool(data, "source_package_checked", false) &&
        json_push_kv_str(data, "authority", "caller-supplied projection digest") &&
        zcl_package_copy_push_root(data, "projection_sha3", source->projection_sha3) &&
        zcl_package_copy_push_root(data, "tree_root", source->tree_root) &&
        zcl_package_copy_push_root(data, "package_root", source->package_root) &&
        zcl_package_copy_push_root(data, "recipe_root", source->recipe_root) &&
        zcl_package_copy_push_root(data, "record_id", source->record_id) &&
        zcl_package_copy_push_root(data, "image_sha3", source->build.image_sha3);
}

void zcl_native_handle_app_source_verify(const struct zcl_command_request *request,
                                        struct zcl_command_reply *reply)
{
    if (!reply) return;
    if (!request || !asv_inputs(request->input)) {
        zcl_package_copy_fail(reply, "BAD_INPUT", false,
            "Provide exactly app, artifact_dir, projection_sha3 and image_file as strings.",
            "app.source.verify");
        return;
    }
    const struct json_value *in = request->input;
    struct app_installed_source source;
    app_installed_source_init(&source);
    char why[256];
    bool ok = app_installed_source_load(zcl_package_copy_str(in, "artifact_dir"),
        zcl_package_copy_str(in, "projection_sha3"), zcl_package_copy_str(in, "image_file"),
        &source, why, sizeof(why));
    if (!ok) zcl_package_copy_fail(reply, "SOURCE_ARTIFACT_INVALID", false, why, "app.source.verify");
    else if (strcmp(source.app, zcl_package_copy_str(in, "app")))
        zcl_package_copy_fail(reply, "APP_MISMATCH", false,
            "The pinned source artifacts name a different app.", "app.source.verify");
    else if (!asv_result(&reply->data, &source)) {
        json_free(&reply->data); json_set_object(&reply->data);
        zcl_package_copy_fail(reply, "OUT_OF_MEMORY", false,
            "Cannot encode source artifact observations.", "app.source.verify");
    }
    app_installed_source_free(&source);
}
