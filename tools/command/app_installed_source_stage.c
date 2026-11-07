/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0
 * purpose: Reconstruct consented installed source and derive its content identity. */
#include "command/app_installed_source.h"
#include "platform/temp_directory.h"
#include "util/file_tree_ops.h"
#include "util/path_util.h"
#include "vcs/package_prepare.h"
#include "vcs/source_bundle.h"
#include "vcs/vcs.h"
#include <stdio.h>
#include <string.h>

static bool ais_stage_matches(const struct app_installed_source *source,
                               const struct vcs_package_prepared *prepared)
{
    return !memcmp(source->package_root, prepared->package_root, 32) &&
        !memcmp(source->recipe_root, prepared->recipe_root, 32) &&
        source->manifest.length == prepared->manifest_wire_len &&
        source->recipe.length == prepared->recipe_wire_len &&
        !memcmp(source->manifest.bytes, prepared->manifest_wire, source->manifest.length) &&
        !memcmp(source->recipe.bytes, prepared->recipe_wire, source->recipe.length);
}

static bool ais_stage_inputs(const struct app_installed_source *source,
    char *scratch, size_t scratch_cap, char *source_path, size_t source_cap)
{
    return source && source->bundle.bytes && source->manifest.bytes && source->recipe.bytes &&
        scratch && scratch_cap && source_path && source_cap;
}

static bool ais_stage_reconstruct(const struct app_installed_source *source,
    const char *scratch, char *staged, size_t staged_cap, size_t source_cap)
{
    struct vcs_source_bundle_metrics metrics;
#if defined(_WIN32)
    /* Preserve the existing store-backed path until direct output has
     * equivalent Windows emptiness and mode handling. */
    char store[PLATFORM_TEMP_PATH_MAX + 16];
    return zcl_path_join(store, sizeof(store), scratch, "store") &&
        zcl_path_join(staged, staged_cap, scratch, "source") &&
        strlen(staged) < source_cap && zcl_mkdir_p(store, 0700).ok &&
        zcl_mkdir_p(staged, 0700).ok &&
        vcs_source_bundle_import(source->bundle.bytes, source->bundle.length,
            source->tree_root, store, &metrics) == VCS_SOURCE_BUNDLE_OK &&
        vcs_tree_materialize_readonly_disposable(store, source->tree_root, staged,
            VCS_SOURCE_BUNDLE_MAX_SOURCE_BYTES, 0) == VCS_OK;
#else
    return zcl_path_join(staged, staged_cap, scratch, "source") &&
        strlen(staged) < source_cap &&
        zcl_mkdir_p(staged, 0700).ok &&
        vcs_source_bundle_materialize_disposable(source->bundle.bytes, source->bundle.length,
            source->tree_root, staged, &metrics) == VCS_SOURCE_BUNDLE_OK;
#endif
}

bool app_installed_source_stage(const struct app_installed_source *source,
    char *scratch, size_t scratch_cap, char *source_path, size_t source_cap,
    char *why, size_t why_cap)
{
    if (scratch && scratch_cap) scratch[0] = 0;
    if (source_path && source_cap) source_path[0] = 0;
    if (why && why_cap) why[0] = 0;
    if (!ais_stage_inputs(source, scratch, scratch_cap, source_path, source_cap))
        return app_installed_source_message(why, why_cap, "Verified retained source and output buffers are required.");
    if (!platform_temp_directory_create("z23-installed-source-", scratch, scratch_cap))
        return app_installed_source_message(why, why_cap, "Cannot create private source scratch.");
    char staged[PLATFORM_TEMP_PATH_MAX + 16];
    if (!ais_stage_reconstruct(source, scratch, staged, sizeof(staged), source_cap))
        return app_installed_source_message(why, why_cap, "Cannot reconstruct the retained source bundle.");
    struct vcs_package_prepared prepared;
    vcs_package_prepared_init(&prepared);
    enum vcs_package_prepare_error err = vcs_package_prepare_content(staged, &prepared, why, why_cap);
    bool ok = err == VCS_PACKAGE_PREPARE_OK && ais_stage_matches(source, &prepared);
    vcs_package_prepared_free(&prepared);
    if (!ok) return app_installed_source_message(why, why_cap,
        "Reconstructed source does not derive the pinned package and recipe.");
    memcpy(source_path, staged, strlen(staged) + 1);
    return true;
}
