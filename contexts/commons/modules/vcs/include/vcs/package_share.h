/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Expose bounded signed package-share verification and cleanup. */
#ifndef VCS_PACKAGE_SHARE_H
#define VCS_PACKAGE_SHARE_H
#include "vcs/package_manifest.h"
#include "vcs/package_publish.h"
#include "vcs/package_recipe.h"
#include "vcs/package_release.h"
#include "platform/temp_directory.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define ZCL_PACKAGE_BUNDLE_MAGIC "Z23SHARE"
#define ZCL_PACKAGE_BUNDLE_VERSION 1u
#define VCS_PACKAGE_SHARE_PATH_MAX 4400
struct zcl_package_bundle_wires {
    const uint8_t *release; size_t release_len;
    const uint8_t *manifest; size_t manifest_len;
    const uint8_t *recipe; size_t recipe_len;
};
struct vcs_package_share {
    struct zcl_package_bundle_wires wires;
    uint8_t tree[32];
    const uint8_t *source; size_t source_len;
    struct vcs_package_release release;
    uint8_t release_id[32];
    struct vcs_package_manifest manifest;
    struct vcs_package_recipe recipe;
    bool parsed, loaded, source_checked;
    char scratch[PLATFORM_TEMP_PATH_MAX];
    char src[VCS_PACKAGE_SHARE_PATH_MAX];
    struct vcs_package_publish_report report;
};
/* Bytes are borrowed until cleanup; source is private disposable scratch.
 * Load initializes a fresh object, and cleanup is required after every load
 * attempt. Call check_source at most once before cleanup, even on failure. */
bool vcs_package_share_load(struct vcs_package_share *share, const uint8_t *bytes,
                            size_t len, const char **reason);
bool vcs_package_share_check_source(struct vcs_package_share *share,
                                    const char **reason);
void vcs_package_share_cleanup(struct vcs_package_share *share);
#endif
