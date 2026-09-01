/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: canonical bounded public-API capsule for ZCODE C23 packages. */
#ifndef ZCL_VCS_PACKAGE_CAPSULE_H
#define ZCL_VCS_PACKAGE_CAPSULE_H

#include "vcs/package_manifest.h"
#include "vcs/package_recipe.h"

#include <stddef.h>
#include <stdint.h>

#define VCS_PACKAGE_CAPSULE_VERSION 1u
#define VCS_PACKAGE_CAPSULE_ROOT_DOMAIN "zcl.zcode_api_capsule.v1"
#define VCS_PACKAGE_CAPSULE_MAX_HEADERS \
    VCS_PACKAGE_RECIPE_MAX_PATHS_PER_LIST
#define VCS_PACKAGE_CAPSULE_MAX_WIRE_BYTES (64u * 1024u)

enum vcs_package_capsule_error {
    VCS_PACKAGE_CAPSULE_OK = 0,
    VCS_PACKAGE_CAPSULE_ERR_NULL,
    VCS_PACKAGE_CAPSULE_ERR_ALLOC,
    VCS_PACKAGE_CAPSULE_ERR_HEADER,
    VCS_PACKAGE_CAPSULE_ERR_COUNT,
    VCS_PACKAGE_CAPSULE_ERR_MAGIC,
    VCS_PACKAGE_CAPSULE_ERR_VERSION,
    VCS_PACKAGE_CAPSULE_ERR_TRUNCATED,
    VCS_PACKAGE_CAPSULE_ERR_TRAILING,
    VCS_PACKAGE_CAPSULE_ERR_ORDER,
    VCS_PACKAGE_CAPSULE_ERR_OVERSIZE,
};

struct vcs_package_capsule_header {
    char path[VCS_PACKAGE_PATH_MAX + 1u];
    uint8_t file_root[32];
};

struct vcs_package_capsule {
    struct vcs_package_capsule_header headers[VCS_PACKAGE_CAPSULE_MAX_HEADERS];
    size_t count;
};

const char *vcs_package_capsule_error_string(
    enum vcs_package_capsule_error error);
void vcs_package_capsule_init(struct vcs_package_capsule *capsule);
enum vcs_package_capsule_error vcs_package_capsule_derive(
    const struct vcs_package_manifest *manifest,
    const struct vcs_package_recipe *recipe,
    struct vcs_package_capsule *out);
enum vcs_package_capsule_error vcs_package_capsule_serialize(
    const struct vcs_package_capsule *capsule, uint8_t **wire,
    size_t *wire_len);
enum vcs_package_capsule_error vcs_package_capsule_parse(
    const uint8_t *wire, size_t wire_len, struct vcs_package_capsule *out);
enum vcs_package_capsule_error vcs_package_capsule_root(
    const struct vcs_package_capsule *capsule, uint8_t out[32]);

#endif /* ZCL_VCS_PACKAGE_CAPSULE_H */
