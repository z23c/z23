/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Shared byte/chunk mechanics for content.v2 carriers. */

#ifndef ZCL_VCS_PACKAGE_CONTENT_H
#define ZCL_VCS_PACKAGE_CONTENT_H

#include "vcs/package_manifest.h"
#include "vcs/package_store.h"

/* Derive canonical content.v2 chunk hashes and add one file to a manifest.
 * This creates no alternate manifest or object identity. */
bool vcs_package_content_add_file(struct vcs_package_manifest *manifest,
                                  const char *path, uint32_t mode,
                                  const uint8_t *bytes, size_t bytes_len);

/* Admit one complete in-memory file through the same coordinate-checked CAS
 * path used by swarm DATA. Existing objects are reused by package_store. The
 * package manifest must already be admitted. This owns no retry or lifecycle
 * state; package_swarm remains the sole transfer scheduler. */
enum vcs_package_store_result vcs_package_content_put_file(
    struct vcs_package_store *store, const uint8_t package_root[32],
    const char *path, const uint8_t *bytes, size_t bytes_len);

/* Reconstruct one manifest-indexed file from verified CAS objects. The
 * supplied manifest is re-rooted against package_root before any bytes are
 * returned. Allocates *out (including a one-byte allocation for an empty
 * file); callers own it. */
enum vcs_package_store_result vcs_package_content_get_file_at(
    struct vcs_package_store *store, const uint8_t package_root[32],
    const struct vcs_package_manifest *manifest, uint32_t file_index,
    uint8_t **out, size_t *out_len);

#endif /* ZCL_VCS_PACKAGE_CONTENT_H */
