/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Canonical manifest-derived ZCODE candidate patch evidence. */

#ifndef ZCL_VCS_ZCODE_PATCH_H
#define ZCL_VCS_ZCODE_PATCH_H

#include "vcs/vcs_manifest.h"
#include "vcs/zcode_dev.h"
#include "vcs/zcode_write_scope.h"

#include <stddef.h>
#include <stdint.h>

#define VCS_ZCODE_PATCH_VERSION 1u
#define VCS_ZCODE_PATCH_DOMAIN "zcl.zcode.patch.v1"
#define VCS_ZCODE_PATCH_HEADER_BYTES 88u
#define VCS_ZCODE_PATCH_CHANGE_FIXED_BYTES 92u
#define VCS_ZCODE_PATCH_MAX_CHANGES 4096u

enum vcs_zcode_patch_result {
    VCS_ZCODE_PATCH_OK = 0,
    VCS_ZCODE_PATCH_NULL,
    VCS_ZCODE_PATCH_SHAPE,
    VCS_ZCODE_PATCH_SCOPE,
    VCS_ZCODE_PATCH_LIMIT,
    VCS_ZCODE_PATCH_ALLOC,
    VCS_ZCODE_PATCH_MANIFEST_MISMATCH,
    VCS_ZCODE_PATCH_CAS,
};

struct vcs_zcode_patch_change_v1 {
    enum vcs_diff_kind kind;
    char *path;
    uint32_t old_mode;
    uint64_t old_size;
    uint8_t old_blob[32];
    uint32_t new_mode;
    uint64_t new_size;
    uint8_t new_blob[32];
};

struct vcs_zcode_patch_v1 {
    uint8_t base_source_root[32];
    uint8_t candidate_source_root[32];
    uint64_t content_bytes;
    struct vcs_zcode_patch_change_v1 *changes;
    size_t count;
    size_t cap;
};

const char *vcs_zcode_patch_result_string(enum vcs_zcode_patch_result result);
void vcs_zcode_patch_init(struct vcs_zcode_patch_v1 *patch);
void vcs_zcode_patch_free(struct vcs_zcode_patch_v1 *patch);

/* Derive, rather than accept, the complete patch from two addressed manifests.
 * content_bytes is the conservative transfer bound: bytes of every added or
 * modified candidate file. Deletions carry only canonical metadata. */
enum vcs_zcode_patch_result vcs_zcode_patch_derive(
    struct vcs_manifest *base, const uint8_t base_root[32],
    struct vcs_manifest *candidate, const uint8_t candidate_root[32],
    const struct vcs_zcode_write_scope_v1 *scope,
    uint32_t max_changed_files, uint64_t max_patch_bytes,
    struct vcs_zcode_patch_v1 *out);

enum vcs_zcode_patch_result vcs_zcode_patch_validate(
    const struct vcs_zcode_patch_v1 *patch);
enum vcs_zcode_patch_result vcs_zcode_patch_serialize(
    const struct vcs_zcode_patch_v1 *patch, uint8_t **wire, size_t *wire_len);
enum vcs_zcode_patch_result vcs_zcode_patch_parse(
    const uint8_t *wire, size_t wire_len, struct vcs_zcode_patch_v1 *out);
enum vcs_zcode_patch_result vcs_zcode_patch_root(
    const struct vcs_zcode_patch_v1 *patch, uint8_t out[32]);

/* Recompute-never-trust verifier shared by local and P2P worker admission.
 * Loads the task's scope/base tree and the candidate's patch/tree from the
 * existing ZVCS CAS, then derives the expected patch again under task limits. */
enum vcs_zcode_patch_result vcs_zcode_patch_verify_cas(
    const char *repo_root, const struct vcs_zcode_task_v1 *task,
    const struct vcs_zcode_candidate_v1 *candidate);

#endif /* ZCL_VCS_ZCODE_PATCH_H */
