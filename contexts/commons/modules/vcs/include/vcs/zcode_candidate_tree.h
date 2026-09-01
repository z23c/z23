/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Carry a complete ZVCS candidate tree as content.v2 files. */

#ifndef ZCL_VCS_ZCODE_CANDIDATE_TREE_H
#define ZCL_VCS_ZCODE_CANDIDATE_TREE_H

#include "vcs/zcode_dev.h"

#include <stddef.h>
#include <stdint.h>

#define VCS_ZCODE_CANDIDATE_TREE_PREFIX "candidate/"

enum vcs_zcode_candidate_tree_result {
    VCS_ZCODE_CANDIDATE_TREE_OK = 0,
    VCS_ZCODE_CANDIDATE_TREE_NULL,
    VCS_ZCODE_CANDIDATE_TREE_AUTHORITY,
    VCS_ZCODE_CANDIDATE_TREE_SHAPE,
    VCS_ZCODE_CANDIDATE_TREE_LIMIT,
    VCS_ZCODE_CANDIDATE_TREE_CAS,
    VCS_ZCODE_CANDIDATE_TREE_STORE,
    VCS_ZCODE_CANDIDATE_TREE_ALLOC,
};

struct vcs_package_manifest;
struct vcs_package_store;

const char *vcs_zcode_candidate_tree_result_string(
    enum vcs_zcode_candidate_tree_result result);

/* Add every regular candidate-tree entry to an existing content.v2
 * manifest under candidate/. Blob bytes come only from the verified ZVCS
 * CAS. max_bytes bounds their combined payload. */
enum vcs_zcode_candidate_tree_result vcs_zcode_candidate_tree_add_manifest(
    const char *repo_root, const struct vcs_zcode_task_v1 *task,
    const struct vcs_zcode_candidate_v1 *candidate, uint64_t max_bytes,
    struct vcs_package_manifest *manifest, uint64_t *tree_bytes);

/* Put the tree's chunks after the caller has admitted the combined manifest. */
enum vcs_zcode_candidate_tree_result vcs_zcode_candidate_tree_put_chunks(
    struct vcs_package_store *store, const uint8_t package_root[32],
    const char *repo_root, const struct vcs_zcode_candidate_v1 *candidate);

/* Reconstruct every candidate blob from a complete content.v2 package,
 * validate the whole tree first, then admit the tagged blobs to ZVCS CAS. */
enum vcs_zcode_candidate_tree_result vcs_zcode_candidate_tree_import(
    struct vcs_package_store *store, const uint8_t package_root[32],
    const char *repo_root, const struct vcs_zcode_task_v1 *task,
    const struct vcs_zcode_candidate_v1 *candidate);

#endif /* ZCL_VCS_ZCODE_CANDIDATE_TREE_H */
