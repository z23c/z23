/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Bounded candidate authority transfer over existing content.v2. */

#ifndef ZCL_VCS_ZCODE_CANDIDATE_BUNDLE_H
#define ZCL_VCS_ZCODE_CANDIDATE_BUNDLE_H

#include "vcs/zcode_dev.h"

#include <stddef.h>
#include <stdint.h>

#define VCS_ZCODE_CANDIDATE_BUNDLE_VERSION 1u
#define VCS_ZCODE_CANDIDATE_BUNDLE_PATH "zcode-candidate-authority.v1"
#define VCS_ZCODE_CANDIDATE_BUNDLE_HEADER_BYTES 48u
#define VCS_ZCODE_CANDIDATE_BUNDLE_BLOB_HEADER_BYTES 40u

enum vcs_zcode_candidate_bundle_result {
    VCS_ZCODE_CANDIDATE_BUNDLE_OK = 0,
    VCS_ZCODE_CANDIDATE_BUNDLE_NULL,
    VCS_ZCODE_CANDIDATE_BUNDLE_SHAPE,
    VCS_ZCODE_CANDIDATE_BUNDLE_LIMIT,
    VCS_ZCODE_CANDIDATE_BUNDLE_CAS,
    VCS_ZCODE_CANDIDATE_BUNDLE_AUTHORITY,
    VCS_ZCODE_CANDIDATE_BUNDLE_ALLOC,
};

const char *vcs_zcode_candidate_bundle_result_string(
    enum vcs_zcode_candidate_bundle_result result);

/* Export the exact scope, patch, base/candidate manifests, and every unique
 * added/modified blob from the requester's existing ZVCS CAS. */
enum vcs_zcode_candidate_bundle_result vcs_zcode_candidate_bundle_export(
    const char *repo_root, const struct vcs_zcode_task_v1 *task,
    const struct vcs_zcode_candidate_v1 *candidate,
    uint8_t **wire, size_t *wire_len);

/* Validate the complete closed wire before writing anything, then import its
 * objects into the receiving peer's existing ZVCS CAS and independently
 * rederive patch authority. */
enum vcs_zcode_candidate_bundle_result vcs_zcode_candidate_bundle_import(
    const char *repo_root, const struct vcs_zcode_task_v1 *task,
    const struct vcs_zcode_candidate_v1 *candidate,
    const uint8_t *wire, size_t wire_len);

#endif /* ZCL_VCS_ZCODE_CANDIDATE_BUNDLE_H */
