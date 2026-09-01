/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Carry canonical task lock/recipe wires inside content.v2. */

#ifndef ZCL_VCS_ZCODE_TASK_AUTHORITY_BUNDLE_H
#define ZCL_VCS_ZCODE_TASK_AUTHORITY_BUNDLE_H

#include "vcs/zcode_task_authority.h"

#include <stddef.h>
#include <stdint.h>

#define VCS_ZCODE_TASK_AUTHORITY_BUNDLE_VERSION 1u
#define VCS_ZCODE_TASK_AUTHORITY_BUNDLE_HEADER_BYTES 28u
#define VCS_ZCODE_TASK_AUTHORITY_BUNDLE_PATH "zcode-task-authority.v1"

enum vcs_zcode_task_authority_result vcs_zcode_task_authority_bundle_export(
    const char *repo_root, const struct vcs_zcode_task_v1 *task,
    uint8_t **wire, size_t *wire_len);
enum vcs_zcode_task_authority_result vcs_zcode_task_authority_bundle_import(
    const char *repo_root, const struct vcs_zcode_task_v1 *task,
    const uint8_t *wire, size_t wire_len);
enum vcs_zcode_task_authority_result
vcs_zcode_task_authority_bundle_validate_for_candidate(
    const char *repo_root, const struct vcs_zcode_task_v1 *task,
    const struct vcs_zcode_candidate_v1 *candidate,
    const uint8_t *wire, size_t wire_len);

#endif /* ZCL_VCS_ZCODE_TASK_AUTHORITY_BUNDLE_H */
