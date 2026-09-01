/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Canonical lock and recipe authority for ZCODE tasks. */

#ifndef ZCL_VCS_ZCODE_TASK_AUTHORITY_H
#define ZCL_VCS_ZCODE_TASK_AUTHORITY_H

#include "vcs/zcode_dev.h"

#include <stddef.h>
#include <stdint.h>

enum vcs_zcode_task_authority_result {
    VCS_ZCODE_TASK_AUTHORITY_OK = 0,
    VCS_ZCODE_TASK_AUTHORITY_NULL,
    VCS_ZCODE_TASK_AUTHORITY_LOCK,
    VCS_ZCODE_TASK_AUTHORITY_RECIPE,
    VCS_ZCODE_TASK_AUTHORITY_MEMBERSHIP,
    VCS_ZCODE_TASK_AUTHORITY_CAS,
};

const char *vcs_zcode_task_authority_result_string(
    enum vcs_zcode_task_authority_result result);

/* Parse exact canonical wires and derive their existing domain-separated
 * roots without changing the workspace CAS. */
enum vcs_zcode_task_authority_result vcs_zcode_task_authority_roots(
    const uint8_t *lock_wire, size_t lock_wire_len,
    const uint8_t *recipe_wire, size_t recipe_wire_len,
    uint8_t lock_root[32], uint8_t recipe_root[32]);

/* Parse, root, store with atomic CAS writes, and readback-verify the canonical
 * package lock and recipe wires in the workspace CAS. */
enum vcs_zcode_task_authority_result vcs_zcode_task_authority_store(
    const char *repo_root, const uint8_t *lock_wire, size_t lock_wire_len,
    const uint8_t *recipe_wire, size_t recipe_wire_len,
    uint8_t lock_root[32], uint8_t recipe_root[32]);

/* Require both addressed wires and recipe membership in the task's exact
 * base source tree or candidate source tree. */
enum vcs_zcode_task_authority_result vcs_zcode_task_authority_validate(
    const char *repo_root, const struct vcs_zcode_task_v1 *task);
enum vcs_zcode_task_authority_result
vcs_zcode_task_authority_validate_for_candidate(
    const char *repo_root, const struct vcs_zcode_task_v1 *task,
    const struct vcs_zcode_candidate_v1 *candidate);

#endif /* ZCL_VCS_ZCODE_TASK_AUTHORITY_H */
