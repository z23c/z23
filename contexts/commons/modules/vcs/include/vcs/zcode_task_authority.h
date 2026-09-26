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
    /* The candidate tree changes a recipe test source the task named. */
    VCS_ZCODE_TASK_AUTHORITY_ACCEPTANCE_TESTS_MODIFIED,
};

/* Acceptance belongs to the task author. acceptance_tests_root is the
 * recipe root: it names the test source PATHS, not their bytes. The bytes
 * are bound through task.source_root, whose manifest records each test
 * source's mode, size and tagged blob. The acceptance-tests bytes root is
 * SHA3-256 over this domain (hashed with its trailing 0x00), the recipe
 * root, the u16le test-source count, then for each recipe test source in
 * canonical order: u16le path length, path bytes, u32le mode, u64le size
 * and the 32-byte tagged blob root. Editing any named test changes it;
 * editing only non-test files leaves it unchanged. */
#define VCS_ZCODE_ACCEPTANCE_TESTS_BYTES_DOMAIN \
    "zcl.zcode.acceptance_tests_bytes.v1"

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
 * base source tree or candidate source tree. The candidate form also
 * requires the candidate tree to carry the task's exact acceptance-test
 * bytes: a candidate cannot edit the tests it is judged by
 * (VCS_ZCODE_TASK_AUTHORITY_ACCEPTANCE_TESTS_MODIFIED). Changing the tests
 * requires a new task whose base source already holds them. */
enum vcs_zcode_task_authority_result vcs_zcode_task_authority_validate(
    const char *repo_root, const struct vcs_zcode_task_v1 *task);

/* Validate the task authority and derive its acceptance-tests bytes root
 * (VCS_ZCODE_ACCEPTANCE_TESTS_BYTES_DOMAIN) over task.source_root. */
enum vcs_zcode_task_authority_result vcs_zcode_task_acceptance_tests_bytes_root(
    const char *repo_root, const struct vcs_zcode_task_v1 *task,
    uint8_t out[32]);
enum vcs_zcode_task_authority_result
vcs_zcode_task_authority_validate_for_candidate(
    const char *repo_root, const struct vcs_zcode_task_v1 *task,
    const struct vcs_zcode_candidate_v1 *candidate);

#endif /* ZCL_VCS_ZCODE_TASK_AUTHORITY_H */
