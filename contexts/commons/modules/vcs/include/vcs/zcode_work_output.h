/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Action-bound fixed-work output over the existing content.v2 swarm. */

#ifndef ZCL_VCS_ZCODE_WORK_OUTPUT_H
#define ZCL_VCS_ZCODE_WORK_OUTPUT_H

#include <stddef.h>
#include <stdint.h>

#define VCS_ZCODE_WORK_OUTPUT_ACTION_PATH "action"
#define VCS_ZCODE_WORK_OUTPUT_BYTES_PATH "output"

struct vcs_package_store;

enum vcs_zcode_work_output_result {
    VCS_ZCODE_WORK_OUTPUT_OK = 0,
    VCS_ZCODE_WORK_OUTPUT_NULL,
    VCS_ZCODE_WORK_OUTPUT_EMPTY,
    VCS_ZCODE_WORK_OUTPUT_LIMIT,
    VCS_ZCODE_WORK_OUTPUT_STORE,
    VCS_ZCODE_WORK_OUTPUT_ABSENT,
    VCS_ZCODE_WORK_OUTPUT_SHAPE,
    VCS_ZCODE_WORK_OUTPUT_CORRUPT,
    VCS_ZCODE_WORK_OUTPUT_ALLOC,
};

const char *vcs_zcode_work_output_result_string(
    enum vcs_zcode_work_output_result result);

/* A work output is an ordinary content.v2 package with exactly two files:
 * the 32-byte immutable action root and the output bytes. The package root is
 * therefore both the transfer address and the receipt's action-bound output
 * commitment. No new store, cache authority, or swarm message is introduced. */
enum vcs_zcode_work_output_result vcs_zcode_work_output_put(
    struct vcs_package_store *store, const uint8_t action_root[32],
    const uint8_t *bytes, size_t len, uint8_t package_root[32]);

/* Reconstruct and re-verify a complete carrier. Allocates *out; caller frees.
 * The expected action root is mandatory and is checked before output bytes are
 * returned. */
enum vcs_zcode_work_output_result vcs_zcode_work_output_get(
    struct vcs_package_store *store, const uint8_t package_root[32],
    const uint8_t expected_action_root[32], uint8_t **out, size_t *out_len);

#endif /* ZCL_VCS_ZCODE_WORK_OUTPUT_H */
