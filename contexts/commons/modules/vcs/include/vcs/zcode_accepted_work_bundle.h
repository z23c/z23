/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Self-contained transfer of an accepted ZCODE proof chain. */

#ifndef ZCL_VCS_ZCODE_ACCEPTED_WORK_BUNDLE_H
#define ZCL_VCS_ZCODE_ACCEPTED_WORK_BUNDLE_H

#include "vcs/zcode_accepted_work.h"

#include <stddef.h>
#include <stdint.h>

#define VCS_ZCODE_ACCEPTED_WORK_BUNDLE_VERSION 1u
#define VCS_ZCODE_ACCEPTED_WORK_BUNDLE_PATH \
    "zcode-accepted-work-authority.v1"
#define VCS_ZCODE_ACCEPTED_WORK_BUNDLE_MAX_BYTES \
    (UINT64_C(2) * 1024u * 1024u)

enum vcs_zcode_accepted_work_bundle_result {
    VCS_ZCODE_ACCEPTED_WORK_BUNDLE_OK = 0,
    VCS_ZCODE_ACCEPTED_WORK_BUNDLE_NULL,
    VCS_ZCODE_ACCEPTED_WORK_BUNDLE_SHAPE,
    VCS_ZCODE_ACCEPTED_WORK_BUNDLE_LIMIT,
    VCS_ZCODE_ACCEPTED_WORK_BUNDLE_CAS,
    VCS_ZCODE_ACCEPTED_WORK_BUNDLE_AUTHORITY,
    VCS_ZCODE_ACCEPTED_WORK_BUNDLE_ALLOC,
};

const char *vcs_zcode_accepted_work_bundle_result_string(
    enum vcs_zcode_accepted_work_bundle_result result);

/* Export every immutable object needed by accepted_work_resolve(), plus the
 * task's existing lock/recipe authority bundle. */
enum vcs_zcode_accepted_work_bundle_result
vcs_zcode_accepted_work_bundle_export(
    const char *workspace, const uint8_t accepted_work_root[32],
    int64_t now_unix, uint8_t **wire, size_t *wire_len,
    struct vcs_zcode_accepted_work_v1 *accepted_out);

/* Validate the closed bundle in an isolated CAS, derive the signer from the
 * candidate, verify the complete FRONTIER->CANDIDATE->PROVEN chain and every
 * proof receipt, then import it into workspace. The candidate source tree must
 * already be present so recipe membership can be checked before authority is
 * written to the destination CAS. */
enum vcs_zcode_accepted_work_bundle_result
vcs_zcode_accepted_work_bundle_import(
    const char *workspace, const uint8_t accepted_work_root[32],
    const uint8_t source_root[32], const uint8_t *wire, size_t wire_len,
    struct vcs_zcode_accepted_work_v1 *accepted_out,
    uint32_t *object_count_out, uint32_t *work_receipt_count_out);

#endif /* ZCL_VCS_ZCODE_ACCEPTED_WORK_BUNDLE_H */
