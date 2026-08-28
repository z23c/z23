/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: canonical simulation-only epoch proposal over signed v2 claims. */
#ifndef ZCL_VCS_ZCODE_CLAIM_EPOCH_H
#define ZCL_VCS_ZCODE_CLAIM_EPOCH_H

#include "vcs/zcode_commons.h"

#include <stddef.h>
#include <stdint.h>

#define VCS_ZCODE_CLAIM_EPOCH_DOMAIN \
    "zcl.zcode.claim_epoch_proposal.v2"
#define VCS_ZCODE_CLAIM_EPOCH_VERSION VCS_ZCODE_CREATION_CLAIM_V2_VERSION
#define VCS_ZCODE_CLAIM_EPOCH_HEADER_BYTES 228u
#define VCS_ZCODE_CLAIM_EPOCH_MAX_SELECTED VCS_ZCODE_COMMONS_MAX_CLAIMS
#define VCS_ZCODE_CLAIM_EPOCH_MAX_WIRE_BYTES \
    (VCS_ZCODE_CLAIM_EPOCH_HEADER_BYTES + \
     VCS_ZCODE_CLAIM_EPOCH_MAX_SELECTED * 32u)
#define VCS_ZCODE_CLAIM_EPOCH_KAT_ROOT \
    "991d9075d085d2d90bb9b86d7bbebe5ae4aa967d4ea13604a4834921fd4a5623"

enum vcs_zcode_claim_epoch_error {
    VCS_ZCODE_CLAIM_EPOCH_OK = 0,
    VCS_ZCODE_CLAIM_EPOCH_NULL,
    VCS_ZCODE_CLAIM_EPOCH_ALLOC,
    VCS_ZCODE_CLAIM_EPOCH_SIZE,
    VCS_ZCODE_CLAIM_EPOCH_MAGIC,
    VCS_ZCODE_CLAIM_EPOCH_VERSION_ERROR,
    VCS_ZCODE_CLAIM_EPOCH_FLAGS,
    VCS_ZCODE_CLAIM_EPOCH_RESERVED,
    VCS_ZCODE_CLAIM_EPOCH_ROOT,
    VCS_ZCODE_CLAIM_EPOCH_TIME,
    VCS_ZCODE_CLAIM_EPOCH_COUNT,
    VCS_ZCODE_CLAIM_EPOCH_SUM,
    VCS_ZCODE_CLAIM_EPOCH_DUPLICATE,
    VCS_ZCODE_CLAIM_EPOCH_SELECTION,
};

struct vcs_zcode_claim_epoch_proposal_v2 {
    uint16_t schema_version;
    uint16_t flags;
    uint64_t epoch;
    uint64_t cutoff_height;
    int64_t cutoff_mtp;
    uint64_t epoch_capacity_atoms;
    uint64_t selected_atoms;
    uint64_t expired_capacity_atoms;
    uint64_t recipient_cap_atoms;
    uint64_t lineage_cap_atoms;
    uint32_t claim_count;
    uint32_t selected_count;
    uint32_t deferred_count;
    uint32_t invalid_count;
    uint8_t first_category;
    uint8_t previous_epoch_root[32];
    uint8_t policy_root[32];
    uint8_t claim_projection_root[32];
    uint8_t epoch_selection_root[32];
    uint8_t (*selected_claim_roots)[32];
};

const char *vcs_zcode_claim_epoch_error_string(
    enum vcs_zcode_claim_epoch_error error);
void vcs_zcode_claim_epoch_init(
    struct vcs_zcode_claim_epoch_proposal_v2 *proposal);
void vcs_zcode_claim_epoch_free(
    struct vcs_zcode_claim_epoch_proposal_v2 *proposal);
enum vcs_zcode_claim_epoch_error vcs_zcode_claim_epoch_validate(
    const struct vcs_zcode_claim_epoch_proposal_v2 *proposal);
enum vcs_zcode_claim_epoch_error vcs_zcode_claim_epoch_encode(
    const struct vcs_zcode_claim_epoch_proposal_v2 *proposal,
    uint8_t **wire_out, size_t *wire_len_out);
enum vcs_zcode_claim_epoch_error vcs_zcode_claim_epoch_decode(
    struct vcs_zcode_claim_epoch_proposal_v2 *out,
    const uint8_t *wire, size_t wire_len);
enum vcs_zcode_claim_epoch_error vcs_zcode_claim_epoch_root(
    const struct vcs_zcode_claim_epoch_proposal_v2 *proposal,
    uint8_t out[32]);

/* Copies the complete selected-root set out of caller-owned selection input.
 * The proposal remains simulation evidence only; it grants no mint authority. */
enum vcs_zcode_claim_epoch_error vcs_zcode_claim_epoch_from_selection(
    const struct vcs_zcode_epoch_selection_v2 *input,
    const uint8_t policy_root[32],
    const uint8_t claim_projection_root[32],
    const struct vcs_zcode_epoch_selection_result_v2 *result,
    struct vcs_zcode_claim_epoch_proposal_v2 *out);

#endif /* ZCL_VCS_ZCODE_CLAIM_EPOCH_H */
