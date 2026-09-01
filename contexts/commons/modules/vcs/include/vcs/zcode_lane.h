/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Signed immutable FRONTIER/CANDIDATE/PROVEN source promotions. */

#ifndef ZCL_VCS_ZCODE_LANE_H
#define ZCL_VCS_ZCODE_LANE_H

#include "vcs/zcode_dev.h"

#include <stddef.h>
#include <stdint.h>

#define VCS_ZCODE_LANE_DOMAIN "zcl.zcode.lane_receipt.v1"
#define VCS_ZCODE_LANE_BODY_BYTES 248u
#define VCS_ZCODE_LANE_WIRE_BYTES 312u

enum vcs_zcode_lane {
    VCS_ZCODE_LANE_FRONTIER = 1,
    VCS_ZCODE_LANE_CANDIDATE = 2,
    VCS_ZCODE_LANE_PROVEN = 3,
};

struct vcs_zcode_lane_receipt_v1 {
    uint16_t schema_version;
    uint8_t lane;
    uint8_t source_root[32];
    uint8_t task_root[32];
    uint8_t candidate_root[32];
    uint8_t proof_policy_root[32];
    uint8_t proof_set_root[32];
    uint8_t prior_receipt_root[32];
    int64_t created_unix;
    uint8_t signer_pubkey[32];
    uint8_t signature[64];
};

const char *vcs_zcode_lane_name(uint8_t lane);
enum vcs_zcode_dev_error vcs_zcode_lane_receipt_validate(
    const struct vcs_zcode_lane_receipt_v1 *receipt);
enum vcs_zcode_dev_error vcs_zcode_lane_receipt_validate_for_candidate(
    const struct vcs_zcode_lane_receipt_v1 *receipt,
    const struct vcs_zcode_task_v1 *task,
    const struct vcs_zcode_candidate_v1 *candidate,
    const struct vcs_zcode_proof_policy_v1 *policy);
enum vcs_zcode_dev_error vcs_zcode_lane_receipt_serialize(
    const struct vcs_zcode_lane_receipt_v1 *receipt,
    uint8_t out[VCS_ZCODE_LANE_WIRE_BYTES]);
enum vcs_zcode_dev_error vcs_zcode_lane_receipt_parse(
    const uint8_t *wire, size_t wire_len,
    struct vcs_zcode_lane_receipt_v1 *out);
enum vcs_zcode_dev_error vcs_zcode_lane_receipt_id(
    const struct vcs_zcode_lane_receipt_v1 *receipt, uint8_t out[32]);
enum vcs_zcode_dev_error vcs_zcode_lane_receipt_seal(
    struct vcs_zcode_lane_receipt_v1 *receipt,
    const uint8_t secret[32], const uint8_t pubkey[32]);
enum vcs_zcode_dev_error vcs_zcode_lane_receipt_verify(
    const struct vcs_zcode_lane_receipt_v1 *receipt,
    const uint8_t expected_signer[32]);

#endif /* ZCL_VCS_ZCODE_LANE_H */
