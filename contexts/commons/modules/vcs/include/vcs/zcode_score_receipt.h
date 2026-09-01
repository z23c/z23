/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: canonical evidence-derived ZC23 Score receipts. */
#ifndef ZCL_VCS_ZCODE_SCORE_RECEIPT_H
#define ZCL_VCS_ZCODE_SCORE_RECEIPT_H

#include "vcs/zcode_dev.h"
#include "vcs/zcode_lane.h"

#include <stddef.h>
#include <stdint.h>

#define VCS_ZCODE_SCORE_DOMAIN "zcl.zcode.score_receipt.v1"
#define VCS_ZCODE_SCORE_VERSION 1u
#define VCS_ZCODE_SCORE_UNITS 5u
#define VCS_ZCODE_SCORE_BODY_BYTES 528u
#define VCS_ZCODE_SCORE_WIRE_BYTES 592u

enum vcs_zcode_score_unit {
    VCS_ZCODE_SCORE_ACCEPTED_EXTRACTION = 0,
    VCS_ZCODE_SCORE_BORN_RED_DEFECT_TEST = 1,
    VCS_ZCODE_SCORE_INDEPENDENT_REPRODUCTION = 2,
    VCS_ZCODE_SCORE_EXACT_CAPSULE_REDERIVATION = 3,
    VCS_ZCODE_SCORE_COMPATIBILITY_MAINTENANCE = 4,
};

enum vcs_zcode_score_error {
    VCS_ZCODE_SCORE_OK = 0,
    VCS_ZCODE_SCORE_NULL,
    VCS_ZCODE_SCORE_SHAPE,
    VCS_ZCODE_SCORE_BINDING,
    VCS_ZCODE_SCORE_PROOF,
    VCS_ZCODE_SCORE_DUPLICATE,
    VCS_ZCODE_SCORE_SIGNATURE,
    VCS_ZCODE_SCORE_CAS,
};

struct vcs_zcode_score_receipt_v1 {
    uint16_t schema_version;
    uint8_t awarded_mask;
    uint8_t score;
    uint8_t task_root[32];
    uint8_t candidate_root[32];
    uint8_t proof_policy_root[32];
    uint8_t proof_set_root[32];
    uint8_t proven_lane_root[32];
    uint8_t package_root[32];
    uint8_t release_root[32];
    uint8_t recipe_root[32];
    uint8_t dependency_lock_root[32];
    uint8_t api_capsule_root[32];
    uint8_t evidence_roots[VCS_ZCODE_SCORE_UNITS][32];
    uint8_t lane_signer[32];
    uint8_t signature[64];
};

struct vcs_zcode_score_plan_input {
    const struct vcs_zcode_task_v1 *task;
    const struct vcs_zcode_candidate_v1 *candidate;
    const struct vcs_zcode_proof_policy_v1 *proof_policy;
    const struct vcs_zcode_lane_receipt_v1 *proven_lane;
    const uint8_t (*proof_receipt_roots)[32];
    const struct vcs_zcode_work_receipt_v1 *work_receipts;
    size_t work_receipt_count;
    const uint8_t *package_root;
    const uint8_t *release_root;
    const uint8_t *recipe_root;
    const uint8_t *dependency_lock_root;
    const uint8_t *api_capsule_root;
};

const char *vcs_zcode_score_error_string(enum vcs_zcode_score_error error);
const char *vcs_zcode_score_unit_name(enum vcs_zcode_score_unit unit);
void vcs_zcode_score_action_root(enum vcs_zcode_score_unit unit,
                                 uint8_t out[32]);
bool vcs_zcode_score_offhost_reproducer_approved(const uint8_t pubkey[32]);

enum vcs_zcode_score_error vcs_zcode_score_plan(
    const struct vcs_zcode_score_plan_input *input,
    struct vcs_zcode_score_receipt_v1 *out);
enum vcs_zcode_score_error vcs_zcode_score_receipt_serialize(
    const struct vcs_zcode_score_receipt_v1 *receipt,
    uint8_t out[VCS_ZCODE_SCORE_WIRE_BYTES]);
enum vcs_zcode_score_error vcs_zcode_score_receipt_body(
    const struct vcs_zcode_score_receipt_v1 *receipt,
    uint8_t out[VCS_ZCODE_SCORE_BODY_BYTES]);
enum vcs_zcode_score_error vcs_zcode_score_receipt_parse(
    const uint8_t *wire, size_t wire_len,
    struct vcs_zcode_score_receipt_v1 *out);
enum vcs_zcode_score_error vcs_zcode_score_receipt_id(
    const struct vcs_zcode_score_receipt_v1 *receipt, uint8_t out[32]);
enum vcs_zcode_score_error vcs_zcode_score_receipt_seal(
    struct vcs_zcode_score_receipt_v1 *receipt,
    const uint8_t secret[32], const uint8_t pubkey[32]);
enum vcs_zcode_score_error vcs_zcode_score_receipt_verify(
    const struct vcs_zcode_score_receipt_v1 *receipt);
/* Reload and rederive the complete task/candidate/policy/proof/PROVEN lane
 * vertical from the existing workspace CAS.  No directory or object is
 * created. */
enum vcs_zcode_score_error vcs_zcode_score_receipt_verify_cas(
    const char *workspace,
    const struct vcs_zcode_score_receipt_v1 *receipt);

#endif /* ZCL_VCS_ZCODE_SCORE_RECEIPT_H */
