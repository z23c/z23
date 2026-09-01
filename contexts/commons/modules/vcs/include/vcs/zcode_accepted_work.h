/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Verified view of one existing PROVEN ZCODE lane chain. */

#ifndef ZCL_VCS_ZCODE_ACCEPTED_WORK_H
#define ZCL_VCS_ZCODE_ACCEPTED_WORK_H

#include "vcs/zcode_dev.h"
#include "vcs/zcode_lane.h"

#include <stdint.h>

/* This is a derived view, not a new canonical object. accepted_work_root is
 * the existing PROVEN lane-receipt root. The three receipts remain the
 * authority in the workspace CAS. */
struct vcs_zcode_accepted_work_v1 {
    struct vcs_zcode_task_v1 task;
    struct vcs_zcode_candidate_v1 candidate;
    struct vcs_zcode_proof_policy_v1 policy;
    struct vcs_zcode_lane_receipt_v1 frontier;
    struct vcs_zcode_lane_receipt_v1 candidate_lane;
    struct vcs_zcode_lane_receipt_v1 proven;
    uint8_t task_root[32];
    uint8_t candidate_root[32];
    uint8_t proof_policy_root[32];
    uint8_t proof_set_root[32];
    uint8_t frontier_root[32];
    uint8_t candidate_lane_root[32];
    uint8_t accepted_work_root[32];
    uint8_t expected_signer[32];
};

/* Reload and rehash the complete existing FRONTIER -> CANDIDATE -> PROVEN
 * chain from CAS. Signatures are checked against candidate.author_pubkey,
 * never against a key supplied by the receipt itself. Every proof-set member
 * is reloaded, re-rooted, signature-checked and candidate-bound. */
bool vcs_zcode_accepted_work_resolve(
    const char *workspace, const uint8_t accepted_work_root[32],
    int64_t now_unix, struct vcs_zcode_accepted_work_v1 *out);

#endif /* ZCL_VCS_ZCODE_ACCEPTED_WORK_H */
