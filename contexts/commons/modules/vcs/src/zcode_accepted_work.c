/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Fail-closed reconstruction of existing ZCODE acceptance objects. */

#include "vcs/zcode_accepted_work.h"

#include "vcs/vcs_object.h"

#include <stdlib.h>
#include <string.h>

static bool accepted_load_lane(
    const char *workspace, const uint8_t root[32],
    const uint8_t expected_signer[32],
    struct vcs_zcode_lane_receipt_v1 *out)
{
    uint8_t *wire = NULL, checked[32];
    size_t len = 0;
    bool ok = vcs_object_load_raw_bounded(
            workspace, root, VCS_ZCODE_LANE_WIRE_BYTES, &wire, &len) == 0 &&
        vcs_zcode_lane_receipt_parse(wire, len, out) == VCS_ZCODE_DEV_OK &&
        vcs_zcode_lane_receipt_id(out, checked) == VCS_ZCODE_DEV_OK &&
        memcmp(root, checked, 32) == 0 &&
        vcs_zcode_lane_receipt_verify(out, expected_signer) ==
            VCS_ZCODE_DEV_OK;
    free(wire);
    return ok;
}

static bool accepted_load_task(
    const char *workspace, const uint8_t root[32], int64_t now_unix,
    struct vcs_zcode_task_v1 *out)
{
    uint8_t *wire = NULL, checked[32];
    size_t len = 0;
    bool ok = vcs_object_load_raw_bounded(
            workspace, root, VCS_ZCODE_TASK_WIRE_BYTES, &wire, &len) == 0 &&
        vcs_zcode_task_parse(wire, len, out) == VCS_ZCODE_DEV_OK &&
        vcs_zcode_task_validate_at(out, now_unix) == VCS_ZCODE_DEV_OK &&
        vcs_zcode_task_root(out, checked) == VCS_ZCODE_DEV_OK &&
        memcmp(root, checked, 32) == 0;
    free(wire);
    return ok;
}

static bool accepted_load_candidate(
    const char *workspace, const uint8_t root[32],
    struct vcs_zcode_candidate_v1 *out)
{
    uint8_t *wire = NULL, checked[32];
    size_t len = 0;
    bool ok = vcs_object_load_raw_bounded(
            workspace, root, VCS_ZCODE_CANDIDATE_WIRE_BYTES, &wire, &len) == 0 &&
        vcs_zcode_candidate_parse(wire, len, out) == VCS_ZCODE_DEV_OK &&
        vcs_zcode_candidate_validate(out) == VCS_ZCODE_DEV_OK &&
        vcs_zcode_candidate_root(out, checked) == VCS_ZCODE_DEV_OK &&
        memcmp(root, checked, 32) == 0;
    free(wire);
    return ok;
}

static bool accepted_load_policy(
    const char *workspace, const uint8_t root[32],
    struct vcs_zcode_proof_policy_v1 *out)
{
    uint8_t *wire = NULL, checked[32];
    size_t len = 0;
    bool ok = vcs_object_load_raw_bounded(
            workspace, root, VCS_ZCODE_PROOF_POLICY_WIRE_BYTES,
            &wire, &len) == 0 &&
        vcs_zcode_proof_policy_parse(wire, len, out) == VCS_ZCODE_DEV_OK &&
        vcs_zcode_proof_policy_validate(out) == VCS_ZCODE_DEV_OK &&
        vcs_zcode_proof_policy_root(out, checked) == VCS_ZCODE_DEV_OK &&
        memcmp(root, checked, 32) == 0;
    free(wire);
    return ok;
}

static bool accepted_proof_set_valid(
    const char *workspace, const uint8_t root[32],
    const struct vcs_zcode_task_v1 *task,
    const struct vcs_zcode_candidate_v1 *candidate)
{
    uint8_t *wire = NULL, checked[32];
    uint8_t receipts[VCS_ZCODE_PROOF_SET_MAX_RECEIPTS][32];
    size_t len = 0, count = 0;
    bool ok = vcs_object_load_raw_bounded(
            workspace, root, VCS_ZCODE_PROOF_SET_WIRE_MAX,
            &wire, &len) == 0 &&
        vcs_zcode_proof_set_parse(
            wire, len, receipts, VCS_ZCODE_PROOF_SET_MAX_RECEIPTS,
            &count) == VCS_ZCODE_DEV_OK && count > 0 &&
        vcs_zcode_proof_set_root(
            (const uint8_t (*)[32])receipts, count, checked) ==
            VCS_ZCODE_DEV_OK && memcmp(root, checked, 32) == 0;
    free(wire);
    for (size_t i = 0; ok && i < count; i++) {
        struct vcs_zcode_work_receipt_v1 receipt;
        uint8_t *receipt_wire = NULL, receipt_root[32];
        size_t receipt_len = 0;
        ok = vcs_object_load_raw_bounded(
                workspace, receipts[i], VCS_ZCODE_WORK_RECEIPT_WIRE_BYTES,
                &receipt_wire, &receipt_len) == 0 &&
            vcs_zcode_work_receipt_parse(
                receipt_wire, receipt_len, &receipt) == VCS_ZCODE_DEV_OK &&
            vcs_zcode_work_receipt_id(&receipt, receipt_root) ==
                VCS_ZCODE_DEV_OK &&
            memcmp(receipts[i], receipt_root, 32) == 0 &&
            vcs_zcode_work_receipt_verify(
                &receipt, receipt.signer_pubkey) == VCS_ZCODE_DEV_OK &&
            vcs_zcode_work_receipt_validate_for_candidate(
                task, candidate, &receipt, receipt.finished_unix) ==
                VCS_ZCODE_DEV_OK;
        free(receipt_wire);
    }
    return ok;
}

static bool accepted_lane_context_equal(
    const struct vcs_zcode_lane_receipt_v1 *a,
    const struct vcs_zcode_lane_receipt_v1 *b)
{
    return memcmp(a->source_root, b->source_root, 32) == 0 &&
        memcmp(a->task_root, b->task_root, 32) == 0 &&
        memcmp(a->candidate_root, b->candidate_root, 32) == 0 &&
        memcmp(a->proof_policy_root, b->proof_policy_root, 32) == 0 &&
        memcmp(a->signer_pubkey, b->signer_pubkey, 32) == 0;
}

bool vcs_zcode_accepted_work_resolve(
    const char *workspace, const uint8_t accepted_work_root[32],
    int64_t now_unix, struct vcs_zcode_accepted_work_v1 *out)
{
    if (!workspace || !accepted_work_root || now_unix <= 0 || !out)
        return false;
    struct vcs_zcode_accepted_work_v1 work;
    memset(&work, 0, sizeof(work));

    /* The PROVEN wire names the immutable context. Load it once without
     * trusting its signature so the expected signer can be derived from the
     * candidate object, then reload it through the pinned verification path. */
    uint8_t *wire = NULL, checked[32];
    size_t len = 0;
    bool ok = vcs_object_load_raw_bounded(
            workspace, accepted_work_root, VCS_ZCODE_LANE_WIRE_BYTES,
            &wire, &len) == 0 &&
        vcs_zcode_lane_receipt_parse(wire, len, &work.proven) ==
            VCS_ZCODE_DEV_OK &&
        vcs_zcode_lane_receipt_id(&work.proven, checked) ==
            VCS_ZCODE_DEV_OK &&
        memcmp(accepted_work_root, checked, 32) == 0 &&
        work.proven.lane == VCS_ZCODE_LANE_PROVEN;
    free(wire);
    if (!ok) return false;

    memcpy(work.task_root, work.proven.task_root, 32);
    memcpy(work.candidate_root, work.proven.candidate_root, 32);
    memcpy(work.proof_policy_root, work.proven.proof_policy_root, 32);
    memcpy(work.proof_set_root, work.proven.proof_set_root, 32);
    memcpy(work.accepted_work_root, accepted_work_root, 32);
    if (!accepted_load_task(
            workspace, work.task_root, now_unix, &work.task) ||
        !accepted_load_candidate(
            workspace, work.candidate_root, &work.candidate) ||
        !accepted_load_policy(
            workspace, work.proof_policy_root, &work.policy) ||
        vcs_zcode_candidate_validate_for_task(
            &work.task, &work.candidate, now_unix) != VCS_ZCODE_DEV_OK)
        return false;
    memcpy(work.expected_signer, work.candidate.author_pubkey, 32);
    if (!accepted_load_lane(
            workspace, accepted_work_root, work.expected_signer,
            &work.proven) ||
        vcs_zcode_lane_receipt_validate_for_candidate(
            &work.proven, &work.task, &work.candidate, &work.policy) !=
            VCS_ZCODE_DEV_OK)
        return false;

    memcpy(work.candidate_lane_root,
           work.proven.prior_receipt_root, 32);
    if (!accepted_load_lane(
            workspace, work.candidate_lane_root, work.expected_signer,
            &work.candidate_lane) ||
        work.candidate_lane.lane != VCS_ZCODE_LANE_CANDIDATE ||
        vcs_zcode_lane_receipt_validate_for_candidate(
            &work.candidate_lane, &work.task, &work.candidate,
            &work.policy) != VCS_ZCODE_DEV_OK ||
        !accepted_lane_context_equal(&work.proven, &work.candidate_lane) ||
        work.candidate_lane.created_unix > work.proven.created_unix)
        return false;

    memcpy(work.frontier_root,
           work.candidate_lane.prior_receipt_root, 32);
    if (!accepted_load_lane(
            workspace, work.frontier_root, work.expected_signer,
            &work.frontier) ||
        work.frontier.lane != VCS_ZCODE_LANE_FRONTIER ||
        vcs_zcode_lane_receipt_validate_for_candidate(
            &work.frontier, &work.task, &work.candidate, &work.policy) !=
            VCS_ZCODE_DEV_OK ||
        !accepted_lane_context_equal(&work.candidate_lane, &work.frontier) ||
        work.frontier.created_unix > work.candidate_lane.created_unix ||
        !accepted_proof_set_valid(
            workspace, work.candidate_lane.proof_set_root,
            &work.task, &work.candidate) ||
        !accepted_proof_set_valid(
            workspace, work.proven.proof_set_root,
            &work.task, &work.candidate))
        return false;

    *out = work;
    return true;
}
