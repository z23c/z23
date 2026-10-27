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

/* Parse the PROVEN wire once without verifying its signature; check it
 * hashes back to the accepted-work root and names the PROVEN lane. */
static bool accepted_proven_wire_matches_root(
    const char *workspace, const uint8_t accepted_work_root[32],
    struct vcs_zcode_accepted_work_v1 *work)
{
    uint8_t *wire = NULL, checked[32];
    size_t len = 0;
    bool ok = vcs_object_load_raw_bounded(
            workspace, accepted_work_root, VCS_ZCODE_LANE_WIRE_BYTES,
            &wire, &len) == 0 &&
        vcs_zcode_lane_receipt_parse(wire, len, &work->proven) ==
            VCS_ZCODE_DEV_OK &&
        vcs_zcode_lane_receipt_id(&work->proven, checked) ==
            VCS_ZCODE_DEV_OK &&
        memcmp(accepted_work_root, checked, 32) == 0 &&
        work->proven.lane == VCS_ZCODE_LANE_PROVEN;
    free(wire);
    return ok;
}

/* Load the task, candidate and policy objects and cross-check the
 * candidate against the task. */
static bool accepted_context_objects_valid(
    const char *workspace, int64_t now_unix,
    struct vcs_zcode_accepted_work_v1 *work)
{
    bool ok = accepted_load_task(
            workspace, work->task_root, now_unix, &work->task) &&
        accepted_load_candidate(
            workspace, work->candidate_root, &work->candidate) &&
        accepted_load_policy(
            workspace, work->proof_policy_root, &work->policy) &&
        vcs_zcode_candidate_validate_for_task(
            &work->task, &work->candidate, now_unix) == VCS_ZCODE_DEV_OK;
    return ok;
}

/* Reload the PROVEN lane with the pinned signer and validate it against
 * the accepted context. */
static bool accepted_proven_lane_verified(
    const char *workspace, const uint8_t accepted_work_root[32],
    const uint8_t expected_signer[32],
    const struct vcs_zcode_task_v1 *task,
    const struct vcs_zcode_candidate_v1 *candidate,
    const struct vcs_zcode_proof_policy_v1 *policy,
    struct vcs_zcode_lane_receipt_v1 *proven)
{
    bool ok = accepted_load_lane(
            workspace, accepted_work_root, expected_signer, proven) &&
        vcs_zcode_lane_receipt_validate_for_candidate(
            proven, task, candidate, policy) == VCS_ZCODE_DEV_OK;
    return ok;
}

/* Load and verify the next lane receipt in the chain, checking its tag,
 * context and timestamp order against prev. */
static bool accepted_chain_lane_valid(
    const char *workspace, const uint8_t root[32],
    const uint8_t expected_signer[32], int expected_lane,
    const struct vcs_zcode_task_v1 *task,
    const struct vcs_zcode_candidate_v1 *candidate,
    const struct vcs_zcode_proof_policy_v1 *policy,
    const struct vcs_zcode_lane_receipt_v1 *prev,
    struct vcs_zcode_lane_receipt_v1 *out)
{
    bool ok = accepted_load_lane(workspace, root, expected_signer, out) &&
        out->lane == expected_lane &&
        vcs_zcode_lane_receipt_validate_for_candidate(
            out, task, candidate, policy) == VCS_ZCODE_DEV_OK &&
        accepted_lane_context_equal(prev, out) &&
        out->created_unix <= prev->created_unix;
    return ok;
}

/* Validate the proof sets named by the candidate lane and the PROVEN lane. */
static bool accepted_lane_proof_sets_valid(
    const char *workspace,
    const struct vcs_zcode_lane_receipt_v1 *candidate_lane,
    const struct vcs_zcode_lane_receipt_v1 *proven,
    const struct vcs_zcode_task_v1 *task,
    const struct vcs_zcode_candidate_v1 *candidate)
{
    bool ok = accepted_proof_set_valid(
            workspace, candidate_lane->proof_set_root, task, candidate) &&
        accepted_proof_set_valid(
            workspace, proven->proof_set_root, task, candidate);
    return ok;
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
    if (!accepted_proven_wire_matches_root(
            workspace, accepted_work_root, &work))
        return false;

    memcpy(work.task_root, work.proven.task_root, 32);
    memcpy(work.candidate_root, work.proven.candidate_root, 32);
    memcpy(work.proof_policy_root, work.proven.proof_policy_root, 32);
    memcpy(work.proof_set_root, work.proven.proof_set_root, 32);
    memcpy(work.accepted_work_root, accepted_work_root, 32);
    if (!accepted_context_objects_valid(workspace, now_unix, &work))
        return false;
    memcpy(work.expected_signer, work.candidate.author_pubkey, 32);
    if (!accepted_proven_lane_verified(
            workspace, accepted_work_root, work.expected_signer,
            &work.task, &work.candidate, &work.policy, &work.proven))
        return false;

    memcpy(work.candidate_lane_root,
           work.proven.prior_receipt_root, 32);
    if (!accepted_chain_lane_valid(
            workspace, work.candidate_lane_root, work.expected_signer,
            VCS_ZCODE_LANE_CANDIDATE, &work.task, &work.candidate,
            &work.policy, &work.proven, &work.candidate_lane))
        return false;

    memcpy(work.frontier_root,
           work.candidate_lane.prior_receipt_root, 32);
    if (!accepted_chain_lane_valid(
            workspace, work.frontier_root, work.expected_signer,
            VCS_ZCODE_LANE_FRONTIER, &work.task, &work.candidate,
            &work.policy, &work.candidate_lane, &work.frontier) ||
        !accepted_lane_proof_sets_valid(
            workspace, &work.candidate_lane, &work.proven,
            &work.task, &work.candidate))
        return false;

    *out = work;
    return true;
}
