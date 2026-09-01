/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: policy-bound, read-only reproduction qualification. */
#include "vcs/zcode_reproduction_qualification.h"

#include "vcs/build_artifact_manifest.h"
#include "vcs/package_build.h"
#include "vcs/package_release.h"
#include "vcs/vcs_object.h"
#include "vcs/zcode_contributor_binding.h"
#include "vcs/zcode_dev.h"
#include "vcs/zcode_reproduction_request.h"
#include "vcs/zcode_score_receipt.h"
#include "vcs/zcode_shadow_policy.h"

#include <stdlib.h>
#include <string.h>

struct qualification_identity {
    uint8_t zid[32];
    uint8_t zcl[33];
};

static bool qualification_equal(const uint8_t a[32], const uint8_t b[32])
{
    return memcmp(a, b, 32) == 0;
}

static bool qualification_load(const char *workspace, const uint8_t root[32],
                               size_t maximum, uint8_t **wire,
                               size_t *wire_len)
{
    *wire = NULL;
    *wire_len = 0;
    return workspace && vcs_object_load_raw_bounded(
        workspace, root, maximum, wire, wire_len) == 0;
}

const char *vcs_zcode_reproduction_qualification_string(
    enum vcs_zcode_reproduction_qualification verdict)
{
    switch (verdict) {
    case VCS_ZCODE_QUALIFICATION_READY:
        return "ready_for_shadow_attribution";
    case VCS_ZCODE_QUALIFICATION_NULL: return "null";
    case VCS_ZCODE_QUALIFICATION_CAS: return "cas_object_invalid";
    case VCS_ZCODE_QUALIFICATION_POLICY: return "policy_invalid";
    case VCS_ZCODE_QUALIFICATION_SCORE: return "score_vertical_invalid";
    case VCS_ZCODE_QUALIFICATION_REQUEST: return "request_invalid";
    case VCS_ZCODE_QUALIFICATION_NO_RECEIPT:
        return "no_reproduction_receipt";
    case VCS_ZCODE_QUALIFICATION_RECEIPT:
        return "reproduction_receipt_invalid";
    case VCS_ZCODE_QUALIFICATION_OUTPUT_MISMATCH:
        return "reproduction_output_mismatch";
    case VCS_ZCODE_QUALIFICATION_SIGNER_NOT_APPROVED:
        return "signer_not_approved";
    case VCS_ZCODE_QUALIFICATION_SIGNER_NOT_DISTINCT:
        return "signer_not_distinct";
    case VCS_ZCODE_QUALIFICATION_APPROVAL_NOT_VALID:
        return "approval_not_valid_at_receipt_time";
    case VCS_ZCODE_QUALIFICATION_CHALLENGE_EXPIRED:
        return "challenge_expired";
    case VCS_ZCODE_QUALIFICATION_CONFINEMENT_INSUFFICIENT:
        return "confinement_insufficient";
    case VCS_ZCODE_QUALIFICATION_DUPLICATE:
        return "duplicate_reproduction";
    case VCS_ZCODE_QUALIFICATION_CONTRADICTION:
        return "contradictory_reproductions";
    }
    return "unknown";
}

static enum vcs_zcode_reproduction_qualification qualification_finish(
    struct vcs_zcode_reproduction_qualification_report *out,
    enum vcs_zcode_reproduction_qualification verdict)
{
    out->verdict = verdict;
    return verdict;
}

static bool qualification_load_binding(
    const char *workspace, const uint8_t root[32], const uint8_t network[32],
    int64_t at_unix, struct qualification_identity *identity)
{
    uint8_t *wire = NULL, observed[32];
    size_t wire_len = 0;
    memset(identity, 0, sizeof(*identity));
    if (!qualification_load(workspace, root,
                            VCS_ZCODE_CONTRIBUTOR_BINDING_V2_WIRE_BYTES,
                            &wire, &wire_len))
        return false;
    bool ok = false;
    if (wire_len == VCS_ZCODE_CONTRIBUTOR_BINDING_WIRE_BYTES) {
        struct vcs_zcode_contributor_binding_v1 binding;
        ok = vcs_zcode_contributor_binding_parse(wire, wire_len, &binding) ==
                 VCS_ZCODE_BINDING_OK &&
            vcs_zcode_contributor_binding_root(&binding, observed) ==
                 VCS_ZCODE_BINDING_OK &&
            qualification_equal(observed, root) &&
            vcs_zcode_contributor_binding_verify(
                &binding, network, binding.zid_pubkey, at_unix) ==
                 VCS_ZCODE_BINDING_OK;
        if (ok) {
            memcpy(identity->zid, binding.zid_pubkey, 32);
            memcpy(identity->zcl, binding.zcl_pubkey, 33);
        }
    } else if (wire_len == VCS_ZCODE_CONTRIBUTOR_BINDING_V2_WIRE_BYTES) {
        struct vcs_zcode_contributor_binding_v2 binding;
        ok = vcs_zcode_contributor_binding_parse_v2(wire, wire_len,
                                                     &binding) ==
                 VCS_ZCODE_BINDING_OK &&
            vcs_zcode_contributor_binding_root_v2(&binding, observed) ==
                 VCS_ZCODE_BINDING_OK &&
            qualification_equal(observed, root) &&
            vcs_zcode_contributor_binding_verify_v2(
                &binding, network, binding.zid_pubkey, at_unix) ==
                 VCS_ZCODE_BINDING_OK;
        if (ok) {
            memcpy(identity->zid, binding.zid_pubkey, 32);
            memcpy(identity->zcl, binding.zcl_pubkey, 33);
        }
    }
    free(wire);
    return ok;
}

static bool qualification_load_build(
    const char *workspace, const uint8_t root[32],
    struct vcs_package_build_receipt *build)
{
    uint8_t *wire = NULL, observed[32];
    size_t wire_len = 0;
    bool ok = qualification_load(workspace, root,
                                 VCS_PACKAGE_BUILD_MAX_WIRE_BYTES,
                                 &wire, &wire_len) &&
        vcs_package_build_parse(wire, wire_len, build) ==
            VCS_PACKAGE_BUILD_OK &&
        vcs_package_build_id(build, observed) == VCS_PACKAGE_BUILD_OK &&
        qualification_equal(observed, root);
    free(wire);
    return ok;
}

static bool qualification_load_manifest(
    const char *workspace, const uint8_t root[32],
    struct vcs_build_artifact_manifest_v1 *manifest)
{
    uint8_t *wire = NULL, observed[32];
    size_t wire_len = 0;
    bool ok = qualification_load(workspace, root,
                                 VCS_BUILD_ARTIFACT_WIRE_MAX,
                                 &wire, &wire_len) &&
        vcs_build_artifact_manifest_v1_parse(wire, wire_len, manifest) &&
        vcs_build_artifact_manifest_v1_root(manifest, observed) &&
        qualification_equal(observed, root);
    free(wire);
    return ok;
}

static bool qualification_load_release(
    const char *workspace, const uint8_t root[32],
    struct vcs_package_release *release)
{
    uint8_t *wire = NULL, observed[32];
    size_t wire_len = 0;
    bool ok = qualification_load(workspace, root,
                                 VCS_PACKAGE_RELEASE_MAX_WIRE_BYTES,
                                 &wire, &wire_len) &&
        vcs_package_release_parse(wire, wire_len, release) ==
            VCS_PACKAGE_RELEASE_OK &&
        vcs_package_release_id(release, observed) ==
            VCS_PACKAGE_RELEASE_OK &&
        qualification_equal(observed, root) &&
        vcs_package_release_verify(release) == VCS_PACKAGE_RELEASE_OK;
    free(wire);
    return ok;
}

enum vcs_zcode_reproduction_qualification
vcs_zcode_reproduction_qualify_cas(
    const char *workspace, const uint8_t score_receipt_root[32],
    const uint8_t policy_candidate_root[32],
    const uint8_t reproduction_request_root[32],
    const uint8_t reproduction_proof_set_root[32],
    uint64_t epoch, int64_t now_unix,
    struct vcs_zcode_reproduction_qualification_report *out)
{
    if (out) memset(out, 0, sizeof(*out));
    if (!workspace || !score_receipt_root || !policy_candidate_root ||
        !reproduction_request_root || !reproduction_proof_set_root ||
        !out || now_unix <= 0)
        return out ? qualification_finish(out, VCS_ZCODE_QUALIFICATION_NULL)
                   : VCS_ZCODE_QUALIFICATION_NULL;
    out->reproduce_rule = VCS_REPRODUCE_REFERENCE_INVALID;
    /* A canonical v1 object has no physical-location attestation. */
    out->physical_independence_proven = false;

    uint8_t *wire = NULL, observed[32];
    size_t wire_len = 0;
    struct vcs_zcode_score_receipt_v1 score;
    if (!qualification_load(workspace, score_receipt_root,
                            VCS_ZCODE_SCORE_WIRE_BYTES, &wire, &wire_len) ||
        vcs_zcode_score_receipt_parse(wire, wire_len, &score) !=
            VCS_ZCODE_SCORE_OK ||
        vcs_zcode_score_receipt_id(&score, observed) != VCS_ZCODE_SCORE_OK ||
        !qualification_equal(observed, score_receipt_root)) {
        free(wire);
        return qualification_finish(out, VCS_ZCODE_QUALIFICATION_SCORE);
    }
    free(wire); wire = NULL;
    if (vcs_zcode_score_receipt_verify_cas(workspace, &score) !=
            VCS_ZCODE_SCORE_OK)
        return qualification_finish(out, VCS_ZCODE_QUALIFICATION_SCORE);

    struct vcs_zcode_policy_candidate_v1 policy;
    if (!qualification_load(workspace, policy_candidate_root,
                            VCS_ZCODE_POLICY_CANDIDATE_WIRE_BYTES,
                            &wire, &wire_len) ||
        vcs_zcode_policy_candidate_parse(wire, wire_len, &policy) !=
            VCS_ZCODE_SHADOW_OK ||
        vcs_zcode_policy_candidate_root(&policy, observed) !=
            VCS_ZCODE_SHADOW_OK ||
        !qualification_equal(observed, policy_candidate_root)) {
        free(wire);
        return qualification_finish(out, VCS_ZCODE_QUALIFICATION_POLICY);
    }
    free(wire); wire = NULL;
    struct vcs_zcode_approved_reproducer_set_v1 approved;
    if (!qualification_load(workspace, policy.approved_reproducer_set_root,
                            VCS_ZCODE_APPROVED_REPRODUCER_SET_MAX_WIRE_BYTES,
                            &wire, &wire_len) ||
        vcs_zcode_approved_reproducer_set_parse(wire, wire_len, &approved) !=
            VCS_ZCODE_SHADOW_OK ||
        vcs_zcode_approved_reproducer_set_root(&approved, observed) !=
            VCS_ZCODE_SHADOW_OK ||
        !qualification_equal(observed,
                             policy.approved_reproducer_set_root) ||
        vcs_zcode_policy_candidate_validate_set(&policy, &approved) !=
            VCS_ZCODE_SHADOW_OK) {
        free(wire);
        return qualification_finish(out, VCS_ZCODE_QUALIFICATION_POLICY);
    }
    free(wire); wire = NULL;

    struct vcs_zcode_reproduction_request_v1 request;
    if (!qualification_load(workspace, reproduction_request_root,
                            VCS_ZCODE_REPRODUCTION_REQUEST_WIRE_BYTES,
                            &wire, &wire_len) ||
        vcs_zcode_reproduction_request_parse(wire, wire_len, &request) !=
            VCS_ZCODE_REPRODUCTION_OK ||
        vcs_zcode_reproduction_request_root(&request, observed) !=
            VCS_ZCODE_REPRODUCTION_OK ||
        !qualification_equal(observed, reproduction_request_root) ||
        !qualification_equal(request.zc23_policy_root,
                             policy_candidate_root) ||
        !qualification_equal(request.network_genesis_root,
                             policy.network_genesis_root) ||
        !qualification_equal(request.task_root, score.task_root) ||
        !qualification_equal(request.candidate_root, score.candidate_root) ||
        !qualification_equal(request.package_root, score.package_root) ||
        !qualification_equal(request.release_root, score.release_root) ||
        !qualification_equal(request.recipe_root, score.recipe_root) ||
        !qualification_equal(request.dependency_lock_root,
                             score.dependency_lock_root) ||
        !qualification_equal(request.toolchain_capsule_root,
                             score.api_capsule_root)) {
        free(wire);
        return qualification_finish(out, VCS_ZCODE_QUALIFICATION_REQUEST);
    }
    free(wire); wire = NULL;

    struct vcs_package_build_receipt reference;
    struct vcs_build_artifact_manifest_v1 manifest;
    if (!qualification_load_build(workspace, request.reference_build_root,
                                  &reference) ||
        !qualification_load_manifest(workspace, request.output_manifest_root,
                                     &manifest) ||
        !qualification_equal(reference.package_root, request.package_root) ||
        !qualification_equal(reference.recipe_root, request.recipe_root) ||
        !qualification_equal(reference.lock_root,
                             request.dependency_lock_root) ||
        !qualification_equal(manifest.action_sha3, request.action_root))
        return qualification_finish(out, VCS_ZCODE_QUALIFICATION_REQUEST);

    struct vcs_zcode_candidate_v1 candidate;
    if (!qualification_load(workspace, score.candidate_root,
                            VCS_ZCODE_CANDIDATE_WIRE_BYTES,
                            &wire, &wire_len) ||
        vcs_zcode_candidate_parse(wire, wire_len, &candidate) !=
            VCS_ZCODE_DEV_OK ||
        vcs_zcode_candidate_root(&candidate, observed) != VCS_ZCODE_DEV_OK ||
        !qualification_equal(observed, score.candidate_root)) {
        free(wire);
        return qualification_finish(out, VCS_ZCODE_QUALIFICATION_SCORE);
    }
    free(wire); wire = NULL;

    uint8_t proof_roots[VCS_ZCODE_PROOF_SET_MAX_RECEIPTS][32];
    size_t proof_count = 0;
    if (!qualification_load(workspace, reproduction_proof_set_root,
                            VCS_ZCODE_PROOF_SET_WIRE_MAX, &wire, &wire_len) ||
        vcs_zcode_proof_set_parse(wire, wire_len, proof_roots,
            VCS_ZCODE_PROOF_SET_MAX_RECEIPTS, &proof_count) !=
            VCS_ZCODE_DEV_OK ||
        vcs_zcode_proof_set_root(proof_roots, proof_count, observed) !=
            VCS_ZCODE_DEV_OK ||
        !qualification_equal(observed, reproduction_proof_set_root)) {
        free(wire);
        return qualification_finish(out, VCS_ZCODE_QUALIFICATION_SCORE);
    }
    free(wire); wire = NULL;

    struct qualification_identity requester_identity;
    bool requester_known = qualification_load_binding(
        workspace, request.requester_contributor_binding_root,
        request.network_genesis_root, request.created_unix,
        &requester_identity);
    if (!requester_known)
        return qualification_finish(out, VCS_ZCODE_QUALIFICATION_REQUEST);
    struct vcs_zcode_work_receipt_v1
        reproduction_works[VCS_ZCODE_PROOF_SET_MAX_RECEIPTS];
    uint8_t reproduction_roots[VCS_ZCODE_PROOF_SET_MAX_RECEIPTS][32];
    size_t reproduction_count = 0;
    bool saw_reproduce = false;

    for (size_t i = 0; i < proof_count; i++) {
        struct vcs_zcode_work_receipt_v1 work;
        if (!qualification_load(workspace, proof_roots[i],
                                VCS_ZCODE_WORK_RECEIPT_WIRE_BYTES,
                                &wire, &wire_len) ||
            vcs_zcode_work_receipt_parse(wire, wire_len, &work) !=
                VCS_ZCODE_DEV_OK) {
            free(wire);
            return qualification_finish(out, VCS_ZCODE_QUALIFICATION_SCORE);
        }
        free(wire); wire = NULL;
        if (work.work_kind != VCS_ZCODE_WORK_REPRODUCE &&
            !qualification_equal(work.action_root, request.action_root))
            continue;
        saw_reproduce = true;
        if (vcs_zcode_work_receipt_id(&work, observed) != VCS_ZCODE_DEV_OK ||
            !qualification_equal(observed, proof_roots[i]) ||
            vcs_zcode_work_receipt_verify(&work, work.signer_pubkey) !=
                VCS_ZCODE_DEV_OK ||
            work.work_kind != VCS_ZCODE_WORK_REPRODUCE ||
            !qualification_equal(work.action_root, request.action_root) ||
            work.status != VCS_ZCODE_WORK_PASS || work.exit_status != 0 ||
            !qualification_equal(work.task_root, request.task_root) ||
            !qualification_equal(work.candidate_root,
                                 request.candidate_root) ||
            !qualification_equal(work.proof_policy_root,
                                 score.proof_policy_root) ||
            !qualification_equal(work.toolchain_capsule_root,
                                 request.toolchain_capsule_root) ||
            !qualification_equal(work.input_root,
                                 reproduction_request_root) ||
            !qualification_equal(work.evidence_root,
                                 request.output_manifest_root))
            return qualification_finish(out, VCS_ZCODE_QUALIFICATION_RECEIPT);
        if (work.started_unix < request.created_unix ||
            work.finished_unix > request.expires_unix)
            return qualification_finish(
                out, VCS_ZCODE_QUALIFICATION_CHALLENGE_EXPIRED);
        reproduction_works[reproduction_count] = work;
        memcpy(reproduction_roots[reproduction_count], proof_roots[i], 32);
        reproduction_count++;
    }
    if (reproduction_count == 0) {
        if (!saw_reproduce && now_unix >= request.expires_unix)
            return qualification_finish(out,
                VCS_ZCODE_QUALIFICATION_CHALLENGE_EXPIRED);
        return qualification_finish(out, VCS_ZCODE_QUALIFICATION_NO_RECEIPT);
    }
    for (size_t i = 0; i < reproduction_count; i++) {
        for (size_t j = i + 1u; j < reproduction_count; j++) {
            if (!qualification_equal(reproduction_works[i].output_root,
                                     reproduction_works[j].output_root))
                return qualification_finish(out,
                    VCS_ZCODE_QUALIFICATION_CONTRADICTION);
            if (qualification_equal(reproduction_works[i].signer_pubkey,
                                    reproduction_works[j].signer_pubkey) ||
                qualification_equal(reproduction_works[i].lease_id,
                                    reproduction_works[j].lease_id))
                return qualification_finish(out,
                    VCS_ZCODE_QUALIFICATION_DUPLICATE);
        }
    }

    for (size_t i = 0; i < reproduction_count; i++) {
        const struct vcs_zcode_work_receipt_v1 *work =
            &reproduction_works[i];

        struct vcs_package_build_receipt rebuild;
        struct vcs_reproduce_verdict reproduction;
        if (!qualification_load_build(workspace, work->output_root, &rebuild))
            return qualification_finish(out,
                VCS_ZCODE_QUALIFICATION_OUTPUT_MISMATCH);
        if (rebuild.isolation != VCS_PACKAGE_BUILD_ISOLATION_FULL)
            return qualification_finish(out,
                VCS_ZCODE_QUALIFICATION_CONFINEMENT_INSUFFICIENT);
        vcs_package_reproduce_compare(&reference, &rebuild, &reproduction);
        out->reproduce_rule = reproduction.rule;
        if (!reproduction.reproduced)
            return qualification_finish(out,
                VCS_ZCODE_QUALIFICATION_OUTPUT_MISMATCH);

        struct vcs_zcode_approved_reproducer_entry_v1 entry;
        enum vcs_zcode_shadow_error approval =
            vcs_zcode_approved_reproducer_set_find(
                &approved, work->signer_pubkey, request.action_root, epoch,
                work->finished_unix, &entry);
        if (approval == VCS_ZCODE_SHADOW_NOT_FOUND ||
            approval == VCS_ZCODE_SHADOW_ACTION)
            return qualification_finish(out,
                VCS_ZCODE_QUALIFICATION_SIGNER_NOT_APPROVED);
        if (approval != VCS_ZCODE_SHADOW_OK)
            return qualification_finish(out,
                VCS_ZCODE_QUALIFICATION_APPROVAL_NOT_VALID);
        struct qualification_identity reproducer_identity;
        if (!qualification_load_binding(
                workspace, entry.contributor_binding_root,
                request.network_genesis_root, work->finished_unix,
                &reproducer_identity) ||
            !qualification_equal(reproducer_identity.zid,
                                 work->signer_pubkey))
            return qualification_finish(out,
                VCS_ZCODE_QUALIFICATION_SIGNER_NOT_APPROVED);
        if (qualification_equal(work->signer_pubkey,
                                candidate.author_pubkey) ||
            qualification_equal(work->signer_pubkey, score.lane_signer) ||
            (requester_known &&
             qualification_equal(work->signer_pubkey,
                                 requester_identity.zid)))
            return qualification_finish(out,
                VCS_ZCODE_QUALIFICATION_SIGNER_NOT_DISTINCT);

        struct vcs_package_release release;
        bool publisher_known = qualification_load_release(
            workspace, request.release_root, &release);
        if (publisher_known &&
            memcmp(reproducer_identity.zcl, release.publisher_pubkey, 33) == 0)
            return qualification_finish(out,
                VCS_ZCODE_QUALIFICATION_SIGNER_NOT_DISTINCT);
        out->identity_linkage_complete = publisher_known;

        out->reproduction_receipts++;
        if (i == 0) {
            memcpy(out->reproduction_receipt_root, reproduction_roots[i], 32);
            memcpy(out->reproducer_signer, work->signer_pubkey, 32);
            memcpy(out->reproducer_contributor_binding_root,
                   entry.contributor_binding_root, 32);
            memcpy(out->operator_group_root, entry.operator_group_root, 32);
        }
    }
    out->exact_reproduction_match = true;
    out->distinct_signer = true;
    out->signer_policy_approved = true;
    /* No v1 authority declares the requester/candidate/lane operator group. */
    out->declared_operator_group_distinct = false;
    out->remote_transport_used = false;
    return qualification_finish(out, VCS_ZCODE_QUALIFICATION_READY);
}
