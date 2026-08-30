/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: independently re-derive every creation-attribution authority. */
#include "vcs/zcode_creation_attribution.h"

#include "base/bytes.h"
#include "vcs/package_manifest.h"
#include "vcs/package_release.h"
#include "vcs/vcs_object.h"
#include "vcs/zcode_contributor_binding.h"
#include "vcs/zcode_continuity_policy.h"
#include "vcs/zcode_dev.h"
#include "vcs/zcode_lane.h"
#include "vcs/zcode_score_receipt.h"

#include <stdlib.h>
#include <string.h>

struct creation_vertical {
    struct vcs_zcode_task_v1 task;
    struct vcs_zcode_candidate_v1 candidate;
    struct vcs_zcode_proof_policy_v1 policy;
    struct vcs_zcode_lane_receipt_v1 lane;
    struct vcs_zcode_score_receipt_v1 score;
    struct vcs_package_release release;
    uint8_t proof_roots[VCS_ZCODE_PROOF_SET_MAX_RECEIPTS][32];
    struct vcs_zcode_work_receipt_v1
        works[VCS_ZCODE_PROOF_SET_MAX_RECEIPTS];
    size_t proof_count;
};

#define CREATION_LINEAGE_MAX_DEPTH 256u

static enum vcs_zcode_creation_error creation_verify_cas_depth(
    const struct vcs_zcode_creation_attribution_v1 *a,
    const struct vcs_zcode_creation_validation_context *context,
    unsigned depth);

static bool creation_equal(const uint8_t a[32], const uint8_t b[32])
{
    return memcmp(a, b, 32) == 0;
}

static bool creation_load(const char *workspace, const uint8_t root[32],
                          size_t maximum, uint8_t **wire, size_t *wire_len)
{
    *wire = NULL;
    *wire_len = 0;
    return vcs_object_load_raw_bounded(workspace, root, maximum,
                                       wire, wire_len) == 0;
}

static enum vcs_zcode_creation_error creation_load_task_triplet(
    const struct vcs_zcode_creation_attribution_v1 *a, const char *workspace,
    struct creation_vertical *vertical)
{
    uint8_t *wire = NULL, root[32];
    size_t wire_len = 0;
    if (!creation_load(workspace, a->task_root, VCS_ZCODE_TASK_WIRE_BYTES,
                       &wire, &wire_len) ||
        vcs_zcode_task_parse(wire, wire_len, &vertical->task) !=
            VCS_ZCODE_DEV_OK ||
        vcs_zcode_task_root(&vertical->task, root) != VCS_ZCODE_DEV_OK ||
        !creation_equal(root, a->task_root)) {
        free(wire);
        return VCS_ZCODE_CREATION_TASK;
    }
    free(wire); wire = NULL;
    if (!creation_load(workspace, a->candidate_root,
                       VCS_ZCODE_CANDIDATE_WIRE_BYTES, &wire, &wire_len) ||
        vcs_zcode_candidate_parse(wire, wire_len, &vertical->candidate) !=
            VCS_ZCODE_DEV_OK ||
        vcs_zcode_candidate_root(&vertical->candidate, root) !=
            VCS_ZCODE_DEV_OK ||
        !creation_equal(root, a->candidate_root) ||
        !creation_equal(vertical->candidate.task_root, a->task_root) ||
        !creation_equal(vertical->candidate.base_source_root,
                        vertical->task.source_root) ||
        !creation_equal(vertical->candidate.candidate_source_root,
                        a->package_root) ||
        vcs_zcode_task_validate_at(&vertical->task,
                                   vertical->candidate.created_unix) !=
            VCS_ZCODE_DEV_OK) {
        free(wire);
        return VCS_ZCODE_CREATION_CANDIDATE;
    }
    free(wire); wire = NULL;
    if (!creation_load(workspace, a->proof_policy_root,
                       VCS_ZCODE_PROOF_POLICY_WIRE_BYTES, &wire, &wire_len) ||
        vcs_zcode_proof_policy_parse(wire, wire_len, &vertical->policy) !=
            VCS_ZCODE_DEV_OK ||
        vcs_zcode_proof_policy_root(&vertical->policy, root) !=
            VCS_ZCODE_DEV_OK ||
        !creation_equal(root, a->proof_policy_root) ||
        !creation_equal(vertical->task.proof_policy_root,
                        a->proof_policy_root)) {
        free(wire);
        return VCS_ZCODE_CREATION_PROOF_POLICY;
    }
    free(wire);
    return VCS_ZCODE_CREATION_OK;
}

static enum vcs_zcode_creation_error creation_load_contributor(
    const struct vcs_zcode_creation_attribution_v1 *a,
    const struct vcs_zcode_creation_validation_context *context,
    const struct vcs_zcode_candidate_v1 *candidate)
{
    uint8_t *wire = NULL, root[32], operation = 0, zid_pubkey[32];
    size_t wire_len = 0;
    if (!creation_load(context->workspace, a->contributor_binding_root,
                       VCS_ZCODE_CONTRIBUTOR_BINDING_V2_WIRE_BYTES,
                       &wire, &wire_len))
        return VCS_ZCODE_CREATION_CONTRIBUTOR;
    enum vcs_zcode_binding_error binding_error = VCS_ZCODE_BINDING_ERR_VERSION;
    if (wire_len == VCS_ZCODE_CONTRIBUTOR_BINDING_WIRE_BYTES) {
        struct vcs_zcode_contributor_binding_v1 binding;
        binding_error = vcs_zcode_contributor_binding_parse(
            wire, wire_len, &binding);
        if (binding_error == VCS_ZCODE_BINDING_OK)
            binding_error = vcs_zcode_contributor_binding_root(&binding, root);
        if (binding_error == VCS_ZCODE_BINDING_OK)
            binding_error = vcs_zcode_contributor_binding_verify(
                &binding, a->network_genesis_root, binding.zid_pubkey,
                candidate->created_unix);
        operation = binding.operation;
        memcpy(zid_pubkey, binding.zid_pubkey, sizeof(zid_pubkey));
    } else if (wire_len == VCS_ZCODE_CONTRIBUTOR_BINDING_V2_WIRE_BYTES) {
        struct vcs_zcode_contributor_binding_v2 binding;
        binding_error = vcs_zcode_contributor_binding_parse_v2(
            wire, wire_len, &binding);
        if (binding_error == VCS_ZCODE_BINDING_OK)
            binding_error = vcs_zcode_contributor_binding_root_v2(&binding,
                                                                   root);
        if (binding_error == VCS_ZCODE_BINDING_OK)
            binding_error = vcs_zcode_contributor_binding_verify_v2(
                &binding, a->network_genesis_root, binding.zid_pubkey,
                candidate->created_unix);
        operation = binding.operation;
        memcpy(zid_pubkey, binding.zid_pubkey, sizeof(zid_pubkey));
    }
    free(wire);
    if (binding_error != VCS_ZCODE_BINDING_OK ||
        !creation_equal(root, a->contributor_binding_root) ||
        !creation_equal(zid_pubkey, candidate->author_pubkey) ||
        operation == VCS_ZCODE_BINDING_REVOKE)
        return VCS_ZCODE_CREATION_CONTRIBUTOR;
    /* Historical attribution proves who authored the candidate at its
     * event time.  Rotation, expiry, or later revocation cannot erase that
     * fact.  Financial adapters must check current payout authority as a
     * separate decision; this verifier deliberately does not consult
     * binding_is_current. */
    return VCS_ZCODE_CREATION_OK;
}

static enum vcs_zcode_creation_error creation_verify_license_chunks(
    const char *workspace, const struct vcs_package_file *license)
{
    if (!license || license->size == 0 || license->chunk_count == 0)
        return VCS_ZCODE_CREATION_LICENSE;
    uint64_t observed = 0;
    for (uint32_t i = 0; i < license->chunk_count; i++) {
        const uint8_t *chunk_root = license->chunk_hashes + (size_t)i * 32u;
        uint8_t *chunk = NULL;
        size_t chunk_len = 0;
        if (!creation_load(workspace, chunk_root, VCS_PACKAGE_CHUNK_BYTES,
                           &chunk, &chunk_len) ||
            !vcs_package_verify_chunk(license, i, chunk, chunk_len)) {
            free(chunk);
            return VCS_ZCODE_CREATION_LICENSE;
        }
        if (UINT64_MAX - observed < chunk_len) {
            free(chunk);
            return VCS_ZCODE_CREATION_OVERFLOW;
        }
        observed += chunk_len;
        free(chunk);
    }
    return observed == license->size ? VCS_ZCODE_CREATION_OK
                                     : VCS_ZCODE_CREATION_LICENSE;
}

static enum vcs_zcode_creation_error creation_load_package(
    const struct vcs_zcode_creation_attribution_v1 *a, const char *workspace,
    struct creation_vertical *vertical)
{
    uint8_t *wire = NULL, root[32];
    size_t wire_len = 0;
    struct vcs_package_manifest manifest;
    vcs_package_manifest_init(&manifest);
    if (!creation_load(workspace, a->package_root,
                       VCS_PACKAGE_MANIFEST_MAX_WIRE_BYTES,
                       &wire, &wire_len) ||
        !vcs_package_manifest_parse(wire, wire_len, &manifest) ||
        !vcs_package_manifest_root(&manifest, root) ||
        !creation_equal(root, a->package_root)) {
        free(wire); vcs_package_manifest_free(&manifest);
        return VCS_ZCODE_CREATION_PACKAGE;
    }
    free(wire); wire = NULL;
    const struct vcs_package_file *license = NULL;
    for (size_t i = 0; i < manifest.count; i++)
        if (strcmp(manifest.files[i].path, "LICENSE") == 0)
            license = &manifest.files[i];
    if (!license || !vcs_package_file_hash(license, root) ||
        !creation_equal(root, a->license_evidence_root)) {
        vcs_package_manifest_free(&manifest);
        return VCS_ZCODE_CREATION_LICENSE;
    }
    enum vcs_zcode_creation_error error =
        creation_verify_license_chunks(workspace, license);
    vcs_package_manifest_free(&manifest);
    if (error != VCS_ZCODE_CREATION_OK)
        return error;

    if (!creation_load(workspace, a->release_root,
                       VCS_PACKAGE_RELEASE_MAX_WIRE_BYTES,
                       &wire, &wire_len) ||
        vcs_package_release_parse(wire, wire_len, &vertical->release) !=
            VCS_PACKAGE_RELEASE_OK ||
        vcs_package_release_verify(&vertical->release) !=
            VCS_PACKAGE_RELEASE_OK ||
        vcs_package_release_id(&vertical->release, root) !=
            VCS_PACKAGE_RELEASE_OK ||
        !creation_equal(root, a->release_root) ||
        !creation_equal(vertical->release.package_root, a->package_root) ||
        strcmp(vertical->release.chain_id, "zclassic-main") != 0) {
        free(wire);
        return VCS_ZCODE_CREATION_RELEASE;
    }
    free(wire);
    return VCS_ZCODE_CREATION_OK;
}

static enum vcs_zcode_creation_error creation_load_release(
    const char *workspace, const uint8_t release_root[32],
    struct vcs_package_release *release)
{
    uint8_t *wire = NULL, observed_root[32];
    size_t wire_len = 0;
    if (!creation_load(workspace, release_root,
                       VCS_PACKAGE_RELEASE_MAX_WIRE_BYTES,
                       &wire, &wire_len) ||
        vcs_package_release_parse(wire, wire_len, release) !=
            VCS_PACKAGE_RELEASE_OK ||
        vcs_package_release_verify(release) != VCS_PACKAGE_RELEASE_OK ||
        vcs_package_release_id(release, observed_root) !=
            VCS_PACKAGE_RELEASE_OK ||
        !creation_equal(observed_root, release_root)) {
        free(wire);
        memset(release, 0, sizeof(*release));
        return VCS_ZCODE_CREATION_RELEASE;
    }
    free(wire);
    return VCS_ZCODE_CREATION_OK;
}

static bool creation_release_is_direct_parent(
    const struct vcs_package_release *current,
    const struct vcs_package_release *parent,
    const uint8_t parent_root[32])
{
    return current->has_parent &&
        creation_equal(current->parent_root, parent_root) &&
        strcmp(current->name, parent->name) == 0 &&
        strcmp(current->chain_id, parent->chain_id) == 0 &&
        memcmp(current->publisher_pubkey, parent->publisher_pubkey,
               sizeof(current->publisher_pubkey)) == 0 &&
        parent->publisher_sequence != UINT64_MAX &&
        current->publisher_sequence == parent->publisher_sequence + 1;
}

static enum vcs_zcode_creation_error creation_verify_lineage(
    const struct vcs_zcode_creation_attribution_v1 *a,
    const struct vcs_zcode_creation_validation_context *context,
    const struct creation_vertical *vertical, unsigned depth)
{
    if (a->lineage_kind == VCS_ZCODE_CREATION_LINEAGE_CONTINUITY_POLICY)
        return VCS_ZCODE_CREATION_OK;
    if (a->lineage_kind == VCS_ZCODE_CREATION_LINEAGE_NONE)
        return vertical->release.has_parent ? VCS_ZCODE_CREATION_RELEASE
                                            : VCS_ZCODE_CREATION_OK;

    struct vcs_package_release parent_release;
    memset(&parent_release, 0, sizeof(parent_release));
    if (a->lineage_kind == VCS_ZCODE_CREATION_LINEAGE_RELEASE) {
        enum vcs_zcode_creation_error error = creation_load_release(
            context->workspace, a->lineage_root, &parent_release);
        if (error != VCS_ZCODE_CREATION_OK ||
            !creation_release_is_direct_parent(
                &vertical->release, &parent_release, a->lineage_root))
            return VCS_ZCODE_CREATION_RELEASE;
        return VCS_ZCODE_CREATION_OK;
    }
    if (a->lineage_kind !=
            VCS_ZCODE_CREATION_LINEAGE_PREDECESSOR_ATTRIBUTION ||
        depth >= CREATION_LINEAGE_MAX_DEPTH)
        return VCS_ZCODE_CREATION_LINEAGE;

    uint8_t *wire = NULL, prior_root[32];
    size_t wire_len = 0;
    struct vcs_zcode_creation_attribution_v1 prior;
    if (!creation_load(context->workspace, a->lineage_root,
                       VCS_ZCODE_CREATION_ATTRIBUTION_WIRE_BYTES,
                       &wire, &wire_len) ||
        vcs_zcode_creation_attribution_parse(wire, wire_len, &prior) !=
            VCS_ZCODE_CREATION_OK ||
        vcs_zcode_creation_attribution_root(&prior, prior_root) !=
            VCS_ZCODE_CREATION_OK ||
        !creation_equal(prior_root, a->lineage_root) ||
        !creation_equal(prior.network_genesis_root,
                        a->network_genesis_root) ||
        !creation_equal(prior.zc23_policy_root, a->zc23_policy_root) ||
        prior.epoch > a->epoch || prior.created_unix >= a->created_unix) {
        free(wire);
        return VCS_ZCODE_CREATION_LINEAGE;
    }
    free(wire);

    struct vcs_zcode_creation_validation_context prior_context = *context;
    prior_context.expected_epoch = prior.epoch;
    prior_context.expected_award_atoms = prior.award_atoms;
    enum vcs_zcode_creation_error error = creation_verify_cas_depth(
        &prior, &prior_context, depth + 1u);
    if (error != VCS_ZCODE_CREATION_OK)
        return VCS_ZCODE_CREATION_LINEAGE;
    if (creation_load_release(context->workspace, prior.release_root,
                              &parent_release) !=
            VCS_ZCODE_CREATION_OK ||
        !creation_release_is_direct_parent(
            &vertical->release, &parent_release, prior.release_root))
        return VCS_ZCODE_CREATION_RELEASE;
    return VCS_ZCODE_CREATION_OK;
}

static enum vcs_zcode_creation_error creation_load_proof_set(
    const struct vcs_zcode_creation_attribution_v1 *a, const char *workspace,
    struct creation_vertical *vertical)
{
    uint8_t *wire = NULL, root[32];
    size_t wire_len = 0;
    if (!creation_load(workspace, a->proof_set_root,
                       VCS_ZCODE_PROOF_SET_WIRE_MAX, &wire, &wire_len) ||
        vcs_zcode_proof_set_parse(
            wire, wire_len, vertical->proof_roots,
            VCS_ZCODE_PROOF_SET_MAX_RECEIPTS, &vertical->proof_count) !=
            VCS_ZCODE_DEV_OK ||
        vcs_zcode_proof_set_root(vertical->proof_roots,
                                 vertical->proof_count, root) !=
            VCS_ZCODE_DEV_OK ||
        !creation_equal(root, a->proof_set_root)) {
        free(wire);
        return VCS_ZCODE_CREATION_PROOF_SET;
    }
    free(wire);
    for (size_t i = 0; i < vertical->proof_count; i++) {
        wire = NULL; wire_len = 0;
        if (!creation_load(workspace, vertical->proof_roots[i],
                           VCS_ZCODE_WORK_RECEIPT_WIRE_BYTES,
                           &wire, &wire_len) ||
            vcs_zcode_work_receipt_parse(
                wire, wire_len, &vertical->works[i]) != VCS_ZCODE_DEV_OK ||
            vcs_zcode_work_receipt_id(&vertical->works[i], root) !=
                VCS_ZCODE_DEV_OK ||
            !creation_equal(root, vertical->proof_roots[i]) ||
            vcs_zcode_work_receipt_verify(
                &vertical->works[i], vertical->works[i].signer_pubkey) !=
                VCS_ZCODE_DEV_OK) {
            free(wire);
            return VCS_ZCODE_CREATION_PROOF_SET;
        }
        free(wire);
    }
    return VCS_ZCODE_CREATION_OK;
}

static enum vcs_zcode_creation_error creation_load_lane_score(
    const struct vcs_zcode_creation_attribution_v1 *a, const char *workspace,
    struct creation_vertical *vertical)
{
    uint8_t *wire = NULL, root[32];
    size_t wire_len = 0;
    if (!creation_load(workspace, a->score_receipt_root,
                       VCS_ZCODE_SCORE_WIRE_BYTES, &wire, &wire_len) ||
        vcs_zcode_score_receipt_parse(wire, wire_len, &vertical->score) !=
            VCS_ZCODE_SCORE_OK ||
        vcs_zcode_score_receipt_id(&vertical->score, root) !=
            VCS_ZCODE_SCORE_OK ||
        !creation_equal(root, a->score_receipt_root) ||
        vcs_zcode_score_receipt_verify(&vertical->score) !=
            VCS_ZCODE_SCORE_OK) {
        free(wire);
        return VCS_ZCODE_CREATION_SCORE;
    }
    free(wire); wire = NULL;
    if (!creation_load(workspace, a->proven_lane_root,
                       VCS_ZCODE_LANE_WIRE_BYTES, &wire, &wire_len) ||
        vcs_zcode_lane_receipt_parse(wire, wire_len, &vertical->lane) !=
            VCS_ZCODE_DEV_OK ||
        vcs_zcode_lane_receipt_id(&vertical->lane, root) !=
            VCS_ZCODE_DEV_OK ||
        !creation_equal(root, a->proven_lane_root) ||
        vertical->lane.lane != VCS_ZCODE_LANE_PROVEN ||
        vcs_zcode_lane_receipt_verify(&vertical->lane,
                                      vertical->score.lane_signer) !=
            VCS_ZCODE_DEV_OK ||
        vcs_zcode_lane_receipt_validate_for_candidate(
            &vertical->lane, &vertical->task, &vertical->candidate,
            &vertical->policy) != VCS_ZCODE_DEV_OK) {
        free(wire);
        return VCS_ZCODE_CREATION_LANE;
    }
    free(wire);
    return VCS_ZCODE_CREATION_OK;
}

static uint8_t creation_required_score_mask(uint16_t category)
{
    switch (category) {
    case VCS_ZCODE_CREATION_PUBLIC_SOURCE:
        return UINT8_C(1) << VCS_ZCODE_SCORE_ACCEPTED_EXTRACTION;
    case VCS_ZCODE_CREATION_BORN_RED_FIX:
    case VCS_ZCODE_CREATION_SECURITY_FIX:
        return UINT8_C(1) << VCS_ZCODE_SCORE_BORN_RED_DEFECT_TEST;
    case VCS_ZCODE_CREATION_INDEPENDENT_REPRODUCTION:
        return UINT8_C(1) << VCS_ZCODE_SCORE_INDEPENDENT_REPRODUCTION;
    case VCS_ZCODE_CREATION_COMPATIBILITY:
        return UINT8_C(1) << VCS_ZCODE_SCORE_COMPATIBILITY_MAINTENANCE;
    case VCS_ZCODE_CREATION_PRESERVATION:
        return (UINT8_C(1) << VCS_ZCODE_SCORE_INDEPENDENT_REPRODUCTION) |
               (UINT8_C(1) << VCS_ZCODE_SCORE_COMPATIBILITY_MAINTENANCE);
    }
    return 0;
}

static enum vcs_zcode_creation_error creation_rederive_score(
    const struct vcs_zcode_creation_attribution_v1 *a,
    struct creation_vertical *vertical)
{
    struct vcs_zcode_score_plan_input input = {
        .task = &vertical->task,
        .candidate = &vertical->candidate,
        .proof_policy = &vertical->policy,
        .proven_lane = &vertical->lane,
        .proof_receipt_roots = vertical->proof_roots,
        .work_receipts = vertical->works,
        .work_receipt_count = vertical->proof_count,
        .package_root = a->package_root,
        .release_root = a->release_root,
        .recipe_root = vertical->release.recipe_root,
        .dependency_lock_root = vertical->task.dependency_lock_root,
        .api_capsule_root = vertical->task.toolchain_capsule_root,
    };
    struct vcs_zcode_score_receipt_v1 expected;
    uint8_t actual_body[VCS_ZCODE_SCORE_BODY_BYTES];
    uint8_t expected_body[VCS_ZCODE_SCORE_BODY_BYTES];
    uint8_t needed = creation_required_score_mask(a->category);
    if (needed == 0 ||
        (vertical->score.awarded_mask & needed) != needed ||
        !creation_equal(vertical->score.task_root, a->task_root) ||
        !creation_equal(vertical->score.candidate_root, a->candidate_root) ||
        !creation_equal(vertical->score.proof_policy_root,
                        a->proof_policy_root) ||
        !creation_equal(vertical->score.proof_set_root, a->proof_set_root) ||
        !creation_equal(vertical->score.proven_lane_root,
                        a->proven_lane_root) ||
        !creation_equal(vertical->score.package_root, a->package_root) ||
        !creation_equal(vertical->score.release_root, a->release_root) ||
        vcs_zcode_score_plan(&input, &expected) != VCS_ZCODE_SCORE_OK ||
        vcs_zcode_score_receipt_body(&vertical->score, actual_body) !=
            VCS_ZCODE_SCORE_OK ||
        vcs_zcode_score_receipt_body(&expected, expected_body) !=
            VCS_ZCODE_SCORE_OK ||
        memcmp(actual_body, expected_body, sizeof(actual_body)) != 0)
        return VCS_ZCODE_CREATION_SCORE;
    return VCS_ZCODE_CREATION_OK;
}

static enum vcs_zcode_creation_error creation_verify_continuity(
    const struct vcs_zcode_creation_attribution_v1 *a,
    const struct vcs_zcode_creation_validation_context *context,
    const struct creation_vertical *vertical,
    const uint8_t attribution_root[32])
{
    if (a->category == VCS_ZCODE_CREATION_PUBLIC_SOURCE)
        return VCS_ZCODE_CREATION_OK;
    if (!context->continuity_is_duplicate)
        return VCS_ZCODE_CREATION_CONTINUITY;

    uint8_t event_key[32];
    if (vcs_zcode_creation_event_key(
            a, &vertical->task, &vertical->score, event_key) !=
            VCS_ZCODE_CONTINUITY_OK)
        return VCS_ZCODE_CREATION_CONTINUITY;

    /* Patronage is an optional additional constraint.  When a v1
     * attribution names a continuity policy, verify its funding caps and
     * transition claims; otherwise the already-verified signed release or
     * predecessor lineage is sufficient creation authority. */
    if (a->lineage_kind ==
            VCS_ZCODE_CREATION_LINEAGE_CONTINUITY_POLICY) {
        uint8_t *wire = NULL, policy_root[32], policy_event_key[32];
        size_t wire_len = 0;
        struct vcs_zcode_continuity_policy_v1 policy;
        if (!creation_load(context->workspace, a->lineage_root,
                           VCS_ZCODE_CONTINUITY_POLICY_WIRE_BYTES,
                           &wire, &wire_len) ||
            vcs_zcode_continuity_policy_parse(wire, wire_len, &policy) !=
                VCS_ZCODE_CONTINUITY_OK ||
            vcs_zcode_continuity_policy_root(&policy, policy_root) !=
                VCS_ZCODE_CONTINUITY_OK ||
            !creation_equal(policy_root, a->lineage_root)) {
            free(wire);
            return VCS_ZCODE_CREATION_CONTINUITY;
        }
        free(wire);
        struct vcs_zcode_patronage_validation_context policy_context = {
            .workspace = context->workspace,
            .expected_network_genesis_root =
                context->expected_network_genesis_root,
            .now_unix = context->now_unix,
            .binding_is_current = context->binding_is_current,
            .callback_opaque = context->callback_opaque,
        };
        if (vcs_zcode_continuity_policy_verify_cas(
                &policy, &policy_context) != VCS_ZCODE_CONTINUITY_OK ||
            vcs_zcode_continuity_event_key(
                a, &policy, &vertical->task, &vertical->score,
                policy_event_key) != VCS_ZCODE_CONTINUITY_OK)
            return VCS_ZCODE_CREATION_CONTINUITY;
    }
    if (context->continuity_is_duplicate(
            context->callback_opaque, event_key, attribution_root))
        return VCS_ZCODE_CREATION_DUPLICATE;
    return VCS_ZCODE_CREATION_OK;
}

static enum vcs_zcode_creation_error creation_verify_cas_depth(
    const struct vcs_zcode_creation_attribution_v1 *a,
    const struct vcs_zcode_creation_validation_context *context,
    unsigned depth)
{
    enum vcs_zcode_creation_error error =
        vcs_zcode_creation_attribution_validate(a);
    if (error != VCS_ZCODE_CREATION_OK)
        return error;
    if (!context || !context->workspace ||
        !context->expected_network_genesis_root ||
        !context->expected_zc23_policy_root ||
        !context->anchor_is_active ||
        !context->contribution_is_duplicate || context->now_unix <= 0 ||
        !zcl_bytes_any_set(context->expected_network_genesis_root, 32) ||
        !zcl_bytes_any_set(context->expected_zc23_policy_root, 32))
        return VCS_ZCODE_CREATION_CONTEXT;
    if (!creation_equal(a->network_genesis_root,
                        context->expected_network_genesis_root))
        return VCS_ZCODE_CREATION_NETWORK;
    if (!creation_equal(a->zc23_policy_root,
                        context->expected_zc23_policy_root))
        return VCS_ZCODE_CREATION_POLICY;
    if (a->epoch != context->expected_epoch)
        return VCS_ZCODE_CREATION_EPOCH;
    if (a->award_atoms != context->expected_award_atoms ||
        context->expected_award_atoms == 0)
        return VCS_ZCODE_CREATION_AMOUNT;
    if (context->active_height < a->challenge_maturity_height ||
        context->active_mtp < a->challenge_maturity_mtp ||
        context->now_unix < a->created_unix)
        return VCS_ZCODE_CREATION_IMMATURE;
    if (!context->anchor_is_active(context->callback_opaque,
                                   a->challenge_opening_height,
                                   a->challenge_opening_hash))
        return VCS_ZCODE_CREATION_REORG;

    struct creation_vertical vertical;
    memset(&vertical, 0, sizeof(vertical));
    error = creation_load_task_triplet(a, context->workspace, &vertical);
    if (error != VCS_ZCODE_CREATION_OK)
        return error;
    error = creation_load_contributor(a, context, &vertical.candidate);
    if (error != VCS_ZCODE_CREATION_OK)
        return error;
    error = creation_load_package(a, context->workspace, &vertical);
    if (error != VCS_ZCODE_CREATION_OK)
        return error;
    error = creation_load_proof_set(a, context->workspace, &vertical);
    if (error != VCS_ZCODE_CREATION_OK)
        return error;
    error = creation_load_lane_score(a, context->workspace, &vertical);
    if (error != VCS_ZCODE_CREATION_OK)
        return error;
    error = creation_rederive_score(a, &vertical);
    if (error != VCS_ZCODE_CREATION_OK)
        return error;
    error = creation_verify_lineage(a, context, &vertical, depth);
    if (error != VCS_ZCODE_CREATION_OK)
        return error;
    uint8_t attribution_root[32];
    if (vcs_zcode_creation_attribution_root(a, attribution_root) !=
            VCS_ZCODE_CREATION_OK)
        return VCS_ZCODE_CREATION_ROOT;
    if (context->contribution_is_duplicate(
            context->callback_opaque, a->candidate_root, attribution_root))
        return VCS_ZCODE_CREATION_DUPLICATE;
    return creation_verify_continuity(
        a, context, &vertical, attribution_root);
}

enum vcs_zcode_creation_error vcs_zcode_creation_attribution_verify_cas(
    const struct vcs_zcode_creation_attribution_v1 *a,
    const struct vcs_zcode_creation_validation_context *context)
{
    return creation_verify_cas_depth(a, context, 0);
}
