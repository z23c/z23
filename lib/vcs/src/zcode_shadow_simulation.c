/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: deterministic scratch-only Living Commons shadow plans. */
#include "vcs/zcode_shadow_simulation.h"

#include "base/bytes.h"
#include "base/checked.h"
#include "base/safe_alloc.h"
#include "codec/cursor.h"
#include "crypto/sha3.h"
#include "vcs/package_manifest.h"
#include "vcs/package_release.h"
#include "vcs/vcs_object.h"
#include "vcs/zcode_commons_projection.h"
#include "vcs/zcode_reproduction_request.h"
#include "vcs/zcode_score_receipt.h"
#include "vcs/zcode_shadow_policy.h"

#include <stdlib.h>
#include <string.h>

struct shadow_fixture_callbacks {
    const struct vcs_zcode_commons_projection *projection;
    uint64_t opening_height;
    uint8_t opening_hash[32];
    uint64_t maturity_height;
    uint8_t maturity_hash[32];
};

static bool shadow_sim_equal(const uint8_t a[32], const uint8_t b[32])
{
    return memcmp(a, b, 32) == 0;
}

static bool shadow_sim_load(const char *workspace, const uint8_t root[32],
                            size_t maximum, uint8_t **wire, size_t *wire_len)
{
    *wire = NULL;
    *wire_len = 0;
    return workspace && vcs_object_load_raw_bounded(
        workspace, root, maximum, wire, wire_len) == 0;
}

const char *vcs_zcode_shadow_simulation_error_string(
    enum vcs_zcode_shadow_simulation_error error)
{
    switch (error) {
    case VCS_ZCODE_SHADOW_SIMULATION_OK: return "ok";
    case VCS_ZCODE_SHADOW_SIMULATION_NULL: return "null";
    case VCS_ZCODE_SHADOW_SIMULATION_CAS: return "cas_object_invalid";
    case VCS_ZCODE_SHADOW_SIMULATION_QUALIFICATION:
        return "reproduction_not_qualified";
    case VCS_ZCODE_SHADOW_SIMULATION_POLICY: return "policy_invalid";
    case VCS_ZCODE_SHADOW_SIMULATION_AWARD: return "award_invalid";
    case VCS_ZCODE_SHADOW_SIMULATION_ANCHOR: return "fixture_anchor_invalid";
    case VCS_ZCODE_SHADOW_SIMULATION_ATTRIBUTION:
        return "attribution_invalid";
    case VCS_ZCODE_SHADOW_SIMULATION_DUPLICATE:
        return "duplicate_creation";
    case VCS_ZCODE_SHADOW_SIMULATION_PREDECESSOR:
        return "predecessor_epoch_invalid";
    case VCS_ZCODE_SHADOW_SIMULATION_EPOCH: return "epoch_invalid";
    case VCS_ZCODE_SHADOW_SIMULATION_OVERFLOW: return "checked_overflow";
    }
    return "unknown";
}

bool vcs_zcode_shadow_fixture_anchor_root(
    const uint8_t policy_root[32], const uint8_t branch_root[32],
    uint64_t epoch, uint8_t anchor_kind, uint8_t out[32])
{
    if (!policy_root || !branch_root || !out ||
        zcl_bytes_all_zero(policy_root, 32) || zcl_bytes_all_zero(branch_root, 32) ||
        (anchor_kind != 1u && anchor_kind != 2u)) {
        if (out) memset(out, 0, 32);
        return false;
    }
    uint8_t numbers[9];
    struct zcl_codec_writer writer;
    zcl_codec_writer_init(&writer, numbers, sizeof(numbers));
    size_t written = 0;
    if (!zcl_codec_write_u64le(&writer, epoch) ||
        !zcl_codec_write_u8(&writer, anchor_kind) ||
        !zcl_codec_writer_finish(&writer, &written) ||
        written != sizeof(numbers))
        return false;
    static const char domain[] = VCS_ZCODE_SHADOW_FIXTURE_DOMAIN;
    struct sha3_256_ctx sha;
    sha3_256_init(&sha);
    sha3_256_write(&sha, (const uint8_t *)domain, sizeof(domain));
    sha3_256_write(&sha, policy_root, 32);
    sha3_256_write(&sha, branch_root, 32);
    sha3_256_write(&sha, numbers, sizeof(numbers));
    sha3_256_finalize(&sha, out);
    return true;
}

static bool shadow_fixture_anchor(void *opaque, uint64_t height,
                                  const uint8_t hash[32])
{
    const struct shadow_fixture_callbacks *fixture = opaque;
    return fixture &&
        ((height == fixture->opening_height &&
          shadow_sim_equal(hash, fixture->opening_hash)) ||
         (height == fixture->maturity_height &&
          shadow_sim_equal(hash, fixture->maturity_hash)));
}

static bool shadow_fixture_duplicate(void *opaque,
                                     const uint8_t candidate_root[32],
                                     const uint8_t attribution_root[32])
{
    const struct shadow_fixture_callbacks *fixture = opaque;
    if (!fixture || !fixture->projection) return false;
    size_t count = vcs_zcode_commons_projection_creation_count(
        fixture->projection);
    for (size_t i = 0; i < count; i++) {
        const struct vcs_zcode_commons_creation_entry *entry =
            vcs_zcode_commons_projection_creation_at(
                fixture->projection, i);
        if (entry && shadow_sim_equal(entry->candidate_root, candidate_root) &&
            !shadow_sim_equal(entry->root, attribution_root))
            return true;
    }
    return false;
}

static bool shadow_fixture_continuity_duplicate(
    void *opaque, const uint8_t event_key[32],
    const uint8_t attribution_root[32])
{
    (void)opaque;
    (void)event_key;
    (void)attribution_root;
    return false;
}

static enum vcs_zcode_shadow_simulation_error shadow_load_policy(
    const char *workspace, const uint8_t root[32],
    struct vcs_zcode_policy_candidate_v1 *policy)
{
    uint8_t *wire = NULL, observed[32];
    size_t wire_len = 0;
    bool ok = shadow_sim_load(workspace, root,
                              VCS_ZCODE_POLICY_CANDIDATE_WIRE_BYTES,
                              &wire, &wire_len) &&
        vcs_zcode_policy_candidate_parse(wire, wire_len, policy) ==
            VCS_ZCODE_SHADOW_OK &&
        vcs_zcode_policy_candidate_root(policy, observed) ==
            VCS_ZCODE_SHADOW_OK && shadow_sim_equal(observed, root);
    free(wire);
    return ok ? VCS_ZCODE_SHADOW_SIMULATION_OK
              : VCS_ZCODE_SHADOW_SIMULATION_POLICY;
}

static enum vcs_zcode_shadow_simulation_error shadow_load_score(
    const char *workspace, const uint8_t root[32],
    struct vcs_zcode_score_receipt_v1 *score)
{
    uint8_t *wire = NULL, observed[32];
    size_t wire_len = 0;
    bool ok = shadow_sim_load(workspace, root, VCS_ZCODE_SCORE_WIRE_BYTES,
                              &wire, &wire_len) &&
        vcs_zcode_score_receipt_parse(wire, wire_len, score) ==
            VCS_ZCODE_SCORE_OK &&
        vcs_zcode_score_receipt_id(score, observed) == VCS_ZCODE_SCORE_OK &&
        shadow_sim_equal(observed, root) &&
        vcs_zcode_score_receipt_verify_cas(workspace, score) ==
            VCS_ZCODE_SCORE_OK;
    free(wire);
    return ok ? VCS_ZCODE_SHADOW_SIMULATION_OK
              : VCS_ZCODE_SHADOW_SIMULATION_CAS;
}

static enum vcs_zcode_shadow_simulation_error shadow_package_facts(
    const char *workspace, const struct vcs_zcode_score_receipt_v1 *score,
    uint8_t license_root[32], uint8_t *lineage_kind,
    uint8_t lineage_root[32])
{
    uint8_t *wire = NULL, observed[32];
    size_t wire_len = 0;
    struct vcs_package_manifest manifest;
    vcs_package_manifest_init(&manifest);
    if (!shadow_sim_load(workspace, score->package_root,
                         VCS_PACKAGE_MANIFEST_MAX_WIRE_BYTES,
                         &wire, &wire_len) ||
        !vcs_package_manifest_parse(wire, wire_len, &manifest) ||
        !vcs_package_manifest_root(&manifest, observed) ||
        !shadow_sim_equal(observed, score->package_root)) {
        free(wire);
        vcs_package_manifest_free(&manifest);
        return VCS_ZCODE_SHADOW_SIMULATION_CAS;
    }
    free(wire); wire = NULL;
    const struct vcs_package_file *license = NULL;
    for (size_t i = 0; i < manifest.count; i++)
        if (strcmp(manifest.files[i].path, "LICENSE") == 0)
            license = &manifest.files[i];
    bool license_ok = license && vcs_package_file_hash(license, license_root);
    vcs_package_manifest_free(&manifest);
    if (!license_ok)
        return VCS_ZCODE_SHADOW_SIMULATION_CAS;

    struct vcs_package_release release;
    if (!shadow_sim_load(workspace, score->release_root,
                         VCS_PACKAGE_RELEASE_MAX_WIRE_BYTES,
                         &wire, &wire_len) ||
        vcs_package_release_parse(wire, wire_len, &release) !=
            VCS_PACKAGE_RELEASE_OK ||
        vcs_package_release_verify(&release) != VCS_PACKAGE_RELEASE_OK ||
        vcs_package_release_id(&release, observed) !=
            VCS_PACKAGE_RELEASE_OK ||
        !shadow_sim_equal(observed, score->release_root) ||
        !shadow_sim_equal(release.package_root, score->package_root)) {
        free(wire);
        return VCS_ZCODE_SHADOW_SIMULATION_CAS;
    }
    free(wire);
    memset(lineage_root, 0, 32);
    if (release.has_parent) {
        *lineage_kind = VCS_ZCODE_CREATION_LINEAGE_RELEASE;
        memcpy(lineage_root, release.parent_root, 32);
    } else {
        *lineage_kind = VCS_ZCODE_CREATION_LINEAGE_NONE;
    }
    return VCS_ZCODE_SHADOW_SIMULATION_OK;
}

enum vcs_zcode_shadow_simulation_error
vcs_zcode_shadow_attribution_plan_cas(
    const struct vcs_zcode_shadow_attribution_input *input,
    struct vcs_zcode_shadow_attribution_plan *out)
{
    if (out) memset(out, 0, sizeof(*out));
    if (!input || !out || !input->workspace ||
        !input->score_receipt_root || !input->policy_candidate_root ||
        !input->reproduction_request_root ||
        !input->reproduction_proof_set_root ||
        !input->contributor_binding_root || input->now_unix <= 0)
        return VCS_ZCODE_SHADOW_SIMULATION_NULL;

    if (vcs_zcode_reproduction_qualify_cas(
            input->workspace, input->score_receipt_root,
            input->policy_candidate_root,
            input->reproduction_request_root,
            input->reproduction_proof_set_root, input->epoch,
            input->now_unix, &out->qualification) !=
            VCS_ZCODE_QUALIFICATION_READY)
        return VCS_ZCODE_SHADOW_SIMULATION_QUALIFICATION;

    struct vcs_zcode_policy_candidate_v1 policy;
    enum vcs_zcode_shadow_simulation_error error = shadow_load_policy(
        input->workspace, input->policy_candidate_root, &policy);
    if (error != VCS_ZCODE_SHADOW_SIMULATION_OK) return error;
    struct vcs_zcode_score_receipt_v1 score;
    error = shadow_load_score(input->workspace, input->score_receipt_root,
                              &score);
    if (error != VCS_ZCODE_SHADOW_SIMULATION_OK) return error;

    struct vcs_zcode_reproduction_request_v1 request;
    uint8_t *wire = NULL, observed[32];
    size_t wire_len = 0;
    if (!shadow_sim_load(input->workspace,
                         input->reproduction_request_root,
                         VCS_ZCODE_REPRODUCTION_REQUEST_WIRE_BYTES,
                         &wire, &wire_len) ||
        vcs_zcode_reproduction_request_parse(wire, wire_len, &request) !=
            VCS_ZCODE_REPRODUCTION_OK ||
        vcs_zcode_reproduction_request_root(&request, observed) !=
            VCS_ZCODE_REPRODUCTION_OK ||
        !shadow_sim_equal(observed, input->reproduction_request_root)) {
        free(wire);
        return VCS_ZCODE_SHADOW_SIMULATION_CAS;
    }
    free(wire);

    uint64_t award = 0;
    if (vcs_zcode_policy_candidate_award_atoms(
            &policy, VCS_ZCODE_CREATION_PUBLIC_SOURCE, &award) !=
            VCS_ZCODE_SHADOW_OK || award == 0)
        return VCS_ZCODE_SHADOW_SIMULATION_AWARD;
    uint64_t epoch_stride = 0, opening_height = 0;
    if (!zcl_u64_add(VCS_ZC23_CHALLENGE_BLOCKS,
                     VCS_ZC23_CHALLENGE_BLOCKS, &epoch_stride) ||
        !zcl_u64_mul(input->epoch, epoch_stride, &opening_height))
        return VCS_ZCODE_SHADOW_SIMULATION_OVERFLOW;
    uint64_t maturity_height = 0;
    if (!zcl_u64_add(opening_height, VCS_ZC23_CHALLENGE_BLOCKS,
                     &maturity_height) ||
        request.created_unix > INT64_MAX - VCS_ZC23_CHALLENGE_SECONDS)
        return VCS_ZCODE_SHADOW_SIMULATION_OVERFLOW;
    int64_t maturity_mtp =
        request.created_unix + VCS_ZC23_CHALLENGE_SECONDS;
    if (input->now_unix < maturity_mtp)
        return VCS_ZCODE_SHADOW_SIMULATION_ANCHOR;

    memcpy(out->fixture_branch_root, input->reproduction_proof_set_root, 32);
    struct vcs_zcode_creation_attribution_v1 *attribution =
        &out->attribution;
    attribution->schema_version = VCS_ZCODE_CREATION_ATTRIBUTION_VERSION;
    attribution->category = VCS_ZCODE_CREATION_PUBLIC_SOURCE;
    attribution->epoch = input->epoch;
    attribution->award_atoms = award;
    attribution->challenge_opening_height = opening_height;
    attribution->challenge_opening_mtp = request.created_unix;
    attribution->challenge_maturity_height = maturity_height;
    attribution->challenge_maturity_mtp = maturity_mtp;
    attribution->created_unix = maturity_mtp;
    memcpy(attribution->network_genesis_root, policy.network_genesis_root, 32);
    memcpy(attribution->zc23_policy_root, input->policy_candidate_root, 32);
    memcpy(attribution->contributor_binding_root,
           input->contributor_binding_root, 32);
    memcpy(attribution->task_root, score.task_root, 32);
    memcpy(attribution->candidate_root, score.candidate_root, 32);
    memcpy(attribution->proof_policy_root, score.proof_policy_root, 32);
    memcpy(attribution->proof_set_root, score.proof_set_root, 32);
    memcpy(attribution->proven_lane_root, score.proven_lane_root, 32);
    memcpy(attribution->score_receipt_root, input->score_receipt_root, 32);
    memcpy(attribution->package_root, score.package_root, 32);
    memcpy(attribution->release_root, score.release_root, 32);
    error = shadow_package_facts(
        input->workspace, &score, attribution->license_evidence_root,
        &attribution->lineage_kind, attribution->lineage_root);
    if (error != VCS_ZCODE_SHADOW_SIMULATION_OK) return error;
    if (!vcs_zcode_shadow_fixture_anchor_root(
            input->policy_candidate_root, out->fixture_branch_root,
            input->epoch, 1, attribution->challenge_opening_hash))
        return VCS_ZCODE_SHADOW_SIMULATION_ANCHOR;
    if (vcs_zcode_creation_attribution_root(
            attribution, out->attribution_root) != VCS_ZCODE_CREATION_OK)
        return VCS_ZCODE_SHADOW_SIMULATION_ATTRIBUTION;

    struct vcs_zcode_commons_projection *projection =
        vcs_zcode_commons_projection_build(input->workspace);
    if (!projection)
        return VCS_ZCODE_SHADOW_SIMULATION_CAS;
    struct shadow_fixture_callbacks fixture = {
        .projection = projection,
        .opening_height = opening_height,
        .maturity_height = maturity_height,
    };
    memcpy(fixture.opening_hash, attribution->challenge_opening_hash, 32);
    (void)vcs_zcode_shadow_fixture_anchor_root(
        input->policy_candidate_root, out->fixture_branch_root,
        input->epoch, 2, fixture.maturity_hash);
    struct vcs_zcode_creation_validation_context context = {
        .workspace = input->workspace,
        .expected_network_genesis_root = policy.network_genesis_root,
        .expected_zc23_policy_root = input->policy_candidate_root,
        .expected_epoch = input->epoch,
        .expected_award_atoms = award,
        .active_height = maturity_height,
        .active_mtp = maturity_mtp,
        .now_unix = input->now_unix,
        .anchor_is_active = shadow_fixture_anchor,
        .contribution_is_duplicate = shadow_fixture_duplicate,
        .continuity_is_duplicate = shadow_fixture_continuity_duplicate,
        .callback_opaque = &fixture,
    };
    enum vcs_zcode_creation_error creation_error =
        vcs_zcode_creation_attribution_verify_cas(attribution, &context);
    vcs_zcode_commons_projection_free(projection);
    if (creation_error == VCS_ZCODE_CREATION_DUPLICATE)
        return VCS_ZCODE_SHADOW_SIMULATION_DUPLICATE;
    return creation_error == VCS_ZCODE_CREATION_OK
        ? VCS_ZCODE_SHADOW_SIMULATION_OK
        : VCS_ZCODE_SHADOW_SIMULATION_ATTRIBUTION;
}

enum vcs_zcode_shadow_simulation_error vcs_zcode_shadow_epoch_plan_cas(
    const struct vcs_zcode_shadow_epoch_input *input,
    struct vcs_zcode_shadow_epoch_plan *out)
{
    if (out) memset(out, 0, sizeof(*out));
    if (!input || !out || !input->workspace ||
        !input->policy_candidate_root || !input->attribution_root ||
        !input->fixture_branch_root ||
        !input->previous_epoch_creation_root || input->now_unix <= 0)
        return VCS_ZCODE_SHADOW_SIMULATION_NULL;
    struct vcs_zcode_policy_candidate_v1 policy;
    enum vcs_zcode_shadow_simulation_error error = shadow_load_policy(
        input->workspace, input->policy_candidate_root, &policy);
    if (error != VCS_ZCODE_SHADOW_SIMULATION_OK) return error;

    uint8_t *wire = NULL, observed[32];
    size_t wire_len = 0;
    struct vcs_zcode_creation_attribution_v1 attribution;
    if (!shadow_sim_load(input->workspace, input->attribution_root,
                         VCS_ZCODE_CREATION_ATTRIBUTION_WIRE_BYTES,
                         &wire, &wire_len) ||
        vcs_zcode_creation_attribution_parse(wire, wire_len, &attribution) !=
            VCS_ZCODE_CREATION_OK ||
        vcs_zcode_creation_attribution_root(&attribution, observed) !=
            VCS_ZCODE_CREATION_OK ||
        !shadow_sim_equal(observed, input->attribution_root) ||
        !shadow_sim_equal(attribution.zc23_policy_root,
                          input->policy_candidate_root)) {
        free(wire);
        return VCS_ZCODE_SHADOW_SIMULATION_ATTRIBUTION;
    }
    free(wire); wire = NULL;

    if (attribution.epoch == 0) {
        if (!zcl_bytes_all_zero(input->previous_epoch_creation_root, 32))
            return VCS_ZCODE_SHADOW_SIMULATION_PREDECESSOR;
    } else {
        struct vcs_zcode_epoch_creation_set_v1 previous;
        vcs_zcode_epoch_creation_init(&previous);
        bool previous_ok = shadow_sim_load(
                input->workspace, input->previous_epoch_creation_root,
                VCS_ZCODE_EPOCH_CREATION_MAX_WIRE_BYTES, &wire, &wire_len) &&
            vcs_zcode_epoch_creation_parse(wire, wire_len, &previous) ==
                VCS_ZCODE_EPOCH_CREATION_OK &&
            vcs_zcode_epoch_creation_root(&previous, observed) ==
                VCS_ZCODE_EPOCH_CREATION_OK &&
            shadow_sim_equal(observed,
                             input->previous_epoch_creation_root) &&
            previous.epoch != UINT64_MAX &&
            previous.epoch + 1u == attribution.epoch &&
            shadow_sim_equal(previous.network_genesis_root,
                             attribution.network_genesis_root) &&
            shadow_sim_equal(previous.zc23_policy_root,
                             attribution.zc23_policy_root);
        free(wire);
        vcs_zcode_epoch_creation_free(&previous);
        if (!previous_ok)
            return VCS_ZCODE_SHADOW_SIMULATION_PREDECESSOR;
    }

    struct vcs_zcode_epoch_creation_set_v1 *epoch = &out->epoch;
    vcs_zcode_epoch_creation_init(epoch);
    epoch->schema_version = VCS_ZCODE_EPOCH_CREATION_VERSION;
    epoch->epoch = attribution.epoch;
    if (vcs_zc23_policy_epoch_cap_atoms(
            epoch->epoch, &epoch->emission_cap_atoms) !=
            VCS_ZCODE_EPOCH_CREATION_OK ||
        attribution.award_atoms > epoch->emission_cap_atoms)
        return VCS_ZCODE_SHADOW_SIMULATION_AWARD;
    epoch->actual_mint_atoms = attribution.award_atoms;
    epoch->unissued_atoms = epoch->emission_cap_atoms -
                            epoch->actual_mint_atoms;
    memcpy(epoch->network_genesis_root, attribution.network_genesis_root, 32);
    memcpy(epoch->zc23_policy_root, input->policy_candidate_root, 32);
    memcpy(epoch->previous_epoch_creation_root,
           input->previous_epoch_creation_root, 32);
    memcpy(epoch->committee_evidence_snapshot_root,
           input->fixture_branch_root, 32);
    epoch->opening_height = attribution.challenge_opening_height;
    memcpy(epoch->opening_hash, attribution.challenge_opening_hash, 32);
    epoch->opening_mtp = attribution.challenge_opening_mtp;
    epoch->maturity_height = attribution.challenge_maturity_height;
    epoch->maturity_mtp = attribution.challenge_maturity_mtp;
    uint8_t expected_opening_hash[32];
    if (!vcs_zcode_shadow_fixture_anchor_root(
            input->policy_candidate_root, input->fixture_branch_root,
            epoch->epoch, 1, expected_opening_hash) ||
        !shadow_sim_equal(expected_opening_hash, epoch->opening_hash) ||
        !vcs_zcode_shadow_fixture_anchor_root(
            input->policy_candidate_root, input->fixture_branch_root,
            epoch->epoch, 2, epoch->maturity_hash)) {
        vcs_zcode_epoch_creation_free(epoch);
        return VCS_ZCODE_SHADOW_SIMULATION_ANCHOR;
    }
    epoch->attribution_roots = zcl_malloc(
        sizeof(*epoch->attribution_roots),
        "zcode_shadow_epoch_attribution_root");
    if (!epoch->attribution_roots) {
        vcs_zcode_epoch_creation_free(epoch);
        return VCS_ZCODE_SHADOW_SIMULATION_CAS;
    }
    memcpy(epoch->attribution_roots[0], input->attribution_root, 32);
    epoch->attribution_count = 1;
    memcpy(out->attribution_root, input->attribution_root, 32);
    if (vcs_zcode_epoch_creation_root(epoch, out->epoch_root) !=
            VCS_ZCODE_EPOCH_CREATION_OK) {
        vcs_zcode_epoch_creation_free(epoch);
        return VCS_ZCODE_SHADOW_SIMULATION_EPOCH;
    }

    struct vcs_zcode_commons_projection *projection =
        vcs_zcode_commons_projection_build(input->workspace);
    if (!projection) {
        vcs_zcode_epoch_creation_free(epoch);
        return VCS_ZCODE_SHADOW_SIMULATION_CAS;
    }
    struct shadow_fixture_callbacks fixture = {
        .projection = projection,
        .opening_height = epoch->opening_height,
        .maturity_height = epoch->maturity_height,
    };
    memcpy(fixture.opening_hash, epoch->opening_hash, 32);
    memcpy(fixture.maturity_hash, epoch->maturity_hash, 32);
    struct vcs_zcode_epoch_creation_validation_context context = {
        .workspace = input->workspace,
        .expected_network_genesis_root = policy.network_genesis_root,
        .expected_zc23_policy_root = input->policy_candidate_root,
        .expected_previous_epoch_creation_root =
            input->previous_epoch_creation_root,
        .observed_actual_mint_atoms = epoch->actual_mint_atoms,
        .active_height = epoch->maturity_height,
        .active_mtp = epoch->maturity_mtp,
        .now_unix = input->now_unix,
        .anchor_is_active = shadow_fixture_anchor,
        .contribution_is_duplicate = shadow_fixture_duplicate,
        .continuity_is_duplicate = shadow_fixture_continuity_duplicate,
        .callback_opaque = &fixture,
    };
    enum vcs_zcode_epoch_creation_error epoch_error =
        vcs_zcode_shadow_epoch_verify_cas(epoch, &context, &policy);
    vcs_zcode_commons_projection_free(projection);
    if (epoch_error != VCS_ZCODE_EPOCH_CREATION_OK) {
        vcs_zcode_epoch_creation_free(epoch);
        return epoch_error == VCS_ZCODE_EPOCH_CREATION_DUPLICATE
            ? VCS_ZCODE_SHADOW_SIMULATION_DUPLICATE
            : VCS_ZCODE_SHADOW_SIMULATION_EPOCH;
    }
    return VCS_ZCODE_SHADOW_SIMULATION_OK;
}

void vcs_zcode_shadow_epoch_plan_free(
    struct vcs_zcode_shadow_epoch_plan *plan)
{
    if (!plan) return;
    vcs_zcode_epoch_creation_free(&plan->epoch);
    memset(plan, 0, sizeof(*plan));
}
