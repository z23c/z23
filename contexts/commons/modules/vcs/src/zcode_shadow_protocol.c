/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: verify four linked Living Commons protocol shadow epochs. */
#include "vcs/zcode_shadow_simulation.h"

#include "base/bytes.h"
#include "base/checked.h"
#include "base/safe_alloc.h"
#include "codec/cursor.h"
#include "crypto/sha3.h"
#include "vcs/vcs_object.h"
#include "vcs/zcode_shadow_policy.h"

#include <stdlib.h>
#include <string.h>

struct shadow_protocol_callbacks {
    uint64_t opening_height;
    uint8_t opening_hash[32];
    uint64_t maturity_height;
    uint8_t maturity_hash[32];
    uint8_t (*candidate_roots)[32];
    uint8_t (*attribution_roots)[32];
    uint8_t (*continuity_keys)[32];
    uint8_t (*continuity_roots)[32];
    size_t seen_candidates;
    size_t seen_continuity;
    size_t capacity;
};

static bool protocol_equal(const uint8_t a[32], const uint8_t b[32])
{
    return memcmp(a, b, 32) == 0;
}

static bool protocol_load(const char *workspace, const uint8_t root[32],
                          size_t maximum, uint8_t **wire, size_t *wire_len)
{
    *wire = NULL;
    *wire_len = 0;
    return workspace && vcs_object_load_raw_bounded(
        workspace, root, maximum, wire, wire_len) == 0;
}

static enum vcs_zcode_shadow_simulation_error protocol_load_policy(
    const char *workspace, const uint8_t root[32],
    struct vcs_zcode_policy_candidate_v1 *policy)
{
    uint8_t *wire = NULL, observed[32];
    size_t wire_len = 0;
    bool ok = protocol_load(workspace, root,
                            VCS_ZCODE_POLICY_CANDIDATE_WIRE_BYTES,
                            &wire, &wire_len) &&
        vcs_zcode_policy_candidate_parse(wire, wire_len, policy) ==
            VCS_ZCODE_SHADOW_OK &&
        vcs_zcode_policy_candidate_root(policy, observed) ==
            VCS_ZCODE_SHADOW_OK && protocol_equal(observed, root);
    free(wire);
    return ok ? VCS_ZCODE_SHADOW_SIMULATION_OK
              : VCS_ZCODE_SHADOW_SIMULATION_POLICY;
}

static bool protocol_anchor(void *opaque, uint64_t height,
                            const uint8_t hash[32])
{
    const struct shadow_protocol_callbacks *state = opaque;
    return state &&
        ((height == state->opening_height &&
          protocol_equal(hash, state->opening_hash)) ||
         (height == state->maturity_height &&
          protocol_equal(hash, state->maturity_hash)));
}

static bool protocol_duplicate(void *opaque,
                               const uint8_t candidate_root[32],
                               const uint8_t attribution_root[32])
{
    struct shadow_protocol_callbacks *state = opaque;
    if (!state) return true;
    for (size_t i = 0; i < state->seen_candidates; i++) {
        if (!protocol_equal(state->candidate_roots[i], candidate_root))
            continue;
        return !protocol_equal(state->attribution_roots[i],
                               attribution_root);
    }
    if (state->seen_candidates >= state->capacity) return true;
    memcpy(state->candidate_roots[state->seen_candidates], candidate_root, 32);
    memcpy(state->attribution_roots[state->seen_candidates],
           attribution_root, 32);
    state->seen_candidates++;
    return false;
}

static bool protocol_continuity_duplicate(
    void *opaque, const uint8_t event_key[32],
    const uint8_t attribution_root[32])
{
    struct shadow_protocol_callbacks *state = opaque;
    if (!state) return true;
    for (size_t i = 0; i < state->seen_continuity; i++) {
        if (!protocol_equal(state->continuity_keys[i], event_key))
            continue;
        return !protocol_equal(state->continuity_roots[i], attribution_root);
    }
    if (state->seen_continuity >= state->capacity) return true;
    memcpy(state->continuity_keys[state->seen_continuity], event_key, 32);
    memcpy(state->continuity_roots[state->seen_continuity],
           attribution_root, 32);
    state->seen_continuity++;
    return false;
}

static bool protocol_report_root(
    const struct vcs_zcode_shadow_protocol_input *input,
    const struct vcs_zcode_shadow_protocol_report *report, uint8_t out[32])
{
    static const char domain[] = VCS_ZCODE_SHADOW_PROTOCOL_REPORT_DOMAIN;
    struct sha3_256_ctx sha;
    sha3_256_init(&sha);
    sha3_256_write(&sha, (const uint8_t *)domain, sizeof(domain));
    sha3_256_write(&sha, input->policy_candidate_root, 32);
    for (size_t i = 0; i < VCS_ZCODE_SHADOW_PROTOCOL_EPOCHS; i++) {
        const struct vcs_zcode_shadow_protocol_epoch_report *row =
            &report->epochs[i];
        uint8_t numbers[67];
        struct zcl_codec_writer writer;
        size_t written = 0;
        zcl_codec_writer_init(&writer, numbers, sizeof(numbers));
        if (!zcl_codec_write_u64le(&writer, row->epoch) ||
            !zcl_codec_write_u64le(&writer, row->creations) ||
            !zcl_codec_write_u64le(&writer, row->cap_atoms) ||
            !zcl_codec_write_u64le(&writer, row->simulated_issue_atoms) ||
            !zcl_codec_write_u64le(&writer, row->attributed_atoms) ||
            !zcl_codec_write_u64le(&writer, row->unissued_atoms) ||
            !zcl_codec_write_u64le(&writer, row->cumulative_issue_atoms) ||
            !zcl_codec_write_u64le(
                &writer, row->cumulative_attributed_atoms) ||
            !zcl_codec_write_u8(&writer,
                                row->active_anchor_status ? 1u : 0u) ||
            !zcl_codec_write_u8(&writer,
                                row->cumulative_equality ? 1u : 0u) ||
            !zcl_codec_write_u8(
                &writer, (uint8_t)row->reproduction_grade) ||
            !zcl_codec_writer_finish(&writer, &written) ||
            written != sizeof(numbers))
            return false;
        sha3_256_write(&sha, row->epoch_root, 32);
        sha3_256_write(&sha, row->predecessor_root, 32);
        sha3_256_write(&sha, row->fixture_branch_root, 32);
        sha3_256_write(&sha, numbers, sizeof(numbers));
    }
    sha3_256_finalize(&sha, out);
    return true;
}

enum vcs_zcode_shadow_simulation_error
vcs_zcode_shadow_protocol_verify_cas(
    const struct vcs_zcode_shadow_protocol_input *input,
    struct vcs_zcode_shadow_protocol_report *out)
{
    if (out) memset(out, 0, sizeof(*out));
    if (!input || !out || !input->workspace ||
        !input->policy_candidate_root || !input->epoch_roots ||
        !input->fixture_branch_roots || input->now_unix <= 0)
        return VCS_ZCODE_SHADOW_SIMULATION_NULL;

    struct vcs_zcode_policy_candidate_v1 policy;
    enum vcs_zcode_shadow_simulation_error error = protocol_load_policy(
        input->workspace, input->policy_candidate_root, &policy);
    if (error != VCS_ZCODE_SHADOW_SIMULATION_OK) return error;

    struct vcs_zcode_epoch_creation_set_v1
        sets[VCS_ZCODE_SHADOW_PROTOCOL_EPOCHS];
    memset(sets, 0, sizeof(sets));
    size_t capacity = 64u;
    for (size_t i = 0; i < VCS_ZCODE_SHADOW_PROTOCOL_EPOCHS; i++) {
        uint8_t *wire = NULL, observed[32];
        size_t wire_len = 0;
        if (zcl_bytes_all_zero(input->epoch_roots[i], 32) ||
            zcl_bytes_all_zero(input->fixture_branch_roots[i], 32) ||
            !protocol_load(input->workspace, input->epoch_roots[i],
                           VCS_ZCODE_EPOCH_CREATION_MAX_WIRE_BYTES,
                           &wire, &wire_len) ||
            vcs_zcode_epoch_creation_parse(wire, wire_len, &sets[i]) !=
                VCS_ZCODE_EPOCH_CREATION_OK ||
            vcs_zcode_epoch_creation_root(&sets[i], observed) !=
                VCS_ZCODE_EPOCH_CREATION_OK ||
            !protocol_equal(observed, input->epoch_roots[i]) ||
            sets[i].epoch != i ||
            !protocol_equal(sets[i].zc23_policy_root,
                            input->policy_candidate_root) ||
            !protocol_equal(sets[i].network_genesis_root,
                            policy.network_genesis_root) ||
            sets[i].attribution_count > SIZE_MAX - capacity) {
            free(wire);
            error = VCS_ZCODE_SHADOW_SIMULATION_EPOCH;
            goto done;
        }
        free(wire);
        capacity += sets[i].attribution_count;
    }

    struct shadow_protocol_callbacks state;
    memset(&state, 0, sizeof(state));
    state.capacity = capacity;
    state.candidate_roots = zcl_calloc(capacity, 32,
                                        "shadow_protocol_candidates");
    state.attribution_roots = zcl_calloc(capacity, 32,
                                          "shadow_protocol_attributions");
    state.continuity_keys = zcl_calloc(capacity, 32,
                                       "shadow_protocol_continuity_keys");
    state.continuity_roots = zcl_calloc(capacity, 32,
                                        "shadow_protocol_continuity_roots");
    if (!state.candidate_roots || !state.attribution_roots ||
        !state.continuity_keys || !state.continuity_roots) {
        error = VCS_ZCODE_SHADOW_SIMULATION_CAS;
        free(state.candidate_roots); free(state.attribution_roots);
        free(state.continuity_keys); free(state.continuity_roots);
        goto done;
    }

    uint8_t zero[32] = {0};
    for (size_t i = 0; i < VCS_ZCODE_SHADOW_PROTOCOL_EPOCHS; i++) {
        struct vcs_zcode_epoch_creation_set_v1 *set = &sets[i];
        const uint8_t *expected_previous = i == 0
            ? zero : input->epoch_roots[i - 1];
        uint8_t expected_opening[32], expected_maturity[32];
        if (!protocol_equal(set->previous_epoch_creation_root,
                            expected_previous)) {
            error = VCS_ZCODE_SHADOW_SIMULATION_PREDECESSOR;
            break;
        }
        if (!protocol_equal(set->committee_evidence_snapshot_root,
                            input->fixture_branch_roots[i]) ||
            !vcs_zcode_shadow_fixture_anchor_root(
                input->policy_candidate_root,
                input->fixture_branch_roots[i], set->epoch, 1,
                expected_opening) ||
            !vcs_zcode_shadow_fixture_anchor_root(
                input->policy_candidate_root,
                input->fixture_branch_roots[i], set->epoch, 2,
                expected_maturity) ||
            !protocol_equal(set->opening_hash, expected_opening) ||
            !protocol_equal(set->maturity_hash, expected_maturity)) {
            error = VCS_ZCODE_SHADOW_SIMULATION_ANCHOR;
            break;
        }
        state.opening_height = set->opening_height;
        state.maturity_height = set->maturity_height;
        memcpy(state.opening_hash, set->opening_hash, 32);
        memcpy(state.maturity_hash, set->maturity_hash, 32);
        struct vcs_zcode_epoch_creation_validation_context context = {
            .workspace = input->workspace,
            .expected_network_genesis_root = policy.network_genesis_root,
            .expected_zc23_policy_root = input->policy_candidate_root,
            .expected_previous_epoch_creation_root = expected_previous,
            .observed_actual_mint_atoms = set->actual_mint_atoms,
            .active_height = set->maturity_height,
            .active_mtp = set->maturity_mtp,
            .now_unix = input->now_unix,
            .anchor_is_active = protocol_anchor,
            .contribution_is_duplicate = protocol_duplicate,
            .continuity_is_duplicate = protocol_continuity_duplicate,
            .callback_opaque = &state,
        };
        enum vcs_zcode_epoch_creation_error epoch_error =
            vcs_zcode_shadow_epoch_verify_cas(set, &context, &policy);
        if (epoch_error != VCS_ZCODE_EPOCH_CREATION_OK) {
            error = epoch_error == VCS_ZCODE_EPOCH_CREATION_DUPLICATE
                ? VCS_ZCODE_SHADOW_SIMULATION_DUPLICATE
                : epoch_error == VCS_ZCODE_EPOCH_CREATION_REORG
                    ? VCS_ZCODE_SHADOW_SIMULATION_ANCHOR
                    : epoch_error == VCS_ZCODE_EPOCH_CREATION_PREDECESSOR
                        ? VCS_ZCODE_SHADOW_SIMULATION_PREDECESSOR
                        : VCS_ZCODE_SHADOW_SIMULATION_EPOCH;
            break;
        }
        struct vcs_zcode_shadow_protocol_epoch_report *row = &out->epochs[i];
        memcpy(row->epoch_root, input->epoch_roots[i], 32);
        memcpy(row->predecessor_root, expected_previous, 32);
        memcpy(row->fixture_branch_root,
               input->fixture_branch_roots[i], 32);
        row->epoch = set->epoch;
        row->creations = set->attribution_count;
        row->cap_atoms = set->emission_cap_atoms;
        row->simulated_issue_atoms = set->actual_mint_atoms;
        row->attributed_atoms = set->actual_mint_atoms;
        row->unissued_atoms = set->unissued_atoms;
        row->active_anchor_status = true;
        row->reproduction_grade =
            VCS_ZCODE_SHADOW_REPRODUCTION_SAME_HOST_FIXTURE;
        if (!zcl_u64_add(out->cumulative_issue_atoms,
                         row->simulated_issue_atoms,
                         &out->cumulative_issue_atoms) ||
            !zcl_u64_add(out->cumulative_attributed_atoms,
                         row->attributed_atoms,
                         &out->cumulative_attributed_atoms) ||
            !zcl_u64_add(out->cumulative_unissued_atoms,
                         row->unissued_atoms,
                         &out->cumulative_unissued_atoms)) {
            error = VCS_ZCODE_SHADOW_SIMULATION_OVERFLOW;
            break;
        }
        row->cumulative_issue_atoms = out->cumulative_issue_atoms;
        row->cumulative_attributed_atoms =
            out->cumulative_attributed_atoms;
        row->cumulative_equality =
            row->cumulative_issue_atoms ==
            row->cumulative_attributed_atoms;
        if (!row->cumulative_equality) {
            error = VCS_ZCODE_SHADOW_SIMULATION_EPOCH;
            break;
        }
        out->epoch_count++;
    }
    free(state.candidate_roots); free(state.attribution_roots);
    free(state.continuity_keys); free(state.continuity_roots);
    if (error == VCS_ZCODE_SHADOW_SIMULATION_OK) {
        out->cumulative_equality =
            out->cumulative_issue_atoms ==
            out->cumulative_attributed_atoms;
        out->real_genesis_gate_satisfied = false;
        if (!out->cumulative_equality ||
            !protocol_report_root(input, out, out->active_projection_root))
            error = VCS_ZCODE_SHADOW_SIMULATION_EPOCH;
    }

done:
    for (size_t i = 0; i < VCS_ZCODE_SHADOW_PROTOCOL_EPOCHS; i++)
        vcs_zcode_epoch_creation_free(&sets[i]);
    if (error != VCS_ZCODE_SHADOW_SIMULATION_OK)
        memset(out, 0, sizeof(*out));
    return error;
}
