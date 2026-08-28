/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: deterministic simulation-only Living Commons economics. */

#include "vcs/zcode_commons.h"

#include "base/checked.h"
#include "base/safe_alloc.h"
#include "base/serialize_le.h"
#include "crypto/sha3.h"

#include <stdlib.h>
#include <string.h>

static const uint64_t award_schedule[VCS_ZCODE_COMMONS_CATEGORY_COUNT] = {
    UINT64_C(100000000), UINT64_C(50000000), UINT64_C(50000000),
    UINT64_C(25000000), UINT64_C(25000000), UINT64_C(25000000),
    UINT64_C(25000000), UINT64_C(12500000),
};

static bool cv2_nonzero(const uint8_t root[32])
{
    uint8_t any = 0;
    if (!root) return false;
    for (size_t i = 0; i < 32; i++) any |= root[i];
    return any != 0;
}

static void cv2_hash_u16(struct sha3_256_ctx *sha, uint16_t value)
{
    uint8_t le[2];
    zcl_write_u16_le(le, value);
    sha3_256_write(sha, le, sizeof(le));
}

static void cv2_hash_u64(struct sha3_256_ctx *sha, uint64_t value)
{
    uint8_t le[8];
    zcl_write_u64_le(le, value);
    sha3_256_write(sha, le, sizeof(le));
}

const char *vcs_zcode_commons_error_string(
    enum vcs_zcode_commons_error error)
{
    switch (error) {
    case VCS_ZCODE_COMMONS_OK: return "ok";
    case VCS_ZCODE_COMMONS_NULL: return "null-argument";
    case VCS_ZCODE_COMMONS_VERSION_ERROR: return "schema-version";
    case VCS_ZCODE_COMMONS_FLAGS: return "flags";
    case VCS_ZCODE_COMMONS_ROOT: return "root";
    case VCS_ZCODE_COMMONS_ENUM: return "closed-enum";
    case VCS_ZCODE_COMMONS_AMOUNT: return "amount";
    case VCS_ZCODE_COMMONS_LIMIT: return "limit";
    case VCS_ZCODE_COMMONS_ORDER: return "canonical-order";
    case VCS_ZCODE_COMMONS_DUPLICATE: return "duplicate";
    case VCS_ZCODE_COMMONS_IMMATURE: return "dual-maturity";
    case VCS_ZCODE_COMMONS_POLICY: return "policy";
    case VCS_ZCODE_COMMONS_COVERAGE: return "coverage";
    case VCS_ZCODE_COMMONS_QUORUM: return "quorum";
    case VCS_ZCODE_COMMONS_OVERFLOW: return "arithmetic-overflow";
    case VCS_ZCODE_COMMONS_SIZE: return "wire-size";
    case VCS_ZCODE_COMMONS_MAGIC: return "wire-magic";
    case VCS_ZCODE_COMMONS_SIGNATURE: return "signature";
    }
    return "unknown-commons-v2-error";
}

uint64_t vcs_zcode_creation_award_atoms_v2(uint16_t category)
{
    return category < VCS_ZCODE_COMMONS_CATEGORY_COUNT
        ? award_schedule[category] : 0;
}

void vcs_zcode_policy_candidate_v2_init(
    struct vcs_zcode_policy_candidate_v2 *policy,
    const uint8_t network_genesis_root[32],
    const uint8_t moderation_policy_root[32],
    const uint8_t qualification_predicates_root[32],
    const uint8_t backlog_algorithm_root[32])
{
    if (!policy) return;
    memset(policy, 0, sizeof(*policy));
    policy->schema_version = VCS_ZCODE_CREATION_CLAIM_V2_VERSION;
    policy->flags = VCS_ZCODE_COMMONS_REQUIRED_FLAGS;
    policy->challenge_blocks = VCS_ZCODE_COMMONS_CHALLENGE_BLOCKS;
    policy->challenge_seconds = VCS_ZCODE_COMMONS_CHALLENGE_SECONDS;
    if (network_genesis_root)
        memcpy(policy->network_genesis_root, network_genesis_root, 32);
    if (moderation_policy_root)
        memcpy(policy->moderation_policy_root, moderation_policy_root, 32);
    if (qualification_predicates_root)
        memcpy(policy->qualification_predicates_root,
               qualification_predicates_root, 32);
    if (backlog_algorithm_root)
        memcpy(policy->backlog_algorithm_root, backlog_algorithm_root, 32);
    memcpy(policy->award_atoms, award_schedule, sizeof(award_schedule));
}

enum vcs_zcode_commons_error vcs_zcode_policy_candidate_v2_validate(
    const struct vcs_zcode_policy_candidate_v2 *policy)
{
    if (!policy) return VCS_ZCODE_COMMONS_NULL;
    if (policy->schema_version != VCS_ZCODE_CREATION_CLAIM_V2_VERSION)
        return VCS_ZCODE_COMMONS_VERSION_ERROR;
    if (policy->flags != VCS_ZCODE_COMMONS_REQUIRED_FLAGS)
        return VCS_ZCODE_COMMONS_FLAGS;
    if (policy->challenge_blocks != VCS_ZCODE_COMMONS_CHALLENGE_BLOCKS ||
        policy->challenge_seconds != VCS_ZCODE_COMMONS_CHALLENGE_SECONDS)
        return VCS_ZCODE_COMMONS_POLICY;
    if (!cv2_nonzero(policy->network_genesis_root) ||
        !cv2_nonzero(policy->moderation_policy_root) ||
        !cv2_nonzero(policy->qualification_predicates_root) ||
        !cv2_nonzero(policy->backlog_algorithm_root))
        return VCS_ZCODE_COMMONS_ROOT;
    for (size_t i = 0; i < VCS_ZCODE_COMMONS_CATEGORY_COUNT; i++)
        if (policy->award_atoms[i] != award_schedule[i])
            return VCS_ZCODE_COMMONS_AMOUNT;
    return VCS_ZCODE_COMMONS_OK;
}

enum vcs_zcode_commons_error vcs_zcode_policy_candidate_v2_root(
    const struct vcs_zcode_policy_candidate_v2 *policy, uint8_t out[32])
{
    if (out) memset(out, 0, 32);
    if (!policy || !out) return VCS_ZCODE_COMMONS_NULL;
    enum vcs_zcode_commons_error error =
        vcs_zcode_policy_candidate_v2_validate(policy);
    if (error != VCS_ZCODE_COMMONS_OK) return error;
    struct sha3_256_ctx sha;
    static const char domain[] = VCS_ZCODE_POLICY_CANDIDATE_V2_DOMAIN;
    sha3_256_init(&sha);
    sha3_256_write(&sha, (const uint8_t *)domain, sizeof(domain));
    cv2_hash_u16(&sha, policy->schema_version);
    cv2_hash_u16(&sha, policy->flags);
    cv2_hash_u64(&sha, policy->challenge_blocks);
    cv2_hash_u64(&sha, (uint64_t)policy->challenge_seconds);
    sha3_256_write(&sha, policy->network_genesis_root, 32);
    sha3_256_write(&sha, policy->moderation_policy_root, 32);
    sha3_256_write(&sha, policy->qualification_predicates_root, 32);
    sha3_256_write(&sha, policy->backlog_algorithm_root, 32);
    for (size_t i = 0; i < VCS_ZCODE_COMMONS_CATEGORY_COUNT; i++)
        cv2_hash_u64(&sha, policy->award_atoms[i]);
    sha3_256_finalize(&sha, out);
    return VCS_ZCODE_COMMONS_OK;
}

static enum vcs_zcode_commons_error claim_shape(
    const struct vcs_zcode_creation_claim_v2 *claim)
{
    if (!claim) return VCS_ZCODE_COMMONS_NULL;
    if (claim->schema_version != VCS_ZCODE_CREATION_CLAIM_V2_VERSION)
        return VCS_ZCODE_COMMONS_VERSION_ERROR;
    if (claim->reserved != 0 ||
        claim->category >= VCS_ZCODE_COMMONS_CATEGORY_COUNT)
        return VCS_ZCODE_COMMONS_ENUM;
    if (!cv2_nonzero(claim->claim_root) ||
        !cv2_nonzero(claim->recipient_binding_root) ||
        !cv2_nonzero(claim->workspace_lineage_root) ||
        !cv2_nonzero(claim->semantic_lineage_root) ||
        !cv2_nonzero(claim->evidence_root) ||
        !cv2_nonzero(claim->commons_admission_root))
        return VCS_ZCODE_COMMONS_ROOT;
    if (claim->maturity_height == 0 || claim->maturity_mtp <= 0)
        return VCS_ZCODE_COMMONS_IMMATURE;
    return VCS_ZCODE_COMMONS_OK;
}

enum vcs_zcode_commons_error vcs_zcode_creation_claim_v2_validate(
    const struct vcs_zcode_creation_claim_v2 *claim,
    const struct vcs_zcode_policy_candidate_v2 *policy)
{
    enum vcs_zcode_commons_error error = claim_shape(claim);
    if (error != VCS_ZCODE_COMMONS_OK) return error;
    error = vcs_zcode_policy_candidate_v2_validate(policy);
    if (error != VCS_ZCODE_COMMONS_OK) return error;
    if ((claim->flags & VCS_ZCODE_CLAIM_V2_REQUIRED_FLAGS) !=
            VCS_ZCODE_CLAIM_V2_REQUIRED_FLAGS ||
        (claim->flags & VCS_ZCODE_CLAIM_V2_INVALIDATING_FLAGS) != 0)
        return VCS_ZCODE_COMMONS_FLAGS;
    return policy->award_atoms[claim->category] != 0
        ? VCS_ZCODE_COMMONS_OK : VCS_ZCODE_COMMONS_AMOUNT;
}

struct cv2_ranked_claim {
    size_t input_index;
    const struct vcs_zcode_creation_claim_v2 *claim;
};

static int ranked_claim_compare(const void *left_ptr, const void *right_ptr)
{
    const struct cv2_ranked_claim *left = left_ptr;
    const struct cv2_ranked_claim *right = right_ptr;
    if (left->claim->category != right->claim->category)
        return left->claim->category < right->claim->category ? -1 : 1;
    if (left->claim->maturity_height != right->claim->maturity_height)
        return left->claim->maturity_height < right->claim->maturity_height
            ? -1 : 1;
    if (left->claim->maturity_mtp != right->claim->maturity_mtp)
        return left->claim->maturity_mtp < right->claim->maturity_mtp
            ? -1 : 1;
    return memcmp(left->claim->claim_root, right->claim->claim_root, 32);
}

static bool prior_root_selected(
    const struct vcs_zcode_epoch_selection_v2 *input,
    const struct vcs_zcode_epoch_selection_result_v2 *out,
    size_t selected_count, const uint8_t root[32], bool semantic)
{
    for (size_t i = 0; i < selected_count; i++) {
        const struct vcs_zcode_creation_claim_v2 *prior =
            &input->claims[out->selected_indices[i]];
        const uint8_t *prior_root = semantic ? prior->semantic_lineage_root
                                              : prior->claim_root;
        if (memcmp(prior_root, root, 32) == 0) return true;
    }
    return false;
}

static uint64_t selected_for_root(
    const struct vcs_zcode_epoch_selection_v2 *input,
    const struct vcs_zcode_epoch_selection_result_v2 *out,
    size_t selected_count, const uint8_t root[32], bool lineage,
    const struct vcs_zcode_policy_candidate_v2 *policy)
{
    uint64_t total = 0;
    for (size_t i = 0; i < selected_count; i++) {
        const struct vcs_zcode_creation_claim_v2 *prior =
            &input->claims[out->selected_indices[i]];
        const uint8_t *candidate = lineage ? prior->workspace_lineage_root
                                           : prior->recipient_binding_root;
        if (memcmp(candidate, root, 32) == 0)
            (void)zcl_u64_add(total, policy->award_atoms[prior->category],
                              &total);
    }
    return total;
}

static void epoch_result_root(
    const struct vcs_zcode_epoch_selection_v2 *input,
    const struct vcs_zcode_epoch_selection_result_v2 *result,
    uint8_t out[32])
{
    struct sha3_256_ctx sha;
    static const char domain[] = VCS_ZCODE_EPOCH_CREATION_SET_V2_DOMAIN;
    sha3_256_init(&sha);
    sha3_256_write(&sha, (const uint8_t *)domain, sizeof(domain));
    cv2_hash_u16(&sha, VCS_ZCODE_CREATION_CLAIM_V2_VERSION);
    cv2_hash_u16(&sha, VCS_ZCODE_COMMONS_REQUIRED_FLAGS);
    cv2_hash_u64(&sha, input->epoch);
    cv2_hash_u64(&sha, input->cutoff_height);
    cv2_hash_u64(&sha, (uint64_t)input->cutoff_mtp);
    cv2_hash_u64(&sha, input->epoch_capacity_atoms);
    sha3_256_write(&sha, input->previous_epoch_root, 32);
    cv2_hash_u64(&sha, result->selected_atoms);
    cv2_hash_u64(&sha, result->expired_capacity_atoms);
    cv2_hash_u64(&sha, result->selected_count);
    for (size_t i = 0; i < result->selected_count; i++)
        sha3_256_write(&sha,
            input->claims[result->selected_indices[i]].claim_root, 32);
    sha3_256_finalize(&sha, out);
}

enum vcs_zcode_commons_error vcs_zcode_epoch_select_v2(
    const struct vcs_zcode_epoch_selection_v2 *input,
    const struct vcs_zcode_policy_candidate_v2 *policy,
    struct vcs_zcode_epoch_selection_result_v2 *out)
{
    if (out) memset(out, 0, sizeof(*out));
    if (!input || !policy || !out ||
        (input->claim_count > 0 && !input->claims))
        return VCS_ZCODE_COMMONS_NULL;
    enum vcs_zcode_commons_error error =
        vcs_zcode_policy_candidate_v2_validate(policy);
    if (error != VCS_ZCODE_COMMONS_OK) return error;
    if (input->claim_count > VCS_ZCODE_COMMONS_MAX_CLAIMS)
        return VCS_ZCODE_COMMONS_LIMIT;
    if (input->cutoff_height == 0 || input->cutoff_mtp <= 0)
        return VCS_ZCODE_COMMONS_IMMATURE;

    uint64_t one_percent = input->epoch_capacity_atoms / UINT64_C(100);
    uint64_t per_root_cap = one_percent > VCS_ZCODE_COMMONS_ATOMS_PER_TOKEN
        ? one_percent : VCS_ZCODE_COMMONS_ATOMS_PER_TOKEN;
    if (per_root_cap > input->epoch_capacity_atoms)
        per_root_cap = input->epoch_capacity_atoms;
    out->recipient_cap_atoms = per_root_cap;
    out->lineage_cap_atoms = per_root_cap;
    out->first_category = cv2_nonzero(input->previous_epoch_root)
        ? (uint8_t)((input->previous_epoch_root[0] + 1u) %
                    VCS_ZCODE_COMMONS_CATEGORY_COUNT)
        : 0;

    if (input->claim_count == 0 || input->epoch_capacity_atoms == 0) {
        out->expired_capacity_atoms = input->epoch_capacity_atoms;
        epoch_result_root(input, out, out->epoch_creation_root);
        return VCS_ZCODE_COMMONS_OK;
    }

    struct cv2_ranked_claim *ranked = zcl_malloc(
        input->claim_count * sizeof(*ranked), "commons_ranked_claims");
    bool *consumed = zcl_calloc(input->claim_count, sizeof(*consumed),
                                "commons_consumed_claims");
    if (!ranked || !consumed) {
        free(ranked); free(consumed);
        return VCS_ZCODE_COMMONS_LIMIT;
    }
    for (size_t i = 0; i < input->claim_count; i++) {
        ranked[i].input_index = i;
        ranked[i].claim = &input->claims[i];
    }
    qsort(ranked, input->claim_count, sizeof(*ranked), ranked_claim_compare);

    size_t remaining = input->claim_count;
    while (remaining > 0) {
        bool visited = false;
        for (size_t turn = 0; turn < VCS_ZCODE_COMMONS_CATEGORY_COUNT;
             turn++) {
            uint16_t category = (uint16_t)((out->first_category + turn) %
                VCS_ZCODE_COMMONS_CATEGORY_COUNT);
            size_t at = input->claim_count;
            for (size_t i = 0; i < input->claim_count; i++) {
                if (!consumed[i] && ranked[i].claim->category == category) {
                    at = i;
                    break;
                }
            }
            if (at == input->claim_count) continue;
            visited = true; consumed[at] = true; remaining--;
            const struct vcs_zcode_creation_claim_v2 *claim =
                ranked[at].claim;
            error = claim_shape(claim);
            bool eligible = error == VCS_ZCODE_COMMONS_OK &&
                (claim->flags & VCS_ZCODE_CLAIM_V2_REQUIRED_FLAGS) ==
                    VCS_ZCODE_CLAIM_V2_REQUIRED_FLAGS &&
                (claim->flags & VCS_ZCODE_CLAIM_V2_INVALIDATING_FLAGS) == 0 &&
                claim->maturity_height <= input->cutoff_height &&
                claim->maturity_mtp <= input->cutoff_mtp;
            if (!eligible || prior_root_selected(
                    input, out, out->selected_count, claim->claim_root, false) ||
                prior_root_selected(input, out, out->selected_count,
                                    claim->semantic_lineage_root, true)) {
                out->invalid_count++;
                continue;
            }
            uint64_t award = policy->award_atoms[category];
            uint64_t recipient_used = selected_for_root(
                input, out, out->selected_count,
                claim->recipient_binding_root, false, policy);
            uint64_t lineage_used = selected_for_root(
                input, out, out->selected_count,
                claim->workspace_lineage_root, true, policy);
            uint64_t next_total = 0, next_recipient = 0, next_lineage = 0;
            if (!zcl_u64_add(out->selected_atoms, award, &next_total) ||
                !zcl_u64_add(recipient_used, award, &next_recipient) ||
                !zcl_u64_add(lineage_used, award, &next_lineage)) {
                free(consumed); free(ranked);
                memset(out, 0, sizeof(*out));
                return VCS_ZCODE_COMMONS_OVERFLOW;
            }
            if (next_total > input->epoch_capacity_atoms ||
                next_recipient > out->recipient_cap_atoms ||
                next_lineage > out->lineage_cap_atoms) {
                out->deferred_count++;
                continue;
            }
            out->selected_indices[out->selected_count++] =
                ranked[at].input_index;
            out->selected_atoms = next_total;
        }
        if (!visited) break;
    }
    free(consumed); free(ranked);
    out->expired_capacity_atoms =
        input->epoch_capacity_atoms - out->selected_atoms;
    epoch_result_root(input, out, out->epoch_creation_root);
    return VCS_ZCODE_COMMONS_OK;
}
