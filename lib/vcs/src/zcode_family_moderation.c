/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: immutable family-c23.v1 policy and deterministic moderation mesh. */

#include "vcs/zcode_commons.h"

#include "base/serialize_le.h"
#include "crypto/sha3.h"

#include <stdlib.h>
#include <string.h>

static bool family_nonzero(const uint8_t root[32])
{
    uint8_t any = 0;
    if (!root) return false;
    for (size_t i = 0; i < 32; i++) any |= root[i];
    return any != 0;
}

static void family_hash_u16(struct sha3_256_ctx *sha, uint16_t value)
{
    uint8_t le[2];
    zcl_write_u16_le(le, value);
    sha3_256_write(sha, le, sizeof(le));
}

static void family_hash_u32(struct sha3_256_ctx *sha, uint32_t value)
{
    uint8_t le[4];
    zcl_write_u32_le(le, value);
    sha3_256_write(sha, le, sizeof(le));
}

static void family_hash_u64(struct sha3_256_ctx *sha, uint64_t value)
{
    uint8_t le[8];
    zcl_write_u64_le(le, value);
    sha3_256_write(sha, le, sizeof(le));
}

void vcs_zcode_family_policy_v1_init(
    struct vcs_zcode_family_policy_v1 *policy,
    const uint8_t profile_name_root[32],
    const uint8_t policy_text_root[32])
{
    if (!policy) return;
    memset(policy, 0, sizeof(*policy));
    policy->schema_version = 1;
    policy->flags = VCS_ZCODE_COMMONS_REQUIRED_FLAGS;
    policy->excluded_reason_mask = VCS_ZCODE_FAMILY_EXCLUSION_MASK;
    policy->max_metadata_items = 4096;
    policy->max_dependency_objects = 4096;
    policy->max_extracted_bytes = UINT64_C(64) * 1024u * 1024u;
    if (profile_name_root)
        memcpy(policy->profile_name_root, profile_name_root, 32);
    if (policy_text_root)
        memcpy(policy->policy_text_root, policy_text_root, 32);
}

static void family_literal_root(const char *domain, const char *literal,
                                uint8_t out[32])
{
    struct sha3_256_ctx sha;
    sha3_256_init(&sha);
    sha3_256_write(&sha, (const uint8_t *)domain, strlen(domain) + 1u);
    sha3_256_write(&sha, (const uint8_t *)literal, strlen(literal) + 1u);
    sha3_256_finalize(&sha, out);
}

void vcs_zcode_family_policy_v1_default(
    struct vcs_zcode_family_policy_v1 *policy)
{
    static const char profile[] = "family-c23.v1";
    static const char policy_text[] =
        "exclude:explicit-sexual,graphic-gore,targeted-hate,self-harm,"
        "harmful-illegal,strong-profanity,primary-abuse-software;"
        "allow-context:scientific,medical,historical,cybersecurity,dual-use;"
        "axes:GENERAL|CONTEXTUAL_SCIENCE|MATURE|EXPLICIT|UNKNOWN,"
        "BENIGN|DUAL_USE|MALICIOUS|UNKNOWN;"
        "unknown:unsupported,encrypted,opaque,missing,truncated,mutable,"
        "over-budget,partial";
    uint8_t profile_root[32], text_root[32];
    family_literal_root("zcl.zcode.family_profile_name.v1", profile,
                        profile_root);
    family_literal_root("zcl.zcode.family_policy_text.v1", policy_text,
                        text_root);
    vcs_zcode_family_policy_v1_init(policy, profile_root, text_root);
}

enum vcs_zcode_commons_error vcs_zcode_family_policy_v1_validate(
    const struct vcs_zcode_family_policy_v1 *policy)
{
    if (!policy) return VCS_ZCODE_COMMONS_NULL;
    if (policy->schema_version != 1)
        return VCS_ZCODE_COMMONS_VERSION_ERROR;
    if (policy->flags != VCS_ZCODE_COMMONS_REQUIRED_FLAGS)
        return VCS_ZCODE_COMMONS_FLAGS;
    if (policy->excluded_reason_mask != VCS_ZCODE_FAMILY_EXCLUSION_MASK)
        return VCS_ZCODE_COMMONS_POLICY;
    if (policy->max_metadata_items != 4096 ||
        policy->max_dependency_objects != 4096 ||
        policy->max_extracted_bytes != UINT64_C(64) * 1024u * 1024u)
        return VCS_ZCODE_COMMONS_LIMIT;
    if (!family_nonzero(policy->profile_name_root) ||
        !family_nonzero(policy->policy_text_root))
        return VCS_ZCODE_COMMONS_ROOT;
    return VCS_ZCODE_COMMONS_OK;
}

enum vcs_zcode_commons_error vcs_zcode_family_policy_v1_root(
    const struct vcs_zcode_family_policy_v1 *policy, uint8_t out[32])
{
    if (out) memset(out, 0, 32);
    if (!policy || !out) return VCS_ZCODE_COMMONS_NULL;
    enum vcs_zcode_commons_error error =
        vcs_zcode_family_policy_v1_validate(policy);
    if (error != VCS_ZCODE_COMMONS_OK) return error;
    struct sha3_256_ctx sha;
    static const char domain[] = VCS_ZCODE_FAMILY_POLICY_V1_DOMAIN;
    sha3_256_init(&sha);
    sha3_256_write(&sha, (const uint8_t *)domain, sizeof(domain));
    family_hash_u16(&sha, policy->schema_version);
    family_hash_u16(&sha, policy->flags);
    family_hash_u32(&sha, policy->excluded_reason_mask);
    family_hash_u32(&sha, policy->max_metadata_items);
    family_hash_u32(&sha, policy->max_dependency_objects);
    family_hash_u64(&sha, policy->max_extracted_bytes);
    sha3_256_write(&sha, policy->profile_name_root, 32);
    sha3_256_write(&sha, policy->policy_text_root, 32);
    sha3_256_finalize(&sha, out);
    return VCS_ZCODE_COMMONS_OK;
}

enum vcs_zcode_moderation_vote_v1 vcs_zcode_moderation_coverage_vote_v1(
    const struct vcs_zcode_moderation_coverage_v1 *coverage,
    enum vcs_zcode_moderation_audience_v1 audience,
    enum vcs_zcode_moderation_behavior_v1 behavior)
{
    if (!coverage ||
        coverage->required_mask != VCS_ZCODE_COVERAGE_REQUIRED_MASK ||
        coverage->completed_mask != coverage->required_mask ||
        coverage->failure_mask != 0 || coverage->object_count == 0 ||
        coverage->inspected_count != coverage->object_count ||
        coverage->declared_bytes == 0 ||
        coverage->inspected_bytes != coverage->declared_bytes)
        return VCS_ZCODE_MODERATION_VOTE_UNKNOWN;
    if (audience > VCS_ZCODE_AUDIENCE_UNKNOWN ||
        behavior > VCS_ZCODE_BEHAVIOR_UNKNOWN ||
        audience == VCS_ZCODE_AUDIENCE_UNKNOWN ||
        behavior == VCS_ZCODE_BEHAVIOR_UNKNOWN)
        return VCS_ZCODE_MODERATION_VOTE_UNKNOWN;
    if ((audience == VCS_ZCODE_AUDIENCE_GENERAL ||
         audience == VCS_ZCODE_AUDIENCE_CONTEXTUAL_SCIENCE) &&
        (behavior == VCS_ZCODE_BEHAVIOR_BENIGN ||
         behavior == VCS_ZCODE_BEHAVIOR_DUAL_USE))
        return VCS_ZCODE_MODERATION_VOTE_PASS;
    return VCS_ZCODE_MODERATION_VOTE_BLOCK;
}

enum vcs_zcode_commons_error vcs_zcode_classification_receipt_v1_validate(
    const struct vcs_zcode_classification_receipt_v1 *receipt)
{
    if (!receipt) return VCS_ZCODE_COMMONS_NULL;
    if (receipt->schema_version != 1)
        return VCS_ZCODE_COMMONS_VERSION_ERROR;
    if (receipt->flags != VCS_ZCODE_COMMONS_REQUIRED_FLAGS)
        return VCS_ZCODE_COMMONS_FLAGS;
    if (!family_nonzero(receipt->request_root) ||
        !family_nonzero(receipt->content_root) ||
        !family_nonzero(receipt->policy_root) ||
        !family_nonzero(receipt->classifier_manifest_root) ||
        !family_nonzero(receipt->operator_group_root) ||
        !family_nonzero(receipt->model_family_root) ||
        !family_nonzero(receipt->signature))
        return VCS_ZCODE_COMMONS_ROOT;
    if (receipt->audience > VCS_ZCODE_AUDIENCE_UNKNOWN ||
        receipt->behavior > VCS_ZCODE_BEHAVIOR_UNKNOWN)
        return VCS_ZCODE_COMMONS_ENUM;
    if (receipt->completed_height == 0 || receipt->completed_mtp <= 0)
        return VCS_ZCODE_COMMONS_IMMATURE;
    enum vcs_zcode_moderation_vote_v1 vote =
        vcs_zcode_moderation_coverage_vote_v1(
            &receipt->coverage,
            (enum vcs_zcode_moderation_audience_v1)receipt->audience,
            (enum vcs_zcode_moderation_behavior_v1)receipt->behavior);
    if (vote == VCS_ZCODE_MODERATION_VOTE_UNKNOWN &&
        receipt->reason_code_mask == 0)
        return VCS_ZCODE_COMMONS_COVERAGE;
    return VCS_ZCODE_COMMONS_OK;
}

enum vcs_zcode_commons_error vcs_zcode_classification_receipt_v1_root(
    const struct vcs_zcode_classification_receipt_v1 *receipt,
    uint8_t out[32])
{
    if (out) memset(out, 0, 32);
    if (!receipt || !out) return VCS_ZCODE_COMMONS_NULL;
    enum vcs_zcode_commons_error error =
        vcs_zcode_classification_receipt_v1_validate(receipt);
    if (error != VCS_ZCODE_COMMONS_OK) return error;
    struct sha3_256_ctx sha;
    static const char domain[] = VCS_ZCODE_CLASSIFICATION_RECEIPT_V1_DOMAIN;
    sha3_256_init(&sha);
    sha3_256_write(&sha, (const uint8_t *)domain, sizeof(domain));
    family_hash_u16(&sha, receipt->schema_version);
    family_hash_u16(&sha, receipt->flags);
    sha3_256_write(&sha, receipt->request_root, 32);
    sha3_256_write(&sha, receipt->content_root, 32);
    sha3_256_write(&sha, receipt->policy_root, 32);
    sha3_256_write(&sha, receipt->classifier_manifest_root, 32);
    sha3_256_write(&sha, receipt->operator_group_root, 32);
    sha3_256_write(&sha, receipt->model_family_root, 32);
    family_hash_u32(&sha, receipt->coverage.required_mask);
    family_hash_u32(&sha, receipt->coverage.completed_mask);
    family_hash_u32(&sha, receipt->coverage.failure_mask);
    family_hash_u32(&sha, receipt->coverage.object_count);
    family_hash_u32(&sha, receipt->coverage.inspected_count);
    family_hash_u64(&sha, receipt->coverage.declared_bytes);
    family_hash_u64(&sha, receipt->coverage.inspected_bytes);
    family_hash_u16(&sha, receipt->audience);
    family_hash_u16(&sha, receipt->behavior);
    family_hash_u32(&sha, receipt->reason_code_mask);
    family_hash_u64(&sha, receipt->completed_height);
    family_hash_u64(&sha, (uint64_t)receipt->completed_mtp);
    sha3_256_write(&sha, receipt->signature, 64);
    sha3_256_finalize(&sha, out);
    return VCS_ZCODE_COMMONS_OK;
}

struct family_panel_candidate {
    uint8_t index;
    uint8_t key[32];
};

static int panel_candidate_compare(const void *left_ptr, const void *right_ptr)
{
    const struct family_panel_candidate *left = left_ptr;
    const struct family_panel_candidate *right = right_ptr;
    int cmp = memcmp(left->key, right->key, 32);
    if (cmp != 0) return cmp;
    return left->index < right->index ? -1 : left->index > right->index;
}

static size_t service_group_index(
    const struct vcs_zcode_moderation_service_v1 *services,
    const struct family_panel_candidate *candidates, size_t count,
    const uint8_t group[32])
{
    for (size_t i = 0; i < count; i++)
        if (memcmp(services[candidates[i].index].operator_group_root,
                   group, 32) == 0)
            return i;
    return count;
}

static bool panel_model_seen(
    const struct vcs_zcode_moderation_service_v1 *services,
    const struct vcs_zcode_classification_panel_v1 *panel,
    const uint8_t family[32])
{
    for (size_t i = 0; i < panel->selected_count; i++)
        if (memcmp(services[panel->selected_indices[i]].model_family_root,
                   family, 32) == 0)
            return true;
    return false;
}

static enum vcs_zcode_moderation_tier_v1 family_tier(size_t groups)
{
    if (groups == 0) return VCS_ZCODE_MODERATION_TIER_SELF_SCREENED;
    if (groups == 1) return VCS_ZCODE_MODERATION_TIER_BOOTSTRAP_PASS;
    if (groups == 2) return VCS_ZCODE_MODERATION_TIER_PEERED_PASS;
    if (groups <= 4) return VCS_ZCODE_MODERATION_TIER_EMERGING_PASS;
    if (groups <= 6) return VCS_ZCODE_MODERATION_TIER_DIVERSE_PASS;
    return VCS_ZCODE_MODERATION_TIER_RESILIENT_PASS;
}

enum vcs_zcode_commons_error vcs_zcode_classification_panel_v1_select(
    const struct vcs_zcode_moderation_service_v1 *services,
    size_t service_count, const uint8_t future_block_hash[32],
    bool resilient_appeal,
    struct vcs_zcode_classification_panel_v1 *out)
{
    if (out) memset(out, 0, sizeof(*out));
    if ((!services && service_count > 0) || !future_block_hash || !out)
        return VCS_ZCODE_COMMONS_NULL;
    if (service_count > VCS_ZCODE_MODERATION_MAX_SERVICES ||
        !family_nonzero(future_block_hash))
        return VCS_ZCODE_COMMONS_LIMIT;
    struct family_panel_candidate candidates[
        VCS_ZCODE_MODERATION_MAX_SERVICES];
    size_t candidate_count = 0;
    for (size_t i = 0; i < service_count; i++) {
        const struct vcs_zcode_moderation_service_v1 *service = &services[i];
        if (!service->eligible || service->related_to_publisher ||
            !family_nonzero(service->zid_root) ||
            !family_nonzero(service->operator_group_root) ||
            !family_nonzero(service->model_family_root))
            continue;
        struct sha3_256_ctx sha;
        static const char domain[] = VCS_ZCODE_CLASSIFICATION_PANEL_V1_DOMAIN;
        uint8_t selection_key[32];
        sha3_256_init(&sha);
        sha3_256_write(&sha, (const uint8_t *)domain, sizeof(domain));
        sha3_256_write(&sha, future_block_hash, 32);
        sha3_256_write(&sha, service->zid_root, 32);
        sha3_256_finalize(&sha, selection_key);
        size_t group_at = service_group_index(
            services, candidates, candidate_count,
            service->operator_group_root);
        if (group_at < candidate_count) {
            if (memcmp(selection_key, candidates[group_at].key, 32) < 0) {
                candidates[group_at].index = (uint8_t)i;
                memcpy(candidates[group_at].key, selection_key, 32);
            }
            continue;
        }
        candidates[candidate_count].index = (uint8_t)i;
        memcpy(candidates[candidate_count].key, selection_key, 32);
        candidate_count++;
    }
    qsort(candidates, candidate_count, sizeof(*candidates),
          panel_candidate_compare);
    out->eligible_operator_groups = candidate_count;
    out->tier = family_tier(candidate_count);
    if (resilient_appeal && candidate_count < 11)
        return VCS_ZCODE_COMMONS_QUORUM;
    size_t target = resilient_appeal ? 11u
        : candidate_count >= 7 ? 7u : candidate_count;
    out->required_votes = resilient_appeal ? 8u
        : candidate_count == 0 ? 1u
        : candidate_count <= 2 ? candidate_count
        : candidate_count >= 7 ? 5u : (2u * candidate_count + 2u) / 3u;

    bool used[VCS_ZCODE_MODERATION_MAX_SERVICES] = {false};
    size_t diversity_target = target < 3u ? target : 3u;
    while (out->selected_count < diversity_target) {
        bool added = false;
        for (size_t i = 0; i < candidate_count; i++) {
            if (used[i]) continue;
            const struct vcs_zcode_moderation_service_v1 *service =
                &services[candidates[i].index];
            if (panel_model_seen(services, out, service->model_family_root))
                continue;
            used[i] = true;
            out->selected_indices[out->selected_count++] =
                candidates[i].index;
            added = true;
            break;
        }
        if (!added) break;
    }
    for (size_t i = 0; i < candidate_count && out->selected_count < target;
         i++) {
        if (used[i]) continue;
        used[i] = true;
        out->selected_indices[out->selected_count++] = candidates[i].index;
    }
    for (size_t i = 0; i < out->selected_count; i++) {
        const uint8_t *family =
            services[out->selected_indices[i]].model_family_root;
        bool seen = false;
        for (size_t j = 0; j < i; j++)
            seen = seen || memcmp(
                services[out->selected_indices[j]].model_family_root,
                family, 32) == 0;
        if (!seen) out->distinct_model_families++;
    }
    struct sha3_256_ctx sha;
    static const char root_domain[] = VCS_ZCODE_CLASSIFICATION_PANEL_V1_DOMAIN;
    sha3_256_init(&sha);
    sha3_256_write(&sha, (const uint8_t *)root_domain,
                   sizeof(root_domain));
    sha3_256_write(&sha, future_block_hash, 32);
    family_hash_u64(&sha, candidate_count);
    family_hash_u64(&sha, out->required_votes);
    family_hash_u64(&sha, out->selected_count);
    for (size_t i = 0; i < out->selected_count; i++) {
        const struct vcs_zcode_moderation_service_v1 *service =
            &services[out->selected_indices[i]];
        sha3_256_write(&sha, service->zid_root, 32);
        sha3_256_write(&sha, service->operator_group_root, 32);
        sha3_256_write(&sha, service->model_family_root, 32);
    }
    sha3_256_finalize(&sha, out->selection_root);
    return VCS_ZCODE_COMMONS_OK;
}

enum vcs_zcode_commons_admission_state_v1
vcs_zcode_classification_panel_v1_decide(
    const struct vcs_zcode_classification_panel_v1 *panel,
    const enum vcs_zcode_moderation_vote_v1 *votes,
    size_t vote_count)
{
    if (!panel || !votes || vote_count == 0)
        return VCS_ZCODE_ADMISSION_UNKNOWN;
    if (panel->tier != VCS_ZCODE_MODERATION_TIER_SELF_SCREENED &&
        vote_count != panel->selected_count)
        return VCS_ZCODE_ADMISSION_UNKNOWN;
    size_t pass = 0, block = 0;
    for (size_t i = 0; i < vote_count; i++) {
        pass += votes[i] == VCS_ZCODE_MODERATION_VOTE_PASS;
        block += votes[i] == VCS_ZCODE_MODERATION_VOTE_BLOCK;
    }
    if (pass >= panel->required_votes) {
        switch (panel->tier) {
        case VCS_ZCODE_MODERATION_TIER_SELF_SCREENED:
            return VCS_ZCODE_ADMISSION_SELF_SCREENED;
        case VCS_ZCODE_MODERATION_TIER_BOOTSTRAP_PASS:
            return VCS_ZCODE_ADMISSION_BOOTSTRAP_PASS;
        case VCS_ZCODE_MODERATION_TIER_PEERED_PASS:
            return VCS_ZCODE_ADMISSION_PEERED_PASS;
        case VCS_ZCODE_MODERATION_TIER_EMERGING_PASS:
            return VCS_ZCODE_ADMISSION_EMERGING_PASS;
        case VCS_ZCODE_MODERATION_TIER_DIVERSE_PASS:
            return VCS_ZCODE_ADMISSION_DIVERSE_PASS;
        case VCS_ZCODE_MODERATION_TIER_RESILIENT_PASS:
            return VCS_ZCODE_ADMISSION_RESILIENT_PASS;
        }
    }
    if (block >= panel->required_votes)
        return VCS_ZCODE_ADMISSION_RESTRICTED;
    return pass == 0 && block == 0 ? VCS_ZCODE_ADMISSION_UNKNOWN
                                   : VCS_ZCODE_ADMISSION_CONFLICTED;
}

bool vcs_zcode_commons_admission_is_default_visible_v1(
    enum vcs_zcode_commons_admission_state_v1 state, bool current,
    bool coverage_complete)
{
    if (!current || !coverage_complete) return false;
    return state >= VCS_ZCODE_ADMISSION_SELF_SCREENED &&
           state <= VCS_ZCODE_ADMISSION_RESILIENT_PASS;
}

bool vcs_zcode_commons_admission_is_issuance_eligible_v1(
    enum vcs_zcode_commons_admission_state_v1 state,
    enum vcs_zcode_moderation_tier_v1 highest_attainable_tier,
    bool challenge_mature)
{
    if (!challenge_mature ||
        highest_attainable_tier == VCS_ZCODE_MODERATION_TIER_SELF_SCREENED)
        return false;
    enum vcs_zcode_commons_admission_state_v1 required =
        (enum vcs_zcode_commons_admission_state_v1)(
            VCS_ZCODE_ADMISSION_SELF_SCREENED + highest_attainable_tier);
    return state == required;
}
