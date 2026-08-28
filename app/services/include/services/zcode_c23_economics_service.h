/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Pure calculation ABI for simulation-only Commons economics. */

#ifndef ZCL_SERVICES_ZCODE_C23_ECONOMICS_SERVICE_H
#define ZCL_SERVICES_ZCODE_C23_ECONOMICS_SERVICE_H

#include "vcs/zcode_commons.h"
#include "vcs/zcode_claim_epoch.h"
#include "vcs/zcode_epoch_schedule.h"

#include <stdbool.h>
#include <stdint.h>

#define ZCODE_C23_ECONOMICS_SERVICE_ID "zcode.c23.economics.v1"
#define ZCODE_C23_ECONOMICS_ABI_FINGERPRINT \
    "zcode.c23.economics.abi.v3:claim-epoch-view"
#define ZCODE_C23_ECONOMICS_SCHEMA_FINGERPRINT \
    "zcl.zcode_commons_economics_status.v2+schedule_proposal_view.v2+backlog-readiness.v1+claim_epoch_view.v2"
#define ZCODE_C23_ECONOMICS_WIRE_FINGERPRINT \
    "zc23-policy+claim+backlog-readiness+epoch-selection+claim-epoch-proposal.v2"
#define ZCODE_C23_ECONOMICS_POLICY_KAT_ROOT \
    "8fc1df9547d1842004e86c1a06714829965693c031f8e3a16dd2fe38ee6f6ad9"
#define ZCODE_C23_ECONOMICS_KAT_FINGERPRINT \
    "988f572ab350e79e76515506025f3db334809c8f2a89d397274c542f26580016"

struct zcode_c23_economics_status_result_v1 {
    uint64_t challenge_blocks;
    int64_t challenge_seconds;
    uint64_t award_atoms[VCS_ZCODE_COMMONS_CATEGORY_COUNT];
    bool partial_claim_issuance;
    bool unused_capacity_carries;
    char queue_order[64];
    char category_order[96];
    char concentration_cap[96];
};

struct zcode_c23_schedule_proposal_view_v1 {
    uint64_t cap_atoms;
    uint64_t total_epochs;
    uint64_t epoch;
    uint64_t budget_atoms;
    uint64_t already_emitted_atoms;
    uint64_t proposed_mint_atoms;
    uint64_t unissued_atoms;
    uint64_t class_weights[4];
    uint32_t evidence_count;
    uint32_t eligible_count;
    uint32_t preservation_skipped;
    bool simulated;
    bool persisted;
    bool schedule_proposal;
    bool mint;
    bool token_exists;
    bool funds_moved;
    bool custody_used;
    bool genesis_gate_satisfied;
    bool balance_used_for_truth;
    char preservation_skip_reason[64];
    char mint_authority[48];
};

struct zcode_c23_backlog_status_input_v1 {
    bool projection_ready;
    uint32_t claim_count;
    uint32_t eligible_claim_count;
};

struct zcode_c23_backlog_status_result_v1 {
    bool valid;
    bool backlog_ready;
    bool issuance_enabled;
    bool unused_capacity_expires;
    char readiness[64];
    char reason[192];
    char next_command[64];
};

struct zcode_c23_claim_epoch_view_v1 {
    uint64_t epoch;
    uint64_t cutoff_height;
    int64_t cutoff_mtp;
    uint64_t epoch_capacity_atoms;
    uint64_t selected_atoms;
    uint64_t expired_capacity_atoms;
    uint64_t recipient_cap_atoms;
    uint64_t lineage_cap_atoms;
    uint32_t claim_count;
    uint32_t selected_count;
    uint32_t deferred_count;
    uint32_t invalid_count;
    uint8_t first_category;
    bool valid;
    bool persisted;
    bool canonical_proposal;
    bool current_selection_verified;
    bool simulation_only;
    bool issuance_enabled;
    bool wallet_used;
    bool funds_moved;
    char verification_state[64];
    char next_command[64];
};

struct zcode_c23_economics_service_v1 {
    uint64_t (*award_atoms)(uint16_t category);
    void (*policy_init)(struct vcs_zcode_policy_candidate_v2 *policy,
                        const uint8_t network_genesis_root[32],
                        const uint8_t moderation_policy_root[32],
                        const uint8_t qualification_predicates_root[32],
                        const uint8_t backlog_algorithm_root[32]);
    enum vcs_zcode_commons_error (*policy_validate)(
        const struct vcs_zcode_policy_candidate_v2 *policy);
    enum vcs_zcode_commons_error (*policy_root)(
        const struct vcs_zcode_policy_candidate_v2 *policy,
        uint8_t out[32]);
    enum vcs_zcode_commons_error (*epoch_select)(
        const struct vcs_zcode_epoch_selection_v2 *input,
        const struct vcs_zcode_policy_candidate_v2 *policy,
        struct vcs_zcode_epoch_selection_result_v2 *out);
    bool (*render_status)(struct zcode_c23_economics_status_result_v1 *out);
    bool (*render_schedule_proposal)(
        const struct vcs_zcode_epoch_schedule_proposal_v1 *proposal,
        bool persisted, struct zcode_c23_schedule_proposal_view_v1 *out);
    bool (*render_backlog_status)(
        const struct zcode_c23_backlog_status_input_v1 *input,
        struct zcode_c23_backlog_status_result_v1 *out);
    bool (*render_claim_epoch)(
        const struct vcs_zcode_claim_epoch_proposal_v2 *proposal,
        bool persisted, bool current_selection_verified,
        struct zcode_c23_claim_epoch_view_v1 *out);
    bool (*schedule_class_name)(uint16_t schedule_class,
                                char *out, size_t out_size);
};

const struct zcode_c23_economics_service_v1 *
zcode_c23_economics_service_builtin(void);
struct zcl_hotswap_service_contract;
const struct zcl_hotswap_service_contract *
zcl_native_zcode_economics_service_contract(void);

#endif /* ZCL_SERVICES_ZCODE_C23_ECONOMICS_SERVICE_H */
