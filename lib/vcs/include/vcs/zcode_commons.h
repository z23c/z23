/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: additive simulation-only Living Commons economics and family
 * moderation authorities.  V1 wires are intentionally not included here. */
#ifndef ZCL_VCS_ZCODE_COMMONS_H
#define ZCL_VCS_ZCODE_COMMONS_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Shared schema generation of the simulation-only claim wires: the creation
 * claim, policy candidate and epoch selection formats are one deliberate v2
 * ladder, stamped into their schema_version fields and hashed into roots. */
#define VCS_ZCODE_CREATION_CLAIM_V2_VERSION 2u
#define VCS_ZCODE_COMMONS_SIMULATION_ONLY (1u << 0)
#define VCS_ZCODE_COMMONS_NOT_OWNER_APPROVED (1u << 1)
#define VCS_ZCODE_COMMONS_REQUIRED_FLAGS \
    (VCS_ZCODE_COMMONS_SIMULATION_ONLY | \
     VCS_ZCODE_COMMONS_NOT_OWNER_APPROVED)

#define VCS_ZCODE_POLICY_CANDIDATE_V2_DOMAIN \
    "zcl.zcode.zc23_policy_candidate.v2"
#define VCS_ZCODE_CREATION_CLAIM_V2_DOMAIN \
    "zcl.zcode.creation_claim.v2"
#define VCS_ZCODE_EPOCH_CREATION_SET_V2_DOMAIN \
    "zcl.zcode.epoch_creation_set.v2"
#define VCS_ZCODE_FAMILY_POLICY_V1_DOMAIN \
    "zcl.zcode.family_policy.v1"
#define VCS_ZCODE_CLASSIFICATION_RECEIPT_V1_DOMAIN \
    "zcl.zcode.classification_receipt.v1"
#define VCS_ZCODE_CLASSIFICATION_PANEL_V1_DOMAIN \
    "zcl.zcode.classification_panel.v1"
#define VCS_ZCODE_COMMONS_ADMISSION_V1_DOMAIN \
    "zcl.zcode.commons_admission.v1"
#define VCS_ZCODE_WORKSPACE_MANIFEST_V1_DOMAIN \
    "zcl.zcode.workspace_manifest.v1"
#define VCS_ZCODE_WORKSPACE_MANIFEST_V1_UNSIGNED_DOMAIN \
    "zcl.zcode.workspace_manifest.unsigned.v1"
#define VCS_ZCODE_WORKSPACE_MANIFEST_V1_SIGNING_DOMAIN \
    "zcl.zcode.workspace_manifest.signature.v1"
#define VCS_ZCODE_WORKSPACE_MANIFEST_V1_SIGNING_PAYLOAD_BYTES \
    ((sizeof(VCS_ZCODE_WORKSPACE_MANIFEST_V1_SIGNING_DOMAIN) - 1u) + 32u)
#define VCS_ZCODE_WORKSPACE_MANIFEST_V1_WIRE_BASE_BYTES 160u
#define VCS_ZCODE_WORKSPACE_MANIFEST_V1_ENTRY_WIRE_BYTES 168u
#define VCS_ZCODE_WORKSPACE_MANIFEST_V1_EDGE_WIRE_BYTES 8u
#define VCS_ZCODE_WORKSPACE_MANIFEST_V1_ASSET_WIRE_BYTES 32u
#define VCS_ZCODE_WORKSPACE_ENTRY_V1_DOMAIN \
    "zcl.zcode.workspace_entry.v1"
#define VCS_ZCODE_TYPED_ASSET_MANIFEST_V1_DOMAIN \
    "zcl.zcode.typed_asset_manifest.v1"
#define VCS_ZCODE_MODULE_PASSPORT_V1_DOMAIN \
    "zcl.zcode.module_passport.v1"
#define VCS_ZCODE_QUALITY_PROFILE_V1_DOMAIN \
    "zcl.zcode.quality_profile.v1"
#define VCS_ZCODE_MISSION_V1_DOMAIN "zcl.zcode.mission.v1"
#define VCS_ZCODE_CONTRIBUTION_SPLIT_V1_DOMAIN \
    "zcl.zcode.contribution_split.v1"

#define VCS_ZCODE_COMMONS_CHALLENGE_BLOCKS UINT64_C(8064)
#define VCS_ZCODE_COMMONS_CHALLENGE_SECONDS INT64_C(604800)
#define VCS_ZCODE_COMMONS_ATOMS_PER_TOKEN UINT64_C(100000000)
#define VCS_ZCODE_COMMONS_CATEGORY_COUNT 8u
#define VCS_ZCODE_COMMONS_MAX_CLAIMS 4096u
#define VCS_ZCODE_MODERATION_MAX_SERVICES 64u
#define VCS_ZCODE_MODERATION_MAX_PANEL 11u
#define VCS_ZCODE_CONTRIBUTION_SPLIT_MAX 64u

enum vcs_zcode_asset_license_v1 {
    VCS_ZCODE_ASSET_LICENSE_CC0_1_0 = 1,
    VCS_ZCODE_ASSET_LICENSE_CC_BY_4_0 = 2,
};

enum vcs_zcode_asset_kind_v1 {
    VCS_ZCODE_ASSET_SOURCE = 1,
    VCS_ZCODE_ASSET_DOCUMENT = 2,
    VCS_ZCODE_ASSET_IMAGE = 3,
    VCS_ZCODE_ASSET_AUDIO = 4,
    VCS_ZCODE_ASSET_VIDEO = 5,
    VCS_ZCODE_ASSET_DATASET = 6,
};

struct vcs_zcode_typed_asset_manifest_v1 {
    uint16_t schema_version;
    uint16_t flags;
    uint16_t kind;
    uint16_t license;
    uint8_t format_root[32];
    uint8_t content_root[32];
    uint8_t attribution_root[32];
    uint8_t collection_root[32];
    uint64_t byte_count;
    uint8_t signer_root[32];
    uint8_t signature[64];
};

#define VCS_ZCODE_QUALITY_UNIVERSAL_MASK UINT64_C(0x00000000000000ff)

enum vcs_zcode_quality_field_v1 {
    VCS_ZCODE_QUALITY_UNIVERSAL = 0,
    VCS_ZCODE_QUALITY_MATH = 1,
    VCS_ZCODE_QUALITY_CRYPTOGRAPHY = 2,
    VCS_ZCODE_QUALITY_BIOLOGY = 3,
    VCS_ZCODE_QUALITY_CHEMISTRY = 4,
    VCS_ZCODE_QUALITY_PHYSICS = 5,
    VCS_ZCODE_QUALITY_ASTRONOMY = 6,
    VCS_ZCODE_QUALITY_NETWORKING = 7,
    VCS_ZCODE_QUALITY_VIDEO = 8,
    VCS_ZCODE_QUALITY_GAMES = 9,
};

struct vcs_zcode_quality_profile_v1 {
    uint16_t schema_version;
    uint16_t flags;
    uint16_t field;
    uint16_t reserved;
    uint64_t required_check_mask;
    uint8_t universal_profile_root[32];
    uint8_t additive_rules_root[32];
};

struct vcs_zcode_module_passport_v1 {
    uint16_t schema_version;
    uint16_t flags;
    uint8_t stable_api_root[32];
    uint8_t recipe_root[32];
    uint8_t toolchain_root[32];
    uint8_t tests_root[32];
    uint8_t license_root[32];
    uint8_t semantic_fingerprint_root[32];
    uint8_t workspace_lineage_root[32];
    uint8_t source_assignment_root[32];
    uint8_t quality_profiles_root[32];
    uint8_t signer_root[32];
    uint8_t signature[64];
};

#define VCS_ZCODE_MODULE_PASSPORT_V1_WIRE_BYTES 396u
#define VCS_ZCODE_MODULE_PASSPORT_V1_UNSIGNED_WIRE_BYTES 332u
#define VCS_ZCODE_MODULE_PASSPORT_V1_SIGNING_DOMAIN \
    "zcl.zcode.module_passport.signature.v1"
#define VCS_ZCODE_MODULE_PASSPORT_V1_SIGNING_PAYLOAD_BYTES \
    ((sizeof(VCS_ZCODE_MODULE_PASSPORT_V1_SIGNING_DOMAIN) - 1u) + \
     VCS_ZCODE_MODULE_PASSPORT_V1_UNSIGNED_WIRE_BYTES)

struct vcs_zcode_workspace_entry_v1 {
    uint8_t module_release_root[32];
    uint8_t module_passport_root[32];
    uint8_t semantic_fingerprint_root[32];
    uint8_t source_assignment_root[32];
    uint8_t predecessor_release_root[32];
    uint64_t sequence;
};

struct vcs_zcode_workspace_edge_v1 {
    uint16_t from_entry;
    uint16_t to_entry;
    uint32_t reserved;
};

struct vcs_zcode_workspace_manifest_v1 {
    uint16_t schema_version;
    uint16_t flags;
    uint64_t sequence;
    uint8_t predecessor_workspace_root[32];
    const struct vcs_zcode_workspace_entry_v1 *entries;
    size_t entry_count;
    const struct vcs_zcode_workspace_edge_v1 *edges;
    size_t edge_count;
    const uint8_t (*typed_asset_roots)[32];
    size_t typed_asset_count;
    uint8_t signer_root[32];
    uint8_t signature[64];
};

/* Owning decode result for the variable-length canonical wire.  The public
 * manifest keeps caller-owned views so existing v1 roots remain unchanged;
 * this wrapper owns only arrays allocated while decoding hostile CAS bytes. */
struct vcs_zcode_workspace_manifest_v1_decoded {
    struct vcs_zcode_workspace_manifest_v1 manifest;
    struct vcs_zcode_workspace_entry_v1 *entries;
    struct vcs_zcode_workspace_edge_v1 *edges;
    uint8_t (*typed_asset_roots)[32];
};

struct vcs_zcode_mission_v1 {
    uint16_t schema_version;
    uint16_t flags;
    uint8_t publisher_binding_root[32];
    uint8_t subject_tags_root[32];
    uint8_t goal_text_root[32];
    uint8_t patron_task_root[32];
    uint64_t created_height;
    int64_t created_mtp;
    uint8_t signature[64];
};

struct vcs_zcode_contribution_split_entry_v1 {
    uint8_t recipient_binding_root[32];
    uint64_t award_atoms;
    uint8_t signature[64];
};

struct vcs_zcode_contribution_split_v1 {
    uint16_t schema_version;
    uint16_t flags;
    uint8_t claim_root[32];
    uint64_t total_award_atoms;
    struct vcs_zcode_contribution_split_entry_v1
        entries[VCS_ZCODE_CONTRIBUTION_SPLIT_MAX];
    size_t entry_count;
};

enum vcs_zcode_commons_error {
    VCS_ZCODE_COMMONS_OK = 0,
    VCS_ZCODE_COMMONS_NULL,
    VCS_ZCODE_COMMONS_VERSION_ERROR,
    VCS_ZCODE_COMMONS_FLAGS,
    VCS_ZCODE_COMMONS_ROOT,
    VCS_ZCODE_COMMONS_ENUM,
    VCS_ZCODE_COMMONS_AMOUNT,
    VCS_ZCODE_COMMONS_LIMIT,
    VCS_ZCODE_COMMONS_ORDER,
    VCS_ZCODE_COMMONS_DUPLICATE,
    VCS_ZCODE_COMMONS_IMMATURE,
    VCS_ZCODE_COMMONS_POLICY,
    VCS_ZCODE_COMMONS_COVERAGE,
    VCS_ZCODE_COMMONS_QUORUM,
    VCS_ZCODE_COMMONS_OVERFLOW,
    VCS_ZCODE_COMMONS_SIZE,
    VCS_ZCODE_COMMONS_MAGIC,
    VCS_ZCODE_COMMONS_SIGNATURE,
};

enum vcs_zcode_creation_category_v2 {
    VCS_ZCODE_CREATION_V2_MODULE_PUBLICATION = 0,
    VCS_ZCODE_CREATION_V2_DEFECT_REPAIR = 1,
    VCS_ZCODE_CREATION_V2_SECURITY_FINDING = 2,
    VCS_ZCODE_CREATION_V2_INDEPENDENT_TEST = 3,
    VCS_ZCODE_CREATION_V2_REPRODUCTION = 4,
    VCS_ZCODE_CREATION_V2_PERFORMANCE_FRONTIER = 5,
    VCS_ZCODE_CREATION_V2_COMPATIBILITY_PROOF = 6,
    VCS_ZCODE_CREATION_V2_PRESERVATION = 7,
};

struct vcs_zcode_policy_candidate_v2 {
    uint16_t schema_version;
    uint16_t flags;
    uint64_t challenge_blocks;
    int64_t challenge_seconds;
    uint8_t network_genesis_root[32];
    uint8_t moderation_policy_root[32];
    uint8_t qualification_predicates_root[32];
    uint8_t backlog_algorithm_root[32];
    uint64_t award_atoms[VCS_ZCODE_COMMONS_CATEGORY_COUNT];
};

enum vcs_zcode_creation_claim_flag_v2 {
    VCS_ZCODE_CLAIM_V2_VALID = 1u << 0,
    VCS_ZCODE_CLAIM_V2_INDEPENDENTLY_MATURED = 1u << 1,
    VCS_ZCODE_CLAIM_V2_CURRENT_MODERATION = 1u << 2,
    VCS_ZCODE_CLAIM_V2_REORGED = 1u << 3,
    VCS_ZCODE_CLAIM_V2_RETRACTED = 1u << 4,
    VCS_ZCODE_CLAIM_V2_DUPLICATE_SEMANTICS = 1u << 5,
    VCS_ZCODE_CLAIM_V2_MODERATION_REVERSED = 1u << 6,
};

#define VCS_ZCODE_CLAIM_V2_REQUIRED_FLAGS \
    (VCS_ZCODE_CLAIM_V2_VALID | \
     VCS_ZCODE_CLAIM_V2_INDEPENDENTLY_MATURED | \
     VCS_ZCODE_CLAIM_V2_CURRENT_MODERATION)
#define VCS_ZCODE_CLAIM_V2_INVALIDATING_FLAGS \
    (VCS_ZCODE_CLAIM_V2_REORGED | VCS_ZCODE_CLAIM_V2_RETRACTED | \
     VCS_ZCODE_CLAIM_V2_DUPLICATE_SEMANTICS | \
     VCS_ZCODE_CLAIM_V2_MODERATION_REVERSED)

struct vcs_zcode_creation_claim_v2 {
    uint16_t schema_version;
    uint16_t flags;
    uint16_t category;
    uint16_t reserved;
    uint8_t claim_root[32];
    uint8_t recipient_binding_root[32];
    uint8_t workspace_lineage_root[32];
    uint8_t semantic_lineage_root[32];
    uint8_t evidence_root[32];
    uint8_t commons_admission_root[32];
    uint64_t maturity_height;
    int64_t maturity_mtp;
};

struct vcs_zcode_epoch_selection_v2 {
    uint64_t epoch;
    uint64_t cutoff_height;
    int64_t cutoff_mtp;
    uint64_t epoch_capacity_atoms;
    uint8_t previous_epoch_root[32];
    const struct vcs_zcode_creation_claim_v2 *claims;
    size_t claim_count;
};

struct vcs_zcode_epoch_selection_result_v2 {
    size_t selected_indices[VCS_ZCODE_COMMONS_MAX_CLAIMS];
    size_t selected_count;
    size_t deferred_count;
    size_t invalid_count;
    uint64_t selected_atoms;
    uint64_t expired_capacity_atoms;
    uint64_t recipient_cap_atoms;
    uint64_t lineage_cap_atoms;
    uint8_t first_category;
    uint8_t epoch_creation_root[32];
};

enum vcs_zcode_family_exclusion_v1 {
    VCS_ZCODE_FAMILY_EXPLICIT_SEXUAL = 1u << 0,
    VCS_ZCODE_FAMILY_GRAPHIC_GORE = 1u << 1,
    VCS_ZCODE_FAMILY_TARGETED_HATE = 1u << 2,
    VCS_ZCODE_FAMILY_SELF_HARM = 1u << 3,
    VCS_ZCODE_FAMILY_HARMFUL_ILLEGAL = 1u << 4,
    VCS_ZCODE_FAMILY_STRONG_PROFANITY = 1u << 5,
    VCS_ZCODE_FAMILY_PRIMARY_ABUSE_SOFTWARE = 1u << 6,
};

#define VCS_ZCODE_FAMILY_EXCLUSION_MASK \
    (VCS_ZCODE_FAMILY_EXPLICIT_SEXUAL | VCS_ZCODE_FAMILY_GRAPHIC_GORE | \
     VCS_ZCODE_FAMILY_TARGETED_HATE | VCS_ZCODE_FAMILY_SELF_HARM | \
     VCS_ZCODE_FAMILY_HARMFUL_ILLEGAL | \
     VCS_ZCODE_FAMILY_STRONG_PROFANITY | \
     VCS_ZCODE_FAMILY_PRIMARY_ABUSE_SOFTWARE)

struct vcs_zcode_family_policy_v1 {
    uint16_t schema_version;
    uint16_t flags;
    uint32_t excluded_reason_mask;
    uint32_t max_metadata_items;
    uint32_t max_dependency_objects;
    uint64_t max_extracted_bytes;
    uint8_t profile_name_root[32];
    uint8_t policy_text_root[32];
};

enum vcs_zcode_moderation_audience_v1 {
    VCS_ZCODE_AUDIENCE_GENERAL = 0,
    VCS_ZCODE_AUDIENCE_CONTEXTUAL_SCIENCE = 1,
    VCS_ZCODE_AUDIENCE_MATURE = 2,
    VCS_ZCODE_AUDIENCE_EXPLICIT = 3,
    VCS_ZCODE_AUDIENCE_UNKNOWN = 4,
};

enum vcs_zcode_moderation_behavior_v1 {
    VCS_ZCODE_BEHAVIOR_BENIGN = 0,
    VCS_ZCODE_BEHAVIOR_DUAL_USE = 1,
    VCS_ZCODE_BEHAVIOR_MALICIOUS = 2,
    VCS_ZCODE_BEHAVIOR_UNKNOWN = 3,
};

enum vcs_zcode_moderation_vote_v1 {
    VCS_ZCODE_MODERATION_VOTE_UNKNOWN = 0,
    VCS_ZCODE_MODERATION_VOTE_PASS = 1,
    VCS_ZCODE_MODERATION_VOTE_BLOCK = 2,
};

enum vcs_zcode_moderation_coverage_flag_v1 {
    VCS_ZCODE_COVERAGE_METADATA = 1u << 0,
    VCS_ZCODE_COVERAGE_DOCUMENTATION = 1u << 1,
    VCS_ZCODE_COVERAGE_COMMENTS = 1u << 2,
    VCS_ZCODE_COVERAGE_STRINGS = 1u << 3,
    VCS_ZCODE_COVERAGE_EXAMPLES = 1u << 4,
    VCS_ZCODE_COVERAGE_MEDIA = 1u << 5,
    VCS_ZCODE_COVERAGE_TYPED_ASSETS = 1u << 6,
    VCS_ZCODE_COVERAGE_DEPENDENCIES = 1u << 7,
};

#define VCS_ZCODE_COVERAGE_REQUIRED_MASK UINT32_C(0x000000ff)

enum vcs_zcode_moderation_failure_flag_v1 {
    VCS_ZCODE_COVERAGE_UNSUPPORTED = 1u << 0,
    VCS_ZCODE_COVERAGE_ENCRYPTED = 1u << 1,
    VCS_ZCODE_COVERAGE_OPAQUE = 1u << 2,
    VCS_ZCODE_COVERAGE_MISSING = 1u << 3,
    VCS_ZCODE_COVERAGE_TRUNCATED = 1u << 4,
    VCS_ZCODE_COVERAGE_MUTABLE = 1u << 5,
    VCS_ZCODE_COVERAGE_OVER_BUDGET = 1u << 6,
    VCS_ZCODE_COVERAGE_PARTIAL = 1u << 7,
};

struct vcs_zcode_moderation_coverage_v1 {
    uint32_t required_mask;
    uint32_t completed_mask;
    uint32_t failure_mask;
    uint32_t object_count;
    uint32_t inspected_count;
    uint64_t declared_bytes;
    uint64_t inspected_bytes;
};

struct vcs_zcode_classification_receipt_v1 {
    uint16_t schema_version;
    uint16_t flags;
    uint8_t request_root[32];
    uint8_t content_root[32];
    uint8_t policy_root[32];
    uint8_t classifier_manifest_root[32];
    uint8_t operator_group_root[32];
    uint8_t model_family_root[32];
    struct vcs_zcode_moderation_coverage_v1 coverage;
    uint16_t audience;
    uint16_t behavior;
    uint32_t reason_code_mask;
    uint64_t completed_height;
    int64_t completed_mtp;
    uint8_t signature[64];
};

struct vcs_zcode_moderation_service_v1 {
    uint8_t zid_root[32];
    uint8_t operator_group_root[32];
    uint8_t model_family_root[32];
    bool eligible;
    bool related_to_publisher;
};

enum vcs_zcode_moderation_tier_v1 {
    VCS_ZCODE_MODERATION_TIER_SELF_SCREENED = 0,
    VCS_ZCODE_MODERATION_TIER_BOOTSTRAP_PASS = 1,
    VCS_ZCODE_MODERATION_TIER_PEERED_PASS = 2,
    VCS_ZCODE_MODERATION_TIER_EMERGING_PASS = 3,
    VCS_ZCODE_MODERATION_TIER_DIVERSE_PASS = 4,
    VCS_ZCODE_MODERATION_TIER_RESILIENT_PASS = 5,
};

enum vcs_zcode_commons_admission_state_v1 {
    VCS_ZCODE_ADMISSION_PENDING = 0,
    VCS_ZCODE_ADMISSION_SELF_SCREENED,
    VCS_ZCODE_ADMISSION_BOOTSTRAP_PASS,
    VCS_ZCODE_ADMISSION_PEERED_PASS,
    VCS_ZCODE_ADMISSION_EMERGING_PASS,
    VCS_ZCODE_ADMISSION_DIVERSE_PASS,
    VCS_ZCODE_ADMISSION_RESILIENT_PASS,
    VCS_ZCODE_ADMISSION_RESTRICTED,
    VCS_ZCODE_ADMISSION_REVIEW_REQUIRED,
    VCS_ZCODE_ADMISSION_DISPUTED,
    VCS_ZCODE_ADMISSION_CONFLICTED,
    VCS_ZCODE_ADMISSION_UNKNOWN,
    VCS_ZCODE_ADMISSION_STALE,
    VCS_ZCODE_ADMISSION_REORGED,
};

struct vcs_zcode_classification_panel_v1 {
    uint8_t selected_indices[VCS_ZCODE_MODERATION_MAX_PANEL];
    size_t selected_count;
    size_t eligible_operator_groups;
    size_t required_votes;
    size_t distinct_model_families;
    enum vcs_zcode_moderation_tier_v1 tier;
    uint8_t selection_root[32];
};

const char *vcs_zcode_commons_error_string(
    enum vcs_zcode_commons_error error);

enum vcs_zcode_commons_error vcs_zcode_typed_asset_manifest_v1_validate(
    const struct vcs_zcode_typed_asset_manifest_v1 *asset);
enum vcs_zcode_commons_error vcs_zcode_typed_asset_manifest_v1_root(
    const struct vcs_zcode_typed_asset_manifest_v1 *asset, uint8_t out[32]);
enum vcs_zcode_commons_error vcs_zcode_quality_profile_v1_validate(
    const struct vcs_zcode_quality_profile_v1 *profile);
enum vcs_zcode_commons_error vcs_zcode_quality_profile_v1_root(
    const struct vcs_zcode_quality_profile_v1 *profile, uint8_t out[32]);
enum vcs_zcode_commons_error vcs_zcode_module_passport_v1_validate(
    const struct vcs_zcode_module_passport_v1 *passport);
enum vcs_zcode_commons_error vcs_zcode_module_passport_v1_signing_payload(
    const struct vcs_zcode_module_passport_v1 *passport,
    uint8_t *payload, size_t payload_capacity, size_t *payload_len);
enum vcs_zcode_commons_error vcs_zcode_module_passport_v1_sign(
    struct vcs_zcode_module_passport_v1 *passport,
    const uint8_t signer_seed[32]);
enum vcs_zcode_commons_error vcs_zcode_module_passport_v1_verify(
    const struct vcs_zcode_module_passport_v1 *passport);
enum vcs_zcode_commons_error vcs_zcode_module_passport_v1_encode(
    const struct vcs_zcode_module_passport_v1 *passport,
    uint8_t *wire, size_t wire_capacity, size_t *wire_len);
enum vcs_zcode_commons_error vcs_zcode_module_passport_v1_decode(
    struct vcs_zcode_module_passport_v1 *out,
    const uint8_t *wire, size_t wire_len);
enum vcs_zcode_commons_error vcs_zcode_module_passport_v1_root(
    const struct vcs_zcode_module_passport_v1 *passport, uint8_t out[32]);
enum vcs_zcode_commons_error vcs_zcode_workspace_manifest_v1_validate(
    const struct vcs_zcode_workspace_manifest_v1 *workspace);
enum vcs_zcode_commons_error vcs_zcode_workspace_manifest_v1_unsigned_root(
    const struct vcs_zcode_workspace_manifest_v1 *workspace,
    uint8_t out[32]);
enum vcs_zcode_commons_error vcs_zcode_workspace_manifest_v1_signing_payload(
    const struct vcs_zcode_workspace_manifest_v1 *workspace,
    uint8_t *payload, size_t payload_capacity, size_t *payload_len);
enum vcs_zcode_commons_error vcs_zcode_workspace_manifest_v1_verify(
    const struct vcs_zcode_workspace_manifest_v1 *workspace);
enum vcs_zcode_commons_error vcs_zcode_workspace_manifest_v1_wire_size(
    const struct vcs_zcode_workspace_manifest_v1 *workspace,
    size_t *wire_size);
enum vcs_zcode_commons_error vcs_zcode_workspace_manifest_v1_encode(
    const struct vcs_zcode_workspace_manifest_v1 *workspace,
    uint8_t *wire, size_t wire_capacity, size_t *wire_len);
enum vcs_zcode_commons_error vcs_zcode_workspace_manifest_v1_decode(
    struct vcs_zcode_workspace_manifest_v1_decoded *out,
    const uint8_t *wire, size_t wire_len);
void vcs_zcode_workspace_manifest_v1_decoded_free(
    struct vcs_zcode_workspace_manifest_v1_decoded *decoded);
enum vcs_zcode_commons_error vcs_zcode_workspace_entry_v1_validate(
    const struct vcs_zcode_workspace_entry_v1 *entry);
enum vcs_zcode_commons_error vcs_zcode_workspace_entry_v1_root(
    const struct vcs_zcode_workspace_entry_v1 *entry, uint8_t out[32]);
enum vcs_zcode_commons_error vcs_zcode_workspace_manifest_v1_root(
    const struct vcs_zcode_workspace_manifest_v1 *workspace,
    uint8_t out[32]);
enum vcs_zcode_commons_error vcs_zcode_mission_v1_validate(
    const struct vcs_zcode_mission_v1 *mission);
enum vcs_zcode_commons_error vcs_zcode_mission_v1_root(
    const struct vcs_zcode_mission_v1 *mission, uint8_t out[32]);
enum vcs_zcode_commons_error vcs_zcode_contribution_split_v1_validate(
    const struct vcs_zcode_contribution_split_v1 *split);
enum vcs_zcode_commons_error vcs_zcode_contribution_split_v1_root(
    const struct vcs_zcode_contribution_split_v1 *split, uint8_t out[32]);

void vcs_zcode_policy_candidate_v2_init(
    struct vcs_zcode_policy_candidate_v2 *policy,
    const uint8_t network_genesis_root[32],
    const uint8_t moderation_policy_root[32],
    const uint8_t qualification_predicates_root[32],
    const uint8_t backlog_algorithm_root[32]);
enum vcs_zcode_commons_error vcs_zcode_policy_candidate_v2_validate(
    const struct vcs_zcode_policy_candidate_v2 *policy);
enum vcs_zcode_commons_error vcs_zcode_policy_candidate_v2_root(
    const struct vcs_zcode_policy_candidate_v2 *policy, uint8_t out[32]);
uint64_t vcs_zcode_creation_award_atoms_v2(uint16_t category);

enum vcs_zcode_commons_error vcs_zcode_creation_claim_v2_validate(
    const struct vcs_zcode_creation_claim_v2 *claim,
    const struct vcs_zcode_policy_candidate_v2 *policy);
enum vcs_zcode_commons_error vcs_zcode_epoch_select_v2(
    const struct vcs_zcode_epoch_selection_v2 *input,
    const struct vcs_zcode_policy_candidate_v2 *policy,
    struct vcs_zcode_epoch_selection_result_v2 *out);

void vcs_zcode_family_policy_v1_init(
    struct vcs_zcode_family_policy_v1 *policy,
    const uint8_t profile_name_root[32],
    const uint8_t policy_text_root[32]);
void vcs_zcode_family_policy_v1_default(
    struct vcs_zcode_family_policy_v1 *policy);
enum vcs_zcode_commons_error vcs_zcode_family_policy_v1_validate(
    const struct vcs_zcode_family_policy_v1 *policy);
enum vcs_zcode_commons_error vcs_zcode_family_policy_v1_root(
    const struct vcs_zcode_family_policy_v1 *policy, uint8_t out[32]);

enum vcs_zcode_moderation_vote_v1 vcs_zcode_moderation_coverage_vote_v1(
    const struct vcs_zcode_moderation_coverage_v1 *coverage,
    enum vcs_zcode_moderation_audience_v1 audience,
    enum vcs_zcode_moderation_behavior_v1 behavior);
enum vcs_zcode_commons_error vcs_zcode_classification_receipt_v1_validate(
    const struct vcs_zcode_classification_receipt_v1 *receipt);
enum vcs_zcode_commons_error vcs_zcode_classification_receipt_v1_root(
    const struct vcs_zcode_classification_receipt_v1 *receipt,
    uint8_t out[32]);

enum vcs_zcode_commons_error vcs_zcode_classification_panel_v1_select(
    const struct vcs_zcode_moderation_service_v1 *services,
    size_t service_count, const uint8_t future_block_hash[32],
    bool resilient_appeal,
    struct vcs_zcode_classification_panel_v1 *out);
enum vcs_zcode_commons_admission_state_v1
vcs_zcode_classification_panel_v1_decide(
    const struct vcs_zcode_classification_panel_v1 *panel,
    const enum vcs_zcode_moderation_vote_v1 *votes,
    size_t vote_count);
bool vcs_zcode_commons_admission_is_default_visible_v1(
    enum vcs_zcode_commons_admission_state_v1 state, bool current,
    bool coverage_complete);
bool vcs_zcode_commons_admission_is_issuance_eligible_v1(
    enum vcs_zcode_commons_admission_state_v1 state,
    enum vcs_zcode_moderation_tier_v1 highest_attainable_tier,
    bool challenge_mature);

#endif /* ZCL_VCS_ZCODE_COMMONS_H */
