/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: canonical simulation-only ZC23 policy and reproducer approvals. */
#ifndef ZCL_VCS_ZCODE_SHADOW_POLICY_H
#define ZCL_VCS_ZCODE_SHADOW_POLICY_H

#include "vcs/zcode_creation_attribution.h"
#include "vcs/zcode_epoch_creation.h"

#include <stddef.h>
#include <stdint.h>

#define VCS_ZCODE_APPROVED_REPRODUCER_SET_DOMAIN \
    "zcl.zcode.approved_reproducer_set.v1"
#define VCS_ZCODE_POLICY_CANDIDATE_DOMAIN \
    "zcl.zcode.zc23_policy_candidate.v1"
#define VCS_ZCODE_SHADOW_POLICY_VERSION 1u

#define VCS_ZCODE_APPROVED_REPRODUCER_SET_HEADER_BYTES 96u
#define VCS_ZCODE_APPROVED_REPRODUCER_ENTRY_BYTES 160u
#define VCS_ZCODE_APPROVED_REPRODUCER_MAX_ENTRIES 64u
#define VCS_ZCODE_APPROVED_REPRODUCER_SET_MAX_WIRE_BYTES \
    (VCS_ZCODE_APPROVED_REPRODUCER_SET_HEADER_BYTES + \
     VCS_ZCODE_APPROVED_REPRODUCER_MAX_ENTRIES * \
         VCS_ZCODE_APPROVED_REPRODUCER_ENTRY_BYTES)
#define VCS_ZCODE_POLICY_CANDIDATE_WIRE_BYTES 256u

enum vcs_zcode_shadow_policy_flag {
    VCS_ZCODE_SHADOW_SIMULATION_ONLY = 1u << 0,
    VCS_ZCODE_SHADOW_NOT_OWNER_APPROVED = 1u << 1,
    VCS_ZCODE_SHADOW_NO_CARRY_FORWARD = 1u << 2,
    VCS_ZCODE_SHADOW_COMPLETE_ATTRIBUTION = 1u << 3,
};

#define VCS_ZCODE_APPROVED_REPRODUCER_REQUIRED_FLAGS \
    (VCS_ZCODE_SHADOW_SIMULATION_ONLY | \
     VCS_ZCODE_SHADOW_NOT_OWNER_APPROVED)
#define VCS_ZCODE_POLICY_CANDIDATE_REQUIRED_FLAGS \
    (VCS_ZCODE_APPROVED_REPRODUCER_REQUIRED_FLAGS | \
     VCS_ZCODE_SHADOW_NO_CARRY_FORWARD | \
     VCS_ZCODE_SHADOW_COMPLETE_ATTRIBUTION)

#define VCS_ZC23_CAP_ALGORITHM_WHOLE_TOKEN_HALVING_V1 1u
#define VCS_ZC23_POLICY_CANDIDATE_VERSION 1u
#define VCS_ZC23_BASE_EPOCH_TOKENS UINT64_C(50000)
#define VCS_ZC23_SHADOW_PUBLIC_SOURCE_ATOMS UINT64_C(100000000)
#define VCS_ZC23_SHADOW_BORN_RED_ATOMS UINT64_C(50000000)
#define VCS_ZC23_SHADOW_INDEPENDENT_REPRODUCTION_ATOMS UINT64_C(25000000)
#define VCS_ZC23_SHADOW_COMPATIBILITY_ATOMS UINT64_C(25000000)
#define VCS_ZC23_SHADOW_PRESERVATION_ATOMS UINT64_C(12500000)
#define VCS_ZC23_SHADOW_CATEGORY_MASK UINT16_C(0x007e)

enum vcs_zcode_shadow_error {
    VCS_ZCODE_SHADOW_OK = 0,
    VCS_ZCODE_SHADOW_NULL,
    VCS_ZCODE_SHADOW_WIRE_SIZE,
    VCS_ZCODE_SHADOW_MAGIC,
    VCS_ZCODE_SHADOW_VERSION,
    VCS_ZCODE_SHADOW_FLAGS,
    VCS_ZCODE_SHADOW_RESERVED,
    VCS_ZCODE_SHADOW_ROOT,
    VCS_ZCODE_SHADOW_ORDER,
    VCS_ZCODE_SHADOW_DUPLICATE,
    VCS_ZCODE_SHADOW_LIMIT,
    VCS_ZCODE_SHADOW_TIME,
    VCS_ZCODE_SHADOW_EPOCH,
    VCS_ZCODE_SHADOW_ACTION,
    VCS_ZCODE_SHADOW_NOT_FOUND,
    VCS_ZCODE_SHADOW_NETWORK,
    VCS_ZCODE_SHADOW_POLICY,
    VCS_ZCODE_SHADOW_CATEGORY,
    VCS_ZCODE_SHADOW_AMOUNT,
    VCS_ZCODE_SHADOW_OVERFLOW,
};

struct vcs_zcode_approved_reproducer_entry_v1 {
    uint8_t signer_pubkey[32];
    uint8_t contributor_binding_root[32];
    uint8_t operator_group_root[32];
    uint8_t action_root[32];
    uint64_t valid_from_epoch;
    uint64_t valid_through_epoch;
    int64_t valid_from_unix;
    int64_t valid_through_unix;
};

struct vcs_zcode_approved_reproducer_set_v1 {
    uint16_t schema_version;
    uint16_t flags;
    uint64_t sequence;
    uint8_t network_genesis_root[32];
    uint8_t predecessor_set_root[32];
    struct vcs_zcode_approved_reproducer_entry_v1
        entries[VCS_ZCODE_APPROVED_REPRODUCER_MAX_ENTRIES];
    size_t entry_count;
};

struct vcs_zcode_policy_candidate_v1 {
    uint16_t schema_version;
    uint16_t flags;
    uint32_t policy_version;
    uint8_t ticker[4];
    uint8_t decimals;
    uint8_t cap_algorithm;
    uint16_t admitted_category_mask;
    uint64_t challenge_blocks;
    int64_t challenge_seconds;
    uint64_t initial_supply_atoms;
    uint64_t atoms_per_token;
    uint64_t epochs_per_era;
    uint64_t base_epoch_tokens;
    uint64_t maximum_supply_atoms;
    uint8_t network_genesis_root[32];
    uint8_t approved_reproducer_set_root[32];
    uint8_t covenant_document_root[32];
    uint64_t award_atoms[6];
};

const char *vcs_zcode_shadow_error_string(enum vcs_zcode_shadow_error error);

void vcs_zcode_approved_reproducer_set_init(
    struct vcs_zcode_approved_reproducer_set_v1 *set);
enum vcs_zcode_shadow_error vcs_zcode_approved_reproducer_set_add(
    struct vcs_zcode_approved_reproducer_set_v1 *set,
    const struct vcs_zcode_approved_reproducer_entry_v1 *entry);
enum vcs_zcode_shadow_error vcs_zcode_approved_reproducer_set_validate(
    const struct vcs_zcode_approved_reproducer_set_v1 *set);
enum vcs_zcode_shadow_error vcs_zcode_approved_reproducer_set_serialize(
    const struct vcs_zcode_approved_reproducer_set_v1 *set,
    uint8_t *out, size_t out_capacity, size_t *out_len);
enum vcs_zcode_shadow_error vcs_zcode_approved_reproducer_set_parse(
    const uint8_t *wire, size_t wire_len,
    struct vcs_zcode_approved_reproducer_set_v1 *out);
enum vcs_zcode_shadow_error vcs_zcode_approved_reproducer_set_root(
    const struct vcs_zcode_approved_reproducer_set_v1 *set, uint8_t out[32]);
enum vcs_zcode_shadow_error vcs_zcode_approved_reproducer_set_find(
    const struct vcs_zcode_approved_reproducer_set_v1 *set,
    const uint8_t signer_pubkey[32], const uint8_t action_root[32],
    uint64_t epoch, int64_t receipt_unix,
    struct vcs_zcode_approved_reproducer_entry_v1 *out);

void vcs_zcode_policy_candidate_init(
    struct vcs_zcode_policy_candidate_v1 *policy,
    const uint8_t network_genesis_root[32],
    const uint8_t approved_reproducer_set_root[32],
    const uint8_t covenant_document_root[32]);
enum vcs_zcode_shadow_error vcs_zcode_policy_candidate_validate(
    const struct vcs_zcode_policy_candidate_v1 *policy);
enum vcs_zcode_shadow_error vcs_zcode_policy_candidate_validate_set(
    const struct vcs_zcode_policy_candidate_v1 *policy,
    const struct vcs_zcode_approved_reproducer_set_v1 *set);
enum vcs_zcode_shadow_error vcs_zcode_policy_candidate_serialize(
    const struct vcs_zcode_policy_candidate_v1 *policy,
    uint8_t out[VCS_ZCODE_POLICY_CANDIDATE_WIRE_BYTES]);
enum vcs_zcode_shadow_error vcs_zcode_policy_candidate_parse(
    const uint8_t *wire, size_t wire_len,
    struct vcs_zcode_policy_candidate_v1 *out);
enum vcs_zcode_shadow_error vcs_zcode_policy_candidate_root(
    const struct vcs_zcode_policy_candidate_v1 *policy, uint8_t out[32]);
enum vcs_zcode_shadow_error vcs_zcode_policy_candidate_award_atoms(
    const struct vcs_zcode_policy_candidate_v1 *policy, uint16_t category,
    uint64_t *out_atoms);

/* Shadow accounting never accepts a caller-selected award callback. This
 * wrapper derives every award from `policy`, while forwarding chain and
 * uniqueness observations through the existing epoch verifier. */
enum vcs_zcode_epoch_creation_error vcs_zcode_shadow_epoch_verify_cas(
    const struct vcs_zcode_epoch_creation_set_v1 *set,
    const struct vcs_zcode_epoch_creation_validation_context *context,
    const struct vcs_zcode_policy_candidate_v1 *policy);

#endif /* ZCL_VCS_ZCODE_SHADOW_POLICY_H */
