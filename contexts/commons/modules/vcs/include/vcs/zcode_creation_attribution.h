/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: canonical factual attribution for policy-eligible ZC23 creation. */
#ifndef ZCL_VCS_ZCODE_CREATION_ATTRIBUTION_H
#define ZCL_VCS_ZCODE_CREATION_ATTRIBUTION_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define VCS_ZCODE_CREATION_ATTRIBUTION_DOMAIN \
    "zcl.zcode.creation_attribution.v1"
#define VCS_ZCODE_CREATION_ATTRIBUTION_VERSION 1u
#define VCS_ZCODE_CREATION_ATTRIBUTION_WIRE_BYTES 520u

#define VCS_ZC23_DECIMALS 8u
#define VCS_ZC23_ATOMS_PER_TOKEN UINT64_C(100000000)
#define VCS_ZC23_INITIAL_SUPPLY_ATOMS UINT64_C(100000000)
#define VCS_ZC23_EPOCHS_PER_ERA UINT64_C(208)
#define VCS_ZC23_MAX_SUPPLY_ATOMS UINT64_C(2079875300000000)
#define VCS_ZC23_CHALLENGE_BLOCKS UINT64_C(8064)
#define VCS_ZC23_CHALLENGE_SECONDS INT64_C(604800)

enum vcs_zcode_creation_category {
    VCS_ZCODE_CREATION_PUBLIC_SOURCE = 1,
    VCS_ZCODE_CREATION_BORN_RED_FIX = 2,
    VCS_ZCODE_CREATION_SECURITY_FIX = 3,
    VCS_ZCODE_CREATION_INDEPENDENT_REPRODUCTION = 4,
    VCS_ZCODE_CREATION_COMPATIBILITY = 5,
    VCS_ZCODE_CREATION_PRESERVATION = 6,
};

enum vcs_zcode_creation_lineage_kind {
    VCS_ZCODE_CREATION_LINEAGE_NONE = 0,
    VCS_ZCODE_CREATION_LINEAGE_PREDECESSOR_ATTRIBUTION = 1,
    VCS_ZCODE_CREATION_LINEAGE_RELEASE = 2,
    VCS_ZCODE_CREATION_LINEAGE_CONTINUITY_POLICY = 3,
};

enum vcs_zcode_creation_error {
    VCS_ZCODE_CREATION_OK = 0,
    VCS_ZCODE_CREATION_NULL,
    VCS_ZCODE_CREATION_WIRE_SIZE,
    VCS_ZCODE_CREATION_MAGIC,
    VCS_ZCODE_CREATION_VERSION,
    VCS_ZCODE_CREATION_RESERVED,
    VCS_ZCODE_CREATION_CATEGORY,
    VCS_ZCODE_CREATION_LINEAGE,
    VCS_ZCODE_CREATION_ROOT,
    VCS_ZCODE_CREATION_AMOUNT,
    VCS_ZCODE_CREATION_TIME,
    VCS_ZCODE_CREATION_OVERFLOW,
    VCS_ZCODE_CREATION_CONTEXT,
    VCS_ZCODE_CREATION_CAS,
    VCS_ZCODE_CREATION_NETWORK,
    VCS_ZCODE_CREATION_POLICY,
    VCS_ZCODE_CREATION_EPOCH,
    VCS_ZCODE_CREATION_CONTRIBUTOR,
    VCS_ZCODE_CREATION_TASK,
    VCS_ZCODE_CREATION_CANDIDATE,
    VCS_ZCODE_CREATION_PROOF_POLICY,
    VCS_ZCODE_CREATION_PROOF_SET,
    VCS_ZCODE_CREATION_LANE,
    VCS_ZCODE_CREATION_SCORE,
    VCS_ZCODE_CREATION_PACKAGE,
    VCS_ZCODE_CREATION_RELEASE,
    VCS_ZCODE_CREATION_LICENSE,
    VCS_ZCODE_CREATION_CONTINUITY,
    VCS_ZCODE_CREATION_IMMATURE,
    VCS_ZCODE_CREATION_REORG,
    VCS_ZCODE_CREATION_DUPLICATE,
};

struct vcs_zcode_creation_attribution_v1 {
    uint16_t schema_version;
    uint16_t category;
    uint8_t lineage_kind;
    uint64_t epoch;
    uint64_t award_atoms;
    uint64_t challenge_opening_height;
    uint8_t challenge_opening_hash[32];
    int64_t challenge_opening_mtp;
    uint64_t challenge_maturity_height;
    int64_t challenge_maturity_mtp;
    int64_t created_unix;
    uint8_t network_genesis_root[32];
    uint8_t zc23_policy_root[32];
    uint8_t contributor_binding_root[32];
    uint8_t task_root[32];
    uint8_t candidate_root[32];
    uint8_t proof_policy_root[32];
    uint8_t proof_set_root[32];
    uint8_t proven_lane_root[32];
    uint8_t score_receipt_root[32];
    uint8_t package_root[32];
    uint8_t release_root[32];
    uint8_t license_evidence_root[32];
    uint8_t lineage_root[32];
};

typedef bool (*vcs_zcode_creation_anchor_active_fn)(
    void *opaque, uint64_t height, const uint8_t block_hash[32]);
typedef bool (*vcs_zcode_creation_duplicate_fn)(
    void *opaque, const uint8_t candidate_root[32],
    const uint8_t attribution_root[32]);
typedef bool (*vcs_zcode_creation_binding_current_fn)(
    void *opaque, const uint8_t contributor_binding_root[32]);
typedef bool (*vcs_zcode_creation_continuity_duplicate_fn)(
    void *opaque, const uint8_t event_key[32],
    const uint8_t attribution_root[32]);

/* Cross-object verification pins policy decisions supplied by the immutable
 * genesis-policy evaluator. Callbacks resolve active-chain and uniqueness
 * facts; they are mandatory so an adapter cannot silently assume either.
 *
 * Authorship is historical: the referenced contributor binding is verified
 * at candidate.created_unix. `now_unix` evaluates challenge maturity only.
 * `binding_is_current` is retained for source compatibility with financial
 * contexts, but creation verification never consults it; payout authority
 * must be checked separately at the time of a financial action. */
struct vcs_zcode_creation_validation_context {
    const char *workspace;
    const uint8_t *expected_network_genesis_root;
    const uint8_t *expected_zc23_policy_root;
    uint64_t expected_epoch;
    uint64_t expected_award_atoms;
    uint64_t active_height;
    int64_t active_mtp;
    int64_t now_unix;
    vcs_zcode_creation_anchor_active_fn anchor_is_active;
    vcs_zcode_creation_duplicate_fn contribution_is_duplicate;
    vcs_zcode_creation_binding_current_fn binding_is_current;
    vcs_zcode_creation_continuity_duplicate_fn continuity_is_duplicate;
    void *callback_opaque;
};

const char *vcs_zcode_creation_error_string(
    enum vcs_zcode_creation_error error);
enum vcs_zcode_creation_error vcs_zcode_creation_attribution_validate(
    const struct vcs_zcode_creation_attribution_v1 *attribution);
enum vcs_zcode_creation_error vcs_zcode_creation_attribution_serialize(
    const struct vcs_zcode_creation_attribution_v1 *attribution,
    uint8_t out[VCS_ZCODE_CREATION_ATTRIBUTION_WIRE_BYTES]);
enum vcs_zcode_creation_error vcs_zcode_creation_attribution_parse(
    const uint8_t *wire, size_t wire_len,
    struct vcs_zcode_creation_attribution_v1 *out);
enum vcs_zcode_creation_error vcs_zcode_creation_attribution_root(
    const struct vcs_zcode_creation_attribution_v1 *attribution,
    uint8_t out[32]);
enum vcs_zcode_creation_error vcs_zcode_creation_attribution_verify_cas(
    const struct vcs_zcode_creation_attribution_v1 *attribution,
    const struct vcs_zcode_creation_validation_context *context);

/* Whole-token emission is converted to atoms after the floor. No fractional
 * tail exists. Every failure zeroes a non-null output. */
enum vcs_zcode_creation_error vcs_zc23_epoch_cap_atoms(
    uint64_t era, uint64_t *out_atoms);
enum vcs_zcode_creation_error vcs_zc23_max_supply_atoms(
    uint64_t *out_atoms);

#endif /* ZCL_VCS_ZCODE_CREATION_ATTRIBUTION_H */
