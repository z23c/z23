/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: ordered epoch accounting for creation-backed ZC23 issuance. */
#ifndef ZCL_VCS_ZCODE_EPOCH_CREATION_H
#define ZCL_VCS_ZCODE_EPOCH_CREATION_H

#include <stddef.h>
#include <stdint.h>

#include "vcs/zcode_creation_attribution.h"

#define VCS_ZCODE_EPOCH_CREATION_DOMAIN "zcl.zcode.epoch_creation_set.v1"
#define VCS_ZCODE_EPOCH_CREATION_VERSION 1u
#define VCS_ZCODE_EPOCH_CREATION_HEADER_BYTES 276u
#define VCS_ZCODE_EPOCH_CREATION_MAX_ATTRIBUTIONS 4096u
#define VCS_ZCODE_EPOCH_CREATION_MAX_WIRE_BYTES \
    (VCS_ZCODE_EPOCH_CREATION_HEADER_BYTES + \
     VCS_ZCODE_EPOCH_CREATION_MAX_ATTRIBUTIONS * 32u)

enum vcs_zcode_epoch_creation_error {
    VCS_ZCODE_EPOCH_CREATION_OK = 0,
    VCS_ZCODE_EPOCH_CREATION_NULL,
    VCS_ZCODE_EPOCH_CREATION_ALLOC,
    VCS_ZCODE_EPOCH_CREATION_WIRE_SIZE,
    VCS_ZCODE_EPOCH_CREATION_MAGIC,
    VCS_ZCODE_EPOCH_CREATION_SCHEMA,
    VCS_ZCODE_EPOCH_CREATION_RESERVED,
    VCS_ZCODE_EPOCH_CREATION_ROOT,
    VCS_ZCODE_EPOCH_CREATION_ORDER,
    VCS_ZCODE_EPOCH_CREATION_PREDECESSOR,
    VCS_ZCODE_EPOCH_CREATION_CAP,
    VCS_ZCODE_EPOCH_CREATION_SUM,
    VCS_ZCODE_EPOCH_CREATION_TIME,
    VCS_ZCODE_EPOCH_CREATION_OVERFLOW,
    VCS_ZCODE_EPOCH_CREATION_CONTEXT,
    VCS_ZCODE_EPOCH_CREATION_CAS,
    VCS_ZCODE_EPOCH_CREATION_ATTRIBUTION,
    VCS_ZCODE_EPOCH_CREATION_DUPLICATE,
    VCS_ZCODE_EPOCH_CREATION_MINT,
    VCS_ZCODE_EPOCH_CREATION_IMMATURE,
    VCS_ZCODE_EPOCH_CREATION_REORG,
};

struct vcs_zcode_epoch_creation_set_v1 {
    uint16_t schema_version;
    uint64_t epoch;
    uint64_t emission_cap_atoms;
    uint64_t actual_mint_atoms;
    uint64_t unissued_atoms;
    uint8_t network_genesis_root[32];
    uint8_t zc23_policy_root[32];
    uint8_t previous_epoch_creation_root[32];
    uint8_t committee_evidence_snapshot_root[32];
    uint64_t opening_height;
    uint8_t opening_hash[32];
    int64_t opening_mtp;
    uint64_t maturity_height;
    uint8_t maturity_hash[32];
    int64_t maturity_mtp;
    uint8_t (*attribution_roots)[32];
    size_t attribution_count;
};

typedef bool (*vcs_zcode_epoch_award_atoms_fn)(
    void *opaque,
    const struct vcs_zcode_creation_attribution_v1 *attribution,
    uint64_t *expected_atoms);

struct vcs_zcode_epoch_creation_validation_context {
    const char *workspace;
    const uint8_t *expected_network_genesis_root;
    const uint8_t *expected_zc23_policy_root;
    const uint8_t *expected_previous_epoch_creation_root;
    uint64_t observed_actual_mint_atoms;
    uint64_t active_height;
    int64_t active_mtp;
    int64_t now_unix;
    vcs_zcode_creation_anchor_active_fn anchor_is_active;
    vcs_zcode_creation_duplicate_fn contribution_is_duplicate;
    vcs_zcode_creation_binding_current_fn binding_is_current;
    vcs_zcode_creation_continuity_duplicate_fn continuity_is_duplicate;
    vcs_zcode_epoch_award_atoms_fn award_atoms_for_creation;
    void *callback_opaque;
};

void vcs_zcode_epoch_creation_init(
    struct vcs_zcode_epoch_creation_set_v1 *set);
void vcs_zcode_epoch_creation_free(
    struct vcs_zcode_epoch_creation_set_v1 *set);
const char *vcs_zcode_epoch_creation_error_string(
    enum vcs_zcode_epoch_creation_error error);
enum vcs_zcode_epoch_creation_error vcs_zcode_epoch_creation_validate(
    const struct vcs_zcode_epoch_creation_set_v1 *set);
enum vcs_zcode_epoch_creation_error vcs_zcode_epoch_creation_serialize(
    const struct vcs_zcode_epoch_creation_set_v1 *set,
    uint8_t **out, size_t *out_len);
enum vcs_zcode_epoch_creation_error vcs_zcode_epoch_creation_parse(
    const uint8_t *wire, size_t wire_len,
    struct vcs_zcode_epoch_creation_set_v1 *out);
enum vcs_zcode_epoch_creation_error vcs_zcode_epoch_creation_root(
    const struct vcs_zcode_epoch_creation_set_v1 *set, uint8_t out[32]);
enum vcs_zcode_epoch_creation_error vcs_zcode_epoch_creation_verify_cas(
    const struct vcs_zcode_epoch_creation_set_v1 *set,
    const struct vcs_zcode_epoch_creation_validation_context *context);

/* Policy epoch 0 is the separately attributable initial 1.00000000 ZC23.
 * Policy epochs >=1 map (epoch-1)/208 to the frozen whole-token era curve. */
enum vcs_zcode_epoch_creation_error vcs_zc23_policy_epoch_cap_atoms(
    uint64_t epoch, uint64_t *out_atoms);

#endif /* ZCL_VCS_ZCODE_EPOCH_CREATION_H */
