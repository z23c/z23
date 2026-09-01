/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: owner-decided Proof-of-Participation emission schedule, encoded
 * as a simulation-only epoch proposer alongside the frozen era curve. */
#ifndef ZCL_VCS_ZCODE_EPOCH_SCHEDULE_H
#define ZCL_VCS_ZCODE_EPOCH_SCHEDULE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "vcs/zcode_creation_attribution.h"

/* The decided rules live in docs/work/ZC23_DISTRIBUTION_RULES.md: a hard cap
 * of 21,000,000 ZC23 and a weekly epoch budget of (cap - already_emitted) /
 * 1040, split pro-rata by class weight over the verified evidence graph.
 * This module is a proposal/projection surface only: nothing here mints,
 * moves funds, or touches the frozen vcs_zc23_policy_epoch_cap_atoms curve. */
#define VCS_ZCODE_EPOCH_SCHEDULE_DOMAIN \
    "zcl.zcode.epoch_schedule_proposal.v1"
#define VCS_ZCODE_EPOCH_SCHEDULE_VERSION 1u
#define VCS_ZC23_SCHEDULE_CAP_ATOMS UINT64_C(2100000000000000)
#define VCS_ZC23_SCHEDULE_TOTAL_EPOCHS UINT64_C(1040)

#define VCS_ZCODE_EPOCH_SCHEDULE_HEADER_BYTES 100u
#define VCS_ZCODE_EPOCH_SCHEDULE_ALLOCATION_BYTES 44u
#define VCS_ZCODE_EPOCH_SCHEDULE_MAX_ALLOCATIONS 4096u
#define VCS_ZCODE_EPOCH_SCHEDULE_MAX_WIRE_BYTES \
    (VCS_ZCODE_EPOCH_SCHEDULE_HEADER_BYTES + \
     VCS_ZCODE_EPOCH_SCHEDULE_MAX_ALLOCATIONS * \
     VCS_ZCODE_EPOCH_SCHEDULE_ALLOCATION_BYTES)

/* The preservation class is decided (weight 5) but has no availability-proof
 * source yet, so a v1 proposal never allocates it: preservation evidence is
 * counted and skipped with this named reason. */
#define VCS_ZCODE_EPOCH_SCHEDULE_PRESERVATION_SKIP_REASON \
    "preservation_availability_proof_unavailable"

enum vcs_zcode_epoch_schedule_class {
    VCS_ZCODE_EPOCH_SCHEDULE_CLASS_CREATION = 1,
    VCS_ZCODE_EPOCH_SCHEDULE_CLASS_REPRODUCTION = 2,
    VCS_ZCODE_EPOCH_SCHEDULE_CLASS_REPAIR = 3,
    VCS_ZCODE_EPOCH_SCHEDULE_CLASS_PRESERVATION = 4,
};

enum vcs_zcode_epoch_schedule_error {
    VCS_ZCODE_EPOCH_SCHEDULE_OK = 0,
    VCS_ZCODE_EPOCH_SCHEDULE_NULL,
    VCS_ZCODE_EPOCH_SCHEDULE_ALLOC,
    VCS_ZCODE_EPOCH_SCHEDULE_WIRE_SIZE,
    VCS_ZCODE_EPOCH_SCHEDULE_MAGIC,
    VCS_ZCODE_EPOCH_SCHEDULE_SCHEMA,
    VCS_ZCODE_EPOCH_SCHEDULE_RESERVED,
    VCS_ZCODE_EPOCH_SCHEDULE_EPOCH,
    VCS_ZCODE_EPOCH_SCHEDULE_PREDECESSOR,
    VCS_ZCODE_EPOCH_SCHEDULE_CAP,
    VCS_ZCODE_EPOCH_SCHEDULE_SUM,
    VCS_ZCODE_EPOCH_SCHEDULE_ORDER,
    VCS_ZCODE_EPOCH_SCHEDULE_CLASS,
    VCS_ZCODE_EPOCH_SCHEDULE_OVERFLOW,
    VCS_ZCODE_EPOCH_SCHEDULE_CAS,
};

struct vcs_zcode_epoch_schedule_allocation {
    uint8_t contributor_binding_root[32];
    uint16_t schedule_class;
    uint64_t award_atoms;
};

struct vcs_zcode_epoch_schedule_proposal_v1 {
    uint16_t schema_version;
    uint64_t epoch;
    uint64_t budget_atoms;
    uint64_t already_emitted_atoms;
    uint64_t proposed_mint_atoms;
    uint64_t unissued_atoms;
    uint32_t evidence_count;
    uint32_t eligible_count;
    uint32_t preservation_skipped;
    uint8_t previous_proposal_root[32];
    struct vcs_zcode_epoch_schedule_allocation *allocations;
    size_t allocation_count;
};

struct vcs_zcode_epoch_schedule_input {
    const char *workspace;
    uint64_t epoch;
    /* Schedule epoch 1 is the bootstrap: it carries an all-zero predecessor.
     * Every later epoch names the committed proposal root of epoch - 1. */
    const uint8_t *previous_proposal_root;
};

const char *vcs_zcode_epoch_schedule_error_string(
    enum vcs_zcode_epoch_schedule_error error);

/* Participation class for a creation-attribution category. Public source is
 * creation, independent reproduction is reproduction, the fix/port categories
 * are repair, and preservation maps to the (currently skipped) class. */
enum vcs_zcode_epoch_schedule_class vcs_zcode_epoch_schedule_class_for_category(
    uint16_t category);
bool vcs_zcode_epoch_schedule_class_weight(
    enum vcs_zcode_epoch_schedule_class schedule_class, uint64_t *out_weight);

/* budget = (cap - already_emitted) / 1040. already_emitted above the cap is
 * a CAP failure; exactly-at-cap yields a zero budget, never a negative one. */
enum vcs_zcode_epoch_schedule_error vcs_zc23_schedule_epoch_budget_atoms(
    uint64_t already_emitted_atoms, uint64_t *out_atoms);

void vcs_zcode_epoch_schedule_proposal_init(
    struct vcs_zcode_epoch_schedule_proposal_v1 *proposal);
void vcs_zcode_epoch_schedule_proposal_free(
    struct vcs_zcode_epoch_schedule_proposal_v1 *proposal);
enum vcs_zcode_epoch_schedule_error vcs_zcode_epoch_schedule_validate(
    const struct vcs_zcode_epoch_schedule_proposal_v1 *proposal);
enum vcs_zcode_epoch_schedule_error vcs_zcode_epoch_schedule_serialize(
    const struct vcs_zcode_epoch_schedule_proposal_v1 *proposal,
    uint8_t **out, size_t *out_len);
enum vcs_zcode_epoch_schedule_error vcs_zcode_epoch_schedule_parse(
    const uint8_t *wire, size_t wire_len,
    struct vcs_zcode_epoch_schedule_proposal_v1 *out);
enum vcs_zcode_epoch_schedule_error vcs_zcode_epoch_schedule_root(
    const struct vcs_zcode_epoch_schedule_proposal_v1 *proposal,
    uint8_t out[32]);

/* Read-only proposer: rebuilds the commons projection, takes its minted
 * totals as already_emitted, splits the epoch budget pro-rata by class
 * weight over that epoch's verified evidence, and writes nothing. An epoch
 * with no eligible evidence proposes zero mint (non-issuance is not
 * redistribution); preservation evidence is counted and skipped. */
enum vcs_zcode_epoch_schedule_error vcs_zcode_epoch_schedule_propose_cas(
    const struct vcs_zcode_epoch_schedule_input *input,
    struct vcs_zcode_epoch_schedule_proposal_v1 *out);

#endif /* ZCL_VCS_ZCODE_EPOCH_SCHEDULE_H */
