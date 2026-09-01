/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: deterministic fixture-only C23 evidence snapshots and elections. */
#ifndef ZCL_VCS_ZCODE_SHADOW_ELECTION_H
#define ZCL_VCS_ZCODE_SHADOW_ELECTION_H

#include "vcs/zcode_seed.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define VCS_C23_EVIDENCE_SNAPSHOT_DOMAIN \
    "zcl.zcode.c23.evidence_snapshot.v1"
#define VCS_C23_SHADOW_ELECTION_DOMAIN \
    "zcl.zcode.c23.shadow_election.v1"
#define VCS_C23_SHADOW_ELECTION_SEED_DOMAIN \
    "zcl.zcode.c23.shadow_election_seed.v1"
#define VCS_C23_SHADOW_ELECTION_VERSION 1u
#define VCS_C23_SHADOW_ELECTION_BLOCKS 64u
#define VCS_C23_SHADOW_MAX_CANDIDATES 256u
#define VCS_C23_SHADOW_MAX_EVIDENCE 4096u
#define VCS_C23_SHADOW_MAX_SEATS 100u
#define VCS_C23_SHADOW_HISTORY_EPOCHS 26u
#define VCS_C23_SHADOW_MAX_WEIGHT 10000u
#define VCS_C23_SHADOW_CONCENTRATION_SCALE UINT64_C(1000000)

enum vcs_c23_shadow_election_error {
    VCS_C23_SHADOW_ELECTION_OK = 0,
    VCS_C23_SHADOW_ELECTION_NULL,
    VCS_C23_SHADOW_ELECTION_LIMIT,
    VCS_C23_SHADOW_ELECTION_ROOT,
    VCS_C23_SHADOW_ELECTION_NETWORK,
    VCS_C23_SHADOW_ELECTION_EPOCH,
    VCS_C23_SHADOW_ELECTION_DUPLICATE,
    VCS_C23_SHADOW_ELECTION_IDENTITY,
    VCS_C23_SHADOW_ELECTION_EVIDENCE,
    VCS_C23_SHADOW_ELECTION_OVERFLOW,
    VCS_C23_SHADOW_ELECTION_ANCHOR,
    VCS_C23_SHADOW_ELECTION_IMMATURE,
    VCS_C23_SHADOW_ELECTION_ALLOCATION,
    VCS_C23_SHADOW_ELECTION_SEATS,
};

struct vcs_c23_shadow_seed_input {
    const struct vcs_c23_seed_v1 *seed;
};

struct vcs_c23_shadow_evidence_input {
    uint8_t contribution_root[32];
    uint8_t zid_pubkey[32];
    uint64_t event_epoch;
    uint32_t points;
};

struct vcs_c23_evidence_snapshot_input {
    const uint8_t *network_genesis_root;
    const uint8_t *policy_root;
    const struct vcs_c23_shadow_seed_input *seeds;
    size_t seed_count;
    const struct vcs_c23_shadow_evidence_input *evidence;
    size_t evidence_count;
    uint64_t election_epoch;
    uint64_t freeze_height;
    const uint8_t *freeze_hash;
    uint64_t active_height;
    int64_t active_mtp;
    vcs_c23_seed_anchor_active_fn anchor_is_active;
    void *anchor_opaque;
};

struct vcs_c23_evidence_snapshot_row {
    uint8_t seed_root[32];
    uint8_t zid_pubkey[32];
    uint64_t weight;
};

struct vcs_c23_evidence_snapshot_v1 {
    uint16_t schema_version;
    uint64_t election_epoch;
    uint64_t freeze_height;
    uint8_t freeze_hash[32];
    uint8_t network_genesis_root[32];
    uint8_t policy_root[32];
    uint8_t evidence_set_root[32];
    uint8_t snapshot_root[32];
    uint64_t total_weight;
    size_t candidate_count;
    struct vcs_c23_evidence_snapshot_row *rows;
};

struct vcs_c23_shadow_election_input {
    const struct vcs_c23_evidence_snapshot_v1 *snapshot;
    uint64_t seed_start_height;
    const uint8_t (*seed_block_hashes)[32];
    size_t seat_count;
};

struct vcs_c23_shadow_election_seat {
    uint8_t seed_root[32];
    uint8_t zid_pubkey[32];
    uint64_t weight;
};

struct vcs_c23_shadow_election_v1 {
    uint16_t schema_version;
    uint64_t election_epoch;
    uint64_t seed_start_height;
    uint8_t snapshot_root[32];
    uint8_t election_seed_root[32];
    uint8_t election_root[32];
    uint64_t total_candidate_weight;
    uint64_t maximum_candidate_weight;
    uint64_t maximum_weight_ppm;
    uint64_t concentration_ppm;
    size_t seat_count;
    struct vcs_c23_shadow_election_seat *seats;
    bool simulation_only;
    bool authority_conferred;
};

const char *vcs_c23_shadow_election_error_string(
    enum vcs_c23_shadow_election_error error);
enum vcs_c23_shadow_election_error vcs_c23_evidence_snapshot_build(
    const struct vcs_c23_evidence_snapshot_input *input,
    struct vcs_c23_evidence_snapshot_row *rows, size_t row_capacity,
    struct vcs_c23_evidence_snapshot_v1 *out);
enum vcs_c23_shadow_election_error vcs_c23_shadow_election_build(
    const struct vcs_c23_shadow_election_input *input,
    struct vcs_c23_shadow_election_seat *seats, size_t seat_capacity,
    struct vcs_c23_shadow_election_v1 *out);

#endif /* ZCL_VCS_ZCODE_SHADOW_ELECTION_H */
