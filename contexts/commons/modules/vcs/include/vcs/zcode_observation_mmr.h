/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: Bounded signed checkpoints for one issuer's observation-root log. */
#ifndef ZCL_VCS_ZCODE_OBSERVATION_MMR_H
#define ZCL_VCS_ZCODE_OBSERVATION_MMR_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define VCS_ZCODE_OBSERVATION_MMR_LEVELS 32u
#define VCS_ZCODE_OBSERVATION_MMR_BATCH_MAX 64u
#define VCS_ZCODE_OBSERVATION_MMR_WIRE_BYTES 1168u

/* A set bit in leaf_count identifies one occupied peak at that height.
 * Checkpoints authenticate ordered roots, not observation correctness. */
struct vcs_zcode_observation_mmr_checkpoint {
    uint32_t schema_version;
    uint8_t issuer[32];
    uint32_t leaf_count;
    int64_t observed_unix;
    uint8_t previous_checkpoint_root[32];
    uint8_t peaks[VCS_ZCODE_OBSERVATION_MMR_LEVELS][32];
    uint8_t signature[64];
};

bool vcs_zcode_observation_mmr_root(
    const struct vcs_zcode_observation_mmr_checkpoint *checkpoint,
    uint8_t out[32]);
bool vcs_zcode_observation_mmr_serialize(
    const struct vcs_zcode_observation_mmr_checkpoint *checkpoint,
    uint8_t wire[VCS_ZCODE_OBSERVATION_MMR_WIRE_BYTES]);
bool vcs_zcode_observation_mmr_parse(
    const uint8_t *wire, size_t wire_len, const uint8_t expected_issuer[32],
    struct vcs_zcode_observation_mmr_checkpoint *out);
bool vcs_zcode_observation_mmr_verify(
    const struct vcs_zcode_observation_mmr_checkpoint *checkpoint,
    const uint8_t expected_issuer[32]);
bool vcs_zcode_observation_mmr_extend(
    const struct vcs_zcode_observation_mmr_checkpoint *previous,
    const uint8_t *observation_roots, size_t root_count, int64_t observed_unix,
    const uint8_t secret[32], const uint8_t issuer[32],
    struct vcs_zcode_observation_mmr_checkpoint *out);
/* A null previous checkpoint requires exact replay from the empty log. */
bool vcs_zcode_observation_mmr_verify_extension(
    const struct vcs_zcode_observation_mmr_checkpoint *previous,
    const struct vcs_zcode_observation_mmr_checkpoint *next,
    const uint8_t *observation_roots, size_t root_count,
    const uint8_t expected_issuer[32]);

#endif
