/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: read-only rebuildable projection of the ZC23 Living Commons. */
#ifndef ZCL_VCS_ZCODE_COMMONS_PROJECTION_H
#define ZCL_VCS_ZCODE_COMMONS_PROJECTION_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "vcs/zcode_commons.h"

#define VCS_ZCODE_COMMONS_PROJECTION_DOMAIN \
    "zcl.zcode.commons_projection.v1"
#define VCS_ZCODE_COMMONS_CLAIM_PROJECTION_DOMAIN \
    "zcl.zcode.commons_claim_projection.v1"
#define VCS_ZCODE_COMMONS_PROJECTION_MAX_OBJECTS 4096u

enum vcs_zcode_commons_verification_status {
    VCS_ZCODE_COMMONS_UNKNOWN = 0,
    VCS_ZCODE_COMMONS_PARTIAL = 1,
    VCS_ZCODE_COMMONS_COMPLETE = 2,
};

struct vcs_zcode_commons_creation_entry {
    uint8_t root[32];
    uint8_t package_root[32];
    uint8_t release_root[32];
    uint8_t candidate_root[32];
    uint8_t contributor_binding_root[32];
    uint64_t epoch;
    uint64_t award_atoms;
    uint16_t category;
};

struct vcs_zcode_commons_epoch_entry {
    uint8_t root[32];
    uint8_t previous_root[32];
    uint64_t epoch;
    uint64_t cap_atoms;
    uint64_t minted_atoms;
    uint64_t unissued_atoms;
    uint32_t attribution_count;
};

struct vcs_zcode_commons_projection;

/* Read-only: a missing .zvcs/objects directory yields an empty UNKNOWN
 * projection and creates no path. Recognized corrupt objects are retained as
 * the first integrity failure; unrelated CAS citizens are ignored. */
struct vcs_zcode_commons_projection *vcs_zcode_commons_projection_build(
    const char *workspace);
void vcs_zcode_commons_projection_free(
    struct vcs_zcode_commons_projection *projection);
enum vcs_zcode_commons_verification_status
vcs_zcode_commons_projection_status(
    const struct vcs_zcode_commons_projection *projection);
size_t vcs_zcode_commons_projection_creation_count(
    const struct vcs_zcode_commons_projection *projection);
size_t vcs_zcode_commons_projection_epoch_count(
    const struct vcs_zcode_commons_projection *projection);
bool vcs_zcode_commons_claim_projection_ready(
    const struct vcs_zcode_commons_projection *projection);
size_t vcs_zcode_commons_projection_claim_count(
    const struct vcs_zcode_commons_projection *projection);
size_t vcs_zcode_commons_projection_eligible_claim_count(
    const struct vcs_zcode_commons_projection *projection,
    uint64_t cutoff_height, int64_t cutoff_mtp);
const struct vcs_zcode_creation_claim_v2 *
vcs_zcode_commons_projection_claim_at(
    const struct vcs_zcode_commons_projection *projection, size_t index);
const struct vcs_zcode_commons_creation_entry *
vcs_zcode_commons_projection_creation_at(
    const struct vcs_zcode_commons_projection *projection, size_t index);
const struct vcs_zcode_commons_epoch_entry *
vcs_zcode_commons_projection_epoch_at(
    const struct vcs_zcode_commons_projection *projection, size_t index);
uint64_t vcs_zcode_commons_projection_attributed_atoms(
    const struct vcs_zcode_commons_projection *projection);
uint64_t vcs_zcode_commons_projection_minted_atoms(
    const struct vcs_zcode_commons_projection *projection);
uint64_t vcs_zcode_commons_projection_unissued_atoms(
    const struct vcs_zcode_commons_projection *projection);
bool vcs_zcode_commons_projection_root(
    const struct vcs_zcode_commons_projection *projection, uint8_t out[32]);
bool vcs_zcode_commons_claim_projection_root(
    const struct vcs_zcode_commons_projection *projection, uint8_t out[32]);
bool vcs_zcode_commons_projection_first_failure(
    const struct vcs_zcode_commons_projection *projection,
    uint8_t root_out[32], const char **reason_out);

#endif /* ZCL_VCS_ZCODE_COMMONS_PROJECTION_H */
