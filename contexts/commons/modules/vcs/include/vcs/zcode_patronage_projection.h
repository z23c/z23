/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: rebuildable read-only projection of simulation patronage objects. */
#ifndef ZCL_VCS_ZCODE_PATRONAGE_PROJECTION_H
#define ZCL_VCS_ZCODE_PATRONAGE_PROJECTION_H

#include "vcs/zcode_patronage.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define VCS_ZCODE_PATRONAGE_PROJECTION_DOMAIN \
    "zcl.zcode.patronage_projection.v1"
#define VCS_ZCODE_PATRONAGE_PROJECTION_MAX_OBJECTS 4096u

enum vcs_zcode_patronage_projection_kind {
    VCS_ZCODE_PATRONAGE_PROJECTION_OFFER = 1,
    VCS_ZCODE_PATRONAGE_PROJECTION_SIMULATED_FUNDING = 2,
    VCS_ZCODE_PATRONAGE_PROJECTION_CONTINUITY_POLICY = 3,
};

struct vcs_zcode_patronage_projection_entry {
    uint8_t root[32];
    uint8_t target_root[32];
    uint8_t kind;
    uint64_t amount_atoms;
    int64_t created_unix;
    int64_t expires_unix;
};

struct vcs_zcode_patronage_projection;

/* Historical verification evaluates each signed object at its own creation
 * time. `now_unix` is presentation time (active/expired), never authority. */
struct vcs_zcode_patronage_projection *
vcs_zcode_patronage_projection_build(
    const struct vcs_zcode_patronage_validation_context *context);
void vcs_zcode_patronage_projection_free(
    struct vcs_zcode_patronage_projection *projection);
size_t vcs_zcode_patronage_projection_count(
    const struct vcs_zcode_patronage_projection *projection);
const struct vcs_zcode_patronage_projection_entry *
vcs_zcode_patronage_projection_at(
    const struct vcs_zcode_patronage_projection *projection, size_t index);
bool vcs_zcode_patronage_projection_root(
    const struct vcs_zcode_patronage_projection *projection, uint8_t out[32]);
bool vcs_zcode_patronage_projection_first_failure(
    const struct vcs_zcode_patronage_projection *projection,
    uint8_t root_out[32], const char **reason_out);

#endif /* ZCL_VCS_ZCODE_PATRONAGE_PROJECTION_H */
