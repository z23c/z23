/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: display-level development profiles over canonical ZCODE policies. */
#ifndef ZCL_VCS_ZCODE_DEV_PRODUCT_H
#define ZCL_VCS_ZCODE_DEV_PRODUCT_H

#include "vcs/zcode_dev.h"

#include <stdbool.h>

/* A profile name is convenience input, never canonical authority. The policy
 * below is the existing proof_policy.v1 object that tasks actually bind. The
 * booleans select fixed orchestration actions and are displayable requirements;
 * they do not create a new wire or proof kind. */
struct vcs_zcode_dev_profile {
    const char *name;
    struct vcs_zcode_proof_policy_v1 policy;
    bool warning_fatal;
    bool sanitizers;
    bool deterministic_fuzz;
    bool local_reproduction;
    bool separate_review;
    bool approved_reproduction;
};

/* Expands quick, standard, strong, or release. Unknown input returns false and
 * zeroes the complete output. */
bool vcs_zcode_dev_profile_expand(
    const char *name, struct vcs_zcode_dev_profile *out);

#endif /* ZCL_VCS_ZCODE_DEV_PRODUCT_H */
