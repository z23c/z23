/* purpose: Bind the complete resident PostNu6_3 verification setup. */
/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#ifndef ZCL_IRONWOOD_VERIFICATION_SETUP_H
#define ZCL_IRONWOOD_VERIFICATION_SETUP_H

#include "services/ironwood_opening_equation.h"
#include "services/ironwood_postnu63_pinned_h.h"

struct ironwood_verification_setup {
    struct ironwood_postnu63_constraint_programs programs;
    const struct ironwood_opening_basis *opening_basis;
    const uint8_t *vk_scalar;
    const uint8_t (*instance_basis)[32];
    const uint8_t *blinding_base;
};

/* The only handle accepted by checked verification. All referenced objects
 * are immutable and have process lifetime. Pointer equality is intentional:
 * callers cannot substitute a partial or unauthenticated setup. */
const struct ironwood_verification_setup *
ironwood_postnu63_verification_setup(void);

struct zcl_result ironwood_postnu63_prepare_opening_trusted(
    const struct v6_wire_view *view,
    const struct ironwood_verification_setup *setup,
    struct ironwood_postnu63_stage *out);
struct zcl_result ironwood_postnu63_check_claim_trusted(
    const struct v6_wire_view *view,
    const struct ironwood_verification_setup *setup,
    const uint8_t commitment[32], const uint8_t evaluation[32], bool *holds);

#endif
