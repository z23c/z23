/* purpose: Check a public IPA opening against a supplied commitment and setup. */
/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#ifndef ZCL_IRONWOOD_OPENING_EQUATION_H
#define ZCL_IRONWOOD_OPENING_EQUATION_H
#include "services/ironwood_ipa.h"
#include <stdbool.h>
struct ironwood_postnu63_stage;
struct ironwood_opening_basis {
    uint8_t generators[IRONWOOD_IPA_GENERATORS][32], u[32], w[32];
};
/* The caller supplies the folded commitment (compressed Vesta), evaluation
 * (canonical little-endian Fp), and setup. The transcript and round points
 * come from the same EVAL_X1 proof stage. On success, holds reports the IPA
 * equation result relative to the supplied inputs. On error it is unchanged.
 * The holds output must be disjoint from the stage, its backing proof,
 * the supplied basis, the commitment, and the evaluation.
 * Verifying the whole proof also requires independently authenticated setup,
 * constraint evaluation and derivation of the folded commitment/evaluation. */
struct zcl_result ironwood_opening_equation(const struct ironwood_postnu63_stage *stage,
    const struct ironwood_opening_basis *basis, const uint8_t commitment[32],
    const uint8_t evaluation[32], bool *holds);
struct v6_wire_view;
/* Check an externally derived folded claim against the given wire view. The
 * function authenticates the IPA basis and derives all transcript challenges
 * using the pinned PostNu6_3 initialization parameters. Inputs must remain
 * stable during the call and disjoint from holds. Errors preserve holds.
 * Bundle verification also requires deriving the claim from the circuit. */
struct zcl_result ironwood_postnu63_check_claim(const struct v6_wire_view *view,
    const struct ironwood_opening_basis *basis, const uint8_t commitment[32],
    const uint8_t evaluation[32], bool *holds);
#endif
