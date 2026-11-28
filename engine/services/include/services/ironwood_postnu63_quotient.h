/* purpose: Fold public PostNu6_3 circuit evaluations into expected H. */
/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#ifndef ZCL_IRONWOOD_POSTNU63_QUOTIENT_H
#define ZCL_IRONWOOD_POSTNU63_QUOTIENT_H
#include "base/result.h"
#include <stddef.h>
#include <stdint.h>

struct ironwood_postnu63_stage;
/* Fold 215 caller-evaluated constraint scalars per action in circuit order.
 * Computes sum-by-Horner(terms, y)/(x^2048-1) in the Pasta Fp field. This is
 * conditional on the caller supplying the correct ordered circuit evaluations;
 * it does not evaluate constraints, authenticate parameters or verify a proof.
 * Inputs are public canonical little-endian scalars. Output is unchanged on
 * failure and must not overlap the stage or terms. */
struct zcl_result ironwood_postnu63_expected_h(const struct ironwood_postnu63_stage *stage,
                                                const uint8_t *terms, size_t terms_size,
                                                uint8_t out[32]);
#endif
