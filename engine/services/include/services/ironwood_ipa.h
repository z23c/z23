/* purpose: Compute the public PostNu6_3 IPA evaluation coefficient. */
/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#ifndef ZCL_IRONWOOD_IPA_H
#define ZCL_IRONWOOD_IPA_H
#include "base/result.h"
#include <stdint.h>

/* For Halo2 Vesta at k=11: b = product_i(1 + u[10-i] * x^(2^i)).
 * x is the multi-opening x3 and u is the eleven IPA round challenges in
 * transcript order. Inputs are canonical little-endian Fp scalars and public;
 * operations are variable-time. Output is unchanged on failure and must not
 * overlap inputs. This coefficient alone does not verify an opening or proof. */
enum { IRONWOOD_IPA_ROUNDS = 11 };
struct zcl_result ironwood_ipa_compute_b(const uint8_t x[32],
    const uint8_t u[IRONWOOD_IPA_ROUNDS][32], uint8_t out[32]);
#endif
