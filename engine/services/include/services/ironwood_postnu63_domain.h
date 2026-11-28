/* purpose: Evaluate the public PostNu6_3 verification-domain row factors. */
/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#ifndef ZCL_IRONWOOD_POSTNU63_DOMAIN_H
#define ZCL_IRONWOOD_POSTNU63_DOMAIN_H
#include "base/result.h"
#include <stdint.h>
struct ironwood_postnu63_stage;
struct ironwood_postnu63_domain_rows { uint8_t l0[32], last[32], active[32]; };
/* Compute L0, Llast, and 1-(Llast+Lblind) at stage x for k=11 and five
 * blinding rows. Omega must be a caller-authenticated canonical primitive
 * 2048th root; this function checks its order but does not authenticate it.
 * Domain-root challenges are refused. Output must not overlap inputs and is
 * unchanged on failure; stage and proof bytes are not modified. */
struct zcl_result ironwood_postnu63_domain_rows(const struct ironwood_postnu63_stage *stage,
    const uint8_t omega[32], struct ironwood_postnu63_domain_rows *out);
#endif
