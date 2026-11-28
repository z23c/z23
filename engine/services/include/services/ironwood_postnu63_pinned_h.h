/* purpose: Derive expected H using the pinned PostNu6_3 constraint programs. */
/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#ifndef ZCL_IRONWOOD_POSTNU63_PINNED_H_H
#define ZCL_IRONWOOD_POSTNU63_PINNED_H_H
#include "base/result.h"
#include <stddef.h>
#include <stdint.h>
struct ironwood_postnu63_stage;
struct ironwood_postnu63_program { const uint8_t *bytes; size_t size; };
struct ironwood_postnu63_constraint_programs {
    struct ironwood_postnu63_program custom, permutation, lookup;
};
/* Derive H from the parsed EVAL_X1 stage using the exact pinned Orchard
 * 0.16.0 PostNu6_3 programs and domain parameters. Program bytes are supplied
 * by the caller, copied and checked against source-derived SHA3-256 digests;
 * no caller-supplied evaluated terms are used. This pins a circuit version,
 * not a release identity, verification key or proof-validity decision. Inputs
 * must remain stable and disjoint from out. Output is unchanged on failure. */
struct zcl_result ironwood_postnu63_pinned_h(const struct ironwood_postnu63_stage *stage,
    const struct ironwood_postnu63_constraint_programs *programs, uint8_t out[32]);
#endif
