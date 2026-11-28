/* purpose: Evaluate caller-supplied PostNu6_3 custom-gate expressions. */
/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#ifndef ZCL_IRONWOOD_POSTNU63_GATES_H
#define ZCL_IRONWOOD_POSTNU63_GATES_H
#include "base/result.h"
#include <stddef.h>
#include <stdint.h>
struct ironwood_postnu63_stage;
enum { IRONWOOD_POSTNU63_CUSTOM_GATES = 193, IRONWOOD_POSTNU63_GATE_BYTES = 193 * 32 };
/* Public postfix instructions: C + 32-byte canonical little-endian scalar;
 * F or A + one byte fixed/advice query index; N negates; S adds; M multiplies;
 * E closes an expression. Exactly 193 E instructions are required. The program
 * is caller-supplied circuit metadata and is not authenticated here. Results
 * are conditional on that metadata, not proof verification. `out` must not
 * overlap the stage, its proof bytes or the program and remains unchanged on
 * failure. The stage and its backing proof are never modified. */
struct zcl_result ironwood_postnu63_custom_gates(const struct ironwood_postnu63_stage *stage,
    uint64_t action, const uint8_t *program, size_t program_size,
    uint8_t *out, size_t out_size);
#endif
