/* purpose: Fixed-width Pallas base-field arithmetic for isolated research. */
/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#ifndef IRONWOOD_PALLAS_FIELD_H
#define IRONWOOD_PALLAS_FIELD_H
#include <stdbool.h>
#include <stdint.h>
#include "util/result.h"
/* Elements are canonical little-endian 64-bit limbs, strictly below p.
 * Inputs and outputs may alias. These routines are not a wallet primitive:
 * secret-scalar and compiler-level constant-time qualification remain open. */
struct pallas_fp { uint64_t limb[4]; };
struct zcl_result pallas_fp_read(struct pallas_fp *out, const uint8_t bytes[32]);
void pallas_fp_write(uint8_t out[32], const struct pallas_fp *a);
void pallas_fp_add(struct pallas_fp *out, const struct pallas_fp *a, const struct pallas_fp *b);
void pallas_fp_sub(struct pallas_fp *out, const struct pallas_fp *a, const struct pallas_fp *b);
void pallas_fp_mul(struct pallas_fp *out, const struct pallas_fp *a, const struct pallas_fp *b);
/* Reject zero after fixed work; leave the output unchanged on refusal. */
struct zcl_result pallas_fp_invert(struct pallas_fp *out, const struct pallas_fp *a);
#endif
