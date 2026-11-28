/* purpose: Compute public Orchard MerkleCRH nodes with pinned parameters. */
/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#ifndef ZCL_IRONWOOD_MERKLE_CRH_H
#define ZCL_IRONWOOD_MERKLE_CRH_H
#include "base/result.h"
#include <stddef.h>
#include <stdint.h>
/* The parameter bytes are Q then 1024 S points, each canonical compressed
 * Pallas. Their exact SHA256 is checked on every call. The two inputs are
 * canonical little-endian Pallas base field elements; level is 0..31 from
 * leaves upward. Public inputs only; output unchanged on invalid input or
 * arithmetic failure. Upstream Sinsemilla bottom maps to the zero field
 * element. This primitive does not authenticate an anchor or update state. */
enum { IRONWOOD_MERKLE_PARAMETERS_SIZE = 32800 };
/* Check the pinned table without hashing a node. */
struct zcl_result ironwood_merkle_parameters_validate(const uint8_t *parameters, size_t parameters_size);
struct zcl_result ironwood_merkle_crh(unsigned level, const uint8_t left[32],
    const uint8_t right[32], const uint8_t *parameters, size_t parameters_size,
    uint8_t out[32]);
#endif
