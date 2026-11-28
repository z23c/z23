/* purpose: Evaluate bounded public Halo2 multiopening scalar claims. */
/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#ifndef ZCL_IRONWOOD_MULTIOPEN_H
#define ZCL_IRONWOOD_MULTIOPEN_H
#include "base/result.h"
#include <stddef.h>
#include <stdint.h>

enum { IRONWOOD_MULTIOPEN_SETS = 5, IRONWOOD_MULTIOPEN_POINTS = 3 };
/* Each evaluation is already compressed across commitments at the matching
 * point, in the caller's source-derived query order. This structure does not
 * authenticate the grouping, commitments, evaluations or challenges. */
struct ironwood_multiopen_set {
    size_t count;
    uint8_t points[IRONWOOD_MULTIOPEN_POINTS][32];
    uint8_t evaluations[IRONWOOD_MULTIOPEN_POINTS][32];
    uint8_t u[32];
};
/* All values are canonical little-endian Vesta scalars and public. Returns
 * v only; this variable-time calculation does not verify a proof. Refuses
 * repeated points and x3 at a point. On failure out remains unchanged. */
struct zcl_result ironwood_multiopen_value(
    const struct ironwood_multiopen_set sets[IRONWOOD_MULTIOPEN_SETS],
    const uint8_t x2[32], const uint8_t x3[32], const uint8_t x4[32], uint8_t out[32]);
#endif
