/* purpose: Locate PostNu6_3 opening commitments and evaluations in verifier order. */
/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#ifndef ZCL_IRONWOOD_POSTNU63_QUERY_H
#define ZCL_IRONWOOD_POSTNU63_QUERY_H
#include "base/result.h"
#include <stddef.h>
#include <stdint.h>
enum { IRONWOOD_SHARED_OPENING_QUERIES = 46, IRONWOOD_ACTION_OPENING_QUERIES = 23 };
enum ironwood_query_source { IRONWOOD_QUERY_WIRE, IRONWOOD_QUERY_H, IRONWOOD_QUERY_VK, IRONWOOD_QUERY_INSTANCE };
struct ironwood_opening_query {
    enum ironwood_query_source source;
    const uint8_t *vk; /* Pinned 32-byte compressed point for VK rows. */
    size_t point, evaluation[3];
    unsigned set, count;
};
/* Zero-based indices. WIRE indexes the proof's initial commitments and
 * evaluation indexes the contiguous scalar section beginning at the instance
 * evaluations. VK enumerates the fifteen sigma commitments in reverse order
 * followed by twenty-nine fixed commitments in reverse fixed-query order.
 * INSTANCE indexes action statements. H denotes the derived quotient opening
 * for both point and evaluation, so its numeric indices are unused.
 * Ordinals run in increasing x1-power accumulation order within each set.
 * An action count n has 46 + 23*n entries. Errors leave out unchanged. */
struct zcl_result ironwood_postnu63_query_at(uint64_t actions, size_t ordinal,
                                             struct ironwood_opening_query *out);
struct v6_wire_view;
/* Derive the IPA evaluation from the pinned wire transcript and one externally
 * computed quotient evaluation H(x). The caller must derive H from the circuit.
 * Failure preserves out; inputs must remain stable and disjoint from out. */
struct zcl_result ironwood_postnu63_wire_value(const struct v6_wire_view *view,
                                                const uint8_t expected_h[32], uint8_t out[32]);
#endif
