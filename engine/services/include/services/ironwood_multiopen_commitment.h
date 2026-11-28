/* purpose: Fold ordered public Halo2 multiopening commitments. */
/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#ifndef ZCL_IRONWOOD_MULTIOPEN_COMMITMENT_H
#define ZCL_IRONWOOD_MULTIOPEN_COMMITMENT_H
#include "base/result.h"
#include "services/ironwood_multiopen.h"
#include <stddef.h>
#include <stdint.h>

enum { IRONWOOD_MULTIOPEN_GROUPS = IRONWOOD_MULTIOPEN_SETS };
enum ironwood_multiopen_point_kind { IRONWOOD_MULTIOPEN_PROOF_POINT, IRONWOOD_MULTIOPEN_DERIVED_POINT };
struct ironwood_multiopen_commitment {
    unsigned group;
    enum ironwood_multiopen_point_kind kind;
    uint8_t point[32];
};
/* Items are supplied in the source-derived commitment-map order. A derived
 * point may be identity (e.g. folded H); proof points and q_prime may not.
 * The caller authenticates the map, grouping, points and challenges. This
 * public variable-time fold is not proof verification. Output is a compressed
 * Vesta point and remains unchanged on failure. */
struct zcl_result ironwood_multiopen_commitment_fold(
    const struct ironwood_multiopen_commitment *items, size_t count,
    const uint8_t q_prime[32], const uint8_t x1[32], const uint8_t x4[32], uint8_t out[32]);
/* Callback is invoked once per item in reverse ordinal order; its result is
 * copied before the next call. It must not mutate the fold inputs. */
typedef struct zcl_result (*ironwood_multiopen_item_at)(void *context, size_t ordinal,
    struct ironwood_multiopen_commitment *out);
struct zcl_result ironwood_multiopen_commitment_fold_stream(
    ironwood_multiopen_item_at item_at, void *context, size_t count,
    const uint8_t q_prime[32], const uint8_t x1[32], const uint8_t x4[32], uint8_t out[32]);
#endif
