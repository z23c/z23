/* purpose: Frame public PostNu6_3 Ironwood proof inputs through x. */
/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#ifndef ZCL_IRONWOOD_POSTNU63_H
#define ZCL_IRONWOOD_POSTNU63_H
#include "base/result.h"
#include "codec/cursor.h"
#include "services/ironwood_halo2_transcript.h"
#include "services/ironwood_instance.h"
#include <stddef.h>
#include <stdint.h>

struct v6_wire_view;
enum ironwood_postnu63_phase { IRONWOOD_POSTNU63_THETA = 1, IRONWOOD_POSTNU63_BETA_GAMMA, IRONWOOD_POSTNU63_Y_X };
struct ironwood_postnu63_stage {
    struct ironwood_halo2_transcript transcript;
    struct zcl_codec_reader proof;
    uint8_t theta[32], beta[32], gamma[32], y[32], x[32];
    uint64_t actions;
    size_t lookup_offset, lookup_size;
    size_t permutation_offset, product_offset, random_offset, quotient_offset;
    enum ironwood_postnu63_phase phase;
};
/* Orchard 0.16.0 PostNu6_3 canonical proof size, with checked arithmetic. */
struct zcl_result ironwood_postnu63_proof_size(uint64_t count, size_t *out);
/* Public framing only. Parameters are supplied by the caller and are not
 * authenticated here. Success does not mean that the proof is valid. The
 * view and full proof bytes must remain alive while the returned cursor is
 * used. Output is unchanged on failure and must not overlap any input. */
struct zcl_result ironwood_postnu63_first_challenge(
    const struct v6_wire_view *view, const uint8_t vk[32], const uint8_t basis[IRONWOOD_INSTANCE_ROWS][32],
    const uint8_t w[32], struct ironwood_postnu63_stage *out);
/* Read the three input/table lookup pairs per action, then squeeze beta
 * and gamma. The stage and cursor are unchanged on failure. The retained
 * proof bytes at lookup_offset/lookup_size are public compressed points.
 * This only frames input and does not verify the proof. */
struct zcl_result ironwood_postnu63_lookup_challenges(struct ironwood_postnu63_stage *stage);
/* Frame permutation products, lookup products, random polynomial and the
 * eight quotient commitments through y and x. Offsets are relative to proof
 * start; the first two spans contain three points per action, random one
 * point and quotient eight points. All state is unchanged on failure. */
struct zcl_result ironwood_postnu63_yx_challenges(struct ironwood_postnu63_stage *stage);
#endif
