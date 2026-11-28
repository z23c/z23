/* purpose: Frame public PostNu6_3 Ironwood proof inputs through the IPA opening. */
/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#ifndef ZCL_IRONWOOD_POSTNU63_H
#define ZCL_IRONWOOD_POSTNU63_H
#include "base/result.h"
#include "codec/cursor.h"
#include "services/ironwood_halo2_transcript.h"
#include "services/ironwood_instance.h"
#include "services/ironwood_ipa.h"
#include <stddef.h>
#include <stdint.h>

struct v6_wire_view;
enum ironwood_postnu63_phase { IRONWOOD_POSTNU63_THETA = 1, IRONWOOD_POSTNU63_BETA_GAMMA, IRONWOOD_POSTNU63_Y_X, IRONWOOD_POSTNU63_EVAL_X1 };
struct ironwood_postnu63_stage {
    struct ironwood_halo2_transcript transcript;
    struct zcl_codec_reader proof;
    uint8_t theta[32], beta[32], gamma[32], y[32], x[32], x1[32];
    uint64_t actions;
    size_t lookup_offset, lookup_size;
    size_t permutation_offset, product_offset, random_offset, quotient_offset;
    size_t instance_eval_offset, advice_eval_offset, fixed_eval_offset, random_eval_offset;
    size_t sigma_eval_offset, permutation_eval_offset, lookup_eval_offset;
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
/* Frame the canonical evaluation scalars and opening challenge x1. Offsets
 * refer to the original proof. The stage is unchanged on failure. This does
 * not evaluate constraints, opening equations or proof validity. */
struct zcl_result ironwood_postnu63_evaluations(struct ironwood_postnu63_stage *stage);

/* The canonical-size PostNu6_3 wire layout carries five set evaluations.
 * Checking the query graph belongs to opening verification. Offsets index
 * compressed points in the proof retained by the input stage. */
enum { IRONWOOD_POSTNU63_OPENING_SETS = 5 };
struct ironwood_postnu63_opening {
    size_t quotient_commitment_offset, s_commitment_offset, round_points_offset;
    uint8_t x2[32], x3[32], x4[32], xi[32], z[32];
    uint8_t set_evaluations[IRONWOOD_POSTNU63_OPENING_SETS][32];
    uint8_t round_challenges[IRONWOOD_IPA_ROUNDS][32], c[32], f[32];
};
/* Decode the complete opening transcript starting at EVAL_X1. The input
 * snapshot is retained for constraint evaluation. The output must not overlap
 * the stage or its backing proof and is unchanged on failure. This function
 * does not evaluate the opening equation. */
struct zcl_result ironwood_postnu63_opening_transcript(
    const struct ironwood_postnu63_stage *stage, struct ironwood_postnu63_opening *out);
#endif
