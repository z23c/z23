/* purpose: Frame public PostNu6_3 Ironwood proof inputs through x. */
/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#include "services/ironwood_postnu63.h"
#include "primitives/transaction_v6_wire.h"

struct zcl_result ironwood_postnu63_proof_size(uint64_t count, size_t *out)
{
    if (!out || !count || count > (SIZE_MAX - 2720) / 2272)
        return ZCL_ERR(-1, "Invalid PostNu6_3 action count");
    *out = 2720 + (size_t)count * 2272;
    return ZCL_OK;
}

static struct zcl_result absorb_instances(struct ironwood_postnu63_stage *stage,
    const struct v6_wire_view *view, const uint8_t basis[IRONWOOD_INSTANCE_ROWS][32],
    const uint8_t w[32])
{
    for (uint64_t i = 0; i < view->ironwood.count; ++i) {
        struct ironwood_instance_rows rows;
        uint8_t encoded[32], affine[64];
        struct zcl_codec_reader reader;
        struct zcl_result result = ironwood_instance_project(view, i, &rows);
        if (!result.ok) return result;
        result = ironwood_instance_commitment(&rows, basis, w, encoded);
        if (!result.ok) return result;
        zcl_codec_reader_init(&reader, encoded, sizeof encoded);
        result = ironwood_halo2_read_point(&stage->transcript, &reader, affine, sizeof affine);
        if (!result.ok) return result;
    }
    return ZCL_OK;
}

static struct zcl_result absorb_advice(struct ironwood_postnu63_stage *stage, uint64_t count)
{
    uint8_t affine[64];
    for (uint64_t i = 0; i < count; ++i)
        for (size_t j = 0; j < 10; ++j) {
            struct zcl_result result = ironwood_halo2_read_point(&stage->transcript, &stage->proof,
                                                                affine, sizeof affine);
            if (!result.ok) return result;
        }
    return ZCL_OK;
}

struct zcl_result ironwood_postnu63_first_challenge(
    const struct v6_wire_view *view, const uint8_t vk[32], const uint8_t basis[IRONWOOD_INSTANCE_ROWS][32],
    const uint8_t w[32], struct ironwood_postnu63_stage *out)
{
    if (!view || !view->ironwood.proof.data || !vk || !basis || !w || !out)
        return ZCL_ERR(-1, "Missing PostNu6_3 framing input");
    size_t expected;
    struct zcl_result result = ironwood_postnu63_proof_size(view->ironwood.count, &expected);
    if (!result.ok) return result;
    if (view->ironwood.proof.size != expected) return ZCL_ERR(-1, "Noncanonical PostNu6_3 proof length");
    struct ironwood_postnu63_stage next = {0};
    struct zcl_codec_reader vk_reader;
    uint8_t scalar[32], wide[64];
    zcl_codec_reader_init(&vk_reader, vk, 32);
    result = ironwood_halo2_transcript_init(&next.transcript);
    if (result.ok) result = ironwood_halo2_read_scalar(&next.transcript, &vk_reader, scalar, sizeof scalar);
    if (result.ok) result = absorb_instances(&next, view, basis, w);
    zcl_codec_reader_init(&next.proof, view->ironwood.proof.data, view->ironwood.proof.size);
    if (result.ok) result = absorb_advice(&next, view->ironwood.count);
    if (result.ok) result = ironwood_halo2_transcript_challenge(&next.transcript, wide, sizeof wide);
    if (result.ok) result = ironwood_halo2_vesta_scalar(wide, sizeof wide, next.theta, sizeof next.theta);
    if (result.ok) { next.actions = view->ironwood.count; next.phase = IRONWOOD_POSTNU63_THETA; *out = next; }
    return result;
}

struct zcl_result ironwood_postnu63_lookup_challenges(struct ironwood_postnu63_stage *stage)
{
    if (!stage || stage->phase != IRONWOOD_POSTNU63_THETA || !stage->actions ||
        stage->actions > SIZE_MAX / 320 || stage->proof.position != (size_t)stage->actions * 320)
        return ZCL_ERR(-1, "Invalid PostNu6_3 lookup stage");
    struct ironwood_postnu63_stage next = *stage;
    next.lookup_offset = next.proof.position;
    uint8_t affine[64], wide[64];
    struct zcl_result result = ZCL_OK;
    for (uint64_t i = 0; result.ok && i < next.actions; ++i)
        for (size_t j = 0; result.ok && j < 6; ++j)
            result = ironwood_halo2_read_point(&next.transcript, &next.proof, affine, sizeof affine);
    next.lookup_size = next.proof.position - next.lookup_offset;
    if (result.ok) result = ironwood_halo2_transcript_challenge(&next.transcript, wide, sizeof wide);
    if (result.ok) result = ironwood_halo2_vesta_scalar(wide, sizeof wide, next.beta, sizeof next.beta);
    if (result.ok) result = ironwood_halo2_transcript_challenge(&next.transcript, wide, sizeof wide);
    if (result.ok) result = ironwood_halo2_vesta_scalar(wide, sizeof wide, next.gamma, sizeof next.gamma);
    if (result.ok) { next.phase = IRONWOOD_POSTNU63_BETA_GAMMA; *stage = next; }
    return result;
}

/* The returned offsets refer to the original proof; no commitment is copied. */
static struct zcl_result absorb_points(struct ironwood_postnu63_stage *stage, size_t count, size_t *offset)
{
    uint8_t affine[64];
    *offset = stage->proof.position;
    for (size_t i = 0; i < count; ++i) {
        struct zcl_result result = ironwood_halo2_read_point(&stage->transcript, &stage->proof,
                                                            affine, sizeof affine);
        if (!result.ok) return result;
    }
    return ZCL_OK;
}

static struct zcl_result squeeze_scalar(struct ironwood_postnu63_stage *stage, uint8_t out[32])
{
    uint8_t wide[64];
    struct zcl_result result = ironwood_halo2_transcript_challenge(&stage->transcript, wide, sizeof wide);
    return result.ok ? ironwood_halo2_vesta_scalar(wide, sizeof wide, out, 32) : result;
}

struct zcl_result ironwood_postnu63_yx_challenges(struct ironwood_postnu63_stage *stage)
{
    if (!stage || stage->phase != IRONWOOD_POSTNU63_BETA_GAMMA || !stage->actions ||
        stage->actions > SIZE_MAX / 512 || stage->proof.position != (size_t)stage->actions * 512)
        return ZCL_ERR(-1, "Invalid PostNu6_3 product stage");
    struct ironwood_postnu63_stage next = *stage;
    size_t per_action = (size_t)next.actions * 3;
    struct zcl_result result = absorb_points(&next, per_action, &next.permutation_offset);
    if (result.ok) result = absorb_points(&next, per_action, &next.product_offset);
    if (result.ok) result = absorb_points(&next, 1, &next.random_offset);
    if (result.ok) result = squeeze_scalar(&next, next.y);
    if (result.ok) result = absorb_points(&next, 8, &next.quotient_offset);
    if (result.ok) result = squeeze_scalar(&next, next.x);
    if (result.ok) { next.phase = IRONWOOD_POSTNU63_Y_X; *stage = next; }
    return result;
}
