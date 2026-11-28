/* purpose: Frame public PostNu6_3 Ironwood proof inputs through theta. */
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

struct zcl_result ironwood_postnu63_first_challenge(
    const struct v6_wire_view *view, const uint8_t *proof, size_t proof_size,
    const uint8_t vk[32], const uint8_t basis[IRONWOOD_INSTANCE_ROWS][32],
    const uint8_t w[32], struct ironwood_postnu63_stage *out)
{
    if (!view || !proof || !vk || !basis || !w || !out)
        return ZCL_ERR(-1, "Missing PostNu6_3 framing input");
    size_t expected;
    struct zcl_result result = ironwood_postnu63_proof_size(view->ironwood.count, &expected);
    if (!result.ok) return result;
    if (proof_size != expected) return ZCL_ERR(-1, "Noncanonical PostNu6_3 proof length");
    struct ironwood_postnu63_stage next = {0};
    struct zcl_codec_reader vk_reader;
    uint8_t scalar[32], affine[64], wide[64];
    zcl_codec_reader_init(&vk_reader, vk, 32);
    result = ironwood_halo2_transcript_init(&next.transcript);
    if (result.ok) result = ironwood_halo2_read_scalar(&next.transcript, &vk_reader, scalar, sizeof scalar);
    if (result.ok) result = absorb_instances(&next, view, basis, w);
    zcl_codec_reader_init(&next.proof, proof, proof_size);
    for (uint64_t i = 0; result.ok && i < view->ironwood.count; ++i)
        for (size_t j = 0; result.ok && j < 10; ++j)
            result = ironwood_halo2_read_point(&next.transcript, &next.proof, affine, sizeof affine);
    if (result.ok) result = ironwood_halo2_transcript_challenge(&next.transcript, wide, sizeof wide);
    if (result.ok) result = ironwood_halo2_vesta_scalar(wide, sizeof wide, next.theta, sizeof next.theta);
    if (result.ok) *out = next;
    return result;
}
