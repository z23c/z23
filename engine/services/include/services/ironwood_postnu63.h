/* purpose: Frame public PostNu6_3 Ironwood proof inputs through theta. */
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
struct ironwood_postnu63_stage {
    struct ironwood_halo2_transcript transcript;
    struct zcl_codec_reader proof;
    uint8_t theta[32];
};
/* Orchard 0.16.0 PostNu6_3 canonical proof size, with checked arithmetic. */
struct zcl_result ironwood_postnu63_proof_size(uint64_t count, size_t *out);
/* Public framing only. Parameters are supplied by the caller and are not
 * authenticated here. Success does not mean that the proof is valid. The
 * view and full proof bytes must remain alive while the returned cursor is
 * used. Output is unchanged on failure and must not overlap any input. */
struct zcl_result ironwood_postnu63_first_challenge(
    const struct v6_wire_view *view, const uint8_t *proof, size_t proof_size,
    const uint8_t vk[32], const uint8_t basis[IRONWOOD_INSTANCE_ROWS][32],
    const uint8_t w[32], struct ironwood_postnu63_stage *out);
#endif
