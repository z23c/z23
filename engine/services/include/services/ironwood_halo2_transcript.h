/* purpose: Frame Halo2 transcript input and derive challenge bytes. */
/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#ifndef ZCL_IRONWOOD_HALO2_TRANSCRIPT_H
#define ZCL_IRONWOOD_HALO2_TRANSCRIPT_H

#include "base/result.h"
#include "crypto/blake2b.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Framing only: callers must validate and decode points and scalars, enforce
 * proof ordering, and reduce challenge bytes to the appropriate field. This
 * interface does not verify a proof or decide transaction validity. */
struct ironwood_halo2_transcript {
    struct blake2b_ctx hash;
    bool initialized;
};

struct zcl_result ironwood_halo2_transcript_init(struct ironwood_halo2_transcript *t);
/* A point is its canonical 32-byte little-endian affine x followed by y;
 * a scalar is its canonical 32-byte little-endian field representation. */
struct zcl_result ironwood_halo2_transcript_point(struct ironwood_halo2_transcript *t,
                                                   const uint8_t *point, size_t size);
struct zcl_result ironwood_halo2_transcript_scalar(struct ironwood_halo2_transcript *t,
                                                    const uint8_t *scalar, size_t size);
/* Appends the challenge delimiter and returns 64 raw bytes; state advances. */
struct zcl_result ironwood_halo2_transcript_challenge(struct ironwood_halo2_transcript *t,
                                                       uint8_t *out, size_t size);
#endif
