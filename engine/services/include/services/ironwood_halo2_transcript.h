/* purpose: Frame Halo2 transcript input and derive challenge bytes. */
/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#ifndef ZCL_IRONWOOD_HALO2_TRANSCRIPT_H
#define ZCL_IRONWOOD_HALO2_TRANSCRIPT_H

#include "base/result.h"
#include "crypto/blake2b.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Low-level framing does not validate points or scalars. Callers enforce
 * proof ordering. This interface does not verify a proof or decide validity. */
struct ironwood_halo2_transcript {
    struct blake2b_ctx hash;
    bool initialized;
};
struct zcl_codec_reader;

struct zcl_result ironwood_halo2_transcript_init(struct ironwood_halo2_transcript *t);
/* A point is its canonical 32-byte little-endian affine x followed by y;
 * a scalar is its canonical 32-byte little-endian field representation. */
struct zcl_result ironwood_halo2_transcript_point(struct ironwood_halo2_transcript *t,
                                                   const uint8_t *point, size_t size);
struct zcl_result ironwood_halo2_transcript_scalar(struct ironwood_halo2_transcript *t,
                                                    const uint8_t *scalar, size_t size);
/* Read one canonical Vesta scalar from public proof bytes and absorb it.
 * On failure the reader, transcript and output are unchanged. Output must
 * not overlap the reader or transcript objects. This does not verify a proof. */
struct zcl_result ironwood_halo2_read_scalar(struct ironwood_halo2_transcript *t,
                                              struct zcl_codec_reader *reader,
                                              uint8_t *out, size_t size);
/* Read and absorb a canonical nonidentity Vesta proof point. On failure the
 * reader, transcript and 64-byte affine output remain unchanged. Output must
 * not overlap the reader or transcript objects. Public inputs only. */
struct zcl_result ironwood_halo2_read_point(struct ironwood_halo2_transcript *t,
                                             struct zcl_codec_reader *reader,
                                             uint8_t *out, size_t size);
/* Appends the challenge delimiter and returns 64 raw bytes; state advances. */
struct zcl_result ironwood_halo2_transcript_challenge(struct ironwood_halo2_transcript *t,
                                                       uint8_t *out, size_t size);
/* Reduce 64 public little-endian challenge bytes modulo the Vesta scalar
 * field, returning 32 canonical little-endian bytes. Not constant-time; do
 * not use for secret inputs. Supports overlapping input and output. */
struct zcl_result ironwood_halo2_vesta_scalar(const uint8_t *wide, size_t wide_size,
                                               uint8_t *out, size_t out_size);
#endif
