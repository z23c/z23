/* purpose: Frame Halo2 transcript input and derive challenge bytes. */
/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#include "services/ironwood_halo2_transcript.h"
#include "core/arith_uint256.h"
#include <string.h>

struct zcl_result ironwood_halo2_transcript_init(struct ironwood_halo2_transcript *t)
{
    static const uint8_t personal[16] = {'H','a','l','o','2','-','T','r','a','n','s','c','r','i','p','t'};
    if (!t) return ZCL_ERR(-1, "Missing transcript");
    struct ironwood_halo2_transcript next = {0};
    if (blake2b_init_salt_personal(&next.hash, 64, NULL, 0, NULL, personal))
        return ZCL_ERR(-1, "Cannot initialize transcript");
    next.initialized = true;
    *t = next;
    return ZCL_OK;
}

static struct zcl_result absorb(struct ironwood_halo2_transcript *t,
                                const uint8_t *bytes, size_t size,
                                size_t expected, uint8_t prefix)
{
    if (!t || !t->initialized || !bytes || size != expected)
        return ZCL_ERR(-1, "Invalid transcript input");
    struct blake2b_ctx next = t->hash;
    if (blake2b_update(&next, &prefix, 1) || blake2b_update(&next, bytes, size))
        return ZCL_ERR(-1, "Cannot absorb transcript input");
    t->hash = next;
    return ZCL_OK;
}

struct zcl_result ironwood_halo2_transcript_point(struct ironwood_halo2_transcript *t,
                                                   const uint8_t *point, size_t size)
{
    return absorb(t, point, size, 64, 1);
}

struct zcl_result ironwood_halo2_transcript_scalar(struct ironwood_halo2_transcript *t,
                                                    const uint8_t *scalar, size_t size)
{
    return absorb(t, scalar, size, 32, 2);
}

struct zcl_result ironwood_halo2_transcript_challenge(struct ironwood_halo2_transcript *t,
                                                       uint8_t *out, size_t size)
{
    if (!t || !t->initialized || !out || size != 64)
        return ZCL_ERR(-1, "Invalid challenge output");
    struct blake2b_ctx next = t->hash;
    uint8_t prefix = 0, challenge[64];
    if (blake2b_update(&next, &prefix, 1))
        return ZCL_ERR(-1, "Cannot advance transcript");
    struct blake2b_ctx final = next;
    if (blake2b_final(&final, challenge, sizeof challenge))
        return ZCL_ERR(-1, "Cannot derive challenge");
    t->hash = next;
    memcpy(out, challenge, sizeof challenge);
    return ZCL_OK;
}

/* Vesta's scalar field is the Pallas base field Fp. The 512-bit input is
 * public Fiat-Shamir output; this branchy reduction is not for secrets. */
struct zcl_result ironwood_halo2_vesta_scalar(const uint8_t *wide, size_t wide_size,
                                               uint8_t *out, size_t out_size)
{
    if (!wide || wide_size != 64 || !out || out_size != 32)
        return ZCL_ERR(-1, "Invalid Vesta challenge reduction input");
    const struct arith_uint256 modulus = { .pn = {
        0x00000001u, 0x992d30edu, 0x094cf91bu, 0x224698fcu,
        0, 0, 0, 0x40000000u
    }};
    struct arith_uint256 value = {0};
    for (int bit = 511; bit >= 0; --bit) {
        /* value < modulus before each step, so twice value plus one is
         * below 2^256 and the fixed-width addition cannot overflow. */
        arith_uint256_add(&value, &value, &value);
        value.pn[0] |= (uint32_t)((wide[bit / 8] >> (bit % 8)) & 1u);
        if (arith_uint256_compare(&value, &modulus) >= 0)
            arith_uint256_sub(&value, &value, &modulus);
    }
    uint8_t result[32];
    for (size_t i = 0; i < sizeof result; ++i)
        result[i] = (uint8_t)(value.pn[i / 4] >> ((i % 4) * 8));
    memcpy(out, result, sizeof result);
    return ZCL_OK;
}
