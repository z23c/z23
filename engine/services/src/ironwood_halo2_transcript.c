/* purpose: Frame Halo2 transcript input and derive challenge bytes. */
/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#include "services/ironwood_halo2_transcript.h"
#include "codec/cursor.h"
#include "core/arith_uint256.h"
#include <string.h>
#include <openssl/bn.h>
#include <openssl/ec.h>

static const struct arith_uint256 vesta_scalar_modulus = { .pn = {
    0x00000001u, 0x992d30edu, 0x094cf91bu, 0x224698fcu,
    0, 0, 0, 0x40000000u
}};

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

struct zcl_result ironwood_halo2_read_scalar(struct ironwood_halo2_transcript *t,
                                              struct zcl_codec_reader *reader,
                                              uint8_t *out, size_t size)
{
    if (!t || !reader || !out || size != 32)
        return ZCL_ERR(-1, "Invalid scalar reader input");
    struct zcl_codec_reader next_reader = *reader;
    const uint8_t *bytes = zcl_codec_take(&next_reader, 32);
    if (!bytes) return ZCL_ERR(-1, "Truncated scalar");
    uint8_t scalar[32];
    memcpy(scalar, bytes, sizeof scalar);
    struct arith_uint256 value = {0};
    for (size_t i = 0; i < sizeof scalar; ++i)
        value.pn[i / 4] |= (uint32_t)scalar[i] << ((i % 4) * 8);
    if (arith_uint256_compare(&value, &vesta_scalar_modulus) >= 0)
        return ZCL_ERR(-1, "Noncanonical Vesta scalar");
    struct ironwood_halo2_transcript next_t = *t;
    struct zcl_result result = ironwood_halo2_transcript_scalar(&next_t, scalar, sizeof scalar);
    if (!result.ok) return result;
    *t = next_t;
    *reader = next_reader;
    memcpy(out, scalar, sizeof scalar);
    return ZCL_OK;
}

/* Vesta coordinates and proof bytes are public. OpenSSL BN/EC operations
 * here are variable-time and must never be used for secret values. */
static bool decode_vesta_point(const uint8_t encoded[32], uint8_t affine[64])
{
    static const char fq[] =
        "40000000000000000000000000000000224698FC0994A8DD8C46EB2100000001";
    uint8_t xbytes[32];
    memcpy(xbytes, encoded, sizeof xbytes);
    unsigned sign = xbytes[31] >> 7;
    xbytes[31] &= 0x7f;
    uint8_t any = 0;
    for (size_t i = 0; i < sizeof xbytes; ++i) any |= xbytes[i];
    if (!any && !sign) return false; /* Halo2 read_point refuses identity. */
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *prime = NULL, *zero = BN_new(), *five = BN_new();
    BIGNUM *x = BN_lebin2bn(xbytes, sizeof xbytes, NULL), *y = BN_new();
    EC_GROUP *curve = NULL;
    EC_POINT *point = NULL;
    bool ok = ctx && zero && five && x && y && BN_hex2bn(&prime, fq) &&
        BN_set_word(five, 5) && BN_cmp(x, prime) < 0;
    if (ok) { curve = EC_GROUP_new_curve_GFp(prime, zero, five, ctx); ok = curve != NULL; }
    if (ok) { point = EC_POINT_new(curve); ok = point != NULL; }
    if (ok) ok = EC_POINT_set_compressed_coordinates(curve, point, x, (int)sign, ctx) == 1 &&
        EC_POINT_is_at_infinity(curve, point) == 0 &&
        EC_POINT_is_on_curve(curve, point, ctx) == 1 &&
        EC_POINT_get_affine_coordinates(curve, point, x, y, ctx) == 1 &&
        BN_bn2lebinpad(x, affine, 32) == 32 && BN_bn2lebinpad(y, affine + 32, 32) == 32;
    EC_POINT_free(point);
    EC_GROUP_free(curve);
    BN_free(y); BN_free(x); BN_free(five); BN_free(zero); BN_free(prime);
    BN_CTX_free(ctx);
    return ok;
}

struct zcl_result ironwood_halo2_read_point(struct ironwood_halo2_transcript *t,
                                             struct zcl_codec_reader *reader,
                                             uint8_t *out, size_t size)
{
    if (!t || !reader || !out || size != 64)
        return ZCL_ERR(-1, "Invalid point reader input");
    struct zcl_codec_reader next_reader = *reader;
    const uint8_t *bytes = zcl_codec_take(&next_reader, 32);
    if (!bytes) return ZCL_ERR(-1, "Truncated point");
    uint8_t affine[64];
    if (!decode_vesta_point(bytes, affine)) return ZCL_ERR(-1, "Invalid Vesta point");
    struct ironwood_halo2_transcript next_t = *t;
    struct zcl_result result = ironwood_halo2_transcript_point(&next_t, affine, sizeof affine);
    if (!result.ok) return result;
    *t = next_t;
    *reader = next_reader;
    memcpy(out, affine, sizeof affine);
    return ZCL_OK;
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
    struct arith_uint256 value = {0};
    for (int bit = 511; bit >= 0; --bit) {
        /* value < modulus before each step, so twice value plus one is
         * below 2^256 and the fixed-width addition cannot overflow. */
        arith_uint256_add(&value, &value, &value);
        value.pn[0] |= (uint32_t)((wide[bit / 8] >> (bit % 8)) & 1u);
        if (arith_uint256_compare(&value, &vesta_scalar_modulus) >= 0)
            arith_uint256_sub(&value, &value, &vesta_scalar_modulus);
    }
    uint8_t result[32];
    for (size_t i = 0; i < sizeof result; ++i)
        result[i] = (uint8_t)(value.pn[i / 4] >> ((i % 4) * 8));
    memcpy(out, result, sizeof result);
    return ZCL_OK;
}
