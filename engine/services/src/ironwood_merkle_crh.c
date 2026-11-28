/* purpose: Compute public Orchard MerkleCRH nodes with pinned parameters. */
/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#include "services/ironwood_merkle_crh.h"
#include "ironwood_pasta_internal.h"
#include "crypto/sha256.h"
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <string.h>

/* Orchard 0.16 and sinsemilla 0.2: compressed Q || S[0..1023]. */
static const uint8_t parameter_hash[32] = {
    0xc7,0x42,0xf4,0xc7,0x6e,0x37,0x27,0xde,0x7b,0xc9,0x3b,0xf4,0x46,0xa5,0x0e,0x9a,
    0x84,0xef,0xa7,0x7a,0x89,0x87,0xd9,0x6f,0x40,0x9d,0x6c,0x46,0x4e,0xd8,0x26,0x2b
};
struct zcl_result ironwood_merkle_parameters_validate(const uint8_t *p, size_t size)
{
    if (!p || size != IRONWOOD_MERKLE_PARAMETERS_SIZE)
        return ZCL_ERR(-1, "Invalid Merkle parameter size");
    struct sha256_ctx h; uint8_t digest[32];
    sha256_init(&h); sha256_write(&h, p, size); sha256_finalize(&h, digest);
    return memcmp(digest, parameter_hash, 32) == 0 ? ZCL_OK :
        ZCL_ERR(-1, "Invalid Merkle parameter digest");
}
/* Upstream incomplete addition returns bottom for either identity or equal x.
 * An OpenSSL error is separate from this mathematical bottom. */
enum addition_status { ADD_ERROR, ADD_BOTTOM, ADD_OK };
static enum addition_status incomplete_add(const EC_GROUP *g, BN_CTX *ctx,
    EC_POINT *out, const EC_POINT *a, const EC_POINT *b, EC_POINT *neg)
{
    int ai = EC_POINT_is_at_infinity(g, a), bi = EC_POINT_is_at_infinity(g, b);
    if (ai < 0 || bi < 0) return ADD_ERROR;
    if (ai || bi) return ADD_BOTTOM;
    int eq = EC_POINT_cmp(g, a, b, ctx);
    if (eq < 0 || !EC_POINT_copy(neg, b) || EC_POINT_invert(g, neg, ctx) != 1) return ADD_ERROR;
    int opposite = EC_POINT_cmp(g, a, neg, ctx);
    if (opposite < 0) return ADD_ERROR;
    if (!eq || !opposite) return ADD_BOTTOM;
    return EC_POINT_add(g, out, a, b, ctx) == 1 ? ADD_OK : ADD_ERROR;
}
static unsigned message_bit(unsigned bit, unsigned level, const uint8_t left[32], const uint8_t right[32])
{
    if (bit < 10) return (level >> bit) & 1u;
    bit -= 10;
    const uint8_t *field = bit < 255 ? left : right;
    if (bit >= 255) bit -= 255;
    return (field[bit / 8] >> (bit % 8)) & 1u;
}
static unsigned piece(unsigned index, unsigned level, const uint8_t left[32], const uint8_t right[32])
{
    unsigned value = 0;
    for (unsigned i = 0; i < 10; ++i) value |= message_bit(index * 10 + i, level, left, right) << i;
    return value;
}
static enum addition_status hash_points(const EC_GROUP *g, BN_CTX *ctx, EC_POINT *acc,
    const uint8_t *p, unsigned level, const uint8_t left[32], const uint8_t right[32])
{
    EC_POINT *s = EC_POINT_new(g), *tmp = EC_POINT_new(g), *neg = EC_POINT_new(g);
    enum addition_status result = s && tmp && neg ? ADD_OK : ADD_ERROR;
    if (result == ADD_OK && !ironwood_pasta_decode(p, IRONWOOD_PALLAS, false, g, acc, ctx).ok)
        result = ADD_ERROR;
    for (unsigned i = 0; result == ADD_OK && i < 52; ++i) {
        unsigned n = piece(i, level, left, right);
        if (!ironwood_pasta_decode(p + (n + 1) * 32, IRONWOOD_PALLAS, false, g, s, ctx).ok) {
            result = ADD_ERROR; break;
        }
        result = incomplete_add(g, ctx, tmp, acc, s, neg);
        if (result == ADD_OK) result = incomplete_add(g, ctx, tmp, tmp, acc, neg);
        if (result == ADD_OK && !EC_POINT_copy(acc, tmp)) result = ADD_ERROR;
    }
    EC_POINT_free(neg); EC_POINT_free(tmp); EC_POINT_free(s);
    return result;
}
static bool merkle_inputs_valid(unsigned level, const uint8_t left[32], const uint8_t right[32],
                                const uint8_t *parameters, size_t parameters_size, const uint8_t *out)
{
    return left && right && out && level < 32 &&
        ironwood_merkle_parameters_validate(parameters, parameters_size).ok &&
        ironwood_pasta_fp_canonical(left).ok && ironwood_pasta_fp_canonical(right).ok;
}

struct zcl_result ironwood_merkle_crh(unsigned level, const uint8_t left[32],
    const uint8_t right[32], const uint8_t *parameters, size_t parameters_size, uint8_t out[32])
{
    if (!merkle_inputs_valid(level, left, right, parameters, parameters_size, out))
        return ZCL_ERR(-1, "Invalid Ironwood MerkleCRH input");
    BN_CTX *ctx = BN_CTX_new(); EC_GROUP *g = NULL;
    bool ok = ctx && ironwood_pasta_group(IRONWOOD_PALLAS, ctx, &g).ok;
    EC_POINT *acc = ok ? EC_POINT_new(g) : NULL; BIGNUM *x = BN_new();
    enum addition_status status = acc && x ? hash_points(g, ctx, acc, parameters, level, left, right) : ADD_ERROR;
    uint8_t value[32] = {0};
    if (status == ADD_OK && (EC_POINT_get_affine_coordinates(g, acc, x, NULL, ctx) != 1 ||
                              BN_bn2lebinpad(x, value, 32) != 32)) status = ADD_ERROR;
    if (status != ADD_ERROR) memcpy(out, value, 32);
    BN_free(x); EC_POINT_free(acc); EC_GROUP_free(g); BN_CTX_free(ctx);
    return status == ADD_ERROR ? ZCL_ERR(-1, "Cannot compute Ironwood MerkleCRH") : ZCL_OK;
}
