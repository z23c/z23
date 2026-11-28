/* purpose: Verify public Ironwood action spend authorization signatures. */
/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#include "services/ironwood_spend_auth.h"
#include "ironwood_pasta_internal.h"
#include "crypto/blake2b.h"
#include "base/serialize_le.h"
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <string.h>

/* Orchard SpendAuth basepoint, compressed Pallas encoding. */
static const uint8_t spend_base[32] = {
    99,201,117,184,132,114,26,141,12,161,112,123,227,12,127,12,
    95,68,95,62,124,24,141,59,6,214,241,40,179,35,85,183
};

static bool challenge(BIGNUM *c, const BIGNUM *order, BN_CTX *ctx,
                      const uint8_t rk[32], const uint8_t sig[64], const uint8_t msg[32])
{
    static const uint8_t personal[16] = {
        0x5a, 0x63, 0x61, 0x73, 0x68, 0x5f, 0x52, 0x65,
        0x64, 0x50, 0x61, 0x6c, 0x6c, 0x61, 0x73, 0x48};
    uint8_t wide[64];
    struct blake2b_ctx hash;
    if (blake2b_init_salt_personal(&hash, 64, NULL, 0, NULL, personal) ||
        blake2b_update(&hash, sig, 32) || blake2b_update(&hash, rk, 32) ||
        blake2b_update(&hash, msg, 32) || blake2b_final(&hash, wide, 64) ||
        !BN_lebin2bn(wide, 64, c)) return false;
    return BN_nnmod(c, c, order, ctx) == 1;
}

static bool equation(const EC_GROUP *g, BN_CTX *ctx, const uint8_t rk[32],
                     const uint8_t sig[64], const BIGNUM *s, const BIGNUM *c,
                     const uint8_t base_bytes[32], bool allow_identity)
{
    EC_POINT *key = EC_POINT_new(g), *r = EC_POINT_new(g), *base = EC_POINT_new(g);
    EC_POINT *lhs = EC_POINT_new(g), *rhs = EC_POINT_new(g);
    bool ok = key && r && base && lhs && rhs;
    if (ok) ok = ironwood_pasta_decode(rk, IRONWOOD_PALLAS, allow_identity, g, key, ctx).ok &&
        ironwood_pasta_decode(sig, IRONWOOD_PALLAS, true, g, r, ctx).ok &&
        ironwood_pasta_decode(base_bytes, IRONWOOD_PALLAS, false, g, base, ctx).ok;
    if (ok) ok = EC_POINT_mul(g, lhs, NULL, base, s, ctx) == 1 &&
        EC_POINT_mul(g, rhs, NULL, key, c, ctx) == 1 &&
        EC_POINT_add(g, rhs, rhs, r, ctx) == 1 && EC_POINT_cmp(g, lhs, rhs, ctx) == 0;
    EC_POINT_free(rhs); EC_POINT_free(lhs); EC_POINT_free(base); EC_POINT_free(r); EC_POINT_free(key);
    return ok;
}

static struct zcl_result verify_signature(const uint8_t rk[32], const uint8_t signature[64],
                                          const uint8_t sighash[32], const uint8_t base[32],
                                          bool allow_identity)
{
    if (!rk || !signature || !sighash) return ZCL_ERR(-1, "Missing signature verification input");
    BN_CTX *ctx = BN_CTX_new();
    EC_GROUP *pallas = NULL, *vesta = NULL;
    BIGNUM *order = BN_new(), *s = BN_lebin2bn(signature + 32, 32, NULL), *c = BN_new();
    bool ok = ctx && order && s && c && ironwood_pasta_group(IRONWOOD_PALLAS, ctx, &pallas).ok &&
        ironwood_pasta_group(IRONWOOD_VESTA, ctx, &vesta).ok &&
        EC_GROUP_get_curve(vesta, order, NULL, NULL, ctx) == 1 && BN_cmp(s, order) < 0;
    if (ok) ok = challenge(c, order, ctx, rk, signature, sighash) &&
        equation(pallas, ctx, rk, signature, s, c, base, allow_identity);
    BN_free(c); BN_free(s); BN_free(order); EC_GROUP_free(vesta); EC_GROUP_free(pallas); BN_CTX_free(ctx);
    return ok ? ZCL_OK : ZCL_ERR(-1, "Invalid signature or arithmetic failure");
}

struct zcl_result ironwood_spend_auth_verify(const uint8_t rk[32],
    const uint8_t signature[64], const uint8_t sighash[32])
{
    return verify_signature(rk, signature, sighash, spend_base, false);
}

/* Orchard 0.16.0 fixed_bases/value_commit_{v,r}.rs: V and R, respectively. */
static const uint8_t value_base[32] = {
    103,67,249,58,110,189,167,42,140,124,90,43,127,163,4,254,
    50,178,155,79,112,106,168,247,66,15,61,142,122,89,112,47
};
static const uint8_t binding_base[32] = {
    145,90,60,136,104,198,195,14,47,128,144,238,69,215,110,64,
    72,32,141,234,91,35,102,79,187,9,164,15,85,68,244,7
};

static bool binding_sum(const EC_GROUP *group, BN_CTX *ctx, EC_POINT *sum,
                        const uint8_t (*commitments)[32], size_t count, int64_t balance)
{
    EC_POINT *value = EC_POINT_new(group), *point = EC_POINT_new(group);
    uint64_t magnitude = (uint64_t)balance;
    if (balance < 0) magnitude = 0 - magnitude;
    uint8_t raw[8];
    zcl_write_u64_le(raw, magnitude);
    BIGNUM *scalar = BN_lebin2bn(raw, sizeof raw, NULL);
    bool ok = value && point && scalar &&
        ironwood_pasta_decode(value_base, IRONWOOD_PALLAS, false, group, value, ctx).ok &&
        EC_POINT_mul(group, sum, NULL, value, scalar, ctx) == 1;
    if (ok && balance > 0) ok = EC_POINT_invert(group, sum, ctx) == 1;
    for (size_t i = 0; ok && i < count; ++i) {
        ok = ironwood_pasta_decode(commitments[i], IRONWOOD_PALLAS, true, group, point, ctx).ok &&
            EC_POINT_add(group, sum, sum, point, ctx) == 1;
    }
    BN_free(scalar); EC_POINT_free(point); EC_POINT_free(value);
    return ok;
}

static bool encode_binding(const EC_GROUP *group, const EC_POINT *point, BN_CTX *ctx, uint8_t out[32])
{
    int identity = EC_POINT_is_at_infinity(group, point);
    if (identity < 0) return false;
    if (identity) { memset(out, 0, 32); return true; }
    BIGNUM *x = BN_new(), *y = BN_new();
    bool ok = x && y && EC_POINT_get_affine_coordinates(group, point, x, y, ctx) == 1 &&
        BN_bn2lebinpad(x, out, 32) == 32;
    if (ok && BN_is_odd(y)) out[31] |= 0x80;
    BN_free(y); BN_free(x);
    return ok;
}

struct zcl_result ironwood_binding_key(const uint8_t (*commitments)[32], size_t count,
                                        int64_t balance, uint8_t out[32])
{
    if (!commitments || !count || count > SIZE_MAX / sizeof *commitments || !out) return ZCL_ERR(-1, "Missing binding key input");
    BN_CTX *ctx = BN_CTX_new();
    EC_GROUP *group = NULL;
    bool ok = ctx && ironwood_pasta_group(IRONWOOD_PALLAS, ctx, &group).ok;
    EC_POINT *sum = ok ? EC_POINT_new(group) : NULL;
    uint8_t encoded[32];
    if (ok) ok = sum && binding_sum(group, ctx, sum, commitments, count, balance) &&
        encode_binding(group, sum, ctx, encoded);
    if (ok) memcpy(out, encoded, sizeof encoded);
    EC_POINT_free(sum); EC_GROUP_free(group); BN_CTX_free(ctx);
    return ok ? ZCL_OK : ZCL_ERR(-1, "Invalid binding commitment or arithmetic failure");
}

struct zcl_result ironwood_binding_auth_verify(const uint8_t (*commitments)[32], size_t count,
    int64_t balance, const uint8_t signature[64], const uint8_t sighash[32])
{
    uint8_t key[32];
    struct zcl_result result = ironwood_binding_key(commitments, count, balance, key);
    if (!result.ok) return result;
    return verify_signature(key, signature, sighash, binding_base, true);
}
