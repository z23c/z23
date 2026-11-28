/* purpose: Verify public Ironwood action spend authorization signatures. */
/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#include "services/ironwood_spend_auth.h"
#include "ironwood_pasta_internal.h"
#include "crypto/blake2b.h"
#include <openssl/bn.h>
#include <openssl/ec.h>

/* Orchard SpendAuth basepoint, compressed Pallas encoding. */
static const uint8_t spend_base[32] = {
    99,201,117,184,132,114,26,141,12,161,112,123,227,12,127,12,
    95,68,95,62,124,24,141,59,6,214,241,40,179,35,85,183
};

static bool challenge(BIGNUM *c, const BIGNUM *order, BN_CTX *ctx,
                      const uint8_t rk[32], const uint8_t sig[64], const uint8_t msg[32])
{
    static const uint8_t personal[16] = "Zcash_RedPallasH";
    uint8_t wide[64];
    struct blake2b_ctx hash;
    if (blake2b_init_salt_personal(&hash, 64, NULL, 0, NULL, personal) ||
        blake2b_update(&hash, sig, 32) || blake2b_update(&hash, rk, 32) ||
        blake2b_update(&hash, msg, 32) || blake2b_final(&hash, wide, 64) ||
        !BN_lebin2bn(wide, 64, c)) return false;
    return BN_nnmod(c, c, order, ctx) == 1;
}

static bool equation(const EC_GROUP *g, BN_CTX *ctx, const uint8_t rk[32],
                     const uint8_t sig[64], const BIGNUM *s, const BIGNUM *c)
{
    EC_POINT *key = EC_POINT_new(g), *r = EC_POINT_new(g), *base = EC_POINT_new(g);
    EC_POINT *lhs = EC_POINT_new(g), *rhs = EC_POINT_new(g);
    bool ok = key && r && base && lhs && rhs;
    if (ok) ok = ironwood_pasta_decode(rk, IRONWOOD_PALLAS, false, g, key, ctx).ok &&
        ironwood_pasta_decode(sig, IRONWOOD_PALLAS, true, g, r, ctx).ok &&
        ironwood_pasta_decode(spend_base, IRONWOOD_PALLAS, false, g, base, ctx).ok;
    if (ok) ok = EC_POINT_mul(g, lhs, NULL, base, s, ctx) == 1 &&
        EC_POINT_mul(g, rhs, NULL, key, c, ctx) == 1 &&
        EC_POINT_add(g, rhs, rhs, r, ctx) == 1 && EC_POINT_cmp(g, lhs, rhs, ctx) == 0;
    EC_POINT_free(rhs); EC_POINT_free(lhs); EC_POINT_free(base); EC_POINT_free(r); EC_POINT_free(key);
    return ok;
}

struct zcl_result ironwood_spend_auth_verify(const uint8_t rk[32],
    const uint8_t signature[64], const uint8_t sighash[32])
{
    if (!rk || !signature || !sighash) return ZCL_ERR(-1, "Missing spend authorization input");
    BN_CTX *ctx = BN_CTX_new();
    EC_GROUP *pallas = NULL, *vesta = NULL;
    BIGNUM *order = BN_new(), *s = BN_lebin2bn(signature + 32, 32, NULL), *c = BN_new();
    bool ok = ctx && order && s && c && ironwood_pasta_group(IRONWOOD_PALLAS, ctx, &pallas).ok &&
        ironwood_pasta_group(IRONWOOD_VESTA, ctx, &vesta).ok &&
        EC_GROUP_get_curve(vesta, order, NULL, NULL, ctx) == 1 && BN_cmp(s, order) < 0;
    if (ok) ok = challenge(c, order, ctx, rk, signature, sighash) &&
        equation(pallas, ctx, rk, signature, s, c);
    BN_free(c); BN_free(s); BN_free(order); EC_GROUP_free(vesta); EC_GROUP_free(pallas); BN_CTX_free(ctx);
    return ok ? ZCL_OK : ZCL_ERR(-1, "Invalid spend authorization or arithmetic failure");
}
