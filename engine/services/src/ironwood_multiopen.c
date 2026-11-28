/* purpose: Evaluate bounded public Halo2 multiopening scalar claims. */
/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#include "services/ironwood_multiopen.h"
#include "ironwood_pasta_internal.h"
#include <openssl/bn.h>
#include <string.h>

static bool set_canonical(const struct ironwood_multiopen_set *s, const uint8_t *x3)
{
    if (!s->count || s->count > IRONWOOD_MULTIOPEN_POINTS ||
        !ironwood_pasta_fp_canonical(s->u).ok) return false;
    for (size_t j = 0; j < s->count; ++j) {
        if (!ironwood_pasta_fp_canonical(s->points[j]).ok ||
            !ironwood_pasta_fp_canonical(s->evaluations[j]).ok ||
            !memcmp(s->points[j], x3, 32)) return false;
        for (size_t k = 0; k < j; ++k)
            if (!memcmp(s->points[j], s->points[k], 32)) return false;
    }
    return true;
}
static bool canonical(const struct ironwood_multiopen_set *sets,
                      const uint8_t *x2, const uint8_t *x3, const uint8_t *x4)
{
    if (!sets || !x2 || !x3 || !x4 || !ironwood_pasta_fp_canonical(x2).ok ||
        !ironwood_pasta_fp_canonical(x3).ok || !ironwood_pasta_fp_canonical(x4).ok)
        return false;
    for (size_t i = 0; i < IRONWOOD_MULTIOPEN_SETS; ++i)
        if (!set_canonical(&sets[i], x3)) return false;
    return true;
}

static bool lagrange_factor(BIGNUM *term, BIGNUM *a, BIGNUM *b, BIGNUM *inv,
                            const BIGNUM *x3, const BIGNUM *pj, const BIGNUM *pk,
                            const BIGNUM *prime, BN_CTX *ctx)
{
    return BN_mod_sub(a, x3, pk, prime, ctx) && BN_mod_sub(b, pj, pk, prime, ctx) &&
           BN_mod_inverse(inv, b, prime, ctx) && BN_mod_mul(term, term, a, prime, ctx) &&
           BN_mod_mul(term, term, inv, prime, ctx);
}
static bool interpolate(const struct ironwood_multiopen_set *s, const BIGNUM *x3,
                        const BIGNUM *prime, BN_CTX *ctx, BIGNUM *result)
{
    BN_CTX_start(ctx);
    BIGNUM *p[IRONWOOD_MULTIOPEN_POINTS];
    for (size_t j = 0; j < s->count; ++j) p[j] = BN_CTX_get(ctx);
    BIGNUM *term = BN_CTX_get(ctx), *a = BN_CTX_get(ctx), *b = BN_CTX_get(ctx), *inv = BN_CTX_get(ctx);
    bool ok = inv != NULL;
    for (size_t j = 0; ok && j < s->count; ++j)
        ok = BN_lebin2bn(s->points[j], 32, p[j]) != NULL;
    if (ok) ok = BN_set_word(result, 0);
    for (size_t j = 0; ok && j < s->count; ++j) {
        ok = BN_lebin2bn(s->evaluations[j], 32, term) != NULL;
        for (size_t k = 0; ok && k < s->count; ++k) if (j != k)
            ok = lagrange_factor(term, a, b, inv, x3, p[j], p[k], prime, ctx);
        if (ok) ok = BN_mod_add(result, result, term, prime, ctx);
    }
    BN_CTX_end(ctx);
    return ok;
}
static bool set_value(const struct ironwood_multiopen_set *s, const BIGNUM *x3,
                      const BIGNUM *prime, BN_CTX *ctx, BIGNUM *result)
{
    BN_CTX_start(ctx);
    BIGNUM *sum = BN_CTX_get(ctx), *point = BN_CTX_get(ctx), *a = BN_CTX_get(ctx), *inv = BN_CTX_get(ctx);
    bool ok = inv && interpolate(s, x3, prime, ctx, sum) && BN_lebin2bn(s->u, 32, result) &&
              BN_mod_sub(result, result, sum, prime, ctx);
    for (size_t j = 0; ok && j < s->count; ++j)
        ok = BN_lebin2bn(s->points[j], 32, point) && BN_mod_sub(a, x3, point, prime, ctx) &&
             BN_mod_inverse(inv, a, prime, ctx) && BN_mod_mul(result, result, inv, prime, ctx);
    BN_CTX_end(ctx);
    return ok;
}
static bool fold(const struct ironwood_multiopen_set *sets, const BIGNUM *prime, BN_CTX *ctx,
                 const uint8_t *x2, const uint8_t *x3, const uint8_t *x4, uint8_t value[32])
{
    BN_CTX_start(ctx);
    BIGNUM *c2 = BN_CTX_get(ctx), *c3 = BN_CTX_get(ctx), *c4 = BN_CTX_get(ctx);
    BIGNUM *v = BN_CTX_get(ctx), *term = BN_CTX_get(ctx);
    bool ok = term && BN_lebin2bn(x2, 32, c2) && BN_lebin2bn(x3, 32, c3) && BN_lebin2bn(x4, 32, c4);
    if (ok) ok = BN_set_word(v, 0);
    for (size_t i = 0; ok && i < IRONWOOD_MULTIOPEN_SETS; ++i)
        ok = set_value(&sets[i], c3, prime, ctx, term) && BN_mod_mul(v, v, c2, prime, ctx) &&
             BN_mod_add(v, v, term, prime, ctx);
    for (size_t i = 0; ok && i < IRONWOOD_MULTIOPEN_SETS; ++i)
        ok = BN_lebin2bn(sets[i].u, 32, term) && BN_mod_mul(v, v, c4, prime, ctx) &&
             BN_mod_add(v, v, term, prime, ctx);
    if (ok) ok = BN_bn2lebinpad(v, value, 32) == 32;
    BN_CTX_end(ctx);
    return ok;
}
struct zcl_result ironwood_multiopen_value(const struct ironwood_multiopen_set sets[IRONWOOD_MULTIOPEN_SETS],
                                            const uint8_t x2[32], const uint8_t x3[32],
                                            const uint8_t x4[32], uint8_t out[32])
{
    if (!out || !canonical(sets, x2, x3, x4)) return ZCL_ERR(-1, "Invalid multiopening inputs");
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *prime = ironwood_pasta_fp_modulus();
    uint8_t value[32];
    bool ok = ctx && prime && fold(sets, prime, ctx, x2, x3, x4, value);
    BN_free(prime); BN_CTX_free(ctx);
    if (!ok) return ZCL_ERR(-1, "Cannot evaluate multiopening claim");
    memcpy(out, value, sizeof value);
    return ZCL_OK;
}
