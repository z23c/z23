/* purpose: Evaluate bounded public Halo2 multiopening scalar claims. */
/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#include "services/ironwood_multiopen.h"
#include "ironwood_pasta_internal.h"
#include <openssl/bn.h>
#include <string.h>

static bool canonical(const struct ironwood_multiopen_set *sets,
                      const uint8_t *x2, const uint8_t *x3, const uint8_t *x4)
{
    if (!sets || !x2 || !x3 || !x4 || !ironwood_pasta_fp_canonical(x2).ok ||
        !ironwood_pasta_fp_canonical(x3).ok || !ironwood_pasta_fp_canonical(x4).ok)
        return false;
    for (size_t i = 0; i < IRONWOOD_MULTIOPEN_SETS; ++i) {
        const struct ironwood_multiopen_set *s = &sets[i];
        if (!s->count || s->count > IRONWOOD_MULTIOPEN_POINTS ||
            !ironwood_pasta_fp_canonical(s->u).ok) return false;
        for (size_t j = 0; j < s->count; ++j) {
            if (!ironwood_pasta_fp_canonical(s->points[j]).ok ||
                !ironwood_pasta_fp_canonical(s->evaluations[j]).ok ||
                !memcmp(s->points[j], x3, 32)) return false;
            for (size_t k = 0; k < j; ++k)
                if (!memcmp(s->points[j], s->points[k], 32)) return false;
        }
    }
    return true;
}

static bool set_value(const struct ironwood_multiopen_set *s, const BIGNUM *x3,
                      const BIGNUM *prime, BN_CTX *ctx, BIGNUM *result)
{
    BN_CTX_start(ctx);
    BIGNUM *p[IRONWOOD_MULTIOPEN_POINTS], *q[IRONWOOD_MULTIOPEN_POINTS];
    for (size_t j = 0; j < s->count; ++j) { p[j] = BN_CTX_get(ctx); q[j] = BN_CTX_get(ctx); }
    BIGNUM *sum = BN_CTX_get(ctx), *term = BN_CTX_get(ctx), *a = BN_CTX_get(ctx);
    BIGNUM *b = BN_CTX_get(ctx), *inv = BN_CTX_get(ctx);
    bool ok = inv != NULL;
    for (size_t j = 0; ok && j < s->count; ++j)
        ok = BN_lebin2bn(s->points[j], 32, p[j]) && BN_lebin2bn(s->evaluations[j], 32, q[j]);
    if (ok) BN_zero(sum);
    for (size_t j = 0; ok && j < s->count; ++j) {
        ok = BN_copy(term, q[j]) != NULL;
        for (size_t k = 0; ok && k < s->count; ++k) if (j != k)
            ok = BN_mod_sub(a, x3, p[k], prime, ctx) && BN_mod_sub(b, p[j], p[k], prime, ctx) &&
                 BN_mod_inverse(inv, b, prime, ctx) && BN_mod_mul(term, term, a, prime, ctx) &&
                 BN_mod_mul(term, term, inv, prime, ctx);
        if (ok) ok = BN_mod_add(sum, sum, term, prime, ctx);
    }
    if (ok) ok = BN_lebin2bn(s->u, 32, result) && BN_mod_sub(result, result, sum, prime, ctx);
    for (size_t j = 0; ok && j < s->count; ++j)
        ok = BN_mod_sub(a, x3, p[j], prime, ctx) && BN_mod_inverse(inv, a, prime, ctx) &&
             BN_mod_mul(result, result, inv, prime, ctx);
    BN_CTX_end(ctx);
    return ok;
}

struct zcl_result ironwood_multiopen_value(const struct ironwood_multiopen_set sets[IRONWOOD_MULTIOPEN_SETS],
                                            const uint8_t x2[32], const uint8_t x3[32],
                                            const uint8_t x4[32], uint8_t out[32])
{
    if (!out || !canonical(sets, x2, x3, x4)) return ZCL_ERR(-1, "Invalid multiopening inputs");
    BN_CTX *ctx = BN_CTX_new();
    if (!ctx) return ZCL_ERR(-1, "Cannot allocate multiopening context");
    BN_CTX_start(ctx);
    BIGNUM *prime = ironwood_pasta_fp_modulus();
    BIGNUM *c2 = BN_CTX_get(ctx), *c3 = BN_CTX_get(ctx);
    BIGNUM *c4 = BN_CTX_get(ctx), *v = BN_CTX_get(ctx), *term = BN_CTX_get(ctx);
    bool ok = term && prime &&
              BN_lebin2bn(x2, 32, c2) && BN_lebin2bn(x3, 32, c3) && BN_lebin2bn(x4, 32, c4);
    if (ok) BN_zero(v);
    for (size_t i = 0; ok && i < IRONWOOD_MULTIOPEN_SETS; ++i)
        ok = set_value(&sets[i], c3, prime, ctx, term) && BN_mod_mul(v, v, c2, prime, ctx) &&
             BN_mod_add(v, v, term, prime, ctx);
    for (size_t i = 0; ok && i < IRONWOOD_MULTIOPEN_SETS; ++i)
        ok = BN_lebin2bn(sets[i].u, 32, term) && BN_mod_mul(v, v, c4, prime, ctx) &&
             BN_mod_add(v, v, term, prime, ctx);
    uint8_t value[32];
    if (ok) ok = BN_bn2lebinpad(v, value, sizeof value) == sizeof value;
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
    BN_free(prime);
    if (!ok) return ZCL_ERR(-1, "Cannot evaluate multiopening claim");
    memcpy(out, value, sizeof value);
    return ZCL_OK;
}
