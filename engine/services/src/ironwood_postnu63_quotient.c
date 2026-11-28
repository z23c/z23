/* purpose: Fold public PostNu6_3 circuit evaluations into expected H. */
/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#include "services/ironwood_postnu63_quotient.h"
#include "services/ironwood_postnu63.h"
#include "ironwood_pasta_internal.h"
#include <openssl/bn.h>
#include <string.h>

enum { TERMS_PER_ACTION = 215, FIELD_BYTES = 32, DOMAIN_LOG = 11 };

static struct zcl_result fold_terms(const uint8_t *terms, size_t count, const BIGNUM *y,
                                    const BIGNUM *prime, BIGNUM *sum, BN_CTX *ctx)
{
    BIGNUM *term = BN_CTX_get(ctx);
    if (!term) return ZCL_ERR(-1, "Cannot allocate quotient term");
    BN_zero(sum);
    for (size_t i = 0; i < count; ++i) {
        const uint8_t *bytes = terms + i * FIELD_BYTES;
        struct zcl_result canonical = ironwood_pasta_fp_canonical(bytes);
        if (!canonical.ok) return canonical;
        if (!BN_lebin2bn(bytes, FIELD_BYTES, term) || !BN_mod_mul(sum, sum, y, prime, ctx) ||
            !BN_mod_add(sum, sum, term, prime, ctx))
            return ZCL_ERR(-1, "Cannot fold quotient term");
    }
    return ZCL_OK;
}

static struct zcl_result divide_domain(BIGNUM *x, BIGNUM *sum, const BIGNUM *prime,
                                       BIGNUM *one, BIGNUM *den, BIGNUM *inv, BN_CTX *ctx)
{
    for (size_t i = 0; i < DOMAIN_LOG; ++i)
        if (!BN_mod_sqr(x, x, prime, ctx)) return ZCL_ERR(-1, "Cannot compute quotient domain");
    if (!BN_mod_sub(den, x, one, prime, ctx) || BN_is_zero(den))
        return ZCL_ERR(-1, "PostNu6_3 quotient domain denominator is zero");
    if (!BN_mod_inverse(inv, den, prime, ctx) || !BN_mod_mul(sum, sum, inv, prime, ctx))
        return ZCL_ERR(-1, "Cannot divide expected quotient");
    return ZCL_OK;
}

static struct zcl_result quotient_value(const struct ironwood_postnu63_stage *stage,
                                         const uint8_t *terms, size_t count, uint8_t out[32])
{
    BN_CTX *ctx = BN_CTX_new(); BIGNUM *prime = ironwood_pasta_fp_modulus();
    if (!ctx || !prime) { BN_free(prime); BN_CTX_free(ctx); return ZCL_ERR(-1, "Cannot allocate quotient context"); }
    BN_CTX_start(ctx);
    BIGNUM *x = BN_CTX_get(ctx), *y = BN_CTX_get(ctx);
    BIGNUM *sum = BN_CTX_get(ctx), *one = BN_CTX_get(ctx), *den = BN_CTX_get(ctx), *inv = BN_CTX_get(ctx);
    struct zcl_result result = inv ? ZCL_OK : ZCL_ERR(-1, "Cannot allocate quotient scalars");
    if (result.ok && (!BN_lebin2bn(stage->x, 32, x) || !BN_lebin2bn(stage->y, 32, y) || !BN_one(one)))
        result = ZCL_ERR(-1, "Cannot initialize quotient scalars");
    if (result.ok) result = fold_terms(terms, count, y, prime, sum, ctx);
    if (result.ok) result = divide_domain(x, sum, prime, one, den, inv, ctx);
    if (result.ok && BN_bn2lebinpad(sum, out, 32) != 32)
        result = ZCL_ERR(-1, "Cannot compute expected quotient");
    BN_CTX_end(ctx); BN_CTX_free(ctx); BN_free(prime);
    return result;
}

struct zcl_result ironwood_postnu63_expected_h(const struct ironwood_postnu63_stage *stage,
                                                const uint8_t *terms, size_t terms_size,
                                                uint8_t out[32])
{
    if (!stage || !terms || !out || stage->phase != IRONWOOD_POSTNU63_EVAL_X1 || !stage->actions ||
        stage->actions > SIZE_MAX / (TERMS_PER_ACTION * FIELD_BYTES))
        return ZCL_ERR(-1, "Invalid PostNu6_3 quotient input");
    size_t count = (size_t)stage->actions * TERMS_PER_ACTION;
    if (terms_size != count * FIELD_BYTES) return ZCL_ERR(-1, "Invalid quotient term count");
    struct zcl_result result = ironwood_pasta_fp_canonical(stage->x);
    if (result.ok) result = ironwood_pasta_fp_canonical(stage->y);
    uint8_t value[32];
    if (result.ok) result = quotient_value(stage, terms, count, value);
    if (result.ok) memcpy(out, value, sizeof value);
    return result;
}
