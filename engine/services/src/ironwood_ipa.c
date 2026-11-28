/* purpose: Compute the public PostNu6_3 IPA evaluation coefficient. */
/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#include "services/ironwood_ipa.h"
#include "ironwood_pasta_internal.h"
#include "util/safe_alloc.h"
#include <openssl/bn.h>
#include <string.h>
#include <stdlib.h>

static bool ipa_inputs_valid(const uint8_t x[32], const uint8_t u[IRONWOOD_IPA_ROUNDS][32])
{
    if (!ironwood_pasta_fp_canonical(x).ok) return false;
    for (size_t i = 0; i < IRONWOOD_IPA_ROUNDS; ++i)
        if (!ironwood_pasta_fp_canonical(u[i]).ok) return false;
    return true;
}

static bool ipa_product(BN_CTX *ctx, const BIGNUM *p, BIGNUM *cur, BIGNUM *acc,
                        const uint8_t u[IRONWOOD_IPA_ROUNDS][32])
{
    BIGNUM *one = BN_new(), *term = BN_new(), *challenge = BN_new();
    bool ok = one && term && challenge && BN_set_word(one, 1) && BN_set_word(acc, 1);
    for (size_t i = IRONWOOD_IPA_ROUNDS; ok && i > 0; --i) {
        ok = BN_lebin2bn(u[i - 1], 32, challenge) && BN_mod_mul(term, challenge, cur, p, ctx) &&
            BN_mod_add(term, term, one, p, ctx) && BN_mod_mul(acc, acc, term, p, ctx) &&
            BN_mod_sqr(cur, cur, p, ctx);
    }
    BN_free(challenge); BN_free(term); BN_free(one);
    return ok;
}

struct zcl_result ironwood_ipa_compute_b(const uint8_t x[32],
    const uint8_t u[IRONWOOD_IPA_ROUNDS][32], uint8_t out[32])
{
    if (!x || !u || !out || !ipa_inputs_valid(x, u)) return ZCL_ERR(-1, "Invalid IPA coefficient input");
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *p = ironwood_pasta_fp_modulus(), *cur = BN_lebin2bn(x, 32, NULL), *acc = BN_new();
    bool ok = ctx && p && cur && acc && ipa_product(ctx, p, cur, acc, u);
    uint8_t value[32];
    if (ok) ok = BN_bn2lebinpad(acc, value, sizeof value) == (int)sizeof value;
    if (ok) memcpy(out, value, sizeof value);
    BN_free(acc); BN_free(cur); BN_free(p); BN_CTX_free(ctx);
    return ok ? ZCL_OK : ZCL_ERR(-1, "Cannot compute IPA coefficient");
}

/* Double the prefix for each reverse-order challenge, as in Halo2 compute_s. */
static bool ipa_weights_fill(BN_CTX *ctx, const BIGNUM *p, const uint8_t u[IRONWOOD_IPA_ROUNDS][32],
                             uint8_t *weights)
{
    BIGNUM *factor = BN_new(), *value = BN_new();
    bool ok = factor && value;
    size_t count = 1;
    for (size_t round = IRONWOOD_IPA_ROUNDS; ok && round > 0; --round) {
        if (!BN_lebin2bn(u[round - 1], 32, factor)) { ok = false; break; }
        for (size_t j = 0; ok && j < count; ++j)
            ok = BN_lebin2bn(weights + j * 32, 32, value) &&
                BN_mod_mul(value, value, factor, p, ctx) &&
                BN_bn2lebinpad(value, weights + (count + j) * 32, 32) == 32;
        count *= 2;
    }
    BN_free(value); BN_free(factor);
    return ok;
}

struct zcl_result ironwood_ipa_generator_weights(const uint8_t initial[32],
    const uint8_t u[IRONWOOD_IPA_ROUNDS][32], uint8_t *out, size_t out_size)
{
    const size_t bytes = (size_t)IRONWOOD_IPA_GENERATORS * 32;
    if (!initial || !u || !out || out_size != bytes || !ipa_inputs_valid(initial, u))
        return ZCL_ERR(-1, "Invalid IPA generator weight input");
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *p = ironwood_pasta_fp_modulus();
    uint8_t *weights = zcl_malloc(bytes, "IPA generator weights");
    bool ok = ctx && p && weights;
    if (ok) { memcpy(weights, initial, 32); ok = ipa_weights_fill(ctx, p, u, weights); }
    if (ok) memcpy(out, weights, bytes);
    free(weights); BN_free(p); BN_CTX_free(ctx);
    return ok ? ZCL_OK : ZCL_ERR(-1, "Cannot compute IPA generator weights");
}
