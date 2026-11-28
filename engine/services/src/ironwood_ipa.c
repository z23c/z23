/* purpose: Compute the public PostNu6_3 IPA evaluation coefficient. */
/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#include "services/ironwood_ipa.h"
#include "ironwood_pasta_internal.h"
#include <openssl/bn.h>
#include <string.h>

struct zcl_result ironwood_ipa_compute_b(const uint8_t x[32],
    const uint8_t u[IRONWOOD_IPA_ROUNDS][32], uint8_t out[32])
{
    static const uint8_t modulus[32] = {
        0x01,0x00,0x00,0x00,0xed,0x30,0x2d,0x99,0x1b,0xf9,0x4c,0x09,0xfc,0x98,0x46,0x22,
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x40};
    if (!x || !u || !out) return ZCL_ERR(-1, "Missing IPA coefficient input");
    if (!ironwood_pasta_fp_canonical(x).ok) return ZCL_ERR(-1, "Noncanonical IPA opening point");
    for (size_t i = 0; i < IRONWOOD_IPA_ROUNDS; ++i)
        if (!ironwood_pasta_fp_canonical(u[i]).ok) return ZCL_ERR(-1, "Noncanonical IPA challenge");
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *p = BN_lebin2bn(modulus, 32, NULL), *cur = BN_lebin2bn(x, 32, NULL);
    BIGNUM *one = BN_new(), *acc = BN_new(), *term = BN_new(), *challenge = BN_new();
    bool ok = ctx && p && cur && one && acc && term && challenge && BN_set_word(one, 1) && BN_set_word(acc, 1);
    for (size_t i = IRONWOOD_IPA_ROUNDS; ok && i > 0; --i) {
        ok = BN_lebin2bn(u[i - 1], 32, challenge) && BN_mod_mul(term, challenge, cur, p, ctx) &&
            BN_mod_add(term, term, one, p, ctx) && BN_mod_mul(acc, acc, term, p, ctx) &&
            BN_mod_sqr(cur, cur, p, ctx);
    }
    uint8_t value[32];
    if (ok) ok = BN_bn2lebinpad(acc, value, sizeof value) == (int)sizeof value;
    if (ok) memcpy(out, value, sizeof value);
    BN_free(challenge); BN_free(term); BN_free(acc); BN_free(one); BN_free(cur); BN_free(p); BN_CTX_free(ctx);
    return ok ? ZCL_OK : ZCL_ERR(-1, "Cannot compute IPA coefficient");
}
