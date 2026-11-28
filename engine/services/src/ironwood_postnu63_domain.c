/* purpose: Evaluate the public PostNu6_3 verification-domain row factors. */
/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#include "services/ironwood_postnu63_domain.h"
#include "services/ironwood_postnu63.h"
#include "ironwood_pasta_internal.h"
#include <openssl/bn.h>

enum { DOMAIN_LOG = 11, DOMAIN_SIZE = 2048, LAST_ROW = 6 };
struct domain_work {
    BN_CTX *ctx;
    BIGNUM *prime, *x, *omega, *power, *numer, *root, *step, *den, *term, *sum, *one, *scale;
};

static struct zcl_result domain_power(struct domain_work *w)
{
    for (unsigned i = 0; i < DOMAIN_LOG - 1; ++i)
        if (!BN_mod_sqr(w->power, w->power, w->prime, w->ctx)) return ZCL_ERR(-1, "Cannot check domain root");
    if (!BN_mod_sub(w->den, w->power, w->one, w->prime, w->ctx)) return ZCL_ERR(-1, "Cannot check domain root");
    if (BN_is_zero(w->den)) return ZCL_ERR(-1, "Domain root has insufficient order");
    if (!BN_mod_sqr(w->power, w->power, w->prime, w->ctx) ||
        !BN_mod_sub(w->den, w->power, w->one, w->prime, w->ctx))
        return ZCL_ERR(-1, "Cannot check domain root");
    return BN_is_zero(w->den) ? ZCL_OK : ZCL_ERR(-1, "Domain root has incorrect order");
}

static struct zcl_result domain_term(struct domain_work *w)
{
    if (!BN_mod_sub(w->den, w->x, w->root, w->prime, w->ctx) ||
        !BN_mod_mul(w->den, w->den, w->scale, w->prime, w->ctx) ||
        !BN_mod_inverse(w->term, w->den, w->prime, w->ctx) ||
        !BN_mod_mul(w->term, w->term, w->numer, w->prime, w->ctx) ||
        !BN_mod_mul(w->term, w->term, w->root, w->prime, w->ctx))
        return ZCL_ERR(-1, "Cannot evaluate domain row");
    return ZCL_OK;
}

static struct zcl_result domain_lagrange(struct domain_work *w, struct ironwood_postnu63_domain_rows *rows)
{
    for (unsigned i = 0; i <= LAST_ROW; ++i) {
        struct zcl_result r = domain_term(w);
        if (!r.ok) return r;
        if (i == 0 && BN_bn2lebinpad(w->term, rows->l0, 32) != 32) return ZCL_ERR(-1, "Cannot encode first row");
        if (i == LAST_ROW && BN_bn2lebinpad(w->term, rows->last, 32) != 32) return ZCL_ERR(-1, "Cannot encode last row");
        if (i && !BN_mod_add(w->sum, w->sum, w->term, w->prime, w->ctx)) return ZCL_ERR(-1, "Cannot sum blind rows");
        if (!BN_mod_mul(w->root, w->root, w->step, w->prime, w->ctx)) return ZCL_ERR(-1, "Cannot rotate domain root");
    }
    if (!BN_mod_sub(w->sum, w->one, w->sum, w->prime, w->ctx) ||
        BN_bn2lebinpad(w->sum, rows->active, 32) != 32) return ZCL_ERR(-1, "Cannot encode active rows");
    return ZCL_OK;
}

static struct zcl_result domain_values(struct domain_work *w, struct ironwood_postnu63_domain_rows *rows)
{
    for (unsigned i = 0; i < DOMAIN_LOG; ++i)
        if (!BN_mod_sqr(w->numer, w->numer, w->prime, w->ctx)) return ZCL_ERR(-1, "Cannot evaluate domain power");
    if (!BN_mod_sub(w->numer, w->numer, w->one, w->prime, w->ctx))
        return ZCL_ERR(-1, "Cannot compute domain numerator");
    if (BN_is_zero(w->numer)) return ZCL_ERR(-1, "Challenge lies in the evaluation domain");
    if (!BN_mod_inverse(w->step, w->omega, w->prime, w->ctx) ||
        !BN_set_word(w->root, 1) || !BN_set_word(w->sum, 0))
        return ZCL_ERR(-1, "Cannot initialize domain rows");
    return domain_lagrange(w, rows);
}

static struct zcl_result domain_calculate(const uint8_t x[32], const uint8_t omega[32],
                                           struct ironwood_postnu63_domain_rows *rows)
{
    struct domain_work w = { .ctx = BN_CTX_new(), .prime = ironwood_pasta_fp_modulus() };
    if (!w.ctx || !w.prime) { BN_CTX_free(w.ctx); BN_free(w.prime); return ZCL_ERR(-1, "Cannot allocate domain field"); }
    BN_CTX_start(w.ctx);
    w.x = BN_CTX_get(w.ctx); w.omega = BN_CTX_get(w.ctx); w.power = BN_CTX_get(w.ctx);
    w.numer = BN_CTX_get(w.ctx); w.root = BN_CTX_get(w.ctx); w.step = BN_CTX_get(w.ctx);
    w.den = BN_CTX_get(w.ctx); w.term = BN_CTX_get(w.ctx); w.sum = BN_CTX_get(w.ctx);
    w.one = BN_CTX_get(w.ctx); w.scale = BN_CTX_get(w.ctx);
    struct zcl_result r = w.scale ? ZCL_OK : ZCL_ERR(-1, "Cannot allocate domain scalars");
    if (r.ok && (!BN_lebin2bn(x, 32, w.x) || !BN_lebin2bn(x, 32, w.numer) ||
        !BN_lebin2bn(omega, 32, w.omega) || !BN_lebin2bn(omega, 32, w.power) ||
        !BN_set_word(w.one, 1) || !BN_set_word(w.scale, DOMAIN_SIZE)))
        r = ZCL_ERR(-1, "Cannot initialize domain scalars");
    if (r.ok) r = domain_power(&w);
    if (r.ok) r = domain_values(&w, rows);
    BN_CTX_end(w.ctx); BN_CTX_free(w.ctx); BN_free(w.prime);
    return r;
}

struct zcl_result ironwood_postnu63_domain_rows(const struct ironwood_postnu63_stage *stage,
    const uint8_t omega[32], struct ironwood_postnu63_domain_rows *out)
{
    if (!stage || !omega || !out || stage->phase != IRONWOOD_POSTNU63_EVAL_X1 || !stage->actions)
        return ZCL_ERR(-1, "Invalid PostNu6_3 domain input");
    struct zcl_result r = ironwood_pasta_fp_canonical(stage->x);
    if (r.ok) r = ironwood_pasta_fp_canonical(omega);
    struct ironwood_postnu63_domain_rows rows = {0};
    if (r.ok) r = domain_calculate(stage->x, omega, &rows);
    if (r.ok) *out = rows;
    return r;
}
