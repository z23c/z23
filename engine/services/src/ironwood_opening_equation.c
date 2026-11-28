/* purpose: Evaluate the final Vesta IPA equation from a public Ironwood proof. */
/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#include "services/ironwood_opening_equation.h"
#include "services/ironwood_postnu63.h"
#include "ironwood_pasta_internal.h"
#include "util/safe_alloc.h"
#include <openssl/bn.h>
#include <stdlib.h>

struct opening_msm {
    BN_CTX *ctx;
    BIGNUM *prime, *scalar, *factor;
    EC_GROUP *group;
    EC_POINT *sum, *point, *term;
};

static bool msm_init(struct opening_msm *m)
{
    m->ctx = BN_CTX_new();
    m->prime = ironwood_pasta_fp_modulus();
    m->scalar = BN_new();
    m->factor = BN_new();
    if (!m->ctx || !m->prime || !m->scalar || !m->factor ||
        !ironwood_pasta_group(IRONWOOD_VESTA, m->ctx, &m->group).ok) return false;
    m->sum = EC_POINT_new(m->group);
    m->point = EC_POINT_new(m->group);
    m->term = EC_POINT_new(m->group);
    return m->sum && m->point && m->term;
}

static bool msm_add(struct opening_msm *m, const uint8_t point[32], const BIGNUM *weight)
{
    return ironwood_pasta_decode(point, IRONWOOD_VESTA, false, m->group, m->point, m->ctx).ok &&
        EC_POINT_mul(m->group, m->term, NULL, m->point, weight, m->ctx) == 1 &&
        EC_POINT_add(m->group, m->sum, m->sum, m->term, m->ctx) == 1;
}

/* The reference verifier batch-inverts the challenges, retaining zero at
 * zero entries. Keep that convention for the L coefficient. */
static bool msm_rounds(struct opening_msm *m, const struct ironwood_postnu63_opening *o,
                       const uint8_t *proof)
{
    bool ok = BN_lebin2bn(o->xi, 32, m->scalar) &&
        msm_add(m, proof + o->s_commitment_offset, m->scalar);
    for (size_t i = 0; ok && i < IRONWOOD_IPA_ROUNDS; ++i) {
        const uint8_t *left = proof + o->round_points_offset + i * 64;
        ok = BN_lebin2bn(o->round_challenges[i], 32, m->scalar) != NULL;
        if (ok) {
            if (BN_is_zero(m->scalar)) ok = BN_set_word(m->factor, 0);
            else ok = BN_mod_inverse(m->factor, m->scalar, m->prime, m->ctx) != NULL;
        }
        if (ok) ok = msm_add(m, left, m->factor) && msm_add(m, left + 32, m->scalar);
    }
    return ok;
}

static bool msm_blinding(struct opening_msm *m, const struct ironwood_postnu63_opening *o,
                         const struct ironwood_opening_basis *basis, uint8_t negative_c[32])
{
    uint8_t b[32];
    if (!ironwood_ipa_compute_b(o->x3, o->round_challenges, b).ok ||
        !BN_lebin2bn(o->c, 32, m->scalar) ||
        !BN_mod_sub(m->scalar, m->prime, m->scalar, m->prime, m->ctx) ||
        BN_bn2lebinpad(m->scalar, negative_c, 32) != 32) return false;
    if (!BN_lebin2bn(b, 32, m->factor) ||
        !BN_mod_mul(m->scalar, m->scalar, m->factor, m->prime, m->ctx) ||
        !BN_lebin2bn(o->z, 32, m->factor) ||
        !BN_mod_mul(m->scalar, m->scalar, m->factor, m->prime, m->ctx) ||
        !msm_add(m, basis->u, m->scalar)) return false;
    return BN_lebin2bn(o->f, 32, m->scalar) &&
        BN_mod_sub(m->scalar, m->prime, m->scalar, m->prime, m->ctx) &&
        msm_add(m, basis->w, m->scalar);
}

static bool msm_generators(struct opening_msm *m, const struct ironwood_postnu63_opening *o,
                           const struct ironwood_opening_basis *basis, const uint8_t evaluation[32],
                           const uint8_t negative_c[32])
{
    size_t bytes = sizeof basis->generators;
    uint8_t *weights = zcl_malloc(bytes, "Ironwood opening weights");
    if (!weights) return false;
    bool ok = ironwood_ipa_generator_weights(negative_c, o->round_challenges, weights, bytes).ok;
    for (size_t i = 0; ok && i < IRONWOOD_IPA_GENERATORS; ++i) {
        ok = BN_lebin2bn(weights + i * 32, 32, m->scalar) != NULL;
        if (ok && i == 0)
            ok = BN_lebin2bn(evaluation, 32, m->factor) &&
                BN_mod_sub(m->scalar, m->scalar, m->factor, m->prime, m->ctx);
        if (ok) ok = msm_add(m, basis->generators[i], m->scalar);
    }
    free(weights);
    return ok;
}

struct zcl_result ironwood_opening_equation(const struct ironwood_postnu63_stage *stage,
    const struct ironwood_opening_basis *basis, const uint8_t commitment[32],
    const uint8_t evaluation[32], bool *holds)
{
    if (!basis || !commitment || !evaluation || !holds || !ironwood_pasta_fp_canonical(evaluation).ok)
        return ZCL_ERR(-1, "Invalid Ironwood opening claim");
    struct ironwood_postnu63_opening opening;
    struct zcl_result r = ironwood_postnu63_opening_transcript(stage, &opening);
    if (!r.ok) return r;
    struct opening_msm m = {0};
    uint8_t negative_c[32];
    bool ok = msm_init(&m) &&
        ironwood_pasta_decode(commitment, IRONWOOD_VESTA, true, m.group, m.sum, m.ctx).ok &&
        msm_rounds(&m, &opening, stage->proof.buffer) &&
        msm_blinding(&m, &opening, basis, negative_c) &&
        msm_generators(&m, &opening, basis, evaluation, negative_c);
    int identity = ok ? EC_POINT_is_at_infinity(m.group, m.sum) : -1;
    EC_POINT_free(m.term); EC_POINT_free(m.point); EC_POINT_free(m.sum);
    EC_GROUP_free(m.group); BN_free(m.factor); BN_free(m.scalar);
    BN_free(m.prime); BN_CTX_free(m.ctx);
    if (identity < 0) return ZCL_ERR(-1, "Cannot evaluate Ironwood opening equation");
    *holds = identity == 1;
    return ZCL_OK;
}
