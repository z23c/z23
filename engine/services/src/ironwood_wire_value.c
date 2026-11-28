/* purpose: Derive the PostNu6_3 IPA evaluation from the wire and expected quotient. */
/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#include "services/ironwood_postnu63_query.h"
#include "services/ironwood_postnu63.h"
#include "services/ironwood_multiopen.h"
#include "ironwood_pasta_internal.h"
#include <openssl/bn.h>
#include <string.h>

struct value_work {
    BN_CTX *ctx;
    BIGNUM *prime, *x1, *term;
    BIGNUM *sum[IRONWOOD_MULTIOPEN_SETS][IRONWOOD_MULTIOPEN_POINTS];
};

static const unsigned cardinality[IRONWOOD_MULTIOPEN_SETS] = {1, 2, 3, 3, 2};
/* Rotations in the five point sets: (0), (0,+1), (0,+1,-1),
 * (0,+1,-6), (0,-1). omega = 5^((Fp-1)/2048). */
static const unsigned rotation_index[5][3] = {{0},{0,1},{0,1,2},{0,1,3},{0,2}};
static const uint8_t rotation[4][32] = {
    {0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00},
    {0x13,0x78,0xa1,0xad,0x5a,0x54,0x28,0xef,0x4e,0xc2,0xa1,0xaa,0xbc,0x88,0x9b,0x7a,0x0b,0x60,0x6d,0x42,0x95,0xd3,0xcb,0x31,0x9e,0x11,0x32,0x5f,0xad,0x50,0x1b,0x18},
    {0x04,0x6f,0xce,0x46,0xa0,0x8b,0x69,0x3b,0x3a,0x75,0x5b,0x90,0xe3,0x7d,0x1f,0x5e,0x38,0x53,0x29,0x2e,0x53,0xcf,0xac,0x75,0x47,0xde,0x72,0xa2,0x7d,0x38,0xbb,0x1a},
    {0xe4,0x49,0x2e,0x2f,0xf5,0xe4,0x84,0x83,0xd2,0xb4,0x8f,0xca,0x92,0x8c,0xfe,0x14,0x23,0xd2,0x98,0x5b,0x6d,0x0c,0x2b,0x16,0x5f,0xe1,0xb9,0xd7,0x38,0x2f,0xcc,0x06},
};

static bool init_sums(struct value_work *w, const uint8_t x1[32])
{
    w->x1 = BN_CTX_get(w->ctx);
    w->term = BN_CTX_get(w->ctx);
    if (!w->term) return false;
    for (size_t i = 0; i < IRONWOOD_MULTIOPEN_SETS; ++i)
        for (size_t j = 0; j < cardinality[i]; ++j) {
            w->sum[i][j] = BN_CTX_get(w->ctx);
            if (!w->sum[i][j]) return false;
        }
    /* BN_CTX_get returns a zero-valued temporary. */
    return BN_lebin2bn(x1, 32, w->x1) != NULL;
}
static bool horner_slot(struct value_work *w, BIGNUM *acc, const uint8_t value[32])
{
    return BN_lebin2bn(value, 32, w->term) && BN_mod_mul(acc, acc, w->x1, w->prime, w->ctx) &&
        BN_mod_add(acc, acc, w->term, w->prime, w->ctx);
}
static bool wire_value_accumulate(struct value_work *w, const struct ironwood_opening_query *q,
                       const struct ironwood_postnu63_stage *stage, const uint8_t h[32])
{
    size_t bytes = stage->proof.position - stage->instance_eval_offset;
    const uint8_t *evals = stage->proof.buffer + stage->instance_eval_offset;
    if (q->set >= IRONWOOD_MULTIOPEN_SETS || q->count != cardinality[q->set]) return false;
    bool ok = true;
    for (size_t j = 0; ok && j < q->count; ++j) {
        if (q->evaluation[j] >= bytes/32) return false;
        const uint8_t *e = q->source == IRONWOOD_QUERY_H ? h : evals + 32*q->evaluation[j];
        ok = horner_slot(w, w->sum[q->set][j], e);
    }
    return ok;
}

static bool prepare_sets(struct value_work *w, const struct ironwood_postnu63_stage *stage,
                         const struct ironwood_postnu63_opening *opening, struct ironwood_multiopen_set *sets)
{
    BIGNUM *x = w->x1;
    uint8_t rotated[4][32];
    bool ok = BN_lebin2bn(stage->x, 32, x) != NULL;
    for (size_t i = 0; ok && i < 4; ++i)
        ok = BN_lebin2bn(rotation[i], 32, w->term) && BN_mod_mul(w->term, w->term, x, w->prime, w->ctx) &&
            BN_bn2lebinpad(w->term, rotated[i], 32) == 32;
    for (size_t i = 0; ok && i < IRONWOOD_MULTIOPEN_SETS; ++i) {
        sets[i].count = cardinality[i];
        memcpy(sets[i].u, opening->set_evaluations[i], 32);
        for (size_t j = 0; ok && j < sets[i].count; ++j) {
            memcpy(sets[i].points[j], rotated[rotation_index[i][j]], 32);
            ok = BN_bn2lebinpad(w->sum[i][j], sets[i].evaluations[j], 32) == 32;
        }
    }
    return ok;
}
static struct zcl_result fold_wire_value(const struct ironwood_postnu63_stage *stage,
    const struct ironwood_postnu63_opening *opening, const uint8_t h[32], uint8_t out[32])
{
    struct value_work w = {.ctx = BN_CTX_new(), .prime = ironwood_pasta_fp_modulus()};
    if (!w.ctx || !w.prime) {
        BN_CTX_free(w.ctx); BN_free(w.prime);
        return ZCL_ERR(-1, "Cannot allocate opening evaluation field");
    }
    BN_CTX_start(w.ctx);
    size_t count = IRONWOOD_SHARED_OPENING_QUERIES + IRONWOOD_ACTION_OPENING_QUERIES * (size_t)stage->actions;
    bool ok = init_sums(&w, stage->x1);
    /* Reverse accumulation order permits Horner folding with one scalar per slot. */
    while (ok && count) {
        struct ironwood_opening_query q = {0};
        ok = ironwood_postnu63_query_at(stage->actions, --count, &q).ok && wire_value_accumulate(&w, &q, stage, h);
    }
    struct ironwood_multiopen_set sets[IRONWOOD_MULTIOPEN_SETS] = {0};
    if (ok) ok = prepare_sets(&w, stage, opening, sets);
    BN_CTX_end(w.ctx); BN_CTX_free(w.ctx); BN_free(w.prime);
    if (!ok) return ZCL_ERR(-1, "Cannot derive PostNu6_3 opening evaluation sets");
    return ironwood_multiopen_value(sets, opening->x2, opening->x3, opening->x4, out);
}

struct zcl_result ironwood_postnu63_wire_value(const struct v6_wire_view *view,
                                                const uint8_t expected_h[32], uint8_t out[32])
{
    if (!out || !expected_h || !ironwood_pasta_fp_canonical(expected_h).ok)
        return ZCL_ERR(-1, "Invalid PostNu6_3 expected quotient evaluation");
    struct ironwood_postnu63_stage stage;
    struct ironwood_postnu63_opening opening;
    struct zcl_result r = ironwood_postnu63_prepare_opening(view, &stage);
    if (r.ok) r = ironwood_postnu63_opening_transcript(&stage, &opening);
    return r.ok ? fold_wire_value(&stage, &opening, expected_h, out) : r;
}
