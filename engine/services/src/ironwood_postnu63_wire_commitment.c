/* purpose: Derive a PostNu6_3 opening commitment from public wire inputs. */
/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#include "services/ironwood_postnu63_wire_commitment.h"
#include "services/ironwood_postnu63.h"
#include "services/ironwood_postnu63_query.h"
#include "services/ironwood_multiopen_commitment.h"
#include "ironwood_pasta_internal.h"
#include "ironwood_multiopen_point_internal.h"
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <string.h>

static bool quotient_fold(const struct ironwood_postnu63_stage *stage, const EC_GROUP *g,
                          BN_CTX *ctx, uint8_t out[32])
{
    if (stage->quotient_offset > stage->proof.length ||
        stage->proof.length - stage->quotient_offset < 8 * 32) return false;
    BIGNUM *p = ironwood_pasta_fp_modulus(), *power = BN_lebin2bn(stage->x, 32, NULL);
    EC_POINT *sum = EC_POINT_new(g), *point = EC_POINT_new(g), *term = EC_POINT_new(g);
    bool ok = p && power && sum && point && term && EC_POINT_set_to_infinity(g, sum);
    for (unsigned i = 0; ok && i < 11; ++i) ok = BN_mod_sqr(power, power, p, ctx);
    for (size_t i = 8; ok && i > 0; --i) {
        const uint8_t *wire = stage->proof.buffer + stage->quotient_offset + (i - 1) * 32;
        ok = ironwood_pasta_decode(wire, IRONWOOD_VESTA, false, g, point, ctx).ok &&
             EC_POINT_mul(g, term, NULL, sum, power, ctx) && EC_POINT_add(g, sum, term, point, ctx);
    }
    if (ok) ok = ironwood_multiopen_encode(g, sum, ctx, out);
    EC_POINT_free(term); EC_POINT_free(point); EC_POINT_free(sum); BN_free(power); BN_free(p);
    return ok;
}
struct query_context {
    const struct v6_wire_view *view;
    const struct ironwood_postnu63_stage *stage;
    uint8_t h[32];
};
static struct zcl_result query_item(void *context, size_t ordinal, struct ironwood_multiopen_commitment *out)
{
    const struct query_context *c = context;
    struct ironwood_opening_query query;
    struct zcl_result r = ironwood_postnu63_query_at(c->stage->actions, ordinal, &query);
    if (!r.ok) return r;
    struct ironwood_multiopen_commitment item = { .group = query.set };
    if (query.source == IRONWOOD_QUERY_H) {
        item.kind = IRONWOOD_MULTIOPEN_DERIVED_POINT;
        memcpy(item.point, c->h, 32);
    } else if (query.source == IRONWOOD_QUERY_VK) {
        memcpy(item.point, query.vk, 32);
    } else if (query.source == IRONWOOD_QUERY_INSTANCE) {
        item.kind = IRONWOOD_MULTIOPEN_DERIVED_POINT;
        r = ironwood_postnu63_instance_commitment(c->view, query.point, item.point);
        if (!r.ok) return r;
    } else if (query.source == IRONWOOD_QUERY_WIRE) {
        if (query.point > (c->stage->proof.length - 32) / 32)
            return ZCL_ERR(-1, "Opening commitment outside proof");
        memcpy(item.point, c->stage->proof.buffer + query.point * 32, 32);
    } else return ZCL_ERR(-1, "Unknown opening query source");
    *out = item;
    return ZCL_OK;
}
struct zcl_result ironwood_postnu63_wire_commitment(const struct v6_wire_view *view, uint8_t out[32])
{
    if (!view || !out) return ZCL_ERR(-1, "Missing wire commitment input");
    struct ironwood_postnu63_stage stage;
    struct ironwood_postnu63_opening opening;
    struct zcl_result r = ironwood_postnu63_prepare_opening(view, &stage);
    if (r.ok) r = ironwood_postnu63_opening_transcript(&stage, &opening);
    if (!r.ok) return r;
    if (opening.quotient_commitment_offset > stage.proof.length ||
        stage.proof.length - opening.quotient_commitment_offset < 32)
        return ZCL_ERR(-1, "Opening quotient outside proof");
    BN_CTX *ctx = BN_CTX_new(); EC_GROUP *g = NULL;
    bool ok = ctx && ironwood_pasta_group(IRONWOOD_VESTA, ctx, &g).ok;
    struct query_context c = { .view = view, .stage = &stage };
    if (ok) ok = quotient_fold(&stage, g, ctx, c.h);
    EC_GROUP_free(g); BN_CTX_free(ctx);
    if (!ok) return ZCL_ERR(-1, "Cannot fold quotient commitments");
    size_t count = IRONWOOD_SHARED_OPENING_QUERIES + (size_t)stage.actions * IRONWOOD_ACTION_OPENING_QUERIES;
    return ironwood_multiopen_commitment_fold_stream(query_item, &c, count,
        stage.proof.buffer + opening.quotient_commitment_offset, stage.x1, opening.x4, out);
}
