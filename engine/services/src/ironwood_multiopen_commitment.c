/* purpose: Fold ordered public Halo2 multiopening commitments. */
/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#include "services/ironwood_multiopen_commitment.h"
#include "ironwood_pasta_internal.h"
#include "ironwood_multiopen_point_internal.h"
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <string.h>

static bool accumulate_item(const struct ironwood_multiopen_commitment *item,
                            const BIGNUM *x1, const EC_GROUP *g, BN_CTX *ctx,
                            EC_POINT *buckets[IRONWOOD_MULTIOPEN_GROUPS], EC_POINT *point, EC_POINT *term)
{
    if (item->group >= IRONWOOD_MULTIOPEN_GROUPS ||
        (item->kind != IRONWOOD_MULTIOPEN_PROOF_POINT && item->kind != IRONWOOD_MULTIOPEN_DERIVED_POINT))
        return false;
    bool identity = item->kind == IRONWOOD_MULTIOPEN_DERIVED_POINT;
    EC_POINT *bucket = buckets[item->group];
    return ironwood_pasta_decode(item->point, IRONWOOD_VESTA, identity, g, point, ctx).ok &&
           EC_POINT_mul(g, term, NULL, bucket, x1, ctx) && EC_POINT_add(g, bucket, term, point, ctx);
}
static bool multiopen_accumulate(ironwood_multiopen_item_at item_at, void *context, size_t count,
                       const BIGNUM *x1, const EC_GROUP *g, BN_CTX *ctx,
                       EC_POINT *buckets[IRONWOOD_MULTIOPEN_GROUPS], EC_POINT *point, EC_POINT *term)
{
    unsigned mask = 0;
    for (size_t i = count; i > 0; --i) {
        struct ironwood_multiopen_commitment item;
        struct zcl_result r = item_at(context, i - 1, &item);
        if (!r.ok) return false;
        if (!accumulate_item(&item, x1, g, ctx, buckets, point, term)) return false; // raw-return-ok: public fold returns contextual error
        mask |= 1u << item.group;
    }
    return mask == (1u << IRONWOOD_MULTIOPEN_GROUPS) - 1u;
}
static bool calculate(ironwood_multiopen_item_at item_at, void *context, size_t count,
                      const uint8_t *q, const uint8_t *x1, const uint8_t *x4,
                      const EC_GROUP *g, BN_CTX *ctx, uint8_t value[32])
{
    BIGNUM *c1 = BN_lebin2bn(x1, 32, NULL), *c4 = BN_lebin2bn(x4, 32, NULL);
    EC_POINT *acc = EC_POINT_new(g), *point = EC_POINT_new(g), *term = EC_POINT_new(g);
    EC_POINT *buckets[IRONWOOD_MULTIOPEN_GROUPS] = {0};
    bool ok = c1 && c4 && acc && point && term;
    for (unsigned i = 0; ok && i < IRONWOOD_MULTIOPEN_GROUPS; ++i) {
        buckets[i] = EC_POINT_new(g);
        ok = buckets[i] && EC_POINT_set_to_infinity(g, buckets[i]);
    }
    if (ok) ok = ironwood_pasta_decode(q, IRONWOOD_VESTA, false, g, acc, ctx).ok;
    if (ok) ok = multiopen_accumulate(item_at, context, count, c1, g, ctx, buckets, point, term);
    for (unsigned i = 0; ok && i < IRONWOOD_MULTIOPEN_GROUPS; ++i)
        ok = EC_POINT_mul(g, term, NULL, acc, c4, ctx) && EC_POINT_add(g, acc, term, buckets[i], ctx);
    if (ok) ok = ironwood_multiopen_encode(g, acc, ctx, value);
    for (unsigned i = 0; i < IRONWOOD_MULTIOPEN_GROUPS; ++i) EC_POINT_free(buckets[i]);
    EC_POINT_free(term); EC_POINT_free(point); EC_POINT_free(acc); BN_free(c4); BN_free(c1);
    return ok;
}
struct zcl_result ironwood_multiopen_commitment_fold_stream(ironwood_multiopen_item_at item_at,
    void *context, size_t count, const uint8_t q_prime[32], const uint8_t x1[32], const uint8_t x4[32], uint8_t out[32])
{
    if (!item_at || !count || !q_prime || !x1 || !x4 || !out ||
        !ironwood_pasta_fp_canonical(x1).ok || !ironwood_pasta_fp_canonical(x4).ok)
        return ZCL_ERR(-1, "Invalid multiopening commitment inputs");
    BN_CTX *ctx = BN_CTX_new(); EC_GROUP *g = NULL;
    bool ok = ctx && ironwood_pasta_group(IRONWOOD_VESTA, ctx, &g).ok;
    uint8_t value[32];
    if (ok) ok = calculate(item_at, context, count, q_prime, x1, x4, g, ctx, value);
    EC_GROUP_free(g); BN_CTX_free(ctx);
    if (!ok) return ZCL_ERR(-1, "Cannot fold multiopening commitments");
    memcpy(out, value, sizeof value);
    return ZCL_OK;
}
static struct zcl_result array_item(void *context, size_t ordinal, struct ironwood_multiopen_commitment *out)
{
    const struct ironwood_multiopen_commitment *items = context;
    *out = items[ordinal];
    return ZCL_OK;
}
struct zcl_result ironwood_multiopen_commitment_fold(const struct ironwood_multiopen_commitment *items,
    size_t count, const uint8_t q_prime[32], const uint8_t x1[32], const uint8_t x4[32], uint8_t out[32])
{
    if (!items || count > SIZE_MAX / sizeof *items) return ZCL_ERR(-1, "Invalid commitment array");
    return ironwood_multiopen_commitment_fold_stream(array_item, (void *)items, count, q_prime, x1, x4, out);
}
