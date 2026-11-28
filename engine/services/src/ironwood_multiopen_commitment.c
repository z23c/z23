/* purpose: Fold ordered public Halo2 multiopening commitments. */
/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#include "services/ironwood_multiopen_commitment.h"
#include "ironwood_pasta_internal.h"
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <string.h>

static bool inputs_valid(const struct ironwood_multiopen_commitment *items, size_t count,
                         const uint8_t *q, const uint8_t *x1, const uint8_t *x4)
{
    if (!items || !q || !x1 || !x4 || !count || count > SIZE_MAX / sizeof *items ||
        !ironwood_pasta_fp_canonical(x1).ok || !ironwood_pasta_fp_canonical(x4).ok) return false;
    unsigned mask = 0;
    for (size_t i = 0; i < count; ++i) {
        if (items[i].group >= IRONWOOD_MULTIOPEN_GROUPS ||
            (items[i].kind != IRONWOOD_MULTIOPEN_PROOF_POINT &&
             items[i].kind != IRONWOOD_MULTIOPEN_DERIVED_POINT)) return false;
        mask |= 1u << items[i].group;
    }
    return mask == (1u << IRONWOOD_MULTIOPEN_GROUPS) - 1u;
}
static bool encode_point(const EC_GROUP *g, const EC_POINT *point, BN_CTX *ctx, uint8_t out[32])
{
    int identity = EC_POINT_is_at_infinity(g, point);
    if (identity < 0) return false;
    if (identity) { memset(out, 0, 32); return true; }
    BN_CTX_start(ctx);
    BIGNUM *x = BN_CTX_get(ctx), *y = BN_CTX_get(ctx);
    bool ok = y && EC_POINT_get_affine_coordinates(g, point, x, y, ctx) &&
              BN_bn2lebinpad(x, out, 32) == 32;
    if (ok && BN_is_odd(y)) out[31] |= 0x80;
    BN_CTX_end(ctx);
    return ok;
}
static bool fold_group(const struct ironwood_multiopen_commitment *items, size_t count,
                       unsigned group, const BIGNUM *x1, const EC_GROUP *g, BN_CTX *ctx,
                       EC_POINT *acc, EC_POINT *point, EC_POINT *term)
{
    if (EC_POINT_set_to_infinity(g, acc) != 1) return false;
    for (size_t i = count; i > 0; --i) {
        const struct ironwood_multiopen_commitment *item = &items[i - 1];
        if (item->group != group) continue;
        bool identity = item->kind == IRONWOOD_MULTIOPEN_DERIVED_POINT;
        if (!ironwood_pasta_decode(item->point, IRONWOOD_VESTA, identity, g, point, ctx).ok ||
            !EC_POINT_mul(g, term, NULL, acc, x1, ctx) || !EC_POINT_add(g, acc, term, point, ctx))
            return false;
    }
    return true;
}
static bool calculate(const struct ironwood_multiopen_commitment *items, size_t count,
                      const uint8_t *q, const uint8_t *x1, const uint8_t *x4,
                      const EC_GROUP *g, BN_CTX *ctx, uint8_t value[32])
{
    BIGNUM *c1 = BN_lebin2bn(x1, 32, NULL), *c4 = BN_lebin2bn(x4, 32, NULL);
    EC_POINT *acc = EC_POINT_new(g), *bucket = EC_POINT_new(g);
    EC_POINT *point = EC_POINT_new(g), *term = EC_POINT_new(g);
    bool ok = c1 && c4 && acc && bucket && point && term;
    if (ok) ok = ironwood_pasta_decode(q, IRONWOOD_VESTA, false, g, acc, ctx).ok;
    for (unsigned i = 0; ok && i < IRONWOOD_MULTIOPEN_GROUPS; ++i)
        ok = fold_group(items, count, i, c1, g, ctx, bucket, point, term) &&
             EC_POINT_mul(g, term, NULL, acc, c4, ctx) && EC_POINT_add(g, acc, term, bucket, ctx);
    if (ok) ok = encode_point(g, acc, ctx, value);
    EC_POINT_free(term); EC_POINT_free(point); EC_POINT_free(bucket); EC_POINT_free(acc);
    BN_free(c4); BN_free(c1);
    return ok;
}
struct zcl_result ironwood_multiopen_commitment_fold(const struct ironwood_multiopen_commitment *items,
    size_t count, const uint8_t q_prime[32], const uint8_t x1[32], const uint8_t x4[32], uint8_t out[32])
{
    if (!out || !inputs_valid(items, count, q_prime, x1, x4))
        return ZCL_ERR(-1, "Invalid multiopening commitment inputs");
    BN_CTX *ctx = BN_CTX_new();
    EC_GROUP *g = NULL;
    bool ok = ctx && ironwood_pasta_group(IRONWOOD_VESTA, ctx, &g).ok;
    uint8_t value[32];
    if (ok) ok = calculate(items, count, q_prime, x1, x4, g, ctx, value);
    EC_GROUP_free(g); BN_CTX_free(ctx);
    if (!ok) return ZCL_ERR(-1, "Cannot fold multiopening commitments");
    memcpy(out, value, sizeof value);
    return ZCL_OK;
}
