/* purpose: Project public Ironwood action statements to Halo2 field rows. */
/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#include "services/ironwood_instance.h"
#include "ironwood_pasta_internal.h"
#include "primitives/transaction_v6_wire.h"
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <string.h>

struct zcl_result ironwood_instance_from_statement(const uint8_t *s, size_t size,
                                                    struct ironwood_instance_rows *out)
{
    struct ironwood_instance_rows rows = {0};
    uint8_t affine[64];
    if (!s || size != V6_IRONWOOD_STATEMENT_SIZE || !out)
        return ZCL_ERR(-1, "Invalid Ironwood statement input");
    if (s[160] > 1 || s[161] > 1 || s[162] > 1)
        return ZCL_ERR(-1, "Invalid Ironwood statement flag");
    static const size_t offsets[] = {0, 64, 128};
    for (size_t i = 0; i < sizeof offsets / sizeof offsets[0]; ++i) {
        struct zcl_result field = ironwood_pasta_fp_canonical(s + offsets[i]);
        if (!field.ok) return field;
    }
    struct zcl_result point = ironwood_pasta_point(s + 32, IRONWOOD_PALLAS, true, affine);
    if (!point.ok) return point;
    memcpy(rows.row[1], affine, 32); memcpy(rows.row[2], affine + 32, 32);
    point = ironwood_pasta_point(s + 96, IRONWOOD_PALLAS, false, affine);
    if (!point.ok) return point;
    memcpy(rows.row[4], affine, 32); memcpy(rows.row[5], affine + 32, 32);
    memcpy(rows.row[0], s, 32); memcpy(rows.row[3], s + 64, 32);
    memcpy(rows.row[6], s + 128, 32);
    for (size_t i = 0; i < 3; ++i) rows.row[7+i][0] = s[160+i];
    *out = rows;
    return ZCL_OK;
}

struct zcl_result ironwood_instance_project(const struct v6_wire_view *view, uint64_t action,
                                            struct ironwood_instance_rows *out)
{
    uint8_t s[V6_IRONWOOD_STATEMENT_SIZE];
    if (!out || !v6_core_ironwood_statement(view, action, s, sizeof s))
        return ZCL_ERR(-1, "Invalid Ironwood action statement");
    return ironwood_instance_from_statement(s, sizeof s, out);
}

static struct zcl_result commitment_add(const EC_GROUP *group, EC_POINT *sum,
                                         const uint8_t encoded[32], const uint8_t scalar[32],
                                         EC_POINT *point, EC_POINT *term, BIGNUM *n, BN_CTX *ctx)
{
    struct zcl_result decoded = ironwood_pasta_decode(encoded, IRONWOOD_VESTA, false, group, point, ctx);
    if (!decoded.ok) return decoded;
    struct zcl_result canonical = ironwood_pasta_fp_canonical(scalar);
    if (!canonical.ok) return canonical;
    bool ok = BN_lebin2bn(scalar, 32, n) &&
        EC_POINT_mul(group, term, NULL, point, n, ctx) == 1 &&
        EC_POINT_add(group, sum, sum, term, ctx) == 1;
    return ok ? ZCL_OK : ZCL_ERR(-1, "Cannot accumulate Ironwood instance point");
}

static struct zcl_result commitment_encode(const EC_GROUP *group, const EC_POINT *sum,
                                            BN_CTX *ctx, uint8_t out[32])
{
    int infinity = EC_POINT_is_at_infinity(group, sum);
    if (infinity < 0) return ZCL_ERR(-1, "Cannot inspect Ironwood instance point");
    if (infinity) { memset(out, 0, 32); return ZCL_OK; }
    BIGNUM *x = BN_new(), *y = BN_new();
    bool ok = x && y && EC_POINT_get_affine_coordinates(group, sum, x, y, ctx) == 1 &&
        BN_bn2lebinpad(x, out, 32) == 32;
    if (ok && BN_is_odd(y)) out[31] |= 0x80;
    BN_free(y); BN_free(x);
    return ok ? ZCL_OK : ZCL_ERR(-1, "Cannot encode Ironwood instance point");
}

struct zcl_result ironwood_instance_commitment(const struct ironwood_instance_rows *rows,
                                                const uint8_t basis[IRONWOOD_INSTANCE_ROWS][32],
                                                const uint8_t w[32], uint8_t out[32])
{
    if (!rows || !basis || !w || !out) return ZCL_ERR(-1, "Missing Ironwood commitment input");
    BN_CTX *ctx = BN_CTX_new(); BIGNUM *n = BN_new();
    EC_GROUP *group = NULL; EC_POINT *sum = NULL, *point = NULL, *term = NULL;
    struct zcl_result result = ironwood_pasta_group(IRONWOOD_VESTA, ctx, &group);
    if (result.ok) {
        sum = EC_POINT_new(group); point = EC_POINT_new(group); term = EC_POINT_new(group);
        if (!n || !sum || !point || !term) result = ZCL_ERR(-1, "Cannot allocate Vesta points");
    }
    if (result.ok) result = ironwood_pasta_decode(w, IRONWOOD_VESTA, false, group, sum, ctx);
    for (size_t i = 0; result.ok && i < IRONWOOD_INSTANCE_ROWS; ++i)
        result = commitment_add(group, sum, basis[i], rows->row[i], point, term, n, ctx);
    uint8_t encoded[32];
    if (result.ok) result = commitment_encode(group, sum, ctx, encoded);
    if (result.ok) memcpy(out, encoded, sizeof encoded);
    EC_POINT_free(term); EC_POINT_free(point); EC_POINT_free(sum); EC_GROUP_free(group);
    BN_free(n); BN_CTX_free(ctx);
    return result;
}
