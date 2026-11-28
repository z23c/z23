/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
/* purpose: Project public Ironwood action statements to Halo2 field rows. */
#include "services/ironwood_instance.h"
#include "primitives/transaction_v6_wire.h"
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <string.h>

static const uint8_t fp[32] = {
    1,0,0,0,0xed,0x30,0x2d,0x99,0x1b,0xf9,0x4c,0x09,0xfc,0x98,0x46,0x22,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0x40
};

static bool canonical_field(const uint8_t *v)
{
    for (int i = 31; i >= 0; --i)
        if (v[i] != fp[i]) return v[i] < fp[i];
    return false;
}

static bool pallas_affine(const EC_GROUP *g, EC_POINT *point, BIGNUM *x,
                          BIGNUM *y, unsigned sign, BN_CTX *ctx,
                          uint8_t xout[32], uint8_t yout[32])
{
    return EC_POINT_set_compressed_coordinates(g, point, x, (int)sign, ctx) == 1 &&
        EC_POINT_is_at_infinity(g, point) == 0 && EC_POINT_is_on_curve(g, point, ctx) == 1 &&
        EC_POINT_get_affine_coordinates(g, point, x, y, ctx) == 1 &&
        BN_bn2lebinpad(x, xout, 32) == 32 && BN_bn2lebinpad(y, yout, 32) == 32;
}

static bool pallas_decode(const uint8_t xbytes[32], unsigned sign,
                          uint8_t xout[32], uint8_t yout[32])
{
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *p = BN_lebin2bn(fp, 32, NULL), *x = BN_lebin2bn(xbytes, 32, NULL);
    BIGNUM *zero = BN_new(), *five = BN_new(), *y = BN_new();
    EC_GROUP *g = NULL; EC_POINT *point = NULL;
    bool ok = ctx && p && x && zero && five && y && BN_set_word(five, 5);
    if (ok) { g = EC_GROUP_new_curve_GFp(p, zero, five, ctx); ok = g != NULL; }
    if (ok) { point = EC_POINT_new(g); ok = point != NULL; }
    if (ok) ok = pallas_affine(g, point, x, y, sign, ctx, xout, yout);
    EC_POINT_free(point); EC_GROUP_free(g); BN_free(y); BN_free(five);
    BN_free(zero); BN_free(x); BN_free(p); BN_CTX_free(ctx);
    return ok;
}

/* Pallas affine coordinates live in Fp (the Vesta scalar field). */
static bool pallas_coordinates(const uint8_t in[32], bool allow_identity,
                               uint8_t xout[32], uint8_t yout[32])
{
    uint8_t xbytes[32];
    memcpy(xbytes, in, 32);
    unsigned sign = xbytes[31] >> 7;
    xbytes[31] &= 0x7f;
    if (!canonical_field(xbytes)) return false;
    uint8_t any = 0;
    for (size_t i = 0; i < 32; ++i) any |= xbytes[i];
    if (!any && !sign) {
        if (!allow_identity) return false;
        memset(xout, 0, 32); memset(yout, 0, 32);
        return true;
    }
    return pallas_decode(xbytes, sign, xout, yout);
}

bool ironwood_instance_from_statement(const uint8_t *s, size_t size,
                                      struct ironwood_instance_rows *out)
{
    struct ironwood_instance_rows rows = {0};
    if (!s || size != V6_IRONWOOD_STATEMENT_SIZE || !out) return false;
    if (s[160] > 1 || s[161] > 1 || s[162] > 1) return false;
    if (!canonical_field(s) || !canonical_field(s + 64) || !canonical_field(s + 128)) return false;
    if (!pallas_coordinates(s + 32, true, rows.row[1], rows.row[2]) ||
        !pallas_coordinates(s + 96, false, rows.row[4], rows.row[5])) return false;
    memcpy(rows.row[0], s, 32); memcpy(rows.row[3], s + 64, 32);
    memcpy(rows.row[6], s + 128, 32);
    for (size_t i = 0; i < 3; ++i) rows.row[7+i][0] = s[160+i];
    *out = rows;
    return true;
}

bool ironwood_instance_project(const struct v6_wire_view *view, uint64_t action,
                               struct ironwood_instance_rows *out)
{
    uint8_t s[V6_IRONWOOD_STATEMENT_SIZE];
    return out && v6_core_ironwood_statement(view, action, s, sizeof s) &&
        ironwood_instance_from_statement(s, sizeof s, out);
}
