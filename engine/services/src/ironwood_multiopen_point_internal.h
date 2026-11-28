/* purpose: Encode a public Vesta point for multiopening calculations. */
/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#ifndef ZCL_IRONWOOD_MULTIOPEN_POINT_INTERNAL_H
#define ZCL_IRONWOOD_MULTIOPEN_POINT_INTERNAL_H
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
static inline bool ironwood_multiopen_encode(const EC_GROUP *g, const EC_POINT *point,
                                              BN_CTX *ctx, uint8_t out[32])
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
#endif
