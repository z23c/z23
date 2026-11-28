/* purpose: Share public Pasta point and field decoding within Ironwood services. */
/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#ifndef ZCL_IRONWOOD_PASTA_INTERNAL_H
#define ZCL_IRONWOOD_PASTA_INTERNAL_H
#include "base/result.h"
#include <openssl/ec.h>
#include <stdint.h>
enum ironwood_pasta_curve { IRONWOOD_PALLAS, IRONWOOD_VESTA };
struct zcl_result ironwood_pasta_fp_canonical(const uint8_t bytes[32]);
struct zcl_result ironwood_pasta_group(enum ironwood_pasta_curve curve, BN_CTX *ctx,
                                       EC_GROUP **out);
/* group and point must be initialized for the specified curve. */
struct zcl_result ironwood_pasta_decode(const uint8_t bytes[32], enum ironwood_pasta_curve curve,
                                        bool allow_identity, const EC_GROUP *group,
                                        EC_POINT *point, BN_CTX *ctx);
struct zcl_result ironwood_pasta_point(const uint8_t bytes[32], enum ironwood_pasta_curve curve,
                                       bool allow_identity, uint8_t affine[64]);
#endif
