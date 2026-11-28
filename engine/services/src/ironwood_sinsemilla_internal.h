/* purpose: Share public Sinsemilla hash-to-point mechanics. */
/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#ifndef ZCL_IRONWOOD_SINSEMILLA_INTERNAL_H
#define ZCL_IRONWOOD_SINSEMILLA_INTERNAL_H
#include <openssl/ec.h>
#include <stddef.h>
#include <stdint.h>
enum addition_status { ADD_ERROR, ADD_BOTTOM, ADD_OK };
/* parameters is the validated resident Q || S table; q chooses the domain. */
enum addition_status ironwood_sinsemilla_hash_points(const EC_GROUP *group, BN_CTX *ctx,
    EC_POINT *out, const uint8_t *parameters, const uint8_t q[32],
    const uint16_t *pieces, size_t count);
#endif
