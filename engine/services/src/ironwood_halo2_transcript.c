/* purpose: Frame Halo2 transcript input and derive challenge bytes. */
/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#include "services/ironwood_halo2_transcript.h"
#include <string.h>

struct zcl_result ironwood_halo2_transcript_init(struct ironwood_halo2_transcript *t)
{
    static const uint8_t personal[16] = {'H','a','l','o','2','-','T','r','a','n','s','c','r','i','p','t'};
    if (!t) return ZCL_ERR(-1, "Missing transcript");
    struct ironwood_halo2_transcript next = {0};
    if (blake2b_init_salt_personal(&next.hash, 64, NULL, 0, NULL, personal))
        return ZCL_ERR(-1, "Cannot initialize transcript");
    next.initialized = true;
    *t = next;
    return ZCL_OK;
}

static struct zcl_result absorb(struct ironwood_halo2_transcript *t,
                                const uint8_t *bytes, size_t size,
                                size_t expected, uint8_t prefix)
{
    if (!t || !t->initialized || !bytes || size != expected)
        return ZCL_ERR(-1, "Invalid transcript input");
    struct blake2b_ctx next = t->hash;
    if (blake2b_update(&next, &prefix, 1) || blake2b_update(&next, bytes, size))
        return ZCL_ERR(-1, "Cannot absorb transcript input");
    t->hash = next;
    return ZCL_OK;
}

struct zcl_result ironwood_halo2_transcript_point(struct ironwood_halo2_transcript *t,
                                                   const uint8_t *point, size_t size)
{
    return absorb(t, point, size, 64, 1);
}

struct zcl_result ironwood_halo2_transcript_scalar(struct ironwood_halo2_transcript *t,
                                                    const uint8_t *scalar, size_t size)
{
    return absorb(t, scalar, size, 32, 2);
}

struct zcl_result ironwood_halo2_transcript_challenge(struct ironwood_halo2_transcript *t,
                                                       uint8_t *out, size_t size)
{
    if (!t || !t->initialized || !out || size != 64)
        return ZCL_ERR(-1, "Invalid challenge output");
    struct blake2b_ctx next = t->hash;
    uint8_t prefix = 0, challenge[64];
    if (blake2b_update(&next, &prefix, 1))
        return ZCL_ERR(-1, "Cannot advance transcript");
    struct blake2b_ctx final = next;
    if (blake2b_final(&final, challenge, sizeof challenge))
        return ZCL_ERR(-1, "Cannot derive challenge");
    t->hash = next;
    memcpy(out, challenge, sizeof challenge);
    return ZCL_OK;
}
