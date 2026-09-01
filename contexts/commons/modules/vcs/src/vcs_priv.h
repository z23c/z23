/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * vcs_priv — private helpers shared across the contexts/commons/modules/vcs/ implementation
 * translation units. NOT a public header: nothing outside contexts/commons/modules/vcs/src/
 * includes this. Little-endian integer codecs, fixed-width hex, and the
 * domain-tagged SHA3-256 helpers the content-addressed store is built on.
 *
 * The tag byte is a domain separator: every hash the VCS computes is
 * SHA3-256 over (tag || bytes...), so a blob and a manifest that happen to
 * share the same raw bytes hash to different ids and never collide. See
 * vcs_object.h for the tag enumeration. */

#ifndef ZCL_VCS_PRIV_H
#define ZCL_VCS_PRIV_H

#include "base/hex.h"
#include "sha3/sha3.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>

/* ── little-endian fixed-width codecs ─────────────────────────────── */

static inline void vcs_wr_u16le(uint8_t *p, uint16_t v)
{
    p[0] = (uint8_t)(v & 0xffu);
    p[1] = (uint8_t)((v >> 8) & 0xffu);
}

static inline void vcs_wr_u32le(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v & 0xffu);
    p[1] = (uint8_t)((v >> 8) & 0xffu);
    p[2] = (uint8_t)((v >> 16) & 0xffu);
    p[3] = (uint8_t)((v >> 24) & 0xffu);
}

static inline void vcs_wr_u64le(uint8_t *p, uint64_t v)
{
    for (int i = 0; i < 8; i++)
        p[i] = (uint8_t)((v >> (8 * i)) & 0xffu);
}

static inline uint16_t vcs_rd_u16le(const uint8_t *p)
{
    return (uint16_t)((uint16_t)p[0] | ((uint16_t)p[1] << 8));
}

static inline uint32_t vcs_rd_u32le(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static inline uint64_t vcs_rd_u64le(const uint8_t *p)
{
    uint64_t v = 0;
    for (int i = 0; i < 8; i++)
        v |= (uint64_t)p[i] << (8 * i);
    return v;
}

/* ── domain-tagged SHA3-256 helpers ───────────────────────────────── */

/* SHA3-256 over (tag || data[0..len)). */
static inline void vcs_sha3_tag(uint8_t tag, const void *data, size_t len,
                                uint8_t out[32])
{
    struct sha3_256_ctx ctx;
    sha3_256_init(&ctx);
    sha3_256_write(&ctx, &tag, 1);
    if (len > 0)
        sha3_256_write(&ctx, (const unsigned char *)data, len);
    sha3_256_finalize(&ctx, out);
}

#endif /* ZCL_VCS_PRIV_H */
