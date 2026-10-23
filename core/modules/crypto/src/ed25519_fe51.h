/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * GF(2^255-19) in radix 2^51: five unsigned 64-bit limbs, products through
 * unsigned __int128. Included only by ed25519.c.
 *
 * Replaces the TweetNaCl 16 x 16-bit-limb field. The arithmetic is exact
 * modular arithmetic either way; every value that leaves this file through
 * pack25519 is the unique canonical residue in [0, p), so encodings, parities
 * and equality tests are byte-identical to the old field.
 *
 * Limb bounds (the contract the point code relies on):
 *   - unpack25519, M, S output limbs < 2^51 + 2^13 ("weakly reduced").
 *   - A adds two limbs: < 2^53 when both operands are weakly reduced sums.
 *   - Z computes a + 4p - b limbwise, so it never underflows as long as every
 *     limb of b is < 2^53 - 76; it outputs limbs < 2^54.
 *   - M and S accept input limbs up to 2^54 (128-bit accumulators have 2^13
 *     of headroom over the worst-case 5 * 19 * 2^108 column sum).
 * Every function here is straight-line (no secret-dependent branch or index),
 * which the constant-time signing ladder relies on.
 */
#ifndef ED25519_FE51_H
#define ED25519_FE51_H

#include "base/serialize_le.h"
#include <stdint.h>
#include <string.h>

typedef uint64_t gf[5];
__extension__ typedef unsigned __int128 fe_u128;

#define FE_MASK51 ((UINT64_C(1) << 51) - 1)

static const gf gf0 = {0, 0, 0, 0, 0};
static const gf gf1 = {1, 0, 0, 0, 0};

/* d = -121665/121666, 2d, and sqrt(-1), the same values as the old 16-bit
 * tables re-split into 51-bit limbs. */
static const gf D = {929955233495203ULL, 466365720129213ULL,
                     1662059464998953ULL, 2033849074728123ULL,
                     1442794654840575ULL};
static const gf D2 = {1859910466990425ULL, 932731440258426ULL,
                      1072319116312658ULL, 1815898335770999ULL,
                      633789495995903ULL};
static const gf I = {1718705420411056ULL, 234908883556509ULL,
                     2233514472574048ULL, 2117202627021982ULL,
                     765476049583133ULL};

/* One carry pass; leaves limbs 1..4 < 2^51 and limb 0 < 2^51 + 19 * 2^13. */
static inline void fe_carry(gf o)
{
    uint64_t c = o[0] >> 51;
    o[0] &= FE_MASK51;
    o[1] += c;
    c = o[1] >> 51;
    o[1] &= FE_MASK51;
    o[2] += c;
    c = o[2] >> 51;
    o[2] &= FE_MASK51;
    o[3] += c;
    c = o[3] >> 51;
    o[3] &= FE_MASK51;
    o[4] += c;
    c = o[4] >> 51;
    o[4] &= FE_MASK51;
    o[0] += 19 * c;
}

static inline void sel25519(gf p, gf q, int b)
{
    uint64_t c = ~((uint64_t)(int64_t)b - 1);
    for (int i = 0; i < 5; i++) {
        uint64_t t = c & (p[i] ^ q[i]);
        p[i] ^= t;
        q[i] ^= t;
    }
}

/* Canonical little-endian encoding of n mod p (full reduction). */
static inline void pack25519(uint8_t o[32], const gf n)
{
    gf t;
    memcpy(t, n, sizeof(gf));
    fe_carry(t);
    fe_carry(t);
    /* t < 2^255 + small < 2p. q = 1 iff t >= p, found by carrying t + 19. */
    uint64_t q = (t[0] + 19) >> 51;
    q = (t[1] + q) >> 51;
    q = (t[2] + q) >> 51;
    q = (t[3] + q) >> 51;
    q = (t[4] + q) >> 51;
    t[0] += 19 * q;
    uint64_t c = t[0] >> 51;
    t[0] &= FE_MASK51;
    t[1] += c;
    c = t[1] >> 51;
    t[1] &= FE_MASK51;
    t[2] += c;
    c = t[2] >> 51;
    t[2] &= FE_MASK51;
    t[3] += c;
    c = t[3] >> 51;
    t[3] &= FE_MASK51;
    t[4] += c;
    t[4] &= FE_MASK51; /* drops the 2^255 that q = 1 produced */

    uint64_t w0 = t[0] | (t[1] << 51);
    uint64_t w1 = (t[1] >> 13) | (t[2] << 38);
    uint64_t w2 = (t[2] >> 26) | (t[3] << 25);
    uint64_t w3 = (t[3] >> 39) | (t[4] << 12);
    zcl_write_u64_le(o, w0);
    zcl_write_u64_le(o + 8, w1);
    zcl_write_u64_le(o + 16, w2);
    zcl_write_u64_le(o + 24, w3);
}


/* Reads 255 bits: the top bit of n[31] (bit 255) is masked off, exactly as
 * the old unpack did; the value may be >= p and is used unreduced. */
static inline void unpack25519(gf o, const uint8_t n[32])
{
    o[0] = zcl_read_u64_le(n) & FE_MASK51;
    o[1] = (zcl_read_u64_le(n + 6) >> 3) & FE_MASK51;
    o[2] = (zcl_read_u64_le(n + 12) >> 6) & FE_MASK51;
    o[3] = (zcl_read_u64_le(n + 19) >> 1) & FE_MASK51;
    o[4] = (zcl_read_u64_le(n + 24) >> 12) & FE_MASK51;
}

static inline void A(gf o, const gf a, const gf b)
{
    for (int i = 0; i < 5; i++) o[i] = a[i] + b[i];
}

static inline void Z(gf o, const gf a, const gf b)
{
    o[0] = a[0] + UINT64_C(0x1FFFFFFFFFFFB4) - b[0];
    for (int i = 1; i < 5; i++)
        o[i] = a[i] + UINT64_C(0x1FFFFFFFFFFFFC) - b[i];
}

/* Shared reduction of five 128-bit column sums into weakly reduced limbs. */
static inline void fe_finish(gf o, fe_u128 r0, fe_u128 r1, fe_u128 r2,
                             fe_u128 r3, fe_u128 r4)
{
    uint64_t c;
    uint64_t o0 = (uint64_t)r0 & FE_MASK51;
    c = (uint64_t)(r0 >> 51);
    r1 += c;
    uint64_t o1 = (uint64_t)r1 & FE_MASK51;
    c = (uint64_t)(r1 >> 51);
    r2 += c;
    uint64_t o2 = (uint64_t)r2 & FE_MASK51;
    c = (uint64_t)(r2 >> 51);
    r3 += c;
    uint64_t o3 = (uint64_t)r3 & FE_MASK51;
    c = (uint64_t)(r3 >> 51);
    r4 += c;
    uint64_t o4 = (uint64_t)r4 & FE_MASK51;
    c = (uint64_t)(r4 >> 51);
    o0 += c * 19;
    c = o0 >> 51;
    o0 &= FE_MASK51;
    o1 += c;
    o[0] = o0;
    o[1] = o1;
    o[2] = o2;
    o[3] = o3;
    o[4] = o4;
}

static inline void M(gf o, const gf a, const gf b)
{
    uint64_t a0 = a[0], a1 = a[1], a2 = a[2], a3 = a[3], a4 = a[4];
    uint64_t b0 = b[0], b1 = b[1], b2 = b[2], b3 = b[3], b4 = b[4];
    uint64_t b1_19 = 19 * b1, b2_19 = 19 * b2, b3_19 = 19 * b3,
             b4_19 = 19 * b4;
    fe_u128 r0 = (fe_u128)a0 * b0 + (fe_u128)a1 * b4_19 +
                 (fe_u128)a2 * b3_19 + (fe_u128)a3 * b2_19 +
                 (fe_u128)a4 * b1_19;
    fe_u128 r1 = (fe_u128)a0 * b1 + (fe_u128)a1 * b0 +
                 (fe_u128)a2 * b4_19 + (fe_u128)a3 * b3_19 +
                 (fe_u128)a4 * b2_19;
    fe_u128 r2 = (fe_u128)a0 * b2 + (fe_u128)a1 * b1 + (fe_u128)a2 * b0 +
                 (fe_u128)a3 * b4_19 + (fe_u128)a4 * b3_19;
    fe_u128 r3 = (fe_u128)a0 * b3 + (fe_u128)a1 * b2 + (fe_u128)a2 * b1 +
                 (fe_u128)a3 * b0 + (fe_u128)a4 * b4_19;
    fe_u128 r4 = (fe_u128)a0 * b4 + (fe_u128)a1 * b3 + (fe_u128)a2 * b2 +
                 (fe_u128)a3 * b1 + (fe_u128)a4 * b0;
    fe_finish(o, r0, r1, r2, r3, r4);
}

static inline void S(gf o, const gf a)
{
    uint64_t a0 = a[0], a1 = a[1], a2 = a[2], a3 = a[3], a4 = a[4];
    uint64_t d0 = 2 * a0, d1 = 2 * a1, d2 = 2 * a2, d3_19 = 19 * 2 * a3;
    uint64_t a3_19 = 19 * a3, a4_19 = 19 * a4;
    fe_u128 r0 = (fe_u128)a0 * a0 + (fe_u128)d1 * a4_19 +
                 (fe_u128)d2 * a3_19;
    fe_u128 r1 = (fe_u128)d0 * a1 + (fe_u128)d2 * a4_19 +
                 (fe_u128)a3 * a3_19;
    fe_u128 r2 = (fe_u128)d0 * a2 + (fe_u128)a1 * a1 +
                 (fe_u128)d3_19 * a4;
    fe_u128 r3 = (fe_u128)d0 * a3 + (fe_u128)d1 * a2 +
                 (fe_u128)a4 * a4_19;
    fe_u128 r4 = (fe_u128)d0 * a4 + (fe_u128)d1 * a3 + (fe_u128)a2 * a2;
    fe_finish(o, r0, r1, r2, r3, r4);
}

static inline void fe_sqn(gf o, const gf a, int n)
{
    S(o, a);
    for (int i = 1; i < n; i++) S(o, o);
}

/* z^(2^250 - 1) into t250, plus z^11 into z11 (shared tail of both chains). */
static inline void fe_pow_250(gf t250, gf z11, const gf z)
{
    gf z2, z9, t, a, b;
    S(z2, z);
    fe_sqn(t, z2, 2);
    M(z9, z, t);
    M(z11, z2, z9);
    S(t, z11);
    M(a, z9, t);          /* 2^5 - 1 */
    fe_sqn(t, a, 5);
    M(b, t, a);           /* 2^10 - 1 */
    fe_sqn(t, b, 10);
    M(a, t, b);           /* 2^20 - 1 */
    fe_sqn(t, a, 20);
    M(a, t, a);           /* 2^40 - 1 */
    fe_sqn(t, a, 10);
    M(a, t, b);           /* 2^50 - 1 */
    fe_sqn(t, a, 50);
    M(b, t, a);           /* 2^100 - 1 */
    fe_sqn(t, b, 100);
    M(b, t, b);           /* 2^200 - 1 */
    fe_sqn(t, b, 50);
    M(t250, t, a);        /* 2^250 - 1 */
}

/* a^(p-2) = a^(2^255 - 21); 0 maps to 0. */
static inline void inv25519(gf o, const gf a)
{
    gf t250, z11, t;
    fe_pow_250(t250, z11, a);
    fe_sqn(t, t250, 5);
    M(o, t, z11);
}

/* a^((p-5)/8) = a^(2^252 - 3). */
static inline void pow2523(gf o, const gf a)
{
    gf t250, z11, t;
    fe_pow_250(t250, z11, a);
    fe_sqn(t, t250, 2);
    M(o, t, a);
}

static inline int par25519(const gf a)
{
    uint8_t d[32];
    pack25519(d, a);
    return d[0] & 1;
}

static inline int neq25519(const gf a, const gf b)
{
    uint8_t c[32], d[32];
    pack25519(c, a);
    pack25519(d, b);
    int v = 0;
    for (int i = 0; i < 32; i++) v |= c[i] ^ d[i];
    return v != 0;
}

#endif /* ED25519_FE51_H */
