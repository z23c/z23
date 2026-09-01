/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Curve25519 scalar multiplication — pure C23 implementation.
 * Montgomery ladder on y^2 = x^3 + 486662*x^2 + x over GF(2^255-19).
 * Based on the TweetNaCl pattern: 16 limbs of ~16 bits each.
 *
 * ── Constant-time properties ───────────────────────────────────
 *
 * The Montgomery ladder below is constant-time **by construction**, and
 * the rest of this file preserves that property. Two callers feed
 * secret material in: Sprout note encryption (esk, sk_enc) and Sapling
 * note encryption — so a timing leak here would directly compromise
 * wallet keys.
 *
 * Properties confirmed:
 *   - sel25519: branchless mask `~(b - 1)` cswap; caller must pass b∈{0,1}
 *   - scalar bit extraction: `(z[i>>3] >> (i&7)) & 1`, no branching
 *   - Montgomery ladder body: every iteration runs the full A/Z/M/S
 *     sequence and two cswaps; no `if (bit) ...` conditional adds
 *   - inv25519: branches on the loop index for the FIXED inversion
 *     exponent (p−2), which is public — not on data
 *   - pack25519: deterministic 2-pass final reduction; the inner
 *     sel25519 swaps based on the borrow bit of the final output, but
 *     the output is the public DH result, not the secret scalar
 *   - No precomputed table lookups (Montgomery doesn't need them)
 *
 * **Do not** "optimise" by adding windowed precomputation, signed-digit
 * recoding, or `if (bit) point_add` shortcuts — those reintroduce
 * cache-timing and branch-timing leaks on the secret scalar. If you
 * want speed, swap the whole file for ref10/donna/fiat-crypto and run
 * the regression in test_sapling.c (Hamming-weight timing test). */

#include "crypto/curve25519.h"
#include "support/cleanse.h"
#include <string.h>
#include <stdint.h>

typedef int64_t gf[16];

static const gf gf0 = {0};
static const gf gf1 = {1};
static const gf _121665 = {0xDB41, 1};

static void car25519(gf o)
{
    for (int i = 0; i < 16; i++) {
        o[i] += (1LL << 16);
        int64_t c = o[i] >> 16;
        o[(i + 1) * (i < 15)] += c - 1 + 37 * (c - 1) * (i == 15);
        /* c may be negative while carrying a reduced limb.  Left-shifting a
         * negative signed value is undefined in C; multiplication by the
         * same power of two preserves the TweetNaCl arithmetic exactly. */
        o[i] -= c * (1LL << 16);
    }
}

static void sel25519(gf p, gf q, int b)
{
    int64_t c = ~(b - 1);
    for (int i = 0; i < 16; i++) {
        int64_t t = c & (p[i] ^ q[i]);
        p[i] ^= t;
        q[i] ^= t;
    }
}

static void pack25519(uint8_t o[32], const gf n)
{
    gf m, t;
    memcpy(t, n, sizeof(gf));
    car25519(t);
    car25519(t);
    car25519(t);
    for (int j = 0; j < 2; j++) {
        m[0] = t[0] - 0xFFED;
        for (int i = 1; i < 15; i++) {
            m[i] = t[i] - 0xFFFF - ((m[i - 1] >> 16) & 1);
            m[i - 1] &= 0xFFFF;
        }
        m[15] = t[15] - 0x7FFF - ((m[14] >> 16) & 1);
        int64_t b = (m[15] >> 16) & 1;
        m[14] &= 0xFFFF;
        sel25519(t, m, (int)(1 - b));
    }
    for (int i = 0; i < 16; i++) {
        o[2 * i] = (uint8_t)(t[i] & 0xFF);
        o[2 * i + 1] = (uint8_t)(t[i] >> 8);
    }
}

static void unpack25519(gf o, const uint8_t n[32])
{
    for (int i = 0; i < 16; i++)
        o[i] = n[2 * i] + ((int64_t)n[2 * i + 1] << 8);
    o[15] &= 0x7FFF;
}

static void A(gf o, const gf a, const gf b)
{
    for (int i = 0; i < 16; i++) o[i] = a[i] + b[i];
}

static void Z(gf o, const gf a, const gf b)
{
    for (int i = 0; i < 16; i++) o[i] = a[i] - b[i];
}

static void M(gf o, const gf a, const gf b)
{
    int64_t t[31] = {0};
    for (int i = 0; i < 16; i++)
        for (int j = 0; j < 16; j++)
            t[i + j] += a[i] * b[j];
    for (int i = 16; i < 31; i++)
        t[i - 16] += 38 * t[i];
    memcpy(o, t, 16 * sizeof(int64_t));
    car25519(o);
    car25519(o);
}

static void S(gf o, const gf a) { M(o, a, a); }

static void inv25519(gf o, const gf a)
{
    gf c;
    memcpy(c, a, sizeof(gf));
    for (int i = 253; i >= 0; i--) {
        S(c, c);
        if (i != 2 && i != 4) M(c, c, a);
    }
    memcpy(o, c, sizeof(gf));
}

bool curve25519_scalarmult(uint8_t result[32], const uint8_t scalar[32],
                            const uint8_t point[32])
{
    uint8_t z[32];
    memcpy(z, scalar, 32);
    z[31] &= 127;
    z[31] |= 64;
    z[0] &= 248;

    gf x, a, b, c, d, e, f;
    unpack25519(x, point);
    memcpy(a, gf1, sizeof(gf));
    memcpy(b, x, sizeof(gf));
    memcpy(c, gf0, sizeof(gf));
    memcpy(d, gf1, sizeof(gf));

    for (int i = 254; i >= 0; i--) {
        int r = (z[i >> 3] >> (i & 7)) & 1;
        sel25519(a, b, r);
        sel25519(c, d, r);
        A(e, a, c);
        Z(a, a, c);
        A(c, b, d);
        Z(b, b, d);
        S(d, e);
        S(f, a);
        M(a, c, a);
        M(c, b, e);
        A(e, a, c);
        Z(a, a, c);
        S(b, a);
        Z(c, d, f);
        M(a, c, _121665);
        A(a, a, d);
        M(c, c, a);
        M(a, d, f);
        M(d, b, x);
        S(b, e);
        sel25519(a, b, r);
        sel25519(c, d, r);
    }
    inv25519(c, c);
    M(a, a, c);
    pack25519(result, a);
    /* Wipe scalar-derived working state. The shared secret / public key is
     * already written to `result`. `z` is the clamped secret scalar; a..f are
     * Montgomery-ladder intermediates carrying scalar-derived secret values;
     * all are dead after pack25519 above. */
    memory_cleanse(z, sizeof(z));
    memory_cleanse(a, sizeof(gf));
    memory_cleanse(b, sizeof(gf));
    memory_cleanse(c, sizeof(gf));
    memory_cleanse(d, sizeof(gf));
    memory_cleanse(e, sizeof(gf));
    memory_cleanse(f, sizeof(gf));
    memory_cleanse(x, sizeof(gf));
    return true;
}

bool curve25519_scalarmult_base(uint8_t result[32], const uint8_t scalar[32])
{
    uint8_t basepoint[32] = {9};
    return curve25519_scalarmult(result, scalar, basepoint);
}
