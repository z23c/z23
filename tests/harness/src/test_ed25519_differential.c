/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Ed25519 DIFFERENTIAL test — pins `ed25519_verify` in
 * core/modules/crypto/src/ed25519.c against a frozen, byte-for-byte copy of the
 * bit-at-a-time TweetNaCl-shaped implementation it grew out of.
 *
 * WHY THIS EXISTS
 * ---------------
 * ed25519_verify sits on the JoinSplit signature path. A block that
 * zclassicd accepts and we reject (or vice versa) is a chain split. Any
 * change to that function is therefore only ever allowed to be a speed
 * change, and the ONLY acceptable evidence is that the accept/reject
 * predicate did not move by a single input. This file is that evidence,
 * and it is written to stay useful for the NEXT optimisation too, not
 * just the one that motivated it.
 *
 * The reference below (`ref_*`) is the pre-optimisation arithmetic —
 * an independent 16x16-limb field with an unconditional 256-step
 * cswap ladder per scalar. It is deliberately NOT shared code: if
 * someone "improves" the shipped implementation again, this oracle must
 * stay frozen or the test proves nothing. It also carries the signing
 * half TweetNaCl has, which is what lets this test feed the verifier
 * VALID signatures over random 253-bit scalars — the only way to
 * exercise the point arithmetic on the ACCEPT path. A differential over
 * random garbage alone would not: both implementations reject garbage,
 * so agreement there is uninformative about the group law.
 *
 * COVERAGE
 *   1. RFC 8032 vectors (shipped verifier must accept).
 *   2. 256 random keypair/message signatures, each verified by BOTH
 *      implementations — accept must agree.
 *   3. Every one of those signatures corrupted in R, in S, in the
 *      message and in the public key — reject must agree.
 *   4. 4096 random (sig, pk, msg) triples — reject must agree.
 *   5. Structured edge cases: identity pk, S = L, S = L-1, S = L+1,
 *      non-canonical y encodings (y = p, p+1, 2^255-1), the sign bit
 *      set on an x = 0 point, and all eight low-order points. */

#include "test/test_core.h"
#include "crypto/ed25519.h"
#include "crypto/sha512.h"
#include <string.h>
#include <stdio.h>
#include <stdint.h>

/* ══════════════════════════════════════════════════════════════════
 *  REFERENCE — frozen copy of the pre-optimisation implementation.
 *  Do not "modernise" this. It is the oracle.
 * ══════════════════════════════════════════════════════════════════ */

typedef int64_t ref_gf[16];

static const ref_gf ref_gf0 = {0};
static const ref_gf ref_gf1 = {1};

static const ref_gf ref_D = {
    0x78a3, 0x1359, 0x4dca, 0x75eb, 0xd8ab, 0x4141, 0x0a4d, 0x0070,
    0xe898, 0x7779, 0x4079, 0x8cc7, 0xfe73, 0x2b6f, 0x6cee, 0x5203
};
static const ref_gf ref_D2 = {
    0xf159, 0x26b2, 0x9b94, 0xebd6, 0xb156, 0x8283, 0x149a, 0x00e0,
    0xd130, 0xeef3, 0x80f2, 0x198e, 0xfce7, 0x56df, 0xd9dc, 0x2406
};
static const ref_gf ref_I = {
    0xa0b0, 0x4a0e, 0x1b27, 0xc4ee, 0xe478, 0xad2f, 0x1806, 0x2f43,
    0xd7a7, 0x3dfb, 0x0099, 0x2b4d, 0xdf0b, 0x4fc1, 0x2480, 0x2b83
};

static const uint8_t REF_BASE_POINT[32] = {
    0x58, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
    0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
    0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
    0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66
};

static void ref_car25519(ref_gf o)
{
    for (int i = 0; i < 16; i++) {
        o[i] += (1LL << 16);
        int64_t c = o[i] >> 16;
        o[(i + 1) * (i < 15)] += c - 1 + 37 * (c - 1) * (i == 15);
        o[i] -= c << 16;
    }
}

static void ref_sel25519(ref_gf p, ref_gf q, int b)
{
    int64_t c = ~(b - 1);
    for (int i = 0; i < 16; i++) {
        int64_t t = c & (p[i] ^ q[i]);
        p[i] ^= t;
        q[i] ^= t;
    }
}

static void ref_pack25519(uint8_t o[32], const ref_gf n)
{
    ref_gf m, t;
    memcpy(t, n, sizeof(ref_gf));
    ref_car25519(t);
    ref_car25519(t);
    ref_car25519(t);
    for (int j = 0; j < 2; j++) {
        m[0] = t[0] - 0xffed;
        for (int i = 1; i < 15; i++) {
            m[i] = t[i] - 0xffff - ((m[i - 1] >> 16) & 1);
            m[i - 1] &= 0xffff;
        }
        m[15] = t[15] - 0x7fff - ((m[14] >> 16) & 1);
        int64_t b = (m[15] >> 16) & 1;
        m[14] &= 0xffff;
        ref_sel25519(t, m, (int)(1 - b));
    }
    for (int i = 0; i < 16; i++) {
        o[2 * i] = (uint8_t)(t[i] & 0xff);
        o[2 * i + 1] = (uint8_t)(t[i] >> 8);
    }
}

static void ref_unpack25519(ref_gf o, const uint8_t n[32])
{
    for (int i = 0; i < 16; i++)
        o[i] = n[2 * i] + ((int64_t)n[2 * i + 1] << 8);
    o[15] &= 0x7fff;
}

static void ref_A(ref_gf o, const ref_gf a, const ref_gf b)
{
    for (int i = 0; i < 16; i++) o[i] = a[i] + b[i];
}

static void ref_Z(ref_gf o, const ref_gf a, const ref_gf b)
{
    for (int i = 0; i < 16; i++) o[i] = a[i] - b[i];
}

static void ref_M(ref_gf o, const ref_gf a, const ref_gf b)
{
    int64_t t[31] = {0};
    for (int i = 0; i < 16; i++)
        for (int j = 0; j < 16; j++)
            t[i + j] += a[i] * b[j];
    for (int i = 0; i < 15; i++)
        t[i] += 38 * t[i + 16];
    memcpy(o, t, sizeof(ref_gf));
    ref_car25519(o);
    ref_car25519(o);
}

static void ref_S(ref_gf o, const ref_gf a) { ref_M(o, a, a); }

static void ref_inv25519(ref_gf o, const ref_gf a)
{
    ref_gf c;
    memcpy(c, a, sizeof(ref_gf));
    for (int i = 253; i >= 0; i--) {
        ref_S(c, c);
        if (i != 2 && i != 4) ref_M(c, c, a);
    }
    memcpy(o, c, sizeof(ref_gf));
}

static void ref_pow2523(ref_gf o, const ref_gf a)
{
    ref_gf c;
    memcpy(c, a, sizeof(ref_gf));
    for (int i = 250; i >= 0; i--) {
        ref_S(c, c);
        if (i != 1) ref_M(c, c, a);
    }
    memcpy(o, c, sizeof(ref_gf));
}

static int ref_par25519(const ref_gf a)
{
    uint8_t d[32];
    ref_pack25519(d, a);
    return d[0] & 1;
}

static int ref_neq25519(const ref_gf a, const ref_gf b)
{
    uint8_t c[32], d[32];
    ref_pack25519(c, a);
    ref_pack25519(d, b);
    int v = 0;
    for (int i = 0; i < 32; i++) v |= c[i] ^ d[i];
    return v != 0;
}

typedef ref_gf ref_gep[4];

static void ref_set_identity(ref_gep p)
{
    memset(p[0], 0, sizeof(ref_gf));
    memcpy(p[1], ref_gf1, sizeof(ref_gf));
    memcpy(p[2], ref_gf1, sizeof(ref_gf));
    memset(p[3], 0, sizeof(ref_gf));
}

static void ref_point_add(ref_gep p, const ref_gep q)
{
    ref_gf a, b, c, d, e, f, g, h, t;
    ref_Z(a, p[1], p[0]);
    ref_Z(t, q[1], q[0]);
    ref_M(a, a, t);
    ref_A(b, p[0], p[1]);
    ref_A(t, q[0], q[1]);
    ref_M(b, b, t);
    ref_M(c, p[3], q[3]);
    ref_M(c, c, ref_D2);
    ref_M(d, p[2], q[2]);
    ref_A(d, d, d);
    ref_Z(e, b, a);
    ref_Z(f, d, c);
    ref_A(g, d, c);
    ref_A(h, b, a);
    ref_M(p[0], e, f);
    ref_M(p[1], h, g);
    ref_M(p[2], g, f);
    ref_M(p[3], e, h);
}

static void ref_cswap(ref_gep p, ref_gep q, int b)
{
    for (int i = 0; i < 4; i++)
        ref_sel25519(p[i], q[i], b);
}

static void ref_pack_point(uint8_t r[32], const ref_gep p)
{
    ref_gf tx, ty, zi;
    ref_inv25519(zi, p[2]);
    ref_M(tx, p[0], zi);
    ref_M(ty, p[1], zi);
    ref_pack25519(r, ty);
    r[31] ^= (uint8_t)(ref_par25519(tx) << 7);
}

static int ref_unpackneg(ref_gep r, const uint8_t p[32])
{
    ref_gf t, chk, num, den, den2, den4, den6;
    ref_set_identity(r);
    ref_unpack25519(r[1], p);
    ref_S(num, r[1]);
    ref_M(den, num, ref_D);
    ref_Z(num, num, r[2]);
    ref_A(den, r[2], den);

    ref_S(den2, den);
    ref_S(den4, den2);
    ref_M(den6, den4, den2);
    ref_M(t, den6, num);
    ref_M(t, t, den);

    ref_pow2523(t, t);
    ref_M(t, t, num);
    ref_M(t, t, den);
    ref_M(t, t, den);
    ref_M(r[0], t, den);

    ref_S(chk, r[0]);
    ref_M(chk, chk, den);
    if (ref_neq25519(chk, num)) ref_M(r[0], r[0], ref_I);

    ref_S(chk, r[0]);
    ref_M(chk, chk, den);
    if (ref_neq25519(chk, num)) return -1;

    if (ref_par25519(r[0]) == (p[31] >> 7))
        ref_Z(r[0], ref_gf0, r[0]);

    ref_M(r[3], r[0], r[1]);
    return 0;
}

static void ref_scalarmult(ref_gep p, ref_gep q, const uint8_t s[32])
{
    ref_set_identity(p);
    for (int i = 255; i >= 0; i--) {
        int b = (s[i / 8] >> (i & 7)) & 1;
        ref_cswap(p, q, b);
        ref_point_add(q, p);
        ref_point_add(p, p);
        ref_cswap(p, q, b);
    }
}

static const uint64_t REF_L[32] = {
    0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58,
    0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
    0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0x10
};

static void ref_modL(uint8_t r[32], int64_t x[64])
{
    for (int i = 63; i >= 32; i--) {
        int64_t carry = 0;
        int j;
        for (j = i - 32; j < i - 12; j++) {
            x[j] += carry - 16 * x[i] * (int64_t)REF_L[j - (i - 32)];
            carry = (x[j] + 128) >> 8;
            x[j] -= carry << 8;
        }
        x[j] += carry;
        x[i] = 0;
    }
    int64_t carry = 0;
    for (int j = 0; j < 32; j++) {
        x[j] += carry - (x[31] >> 4) * (int64_t)REF_L[j];
        carry = x[j] >> 8;
        x[j] &= 255;
    }
    for (int j = 0; j < 32; j++)
        x[j] -= carry * (int64_t)REF_L[j];
    for (int i = 0; i < 32; i++) {
        x[i + 1] += x[i] >> 8;
        r[i] = (uint8_t)(x[i] & 255);
    }
}

static void ref_reduce(uint8_t r[64])
{
    int64_t x[64];
    for (int i = 0; i < 64; i++) x[i] = (int64_t)(uint64_t)r[i];
    memset(r, 0, 64);
    ref_modL(r, x);
}

static bool ref_S_is_canonical(const uint8_t S[32])
{
    uint32_t lt = 0, eq = 1;
    for (int i = 31; i >= 0; i--) {
        uint32_t sb = S[i];
        uint32_t lb = (uint32_t)REF_L[i];
        uint32_t is_lt = ((sb - lb) >> 31) & 1u;
        uint32_t is_eq = (((sb ^ lb) - 1u) >> 31) & 1u;
        lt |= eq & is_lt;
        eq &= is_eq;
    }
    return lt != 0u;
}

/* The frozen verifier. Same predicate, no logging (a test oracle must be
 * quiet: it is fed thousands of deliberately-invalid inputs). */
static bool ref_ed25519_verify(const uint8_t sig[64],
                               const uint8_t *msg, size_t msg_len,
                               const uint8_t pk[32])
{
    ref_gep q;
    uint8_t zero[32] = {0};

    if (memcmp(pk, zero, 32) == 0) return false;
    if (!ref_S_is_canonical(sig + 32)) return false;
    if (ref_unpackneg(q, pk) != 0) return false;

    uint8_t h[64];
    struct sha512_ctx hs;
    sha512_init(&hs);
    sha512_write(&hs, sig, 32);
    sha512_write(&hs, pk, 32);
    sha512_write(&hs, msg, msg_len);
    sha512_finalize(&hs, h);
    ref_reduce(h);

    ref_gep sb;
    {
        ref_gep bp;
        if (ref_unpackneg(bp, REF_BASE_POINT) != 0) return false;
        ref_Z(bp[0], ref_gf0, bp[0]);
        ref_Z(bp[3], ref_gf0, bp[3]);
        ref_scalarmult(sb, bp, sig + 32);
    }

    ref_gep ha;
    {
        ref_gep q2;
        memcpy(q2, q, sizeof(ref_gep));
        ref_scalarmult(ha, q2, h);
    }

    ref_point_add(sb, ha);

    uint8_t t[32];
    ref_pack_point(t, sb);

    int diff = 0;
    for (int i = 0; i < 32; i++) diff |= t[i] ^ sig[i];
    return diff == 0;
}

/* ── Reference SIGNER (TweetNaCl crypto_sign, verify-side tree has none)
 *
 * Needed only so this test can hand the shipped verifier valid
 * signatures over random scalars. Never linked into the node. */

static void ref_scalarbase(ref_gep p, const uint8_t s[32])
{
    ref_gep b;
    /* B = -(unpackneg(B_encoded)) — exactly how the old verifier built it. */
    if (ref_unpackneg(b, REF_BASE_POINT) != 0) {
        ref_set_identity(p);
        return;
    }
    ref_Z(b[0], ref_gf0, b[0]);
    ref_Z(b[3], ref_gf0, b[3]);
    ref_scalarmult(p, b, s);
}

/* sk = 32-byte seed. Writes the 32-byte public key. */
static void ref_keypair(uint8_t pk[32], const uint8_t seed[32])
{
    uint8_t d[64];
    struct sha512_ctx hs;
    sha512_init(&hs);
    sha512_write(&hs, seed, 32);
    sha512_finalize(&hs, d);
    d[0] &= 248; d[31] &= 127; d[31] |= 64;

    ref_gep p;
    ref_scalarbase(p, d);
    ref_pack_point(pk, p);
}

static void ref_sign(uint8_t sig[64], const uint8_t *msg, size_t mlen,
                     const uint8_t seed[32], const uint8_t pk[32])
{
    uint8_t d[64], r64[64], h64[64];
    struct sha512_ctx hs;

    sha512_init(&hs);
    sha512_write(&hs, seed, 32);
    sha512_finalize(&hs, d);
    d[0] &= 248; d[31] &= 127; d[31] |= 64;

    /* r = H(prefix || m) mod L */
    sha512_init(&hs);
    sha512_write(&hs, d + 32, 32);
    sha512_write(&hs, msg, mlen);
    sha512_finalize(&hs, r64);
    ref_reduce(r64);

    ref_gep p;
    ref_scalarbase(p, r64);
    ref_pack_point(sig, p);              /* R */

    /* h = H(R || A || m) mod L */
    sha512_init(&hs);
    sha512_write(&hs, sig, 32);
    sha512_write(&hs, pk, 32);
    sha512_write(&hs, msg, mlen);
    sha512_finalize(&hs, h64);
    ref_reduce(h64);

    /* S = r + h*a mod L */
    int64_t x[64] = {0};
    for (int i = 0; i < 32; i++) x[i] = (int64_t)(uint64_t)r64[i];
    for (int i = 0; i < 32; i++)
        for (int j = 0; j < 32; j++)
            x[i + j] += (int64_t)h64[i] * (int64_t)d[j];
    ref_modL(sig + 32, x);
}

/* ══════════════════════════════════════════════════════════════════
 *  Deterministic PRNG — the corpus must be reproducible on a failure.
 * ══════════════════════════════════════════════════════════════════ */

static uint64_t g_rng = 0x9e3779b97f4a7c15ULL;

static uint64_t rng_next(void)
{
    g_rng ^= g_rng << 13;
    g_rng ^= g_rng >> 7;
    g_rng ^= g_rng << 17;
    return g_rng;
}

static void rng_bytes(uint8_t *p, size_t n)
{
    for (size_t i = 0; i < n; i++) p[i] = (uint8_t)(rng_next() >> 24);
}

/* ══════════════════════════════════════════════════════════════════ */

static int g_failures;
static unsigned g_agreements;

static void expect_agree(const uint8_t sig[64], const uint8_t *msg,
                         size_t mlen, const uint8_t pk[32],
                         const char *what)
{
    bool got = ed25519_verify(sig, msg, mlen, pk);
    bool want = ref_ed25519_verify(sig, msg, mlen, pk);
    if (got != want) {
        printf("FAIL (%s: shipped=%d reference=%d)\n", what, got, want);
        g_failures++;
    } else {
        g_agreements++;
    }
}

static void expect_agree_and(const uint8_t sig[64], const uint8_t *msg,
                             size_t mlen, const uint8_t pk[32],
                             bool want_value, const char *what)
{
    bool got = ed25519_verify(sig, msg, mlen, pk);
    bool want = ref_ed25519_verify(sig, msg, mlen, pk);
    if (got != want) {
        printf("FAIL (%s: shipped=%d reference=%d)\n", what, got, want);
        g_failures++;
        return;
    }
    if (got != want_value) {
        printf("FAIL (%s: both implementations returned %d, expected %d)\n",
               what, got, want_value);
        g_failures++;
        return;
    }
    g_agreements++;
}

int test_ed25519_differential(void)
{
    g_failures = 0;
    g_agreements = 0;

    printf("\n=== ed25519_differential (shipped verifier vs frozen ladder oracle) ===\n");

    /* ── 1. RFC 8032 vectors ─────────────────────────────────────── */
    printf("RFC 8032 vectors accepted by both... ");
    {
        struct { const char *pk, *sig, *msg; size_t mlen; } V[] = {
            { "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
              "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
              "", 0 },
            { "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
              "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
              "72", 1 },
            { "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
              "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a",
              "af82", 2 },
        };
        int bad = 0;
        for (size_t i = 0; i < sizeof(V) / sizeof(V[0]); i++) {
            uint8_t pk[32], sig[64], msg[8] = {0};
            test_hex_to_bytes(V[i].pk, pk, 32);
            test_hex_to_bytes(V[i].sig, sig, 64);
            if (V[i].mlen) test_hex_to_bytes(V[i].msg, msg, V[i].mlen);
            if (!ed25519_verify(sig, V[i].mlen ? msg : NULL, V[i].mlen, pk)) {
                printf("\n  vector %zu REJECTED by the shipped verifier\n", i);
                bad++;
            }
            if (!ref_ed25519_verify(sig, V[i].mlen ? msg : NULL, V[i].mlen, pk)) {
                printf("\n  vector %zu REJECTED by the reference oracle "
                       "(the ORACLE is broken, not the shipped code)\n", i);
                bad++;
            }
        }
        if (bad) { printf("FAIL (%d)\n", bad); g_failures += bad; }
        else printf("OK (3 vectors)\n");
    }

    /* ── 2+3. Random signatures: accept, then four corruptions ───── */
    printf("256 random signatures: accept + 1024 corruptions reject... ");
    {
        for (int iter = 0; iter < 256; iter++) {
            uint8_t seed[32], pk[32], sig[64], msg[64];
            size_t mlen = (size_t)(rng_next() % 64u);

            rng_bytes(seed, 32);
            rng_bytes(msg, sizeof(msg));
            ref_keypair(pk, seed);
            ref_sign(sig, msg, mlen, seed, pk);

            expect_agree_and(sig, msg, mlen, pk, true, "valid signature");

            /* R corrupted */
            {
                uint8_t bad[64];
                memcpy(bad, sig, 64);
                bad[rng_next() % 32u] ^= (uint8_t)(1u << (rng_next() % 8u));
                expect_agree_and(bad, msg, mlen, pk, false, "corrupt R");
            }
            /* S corrupted (low bytes, so it usually stays < L) */
            {
                uint8_t bad[64];
                memcpy(bad, sig, 64);
                bad[32 + (rng_next() % 16u)] ^= (uint8_t)(1u << (rng_next() % 8u));
                expect_agree(bad, msg, mlen, pk, "corrupt S");
            }
            /* message corrupted */
            if (mlen) {
                uint8_t bad[64];
                memcpy(bad, msg, sizeof(bad));
                bad[rng_next() % mlen] ^= 0x40;
                expect_agree_and(sig, bad, mlen, pk, false, "corrupt msg");
            }
            /* public key corrupted */
            {
                uint8_t bad[32];
                memcpy(bad, pk, 32);
                bad[rng_next() % 32u] ^= (uint8_t)(1u << (rng_next() % 8u));
                expect_agree(sig, msg, mlen, bad, "corrupt pk");
            }
        }
        printf("%s\n", g_failures ? "FAIL" : "OK");
    }

    /* ── 4. Random garbage triples ───────────────────────────────── */
    printf("4096 random garbage triples agree... ");
    {
        int before = g_failures;
        for (int iter = 0; iter < 4096; iter++) {
            uint8_t sig[64], pk[32], msg[16];
            rng_bytes(sig, 64);
            rng_bytes(pk, 32);
            rng_bytes(msg, 16);
            /* Half the time force S into range so decompression is reached. */
            if (iter & 1) sig[63] &= 0x0f;
            expect_agree(sig, msg, sizeof(msg), pk, "random triple");
        }
        printf("%s\n", g_failures > before ? "FAIL" : "OK");
    }

    /* ── 5. Structured edge cases ────────────────────────────────── */
    printf("structured edge cases agree... ");
    {
        int before = g_failures;
        static const uint8_t L_LE[32] = {
            0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58,
            0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
        };
        uint8_t seed[32], pk[32], sig[64];
        const uint8_t msg[4] = { 'e', 'd', '2', '5' };

        rng_bytes(seed, 32);
        ref_keypair(pk, seed);
        ref_sign(sig, msg, sizeof(msg), seed, pk);

        /* identity public key */
        {
            uint8_t zpk[32] = {0};
            expect_agree_and(sig, msg, sizeof(msg), zpk, false, "identity pk");
        }
        /* S == L, S == L-1, S == L+1 */
        {
            uint8_t s2[64];
            memcpy(s2, sig, 64);
            memcpy(s2 + 32, L_LE, 32);
            expect_agree_and(s2, msg, sizeof(msg), pk, false, "S == L");

            memcpy(s2 + 32, L_LE, 32);
            s2[32] -= 1;
            expect_agree(s2, msg, sizeof(msg), pk, "S == L-1");

            memcpy(s2 + 32, L_LE, 32);
            s2[32] += 1;
            expect_agree_and(s2, msg, sizeof(msg), pk, false, "S == L+1");

            memcpy(s2 + 32, L_LE, 32);
            s2[63] = 0xff;
            expect_agree_and(s2, msg, sizeof(msg), pk, false, "S top byte 0xff");
        }
        /* ── malleability, stated ABSOLUTELY and not differentially ─────
         * (R, S) and (R, S+L) satisfy the same group equation, so a
         * verifier without the S<L canonical check accepts both — that is
         * the classic Ed25519 malleability, and RFC 8032 §5.1.7 plus the
         * Zcash consensus rules forbid the second.
         *
         * This CANNOT be a differential assertion. The frozen reference
         * carries its own copy of the canonical-S check, so both sides
         * reject S+L and agree no matter what the shipped predicate does.
         * It cannot be an S == L case either: S == L means S ≡ 0 mod L, so
         * [S]B is the identity and the point equation fails on its own —
         * both implementations still reject, for a reason that has nothing
         * to do with the predicate under test. Proven, not assumed: with
         * ed25519_S_is_canonical stubbed to `return true` — the whole
         * malleability defence removed — every differential case in this
         * file stayed GREEN, including the S == L / L±1 ones, and only the
         * absolute assertion below turned red.
         *
         * So: the honest signature must ACCEPT and its +L malleation must
         * REJECT, both stated against the shipped verifier directly. */
        {
            uint8_t mal[64];
            memcpy(mal, sig, 64);
            unsigned carry = 0;
            for (int i = 0; i < 32; i++) {
                unsigned t = (unsigned)mal[32 + i] + (unsigned)L_LE[i] + carry;
                mal[32 + i] = (uint8_t)(t & 0xFF);
                carry = t >> 8;
            }
            if (!ed25519_verify(sig, msg, sizeof(msg), pk)) {
                printf("FAIL (honest signature rejected)\n");
                g_failures++;
            } else {
                g_agreements++;
            }
            if (ed25519_verify(mal, msg, sizeof(msg), pk)) {
                printf("FAIL (S+L malleation ACCEPTED — canonical-S check "
                       "is not enforcing S < L)\n");
                g_failures++;
            } else {
                g_agreements++;
            }
        }
        /* Non-canonical y encodings: y = p, p+1, 2^255-1, and with the
         * sign bit both clear and set. */
        {
            static const uint8_t P_LE[32] = {
                0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f,
            };
            uint8_t npk[32];
            for (int variant = 0; variant < 3; variant++) {
                memcpy(npk, P_LE, 32);
                if (variant == 1) npk[0] += 1;               /* p+1 */
                if (variant == 2) { for (int i = 0; i < 32; i++) npk[i] = 0xff;
                                    npk[31] = 0x7f; }        /* 2^255-1 */
                for (int sign = 0; sign < 2; sign++) {
                    uint8_t t[32];
                    memcpy(t, npk, 32);
                    if (sign) t[31] |= 0x80;
                    expect_agree(sig, msg, sizeof(msg), t, "non-canonical y");
                }
            }
        }
        /* The eight low-order points (encodings of the order-1/2/4/8
         * torsion subgroup), each with both sign bits. */
        {
            static const char *LOW_ORDER[] = {
                "0100000000000000000000000000000000000000000000000000000000000000",
                "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
                "0000000000000000000000000000000000000000000000000000000000000080",
                "0000000000000000000000000000000000000000000000000000000000000000",
                "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
                "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
                "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
                "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
            };
            for (size_t i = 0; i < sizeof(LOW_ORDER) / sizeof(LOW_ORDER[0]); i++) {
                uint8_t lp[32];
                test_hex_to_bytes(LOW_ORDER[i], lp, 32);
                for (int sign = 0; sign < 2; sign++) {
                    uint8_t t[32];
                    memcpy(t, lp, 32);
                    if (sign) t[31] ^= 0x80;
                    expect_agree(sig, msg, sizeof(msg), t, "low-order pk");
                    /* also as the R half of the signature */
                    uint8_t s2[64];
                    memcpy(s2, sig, 64);
                    memcpy(s2, t, 32);
                    expect_agree(s2, msg, sizeof(msg), pk, "low-order R");
                }
            }
        }
        /* S == 0 and S == 1 against a real key. */
        {
            uint8_t s2[64];
            memcpy(s2, sig, 64);
            memset(s2 + 32, 0, 32);
            expect_agree(s2, msg, sizeof(msg), pk, "S == 0");
            s2[32] = 1;
            expect_agree(s2, msg, sizeof(msg), pk, "S == 1");
        }
        /* Zero-length message on a real key pair. */
        {
            uint8_t esig[64];
            ref_sign(esig, NULL, 0, seed, pk);
            expect_agree_and(esig, NULL, 0, pk, true, "empty message");
        }
        printf("%s\n", g_failures > before ? "FAIL" : "OK");
    }

    printf("ed25519_differential: %u agreeing comparisons, %d failure(s)\n",
           g_agreements, g_failures);

    /* Guard against a silently-empty run. */
    if (g_agreements < 5000) {
        printf("FAIL (only %u comparisons ran — the corpus did not build)\n",
               g_agreements);
        g_failures++;
    }

    return g_failures;
}
