/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Ed25519 DIFFERENTIAL test: pins `ed25519_verify`
 * (core/modules/crypto/src/ed25519.c) against a frozen copy of the
 * bit-at-a-time TweetNaCl-shaped implementation.
 *
 * ed25519_verify is on the JoinSplit signature path, so a block zclassicd
 * accepts and we reject (or vice versa) is a chain split; any change to it
 * must leave the accept/reject predicate identical for every input.
 *
 * The `ref_*` reference is the frozen 16x16-limb field with an
 * unconditional 256-step cswap ladder. It is deliberately not shared code and
 * must stay frozen. It carries the signing half so the test can feed the
 * verifier VALID signatures over random 253-bit scalars, which is the only
 * way to exercise the point arithmetic on the accept path.
 *
 * COVERAGE
 *   1. RFC 8032 vectors (shipped verifier must accept).
 *   2. 256 random keypair/message signatures verified by BOTH
 *      implementations: accept must agree.
 *   3. Each of those corrupted in R, S, the message and the public key:
 *      reject must agree.
 *   4. 4096 random (sig, pk, msg) triples: reject must agree.
 *   5. Edge cases: identity pk, S = L, L-1, L+1, non-canonical y encodings
 *      (y = p, p+1, 2^255-1), sign bit set on an x = 0 point, and all eight
 *   6. Published corpora: the 12 ed25519-speccheck cases and the 139
 *      Wycheproof vectors with a 64-byte signature. Each row is pinned to
 *      the ORACLE verdict, not to the published one (see the table comment). */

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

/* ── Reference SIGNER (TweetNaCl crypto_sign; the verify-side tree has none)
 * Lets this test hand the shipped verifier valid signatures over random
 * scalars. Never linked into the node. */

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
static unsigned g_published_diffs;

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

/* ══════════════════════════════════════════════════════════════════
 *  PUBLISHED CORPORA
 *    speccheck: novifinancial/ed25519-speccheck cases.json (12 cases, index
 *      0-11 as in its condition table). Published expectation: the
 *      cofactorless column ("cof-less"); the cofactored column is V for all
 *      twelve.
 *    Wycheproof: C2SP/wycheproof testvectors_v1/ed25519_test.json, tcId as
 *      given, published expectation = its "result".
 *  Every row is copied verbatim from those files. The assertion is only
 *  oracle == shipped. The published verdict is recorded in the comment and
 *  printed as a note where the oracle disagrees with it (information, not a
 *  failure).
 *  Excluded: Wycheproof tcId 30-41 (signature not 64 bytes: Truncated,
 *  SignatureWithGarbage, CompressedSignature). The verifier takes exactly 64
 *  signature bytes, so those inputs cannot be passed to it.
 * ══════════════════════════════════════════════════════════════════ */

#define ED_CORPUS_MSG_MAX 1024u

struct ed_corpus_vec {
    const char *msg_hex;
    const char *pk_hex;
    const char *sig_hex;
    int published_valid;
    const char *id;
};

static const struct ed_corpus_vec ED_CORPUS[] = {
    /* WP tcId 1 Valid: published valid, oracle valid */
    { "", "7d4d0e7f6153a69b6242b522abbee685fda4420f8834b108c3bdae369ef549fa", "d4fbdb52bfa726b44d1786a8c0d171c3e62ca83c9e5bbe63de0bb2483f8fd6cc1429ab72cafc41ab56af02ff8fcc43b99bfe4c7ae940f60f38ebaa9d311c4007", 1, "wp tcId 1 Valid" },
    /* WP tcId 2 Valid: published valid, oracle valid */
    { "78", "7d4d0e7f6153a69b6242b522abbee685fda4420f8834b108c3bdae369ef549fa", "d80737358ede548acb173ef7e0399f83392fe8125b2ce877de7975d8b726ef5b1e76632280ee38afad12125ea44b961bf92f1178c9fa819d020869975bcbe109", 1, "wp tcId 2 Valid" },
    /* WP tcId 3 Valid: published valid, oracle valid */
    { "54657374", "7d4d0e7f6153a69b6242b522abbee685fda4420f8834b108c3bdae369ef549fa", "7c38e026f29e14aabd059a0f2db8b0cd783040609a8be684db12f82a27774ab07a9155711ecfaf7f99f277bad0c6ae7e39d4eef676573336a5c51eb6f946b30d", 1, "wp tcId 3 Valid" },
    /* WP tcId 4 Valid: published valid, oracle valid */
    { "48656c6c6f", "7d4d0e7f6153a69b6242b522abbee685fda4420f8834b108c3bdae369ef549fa", "1c1ad976cbaae3b31dee07971cf92c928ce2091a85f5899f5e11ecec90fc9f8e93df18c5037ec9b29c07195ad284e63d548cd0a6fe358cc775bd6c1608d2c905", 1, "wp tcId 4 Valid" },
    /* WP tcId 5 Valid: published valid, oracle valid */
    { "313233343030", "7d4d0e7f6153a69b6242b522abbee685fda4420f8834b108c3bdae369ef549fa", "657c1492402ab5ce03e2c3a7f0384d051b9cf3570f1207fc78c1bcc98c281c2bf0cf5b3a289976458a1be6277a5055545253b45b07dcc1abd96c8b989c00f301", 1, "wp tcId 5 Valid" },
    /* WP tcId 6 Valid: published valid, oracle valid */
    { "000000000000000000000000", "7d4d0e7f6153a69b6242b522abbee685fda4420f8834b108c3bdae369ef549fa", "d46543bfb892f84ec124dcdfc847034c19363bf3fc2fa89b1267833a14856e52e60736918783f950b6f1dd8d40dc343247cd43ce054c2d68ef974f7ed0f3c60f", 1, "wp tcId 6 Valid" },
    /* WP tcId 7 Valid: published valid, oracle valid */
    { "6161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161", "7d4d0e7f6153a69b6242b522abbee685fda4420f8834b108c3bdae369ef549fa", "879350045543bc14ed2c08939b68c30d22251d83e018cacbaf0c9d7a48db577e80bdf76ce99e5926762bc13b7b3483260a5ef63d07e34b58eb9c14621ac92f00", 1, "wp tcId 7 Valid" },
    /* WP tcId 8 Valid: published valid, oracle valid */
    { "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f60", "7d4d0e7f6153a69b6242b522abbee685fda4420f8834b108c3bdae369ef549fa", "7bdc3f9919a05f1d5db4a3ada896094f6871c1f37afc75db82ec3147d84d6f237b7e5ecc26b59cfea0c7eaf1052dc427b0f724615be9c3d3e01356c65b9b5109", 1, "wp tcId 8 Valid" },
    /* WP tcId 9 Valid: published valid, oracle valid */
    { "ffffffffffffffffffffffffffffffff", "7d4d0e7f6153a69b6242b522abbee685fda4420f8834b108c3bdae369ef549fa", "5dbd7360e55aa38e855d6ad48c34bd35b7871628508906861a7c4776765ed7d1e13d910faabd689ec8618b78295c8ab8f0e19c8b4b43eb8685778499e943ae04", 1, "wp tcId 9 Valid" },
    /* WP tcId 10 InvalidSignature: published invalid, oracle invalid */
    { "3f", "7d4d0e7f6153a69b6242b522abbee685fda4420f8834b108c3bdae369ef549fa", "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000", 0, "wp tcId 10 InvalidSignature" },
    /* WP tcId 11 InvalidSignature: published invalid, oracle invalid */
    { "3f", "7d4d0e7f6153a69b6242b522abbee685fda4420f8834b108c3bdae369ef549fa", "00000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000", 0, "wp tcId 11 InvalidSignature" },
    /* WP tcId 12 InvalidSignature: published invalid, oracle invalid */
    { "3f", "7d4d0e7f6153a69b6242b522abbee685fda4420f8834b108c3bdae369ef549fa", "0000000000000000000000000000000000000000000000000000000000000000ecd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010", 0, "wp tcId 12 InvalidSignature" },
    /* WP tcId 13 InvalidSignature: published invalid, oracle invalid */
    { "3f", "7d4d0e7f6153a69b6242b522abbee685fda4420f8834b108c3bdae369ef549fa", "0000000000000000000000000000000000000000000000000000000000000000edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010", 0, "wp tcId 13 InvalidSignature" },
    /* WP tcId 14 InvalidSignature: published invalid, oracle invalid */
    { "3f", "7d4d0e7f6153a69b6242b522abbee685fda4420f8834b108c3bdae369ef549fa", "0000000000000000000000000000000000000000000000000000000000000000edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", 0, "wp tcId 14 InvalidSignature" },
    /* WP tcId 15 InvalidSignature: published invalid, oracle invalid */
    { "3f", "7d4d0e7f6153a69b6242b522abbee685fda4420f8834b108c3bdae369ef549fa", "01000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000", 0, "wp tcId 15 InvalidSignature" },
    /* WP tcId 16 InvalidSignature: published invalid, oracle invalid */
    { "3f", "7d4d0e7f6153a69b6242b522abbee685fda4420f8834b108c3bdae369ef549fa", "01000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000", 0, "wp tcId 16 InvalidSignature" },
    /* WP tcId 17 InvalidSignature: published invalid, oracle invalid */
    { "3f", "7d4d0e7f6153a69b6242b522abbee685fda4420f8834b108c3bdae369ef549fa", "0100000000000000000000000000000000000000000000000000000000000000ecd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010", 0, "wp tcId 17 InvalidSignature" },
    /* WP tcId 18 InvalidSignature: published invalid, oracle invalid */
    { "3f", "7d4d0e7f6153a69b6242b522abbee685fda4420f8834b108c3bdae369ef549fa", "0100000000000000000000000000000000000000000000000000000000000000edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010", 0, "wp tcId 18 InvalidSignature" },
    /* WP tcId 19 InvalidSignature: published invalid, oracle invalid */
    { "3f", "7d4d0e7f6153a69b6242b522abbee685fda4420f8834b108c3bdae369ef549fa", "0100000000000000000000000000000000000000000000000000000000000000edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", 0, "wp tcId 19 InvalidSignature" },
    /* WP tcId 20 InvalidSignature: published invalid, oracle invalid */
    { "3f", "7d4d0e7f6153a69b6242b522abbee685fda4420f8834b108c3bdae369ef549fa", "edd3f55c1a631258d69cf7a2def9de14000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000000", 0, "wp tcId 20 InvalidSignature" },
    /* WP tcId 21 InvalidSignature: published invalid, oracle invalid */
    { "3f", "7d4d0e7f6153a69b6242b522abbee685fda4420f8834b108c3bdae369ef549fa", "edd3f55c1a631258d69cf7a2def9de14000000000000000000000000000000100100000000000000000000000000000000000000000000000000000000000000", 0, "wp tcId 21 InvalidSignature" },
    /* WP tcId 22 InvalidSignature: published invalid, oracle invalid */
    { "3f", "7d4d0e7f6153a69b6242b522abbee685fda4420f8834b108c3bdae369ef549fa", "edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010ecd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010", 0, "wp tcId 22 InvalidSignature" },
    /* WP tcId 23 InvalidSignature: published invalid, oracle invalid */
    { "3f", "7d4d0e7f6153a69b6242b522abbee685fda4420f8834b108c3bdae369ef549fa", "edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010", 0, "wp tcId 23 InvalidSignature" },
    /* WP tcId 24 InvalidSignature: published invalid, oracle invalid */
    { "3f", "7d4d0e7f6153a69b6242b522abbee685fda4420f8834b108c3bdae369ef549fa", "edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", 0, "wp tcId 24 InvalidSignature" },
    /* WP tcId 25 InvalidSignature: published invalid, oracle invalid */
    { "3f", "7d4d0e7f6153a69b6242b522abbee685fda4420f8834b108c3bdae369ef549fa", "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f0000000000000000000000000000000000000000000000000000000000000000", 0, "wp tcId 25 InvalidSignature" },
    /* WP tcId 26 InvalidSignature: published invalid, oracle invalid */
    { "3f", "7d4d0e7f6153a69b6242b522abbee685fda4420f8834b108c3bdae369ef549fa", "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f0100000000000000000000000000000000000000000000000000000000000000", 0, "wp tcId 26 InvalidSignature" },
    /* WP tcId 27 InvalidSignature: published invalid, oracle invalid */
    { "3f", "7d4d0e7f6153a69b6242b522abbee685fda4420f8834b108c3bdae369ef549fa", "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7fecd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010", 0, "wp tcId 27 InvalidSignature" },
    /* WP tcId 28 InvalidSignature: published invalid, oracle invalid */
    { "3f", "7d4d0e7f6153a69b6242b522abbee685fda4420f8834b108c3bdae369ef549fa", "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7fedd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010", 0, "wp tcId 28 InvalidSignature" },
    /* WP tcId 29 InvalidSignature: published invalid, oracle invalid */
    { "3f", "7d4d0e7f6153a69b6242b522abbee685fda4420f8834b108c3bdae369ef549fa", "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7fedffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", 0, "wp tcId 29 InvalidSignature" },
    /* WP tcId 42 InvalidEncoding: published invalid, oracle invalid */
    { "313233343030", "7d4d0e7f6153a69b6242b522abbee685fda4420f8834b108c3bdae369ef549fa", "647c1492402ab5ce03e2c3a7f0384d051b9cf3570f1207fc78c1bcc98c281c2b1d125e5538f38afbcc1c84e489521083041d24bc6240767029da063271a1ff0c", 0, "wp tcId 42 InvalidEncoding" },
    /* WP tcId 43 InvalidEncoding: published invalid, oracle invalid */
    { "313233343030", "7d4d0e7f6153a69b6242b522abbee685fda4420f8834b108c3bdae369ef549fa", "677c1492402ab5ce03e2c3a7f0384d051b9cf3570f1207fc78c1bcc98c281c2bc108ca4b87a49c9ed2cf383aecad8f54a962b2899da891e12004d7993a627e01", 0, "wp tcId 43 InvalidEncoding" },
    /* WP tcId 44 InvalidEncoding: published invalid, oracle invalid */
    { "313233343030", "7d4d0e7f6153a69b6242b522abbee685fda4420f8834b108c3bdae369ef549fa", "617c1492402ab5ce03e2c3a7f0384d051b9cf3570f1207fc78c1bcc98c281c2b9ce23fc6213ed5b87912e9bbf92f5e2c780eae26d15c50a112d1e97d2ea33c06", 0, "wp tcId 44 InvalidEncoding" },
    /* WP tcId 45 InvalidEncoding: published invalid, oracle invalid */
    { "313233343030", "7d4d0e7f6153a69b6242b522abbee685fda4420f8834b108c3bdae369ef549fa", "e57c1492402ab5ce03e2c3a7f0384d051b9cf3570f1207fc78c1bcc98c281c2bbb3eb51cd98dddb235a5f46f2bded6af184a58d09cce928bda43f41d69118a03", 0, "wp tcId 45 InvalidEncoding" },
    /* WP tcId 46 InvalidEncoding: published invalid, oracle invalid */
    { "313233343030", "7d4d0e7f6153a69b6242b522abbee685fda4420f8834b108c3bdae369ef549fa", "657d1492402ab5ce03e2c3a7f0384d051b9cf3570f1207fc78c1bcc98c281c2bcd237dda9a116501f67a5705a854b9adc304f34720803a91b324f2c13e0f5a09", 0, "wp tcId 46 InvalidEncoding" },
    /* WP tcId 47 InvalidEncoding: published invalid, oracle invalid */
    { "313233343030", "7d4d0e7f6153a69b6242b522abbee685fda4420f8834b108c3bdae369ef549fa", "657c1592402ab5ce03e2c3a7f0384d051b9cf3570f1207fc78c1bcc98c281c2b6b167bbdc0d881cc04d28905552c1876f3709851abc5007376940cc8a435c300", 0, "wp tcId 47 InvalidEncoding" },
    /* WP tcId 48 InvalidEncoding: published invalid, oracle invalid */
    { "313233343030", "7d4d0e7f6153a69b6242b522abbee685fda4420f8834b108c3bdae369ef549fa", "657c1412402ab5ce03e2c3a7f0384d051b9cf3570f1207fc78c1bcc98c281c2b7fd2ac7da14afffcceeb13f2a0d6b887941cb1a5eb57a52f3cb131a16cce7b0e", 0, "wp tcId 48 InvalidEncoding" },
    /* WP tcId 49 InvalidEncoding: published invalid, oracle invalid */
    { "313233343030", "7d4d0e7f6153a69b6242b522abbee685fda4420f8834b108c3bdae369ef549fa", "657c1492412ab5ce03e2c3a7f0384d051b9cf3570f1207fc78c1bcc98c281c2b7373ba13ebbef99cd2a8ead55ce735c987d85a35320925a8e871702dc7c5c40d", 0, "wp tcId 49 InvalidEncoding" },
    /* WP tcId 50 InvalidEncoding: published invalid, oracle invalid */
    { "313233343030", "7d4d0e7f6153a69b6242b522abbee685fda4420f8834b108c3bdae369ef549fa", "657c1492402ab54e03e2c3a7f0384d051b9cf3570f1207fc78c1bcc98c281c2bd35bd331c03f0855504ca1cab87b83c36a028425a3cf007ede4f4254c261cb00", 0, "wp tcId 50 InvalidEncoding" },
    /* WP tcId 51 InvalidEncoding: published invalid, oracle invalid */
    { "313233343030", "7d4d0e7f6153a69b6242b522abbee685fda4420f8834b108c3bdae369ef549fa", "657c1492402ab5ce02e2c3a7f0384d051b9cf3570f1207fc78c1bcc98c281c2bcb35101f73cf467deac8c1a03b6c3dc35af544132734b7e57ab20c89b2e4750d", 0, "wp tcId 51 InvalidEncoding" },
    /* WP tcId 52 InvalidEncoding: published invalid, oracle invalid */
    { "313233343030", "7d4d0e7f6153a69b6242b522abbee685fda4420f8834b108c3bdae369ef549fa", "657c1492402ab5ce03e2c3a7f2384d051b9cf3570f1207fc78c1bcc98c281c2bb58d2e8878290bff8d3355fdd4ea381924ee578752354eb6dee678ab4011c301", 0, "wp tcId 52 InvalidEncoding" },
    /* WP tcId 53 InvalidEncoding: published invalid, oracle invalid */
    { "313233343030", "7d4d0e7f6153a69b6242b522abbee685fda4420f8834b108c3bdae369ef549fa", "657c1492402ab5ce03e2c3a7f0384d851b9cf3570f1207fc78c1bcc98c281c2bb978c866187ffb1cc7b29a0b4045aefc08768df65717194ff0c6e63f4dea0d02", 0, "wp tcId 53 InvalidEncoding" },
    /* WP tcId 54 InvalidEncoding: published invalid, oracle invalid */
    { "313233343030", "7d4d0e7f6153a69b6242b522abbee685fda4420f8834b108c3bdae369ef549fa", "657c1492402ab5ce03e2c3a7f0384d051b9cf3570f1207fc78c1bcc98c281d2b0576ecf8eaf675f00f3dfbe19f75b83b7607a6c96414f6821af920a2498d0305", 0, "wp tcId 54 InvalidEncoding" },
    /* WP tcId 55 InvalidEncoding: published invalid, oracle invalid */
    { "313233343030", "7d4d0e7f6153a69b6242b522abbee685fda4420f8834b108c3bdae369ef549fa", "657c1492402ab5ce03e2c3a7f0384d051b9cf3570f1207fc78c1bcc98c289c2be5241a345c7b5428054c74b7c382fa10d4a5f1e8f8b79a71d3fdea2254f1ff0e", 0, "wp tcId 55 InvalidEncoding" },
    /* WP tcId 56 InvalidEncoding: published invalid, oracle invalid */
    { "313233343030", "7d4d0e7f6153a69b6242b522abbee685fda4420f8834b108c3bdae369ef549fa", "657c1492402ab5ce03e2c3a7f0384d051b9cf3570f1207fc78c1bcc98c281c2a63950c85cd6dc96364e768de50ff7732b538f8a0b1615d799190ab600849230e", 0, "wp tcId 56 InvalidEncoding" },
    /* WP tcId 57 InvalidEncoding: published invalid, oracle invalid */
    { "313233343030", "7d4d0e7f6153a69b6242b522abbee685fda4420f8834b108c3bdae369ef549fa", "657c1492402ab5ce03e2c3a7f0384d051b9cf3570f1207fc78c1bcc98c281c0b543bd3da0a56a8c9c152f59c9fec12f31fa66434d48b817b30d90cb4efa8b501", 0, "wp tcId 57 InvalidEncoding" },
    /* WP tcId 58 InvalidEncoding: published invalid, oracle invalid */
    { "313233343030", "7d4d0e7f6153a69b6242b522abbee685fda4420f8834b108c3bdae369ef549fa", "657c1492402ab5ce03e2c3a7f0384d051b9cf3570f1207fc78c1bcc98c281c6b8da07efd07a6dafb015ed6a32fe136319a972ffbc341f3a0beae97ccf8136505", 0, "wp tcId 58 InvalidEncoding" },
    /* WP tcId 59 InvalidEncoding: published invalid, oracle invalid */
    { "313233343030", "7d4d0e7f6153a69b6242b522abbee685fda4420f8834b108c3bdae369ef549fa", "657c1492402ab5ce03e2c3a7f0384d051b9cf3570f1207fc78c1bcc98c281cab227aedf259f910f0f3a759a335062665217925d019173b88917eae294f75d40f", 0, "wp tcId 59 InvalidEncoding" },
    /* WP tcId 60 InvalidEncoding: published invalid, oracle invalid */
    { "313233343030", "7d4d0e7f6153a69b6242b522abbee685fda4420f8834b108c3bdae369ef549fa", "0000000000000000000000000000000000000000000000000000000000000000e0b8e7770d51c7a36375d006c5bffd6af43ff54aaf47e4330dc118c71d61ec02", 0, "wp tcId 60 InvalidEncoding" },
    /* WP tcId 61 InvalidEncoding: published invalid, oracle invalid */
    { "313233343030", "7d4d0e7f6153a69b6242b522abbee685fda4420f8834b108c3bdae369ef549fa", "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff463a1908382e7eb7693acef9884f7cf931a215e0791876be22c631a59881fd0e", 0, "wp tcId 61 InvalidEncoding" },
    /* WP tcId 62 InvalidEncoding: published invalid, oracle invalid */
    { "313233343030", "7d4d0e7f6153a69b6242b522abbee685fda4420f8834b108c3bdae369ef549fa", "9a83eb6dbfd54a31fc1d3c580fc7b2fae4630ca8f0edf803873e433673d7e3d40e94254586cb6188c5386c3febed477cb9a6cb29e3979adc4cb27cf5278fb70a", 0, "wp tcId 62 InvalidEncoding" },
    /* WP tcId 63 SignatureMalleability: published invalid, oracle invalid */
    { "54657374", "7d4d0e7f6153a69b6242b522abbee685fda4420f8834b108c3bdae369ef549fa", "7c38e026f29e14aabd059a0f2db8b0cd783040609a8be684db12f82a27774ab067654bce3832c2d76f8f6f5dafc08d9339d4eef676573336a5c51eb6f946b31d", 0, "wp tcId 63 SignatureMalleability" },
    /* WP tcId 64 SignatureMalleability: published invalid, oracle invalid */
    { "54657374", "7d4d0e7f6153a69b6242b522abbee685fda4420f8834b108c3bdae369ef549fa", "7c38e026f29e14aabd059a0f2db8b0cd783040609a8be684db12f82a27774ab05439412b5395d42f462c67008eba6ca839d4eef676573336a5c51eb6f946b32d", 0, "wp tcId 64 SignatureMalleability" },
    /* WP tcId 65 SignatureMalleability: published invalid, oracle invalid */
    { "54657374", "7d4d0e7f6153a69b6242b522abbee685fda4420f8834b108c3bdae369ef549fa", "7c38e026f29e14aabd059a0f2db8b0cd783040609a8be684db12f82a27774ab02ee12ce5875bf9dff26556464bae2ad239d4eef676573336a5c51eb6f946b34d", 0, "wp tcId 65 SignatureMalleability" },
    /* WP tcId 66 SignatureMalleability: published invalid, oracle invalid */
    { "54657374", "7d4d0e7f6153a69b6242b522abbee685fda4420f8834b108c3bdae369ef549fa", "7c38e026f29e14aabd059a0f2db8b0cd783040609a8be684db12f82a27774ab0e2300459f1e742404cd934d2c595a6253ad4eef676573336a5c51eb6f946b38d", 0, "wp tcId 66 SignatureMalleability" },
    /* WP tcId 67 SignatureMalleability: published invalid, oracle invalid */
    { "54657374", "7d4d0e7f6153a69b6242b522abbee685fda4420f8834b108c3bdae369ef549fa", "7c38e026f29e14aabd059a0f2db8b0cd783040609a8be684db12f82a27774ab07a9155711ecfaf7f99f277bad0c6ae7e39d4eef676573336a5c51eb6f946b32d", 0, "wp tcId 67 SignatureMalleability" },
    /* WP tcId 68 SignatureMalleability: published invalid, oracle invalid */
    { "54657374", "7d4d0e7f6153a69b6242b522abbee685fda4420f8834b108c3bdae369ef549fa", "7c38e026f29e14aabd059a0f2db8b0cd783040609a8be684db12f82a27774ab07a9155711ecfaf7f99f277bad0c6ae7e39d4eef676573336a5c51eb6f946b34d", 0, "wp tcId 68 SignatureMalleability" },
    /* WP tcId 69 SignatureMalleability: published invalid, oracle invalid */
    { "54657374", "7d4d0e7f6153a69b6242b522abbee685fda4420f8834b108c3bdae369ef549fa", "7c38e026f29e14aabd059a0f2db8b0cd783040609a8be684db12f82a27774ab07a9155711ecfaf7f99f277bad0c6ae7e39d4eef676573336a5c51eb6f946b38d", 0, "wp tcId 69 SignatureMalleability" },
    /* WP tcId 70 SignatureMalleability: published invalid, oracle invalid */
    { "54657374", "7d4d0e7f6153a69b6242b522abbee685fda4420f8834b108c3bdae369ef549fa", "7c38e026f29e14aabd059a0f2db8b0cd783040609a8be684db12f82a27774ab0679155711ecfaf7f99f277bad0c6ae7e39d4eef676573336a5c51eb6f946b38d", 0, "wp tcId 70 SignatureMalleability" },
    /* WP tcId 71 Valid: published valid, oracle valid */
    { "", "a12c2beb77265f2aac953b5009349d94155a03ada416aad451319480e983ca4c", "5056325d2ab440bf30bbf0f7173199aa8b4e6fbc091cf3eb6bc6cf87cd73d992ffc216c85e4ab5b8a0bbc7e9a6e9f8d33b7f6e5ac0ffdc22d9fcaf784af84302", 1, "wp tcId 71 Valid" },
    /* WP tcId 72 Valid: published valid, oracle valid */
    { "78", "a12c2beb77265f2aac953b5009349d94155a03ada416aad451319480e983ca4c", "481fafbf4364d7b682475282f517a3ac0538c9a6b6a562e99a3d8e5afb4f90a559b056b9f07af023905753b02d95eb329a35c77f154b79abbcd291615ce42f02", 1, "wp tcId 72 Valid" },
    /* WP tcId 73 Valid: published valid, oracle valid */
    { "54657374", "a12c2beb77265f2aac953b5009349d94155a03ada416aad451319480e983ca4c", "8a9bb4c465a3863abc9fd0dd35d80bb28f7d33d37d74679802d63f82b20da114b8d765a1206b3e9ad7cf2b2d8d778bb8651f1fa992db293c0039eacb6161480f", 1, "wp tcId 73 Valid" },
    /* WP tcId 74 Valid: published valid, oracle valid */
    { "48656c6c6f", "a12c2beb77265f2aac953b5009349d94155a03ada416aad451319480e983ca4c", "d839c20abfda1fd429531831c64f813f84b913e9928540310cf060b44c3dbf9457d44a7721fdc0d67724ff81cb450dd39b10cfb65db15dda4b8bf09d26bd3801", 1, "wp tcId 74 Valid" },
    /* WP tcId 75 Valid: published valid, oracle valid */
    { "313233343030", "a12c2beb77265f2aac953b5009349d94155a03ada416aad451319480e983ca4c", "9bbb1052dcfa8ad2715c2eb716ae4f1902dea353d42ee09fd4c0b4fcb8b52b5219e2200016e1199d0061891c263e31b0bc3b55673c19610c4e0fa5408004160b", 1, "wp tcId 75 Valid" },
    /* WP tcId 76 Valid: published valid, oracle valid */
    { "000000000000000000000000", "a12c2beb77265f2aac953b5009349d94155a03ada416aad451319480e983ca4c", "f63b5c0667c7897fc283296416f7f60e84bbde9cbd832e56be463ed9f568069702b17a2f7c341ebf590706a6388ac76ac613c1675ec0f2c7118f2573422a500b", 1, "wp tcId 76 Valid" },
    /* WP tcId 77 Valid: published valid, oracle valid */
    { "6161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161", "a12c2beb77265f2aac953b5009349d94155a03ada416aad451319480e983ca4c", "1bc44d7001e6b5b9090fef34b2ca480f9786bbefa7d279353e5881e8dfb91b803ccd46500e270ef0109bfd741037558832120bc2a4f20fbe7b5fb3c3aaf23e08", 1, "wp tcId 77 Valid" },
    /* WP tcId 78 Valid: published valid, oracle valid */
    { "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f60", "a12c2beb77265f2aac953b5009349d94155a03ada416aad451319480e983ca4c", "ea8e22143b02372e76e99aece3ed36aec529768a27e2bb49bdc135d44378061e1f62d1ac518f33ebf37b2ee8cc6dde68a4bd7d4a2f4d6cb77f015f71ca9fc30d", 1, "wp tcId 78 Valid" },
    /* WP tcId 79 Valid: published valid, oracle valid */
    { "ffffffffffffffffffffffffffffffff", "a12c2beb77265f2aac953b5009349d94155a03ada416aad451319480e983ca4c", "8acd679e1a914fc45d5fa83d3021f0509c805c8d271df54e52f43cfbd00cb6222bf81d58fe1de2de378df67ee9f453786626961fe50a9b05f12b6f0899ebdd0a", 1, "wp tcId 79 Valid" },
    /* WP tcId 80 Ktv: published valid, oracle valid */
    { "", "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a", "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b", 1, "wp tcId 80 Ktv" },
    /* WP tcId 81 Ktv: published valid, oracle valid */
    { "72", "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c", "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00", 1, "wp tcId 81 Ktv" },
    /* WP tcId 82 Ktv: published valid, oracle valid */
    { "af82", "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025", "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a", 1, "wp tcId 82 Ktv" },
    /* WP tcId 83 Ktv: published valid, oracle valid */
    { "08b8b2b733424243760fe426a4b54908632110a66c2f6591eabd3345e3e4eb98fa6e264bf09efe12ee50f8f54e9f77b1e355f6c50544e23fb1433ddf73be84d879de7c0046dc4996d9e773f4bc9efe5738829adb26c81b37c93a1b270b20329d658675fc6ea534e0810a4432826bf58c941efb65d57a338bbd2e26640f89ffbc1a858efcb8550ee3a5e1998bd177e93a7363c344fe6b199ee5d02e82d522c4feba15452f80288a821a579116ec6dad2b3b310da903401aa62100ab5d1a36553e06203b33890cc9b832f79ef80560ccb9a39ce767967ed628c6ad573cb116dbefefd75499da96bd68a8a97b928a8bbc103b6621fcde2beca1231d206be6cd9ec7aff6f6c94fcd7204ed3455c68c83f4a41da4af2b74ef5c53f1d8ac70bdcb7ed185ce81bd84359d44254d95629e9855a94a7c1958d1f8ada5d0532ed8a5aa3fb2d17ba70eb6248e594e1a2297acbbb39d502f1a8c6eb6f1ce22b3de1a1f40cc24554119a831a9aad6079cad88425de6bde1a9187ebb6092cf67bf2b13fd65f27088d78b7e883c8759d2c4f5c65adb7553878ad575f9fad878e80a0c9ba63bcbcc2732e69485bbc9c90bfbd62481d9089beccf80cfe2df16a2cf65bd92dd597b0707e0917af48bbb75fed413d238f5555a7a569d80c3414a8d0859dc65a46128bab27af87a71314f318c782b23ebfe808b82b0ce26401d2e22f04d83d1255dc51addd3b75a2b1ae0784504df543af8969be3ea7082ff7fc9888c144da2af58429ec96031dbcad3dad9af0dcbaaaf268cb8fcffead94f3c7ca495e056a9b47acdb751fb73e666c6c655ade8297297d07ad1ba5e43f1bca32301651339e22904cc8c42f58c30c04aafdb038dda0847dd988dcda6f3bfd15c4b4c4525004aa06eeff8ca61783aacec57fb3d1f92b0fe2fd1a85f6724517b65e614ad6808d6f6ee34dff7310fdc82aebfd904b01e1dc54b2927094b2db68d6f903b68401adebf5a7e08d78ff4ef5d63653a65040cf9bfd4aca7984a74d37145986780fc0b16ac451649de6188a7dbdf191f64b5fc5e2ab47b57f7f7276cd419c17a3ca8e1b939ae49e488acba6b965610b5480109c8b17b80e1b7b750dfc7598d5d5011fd2dcc5600a32ef5b52a1ecc820e308aa342721aac0943bf6686b64b2579376504ccc493d97e6aed3fb0f9cd71a43dd497f01f17c0e2cb3797aa2a2f256656168e6c496afc5fb93246f6b1116398a346f1a641f3b041e989f7914f90cc2c7fff357876e506b50d334ba77c225bc307ba537152f3f1610e4eafe595f6d9d90d11faa933a15ef1369546868a7f3a45a96768d40fd9d03412c091c6315cf4fde7cb68606937380db2eaaa707b4c4185c32eddcdd306705e4dc1ffc872eeee475a64dfac86aba41c0618983f8741c5ef68d3a101e8a3b8cac60c905c15fc910840b94c00a0b9d0", "278117fc144c72340f67d0f2316e8386ceffbf2b2428c9c51fef7c597f1d426e", "0aab4c900501b3e24d7cdf4663326a3a87df5e4843b2cbdb67cbf6e460fec350aa5371b1508f9f4528ecea23c436d94b5e8fcd4f681e30a6ac00a9704a188a03", 1, "wp tcId 83 Ktv" },
    /* WP tcId 84 Ktv: published valid, oracle valid */
    { "124e583f8b8eca58bb29c271b41d36986bbc45541f8e51f9cb0133eca447601e", "100fdf47fb94f1536a4f7c3fda27383fa03375a8f527c537e6f1703c47f94f86", "dac119d6ca87fc59ae611c157048f4d4fc932a149dbe20ec6effd1436abf83ea05c7df0fef06147241259113909bc71bd3c53ba4464ffcad3c0968f2ffffff0f", 1, "wp tcId 84 Ktv" },
    /* WP tcId 85 InvalidKtv: published invalid, oracle invalid */
    { "6a0bc2b0057cedfc0fa2e3f7f7d39279b30f454a69dfd1117c758d86b19d85e0", "100fdf47fb94f1536a4f7c3fda27383fa03375a8f527c537e6f1703c47f94f86", "0971f86d2c9c78582524a103cb9cf949522ae528f8054dc20107d999be673ff4e25ebf2f2928766b1248bec6e91697775f8446639ede46ad4df4053000000010", 0, "wp tcId 85 InvalidKtv" },
    /* WP tcId 86 Ktv: published valid, oracle valid */
    { "b0729a713593a92e46b56eaa66b9e435f7a09a8e7de03b078f6f282285276635f301e7aaafe42187c45d6f5b13f9f16b11195cc125c05b90d24dfe4c", "8fd659b77b558ed93882c1157438450ac86ec62d421d568e98ee236f3810295a", "7db17557ac470c0eda4eedaabce99197ab62565653cf911f632ee8be0e5ffcfc88fb94276b42e0798fd3aa2f0318be7fc6a29fae75f70c3dcdc414a0ad866601", 1, "wp tcId 86 Ktv" },
    /* WP tcId 87 Ktv: published valid, oracle valid */
    { "a8546e50ba31cae3234310d32672447be213fad91a227a19669c53d309b959782b0e6b71f8791fdb470043b58122003157d2d96a43a6cbd7d3a8d86bf4c97391883e268d50af80e1e6e12939c2bd50ca746cdadfad4edf1bda875299740724148efb1ebe73fb60088cda890317658627a5f7ab5a0c075d9d8f3f97b6492b35519e50ff6b38377432a7081f9176bb1c29a862deac1336ca20b097a47829cec10a6a7cec178eda2d12f6dc6c87f910454af0123555ba184e68804d9cced60fd5c8c90943e56599c8f0ba59a38491ba5e5a53460682474c07e40ca142983314fd762856bb1093f359da6eb0a756bd93a3160c10dd8feea6b97e7c6a17cb54bd5d7649c05c66d7bdee056671dfdaf689fa3945bb8e29a429f4bd5d355dce9687b06f01d5e33e3999f0e8", "2a606bf67ac770c607038b004101b325edb569efd3413d2d1f2c3e6b4e6e3082", "67d84d4c3945aaf06e06d524be63acbfb5dbb1988c4aea96a5ee9f7a9b9eecc29df4f66b8aa1d9e8607a58fb1ef0c2ad69aac005b4f58e34103344a9c8871a09", 1, "wp tcId 87 Ktv" },
    /* WP tcId 88 Ktv: published valid, oracle valid */
    { "cd2212eddb0706f62c995cef958634f0cb7793444cbf4d30e81c27c41ebea6cb02607510131f9c015692dfd521b148841e9a2d3564d20ac401f6cb8e40f520fe0cafbeaa88840b83013369d879f013463fe52a13267aa0c8c59c45cde9399cd1e6be8cc64cf48315ac2eb31a1c567a4fb7d601746d1f63b5ac020712adbbe07519bded6f", "c9c946cbc5544ac74eef491f07c5881c16faf7ec31ce4aa91bb60ae7b4539051", "24087d47f3e20af51b9668ae0a88ce76586802d0ec75d8c0f28fc30962b5e1d1a1d509571a1624ed125a8df92a6e963728d6b5de99200b8e285f70feb6f05207", 1, "wp tcId 88 Ktv" },
    /* WP tcId 89 Ktv: published valid, oracle valid */
    { "ec5c7cb078", "32ad026f693d0d2afe7f4388d91c4c964426fcb9e3665c3ebd8650009b815c8e", "d920d421a5956b69bfe1ba834c025e2babb6c7a6d78c97de1d9bb1116dfdd1185147b2887e34e15578172e150774275ea2aad9e02106f7e8ca1caa669a066f0c", 1, "wp tcId 89 Ktv" },
    /* WP tcId 90 Ktv: published valid, oracle valid */
    { "4668c6a76f0e482190a7175b9f3806a5fe4314a004fa69f988373f7a", "32ad026f693d0d2afe7f4388d91c4c964426fcb9e3665c3ebd8650009b815c8e", "4f62daf7f7c162038552ad7d306e195baa37ecf6ca7604142679d7d1128e1f8af52e4cb3545748c44ef1ff1c64e877e4f4d248259b7f6eb56e3ef72097dc8e0c", 1, "wp tcId 90 Ktv" },
    /* WP tcId 91 Ktv: published valid, oracle valid */
    { "0f325ffd87e58131ffa23c05ea4579513b287fdba87b44", "c29ec1894e06d27b4e40486b4fa5063d66a746c7f9c323b12203c03b72b8b78a", "6669acf94667c5b541afe5307bde9476b13ae7e0e6058a772101ac8eb0a94331428eb4db0a2c68a9b6c1763b8624dab259b0876cdcfaeacc17b21a18e3fc010a", 1, "wp tcId 91 Ktv" },
    /* WP tcId 92 Ktv: published valid, oracle valid */
    { "ec5c7cb078", "cfda5b899e35764c5229e59295fe1222b7ddce176643697c29e46ecbba10cf10", "30490c28f806298225df62103521dcee047153912c33ab8ab8bbdd1ffabd70fd4fdb360f05be535b067d1cf4e78c2cb432206bf280aab3bd21aaa1cb894c5b06", 1, "wp tcId 92 Ktv" },
    /* WP tcId 93 Ktv: published valid, oracle valid */
    { "5dc9bb87eb11621a93f92abe53515697d2611b2eef73", "32ad026f693d0d2afe7f4388d91c4c964426fcb9e3665c3ebd8650009b815c8e", "deecafb6f2ede73fec91a6f10e45b9c1c61c4b9bfbe6b6147e2de0b1df6938971f7896c3ab83851fb5d9e537037bff0fca0ccb4a3cc38f056f91f7d7a0557e08", 1, "wp tcId 93 Ktv" },
    /* WP tcId 94 Ktv: published valid, oracle valid */
    { "67484059b2490b1a0a4f8dee77979e26", "cfda5b899e35764c5229e59295fe1222b7ddce176643697c29e46ecbba10cf10", "4cd4f77ed473a6647387f3163541c67a1708a3c3bd1673247cb87f0cb68b3c56f04bfa72970c8a483efe659c87009ab4020b590b6641316b3deddb5450544e02", 1, "wp tcId 94 Ktv" },
    /* WP tcId 95 Ktv: published valid, oracle valid */
    { "7dcfe60f881e1285676f35b68a1b2dbcdd7be6f719a288ababc28d36e3a42ac3010a1ca54b32760e74", "32ad026f693d0d2afe7f4388d91c4c964426fcb9e3665c3ebd8650009b815c8e", "7f8663cf98cbd39d5ff553f00bcf3d0d520605794f8866ce75714d77cc51e66c91818b657d7b0dae430a68353506edc4a714c345f5ddb5c8b958ba3d035f7a01", 1, "wp tcId 95 Ktv" },
    /* WP tcId 96 Ktv: published valid, oracle valid */
    { "a020a4381dc9141f47ee508871ab7a8b5a3648727c4281ae9932376f23a8e1bcda0626b7129197d864178631ec89c4332dbb18", "cfda5b899e35764c5229e59295fe1222b7ddce176643697c29e46ecbba10cf10", "1e41a24fe732bd7cab14c2a2f5134ee8c87fcbd2e987e60957ed9239e5c32404d56977e1b4282871896cb10625a1937468e4dc266e16a9c1b8e9891177eca802", 1, "wp tcId 96 Ktv" },
    /* WP tcId 97 Ktv: published valid, oracle valid */
    { "58e456064dff471109def4ca27fa8310a1df32739655b624f27e6418d34b7f007173f3faa5", "32ad026f693d0d2afe7f4388d91c4c964426fcb9e3665c3ebd8650009b815c8e", "6aab49e5c0bc309b783378ee03ffda282f0185cdf94c847701ff307a6ee8d0865411c44e0a8206f6a5f606107451940c2593af790ce1860f4c14ab25b2deae08", 1, "wp tcId 97 Ktv" },
    /* WP tcId 98 Ktv: published valid, oracle valid */
    { "e1cbf2d86827825613fb7a85811d", "529919c9c780985a841c42ba6c180ff2d67a276ccfbe281080e47ab71a758f56", "01abfa4d6bbc726b196928ec84fd03f0c953a4fa2b228249562ff1442a4f63a7150b064f3712b51c2af768d2c2711a71aabf8d186833e941a0301b82f0502905", 1, "wp tcId 98 Ktv" },
    /* WP tcId 99 Ktv: published valid, oracle valid */
    { "a25176b3afea318b2ec11ddacb10caf7179c0b3f8eabbfa2895581138d3c1e0e", "cfda5b899e35764c5229e59295fe1222b7ddce176643697c29e46ecbba10cf10", "2a833aadecd9f28235cb5896bf3781521dc71f28af2e91dbe1735a61dce3e31ac15ca24b3fc47817a59d386bbbb2ce60a6adc0a2703bb2bdea8f70f91051f706", 1, "wp tcId 99 Ktv" },
    /* WP tcId 100 Ktv: published valid, oracle valid */
    { "a1", "32ad026f693d0d2afe7f4388d91c4c964426fcb9e3665c3ebd8650009b815c8e", "1a74ed2cbdc7d8f3827014e8e6ecf8fd2698ac8f86833acccdd400df710fe0d6b0543c9cfa00d52bf024ab7ce0d91981944097233ec134d5c7abbd44bfd32d0d", 1, "wp tcId 100 Ktv" },
    /* WP tcId 101 Ktv: published valid, oracle valid */
    { "975ef941710071a9e1e6325a0c860becd7c695b5117c3107b686e330e5", "2252b3d57c74cbf8bc460dc2e082847926bc022f09ab6ae95756362bfd1167c1", "af0fd9dda7e03e12313410d8d8844ebb6fe6b7f65141f22d7bcba5695a25414a9e54326fb44d59fb14707899a8aae70857b23d4080d7ab2c396ef3a36d45ce02", 1, "wp tcId 101 Ktv" },
    /* WP tcId 102 Ktv: published valid, oracle valid */
    { "", "c0a773110f975de3732355bb7ec7f0c41c091c0252966070205516693b992a4a", "0280427e713378f49d478df6373c6cac847b622b567daa2376c839e7ac10e22c380ab0fa8617c9dcfe76c4d9db5459b21dc1413726e46cc8f387d359e344f407", 1, "wp tcId 102 Ktv" },
    /* WP tcId 103 Ktv: published valid, oracle valid */
    { "a9e6d94870a67a9fe1cf13b1e6f9150cdd407bf6480ec841ea586ae3935e9787163cf419c1", "cfda5b899e35764c5229e59295fe1222b7ddce176643697c29e46ecbba10cf10", "c97e3190f83bae7729ba473ad46b420b8aad735f0808ea42c0f898ccfe6addd4fd9d9fa3355d5e67ee21ab7e1f805cd07f1fce980e307f4d7ad36cc924eef00c", 1, "wp tcId 103 Ktv" },
    /* WP tcId 104 Ktv: published valid, oracle valid */
    { "11cb1eafa4c42a8402c4193c4696f7b2e6d4585e4b42dcf1a8b67a80b2da80bc9d4b649fb2f35eaf1f56c426fd0b", "32ad026f693d0d2afe7f4388d91c4c964426fcb9e3665c3ebd8650009b815c8e", "14ceb2eaf4688d995d482f44852d71ad878cd7c77b41e60b0065fd01a59b054ee74759224187dbde9e59a763a70277c960892ef89fba997aba2576b2c54ba608", 1, "wp tcId 104 Ktv" },
    /* WP tcId 105 Ktv: published valid, oracle valid */
    { "27d465bc632743522aefa23c", "c9c946cbc5544ac74eef491f07c5881c16faf7ec31ce4aa91bb60ae7b4539051", "c2656951e2a0285585a51ff0eda7e9a23c2dfd2ffa273aee7808f4604e8f9a8c8ea49e9fce4eb2d8d75d36b7238fe6fc13b6c5d9427dd58f8c6615d033c0bd0f", 1, "wp tcId 105 Ktv" },
    /* WP tcId 106 Ktv: published valid, oracle valid */
    { "5ffa", "c29ec1894e06d27b4e40486b4fa5063d66a746c7f9c323b12203c03b72b8b78a", "931e5152fcef078c22cc5d6a3a65f06e396289f6f5f2d1efa6340254a53526ef5dc6874eeddf35c3f50991c53cd02bf06313e37d93ee1f7022128ffa3b8f300b", 1, "wp tcId 106 Ktv" },
    /* WP tcId 107 Ktv: published valid, oracle valid */
    { "25", "529919c9c780985a841c42ba6c180ff2d67a276ccfbe281080e47ab71a758f56", "e4ae21f7a8f4b3b325c161a8c6e53e2edd7005b9c2f8a2e3b0ac4ba94aa80be6f2ee22ac8d4a96b9a3eb73a825e7bb5aff4a3393bf5b4a38119e9c9b1b041106", 1, "wp tcId 107 Ktv" },
    /* WP tcId 108 Ktv: published valid, oracle valid */
    { "80fdd6218f29c8c8f6bd820945f9b0854e3a8824", "2252b3d57c74cbf8bc460dc2e082847926bc022f09ab6ae95756362bfd1167c1", "e097e0bd0370bff5bde359175a11b728ee9639095d5df8eda496395565616edfe079977f7d4dc8c75d6113a83d6a55e6e1676408c0967a2906339b43337dcb01", 1, "wp tcId 108 Ktv" },
    /* WP tcId 109 Ktv: published valid, oracle valid */
    { "b477b0480bb84642608b908d29a51cf2fce63f24ee95", "2a606bf67ac770c607038b004101b325edb569efd3413d2d1f2c3e6b4e6e3082", "28fafbb62b4d688fa79e1ac92851f46e319b161f801d4dc09acc21fdd6780a2c4292b8c1003c61c2bcebe7f3f88ccc4bb26d407387c5f27cb8c94cf6ce810405", 1, "wp tcId 109 Ktv" },
    /* WP tcId 110 Ktv: published valid, oracle valid */
    { "aa365b442d12b7f3c925", "32ad026f693d0d2afe7f4388d91c4c964426fcb9e3665c3ebd8650009b815c8e", "83c40ce13d483cc58ff65844875862d93df4bd367af77efa469ec06a8ed9e6d7905a04879535708ddf225567a815c9b941d405c98e918fd0c151165cea7fb101", 1, "wp tcId 110 Ktv" },
    /* WP tcId 111 Ktv: published valid, oracle valid */
    { "27e792b28b2f1702", "54cda623245759ad6d43e620a606908befc633d60792bc7798447a0ef38e7311", "14d9b497c19b91d43481c55bb6f5056de252d9ecb637575c807e58e9b4c5eac8b284089d97e2192dc242014363208e2c9a3435edf8928fb1d893553e9be4c703", 1, "wp tcId 111 Ktv" },
    /* WP tcId 112 Ktv: published valid, oracle valid */
    { "eef3bb0f617c17d0420c115c21c28e3762edc7b7fb048529b84a9c2bc6", "2362bac514d5fad33802642e979a1e82de6eb6f1bcbf6a5b304f2bb02b9e57fe", "242ddb3a5d938d07af690b1b0ef0fa75842c5f9549bf39c8750f75614c712e7cbaf2e37cc0799db38b858d41aec5b9dd2fca6a3c8e082c10408e2cf3932b9d08", 1, "wp tcId 112 Ktv" },
    /* WP tcId 113 Ktv: published valid, oracle valid */
    { "475f", "32ad026f693d0d2afe7f4388d91c4c964426fcb9e3665c3ebd8650009b815c8e", "71a4a06a34075f2fd47bc3abf4714d46db7e97b08cb6180d3f1539ac50b18ce51f8af8ae95ed21d4fa0daab7235925631ecea1fd9d0d8a2ba7a7583fd04b900c", 1, "wp tcId 113 Ktv" },
    /* WP tcId 114 Ktv: published valid, oracle valid */
    { "01234567", "037b55b427dc8daa0f80fcebaf0846902309f8a6cf18b465c0ce9b6539629ac8", "c964e100033ce8888b23466677da4f4aea29923f642ae508f9d0888d788150636ab9b2c3765e91bbb05153801114d9e52dc700df377212222bb766be4b8c020d", 1, "wp tcId 114 Ktv" },
    /* WP tcId 115 Ktv: published valid, oracle valid */
    { "9399a6db9433d2a28d2b0c11c8794ab7d108c95b", "9c0007698f177998a7666c7cf7973e2b88e9c4946e33804a7bbe8968d2394b2e", "176065c6d64a136a2227687d77f61f3fca3b16122c966276fd9a8b14a1a2cea4c33b3533d11101717016684e3810efbea63bb23773f7cc480174199abd734f08", 1, "wp tcId 115 Ktv" },
    /* WP tcId 116 Ktv: published valid, oracle valid */
    { "7af783afbbd44c1833ab7237ecaf63b94ffdd003", "ed3a6f9721dc9729c1f76635bcf080d7036e1c2f0228654ccbbe1e738c17b963", "7ca69331eec8610d38f00e2cdbd46966cb359dcde98a257ac6f362cc00c8f4fe85c02285fe4d66e31a44cadb2bf474e1a7957609eb4fe95a71473fe6699aa70d", 1, "wp tcId 116 Ktv" },
    /* WP tcId 117 Ktv: published valid, oracle valid */
    { "321b5f663c19e30ee7bbb85e48ecf44db9d3f512", "4abfb535313705a6570018440cdec1a3ae33e51f352112fa6acbd0c6bc3ea859", "f296715e855d8aecccba782b670163dedc4458fe4eb509a856bcac450920fd2e95a3a3eb212d2d9ccaf948c39ae46a2548af125f8e2ad9b77bd18f92d59f9200", 1, "wp tcId 117 Ktv" },
    /* WP tcId 118 Ktv: published valid, oracle valid */
    { "c48890e92aeeb3af04858a8dc1d34f16a4347b91", "4f2162e6bf03a712db0efa418b7e7006e23871d9d7ec555a313885c4afd96385", "367d07253a9d5a77d054b9c1a82d3c0a448a51905343320b3559325ef41839608aa45564978da1b2968c556cfb23b0c98a9be83e594d5e769d69d1156e1b1506", 1, "wp tcId 118 Ktv" },
    /* WP tcId 119 TinkOverflow: published valid, oracle valid */
    { "321b5f663c19e30ee7bbb85e48ecf44db9d3f512", "4abfb535313705a6570018440cdec1a3ae33e51f352112fa6acbd0c6bc3ea859", "f296715e855d8aecccba782b670163dedc4458fe4eb509a856bcac450920fd2e95a3a3eb212d2d9ccaf948c39ae46a2548af125f8e2ad9b77bd18f92d59f9200", 1, "wp tcId 119 TinkOverflow" },
    /* WP tcId 120 TinkOverflow: published valid, oracle valid */
    { "c48890e92aeeb3af04858a8dc1d34f16a4347b91", "4f2162e6bf03a712db0efa418b7e7006e23871d9d7ec555a313885c4afd96385", "367d07253a9d5a77d054b9c1a82d3c0a448a51905343320b3559325ef41839608aa45564978da1b2968c556cfb23b0c98a9be83e594d5e769d69d1156e1b1506", 1, "wp tcId 120 TinkOverflow" },
    /* WP tcId 121 TinkOverflow: published valid, oracle valid */
    { "26d5f0631f49106db58c4cfc903691134811b33c", "0717d75ce27ea181ed5a30e6456c649b5cf453a6b4c12cd3f9fd16b31e0c25cd", "9588e02bc815649d359ce710cdc69814556dd8c8bab1c468f40a49ebefb7f0de7ed49725edfd1b708fa1bad277c35d6c1b9c5ec25990997645780f9203d7dd08", 1, "wp tcId 121 TinkOverflow" },
    /* WP tcId 122 TinkOverflow: published valid, oracle valid */
    { "2a71f064af982a3a1103a75cef898732d7881981", "db5b9eab7e84e5a13505865fa711c9c896c898609fc11fc9bc1e55028f9496df", "2217a0be57dd0d6c0090641496bcb65e37213f02a0df50aff0368ee2808e1376504f37b37494132dfc4d4887f58b9e86eff924040db3925ee4f8e1428c4c500e", 1, "wp tcId 122 TinkOverflow" },
    /* WP tcId 123 TinkOverflow: published valid, oracle valid */
    { "bf26796cef4ddafcf5033c8d105057db0210b6ad", "7bac18f6d2625d3915f233434cda38a577247a7332a5170b37142a34644145e0", "1fda6dd4519fdbefb515bfa39e8e5911f4a0a8aa65f40ef0c542b8b34b87f9c249dc57f320718ff457ed5915c4d0fc352affc1287724d3f3a9de1ff777a02e01", 1, "wp tcId 123 TinkOverflow" },
    /* WP tcId 124 TinkOverflow: published valid, oracle valid */
    { "bf26796cef4ddafcf5033c8d105057db0210b6ad", "7bac18f6d2625d3915f233434cda38a577247a7332a5170b37142a34644145e0", "1fda6dd4519fdbefb515bfa39e8e5911f4a0a8aa65f40ef0c542b8b34b87f9c249dc57f320718ff457ed5915c4d0fc352affc1287724d3f3a9de1ff777a02e01", 1, "wp tcId 124 TinkOverflow" },
    /* WP tcId 125 TinkOverflow: published valid, oracle valid */
    { "ae03da6997e40cea67935020152d3a9a365cc055", "38ead304624abebf3e2b31e20e5629531e3fc659008887c9106f5e55adbbc62a", "068eafdc2f36b97f9bae7fbda88b530d16b0e35054d3a351e3a4c914b22854c711505e49682e1a447e10a69e3b04d0759c859897b64f71137acf355b63faf100", 1, "wp tcId 125 TinkOverflow" },
    /* WP tcId 126 TinkOverflow: published valid, oracle valid */
    { "489d473f7fb83c7f6823baf65482517bccd8f4ea", "e9bc95049af7e4817b17c402269ba5e767b7348757ac8002fec9e08390c0a9cf", "43670abc9f09a8a415e76f4a21c6a46156f066b5a37b3c1e867cf67248c7b927e8d13a763e37abf936f5f27f7a8aa290539d21f740efd26b65fd5ad27085f400", 1, "wp tcId 126 TinkOverflow" },
    /* WP tcId 127 TinkOverflow: published valid, oracle valid */
    { "1b704d6692d60a07ad1e1d047b65e105a80d3459", "ee8155ca4e8fe7bc5bca5992044eab7f8c3c6a13db1176f42f46c29da5b064f4", "56388f2228893b14ce4f2a5e0cc626591061de3a57c50a5ecab7b9d5bb2caeea191560a1cf2344c75fdb4a085444aa68d727b39f498169eaa82cf64a31f59803", 1, "wp tcId 127 TinkOverflow" },
    /* WP tcId 128 TinkOverflow: published valid, oracle valid */
    { "dc87030862c4c32f56261e93a367caf458c6be27", "db507bfcc9576393f7157bb360532b05c5fcf2e764b690cc6698a4a30d349095", "553e5845fc480a577da6544e602caadaa00ae3e5aa3dce9ef332b1541b6d5f21bdf1d01e98baf80b8435f9932f89b3eb70f02da24787aac8e77279e797d0bd0b", 1, "wp tcId 128 TinkOverflow" },
    /* WP tcId 129 TinkOverflow: published valid, oracle valid */
    { "7f41ef68508343ef18813cb2fb332445ec6480cd", "994eaf03309d6ad9d95a656bc1744e2886f029023a3750b34f35086b3c7227f8", "bc10f88081b7be1f2505b6e76c5c82e358cf21ec11b7df1f334fb587bada465b53d9f7b4d4fec964432ee91ead1bc32ed3c82f2167da1c834a37515df7fe130e", 1, "wp tcId 129 TinkOverflow" },
    /* WP tcId 130 TinkOverflow: published valid, oracle valid */
    { "e1ce107971534bc46a42ac609a1a37b4ca65791d", "127d37e406e0d83e4b55a09e21e8f50fb88af47e4a43f018cdebffc1948757f0", "00c11e76b5866b7c37528b0670188c1a0473fb93c33b72ae604a8865a7d6e094ff722e8ede3cb18389685ff3c4086c29006047466f81e71a329711e0b9294709", 1, "wp tcId 130 TinkOverflow" },
    /* WP tcId 131 TinkOverflow: published valid, oracle valid */
    { "869a827397c585cf35acf88a8728833ab1c8c81e", "d83ba84edfb4bec49f29be31d80a64b7c0b5a502438cdb1d0dd1e0e3e55786de", "0a6f0ac47ea136cb3ff00f7a96638e4984048999ee2da0af6e5c86bffb0e70bb97406b6ad5a4b764f7c99ebb6ec0fd434b8efe253b0423ef876c037998e8ab07", 1, "wp tcId 131 TinkOverflow" },
    /* WP tcId 132 TinkOverflow: published valid, oracle valid */
    { "619d8c4f2c93104be01cd574a385ceca08c33a9e", "d3c9aa2f3d6ef217a166e8ae403ed436c37facbbe3beceb78df6eb439f8fa04a", "b7cbb942a6661e2312f79548224f3e44f5841c6e880c68340756a00ce94a914e8404858265985e6bb97ef01d2d7e5e41340309606bfc43c8c6a8f925126b3d09", 1, "wp tcId 132 TinkOverflow" },
    /* WP tcId 133 TinkOverflow: published valid, oracle valid */
    { "5257a0bae8326d259a6ce97420c65e6c2794afe2", "d53280367c1c0b95ac4112218b92c6a71c51fb6312ce668de196c7d52a136155", "27a4f24009e579173ff3064a6eff2a4d20224f8f85fdec982a9cf2e6a3b51537348a1d7851a3a932128a923a393ea84e6b35eb3473c32dceb9d7e9cab03a0f0d", 1, "wp tcId 133 TinkOverflow" },
    /* WP tcId 134 TinkOverflow: published valid, oracle valid */
    { "5acb6afc9b368f7acac0e71f6a4831c72d628405", "94ac2336ba97a476fb4c9f2b5563e4167ca292c6e99e422350a911ae3172c315", "985b605fe3f449f68081197a68c714da0bfbf6ac2ab9abb0508b6384ea4999cb8d79af98e86f589409e8d2609a8f8bd7e80aaa8d92a84e7737fbe8dcef41920a", 1, "wp tcId 134 TinkOverflow" },
    /* WP tcId 135 TinkOverflow: published valid, oracle valid */
    { "3c87b3453277b353941591fc7eaa7dd37604b42a", "e1e7316d231f7f275bdf403360304da1509fdf1af1fd25ca214eaac0a289398f", "1c8fbda3d39e2b441f06da6071c13115cb4115c7c3341704cf6513324d4cf1ef4a1dd7678a048b0dde84e48994d080befcd70854079d44b6a0b0f9fa002d130c", 1, "wp tcId 135 TinkOverflow" },
    /* WP tcId 136 TinkOverflow: published valid, oracle valid */
    { "0a68e27ef6847bfd9e398b328a0ded3679d4649d", "fffbeea71215efaf9888fec2cc68edb3703ff11a66fd629b53cbda5eabc18750", "59097233eb141ed948b4f3c28a9496b9a7eca77454ecfe7e46737d1449a0b76b15aacf77cf48af27a668aa4434cfa26c504d75a2bcc4feac46465446234c0508", 1, "wp tcId 136 TinkOverflow" },
    /* WP tcId 137 TinkOverflow: published valid, oracle valid */
    { "4e9bef60737c7d4dd10bd52567e1473a36d3573d", "19ccc0527599cb032e0b4c4d74e60f13901768a99df041c3bc1bf6c0ef271169", "519105608508fe2f1b6da4cc8b23e39798b1d18d25972beed0404cec722e01ba1b6a0f85e99e092cca8076b101b60d4ac5035684357f4d0daacdc642da742a06", 1, "wp tcId 137 TinkOverflow" },
    /* WP tcId 138 TinkOverflow: published valid, oracle valid */
    { "cc82b3163efda3ba7e9240e765112caa69113694", "0e726e27047563aa0a1a9c2e085d8d26af2acba129d0869c65031e3e6cac329a", "d8b03ee579e73f16477527fc9dc37a72eaac0748a733772c483ba013944f01ef64fb4ec5e3a95021dc22f4ae282baff6e9b9cc8433c6b6710d82e7397d72ef04", 1, "wp tcId 138 TinkOverflow" },
    /* WP tcId 139 TinkOverflow: published valid, oracle valid */
    { "923a5c9e7b5635bb6c32c5a408a4a15b652450eb", "e77717b54a2b5e5bce5bccb8f0c5fdb5fd7df77ac254020fc9120dc0d4df4178", "26da61fdfd38e6d01792813f27840c8b4766b0faaed39d0ee898cb450d94a5d5f57e58b6a003d7f9b56b20561954c6edcf66492d116b8b5e91f205a3a6449d0b", 1, "wp tcId 139 TinkOverflow" },
    /* WP tcId 140 TinkOverflow: published valid, oracle valid */
    { "6f2f0245de4587062979d0422d349f93ccdc3af2", "6220972d3f7d150b36790d7d522384876d64d640cd9913186815e1629582ed36", "4adeaff7a58c5010a5a067feea0ae504d37b0c6a76c6c153e222f13409dff2df0fab69bc5059b97d925dc1b89e9851d7c627cb82d65585f9fd976124553f8902", 1, "wp tcId 140 TinkOverflow" },
    /* WP tcId 141 TinkOverflow: published valid, oracle valid */
    { "6e911edb27a170b983d4dee1110554f804330f41", "7b64a28c50ec7678a90e3e1a21522e30ac9db7b5215aea2bfb33bea037eab987", "4204d620cde0c3008c0b2901f5d6b44f88f0e3cb4f4d62252bf6f3cb37c1fb150a9ccb296afe5e7c75f65b5c8edd13dc4910ffe1e1265b3707c59042cf9a5902", 1, "wp tcId 141 TinkOverflow" },
    /* WP tcId 142 TinkOverflow: published valid, oracle valid */
    { "b8cf807eea809aaf739aa091f3b7a3f2fd39fb51", "724452210a9e4c994819229bf12bf84e95768a3a97c08d8d8f5f939a4cad34c5", "f8a69d3fd8c2ff0a9dec41e4c6b43675ce08366a35e220b1185ffc246c339e22c20ac661e866f52054015efd04f42eca2adcee6834c4df923b4a62576e4dff0e", 1, "wp tcId 142 TinkOverflow" },
    /* WP tcId 143 TinkOverflow: published valid, oracle valid */
    { "01a2b5f7fee813b4e9bd7fc25137648004795010", "bad265b294ed2f422cb6a141694086238fbfe987571aa765d8b4f3a24105aa01", "61792c9442bc6338ac41fd42a40bee9b02ec1836503d60ff725128c63d72808880c36e6190b7da525cbee5d12900aa043547dd14a2709ef9e49d628f37f6b70c", 1, "wp tcId 143 TinkOverflow" },
    /* WP tcId 144 TinkOverflow: published valid, oracle valid */
    { "0fbf5d47cb5d498feace8f98f1896208da38a885", "0aaee4b723db9b51ba7d22eb23eb8a76a5ac02f4fc9dd06f77bea42e1d37ec5a", "fa3cd41e3a8c00b19eecd404a63c3cb787cd30de0dfc936966cff2117f5aff18db6bef80fcfd8856f3fb2e9c3dc47593e9471103032af918feee638a33d40505", 1, "wp tcId 144 TinkOverflow" },
    /* WP tcId 145 TinkOverflow: published valid, oracle valid */
    { "36e67c1939750bffb3e4ba6cb85562612275e862", "812344af15a91ba83c2c91e96f1727ac0f3c4c41385b9fa84efa399ada5168be", "97fbbcd7a1d0eb42d2f8c42448ef35a2c2472740556b645547865330d6c57068af377fced08aaf810c08cd3c43d296f1975710312e9334c98b485f831efa4103", 1, "wp tcId 145 TinkOverflow" },
    /* WP tcId 146 TinkOverflow: published valid, oracle valid */
    { "13945c894c1d3fe8562e8b20e5f0efaa26ade8e3", "0ee5cb5597fbdf8dccc48b01485e39b33aa133b52d30d23740277267cfec3e3e", "d7dbaa337ffd2a5fd8d5fd8ad5aeccc0c0f83795c2c59fe62a40b87903b1ae62ed748a8df5af4d32f9f822a65d0e498b6f40eaf369a9342a1164ee7d08b58103", 1, "wp tcId 146 TinkOverflow" },
    /* WP tcId 147 TinkOverflow: published valid, oracle valid */
    { "4de142af4b8402f80a47fa812df84f42e283cee7", "9fba1de92b60b5b4703089763d0d6f9125e4dd7efae41f08a22882aef96892c4", "09a2ed303a2fa7027a1dd7c3b0d25121eeed2b644a2fbc17aa0c8aea4524071ede7e7dd7a536d5497f8165d29e4e1b63200f74bbae39fbbbccb29889c62c1f09", 1, "wp tcId 147 TinkOverflow" },
    /* WP tcId 148 TinkOverflow: published valid, oracle valid */
    { "563357f41b8b23b1d83f19f5667177a67da20b18", "7582ab1b52e1316e5c13671f43b39ca36b28133cd0832831bcddd0b0f23398cb", "e6884a6e6b2e60a0b5862251c001e7c79d581d777d6fc11d218d0aecd79f26a30e2ca22cc7c4674f8b72655bc4ee5cb5494ca07c05177656142ac55cc9d33e02", 1, "wp tcId 148 TinkOverflow" },
    /* WP tcId 149 TinkOverflow: published valid, oracle valid */
    { "931bbf9c877a6571cf7d4609fc3eb867edd43f51", "dd2d678bae222f3fb6e8278f08cc9e1a66339c926c29ac0a16f9717f5ee18cd8", "6124c206d864507ea5d984b363b4cf583314db6856a45ded5e61eebff4d5e337e0b4c82b445ae2e52d549d2d961eace2ea01f81158e09a9686baa040db65ad08", 1, "wp tcId 149 TinkOverflow" },
    /* WP tcId 150 TinkOverflow: published valid, oracle valid */
    { "44530b0b34f598767a7b875b0caee3c7b9c502d1", "ccbe7cb2e4bc215cee2f885e1d22f7e0d582b2bbbd782c104e548b152d26fc69", "cfbd450a2c83cb8436c348822fe3ee347d4ee937b7f2ea11ed755cc52852407c9eec2c1fa30d2f9aef90e89b2cc3bcef2b1b9ca59f712110d19894a9cf6a2802", 1, "wp tcId 150 TinkOverflow" },
    /* WP tcId 151 InvalidEncoding: published invalid, oracle invalid */
    { "313233343030", "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a", "0100000000000000000000000000000000000000000000000000000000000080c803ee1f2342aa96ff698a393d1ab5e66f3eda101d6d120b394c3fd32c117d0a", 0, "wp tcId 151 InvalidEncoding" },
    /* SC0 speccheck: published cof-less valid, oracle valid */
    { "8c93255d71dcab10e8f379c26200f3c7bd5f09d9bc3068d3ef4edeb4853022b6", "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa", "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a0000000000000000000000000000000000000000000000000000000000000000", 1, "SC0" },
    /* SC1 speccheck: published cof-less valid, oracle valid */
    { "9bd9f44f4dcc75bd531b56b2cd280b0bb38fc1cd6d1230e14861d861de092e79", "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa", "f7badec5b8abeaf699583992219b7b223f1df3fbbea919844e3f7c554a43dd43a5bb704786be79fc476f91d3f3f89b03984d8068dcf1bb7dfc6637b45450ac04", 1, "SC1" },
    /* SC2 speccheck: published cof-less valid, oracle valid */
    { "aebf3f2601a0c8c5d39cc7d8911642f740b78168218da8471772b35f9d35b9ab", "f7badec5b8abeaf699583992219b7b223f1df3fbbea919844e3f7c554a43dd43", "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa8c4bd45aecaca5b24fb97bc10ac27ac8751a7dfe1baff8b953ec9f5833ca260e", 1, "SC2" },
    /* SC3 speccheck: published cof-less valid, oracle valid */
    { "9bd9f44f4dcc75bd531b56b2cd280b0bb38fc1cd6d1230e14861d861de092e79", "cdb267ce40c5cd45306fa5d2f29731459387dbf9eb933b7bd5aed9a765b88d4d", "9046a64750444938de19f227bb80485e92b83fdb4b6506c160484c016cc1852f87909e14428a7a1d62e9f22f3d3ad7802db02eb2e688b6c52fcd6648a98bd009", 1, "SC3" },
    /* SC4 speccheck: published cof-less invalid, oracle invalid */
    { "e47d62c63f830dc7a6851a0b1f33ae4bb2f507fb6cffec4011eaccd55b53f56c", "cdb267ce40c5cd45306fa5d2f29731459387dbf9eb933b7bd5aed9a765b88d4d", "160a1cb0dc9c0258cd0a7d23e94d8fa878bcb1925f2c64246b2dee1796bed5125ec6bc982a269b723e0668e540911a9a6a58921d6925e434ab10aa7940551a09", 0, "SC4" },
    /* SC5 speccheck: published cof-less invalid, oracle invalid */
    { "e47d62c63f830dc7a6851a0b1f33ae4bb2f507fb6cffec4011eaccd55b53f56c", "cdb267ce40c5cd45306fa5d2f29731459387dbf9eb933b7bd5aed9a765b88d4d", "21122a84e0b5fca4052f5b1235c80a537878b38f3142356b2c2384ebad4668b7e40bc836dac0f71076f9abe3a53f9c03c1ceeeddb658d0030494ace586687405", 0, "SC5" },
    /* SC6 speccheck: published cof-less valid, oracle invalid */
    { "85e241a07d148b41e47d62c63f830dc7a6851a0b1f33ae4bb2f507fb6cffec40", "442aad9f089ad9e14647b1ef9099a1ff4798d78589e66f28eca69c11f582a623", "e96f66be976d82e60150baecff9906684aebb1ef181f67a7189ac78ea23b6c0e547f7690a0e2ddcd04d87dbc3490dc19b3b3052f7ff0538cb68afb369ba3a514", 1, "SC6" },
    /* SC7 speccheck: published cof-less valid, oracle invalid */
    { "85e241a07d148b41e47d62c63f830dc7a6851a0b1f33ae4bb2f507fb6cffec40", "442aad9f089ad9e14647b1ef9099a1ff4798d78589e66f28eca69c11f582a623", "8ce5b96c8f26d0ab6c47958c9e68b937104cd36e13c33566acd2fe8d38aa19427e71f98a473474f2f13f06f97c20d58cc3f54b8bd0d272f42b695dd7e89a8c22", 1, "SC7" },
    /* SC8 speccheck: published cof-less valid, oracle invalid */
    { "9bedc267423725d473888631ebf45988bad3db83851ee85c85e241a07d148b41", "f7badec5b8abeaf699583992219b7b223f1df3fbbea919844e3f7c554a43dd43", "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff03be9678ac102edcd92b0210bb34d7428d12ffc5df5f37e359941266a4e35f0f", 1, "SC8" },
    /* SC9 speccheck: published cof-less valid, oracle invalid */
    { "9bedc267423725d473888631ebf45988bad3db83851ee85c85e241a07d148b41", "f7badec5b8abeaf699583992219b7b223f1df3fbbea919844e3f7c554a43dd43", "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffca8c5b64cd208982aa38d4936621a4775aa233aa0505711d8fdcfdaa943d4908", 1, "SC9" },
    /* SC10 speccheck: published cof-less valid, oracle invalid */
    { "e96b7021eb39c1a163b6da4e3093dcd3f21387da4cc4572be588fafae23c155b", "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", "a9d55260f765261eb9b84e106f665e00b867287a761990d7135963ee0a7d59dca5bb704786be79fc476f91d3f3f89b03984d8068dcf1bb7dfc6637b45450ac04", 1, "SC10" },
    /* SC11 speccheck: published cof-less valid, oracle valid */
    { "39a591f5321bbe07fd5a23dc2f39d025d74526615746727ceefd6e82ae65c06f", "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", "a9d55260f765261eb9b84e106f665e00b867287a761990d7135963ee0a7d59dca5bb704786be79fc476f91d3f3f89b03984d8068dcf1bb7dfc6637b45450ac04", 1, "SC11" },
};

/* Decodes an even-length hex string into out (at most out_max bytes). */
static int corpus_decode(const char *hex, uint8_t *out, size_t out_max,
                         size_t *out_len)
{
    size_t n = strlen(hex);
    if (n % 2 != 0 || n / 2 > out_max) return -1;
    *out_len = n / 2;
    test_hex_to_bytes(hex, out, (int)*out_len);
    return 0;
}

/* One row: the oracle and the shipped verifier must agree. Returns the
 * failure count for this row. */
static int corpus_check_one(const struct ed_corpus_vec *v)
{
    uint8_t msg[ED_CORPUS_MSG_MAX], pk[32], sig[64];
    size_t mlen = 0;
    if (strlen(v->pk_hex) != 64 || strlen(v->sig_hex) != 128 ||
        corpus_decode(v->msg_hex, msg, sizeof msg, &mlen) != 0) {
        printf("FAIL (corpus row %s is malformed)\n", v->id);
        return 1;
    }
    test_hex_to_bytes(v->pk_hex, pk, 32);
    test_hex_to_bytes(v->sig_hex, sig, 64);
    bool got = ed25519_verify(sig, msg, mlen, pk);
    bool want = ref_ed25519_verify(sig, msg, mlen, pk);
    if (got != want) {
        printf("FAIL (%s: shipped=%d reference=%d)\n", v->id, got, want);
        return 1;
    }
    g_agreements++;
    if (want != (v->published_valid != 0)) {
        printf("  note %s: oracle=%d published=%d (information, not a failure)\n",
               v->id, want, v->published_valid);
        g_published_diffs++;
    }
    return 0;
}

static int corpus_run_all(void)
{
    int failures = 0;
    for (size_t i = 0; i < sizeof(ED_CORPUS) / sizeof(ED_CORPUS[0]); i++)
        failures += corpus_check_one(&ED_CORPUS[i]);
    return failures;
}

static void corpus_section(void)
{
    int before = g_failures;
    printf("speccheck + Wycheproof rows agree with the oracle (%zu rows)... ",
           sizeof(ED_CORPUS) / sizeof(ED_CORPUS[0]));
    g_failures += corpus_run_all();
    printf("%s\n", g_failures > before ? "FAIL" : "OK");
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
        /* ── malleability, stated absolutely and not differentially ─────
         * (R, S) and (R, S+L) satisfy the same group equation; RFC 8032
         * §5.1.7 and the Zcash consensus rules forbid the second. This
         * cannot be differential: the frozen reference has its own
         * canonical-S check, and S == L fails the point equation on its own.
         * So the honest signature must ACCEPT and its +L malleation must
         * REJECT, both against the shipped verifier directly. */
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

    /* ── 6. Published corpora ────────────────────────────────────── */
    g_published_diffs = 0;
    corpus_section();
    printf("published-vs-oracle notes: %u (information only)\n", g_published_diffs);

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
