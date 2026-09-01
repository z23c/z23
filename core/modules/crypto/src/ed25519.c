/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Ed25519 signatures (verify + keypair + sign) — pure C23 implementation.
 * Twisted Edwards curve: -x^2 + y^2 = 1 + d*x^2*y^2
 * Field: GF(2^255-19), TweetNaCl-style 16-limb representation.
 *
 * ── Constant-time audit ────────────────────────────────────
 *
 * Verify path: all inputs to ed25519_verify are public — signature,
 * message, public key — so the threat model that makes Curve25519 DH and
 * jub_scalar_mul timing-critical does not apply there. The CT properties
 * below are belt-and-suspenders for verify and load-bearing for sign.
 *
 * Sign path (added for off-chain identity documents, contexts/wallet/modules/zid — consensus
 * paths only need verify; JoinSplit/Sapling signing happens via
 * RedJubjub in core/modules/sapling): the secret scalar and nonce stay out of
 * timing by construction:
 *   - clamp is branch-free byte masking (& 248, & 127, | 64)
 *   - the nonce r and scalar a are hashed/reduced through the same
 *     fixed-loop reduce/modL as verify — no secret-dependent branches
 *   - the [r]B / [a]B multiplications use the same cswap-driven ladder
 *     as verify: every iteration runs the full point_add + point_add
 *     sequence with sel25519 mask swaps, no conditional adds keyed on
 *     secret bits, no table lookups
 *
 * Properties confirmed:
 *   - sel25519: branchless mask cswap (same as curve25519.c)
 *   - scalarmult: cswap-driven Montgomery-like ladder; every iteration
 *     runs the full point_add(q,p) + point_add(p,p) sequence, no
 *     conditional adds keyed on bits
 *   - Final compare: `diff |= t[i] ^ sig[i]` (XOR-OR accumulator), NOT
 *     a memcmp early-exit
 * - S<L canonical-S check: byte-walked accumulator with mask
 *     selection; rejects malleable signatures pre-scalarmult
 *
 * Branches on data (verify only; acceptable, public values only):
 *   - unpackneg: `if (neq25519(chk, num)) ...` — operates on the
 *     decompressed public key; leak is OK (pubkey is public)
 *   - LOG_FAIL early-returns: branches on verify outcomes (a public
 *     signature is either valid or not — observable from the result) */

#include "crypto/ed25519.h"
#include "crypto/random_secret.h"
#include "crypto/sha512.h"
#include "support/cleanse.h"
#include "util/log_macros.h"
#include "util/safe_alloc.h"
#include <stdlib.h>
#include <string.h>

typedef int64_t gf[16];

static const gf gf0 = {0};
static const gf gf1 = {1};

static const gf D = {
    0x78a3, 0x1359, 0x4dca, 0x75eb,
    0xd8ab, 0x4141, 0x0a4d, 0x0070,
    0xe898, 0x7779, 0x4079, 0x8cc7,
    0xfe73, 0x2b6f, 0x6cee, 0x5203
};

static const gf D2 = {
    0xf159, 0x26b2, 0x9b94, 0xebd6,
    0xb156, 0x8283, 0x149a, 0x00e0,
    0xd130, 0xeef3, 0x80f2, 0x198e,
    0xfce7, 0x56df, 0xd9dc, 0x2406
};

static const gf I = {
    0xa0b0, 0x4a0e, 0x1b27, 0xc4ee,
    0xe478, 0xad2f, 0x1806, 0x2f43,
    0xd7a7, 0x3dfb, 0x0099, 0x2b4d,
    0xdf0b, 0x4fc1, 0x2480, 0x2b83
};

static const uint8_t BASE_POINT[32] = {
    0x58, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
    0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
    0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
    0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66
};

static void car25519(gf o)
{
    for (int i = 0; i < 16; i++) {
        o[i] += (1LL << 16);
        int64_t c = o[i] >> 16;
        o[(i + 1) * (i < 15)] += c - 1 + 37 * (c - 1) * (i == 15);
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
        m[0] = t[0] - 0xffed;
        for (int i = 1; i < 15; i++) {
            m[i] = t[i] - 0xffff - ((m[i - 1] >> 16) & 1);
            m[i - 1] &= 0xffff;
        }
        m[15] = t[15] - 0x7fff - ((m[14] >> 16) & 1);
        int64_t b = (m[15] >> 16) & 1;
        m[14] &= 0xffff;
        sel25519(t, m, (int)(1 - b));
    }
    for (int i = 0; i < 16; i++) {
        o[2 * i] = (uint8_t)(t[i] & 0xff);
        o[2 * i + 1] = (uint8_t)(t[i] >> 8);
    }
}

static void unpack25519(gf o, const uint8_t n[32])
{
    for (int i = 0; i < 16; i++)
        o[i] = n[2 * i] + ((int64_t)n[2 * i + 1] << 8);
    o[15] &= 0x7fff; /* mask sign bit (bit 255) */
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
    for (int i = 0; i < 15; i++)
        t[i] += 38 * t[i + 16];
    memcpy(o, t, sizeof(gf));
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

static void pow2523(gf o, const gf a)
{
    gf c;
    memcpy(c, a, sizeof(gf));
    for (int i = 250; i >= 0; i--) {
        S(c, c);
        if (i != 1) M(c, c, a);
    }
    memcpy(o, c, sizeof(gf));
}

static int par25519(const gf a)
{
    uint8_t d[32];
    pack25519(d, a);
    return d[0] & 1;
}

static int neq25519(const gf a, const gf b)
{
    uint8_t c[32], d[32];
    pack25519(c, a);
    pack25519(d, b);
    int v = 0;
    for (int i = 0; i < 32; i++) v |= c[i] ^ d[i];
    return v != 0;
}

/* Extended coordinates: (X, Y, Z, T) where x=X/Z, y=Y/Z, T=X*Y/Z */
typedef gf gep[4];

static void set_identity(gep p)
{
    memset(p[0], 0, sizeof(gf));
    memcpy(p[1], gf1, sizeof(gf));
    memcpy(p[2], gf1, sizeof(gf));
    memset(p[3], 0, sizeof(gf));
}

static void point_add(gep p, const gep q)
{
    gf a, b, c, d, e, f, g, h, t;
    Z(a, p[1], p[0]);
    Z(t, q[1], q[0]);
    M(a, a, t);
    A(b, p[0], p[1]);
    A(t, q[0], q[1]);
    M(b, b, t);
    M(c, p[3], q[3]);
    M(c, c, D2);
    M(d, p[2], q[2]);
    A(d, d, d);
    Z(e, b, a);
    Z(f, d, c);
    A(g, d, c);
    A(h, b, a);
    M(p[0], e, f);
    M(p[1], h, g);
    M(p[2], g, f);
    M(p[3], e, h);
}

static void cswap(gep p, gep q, int b)
{
    for (int i = 0; i < 4; i++)
        sel25519(p[i], q[i], b);
}

static void pack_point(uint8_t r[32], const gep p)
{
    gf tx, ty, zi;
    inv25519(zi, p[2]);
    M(tx, p[0], zi);
    M(ty, p[1], zi);
    pack25519(r, ty);
    r[31] ^= (uint8_t)(par25519(tx) << 7);
}

static int unpackneg(gep r, const uint8_t p[32])
{
    gf t, chk, num, den, den2, den4, den6;
    set_identity(r);
    unpack25519(r[1], p);
    S(num, r[1]);
    M(den, num, D);
    Z(num, num, r[2]);
    A(den, r[2], den);

    S(den2, den);
    S(den4, den2);
    M(den6, den4, den2);
    M(t, den6, num);
    M(t, t, den);

    pow2523(t, t);
    M(t, t, num);
    M(t, t, den);
    M(t, t, den);
    M(r[0], t, den);

    S(chk, r[0]);
    M(chk, chk, den);
    if (neq25519(chk, num)) M(r[0], r[0], I);

    S(chk, r[0]);
    M(chk, chk, den);
    if (neq25519(chk, num)) return -1;

    if (par25519(r[0]) == (p[31] >> 7))
        Z(r[0], gf0, r[0]);

    M(r[3], r[0], r[1]);
    return 0;
}

static void scalarmult(gep p, gep q, const uint8_t s[32])
{
    set_identity(p);
    for (int i = 255; i >= 0; i--) {
        int b = (s[i / 8] >> (i & 7)) & 1;
        cswap(p, q, b);
        point_add(q, p);
        point_add(p, p);
        cswap(p, q, b);
    }
}

static const uint64_t L[32] = {
    0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58,
    0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
    0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0x10
};

static void modL(uint8_t r[32], int64_t x[64])
{
    for (int i = 63; i >= 32; i--) {
        int64_t carry = 0;
        int j;
        for (j = i - 32; j < i - 12; j++) {
            x[j] += carry - 16 * x[i] * (int64_t)L[j - (i - 32)];
            carry = (x[j] + 128) >> 8;
            x[j] -= carry * (1LL << 8);
        }
        x[j] += carry;
        x[i] = 0;
    }
    int64_t carry = 0;
    for (int j = 0; j < 32; j++) {
        x[j] += carry - (x[31] >> 4) * (int64_t)L[j];
        carry = x[j] >> 8;
        x[j] &= 255;
    }
    for (int j = 0; j < 32; j++)
        x[j] -= carry * (int64_t)L[j];
    for (int i = 0; i < 32; i++) {
        x[i + 1] += x[i] >> 8;
        r[i] = (uint8_t)(x[i] & 255);
    }
}

static void reduce(uint8_t r[64])
{
    int64_t x[64];
    for (int i = 0; i < 64; i++) x[i] = (int64_t)(uint64_t)r[i];
    memset(r, 0, 64);
    modL(r, x);
}

/* Constant-time check that S (sig[32..63], 32 LE bytes) is canonical:
 *   S < L, where L is the Ed25519 group order. Required by RFC 8032
 *   §5.1.7 and by Zcash consensus (malleable S-values split consensus
 *   from zcashd). Compare from most-significant byte down; accumulate
 *   "less-than" only on bytes where all higher bytes are still equal. */
static bool ed25519_S_is_canonical(const uint8_t S[32])
{
    uint32_t lt = 0;
    uint32_t eq = 1;
    for (int i = 31; i >= 0; i--) {
        uint32_t sb = S[i];
        uint32_t lb = (uint32_t)L[i]; /* L[i] fits in one byte */
        /* sb < lb  iff  (sb - lb) underflows to a value with bit 31 set */
        uint32_t is_lt = ((sb - lb) >> 31) & 1u;
        /* sb == lb iff  (sb ^ lb) == 0 */
        uint32_t is_eq = (((sb ^ lb) - 1u) >> 31) & 1u;
        lt |= eq & is_lt;
        eq &= is_eq;
    }
    (void)eq;
    return lt != 0u;
}

/* out = [s1]P1 + [s2]P2 — fixed-window Straus, defined with the rest of the
 * windowed multi-scalar machinery further down this file. Used ONLY by
 * `ed25519_verify`, whose every input is public. */
static void point_mul_double(gep out, const gep p1, const uint8_t s1[32],
                             const gep p2, const uint8_t s2[32]);

bool ed25519_verify(const uint8_t sig[64],
                    const uint8_t *msg, size_t msg_len,
                    const uint8_t pk[32])
{
    gep q;

    /* Reject the identity point (all-zero pubkey) */
    {
        uint8_t zero[32] = {0};
        if (memcmp(pk, zero, 32) == 0)
            LOG_FAIL("ed25519", "pk is identity (all zero)");
    }

    /* Canonical-S check (RFC 8032 §5.1.7, Zcash consensus). Must happen
     * BEFORE the scalar mul so malleable signatures are rejected even if
     * the decompression/point math would otherwise accept them. */
    if (!ed25519_S_is_canonical(sig + 32))
        LOG_FAIL("ed25519", "S >= L (non-canonical signature scalar)");

    /* Decompress -A from public key */
    if (unpackneg(q, pk) != 0)
        LOG_FAIL("ed25519", "pubkey decompression (unpackneg) failed");

    /* h = SHA-512(R || pk || msg) mod L */
    uint8_t h[64];
    struct sha512_ctx hs;
    sha512_init(&hs);
    sha512_write(&hs, sig, 32);
    sha512_write(&hs, pk, 32);
    sha512_write(&hs, msg, msg_len);
    sha512_finalize(&hs, h);
    reduce(h);

    /* Compute [S]B + [h](-A) and check == R.
     *
     * One interleaved Straus multiplication, NOT two separate ladders: the
     * 256 doublings are shared between the two terms, which is where the
     * speed comes from. Every operand here is public (the signature, the
     * public key, and a hash of them plus the message), so the windowed
     * path's data-dependent table indexing leaks nothing. Secret scalars —
     * key derivation and signing — keep the constant-time `scalarmult`
     * ladder and are deliberately NOT routed through here. */
    gep sb;
    {
        gep bp;
        if (unpackneg(bp, BASE_POINT) != 0)
            LOG_FAIL("ed25519", "base point decompression failed");
        Z(bp[0], gf0, bp[0]);
        Z(bp[3], gf0, bp[3]);
        point_mul_double(sb, bp, sig + 32, q, h);
    }

    uint8_t t[32];
    pack_point(t, sb);

    int diff = 0;
    for (int i = 0; i < 32; i++)
        diff |= t[i] ^ sig[i];

    if (diff != 0)
        LOG_FAIL("ed25519",
                 "signature verify: [S]B - [h]A != R (signature mismatch, msg_len=%zu)",
                 msg_len);
    return true;
}

/* Decompress the standard base point B (BASE_POINT encodes y=4/5 with
 * positive-x parity; unpackneg returns the x-negated form, so negate X
 * and T back). Cannot fail for this constant. */
static void base_point(gep bp)
{
    /* unpackneg only fails on a non-canonical/non-curve encoding;
     * BASE_POINT is a compile-time constant known to decompress. */
    if (unpackneg(bp, BASE_POINT) != 0)
        set_identity(bp); /* unreachable; keeps bp defined */
    Z(bp[0], gf0, bp[0]);
    Z(bp[3], gf0, bp[3]);
}

/* RFC 8032 §5.1.5 clamp of the low half of SHA-512(seed). Branch-free. */
static void clamp_scalar(uint8_t a[32])
{
    a[0] &= 248;
    a[31] &= 127;
    a[31] |= 64;
}

void zcl_ed25519_keypair(uint8_t pk[32], uint8_t sk[32], const uint8_t seed[32])
{
    uint8_t h[64];
    struct sha512_ctx hs;
    sha512_init(&hs);
    sha512_write(&hs, seed, 32);
    sha512_finalize(&hs, h);

    uint8_t a[32];
    memcpy(a, h, 32);
    clamp_scalar(a);

    gep bp, p;
    base_point(bp);
    scalarmult(p, bp, a);
    pack_point(pk, p);

    memcpy(sk, seed, 32); /* the RFC 8032 secret key IS the seed */

    /* h holds the expanded secret (scalar half + nonce prefix); a is the
     * clamped scalar. Neither may be left on the stack. */
    memory_cleanse(h, sizeof(h));
    memory_cleanse(a, sizeof(a));
}

void zcl_ed25519_sign(uint8_t sig[64], const uint8_t *msg, size_t msg_len,
                      const uint8_t sk[32], const uint8_t pk[32])
{
    uint8_t h[64];
    struct sha512_ctx hs;
    sha512_init(&hs);
    sha512_write(&hs, sk, 32);
    sha512_finalize(&hs, h);

    uint8_t a[32];
    memcpy(a, h, 32);
    clamp_scalar(a);
    const uint8_t *prefix = h + 32;

    /* r = SHA-512(prefix || M) mod L */
    uint8_t r[64];
    sha512_init(&hs);
    sha512_write(&hs, prefix, 32);
    sha512_write(&hs, msg, msg_len);
    sha512_finalize(&hs, r);
    reduce(r);

    /* R = [r]B */
    gep bp, rp;
    base_point(bp);
    scalarmult(rp, bp, r);
    pack_point(sig, rp);

    /* k = SHA-512(R || pk || M) mod L */
    uint8_t k[64];
    sha512_init(&hs);
    sha512_write(&hs, sig, 32);
    sha512_write(&hs, pk, 32);
    sha512_write(&hs, msg, msg_len);
    sha512_finalize(&hs, k);
    reduce(k);

    /* S = (r + k*a) mod L */
    int64_t x[64] = {0};
    for (int i = 0; i < 32; i++)
        x[i] = (int64_t)(uint64_t)r[i];
    for (int i = 0; i < 32; i++)
        for (int j = 0; j < 32; j++)
            x[i + j] += (int64_t)(uint64_t)k[i] * (int64_t)(uint64_t)a[j];
    modL(sig + 32, x);

    /* h = expanded secret (scalar + nonce prefix), a = clamped scalar,
     * r = secret nonce, x = r + k*a intermediate. All secret: cleanse.
     * (k is a hash of public values; cleansed anyway, costs nothing.) */
    memory_cleanse(h, sizeof(h));
    memory_cleanse(a, sizeof(a));
    memory_cleanse(r, sizeof(r));
    memory_cleanse(k, sizeof(k));
    memory_cleanse(x, sizeof(x));
}

/* ══ Batch verification ═══════════════════════════════════════════════
 *
 * `ed25519_verify_batch` returns exactly
 *     ed25519_verify(0) && ed25519_verify(1) && ... && ed25519_verify(n-1)
 * for EVERY input, adversarial included. It is not "usually the same":
 * every way the two paths could disagree is closed below, and the one
 * remaining probabilistic step is one-sided (it can only reject a set the
 * per-signature path also rejects, with error probability <= 2^-128 that a
 * BAD set is accepted, and probability EXACTLY 0 that a good set is
 * rejected).
 *
 * ── Why a naive batch is unsound here ─────────────────────────────
 *
 * The textbook batch equation is: draw independent random 128-bit z_i and
 * check  sum_i z_i * e_i == O,  where the per-signature "error point" is
 *     e_i = R_i + [h_i]A_i - [S_i]B.
 * `ed25519_verify` above is COFACTORLESS: it accepts iff e_i == O exactly
 * (it packs [S]B - [h]A and byte-compares against R). The Ed25519 group is
 * Z/8L — a prime-order part of order L and an 8-torsion part. Write
 * e_i = f_i + tau(e_i)*P8 with f_i in the prime-order subgroup and
 * tau(e_i) in Z/8.
 *
 *   - The prime-order part IS protected by the random z_i: a nonzero f_j
 *     survives sum_i z_i f_i except with probability <= 2^-128.
 *   - The 8-torsion part is NOT. tau is a group homomorphism onto Z/8, so
 *     the torsion of the sum is (sum_i z_i tau(e_i)) mod 8 — a value in a
 *     set of size 8. An attacker who publishes A' = A + T (T of order 2)
 *     and signs honestly produces e = [h]T != O, i.e. a signature that
 *     `ed25519_verify` REJECTS, yet z*e == O whenever z is even: the naive
 *     batch would accept it half the time. That is a critical divergence,
 *     not a rounding error, and it is why the well-known batch
 *     constructions are paired with COFACTORED single verification.
 *
 * ── How this implementation closes it ─────────────────────────────
 *
 * 1. Every cheap per-signature predicate `ed25519_verify` applies is
 *    applied here first, with identical semantics: all-zero public key,
 *    S < L, public-key decompression, R decompression, and R's encoding
 *    being CANONICAL (`ed25519_verify` byte-compares a freshly packed
 *    point against sig[0..31], so a non-canonical y >= p or a sign bit
 *    that disagrees with the recovered x can never match — see
 *    `enc_is_canonical`). Any failure is a per-signature verdict of
 *    false, so the batch verdict is false.
 *
 * 2. TORSION SCREEN, per signature, exact and deterministic. Since
 *    tau(B) = 0,
 *        tau(e_i) = tau(R_i) + (h_i mod 8) * tau(A_i) = tau(W_i),
 *        W_i := R_i + [h_i mod 8]A_i.
 *    [L]W_i = [(L mod 8) * tau(W_i)]P8 = [5*tau(W_i)]P8, and 5 is a unit
 *    mod 8, so  [L]W_i == O  <=>  tau(e_i) == 0. If the screen fails then
 *    e_i != O, so `ed25519_verify(i)` is false and the batch answer is
 *    false — reported immediately, no probabilistic step involved.
 *    Cost is one 253-bit variable-base multiply per signature (~1/4 of a
 *    single verification), and it buys unconditional agreement.
 *
 *    The screen is not belt-and-braces, it is load-bearing: step 3 below
 *    clears the cofactor, and [8] annihilates the 8-torsion outright, so
 *    without the screen this construction would accept an A = A' + T
 *    forgery not half the time but ALWAYS. Measured on this code with
 *    the screen disabled: 16/16 accepted (see the 8-torsion case in
 *    tests/harness/src/test_zid.c).
 *
 * 3. With every tau(e_i) == 0, every e_i lies in the prime-order
 *    subgroup, so the torsion channel of the batch equation is provably
 *    empty and multiplication by the cofactor is injective on the sum.
 *    The batch is therefore evaluated in cofactor-cleared form:
 *        [8](sum_i z_i e_i)
 *          = sum_i z_i([8]R_i) + sum_i [z_i h_i mod L]([8]A_i)
 *            - [sum_i z_i S_i mod L]([8]B)
 *    Clearing the cofactor on each input point first is what makes the
 *    mod-L scalar reductions exact (scalars act mod L only on
 *    torsion-free points); it costs 3 doublings per point. The result is
 *    O iff sum_i z_i e_i is O.
 *
 * Result: false accept <= 2^-128 (one uniform 128-bit z_j must hit a
 * single root), false reject impossible.
 *
 * ── Randomness ───────────────────────────────────────────────────
 *
 * z_i comes from `zcl_random_secret_bytes` (the project CSPRNG wrapper
 * over core/random.GetRandBytes, which rejects the all-zero /dev/urandom
 * failure mode). Predictable z_i is a forgery oracle, so there is no
 * fallback RNG: if the CSPRNG refuses, the batch degrades to n
 * independent `ed25519_verify` calls, which need no randomness and give
 * the same answer.
 *
 * ── Portability ──────────────────────────────────────────────────
 *
 * Scalar C23 only — same gf/point_add primitives as the single path, no
 * intrinsics, no runtime CPU dispatch, so there is exactly one code path
 * on every target and the tests exercise it everywhere. */

/* p = 2^255 - 19, little-endian. */
static const uint8_t FIELD_P_LE[32] = {
    0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f
};

/* L = 2^252 + 27742317777372353535851937790883648493, little-endian —
 * the byte-array twin of `L[32]` above (same values, usable as a scalar). */
static const uint8_t L_LE[32] = {
    0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58,
    0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10
};

/* Straus/Shamir interleaved multi-scalar multiplication parameters.
 * MX_W-bit fixed windows, MX_WINDOWS * MX_W = 256 bits covers every
 * scalar used here (all are < L < 2^253). Signatures are processed in
 * chunks so the precomputed-table working set stays bounded (~512 KiB)
 * regardless of n; the 256 shared doublings amortise over 64 points. */
#define MX_W 4
#define MX_WINDOWS 64
#define MX_CHUNK_SIGS 32
#define MX_CHUNK_POINTS (2 * MX_CHUNK_SIGS)

struct ed_batch_ws {
    gep tab[MX_CHUNK_POINTS][1 << MX_W];
    uint8_t scal[MX_CHUNK_POINTS][32];
};

static void point_negate(gep p)
{
    Z(p[0], gf0, p[0]);
    Z(p[3], gf0, p[3]);
}

/* Projective identity test: x == 0 and y == 1, i.e. X == 0 and Y == Z. */
static bool point_is_identity(const gep p)
{
    uint8_t x[32];
    pack25519(x, p[0]);
    int nz = 0;
    for (int i = 0; i < 32; i++) nz |= x[i];
    return nz == 0 && neq25519(p[1], p[2]) == 0;
}

/* Decompress a compressed Edwards point. `unpackneg` yields -P, so negate
 * back. On success `out` is affine (Z == 1). Returns false when `enc` is
 * not a point encoding — the same condition that makes `ed25519_verify`
 * reject (a public key that fails to decompress, or an R that no packed
 * point can equal). */
static bool point_decode(gep out, const uint8_t enc[32])
{
    if (unpackneg(out, enc) != 0)
        return false; /* raw-return-ok: predicate, caller logs with context */
    point_negate(out);
    return true;
}

/* Is `enc` the CANONICAL encoding of the decoded point `p` (Z == 1)?
 *
 * `ed25519_verify` compares `pack_point([S]B - [h]A)` byte-for-byte with
 * sig[0..31]. `pack_point` always emits the canonical form, so a signature
 * whose R is encoded non-canonically can never verify, even if the group
 * equation holds. Two ways to be non-canonical: y >= p (the top bit is the
 * sign bit and is masked off, so y is read mod nothing and re-packing
 * reduces it), and a sign bit that disagrees with the parity of the
 * recovered x — reachable only at x == 0, where decompression cannot honour
 * a set sign bit. */
static bool enc_is_canonical(const uint8_t enc[32], const gep p)
{
    uint8_t y[32];
    memcpy(y, enc, 32);
    y[31] &= 0x7fu;

    bool y_lt_p = false;
    for (int i = 31; i >= 0; i--) {
        if (y[i] != FIELD_P_LE[i]) {
            y_lt_p = y[i] < FIELD_P_LE[i];
            break;
        }
    }
    if (!y_lt_p)
        return false; /* raw-return-ok: predicate, caller logs with context */

    return par25519(p[0]) == (enc[31] >> 7);
}

/* Table of small multiples [0]P .. [2^MX_W - 1]P. */
static void mx_build_table(gep tab[1 << MX_W], const gep p)
{
    set_identity(tab[0]);
    memcpy(tab[1], p, sizeof(gep));
    for (int i = 2; i < (1 << MX_W); i++) {
        memcpy(tab[i], tab[i - 1], sizeof(gep));
        point_add(tab[i], p);
    }
}

static unsigned mx_digit(const uint8_t s[32], int window)
{
    int bit = window * MX_W;
    return (unsigned)((s[bit >> 3] >> (bit & 7)) & ((1u << MX_W) - 1u));
}

/* out = [s]base, fixed-window left-to-right. `s` is a 32-byte little-endian
 * scalar; all callers pass values < 2^253. Every input here is public
 * (public keys, signatures, hash outputs, batch randomisers that are
 * discarded before returning), so window-index branching is not a leak. */
static void point_mul_scalar(gep out, const gep base, const uint8_t s[32])
{
    gep tab[1 << MX_W];
    mx_build_table(tab, base);
    set_identity(out);
    for (int w = MX_WINDOWS - 1; w >= 0; w--) {
        for (int k = 0; k < MX_W; k++)
            point_add(out, out);
        unsigned d = mx_digit(s, w);
        if (d != 0u)
            point_add(out, tab[d]);
    }
}

/* out = [s1]P1 + [s2]P2, the two-term case of the same Straus interleaving
 * `mx_accumulate` does for a whole batch: build a small-multiples table per
 * point, then walk the windows sharing every doubling between the terms.
 *
 * This is the single-signature verify equation. Doing it as two independent
 * scalar multiplications costs 2 x 256 ladder steps; sharing the doublings
 * costs 256 doublings plus at most two table adds per window, which is why
 * `ed25519_verify` calls this instead of `scalarmult` twice.
 *
 * The two tables are 2 * 16 * sizeof(gep) = 16 KiB of stack — small enough
 * to keep here, unlike the batch path's workspace, which scales with n and
 * therefore has to be heap-allocated.
 *
 * Callers must pass PUBLIC scalars only (see the note in `point_mul_scalar`
 * — window indices are branched on). `ed25519_verify` is the only caller. */
static void point_mul_double(gep out, const gep p1, const uint8_t s1[32],
                             const gep p2, const uint8_t s2[32])
{
    gep t1[1 << MX_W], t2[1 << MX_W];
    mx_build_table(t1, p1);
    mx_build_table(t2, p2);

    set_identity(out);
    for (int w = MX_WINDOWS - 1; w >= 0; w--) {
        for (int k = 0; k < MX_W; k++)
            point_add(out, out);
        unsigned d1 = mx_digit(s1, w);
        if (d1 != 0u)
            point_add(out, t1[d1]);
        unsigned d2 = mx_digit(s2, w);
        if (d2 != 0u)
            point_add(out, t2[d2]);
    }
}

/* acc += sum_j [scal[j]]P_j over the `m` points whose tables are already
 * built in `ws`. Doublings are shared across the whole chunk — this is the
 * only reason a batch beats n separate ladders. */
static void mx_accumulate(gep acc, const struct ed_batch_ws *ws, size_t m)
{
    gep sum;
    set_identity(sum);
    for (int w = MX_WINDOWS - 1; w >= 0; w--) {
        for (int k = 0; k < MX_W; k++)
            point_add(sum, sum);
        for (size_t j = 0; j < m; j++) {
            unsigned d = mx_digit(ws->scal[j], w);
            if (d != 0u)
                point_add(sum, ws->tab[j][d]);
        }
    }
    point_add(acc, sum);
}

/* r = (a * b) mod L, both little-endian 32-byte scalars. */
static void scalar_mul_reduce(uint8_t r[32], const uint8_t a[32],
                              const uint8_t b[32])
{
    int64_t x[64] = {0};
    for (int i = 0; i < 32; i++)
        for (int j = 0; j < 32; j++)
            x[i + j] += (int64_t)(uint64_t)a[i] * (int64_t)(uint64_t)b[j];
    modL(r, x);
}

/* r = (a + b) mod L. */
static void scalar_add_reduce(uint8_t r[32], const uint8_t a[32],
                              const uint8_t b[32])
{
    int64_t x[64] = {0};
    for (int i = 0; i < 32; i++)
        x[i] = (int64_t)(uint64_t)a[i] + (int64_t)(uint64_t)b[i];
    modL(r, x);
}

/* The deterministic reference verdict: n independent `ed25519_verify`
 * calls. Used when the CSPRNG refuses to produce batch randomisers. */
static bool ed_batch_serial(const uint8_t *const *msgs, const size_t *msg_lens,
                            const uint8_t *const *sigs,
                            const uint8_t *const *pubkeys, size_t n)
{
    for (size_t i = 0; i < n; i++) {
        if (!ed25519_verify(sigs[i], msgs[i], msg_lens[i], pubkeys[i]))
            return false; /* raw-return-ok: per-signature verdict, callee logged */
    }
    return true;
}

/* Steps 1-3 of the header comment. `*rng_failed` is set when the CSPRNG
 * refused, which is not a verdict — the caller then answers serially. */
static bool ed_batch_core(const uint8_t *const *msgs, const size_t *msg_lens,
                          const uint8_t *const *sigs,
                          const uint8_t *const *pubkeys, size_t n,
                          struct ed_batch_ws *ws, bool *rng_failed)
{
    gep total;
    set_identity(total);
    uint8_t sigma[32] = {0};
    uint8_t zbuf[MX_CHUNK_SIGS * 16];

    for (size_t base = 0; base < n; base += MX_CHUNK_SIGS) {
        size_t cnt = n - base;
        if (cnt > MX_CHUNK_SIGS) cnt = MX_CHUNK_SIGS;

        if (!zcl_random_secret_bytes(zbuf, cnt * 16, "ed25519_batch_z")) {
            *rng_failed = true;
            memory_cleanse(zbuf, sizeof(zbuf));
            return false; /* raw-return-ok: not a verdict; rng_failed reroutes */
        }

        size_t np = 0;
        for (size_t k = 0; k < cnt; k++) {
            size_t i = base + k;
            const uint8_t *sig = sigs[i];
            const uint8_t *pk = pubkeys[i];

            /* (1) The per-signature predicates, identical to ed25519_verify. */
            {
                uint8_t zero[32] = {0};
                if (memcmp(pk, zero, 32) == 0) {
                    memory_cleanse(zbuf, sizeof(zbuf));
                    LOG_FAIL("ed25519",
                             "batch[%zu]: pk is identity (all zero)", i);
                }
            }
            if (!ed25519_S_is_canonical(sig + 32)) {
                memory_cleanse(zbuf, sizeof(zbuf));
                LOG_FAIL("ed25519",
                         "batch[%zu]: S >= L (non-canonical signature scalar)", i);
            }

            gep ap, rp;
            if (!point_decode(ap, pk)) {
                memory_cleanse(zbuf, sizeof(zbuf));
                LOG_FAIL("ed25519",
                         "batch[%zu]: pubkey decompression failed", i);
            }
            if (!point_decode(rp, sig)) {
                memory_cleanse(zbuf, sizeof(zbuf));
                LOG_FAIL("ed25519",
                         "batch[%zu]: R decompression failed", i);
            }
            if (!enc_is_canonical(sig, rp)) {
                memory_cleanse(zbuf, sizeof(zbuf));
                LOG_FAIL("ed25519",
                         "batch[%zu]: R encoding not canonical (pack_point can never match)",
                         i);
            }

            /* h = SHA-512(R || pk || msg) mod L — byte-identical to the
             * single path, including msg_len == 0. */
            uint8_t h[64];
            struct sha512_ctx hs;
            sha512_init(&hs);
            sha512_write(&hs, sig, 32);
            sha512_write(&hs, pk, 32);
            sha512_write(&hs, msgs[i], msg_lens[i]);
            sha512_finalize(&hs, h);
            reduce(h);

            /* (2) Torsion screen: [L](R_i + [h_i mod 8]A_i) must be O. */
            {
                gep w, t;
                set_identity(t);
                unsigned e3 = (unsigned)h[0] & 7u;
                for (int b = 2; b >= 0; b--) {
                    point_add(t, t);
                    if ((e3 >> b) & 1u)
                        point_add(t, ap);
                }
                memcpy(w, rp, sizeof(gep));
                point_add(w, t);

                gep lw;
                point_mul_scalar(lw, w, L_LE);
                if (!point_is_identity(lw)) {
                    memory_cleanse(zbuf, sizeof(zbuf));
                    LOG_FAIL("ed25519",
                             "batch[%zu]: R + [h mod 8]A has 8-torsion — [S]B - [h]A != R",
                             i);
                }
            }

            /* z_i: uniform 128-bit, never zero (a zero randomiser would
             * silently drop this signature from the combined equation). */
            uint8_t z[32] = {0};
            memcpy(z, zbuf + k * 16, 16);
            int znz = 0;
            for (int b = 0; b < 16; b++) znz |= z[b];
            if (znz == 0) z[0] = 1;

            /* (3) Cofactor-cleared points; mod-L scalars are then exact. */
            gep r8, a8;
            memcpy(r8, rp, sizeof(gep));
            memcpy(a8, ap, sizeof(gep));
            for (int d = 0; d < 3; d++) {
                point_add(r8, r8);
                point_add(a8, a8);
            }

            mx_build_table(ws->tab[np], r8);
            memcpy(ws->scal[np], z, 32);
            np++;

            uint8_t u[32];
            scalar_mul_reduce(u, z, h);
            mx_build_table(ws->tab[np], a8);
            memcpy(ws->scal[np], u, 32);
            np++;

            /* sigma += z_i * S_i  (mod L) */
            uint8_t zs[32];
            scalar_mul_reduce(zs, z, sig + 32);
            scalar_add_reduce(sigma, sigma, zs);
        }

        mx_accumulate(total, ws, np);
    }

    /* - [sigma]([8]B), added as [sigma]([8](-B)). */
    {
        gep nb;
        base_point(nb);
        point_negate(nb);
        for (int d = 0; d < 3; d++)
            point_add(nb, nb);
        gep term;
        point_mul_scalar(term, nb, sigma);
        point_add(total, term);
    }

    bool ok = point_is_identity(total);
    memory_cleanse(zbuf, sizeof(zbuf));
    memory_cleanse(sigma, sizeof(sigma));
    if (!ok)
        LOG_FAIL("ed25519",
                 "batch of %zu: combined equation != identity (>=1 invalid signature)",
                 n);
    return true;
}

bool zcl_ed25519_verify_batch(const uint8_t *const *msgs,
                              const size_t *msg_lens,
                              const uint8_t *const *sigs,
                              const uint8_t *const *pubkeys,
                              size_t n)
{
    /* n == 0 is the empty conjunction: true. Documented in the header —
     * callers that mean "at least one signature required" must check n
     * themselves, exactly as they would around a verify loop. */
    if (n == 0)
        return true;

    if (!msgs || !msg_lens || !sigs || !pubkeys)
        LOG_FAIL("ed25519",
                 "batch: NULL argument array (msgs=%p lens=%p sigs=%p pks=%p n=%zu)",
                 (const void *)msgs, (const void *)msg_lens,
                 (const void *)sigs, (const void *)pubkeys, n);

    struct ed_batch_ws *ws = zcl_malloc(sizeof(*ws), "ed25519_batch_ws");
    if (!ws) {
        LOG_WARN("ed25519",
                 "batch: table allocation of %zu bytes failed — verifying %zu signatures serially",
                 sizeof(*ws), n);
        return ed_batch_serial(msgs, msg_lens, sigs, pubkeys, n);
    }

    bool rng_failed = false;
    bool ok = ed_batch_core(msgs, msg_lens, sigs, pubkeys, n, ws, &rng_failed);
    memory_cleanse(ws->scal, sizeof(ws->scal));
    free(ws);

    if (rng_failed) {
        LOG_WARN("ed25519",
                 "batch: CSPRNG unavailable — verifying %zu signatures serially "
                 "(predictable batch randomisers would be a forgery oracle)", n);
        return ed_batch_serial(msgs, msg_lens, sigs, pubkeys, n);
    }
    return ok;
}
