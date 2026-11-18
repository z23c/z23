/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * BN254 / PHGR13 point decoding: the accept set must equal zclassicd's.
 *
 * zclassicd decodes a PHGR13 JoinSplit proof with src/zcash/Proof.hpp and
 * Proof.cpp on top of libsnark. A differential over 483,797 cases (every
 * distinct mainnet PHGR13 JoinSplit proof plus mutations) found bn254.c
 * ACCEPTING encodings zclassicd rejects, and one square-root case where it
 * REJECTS a value libsnark takes a root of:
 *
 *   F1  a G1/G2 lead byte other than 0x02/0x03 and 0x0a/0x0b   Proof.hpp:105,155
 *   F2  lead bit 0x04 with x = 0 read as the point at infinity  (no such encoding)
 *   F3  a coordinate equal to q, reduced to 0                   Proof.cpp:74
 *   F4  G2 FE2IP integer X + 2^256*q read as X                  Proof.cpp:92-93
 *   F5  a G2 point outside the order-r subgroup                 Proof.cpp:166
 *   F6  no Fq2 square root of a non-residue of Fq               fp2.tcc:146-170
 *   F7  Frobenius table and Montgomery dispatch initialised on first use
 *       without synchronisation (data race between first callers)
 *
 * F7 runs FIRST: it is a first-call race only while nothing in the process
 * has used the pairing yet. `make t-tsan ONLY=bn254_phgr13_parity` is the lane
 * that reports it on unfixed code; without TSan it asserts that every racer
 * computes the same pairing value.
 *
 * Whole-proof forms of F1, F2 and F4 (a real mainnet proof, mutated) live in
 * test_sprout_phgr13_kat.c next to the fixture. */

#include "test/test_core.h"
#include "platform/barrier.h"
#include "sapling/bn254.h"

#include <pthread.h>
#include <stdlib.h>
#include <string.h>

/* Defined in bn254.c without a header prototype. */
extern bool fq2_decode_fe2ip(struct bn_fq *c0, struct bn_fq *c1,
                             const uint8_t data[64]);

#define PAR_CHECK(name, expr) do {             \
    printf("%s... ", (name));                  \
    if ((expr)) printf("OK\n");                \
    else { printf("FAIL\n"); failures++; }     \
} while (0)

static const uint8_t k_q_be[32] = {
    0x30, 0x64, 0x4e, 0x72, 0xe1, 0x31, 0xa0, 0x29,
    0xb8, 0x50, 0x45, 0xb6, 0x81, 0x81, 0x58, 0x5d,
    0x97, 0x81, 0x6a, 0x91, 0x68, 0x71, 0xca, 0x8d,
    0x3c, 0x20, 0x8c, 0x16, 0xd8, 0x7c, 0xfd, 0x47
};

/* r, the order of G1 and G2, little-endian limbs. */
static const uint64_t k_r_le[4] = {
    0x43e1f593f0000001ULL, 0x2833e84879b97091ULL,
    0xb85045b68181585dULL, 0x30644e72e131a029ULL
};

/* ── big-endian byte-string integers (test-side, independent of bn254.c) ── */

/* out[n] += add[n], big-endian; returns the carry out. */
static unsigned be_add(uint8_t *out, const uint8_t *add, size_t n)
{
    unsigned carry = 0;
    for (size_t i = n; i-- > 0;) {
        unsigned s = (unsigned)out[i] + add[i] + carry;
        out[i] = (uint8_t)s;
        carry = s >> 8;
    }
    return carry;
}

/* out[64] = a[32] * b[32], big-endian schoolbook. */
static void be_mul_32x32(uint8_t out[64], const uint8_t a[32], const uint8_t b[32])
{
    uint32_t acc[64] = {0};
    for (int i = 0; i < 32; i++)
        for (int j = 0; j < 32; j++)
            acc[i + j + 1] += (uint32_t)a[i] * b[j];
    uint32_t carry = 0;
    for (int k = 63; k >= 0; k--) {
        uint32_t v = acc[k] + carry;
        out[k] = (uint8_t)v;
        carry = v >> 8;
    }
}

/* FE2IP (Proof.cpp:25-34): the 512-bit integer c1*q + c0. */
static void fe2ip_encode(uint8_t out[64], const struct bn_fq2 *e)
{
    uint8_t c0[32], c1[32], wide[64] = {0};
    bn_fq_to_bytes_be(c0, &e->c0);
    bn_fq_to_bytes_be(c1, &e->c1);
    be_mul_32x32(out, c1, k_q_be);
    memcpy(wide + 32, c0, 32);
    (void)be_add(out, wide, 64);
}

/* CompressedG2 (Proof.cpp:132-143) of an affine point. */
static void g2_compress(uint8_t out[65], const struct bn_fq2 *x, const struct bn_fq2 *y)
{
    struct bn_fq2 ny;
    uint8_t ye[64], nye[64];
    bn_fq2_neg(&ny, y);
    fe2ip_encode(ye, y);
    fe2ip_encode(nye, &ny);
    out[0] = (uint8_t)(0x0a | (memcmp(ye, nye, 64) > 0 ? 1 : 0));
    fe2ip_encode(out + 1, x);
}

/* r * P by the public group law (test-side copy of Proof.cpp:166). */
static bool g2_times_r_is_identity(const struct bn_g2 *p)
{
    struct bn_g2 acc;
    bn_g2_identity(&acc);
    for (int i = 3; i >= 0; i--) {
        for (int bit = 63; bit >= 0; bit--) {
            bn_g2_double(&acc, &acc);
            if ((k_r_le[i] >> bit) & 1)
                bn_g2_add(&acc, &acc, p);
        }
    }
    return bn_g2_is_identity(&acc);
}

static void twist_b(struct bn_fq2 *b)
{
    struct bn_fq2 xi, three;
    bn_fq_from_u64(&xi.c0, 9);
    bn_fq_one(&xi.c1);
    bn_fq_from_u64(&three.c0, 3);
    bn_fq_zero(&three.c1);
    bn_fq2_inv(b, &xi);
    bn_fq2_mul(b, b, &three);
}

static void g2_rhs(struct bn_fq2 *rhs, const struct bn_fq2 *x)
{
    struct bn_fq2 b;
    twist_b(&b);
    bn_fq2_sq(rhs, x);
    bn_fq2_mul(rhs, rhs, x);
    bn_fq2_add(rhs, rhs, &b);
}

static bool g2_affine_eq(const struct bn_g2 *p, const struct bn_fq2 *x, const struct bn_fq2 *y)
{
    struct bn_fq2 px, py;
    bn_g2_to_affine(&px, &py, p);
    return bn_fq2_eq(&px, x) && bn_fq2_eq(&py, y);
}

/* ── F7: first-call race over the pairing's lazily initialised state ── */

#define RACE_THREADS 24

struct race_shared {
    zcl_barrier_t barrier;
    struct bn_g1 g1;
    struct bn_fq12 out[RACE_THREADS];
};

struct race_arg {
    struct race_shared *sh;
    int idx;
};

static void *race_worker(void *p)
{
    struct race_arg *a = p;
    struct bn_g2 g2;
    zcl_barrier_wait(&a->sh->barrier);
    /* First use of the Montgomery dispatch (bn254_g2_one already multiplies)
     * and of the Frobenius table (Miller-loop correction, final
     * exponentiation), by every thread at once. */
    bn254_g2_one(&g2);
    bn254_pairing(&a->sh->out[a->idx], &a->sh->g1, &g2);
    return NULL;
}

static int check_first_call_race(void)
{
    int failures = 0;
    static struct race_shared sh;
    pthread_t th[RACE_THREADS];
    struct race_arg args[RACE_THREADS];

    /* G1 generator (1, 2) from Montgomery constants and additions only: no
     * field multiply happens on this thread before the workers are released,
     * so they really are the first users. */
    memset(&sh, 0, sizeof sh);
    bn_fq_one(&sh.g1.x);
    bn_fq_one(&sh.g1.y);
    bn_fq_add(&sh.g1.y, &sh.g1.y, &sh.g1.y);
    bn_fq_one(&sh.g1.z);

    zcl_barrier_init(&sh.barrier, RACE_THREADS);
    for (int i = 0; i < RACE_THREADS; i++) {
        args[i].sh = &sh;
        args[i].idx = i;
        if (pthread_create(&th[i], NULL, race_worker, &args[i]) != 0) {
            /* The barrier can never release with a thread missing. */
            printf("F7: only %d/%d threads started... FAIL\n", i, RACE_THREADS);
            fflush(stdout);
            exit(1);
        }
    }
    for (int i = 0; i < RACE_THREADS; i++)
        pthread_join(th[i], NULL);
    zcl_barrier_destroy(&sh.barrier);

    bool all_equal = true;
    for (int i = 1; i < RACE_THREADS; i++)
        if (!bn_fq12_eq(&sh.out[0], &sh.out[i]))
            all_equal = false;

    struct bn_g2 g2;
    struct bn_fq12 again, one;
    bn254_g2_one(&g2);
    bn254_pairing(&again, &sh.g1, &g2);
    bn_fq12_one(&one);
    PAR_CHECK("F7: concurrent first pairings all agree", all_equal);
    PAR_CHECK("F7: raced pairing equals a later single-threaded one",
              bn_fq12_eq(&sh.out[0], &again));
    PAR_CHECK("F7: e(G1, G2) is not 1", !bn_fq12_eq(&again, &one));
    return failures;
}

/* ── F1, F2, F3: G1 ───────────────────────────────────────────── */

static int check_g1_lead_byte(void)
{
    int failures = 0;
    /* x = 1: y^2 = 4, y = 2 (even) or q - 2 (odd). */
    uint8_t enc[33] = {0};
    enc[32] = 1;
    struct bn_fq two, neg_two;
    bn_fq_from_u64(&two, 2);
    bn_fq_neg(&neg_two, &two);

    int wrong = 0, first_wrong = -1;
    for (int b = 0; b < 256; b++) {
        struct bn_g1 p;
        enc[0] = (uint8_t)b;
        bool ok = bn_g1_decompress(&p, enc);
        bool want = (b == 0x02 || b == 0x03);
        if (ok != want) {
            wrong++;
            if (first_wrong < 0)
                first_wrong = b;
        }
    }
    printf("F1: G1 accepts exactly the lead bytes 0x02 and 0x03 "
           "(%d of 256 wrong, first %d)... ", wrong, first_wrong);
    if (wrong == 0) printf("OK\n"); else { printf("FAIL\n"); failures++; }

    struct bn_g1 even, odd;
    enc[0] = 0x02;
    bool ok_even = bn_g1_decompress(&even, enc);
    enc[0] = 0x03;
    bool ok_odd = bn_g1_decompress(&odd, enc);
    PAR_CHECK("F1: G1 0x02 selects the even y, 0x03 the odd y",
              ok_even && ok_odd && bn_fq_eq(&even.y, &two) && bn_fq_eq(&odd.y, &neg_two));
    return failures;
}

static int check_g1_no_infinity(void)
{
    int failures = 0;
    /* x = 0: y^2 = 3 has no root in Fq, so zclassicd refuses every lead byte
     * (differential class g1.x_zero: 0 of 200 accepted). bn254.c read lead
     * bit 0x04 here as "the point at infinity". */
    uint8_t enc[33] = {0};
    int accepted = 0, first = -1;
    for (int b = 0; b < 256; b++) {
        struct bn_g1 p;
        enc[0] = (uint8_t)b;
        if (bn_g1_decompress(&p, enc)) {
            accepted++;
            if (first < 0)
                first = b;
        }
    }
    printf("F2: G1 x = 0 is refused under every lead byte "
           "(%d of 256 accepted, first %d)... ", accepted, first);
    if (accepted == 0) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    return failures;
}

static int check_fq_strict(void)
{
    int failures = 0;
    struct bn_fq e;
    uint8_t v[32];
    static const uint8_t one[32] = { [31] = 1 };

    PAR_CHECK("F3: Fq decode refuses q", !bn_fq_from_bytes_be(&e, k_q_be));

    memcpy(v, k_q_be, 32);
    v[31] -= 1; /* q - 1: last byte 0x47 -> 0x46, no borrow */
    struct bn_fq minus_one;
    bn_fq_one(&minus_one);
    bn_fq_neg(&minus_one, &minus_one);
    PAR_CHECK("F3: Fq decode accepts q - 1 as -1",
              bn_fq_from_bytes_be(&e, v) && bn_fq_eq(&e, &minus_one));

    memcpy(v, k_q_be, 32);
    (void)be_add(v, one, 32);
    PAR_CHECK("F3: Fq decode refuses q + 1", !bn_fq_from_bytes_be(&e, v));

    memset(v, 0xff, 32);
    PAR_CHECK("F3: Fq decode refuses 2^256 - 1", !bn_fq_from_bytes_be(&e, v));

    /* A G1 x equal to q must not be read as x = 0. Pinned at the field level
     * above; at the point level x = 0 is itself refused (y^2 = 3). */
    uint8_t enc[33];
    struct bn_g1 p;
    enc[0] = 0x02;
    memcpy(enc + 1, k_q_be, 32);
    PAR_CHECK("F3: G1 x = q is refused", !bn_g1_decompress(&p, enc));
    return failures;
}

/* ── F3, F4: FE2IP ────────────────────────────────────────────── */

static int check_fe2ip_range(void)
{
    int failures = 0;
    struct bn_fq c0, c1, minus_one;
    uint8_t q2[64], v[64];
    static const uint8_t one64[64] = { [63] = 1 };

    bn_fq_one(&minus_one);
    bn_fq_neg(&minus_one, &minus_one);
    be_mul_32x32(q2, k_q_be, k_q_be);

    /* q^2 = q*q + 0: quotient exactly q, which is not < q. */
    PAR_CHECK("F3: FE2IP refuses q^2 (c1 = q)", !fq2_decode_fe2ip(&c0, &c1, q2));

    /* q^2 - 1 = (q-1)*q + (q-1): the largest valid integer. */
    memcpy(v, q2, 64);
    for (int i = 63; i >= 0; i--)
        if (v[i]-- != 0)
            break;
    PAR_CHECK("F3: FE2IP accepts q^2 - 1 as (-1, -1)",
              fq2_decode_fe2ip(&c0, &c1, v) &&
              bn_fq_eq(&c0, &minus_one) && bn_fq_eq(&c1, &minus_one));

    memcpy(v, q2, 64);
    (void)be_add(v, one64, 64);
    PAR_CHECK("F3: FE2IP refuses q^2 + 1", !fq2_decode_fe2ip(&c0, &c1, v));

    memset(v, 0xff, 64);
    PAR_CHECK("F4: FE2IP refuses 2^512 - 1", !fq2_decode_fe2ip(&c0, &c1, v));

    /* X + 2^256*q for the generator's x: the quotient is c1 + 2^256. Dropping
     * quotient bits >= 2^256 decoded it to the same (c0, c1) as X. */
    struct bn_g2 gen;
    bn254_g2_one(&gen);
    uint8_t enc[65];
    g2_compress(enc, &gen.x, &gen.y);
    PAR_CHECK("F4: FE2IP decodes the generator's X",
              fq2_decode_fe2ip(&c0, &c1, enc + 1) &&
              bn_fq_eq(&c0, &gen.x.c0) && bn_fq_eq(&c1, &gen.x.c1));

    uint8_t mal[65];
    memcpy(mal, enc, 65);
    unsigned carry = be_add(mal + 1, k_q_be, 32); /* + q * 2^256 */
    PAR_CHECK("F4: X + 2^256*q still fits in 512 bits", carry == 0);
    PAR_CHECK("F4: FE2IP refuses X + 2^256*q", !fq2_decode_fe2ip(&c0, &c1, mal + 1));
    struct bn_g2 p;
    PAR_CHECK("F4: G2 refuses the generator re-encoded as X + 2^256*q",
              !bn_g2_decompress(&p, mal));
    return failures;
}

/* ── F1, F2, F5: G2 ───────────────────────────────────────────── */

static int check_g2_lead_byte(void)
{
    int failures = 0;
    struct bn_g2 gen;
    bn254_g2_one(&gen);
    struct bn_fq2 neg_y;
    bn_fq2_neg(&neg_y, &gen.y);
    uint8_t enc[65];
    g2_compress(enc, &gen.x, &gen.y);
    uint8_t right = enc[0];

    int wrong = 0, first_wrong = -1;
    for (int b = 0; b < 256; b++) {
        struct bn_g2 p;
        enc[0] = (uint8_t)b;
        bool ok = bn_g2_decompress(&p, enc);
        bool want = (b == 0x0a || b == 0x0b);
        if (ok != want) {
            wrong++;
            if (first_wrong < 0)
                first_wrong = b;
        }
    }
    printf("F1: G2 accepts exactly the lead bytes 0x0a and 0x0b "
           "(%d of 256 wrong, first %d)... ", wrong, first_wrong);
    if (wrong == 0) printf("OK\n"); else { printf("FAIL\n"); failures++; }

    struct bn_g2 p, n;
    enc[0] = right;
    bool ok_p = bn_g2_decompress(&p, enc);
    enc[0] = right ^ 1;
    bool ok_n = bn_g2_decompress(&n, enc);
    PAR_CHECK("F1: G2 y_gt flag selects y, its complement -y",
              ok_p && ok_n && g2_affine_eq(&p, &gen.x, &gen.y) &&
              g2_affine_eq(&n, &gen.x, &neg_y));

    /* x = 0: zclassicd refuses every lead byte (class g2.x_zero); lead bit
     * 0x04 was read as the point at infinity. */
    memset(enc, 0, sizeof enc);
    int accepted = 0, first = -1;
    for (int b = 0; b < 256; b++) {
        enc[0] = (uint8_t)b;
        if (bn_g2_decompress(&p, enc)) {
            accepted++;
            if (first < 0)
                first = b;
        }
    }
    printf("F2: G2 x = 0 is refused under every lead byte "
           "(%d of 256 accepted, first %d)... ", accepted, first);
    if (accepted == 0) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    return failures;
}

static int check_g2_subgroup_members(void)
{
    int failures = 0;

    /* In the subgroup: k*G and -(k*G) round-trip for k = 1..8. */
    struct bn_g2 gen, acc;
    bn254_g2_one(&gen);
    bn_g2_identity(&acc);
    bool roundtrip = true, in_subgroup = true;
    for (int k = 1; k <= 8; k++) {
        struct bn_fq2 x, y, ny;
        uint8_t enc[65];
        struct bn_g2 p;
        bn_g2_add(&acc, &acc, &gen);
        bn_g2_to_affine(&x, &y, &acc);
        bn_fq2_neg(&ny, &y);
        g2_compress(enc, &x, &y);
        if (!bn_g2_decompress(&p, enc) || !g2_affine_eq(&p, &x, &y))
            roundtrip = false;
        g2_compress(enc, &x, &ny);
        if (!bn_g2_decompress(&p, enc) || !g2_affine_eq(&p, &x, &ny))
            roundtrip = false;
        if (!g2_times_r_is_identity(&acc))
            in_subgroup = false;
    }
    PAR_CHECK("F5: r * (k*G) is the identity for k = 1..8", in_subgroup);
    PAR_CHECK("F5: k*G and -(k*G) decode to themselves for k = 1..8", roundtrip);
    return failures;
}

static int check_g2_outside_subgroup(void)
{
    int failures = 0;

    /* On the twist curve but outside the subgroup: x = (k, 0) for the first
     * few k whose x^3 + b' is a square. The curve has r * (2q - r) points, so
     * such a point is in the order-r subgroup with probability about 2^-254;
     * the test checks r*P != O itself rather than assume it. */
    int found = 0, accepted = 0;
    for (uint64_t k = 1; k <= 64 && found < 8; k++) {
        struct bn_g2 pt;
        struct bn_fq2 rhs, ny;
        bn_fq_from_u64(&pt.x.c0, k);
        bn_fq_zero(&pt.x.c1);
        g2_rhs(&rhs, &pt.x);
        if (!bn_fq2_sqrt(&pt.y, &rhs))
            continue;
        bn_fq2_one(&pt.z);
        if (!bn_g2_is_on_curve(&pt) || g2_times_r_is_identity(&pt))
            continue;
        found++;
        uint8_t enc[65];
        struct bn_g2 p;
        g2_compress(enc, &pt.x, &pt.y);
        if (bn_g2_decompress(&p, enc))
            accepted++;
        bn_fq2_neg(&ny, &pt.y);
        g2_compress(enc, &pt.x, &ny);
        if (bn_g2_decompress(&p, enc))
            accepted++;
    }
    PAR_CHECK("F5: found on-curve G2 points outside the subgroup", found == 8);
    printf("F5: G2 refuses on-curve points outside the order-r subgroup "
           "(%d of %d encodings accepted)... ", accepted, found * 2);
    if (found == 8 && accepted == 0) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    return failures;
}

/* ── F6: Fq2 square root ──────────────────────────────────────── */

static bool sqrt_squares_back(const struct bn_fq2 *a)
{
    struct bn_fq2 r, chk;
    if (!bn_fq2_sqrt(&r, a))
        return false;
    bn_fq2_sq(&chk, &r);
    return bn_fq2_eq(&chk, a);
}

/* Find x = s + t*u with x^3 + b' = a0 in Fq and a0 a NON-residue of Fq.
 * Im(x^3) = 3*s^2*t - t^3 must equal -Im(b'), so s^2 = (t^3 - b1) / (3t):
 * one Fq square root per trial t. */
static bool find_point_with_fq_nonresidue_rhs(struct bn_fq2 *x, struct bn_fq2 *rhs)
{
    struct bn_fq2 b;
    twist_b(&b);
    for (uint64_t tv = 1; tv <= 256; tv++) {
        struct bn_fq t, t3, num, den, s2, s, probe;
        bn_fq_from_u64(&t, tv);
        bn_fq_sq(&t3, &t);
        bn_fq_mul(&t3, &t3, &t);
        bn_fq_sub(&num, &t3, &b.c1);
        bn_fq_from_u64(&den, 3 * tv);
        bn_fq_inv(&den, &den);
        bn_fq_mul(&s2, &num, &den);
        if (!bn_fq_sqrt(&s, &s2))
            continue;
        x->c0 = s;
        x->c1 = t;
        g2_rhs(rhs, x);
        if (!bn_fq_is_zero(&rhs->c1))
            return false; /* the construction itself is wrong */
        if (bn_fq_is_zero(&rhs->c0) || bn_fq_sqrt(&probe, &rhs->c0))
            continue;
        return true;
    }
    return false;
}

static int check_fq2_sqrt(void)
{
    int failures = 0;

    /* Every element of Fq is a square in Fq2: residues have a root in Fq,
     * non-residues a root t*u. libsnark's Fp2 sqrt returns both kinds. */
    int residues = 0, nonresidues = 0, bad = 0;
    for (uint64_t v = 1; v <= 64; v++) {
        struct bn_fq2 a;
        struct bn_fq probe;
        bn_fq_from_u64(&a.c0, v);
        bn_fq_zero(&a.c1);
        if (bn_fq_sqrt(&probe, &a.c0)) residues++; else nonresidues++;
        if (!sqrt_squares_back(&a))
            bad++;
    }
    printf("F6: Fq2 sqrt of the Fq elements 1..64 (%d residues, %d non-residues, "
           "%d without a root)... ", residues, nonresidues, bad);
    if (bad == 0 && residues > 0 && nonresidues > 0) printf("OK\n");
    else { printf("FAIL\n"); failures++; }

    /* General elements: sqrt(a^2) is +/-a. */
    bool general = true;
    for (uint64_t i = 1; i <= 16; i++) {
        struct bn_fq2 a, sq, r, nr;
        bn_fq_from_u64(&a.c0, i * 7919);
        bn_fq_from_u64(&a.c1, i * 104729 + 1);
        bn_fq2_sq(&sq, &a);
        bn_fq2_neg(&nr, &a);
        if (!bn_fq2_sqrt(&r, &sq) || !(bn_fq2_eq(&r, &a) || bn_fq2_eq(&r, &nr)))
            general = false;
    }
    PAR_CHECK("F6: Fq2 sqrt(a^2) is a or -a for general a", general);

    /* Non-squares stay refused: xi = 9 + u is a non-square (it is the
     * quadratic non-residue the Fq12 tower is built on). */
    struct bn_fq2 xi, r;
    bn_fq_from_u64(&xi.c0, 9);
    bn_fq_one(&xi.c1);
    PAR_CHECK("F6: Fq2 sqrt refuses the non-square 9 + u", !bn_fq2_sqrt(&r, &xi));
    return failures;
}

static int check_fq2_sqrt_curve_point(void)
{
    int failures = 0;

    /* A real twist-curve point whose y^2 is a non-residue of Fq. */
    struct bn_g2 pt;
    struct bn_fq2 rhs;
    bool have = find_point_with_fq_nonresidue_rhs(&pt.x, &rhs);
    PAR_CHECK("F6: constructed x with x^3 + b' a non-residue of Fq", have);
    if (!have)
        return failures;
    bool rooted = bn_fq2_sqrt(&pt.y, &rhs);
    bn_fq2_one(&pt.z);
    PAR_CHECK("F6: that x has a y on the twist curve",
              rooted && bn_g2_is_on_curve(&pt) && bn_fq_is_zero(&pt.y.c0));

    /* The point is outside the subgroup (checked, not assumed), so zclassicd
     * refuses it at Proof.cpp:166 and so must bn254.c. A subgroup point of
     * this shape would be the only way to observe F6 as a verdict difference;
     * none is known and finding one is a ~2^254 search. */
    if (rooted) {
        uint8_t enc[65];
        struct bn_g2 p;
        g2_compress(enc, &pt.x, &pt.y);
        PAR_CHECK("F6: the constructed point is outside the subgroup and refused",
                  !g2_times_r_is_identity(&pt) && !bn_g2_decompress(&p, enc));
    }
    return failures;
}

/* P1: libsnark pairs a G1 identity at the affine point (0, 1)
 * (alt_bn128_G1::to_affine_coordinates leaves (0,1,0) and the Miller loop
 * then evaluates its lines there). With x_P = 0 every line value loses its
 * x_P term, the Miller value lies in a proper subfield of Fq12 and the final
 * exponentiation maps it to 1, so libsnark's e(O, Q) is 1 and the verifier
 * dropping the factor (bn254_engine.inc: a pair with no line table
 * contributes 1) computes the same function, on the positive side and on the
 * unitary_inverse side alike. The differential gate class pairing.g1_infinity
 * agrees with libsnark itself on 50 of 50; this pins the same fact in the
 * unit suite for P = (0, 1) and (0, -1) over k*G2, k = 1..24, and shows a
 * real G1 point does not pair to 1. */
static int check_g1_identity_pairing_is_one(void)
{
    int failures = 0;
    struct bn_g2 gen, q;
    struct bn_fq12 one;
    bn254_g2_one(&gen);
    bn_g2_identity(&q);
    bn_fq12_one(&one);
    bool all_one = true, neg_one = true;
    for (int k = 1; k <= 24; k++) {
        struct bn_g1 p;
        struct bn_fq12 r;
        bn_g2_add(&q, &q, &gen);
        bn_fq_zero(&p.x);
        bn_fq_one(&p.y);
        bn_fq_one(&p.z);
        bn254_pairing(&r, &p, &q);
        if (!bn_fq12_eq(&r, &one)) all_one = false;
        bn_fq_neg(&p.y, &p.y);
        bn254_pairing(&r, &p, &q);
        if (!bn_fq12_eq(&r, &one)) neg_one = false;
    }
    PAR_CHECK("P1: pairing at (0,1) is 1 for k*G2, k = 1..24", all_one);
    PAR_CHECK("P1: pairing at (0,-1) is 1 for k*G2, k = 1..24", neg_one);

    /* (1, 2) is the generator of G1 on y^2 = x^3 + 3. */
    struct bn_g1 g1;
    struct bn_fq12 r;
    bn_fq_one(&g1.x);
    bn_fq_one(&g1.y);
    bn_fq_add(&g1.y, &g1.y, &g1.y);
    bn_fq_one(&g1.z);
    bn254_pairing(&r, &g1, &gen);
    PAR_CHECK("P1: a real G1 point does not pair to 1", !bn_fq12_eq(&r, &one));
    return failures;
}

int test_bn254_phgr13_parity(void)
{
    printf("\n=== BN254 PHGR13 decode parity with zclassicd ===\n");
    int failures = 0;

    failures += check_first_call_race();
    failures += check_g1_lead_byte();
    failures += check_g1_no_infinity();
    failures += check_fq_strict();
    failures += check_fe2ip_range();
    failures += check_g2_lead_byte();
    failures += check_g2_subgroup_members();
    failures += check_g2_outside_subgroup();
    failures += check_fq2_sqrt();
    failures += check_fq2_sqrt_curve_point();
    failures += check_g1_identity_pairing_is_one();

    printf("BN254 PHGR13 decode parity: %s (%d failures)\n",
           failures == 0 ? "OK" : "FAIL", failures);
    return failures;
}
