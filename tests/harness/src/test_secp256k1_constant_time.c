/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * secp256k1 CONSTANT-TIME check — pins that the work done by the signing and
 * public-key-derivation paths does not depend on the secret scalar.
 *
 * WHAT THIS IS
 * ------------
 * A statistical black-box work-ratio test, modelled on the shipped
 * curve25519 Hamming-weight gate (tests/harness/src/test_sapling.c). It measures
 * PER-THREAD CPU time (clock_thread_cpu_ns), not wall clock, so it counts
 * cycles this thread actually burned rather than time the scheduler gave us —
 * a real secret-dependent branch still burns real cycles and still moves the
 * ratio, while preemption from a parallel test group drops out. Each sample
 * runs the two secrets in alternating order and sums both directions, which
 * cancels one-sided frequency-ramp and cache bias; the verdict is the MEDIAN
 * ratio over 9 samples, so one skewed sample cannot decide it.
 *
 * WHAT IT CAN PROVE
 * -----------------
 * That total executed work on this microarchitecture is not measurably
 * correlated with the Hamming weight of the secret scalar. That is exactly
 * the signal an early-exit loop, a skip-the-add-when-bit-is-zero ladder, or a
 * "strip leading zero limbs" fast path produces — historically the way
 * scalar-multiplication implementations leak.
 *
 * WHAT IT CANNOT PROVE  (state the limits, do not oversell the gate)
 * ------------------------------------------------------------------
 *  - It is not a proof of constant-time-ness. It is a detector for GROSS work
 *    asymmetry (roughly >15%). A leak of a few cycles per bit is invisible here.
 *  - It says nothing about cache-line or branch-predictor state. A table
 *    lookup INDEXED by secret bits costs the same time on an idle core but
 *    leaks through a shared L1 to an SMT sibling. This test would pass it.
 *  - It observes only two secrets (minimum and maximum Hamming weight). It is
 *    not a correlation study over a key distribution.
 *  - It is single-host and single-microarchitecture. A data-dependent
 *    instruction (a variable-latency divide, a subnormal float) may be flat
 *    here and leaky elsewhere.
 *  - The vendored libsecp256k1 archive is where the actual arithmetic lives;
 *    this test observes it through the in-tree wrappers, so it grades the
 *    composite, not the library in isolation.
 *
 * WHY IT IS NOT VACUOUS
 * ---------------------
 * The last leg feeds a DELIBERATELY LEAKY function — one whose work scales
 * with the popcount of the secret — through the SAME checker and REQUIRES it
 * to be flagged. If the checker ever degrades into "always passes", that leg
 * fails first. A constant-time gate that cannot fail is worse than none.
 */

#include "test/test_core.h"
#include "test/secp256k1_corpus.h"
#include "keys/key.h"
#include "keys/pubkey.h"
#include "platform/clock.h"

#include <stdint.h>

#define CT_SAMPLES 9
#define CT_ITERS   64
#define CT_WARMUP  16

/* Two-sided tolerance on the median work ratio. Same bound as the shipped
 * curve25519 gate: a reintroduced secret-dependent control path pushes the
 * ratio well past this; SMT/cache noise on an idle-ish core does not. */
#define CT_TOLERANCE 1.15

typedef void (*ct_workfn)(const void *secret, void *scratch);

/* Median of CT_SAMPLES alternating-order work ratios (hi / lo).
 * `lo_ns_out` receives the low-secret work total of the median sample — the
 * caller uses it to reject a VACUOUS measurement: a call the optimiser
 * deleted, or one that returned early, also has a perfectly flat ratio. */
static double ct_ratio(ct_workfn fn, const void *lo, const void *hi,
                       void *scratch, uint64_t *lo_ns_out)
{
    for (int i = 0; i < CT_WARMUP; i++) {
        fn(lo, scratch);
        fn(hi, scratch);
    }

    struct { double ratio; uint64_t lo_ns; } samples[CT_SAMPLES];
    for (int b = 0; b < CT_SAMPLES; b++) {
        uint64_t lo_a, lo_b, hi_a, hi_b, t0;
#define CT_RUN(dst, secret)                                        \
        t0 = (uint64_t)clock_thread_cpu_ns();                      \
        for (int i = 0; i < CT_ITERS; i++) fn((secret), scratch);  \
        (dst) = (uint64_t)clock_thread_cpu_ns() - t0
        if ((b & 1) == 0) {
            CT_RUN(lo_a, lo); CT_RUN(hi_a, hi);
            CT_RUN(hi_b, hi); CT_RUN(lo_b, lo);
        } else {
            CT_RUN(hi_a, hi); CT_RUN(lo_a, lo);
            CT_RUN(lo_b, lo); CT_RUN(hi_b, hi);
        }
#undef CT_RUN
        uint64_t l = lo_a + lo_b, h = hi_a + hi_b;
        samples[b].lo_ns = l;
        samples[b].ratio = (l != 0) ? (double)h / (double)l : 0.0;
    }
    for (int a = 1; a < CT_SAMPLES; a++) {
        typeof(samples[0]) s = samples[a];
        int i = a;
        while (i > 0 && samples[i - 1].ratio > s.ratio) {
            samples[i] = samples[i - 1];
            i--;
        }
        samples[i] = s;
    }
    if (lo_ns_out)
        *lo_ns_out = samples[CT_SAMPLES / 2].lo_ns;
    return samples[CT_SAMPLES / 2].ratio;
}

static bool ct_flat(double r)
{
    return r > 0.0 && r <= CT_TOLERANCE && r >= 1.0 / CT_TOLERANCE;
}

/* A flat ratio is only evidence if real work happened. 100 us across
 * CT_ITERS calls is orders of magnitude below a genuine secp256k1 scalar
 * multiplication and orders of magnitude above an elided call. */
#define CT_WORK_FLOOR_NS 100000ULL

static bool ct_did_work(uint64_t lo_ns)
{
    return lo_ns >= CT_WORK_FLOOR_NS;
}

/* ── work functions under test ────────────────────────────────────────── */

static void work_pubkey_derive(const void *secret, void *scratch)
{
    struct pubkey *out = (struct pubkey *)scratch;
    (void)privkey_get_pubkey((const struct privkey *)secret, out);
}

struct sign_scratch {
    struct uint256 msg;
    unsigned char  sig[SIGNATURE_SIZE];
};

static void work_sign(const void *secret, void *scratch)
{
    struct sign_scratch *s = (struct sign_scratch *)scratch;
    size_t len = sizeof(s->sig);
    (void)privkey_sign((const struct privkey *)secret, &s->msg, s->sig, &len);
}

/* ── the deliberately leaky control (the checker's own teeth) ─────────── */

static volatile uint64_t g_ct_sink;

/* Keep the deliberately conditional work observably separate under LTO.
 * Modern compilers can if-convert the inline multiply below into an
 * unconditional multiply plus cmov, making both secrets execute identical
 * work and turning the checker's calibration control into a false failure.
 * A noinline call with a volatile observation cannot be if-converted away. */
static __attribute__((noinline)) uint64_t work_leaky_add(uint64_t acc)
{
    g_ct_sink ^= acc;
    return acc * 2862933555777941757ULL + 3037000493ULL;
}

static void work_leaky(const void *secret, void *scratch)
{
    /* Textbook double-and-add with the add SKIPPED on a zero bit — the exact
     * shape a "constant-time" ladder degrades into when someone optimises it.
     * Work is proportional to the popcount of the secret. */
    const uint8_t *d = (const uint8_t *)secret;
    (void)scratch;
    uint64_t acc = 1;
    /* Repeat so one call costs roughly what one scalar multiplication costs;
     * otherwise the control sits under CT_WORK_FLOOR_NS and its own result
     * would be noise rather than a demonstration. */
    for (int rep = 0; rep < 8; rep++)
    for (int byte = 0; byte < 32; byte++) {
        for (int bit = 7; bit >= 0; bit--) {
            /* the unconditional "double" */
            acc = acc * 6364136223846793005ULL + 1442695040888963407ULL;
            /* the conditional "add" — ONE extra step, so a maximum-weight
             * secret costs only ~2x a minimum-weight one. Kept deliberately
             * mild: the point is to show the checker resolves a modest leak,
             * not that it can spot a 20x one. */
            if ((d[byte] >> bit) & 1)
                acc = work_leaky_add(acc);
        }
    }
    g_ct_sink = acc;
}

int test_secp256k1_constant_time(void)
{
    int failures = 0;
    printf("\n=== secp256k1_constant_time (work-ratio, black box) ===\n");

    /* Minimum-weight and maximum-weight VALID secret scalars.
     * lo = 1 (Hamming weight 1); hi = n-1 (weight 255, the largest scalar
     * still inside the group order). Both are legal private keys. */
    struct privkey lo, hi;
    memset(lo.vch, 0, 32);
    lo.vch[31] = 1;
    lo.fValid = true; lo.fCompressed = true;
    secp_be256_sub(hi.vch, SECP_ORDER_N, (const uint8_t[32]){
        0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1});
    hi.fValid = true; hi.fCompressed = true;

    printf("fixtures are valid secret scalars... ");
    if (privkey_range_check(&lo) && privkey_range_check(&hi)) printf("OK\n");
    else { printf("FAIL\n"); failures++; return failures; }

    /* Leg 1 — public-key derivation is a pure secret-scalar multiplication,
     * the cleanest place a bit-dependent ladder would show. */
    printf("leg 1: privkey_get_pubkey work vs secret Hamming weight... ");
    {
        struct pubkey scratch;
        uint64_t lo_ns = 0;
        double r = ct_ratio(work_pubkey_derive, &lo, &hi, &scratch, &lo_ns);
        if (!ct_did_work(lo_ns)) {
            printf("FAIL — measurement is VACUOUS (%llu ns < floor)\n",
                   (unsigned long long)lo_ns);
            failures++;
        } else if (ct_flat(r)) {
            printf("OK (ratio %.3f, %llu ns)\n", r, (unsigned long long)lo_ns);
        } else {
            printf("FAIL (ratio %.3f, tolerance %.2f)\n", r, CT_TOLERANCE);
            failures++;
        }
    }

    /* Leg 2 — the full signing path. The RFC 6979 nonce is pseudorandom for
     * both secrets, so this leg grades the whole composite (nonce derivation,
     * nonce scalar-mult, and the secret-times-r modular arithmetic) for
     * correlation with the secret. */
    printf("leg 2: privkey_sign work vs secret Hamming weight... ");
    {
        struct sign_scratch scratch;
        for (int i = 0; i < 32; i++)
            scratch.msg.data[i] = (uint8_t)(i * 11 + 3);
        uint64_t lo_ns = 0;
        double r = ct_ratio(work_sign, &lo, &hi, &scratch, &lo_ns);
        if (!ct_did_work(lo_ns)) {
            printf("FAIL — measurement is VACUOUS (%llu ns < floor)\n",
                   (unsigned long long)lo_ns);
            failures++;
        } else if (ct_flat(r)) {
            printf("OK (ratio %.3f, %llu ns)\n", r, (unsigned long long)lo_ns);
        } else {
            printf("FAIL (ratio %.3f, tolerance %.2f)\n", r, CT_TOLERANCE);
            failures++;
        }
    }

    /* Leg 3 — TEETH. The checker must FLAG a known-leaky function. If this
     * leg reports "flat", the two legs above proved nothing. */
    printf("leg 3 (teeth): checker flags a deliberately leaky ladder... ");
    {
        uint64_t lo_ns = 0;
        double r = ct_ratio(work_leaky, lo.vch, hi.vch, NULL, &lo_ns);
        if (!ct_did_work(lo_ns)) {
            printf("FAIL — control ran too briefly to grade (%llu ns)\n",
                   (unsigned long long)lo_ns);
            failures++;
        } else if (!ct_flat(r)) {
            printf("OK (leak detected, ratio %.3f > %.2f)\n", r, CT_TOLERANCE);
        } else {
            printf("FAIL — checker is VACUOUS (leaky ratio %.3f <= %.2f)\n",
                   r, CT_TOLERANCE);
            failures++;
        }
    }

    printf("secp256k1_constant_time: %s (%d failures)\n",
           failures == 0 ? "OK" : "FAIL", failures);
    return failures;
}
