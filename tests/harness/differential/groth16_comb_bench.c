/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Differential bench + profile harness for the Sapling Groth16 verifier.
 * Three modes, all driven by tests/harness/differential/run_parity_oracle.sh:
 *
 *   comb     Groth16 verify timing: naive public-input scalar-mul vs the
 *            precomputed fixed-base tables. Both paths run in ONE process
 *            against the SAME synthetic verifying key, so the reported ratio
 *            is a direct before/after and needs no rebuild, no checkout, and
 *            no live node.
 *
 *   pairing  VALUE-equality differential for the pairing itself — the
 *            apparatus the pairing restructure is gated on. See the block
 *            comment above pairing_mode().
 *
 *   profile  Where the 7.7 ms actually goes: exact field-multiplication
 *            counts per phase (Miller loop / final exponentiation / public-
 *            input MSM / the affine inversions) plus per-phase wall time.
 *            See the block comment above profile_mode().
 *
 * The public-input count is what the Sapling consensus circuits actually use —
 * 7 for SPEND (sapling.c:664), 5 for OUTPUT (sapling.c:749) — and verify cost
 * is 4 pairings plus one scalar-mul per non-zero input regardless of which
 * curve points the bases are, so a synthetic key measures the real shape.
 *
 * Verdicts are asserted equal on every iteration: a timing run that silently
 * diverged would be worthless. Correctness itself is gated by
 * make check-groth16-parity and test_groth16_msm_parity.
 */

#include "pairing_corpus.h"

#include "sapling/bls12_381.h"
#include "util/log_level.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* ── exact field-multiplication counter ──────────────────────────────
 *
 * bls12_381.c routes EVERY Fp multiply and square through one cross-TU call
 * (`#define fp_mont_mul fp_mont_mul_accel`, defined in fr_avx512.c), so the
 * linker can interpose it with -Wl,--wrap and count exactly, with no edit to
 * the consensus source. That matters here: bls12_381.c is frozen for this job
 * and owned by the pairing restructure. An instrumentation scheme that needed
 * a counter INSIDE the verifier would either not exist or would have to be
 * merged into someone else's in-flight change.
 *
 * The wrapper adds one call layer per multiply, so the timings this build
 * reports are INFLATED. It measures its own fp_mul cost under the same
 * inflation, which keeps every count x cost attribution internally
 * consistent; absolute wall times come from the uninstrumented build, and the
 * script prints both. */
#ifdef ZCL_FPMUL_COUNT
extern void __real_fp_mont_mul_accel(uint64_t r[6], const uint64_t a[6],
                                     const uint64_t b[6]);
static unsigned long long g_fp_mul_calls;
void __wrap_fp_mont_mul_accel(uint64_t r[6], const uint64_t a[6],
                              const uint64_t b[6]);
void __wrap_fp_mont_mul_accel(uint64_t r[6], const uint64_t a[6],
                              const uint64_t b[6])
{
    g_fp_mul_calls++;
    __real_fp_mont_mul_accel(r, a, b);
}
#define FPMUL_COUNT_AVAILABLE 1
static inline unsigned long long fpmul_count(void) { return g_fp_mul_calls; }
#else
#define FPMUL_COUNT_AVAILABLE 0
static inline unsigned long long fpmul_count(void) { return 0; }
#endif

#define MAX_K 8

static volatile uint64_t g_sink;

static uint64_t now_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);  // platform-ok:standalone-bench-links-no-platform-clock
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

/* ════════════════════════════════════════════════════════════════════
 *  comb mode — naive vs fixed-base public-input paths
 * ════════════════════════════════════════════════════════════════════ */

/* Full-width, non-trivial public inputs: a small scalar would understate the
 * naive path, which always walks all 256 bits. */
static void fill_inputs(uint64_t (*inputs)[4], size_t k)
{
    for (size_t i = 0; i < k; i++) {
        inputs[i][0] = 0x9E3779B97F4A7C15ULL ^ (uint64_t)(i + 1);
        inputs[i][1] = 0xBF58476D1CE4E5B9ULL + (uint64_t)i;
        inputs[i][2] = 0x94D049BB133111EBULL ^ (uint64_t)(i * 7 + 3);
        inputs[i][3] = 0x0339d80809a1d805ULL + (uint64_t)i;  /* < r */
    }
}

/* Build a synthetic-but-real-shaped VK + a proof that VERIFIES under it, so
 * both paths run the full pairing check rather than short-circuiting on an
 * early reject. Shared by comb mode and the teeth checks. */
struct fixture {
    struct g1_point G1, ic[MAX_K + 1];
    struct g2_point G2;
    struct groth16_vk vk;
    struct groth16_proof pr;
    uint64_t inputs[MAX_K][4];
    size_t k;
};

static bool fixture_build(struct fixture *f, size_t k)
{
    memset(f, 0, sizeof(*f));
    f->k = k;
    if (!g1_from_compressed(&f->G1, PC_G1_GEN) ||
        !g2_from_compressed(&f->G2, PC_G2_GEN)) {
        fprintf(stderr, "generator decode failed\n");
        return false;
    }
    g1_identity(&f->ic[0]);
    for (size_t i = 1; i <= k; i++) {
        uint64_t m[4] = { (uint64_t)(7 * i + 1), 0, 0, 0 };
        g1_scalar_mul(&f->ic[i], &f->G1, m);
    }
    f->vk.alpha_g1 = f->G1;
    f->vk.beta_g2 = f->G2;
    f->vk.gamma_g2 = f->G2;
    f->vk.delta_g2 = f->G2;
    f->vk.ic = f->ic;
    f->vk.ic_len = k + 1;
    f->vk.ic_combs = NULL;

    fill_inputs(f->inputs, k);

    /* C = -vk_x makes the proof verify. */
    struct g1_point vk_x = f->ic[0];
    for (size_t i = 0; i < k; i++) {
        struct g1_point term;
        g1_scalar_mul(&term, &f->ic[i + 1], f->inputs[i]);
        g1_add(&vk_x, &vk_x, &term);
    }
    f->pr.a = f->G1;
    f->pr.b = f->G2;
    g1_neg(&f->pr.c, &vk_x);
    return true;
}

static int bench_one(const char *name, size_t k, int iters)
{
    struct fixture f;
    if (!fixture_build(&f, k)) return 1;
    struct groth16_vk vk = f.vk;
    vk.ic = f.ic;

    /* Naive path. */
    vk.ic_combs = NULL;
    if (!groth16_verify(&vk, &f.pr, (const uint64_t (*)[4])f.inputs, k)) {
        fprintf(stderr, "%s: naive path rejected a valid proof\n", name);
        return 1;
    }
    uint64_t t0 = now_ns();
    for (int i = 0; i < iters; i++)
        if (!groth16_verify(&vk, &f.pr, (const uint64_t (*)[4])f.inputs, k)) {
            fprintf(stderr, "%s: naive verdict flipped mid-run\n", name);
            return 1;
        }
    uint64_t naive_ns = (now_ns() - t0) / (uint64_t)iters;

    /* Fixed-base path (table build is one-time at VK load, excluded). */
    uint64_t b0 = now_ns();
    if (!groth16_vk_build_combs(&vk)) {
        fprintf(stderr, "%s: build_combs failed\n", name);
        return 1;
    }
    uint64_t build_ns = now_ns() - b0;

    if (!groth16_verify(&vk, &f.pr, (const uint64_t (*)[4])f.inputs, k)) {
        fprintf(stderr, "%s: fixed-base path rejected a proof the naive path "
                        "accepted — CONSENSUS BREAK\n", name);
        groth16_vk_free_combs(&vk);
        return 1;
    }
    t0 = now_ns();
    for (int i = 0; i < iters; i++)
        if (!groth16_verify(&vk, &f.pr, (const uint64_t (*)[4])f.inputs, k)) {
            fprintf(stderr, "%s: fixed-base verdict flipped mid-run — "
                            "CONSENSUS BREAK\n", name);
            groth16_vk_free_combs(&vk);
            return 1;
        }
    uint64_t comb_ns = (now_ns() - t0) / (uint64_t)iters;
    groth16_vk_free_combs(&vk);

    printf("%-22s k=%zu  naive %8.3f ms   fixed-base %8.3f ms   "
           "%.2fx  (-%.1f%%)   one-time table build %.1f ms\n",
           name, k, naive_ns / 1e6, comb_ns / 1e6,
           (double)naive_ns / (double)comb_ns,
           100.0 * (1.0 - (double)comb_ns / (double)naive_ns),
           build_ns / 1e6);
    return 0;
}

static int comb_mode(int iters)
{
    int rc = 0;
    rc |= bench_one("sapling OUTPUT verify", 5, iters);
    rc |= bench_one("sapling SPEND verify", 7, iters);
    return rc;
}

/* ════════════════════════════════════════════════════════════════════
 *  TEETH — run before ANY number is printed, in every mode
 * ════════════════════════════════════════════════════════════════════
 *
 * A benchmark of a hollow function is worse than no benchmark: it converts
 * "we deleted the check" into "we got 40x faster". So before this harness
 * reports a single nanosecond it proves the thing it is timing still bites:
 *
 *   T1  a valid proof VERIFIES                    (not always-false)
 *   T2  one flipped bit in a public input REJECTS (not always-true)
 *   T3  one flipped bit in proof.c REJECTS        (not ignoring the proof)
 *   T4  e(P,Q) != 1                               (pairing is not a no-op)
 *   T5  e(P,Q) != e([2]P,Q)                       (comparator distinguishes)
 *   T6  the 4-pairing GT product of a VALID proof IS exactly 1, and is NOT 1
 *       once an input bit flips — the value-level form of T1/T2, which is
 *       what makes the Fp12 comparison below meaningful rather than decorative
 *
 * Any failure returns non-zero and NOTHING is timed. Weakening one of these to
 * make a run go green is the exact failure mode this apparatus exists to stop.
 */
static bool gt_product_of_verify(struct fp12 *out, const struct fixture *f,
                                 const uint64_t (*inputs)[4])
{
    struct g1_point vk_x = f->vk.ic[0];
    for (size_t i = 0; i < f->k; i++) {
        if (!inputs[i][0] && !inputs[i][1] && !inputs[i][2] && !inputs[i][3])
            continue;
        struct g1_point term;
        g1_scalar_mul(&term, &f->vk.ic[i + 1], inputs[i]);
        g1_add(&vk_x, &vk_x, &term);
    }
    struct g2_point neg_gamma, neg_delta;
    g2_neg(&neg_gamma, &f->vk.gamma_g2);
    g2_neg(&neg_delta, &f->vk.delta_g2);
    struct g1_point neg_alpha;
    g1_neg(&neg_alpha, &f->vk.alpha_g1);

    const struct g1_point p[4] = { f->pr.a, vk_x, f->pr.c, neg_alpha };
    const struct g2_point q[4] = { f->pr.b, neg_gamma, neg_delta,
                                   f->vk.beta_g2 };
    struct fp12 acc;
    fp12_one(&acc);
    for (int i = 0; i < 4; i++) {
        struct fp12 e;
        bls12_381_pairing(&e, &p[i], &q[i]);
        fp12_mul(&acc, &acc, &e);
    }
    *out = acc;
    return true;
}

static int teeth_check(void)
{
    struct fixture f;
    if (!fixture_build(&f, 5)) return 1;
    struct groth16_vk vk = f.vk;
    int fails = 0;

    /* T1 */
    if (!groth16_verify(&vk, &f.pr, (const uint64_t (*)[4])f.inputs, f.k)) {
        fprintf(stderr, "TEETH FAIL T1: valid proof did not verify\n");
        fails++;
    }
    /* T2 — one bit flipped in public input 0 */
    uint64_t bad[MAX_K][4];
    memcpy(bad, f.inputs, sizeof(bad));
    bad[0][0] ^= 1ULL;
    if (groth16_verify(&vk, &f.pr, (const uint64_t (*)[4])bad, f.k)) {
        fprintf(stderr, "TEETH FAIL T2: one-bit-flipped public input still "
                        "verified — the verifier is hollow, refusing to time "
                        "it\n");
        fails++;
    }
    /* T3 — one bit flipped in proof.c */
    struct groth16_proof badpr = f.pr;
    badpr.c.x.d[0] ^= 1ULL;
    if (groth16_verify(&vk, &badpr, (const uint64_t (*)[4])f.inputs, f.k)) {
        fprintf(stderr, "TEETH FAIL T3: one-bit-flipped proof.c still "
                        "verified\n");
        fails++;
    }
    /* T4 / T5 */
    struct g1_point g1, g1x2;
    struct g2_point g2;
    if (!g1_from_compressed(&g1, PC_G1_GEN) ||
        !g2_from_compressed(&g2, PC_G2_GEN)) {
        fprintf(stderr, "TEETH FAIL: generator decode\n");
        return 1;
    }
    const uint64_t two[4] = { 2, 0, 0, 0 };
    g1_scalar_mul(&g1x2, &g1, two);
    struct fp12 e1, e2, one;
    fp12_one(&one);
    bls12_381_pairing(&e1, &g1, &g2);
    bls12_381_pairing(&e2, &g1x2, &g2);
    if (pc_fp12_first_diff(&e1, &one) < 0) {
        fprintf(stderr, "TEETH FAIL T4: e(G1,G2) == 1 — pairing is a no-op\n");
        fails++;
    }
    if (pc_fp12_first_diff(&e1, &e2) < 0) {
        fprintf(stderr, "TEETH FAIL T5: e(G1,G2) == e([2]G1,G2) — the Fp12 "
                        "comparator cannot distinguish distinct pairings\n");
        fails++;
    }
    /* T6 */
    struct fp12 prod_ok, prod_bad;
    gt_product_of_verify(&prod_ok, &f, (const uint64_t (*)[4])f.inputs);
    gt_product_of_verify(&prod_bad, &f, (const uint64_t (*)[4])bad);
    if (pc_fp12_first_diff(&prod_ok, &one) >= 0) {
        fprintf(stderr, "TEETH FAIL T6a: GT product of a VALID proof is not "
                        "exactly 1\n");
        fails++;
    }
    if (pc_fp12_first_diff(&prod_bad, &one) < 0) {
        fprintf(stderr, "TEETH FAIL T6b: GT product with a flipped input bit "
                        "is still exactly 1\n");
        fails++;
    }
    if (fails) {
        fprintf(stderr, "TEETH: %d check(s) failed — NO NUMBERS REPORTED\n",
                fails);
        return 1;
    }
    printf("teeth: T1..T6 pass (valid verifies, one-bit flips reject, "
           "pairing non-trivial, GT product of a valid proof is exactly 1)\n");
    return 0;
}

/* ════════════════════════════════════════════════════════════════════
 *  pairing mode — FIELD-ELEMENT BIT EQUALITY, not verdict equality
 * ════════════════════════════════════════════════════════════════════
 *
 * The comb bench above asserts VERDICT equality. That is the right bar for a
 * public-input MSM (a different group element there always flips the verdict
 * on the fixture). It is NOT a sufficient bar for restructuring the pairing.
 *
 * A verdict is one bit distilled from a 576-byte Fp12 element. Two pairing
 * implementations can agree on every accept/reject in a finite corpus and
 * still compute different GT elements — the corpus is finite, the chain is
 * not, and the first block where they disagree forks this node off the
 * network permanently. Verdict equality throws away 4607 of the 4608 bits of
 * evidence each vector produces.
 *
 * The restructured pairing is SUPPOSED to compute the identical field
 * element — a regrouping of the same arithmetic, not a different function —
 * so the stronger assertion is AVAILABLE, and therefore it is the one used
 * here: byte-exact equality of the canonically serialized Fp12
 * (pc_fp12_to_bytes: out of Montgomery form, fully reduced, big-endian, so
 * the check is immune to representation changes in both directions).
 *
 * ┌──────────────────────────────────────────────────────────────────┐
 * │ IF BIT EQUALITY CANNOT BE MADE TO HOLD, THAT IS THE SIGNAL TO    │
 * │ ABANDON THE OPTIMIZATION.                                        │
 * │                                                                  │
 * │ It is NOT a signal to fall back to verdict equality. It is NOT a │
 * │ signal to shrink the corpus, relax the comparison to "same up to │
 * │ representation", or move the assertion behind a flag. A pairing   │
 * │ that lands on a different GT element is a different consensus     │
 * │ rule wearing the old rule's verdicts on the vectors we happened   │
 * │ to write down. Revert the change; the speed is not worth the      │
 * │ fork.                                                            │
 * └──────────────────────────────────────────────────────────────────┘
 */
static int pairing_mode(int iters)
{
    struct pc_vec v[PC_MAX_VECS];
    size_t n = pc_build(v);
    if (n == 0) {
        fprintf(stderr, "pairing corpus build failed\n");
        return 1;
    }

    const bool have_cand = pc_have_candidate();
    printf("\npairing differential — %zu vectors, Fp12 BIT equality\n", n);
    if (have_cand) {
        printf("  candidate: bls12_381_pairing_candidate (linked)\n");
    } else {
        printf("  candidate: ABSENT — bls12_381_pairing_candidate is not "
               "defined.\n"
               "             Comparing the shipping pairing to ITSELF: this "
               "run proves the\n"
               "             comparator, corpus and teeth work, and proves "
               "NOTHING about any\n"
               "             optimization. Define the symbol in "
               "core/modules/sapling/src/bls12_381.c\n"
               "             to arm the real differential.\n");
    }

    int diffs = 0;
    uint64_t base_total = 0, cand_total = 0;
    for (size_t i = 0; i < n; i++) {
        struct fp12 a, b;
        uint64_t t0 = now_ns();
        for (int it = 0; it < iters; it++) {
            bls12_381_pairing(&a, &v[i].p, &v[i].q);
            g_sink += a.c0.c0.c0.d[0];
        }
        base_total += (now_ns() - t0) / (uint64_t)iters;

        t0 = now_ns();
        for (int it = 0; it < iters; it++) {
            if (have_cand) bls12_381_pairing_candidate(&b, &v[i].p, &v[i].q);
            else           bls12_381_pairing(&b, &v[i].p, &v[i].q);
            g_sink += b.c0.c0.c0.d[0];
        }
        cand_total += (now_ns() - t0) / (uint64_t)iters;

        int d = pc_fp12_first_diff(&a, &b);
        if (d >= 0) {
            uint8_t ba[PC_FP12_BYTES], bb[PC_FP12_BYTES];
            pc_fp12_to_bytes(ba, &a);
            pc_fp12_to_bytes(bb, &b);
            fprintf(stderr,
                    "VALUE DIVERGENCE [%s]: Fp12 coefficient %s, byte %d: "
                    "baseline %02x candidate %02x\n"
                    "  -> the restructured pairing computes a DIFFERENT field "
                    "element.\n"
                    "  -> ABANDON the optimization. Do not weaken this check.\n",
                    v[i].label, pc_fp12_coeff_name(d), d, ba[d], bb[d]);
            diffs++;
        } else {
            printf("  ok  %-40s  all %d Fp12 bytes identical\n",
                   v[i].label, PC_FP12_BYTES);
        }
    }

    printf("\n  baseline  %8.3f ms/pairing (mean over %zu vectors)\n",
           (double)base_total / (double)n / 1e6, n);
    printf("  candidate %8.3f ms/pairing%s\n",
           (double)cand_total / (double)n / 1e6,
           have_cand ? "" : "  [same code — not a measurement]");
    if (have_cand && cand_total)
        printf("  speedup   %.3fx\n",
               (double)base_total / (double)cand_total);

    if (diffs) {
        fprintf(stderr,
                "\nPAIRING VALUE PARITY FAILED: %d/%zu vectors diverge.\n",
                diffs, n);
        return 1;
    }
    printf("\nPAIRING VALUE PARITY OK: %zu/%zu vectors bit-identical%s\n",
           n, n, have_cand ? "" : " (candidate absent — tautology)");
    return 0;
}

/* ════════════════════════════════════════════════════════════════════
 *  profile mode — where the 7.7 ms actually goes
 * ════════════════════════════════════════════════════════════════════
 *
 * A naive operation count of this algorithm predicts roughly 2 ms per verify;
 * the measured number is ~7.7 ms. Nobody should optimize a layer until that
 * ~3.6x is explained, because the naive count and the measurement disagree
 * about WHICH layer is expensive.
 *
 * Phase decomposition uses only the PUBLIC API, so it needs no edit to the
 * frozen verifier:
 *
 *   bls12_381_multi_pairing_check(pts, qts, 0)  = exactly one final
 *       exponentiation over Fp12(1). The loop body never runs.
 *   ...(pts, qts, n) - ...(pts, qts, n-1)       = exactly one Miller loop
 *       plus one fp12_mul.
 *   fp12_mul measured directly (exposed) and subtracted.
 *   groth16_verify - (4 Miller + 4 fp12_mul + 1 final exp) = the public-input
 *       MSM plus the three negations.
 *
 * The same decomposition is run twice: once counting Fp multiplies exactly
 * (linker-interposed, see the top of this file) and once for wall time. Cost
 * attribution (count x measured-cost) is computed inside ONE build so the
 * instrumentation overhead cancels; absolute milliseconds come from the
 * uninstrumented build.
 */
struct phase {
    const char *name;
    unsigned long long muls;
    double ns;
};

static void time_phase(double *ns_out, void (*fn)(void *), void *arg,
                       int iters)
{
    fn(arg); /* warm */
    uint64_t t0 = now_ns();
    for (int i = 0; i < iters; i++) fn(arg);
    *ns_out = (double)(now_ns() - t0) / (double)iters;
}

struct mp_arg { struct g1_point p[8]; struct g2_point q[8]; size_t n; };
static void run_mp(void *a)
{
    struct mp_arg *m = a;
    g_sink += bls12_381_multi_pairing_check(m->p, m->q, m->n) ? 1u : 2u;
}

struct vfy_arg { struct fixture f; };
static void run_vfy(void *a)
{
    struct vfy_arg *v = a;
    g_sink += groth16_verify(&v->f.vk, &v->f.pr,
                             (const uint64_t (*)[4])v->f.inputs, v->f.k)
              ? 1u : 2u;
}

struct fp12mul_arg { struct fp12 a, b, r; };
static void run_fp12mul(void *a)
{
    struct fp12mul_arg *x = a;
    fp12_mul(&x->r, &x->a, &x->b);
    g_sink += x->r.c0.c0.c0.d[0];
}

struct fpmul_arg { struct fp a, b, r; };
static void run_fpmul(void *a)
{
    struct fpmul_arg *x = a;
    fp_mul(&x->r, &x->a, &x->b);
    g_sink += x->r.d[0];
}

struct fpinv_arg { struct fp a, r; };
static void run_fpinv(void *a)
{
    struct fpinv_arg *x = a;
    fp_inv(&x->r, &x->a);
    g_sink += x->r.d[0];
}

struct g1aff_arg { struct g1_point p; struct fp x, y; };
static void run_g1aff(void *a)
{
    struct g1aff_arg *g = a;
    g1_to_affine(&g->x, &g->y, &g->p);
    g_sink += g->x.d[0];
}

struct g2aff_arg { struct g2_point p; struct fp2 x, y; };
static void run_g2aff(void *a)
{
    struct g2aff_arg *g = a;
    g2_to_affine(&g->x, &g->y, &g->p);
    g_sink += g->x.c0.d[0];
}

/* Count Fp multiplies over one invocation of fn(arg). Returns 0 when the
 * build is uninstrumented. */
static unsigned long long count_muls(void (*fn)(void *), void *arg)
{
    unsigned long long before = fpmul_count();
    fn(arg);
    return fpmul_count() - before;
}

static int profile_mode(int iters)
{
    struct fixture f;
    if (!fixture_build(&f, 5)) return 1;

    struct mp_arg mp;
    {
        struct g1_point g1;
        struct g2_point g2;
        if (!g1_from_compressed(&g1, PC_G1_GEN) ||
            !g2_from_compressed(&g2, PC_G2_GEN)) return 1;
        for (size_t i = 0; i < 8; i++) {
            uint64_t s[4] = { (uint64_t)(2 * i + 3), 0, 0, 0 };
            g1_scalar_mul(&mp.p[i], &g1, s);
            uint64_t t[4] = { (uint64_t)(3 * i + 5), 0, 0, 0 };
            pc_g2_mul(&mp.q[i], &g2, t);
        }
    }

    struct vfy_arg va = { .f = f };
    struct fp12mul_arg m12 = {0};
    bls12_381_pairing(&m12.a, &mp.p[0], &mp.q[0]);
    bls12_381_pairing(&m12.b, &mp.p[1], &mp.q[1]);
    struct fpmul_arg mfp = {0};
    fp_from_bytes(&mfp.a, PC_G1_GEN + 0);       /* arbitrary in-range Fp */
    mfp.a.d[5] &= 0x0FFFFFFFFFFFFFFFULL;
    fp_one(&mfp.b);
    fp_add(&mfp.b, &mfp.b, &mfp.a);
    struct fpinv_arg minv = { .a = mfp.a };
    struct g1aff_arg ga1 = { .p = mp.p[0] };
    struct g2aff_arg ga2 = { .p = mp.q[0] };

    /* ── exact multiplication counts ── */
    printf("\nprofile — Groth16 verify (k=5, sapling OUTPUT shape)\n");
    printf("  fixture: synthetic VK. Constructing a proof that VERIFIES without\n"
           "  a trapdoor forces beta=gamma=delta and alpha=proof.a, so the four\n"
           "  Miller loops here share G2 arguments. The MULTIPLY COUNTS are\n"
           "  exact for this shape and the phase SHARES are the real ones;\n"
           "  absolute ms run below production sapling_check_output, which also\n"
           "  pays proof decompression (2 fp_sqrt + 1 fp2_sqrt) and the jubjub\n"
           "  public-input prep. Optimize against the shares, not these ms.\n");
#if FPMUL_COUNT_AVAILABLE
    unsigned long long c_fpmul_self, c_fpinv, c_g1aff, c_g2aff;
    unsigned long long c_fp12mul, c_mp0, c_mp1, c_mp4, c_vfy;
    c_fpmul_self = count_muls(run_fpmul, &mfp);
    c_fpinv      = count_muls(run_fpinv, &minv);
    c_g1aff      = count_muls(run_g1aff, &ga1);
    c_g2aff      = count_muls(run_g2aff, &ga2);
    c_fp12mul    = count_muls(run_fp12mul, &m12);
    mp.n = 0; c_mp0 = count_muls(run_mp, &mp);
    mp.n = 1; c_mp1 = count_muls(run_mp, &mp);
    mp.n = 4; c_mp4 = count_muls(run_mp, &mp);
    c_vfy        = count_muls(run_vfy, &va);

    unsigned long long c_miller = c_mp1 - c_mp0 - c_fp12mul;
    unsigned long long c_finalexp = c_mp0;
    long long c_msm = (long long)c_vfy - (long long)c_mp4;

    printf("  Fp multiplies (EXACT, linker-interposed fp_mont_mul_accel):\n");
    printf("    fp_mul / fp_sq (self-check)        %10llu   (must be 1)\n",
           c_fpmul_self);
    printf("    fp_inv           (Fermat q-2 pow)  %10llu\n", c_fpinv);
    printf("    g1_to_affine                       %10llu\n", c_g1aff);
    printf("    g2_to_affine                       %10llu\n", c_g2aff);
    printf("    fp12_mul                           %10llu\n", c_fp12mul);
    printf("    ONE Miller loop                    %10llu   "
           "(of which %llu = the two to-affine inversions, %.1f%%)\n",
           c_miller, c_g1aff + c_g2aff,
           100.0 * (double)(c_g1aff + c_g2aff) / (double)c_miller);
    printf("    ONE final exponentiation           %10llu\n", c_finalexp);
    printf("    public-input MSM + negations       %10lld\n", c_msm);
    printf("    ---------------------------------------------\n");
    printf("    FULL groth16_verify                %10llu\n", c_vfy);
    printf("      = 4 Miller (%llu) + 4 fp12_mul (%llu) + final exp (%llu)"
           " + MSM (%lld)\n",
           4 * c_miller, 4 * c_fp12mul, c_finalexp, c_msm);
#else
    printf("  Fp multiply counts: NOT AVAILABLE in this build "
           "(rebuild with -DZCL_FPMUL_COUNT -Wl,--wrap=fp_mont_mul_accel)\n");
#endif

    /* ── wall time per phase ── */
    double t_fpmul, t_fpinv, t_fp12mul, t_mp0, t_mp1, t_mp4, t_vfy;
    time_phase(&t_fpmul, run_fpmul, &mfp, iters * 2000);
    time_phase(&t_fpinv, run_fpinv, &minv, iters * 4);
    time_phase(&t_fp12mul, run_fp12mul, &m12, iters * 200);
    mp.n = 0; time_phase(&t_mp0, run_mp, &mp, iters);
    mp.n = 1; time_phase(&t_mp1, run_mp, &mp, iters);
    mp.n = 4; time_phase(&t_mp4, run_mp, &mp, iters);
    time_phase(&t_vfy, run_vfy, &va, iters);

    double t_miller = t_mp1 - t_mp0 - t_fp12mul;
    double t_finalexp = t_mp0;
    double t_msm = t_vfy - t_mp4;

    printf("\n  wall time%s:\n",
           FPMUL_COUNT_AVAILABLE
               ? " (INSTRUMENTED build — inflated; ratios still valid)" : "");
    printf("    fp_mul                             %10.1f ns\n", t_fpmul);
    printf("    fp_inv                             %10.1f ns   "
           "(= %.0f fp_mul)\n", t_fpinv, t_fpinv / t_fpmul);
    printf("    fp12_mul                           %10.1f ns\n", t_fp12mul);
    printf("    ONE Miller loop                    %10.3f ms\n",
           t_miller / 1e6);
    printf("    ONE final exponentiation           %10.3f ms\n",
           t_finalexp / 1e6);
    printf("    public-input MSM + negations       %10.3f ms\n", t_msm / 1e6);
    printf("    ---------------------------------------------\n");
    printf("    FULL groth16_verify                %10.3f ms\n", t_vfy / 1e6);
    printf("    share: Miller %.1f%%   final-exp %.1f%%   MSM %.1f%%\n",
           100.0 * 4.0 * t_miller / t_vfy,
           100.0 * t_finalexp / t_vfy,
           100.0 * t_msm / t_vfy);

#if FPMUL_COUNT_AVAILABLE
    double predicted = (double)c_vfy * t_fpmul;
    printf("\n  cost model reconciliation (this build, so overhead cancels):\n");
    printf("    %llu Fp muls x %.1f ns              = %10.3f ms predicted\n",
           c_vfy, t_fpmul, predicted / 1e6);
    printf("    measured                             = %10.3f ms\n",
           t_vfy / 1e6);
    printf("    Fp-mul share of verify               = %10.1f%%\n",
           100.0 * predicted / t_vfy);
    printf("    residual (adds/subs/copies/branches) = %10.1f%%\n",
           100.0 * (1.0 - predicted / t_vfy));
#endif
    return 0;
}

/* ════════════════════════════════════════════════════════════════════ */

static void usage(const char *argv0)
{
    fprintf(stderr,
            "usage: %s [comb|pairing|profile|all] [iters]\n"
            "       %s <iters>          (legacy: comb mode)\n",
            argv0, argv0);
}

int main(int argc, char **argv)
{
    zcl_log_level_set(ZCL_LOG_OFF);

    const char *mode = "comb";
    int iters = 30;
    if (argc > 1) {
        if (argv[1][0] >= '0' && argv[1][0] <= '9') {
            iters = atoi(argv[1]);            /* legacy positional iters */
        } else {
            mode = argv[1];
            if (argc > 2) iters = atoi(argv[2]);
        }
    }
    if (iters < 1) iters = 1;

    /* Teeth first, always. No mode prints a number before the verifier has
     * proven it still accepts what it must and rejects what it must. */
    if (teeth_check() != 0) return 1;

    if (strcmp(mode, "comb") == 0)    return comb_mode(iters);
    if (strcmp(mode, "pairing") == 0) return pairing_mode(iters);
    if (strcmp(mode, "profile") == 0) return profile_mode(iters);
    if (strcmp(mode, "all") == 0) {
        int rc = 0;
        rc |= comb_mode(iters);
        rc |= pairing_mode(iters);
        rc |= profile_mode(iters);
        return rc;
    }
    usage(argv[0]);
    return 2;
}
