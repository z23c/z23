/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Shared-f multi-Miller loop with precomputed G2 lines versus the per-pair
 * bls12_381_miller_loop product. Requires bit equality of the Fp12 before the
 * final exponentiation and of the GT value after it, with lines for every
 * pair, for none, and for a mix; and requires groth16_verify with the VK's
 * precomputed lines to give the same verdict as the same VK without them on
 * valid, corrupted and identity-point proofs. */

#pragma GCC diagnostic ignored "-Wpedantic"

#include "test/test_core.h"
#include "sapling/bls12_381.h"
#include "../differential/pairing_corpus.h"

#include <stdio.h>

#define SM_PAIRS 4
#define SM_CASES 24

static uint64_t g_sm_state = 0x13198a2e03707344ULL;

static uint64_t sm_rnd(void)
{
    uint64_t z = (g_sm_state += 0x9e3779b97f4a7c15ULL);
    z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ULL;
    z = (z ^ (z >> 27)) * 0x94d049bb133111ebULL;
    return z ^ (z >> 31);
}

/* Scalars stay below 2^14 so the Groth16 relation holds over the integers. */
static uint64_t sm_small(void) { return (sm_rnd() % 16000) + 1; }

static void g1_mul_small(struct g1_point *r, const struct g1_point *g, uint64_t s)
{
    uint64_t k[4] = { s, 0, 0, 0 };
    g1_scalar_mul(r, g, k);
}

static void g2_mul_small(struct g2_point *r, const struct g2_point *g, uint64_t s)
{
    struct g2_point acc, base = *g;
    g2_identity(&acc);
    for (; s; s >>= 1) {
        struct g2_point t;
        if (s & 1) {
            g2_add(&t, &acc, &base);   /* g2_add is not alias-safe */
            acc = t;
        }
        g2_double(&t, &base);
        base = t;
    }
    *r = acc;
}

static bool fp12_same(const struct fp12 *a, const struct fp12 *b)
{
    return memcmp(a, b, sizeof(*a)) == 0;
}

/* lines_mode: 0 = no tables, 1 = every pair, 2 = alternating. */
static bool miller_case(const struct g1_point *g1, const struct g2_point *g2,
                        int lines_mode)
{
    struct g1_point p[SM_PAIRS];
    struct g2_point q[SM_PAIRS];
    struct g2_lines *tab[SM_PAIRS] = { NULL };
    const struct g2_lines *use[SM_PAIRS] = { NULL };
    for (int i = 0; i < SM_PAIRS; i++) {
        uint64_t sel = sm_rnd() % 8;
        if (sel == 0) g1_identity(&p[i]); else g1_mul_small(&p[i], g1, sm_small());
        sel = sm_rnd() % 8;
        if (sel == 0) g2_identity(&q[i]); else g2_mul_small(&q[i], g2, sm_small());
        if (lines_mode == 1 || (lines_mode == 2 && (i & 1))) {
            tab[i] = bls12_381_g2_lines_new(&q[i]);
            use[i] = tab[i];
        }
    }

    struct fp12 want, got, ml;
    fp12_one(&want);
    for (int i = 0; i < SM_PAIRS; i++) {
        if (g1_is_identity(&p[i]) || g2_is_identity(&q[i]))
            continue;
        bls12_381_miller_loop(&ml, &p[i], &q[i]);
        fp12_mul(&want, &want, &ml);
    }
    bool ok = bls12_381_multi_miller_shared(&got, p, q, use, SM_PAIRS);
    ok = ok && fp12_same(&want, &got);
    struct fp12 fe_want, fe_got;
    bls12_381_final_exp(&fe_want, &want);
    bls12_381_final_exp(&fe_got, &got);
    ok = ok && fp12_same(&fe_want, &fe_got);
    for (int i = 0; i < SM_PAIRS; i++)
        bls12_381_g2_lines_free(tab[i]);
    return ok;
}

static int miller_differential(void)
{
    struct g1_point g1;
    struct g2_point g2;
    if (!g1_from_compressed(&g1, PC_G1_GEN) || !g2_from_compressed(&g2, PC_G2_GEN))
        return 1;
    int bad = 0;
    for (int c = 0; c < SM_CASES; c++)
        for (int mode = 0; mode < 3; mode++)
            if (!miller_case(&g1, &g2, mode))
                bad++;
    return bad;
}

/* Valid proof: a*b = alpha*beta + x*gamma + c*delta over the integers, with
 * b = 1 so a is the whole right-hand side. */
struct gfix {
    struct g1_point g1, ic[2];
    struct g2_point g2;
    struct groth16_vk vk;
    struct groth16_proof pr;
    uint64_t input[1][4];
};

static bool gfix_build(struct gfix *f)
{
    memset(f, 0, sizeof(*f));
    if (!g1_from_compressed(&f->g1, PC_G1_GEN) ||
        !g2_from_compressed(&f->g2, PC_G2_GEN))
        return false;
    uint64_t alpha = sm_small(), beta = sm_small(), gamma = sm_small();
    uint64_t delta = sm_small(), u = sm_small(), w = sm_small();
    uint64_t x = sm_small(), c = sm_small();
    g1_mul_small(&f->ic[0], &f->g1, u);
    g1_mul_small(&f->ic[1], &f->g1, w);
    g1_mul_small(&f->vk.alpha_g1, &f->g1, alpha);
    g2_mul_small(&f->vk.beta_g2, &f->g2, beta);
    g2_mul_small(&f->vk.gamma_g2, &f->g2, gamma);
    g2_mul_small(&f->vk.delta_g2, &f->g2, delta);
    f->vk.ic = f->ic;
    f->vk.ic_len = 2;
    f->input[0][0] = x;
    uint64_t vkx = u + x * w;
    uint64_t a = alpha * beta + vkx * gamma + c * delta;
    g1_mul_small(&f->pr.a, &f->g1, a);
    f->pr.b = f->g2;
    g1_mul_small(&f->pr.c, &f->g1, c);
    return true;
}

static bool verdicts_agree(const struct groth16_vk *with, const struct groth16_vk *without,
                           const struct groth16_proof *pr, const uint64_t (*in)[4],
                           bool want)
{
    bool a = groth16_verify(with, pr, in, 1);
    bool b = groth16_verify(without, pr, in, 1);
    return a == b && a == want;
}

#define SM_VARIANTS 7

/* One proof variant: 0 valid, 1..3 corrupt A/C/B, 4 identity A, 5 identity B,
 * 6 wrong public input. Returns 1 when the two VKs disagree or the verdict is
 * not the expected one. */
static int proof_variant(const struct gfix *f, const struct groth16_vk *bare,
                         int kind)
{
    struct groth16_proof p = f->pr;
    uint64_t other[1][4] = { { f->input[0][0] + 1, 0, 0, 0 } };
    const uint64_t (*in)[4] = (const uint64_t (*)[4])f->input;
    switch (kind) {
    case 1: g1_add(&p.a, &p.a, &f->g1); break;
    case 2: g1_add(&p.c, &p.c, &f->g1); break;
    case 3: g2_double(&p.b, &f->pr.b); break;
    case 4: g1_identity(&p.a); break;
    case 5: g2_identity(&p.b); break;
    case 6: in = (const uint64_t (*)[4])other; break;
    default: break;
    }
    return verdicts_agree(&f->vk, bare, &p, in, kind == 0) ? 0 : 1;
}

static int groth16_differential(void)
{
    int bad = 0;
    for (int round = 0; round < 4; round++) {
        struct gfix f;
        if (!gfix_build(&f))
            return 1;
        if (!groth16_vk_build_combs(&f.vk) || !f.vk.g2_lines[0] ||
            !f.vk.g2_lines[1] || !f.vk.g2_lines[2])
            return 1;
        struct groth16_vk bare = f.vk;           /* same points, no lines */
        for (int i = 0; i < 3; i++)
            bare.g2_lines[i] = NULL;
        for (int kind = 0; kind < SM_VARIANTS; kind++)
            bad += proof_variant(&f, &bare, kind);
        groth16_vk_free_combs(&f.vk);
        groth16_vk_free_combs(&f.vk);              /* double free is safe */
        if (f.vk.g2_lines[0] || f.vk.g2_lines[1] || f.vk.g2_lines[2]) bad++;
    }
    return bad;
}

int test_bls12_381_shared_miller(void);
int test_bls12_381_shared_miller(void)
{
    int failures = 0;
    printf("bls12_381_shared_miller: shared-f vs per-pair Miller + final exp... ");
    int bad = miller_differential();
    if (bad == 0) printf("PASS\n");
    else { printf("FAIL (%d)\n", bad); failures++; }

    printf("bls12_381_shared_miller: groth16_verify with vs without lines... ");
    bad = groth16_differential();
    if (bad == 0) printf("PASS\n");
    else { printf("FAIL (%d)\n", bad); failures++; }
    return failures;
}
