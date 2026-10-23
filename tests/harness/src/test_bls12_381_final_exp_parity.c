/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * ACCEL-ORACLE: core/modules/sapling/src/bls12_381.c
 * Parity of the BLS12-381 final exponentiation (Granger-Scott cyclotomic
 * squaring in the hard part) against the FROZEN generic-squaring version in
 * tests/harness/differential/bls12_381_oracle_frozen.c (oracle_ prefix,
 * never edited). Byte-for-byte via pc_fp12_to_bytes on deterministic inputs
 * (0, 1, conjugates, real Miller-loop outputs, random Fp12), plus a direct
 * check fp12_cyclotomic_sq == fp12_sq on subgroup elements.
 * (A one-off 100000-input pass was run by raising FE_DEFAULT_RANDOM locally.) */

#pragma GCC diagnostic ignored "-Wpedantic"

#include "test/test_core.h"
#include "sapling/bls12_381.h"
#define ORACLE_WITH_FINAL_EXP 1
#pragma GCC diagnostic ignored "-Wunused-function"
#pragma GCC diagnostic ignored "-Wunused-const-variable"
#include "../differential/bls12_381_oracle_frozen.c"
#include "../differential/pairing_corpus.h"

#include <stdio.h>

#define FE_DEFAULT_RANDOM 2000ULL
#define FE_SQ_CHECKS 1000

static uint64_t g_state = 0x243f6a8885a308d3ULL;

static uint64_t rnd(void)
{
    uint64_t z = (g_state += 0x9e3779b97f4a7c15ULL);
    z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ULL;
    z = (z ^ (z >> 27)) * 0x94d049bb133111ebULL;
    return z ^ (z >> 31);
}

static void rnd_fp(struct fp *r)
{
    uint8_t b[48];
    for (int i = 0; i < 48; i += 8) {
        uint64_t v = rnd();
        memcpy(b + i, &v, 8);
    }
    b[0] &= 0x0f; /* < q */
    if (!fp_from_bytes(r, b)) fp_zero(r);
}

static void rnd_fp12(struct fp12 *r)
{
    struct fp *c[12] = {
        &r->c0.c0.c0, &r->c0.c0.c1, &r->c0.c1.c0, &r->c0.c1.c1,
        &r->c0.c2.c0, &r->c0.c2.c1, &r->c1.c0.c0, &r->c1.c0.c1,
        &r->c1.c1.c0, &r->c1.c1.c1, &r->c1.c2.c0, &r->c1.c2.c1,
    };
    for (int i = 0; i < 12; i++) rnd_fp(c[i]);
}

static bool same(const struct fp12 *a, const struct fp12 *b)
{
    return pc_fp12_first_diff(a, b) < 0;
}

static bool one_input(const struct fp12 *in)
{
    struct fp12 x, y;
    bls12_381_final_exp(&x, in);
    oracle_bls12_381_final_exp(&y, in);
    return same(&x, &y);
}

static bool structured_inputs(void)
{
    struct fp12 f, c;
    fp12_zero(&f);
    if (!one_input(&f)) return false;
    fp12_one(&f);
    if (!one_input(&f)) return false;
    struct pc_vec v[PC_MAX_VECS];
    size_t n = pc_build(v);
    if (n == 0) return false;
    for (size_t i = 0; i < n; i++) {
        bls12_381_miller_loop(&f, &v[i].p, &v[i].q);
        c = f;
        fp12_conjugate(&c);
        if (!one_input(&f) || !one_input(&c)) return false;
    }
    return true;
}

static bool random_inputs(uint64_t count)
{
    for (uint64_t k = 0; k < count; k++) {
        struct fp12 f, c;
        rnd_fp12(&f);
        if (!one_input(&f)) {
            printf("  mismatch at input %llu\n", (unsigned long long)k);
            return false;
        }
        if ((k & 15) == 0) {
            c = f;
            fp12_conjugate(&c);
            if (!one_input(&c)) return false;
        }
    }
    return true;
}

/* Easy part: maps any nonzero f into the cyclotomic subgroup. */
static void to_subgroup(struct fp12 *r, const struct fp12 *f)
{
    struct fp12 c = *f, inv, t;
    fp12_conjugate(&c);
    fp12_inv(&inv, f);
    fp12_mul(r, &c, &inv);
    t = *r;
    fp12_frobenius_map(r, 2);
    fp12_mul(r, r, &t);
}

static bool cyclotomic_sq_checks(void)
{
    for (int k = 0; k < FE_SQ_CHECKS; k++) {
        struct fp12 f, g, x, y;
        rnd_fp12(&f);
        to_subgroup(&g, &f);
        fp12_cyclotomic_sq(&x, &g);
        fp12_sq(&y, &g);
        if (!same(&x, &y)) return false;
        fp12_cyclotomic_sq(&g, &g); /* aliasing r == a */
        if (!same(&g, &y)) return false;
    }
    return true;
}

int test_bls12_381_final_exp_parity(void);
int test_bls12_381_final_exp_parity(void)
{
    int failures = 0;
    printf("bls12_381_final_exp_parity: 0, 1, Miller outputs + conjugates... ");
    if (structured_inputs()) printf("PASS\n");
    else { printf("FAIL\n"); failures++; }

    printf("bls12_381_final_exp_parity: cyclotomic_sq == fp12_sq x%d... ", FE_SQ_CHECKS);
    if (cyclotomic_sq_checks()) printf("PASS\n");
    else { printf("FAIL\n"); failures++; }

    uint64_t n = FE_DEFAULT_RANDOM;
    printf("bls12_381_final_exp_parity: %llu random Fp12 vs frozen oracle... ",
           (unsigned long long)n);
    if (random_inputs(n)) printf("PASS\n");
    else { printf("FAIL\n"); failures++; }
    return failures;
}
