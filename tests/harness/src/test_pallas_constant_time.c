/* purpose: Detect gross secret-dependent Pallas work asymmetry in research paths. */
/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0
 *
 * Statistical black-box work-ratio detector: per-thread CPU time, alternating
 * order, median of nine samples. It detects gross asymmetry (roughly >15%),
 * not constant-time-ness; it says nothing about cache or branch-predictor
 * leakage. Only two scalars, this host and this build are observed. Neither
 * compiler-level timing nor secret-memory handling is qualified.
 */
#include "../../../engine/services/src/ironwood_pallas_point.h"
#include "../../../engine/services/src/ironwood_pallas_agreement.h"
#include "base/hex.h"
#include "platform/clock.h"
#include <stdio.h>
#include <string.h>

#define CT_SAMPLES 9
#define CT_ITERS 64
#define CT_WARMUP 16
#define CT_TOLERANCE 1.15
#define CT_WORK_FLOOR_NS 100000ULL

typedef void (*ct_workfn)(const void *secret, void *scratch);
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
    if (lo_ns_out) *lo_ns_out = samples[CT_SAMPLES / 2].lo_ns;
    return samples[CT_SAMPLES / 2].ratio;
}
static bool ct_flat(double r)
{
    return r > 0.0 && r <= CT_TOLERANCE && r >= 1.0 / CT_TOLERANCE;
}
static bool ct_did_work(uint64_t lo_ns)
{
    return lo_ns >= CT_WORK_FLOOR_NS;
}

struct ct_scratch {
    struct pallas_point point, result;
    uint8_t epk[32], out[32];
    bool ok;
};
static volatile uint64_t ct_sink;

static void work_multiply(const void *secret, void *scratch)
{
    struct ct_scratch *s = scratch;
    pallas_point_multiply(&s->result, &s->point, secret);
    ct_sink ^= s->result.x.limb[0];
}
static __attribute__((noinline)) void leaky_add(struct pallas_point *acc,
                                                 const struct pallas_point *point)
{
    pallas_point_add(acc, acc, point);
    ct_sink ^= acc->x.limb[0];
}
static void work_leaky(const void *secret, void *scratch)
{
    const uint8_t *bits = secret;
    struct ct_scratch *s = scratch;
    struct pallas_point acc = { .y = {{1,0,0,0}} };
    for (size_t i = 255; i-- > 0;) {
        pallas_point_double(&acc, &acc);
        if ((bits[i / 8] >> (i % 8)) & 1) leaky_add(&acc, &s->point);
    }
    ct_sink ^= acc.x.limb[0];
}
static void work_agree(const void *secret, void *scratch)
{
    struct ct_scratch *s = scratch;
    s->ok &= ironwood_research_pallas_agree(secret, s->epk, s->out).ok;
    ct_sink ^= s->out[0];
}
/* The point fixture is (-1,2), from pallas-point-add.txt. Check y²=x³+5. */
static bool fixtures(struct ct_scratch *s, const uint8_t lo[32], const uint8_t hi[32])
{
    uint8_t x[32], y[32] = {2};
    struct pallas_fp scalar, lhs, rhs, five = {{5,0,0,0}};
    if (!pallas_fp_read(&scalar, lo).ok || !pallas_fp_read(&scalar, hi).ok ||
        !zcl_hex_decode("00000000ed302d991bf94c09fc98462200000000000000000000000000000040", x, 32) ||
        !pallas_fp_read(&s->point.x, x).ok || !pallas_fp_read(&s->point.y, y).ok ||
        !zcl_hex_decode("54584886e0359da65fb9d846d2f6fb5d6e64869e66b922d02b6c74141004cd2b", s->epk, 32))
        return false;
    s->point.z = (struct pallas_fp){{1,0,0,0}};
    pallas_fp_mul(&lhs, &s->point.y, &s->point.y);
    pallas_fp_mul(&rhs, &s->point.x, &s->point.x);
    pallas_fp_mul(&rhs, &rhs, &s->point.x);
    pallas_fp_add(&rhs, &rhs, &five);
    return !memcmp(&lhs, &rhs, sizeof lhs) &&
        ironwood_research_pallas_agree(lo, s->epk, s->out).ok &&
        ironwood_research_pallas_agree(hi, s->epk, s->out).ok;
}
static int check_leg(const char *name, ct_workfn fn, const uint8_t lo[32],
                     const uint8_t hi[32], struct ct_scratch *s, bool leaky)
{
    uint64_t lo_ns = 0;
    s->ok = true;
    double r = ct_ratio(fn, lo, hi, s, &lo_ns);
    bool ok = ct_did_work(lo_ns) && s->ok && (leaky ? !ct_flat(r) && r > 0.0 : ct_flat(r));
    printf("%s: %s (ratio %.3f, %llu ns, tolerance %.2f)\n",
           name, ok ? "OK" : "FAIL", r, (unsigned long long)lo_ns, CT_TOLERANCE);
    return ok ? 0 : 1;
}
int test_pallas_constant_time(void)
{
    uint8_t lo[32] = {1}, hi[32];
    memset(hi, 0xff, sizeof hi);
    hi[31] = 0x0f;
    struct ct_scratch s = {0};
    if (!fixtures(&s, lo, hi)) {
        printf("pallas_constant_time: FAIL invalid fixture\n");
        return 1;
    }
    int failures = 0;
    failures += check_leg("leg 1 multiply", work_multiply, lo, hi, &s, false);
    failures += check_leg("leg 2 leaky control", work_leaky, lo, hi, &s, true);
    failures += check_leg("leg 3 agreement", work_agree, lo, hi, &s, false);
    printf("pallas_constant_time: %s (%d failures)\n", failures ? "FAIL" : "OK", failures);
    return failures;
}
