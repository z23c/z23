/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0
 * Exercise streaming statistics, count refusal and the pinned merge contract. */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include "zstats/zstats.h"
#include <float.h>
#include <math.h>


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#if defined(_WIN32)
#include <io.h>
#else
#include <unistd.h>
#endif

#define CHECK(cond) do { \
    if (!(cond)) { \
        fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); \
        exit(1); \
    } \
} while (0)

#define CHECK_NEAR(a, b, eps) do { \
    double _d = (a) - (b); \
    if (_d < 0) _d = -_d; \
    if (!(_d <= (eps))) { \
        fprintf(stderr, "FAIL %s:%d: %f !~ %f (eps %g)\n", \
                __FILE__, __LINE__, (double)(a), (double)(b), (double)(eps)); \
        exit(1); \
    } \
} while (0)

static void test_empty_and_single(void)
{
    zstats s;
    zstats_init(&s);
    CHECK(zstats_count(&s) == 0);
    CHECK(zstats_mean(&s) == 0.0);
    CHECK(zstats_variance(&s) == 0.0);
    CHECK(zstats_sample_variance(&s) == 0.0);
    CHECK(zstats_stddev(&s) == 0.0);
    CHECK(zstats_min(&s) == 0.0);
    CHECK(zstats_max(&s) == 0.0);
    CHECK(zstats_total(&s) == 0.0L);

    zstats_add(&s, 42.0);
    CHECK(zstats_count(&s) == 1);
    CHECK(zstats_mean(&s) == 42.0);
    CHECK(zstats_variance(&s) == 0.0);
    CHECK(zstats_min(&s) == 42.0 && zstats_max(&s) == 42.0);
    CHECK(zstats_total(&s) == 42.0L);

    /* NULL tolerance. */
    zstats_init(NULL);
    zstats_add(NULL, 1.0);
    zstats_add_repeated(NULL, 1.0, 3);
    zstats_merge(NULL, &s);
    zstats_merge(&s, NULL);
    CHECK(zstats_count(NULL) == 0);
    CHECK(zstats_mean(NULL) == 0.0);
}

static void test_known_dataset(void)
{
    /* Classic: 2 4 4 4 5 5 7 9 -> mean 5, pop var 4, sample var 32/7. */
    const double data[] = {2, 4, 4, 4, 5, 5, 7, 9};
    zstats s;
    zstats_init(&s);
    for (size_t i = 0; i < 8; i++) zstats_add(&s, data[i]);
    CHECK(zstats_count(&s) == 8);
    CHECK_NEAR(zstats_mean(&s), 5.0, 1e-12);
    CHECK_NEAR(zstats_variance(&s), 4.0, 1e-12);
    CHECK_NEAR(zstats_sample_variance(&s), 32.0 / 7.0, 1e-12);
    CHECK_NEAR(zstats_stddev(&s), 2.0, 1e-12);
    CHECK(zstats_min(&s) == 2.0 && zstats_max(&s) == 9.0);
    CHECK(zstats_total(&s) == 40.0L);
}

static void test_repeated_and_merge(void)
{
    /* add_repeated must equal individual adds. */
    zstats a, b;
    zstats_init(&a);
    zstats_init(&b);
    for (int i = 0; i < 100; i++) zstats_add(&a, 7.5);
    zstats_add_repeated(&b, 7.5, 100);
    CHECK(zstats_count(&b) == 100);
    CHECK_NEAR(zstats_mean(&a), zstats_mean(&b), 1e-9);
    CHECK_NEAR(zstats_variance(&a), zstats_variance(&b), 1e-12);

    /* Mixed: 3 then repeated 97. */
    zstats c;
    zstats_init(&c);
    zstats_add(&c, 7.5);
    zstats_add_repeated(&c, 7.5, 99);
    CHECK(zstats_count(&c) == 100);
    CHECK_NEAR(zstats_mean(&c), 7.5, 1e-12);

    /* Merge two halves equals the whole. */
    zstats left, right, whole;
    zstats_init(&left);
    zstats_init(&right);
    zstats_init(&whole);
    for (int i = 0; i < 1000; i++) {
        double x = (double)((i * 7919) % 1000) / 10.0;
        zstats_add(&whole, x);
        if (i % 2 == 0) zstats_add(&left, x);
        else zstats_add(&right, x);
    }
    zstats_merge(&left, &right);
    CHECK(zstats_count(&left) == 1000);
    CHECK_NEAR(zstats_mean(&left), zstats_mean(&whole), 1e-9);
    CHECK_NEAR(zstats_variance(&left), zstats_variance(&whole), 1e-6);
    CHECK(zstats_min(&left) == zstats_min(&whole));
    CHECK(zstats_max(&left) == zstats_max(&whole));

    /* Merge into empty; merge empty. */
    zstats e, full;
    zstats_init(&e);
    zstats_init(&full);
    zstats_add(&full, 3.0);
    zstats_merge(&e, &full);
    CHECK(zstats_count(&e) == 1 && zstats_mean(&e) == 3.0);
    zstats empty;
    zstats_init(&empty);
    zstats_merge(&e, &empty);
    CHECK(zstats_count(&e) == 1);
}

static void test_count_overflow(unsigned row) {
    zstats s, other;
    zstats_init(&s); zstats_init(&other);
    zstats_add_repeated(&s, 1.0, row == 1 ? UINT64_MAX - 1 : UINT64_MAX);
    zstats before = s;
    if (row == 0) zstats_add(&s, 2.0);
    else if (row == 1) zstats_add_repeated(&s, 2.0, 2);
    else { zstats_add(&other, 2.0); zstats_merge(&s, &other); }
    CHECK(s.n == before.n && s.mean == before.mean && s.m2 == before.m2 &&
          s.min == before.min && s.max == before.max && s.sum == before.sum);
}
static void test_count_overflow_rows(void) {
    const char *row = getenv("ZQA_ROW");
    if (row) {
        unsigned r = (unsigned)strtoul(row, NULL, 10);
        if (r > 2) exit(2);
        test_count_overflow(r);
    } else {
        for (unsigned r = 0; r < 3; r++) test_count_overflow(r);
    }
}

static uint64_t rng_state = 0x0123456789abcdefull;
static uint64_t rng_next(void)
{
    rng_state ^= rng_state << 13;
    rng_state ^= rng_state >> 7;
    rng_state ^= rng_state << 17;
    return rng_state;
}

static void test_fuzz_vs_reference(void)
{
    /* Random datasets: streaming result must match a naive two-pass
     * reference within tight tolerance. */
    for (int trial = 0; trial < 200; trial++) {
        size_t n = (size_t)(rng_next() % 500) + 1;
        double data[500];
        for (size_t i = 0; i < n; i++)
            data[i] = (double)(rng_next() % 10000) / 8.0 - 500.0;

        zstats s;
        zstats_init(&s);
        for (size_t i = 0; i < n; i++) zstats_add(&s, data[i]);

        long double sum = 0.0L;
        double mn = data[0], mx = data[0];
        for (size_t i = 0; i < n; i++) {
            sum += data[i];
            if (data[i] < mn) mn = data[i];
            if (data[i] > mx) mx = data[i];
        }
        double mean = (double)(sum / (long double)n);
        double var = 0.0;
        for (size_t i = 0; i < n; i++) {
            double d = data[i] - mean;
            var += d * d;
        }
        var /= (double)n;

        CHECK(zstats_count(&s) == n);
        CHECK_NEAR(zstats_mean(&s), mean, 1e-9);
        CHECK_NEAR(zstats_variance(&s), var, 1e-6);
        CHECK(zstats_min(&s) == mn);
        CHECK(zstats_max(&s) == mx);

        /* Random split-merge equals the whole. */
        zstats l, r;
        zstats_init(&l);
        zstats_init(&r);
        for (size_t i = 0; i < n; i++)
            if (rng_next() & 1) zstats_add(&l, data[i]);
            else zstats_add(&r, data[i]);
        zstats_merge(&l, &r);
        CHECK(zstats_count(&l) == n);
        CHECK_NEAR(zstats_mean(&l), mean, 1e-9);
        CHECK_NEAR(zstats_variance(&l), var, 1e-5);
    }
}

static void test_merge_weight(unsigned row)
{
    zstats a, b;
    zstats_init(&a);
    zstats_init(&b);
    if (row == 0) {
        zstats_add(&a, 1.0);
        zstats_add_repeated(&b, 0.0, UINT64_C(1) << 54);
        zstats reverse = b;
        zstats_merge(&reverse, &a);
        zstats_merge(&a, &b);
        CHECK(a.mean == 0x1p-54 && reverse.mean == 0x1p-54);
        CHECK(a.n == (UINT64_C(1) << 54) + 1 && a.sum == 1.0L);
    } else {
        zstats_add(&a, DBL_MAX);
        zstats_add_repeated(&b, DBL_MAX, 2);
        zstats_merge(&a, &b);
        CHECK(a.mean == DBL_MAX && a.n == 3 && a.m2 == 0.0);
    }
}

static void test_opposite_merge_weight(void)
{
    static const double minority[] = {1.0, -1.0};
    static const double majority[] = {-1.0, 1.0};
    static const double expected[] = {-0x1.fffffffffffffp-1,
                                      0x1.fffffffffffffp-1};
    for (unsigned row = 0; row < 2; row++) {
        zstats a, b;
        zstats_init(&a);
        zstats_init(&b);
        zstats_add(&a, minority[row]);
        zstats_add_repeated(&b, majority[row], UINT64_C(1) << 54);
        zstats reverse = b;
        zstats_merge(&reverse, &a);
        zstats_merge(&a, &b);
        CHECK(a.mean == expected[row] && reverse.mean == expected[row]);
        CHECK(a.n == (UINT64_C(1) << 54) + 1 && reverse.n == a.n);
    }
    /* The product fallback still handles an unrepresentable difference. */
    zstats a, b;
    zstats_init(&a);
    zstats_init(&b);
    zstats_add(&a, DBL_MAX);
    zstats_add(&b, -DBL_MAX);
    zstats reverse = b;
    zstats_merge(&reverse, &a);
    zstats_merge(&a, &b);
    CHECK(a.mean == 0.0 && reverse.mean == 0.0);
}

static void test_nonfinite_merge_row(double minority, double majority,
                                     double expected)
{
    const uint64_t many = UINT64_C(1) << 54;
    zstats a, b;
    zstats_init(&a);
    zstats_init(&b);
    zstats_add(&a, minority);
    zstats_add_repeated(&b, majority, many);
    zstats reverse = b;
    zstats_merge(&reverse, &a);
    zstats_merge(&a, &b);
    CHECK(a.n == many + 1 && reverse.n == a.n);
    CHECK(b.n == many);
    if (isnan(expected)) {
        CHECK(isnan(a.mean) && isnan(reverse.mean));
    } else {
        CHECK(a.mean == expected && reverse.mean == expected);
    }
}

static void test_nonfinite_merge(const char *selected)
{
    static const struct {
        const char *name;
        double minority, majority, expected;
    } rows[] = {
        {"positive_inf", INFINITY, 0.0, INFINITY},
        {"negative_inf", -INFINITY, 0.0, -INFINITY},
        {"positive_inf_negative_finite", INFINITY, -2.0, INFINITY},
        {"negative_inf_positive_finite", -INFINITY, 2.0, -INFINITY},
        {"positive_infinities", INFINITY, INFINITY, INFINITY},
        {"negative_infinities", -INFINITY, -INFINITY, -INFINITY},
        {"minority_nan", NAN, 0.0, NAN},
        {"majority_nan", 0.0, NAN, NAN},
        {"nan_with_inf", NAN, INFINITY, NAN},
        {"inf_with_nan", INFINITY, NAN, NAN},
        {"opposite_inf", INFINITY, -INFINITY, NAN},
        {"reverse_opposite_inf", -INFINITY, INFINITY, NAN},
    };
    bool found = false;
    for (size_t i = 0; i < sizeof rows / sizeof rows[0]; i++) {
        if (selected && strcmp(selected, rows[i].name) != 0) continue;
        found = true;
        test_nonfinite_merge_row(rows[i].minority, rows[i].majority,
                                 rows[i].expected);
    }
    if (!found) exit(2);
}

/* STATS-CONTRACT rows, numbered in specification order. Row 26 exercises
 * both forms of invalid M2. The void API signals refusal by no mutation. */
static void check_contract_value(double actual, double expected)
{
    if (isnan(expected)) { CHECK(isnan(actual)); return; }
    CHECK(actual == expected);
    CHECK(!!signbit(actual) == !!signbit(expected));
}

static void test_merge_contract(unsigned selected)
{
    static const struct {
        uint64_t na, nb, n;
        double a, b, ma, mb, mean, m2;
        bool refused;
    } rows[] = {
        {0, 2, 2, NAN, 3, NAN, 4, 3, 4, false},
        {0, 0, 0, NAN, INFINITY, NAN, -INFINITY, 0, 0, false},
        {2, 3, 5, 7, 7, 3, 4, 7, 7, false},
        {2, 2, 4, 1, 3, 0, 0, 2, 4, false},
        {1, 1, 2, DBL_MAX, DBL_MAX, 0, 0, DBL_MAX, 0, false},
        {1, 1, 2, -DBL_MAX, -DBL_MAX, 0, 0, -DBL_MAX, 0, false},
        {2, 2, 4, DBL_MAX, -DBL_MAX, 0, 0, 0, INFINITY, false},
        {3, 1, 4, DBL_MAX, -DBL_MAX, 0, 0, DBL_MAX/2, INFINITY, false},
        {UINT64_C(1)<<63, (UINT64_C(1)<<63)-1, UINT64_MAX,
         DBL_MAX, -DBL_MAX, 0, 0, 0x1.fffffffffffffp959, INFINITY, false},
        {1, 1, 2, 0, 0x1p512, 0, 0, 0x1p511, 0x1p1023, false},
        {UINT64_C(1)<<62, UINT64_C(1)<<62, UINT64_C(1)<<63,
         0, 0x1p-540, 0, 0, 0x1p-541, 0x1p-1019, false},
        {1, 1, 2, 1, 1, DBL_MAX, DBL_MAX, 1, INFINITY, false},
        {1, 1, 2, 1, 1, INFINITY, 0, 1, INFINITY, false},
        {1, 1, 2, 1, 3, NAN, 0, 2, NAN, false},
        {1, 1, 2, 1, 1, NAN, INFINITY, 1, NAN, false},
        {1, 1, 2, NAN, 2, 0, 0, NAN, NAN, false},
        {1, 1, 2, NAN, INFINITY, 0, 0, NAN, NAN, false},
        {1, 1, 2, INFINITY, 2, 0, 0, INFINITY, NAN, false},
        {1, 1, 2, -INFINITY, 2, 0, 0, -INFINITY, NAN, false},
        {1, 1, 2, INFINITY, INFINITY, 0, 0, INFINITY, NAN, false},
        {1, 1, 2, -INFINITY, -INFINITY, 0, 0, -INFINITY, NAN, false},
        {1, 1, 2, INFINITY, -INFINITY, 0, 0, NAN, NAN, false},
        {2, 2, 4, 4, 4, 6, 6, 4, 12, false},
        {1, 1, 2, -0.0, 0.0, 0, 0, 0.0, 0, false},
        {1, 1, 2, -0.0, -0.0, 0, 0, -0.0, 0, false},
        {1, 1, 0, 0, 0, -INFINITY, 0, 0, 0, true},
        {UINT64_MAX, 1, 0, 0, 0, 0, 0, 0, 0, true},
    };
    CHECK(selected >= 1 && selected <= sizeof rows / sizeof rows[0]);
    size_t i = selected - 1;
    for (unsigned variant = 0; variant < (selected == 26 ? 2u : 1u); variant++) {
        for (unsigned order = 0; order < 2; order++) {
            zstats a = {0}, b = {0};
            a.n = rows[i].na; b.n = rows[i].nb;
            a.mean = rows[i].a; b.mean = rows[i].b;
            a.m2 = variant ? -1.0 : rows[i].ma; b.m2 = rows[i].mb;
            a.min = a.max = a.mean; b.min = b.max = b.mean;
            a.sum = 11; b.sum = 13;
            if (order) { zstats tmp = a; a = b; b = tmp; }
            unsigned char before[sizeof a], source[sizeof b];
            memcpy(before, &a, sizeof a); memcpy(source, &b, sizeof b);
            zstats_merge(&a, &b);
            CHECK(memcmp(source, &b, sizeof b) == 0);
            if (rows[i].refused) {
                CHECK(memcmp(before, &a, sizeof a) == 0);
            } else {
                CHECK(a.n == rows[i].n);
                check_contract_value(a.mean, rows[i].mean);
                check_contract_value(a.m2, rows[i].m2);
                if (selected == 2) {
                    CHECK(a.min == 0 && a.max == 0 && a.sum == 0);
                }
            }
            printf("contract row %u variant %u order %u passed\n",
                   selected, variant, order);
        }
    }
}

/* Append-contract rows: constants are independent of the merge comparison. */
typedef struct {
    uint64_t n, k;
    double a, b, mean, m2;
} add_case;

static zstats constant_block(uint64_t n, double x)
{
    return (zstats){.n=n, .mean=x, .m2=0, .min=x, .max=x,
                    .sum=(long double)x * (long double)n};
}

static void append_api(zstats *s, double x, unsigned api, uint64_t k)
{
    if (api == 0) zstats_add(s, x);
    else zstats_add_repeated(s, x, k);
}

static void check_all_fields(const zstats *actual, const zstats *expected)
{
    CHECK(actual->n == expected->n);
    check_contract_value(actual->mean, expected->mean);
    check_contract_value(actual->m2, expected->m2);
    check_contract_value(actual->min, expected->min);
    check_contract_value(actual->max, expected->max);
    if (isnan(expected->sum)) CHECK(isnan(actual->sum));
    else {
        CHECK(actual->sum == expected->sum);
        CHECK(!!signbit(actual->sum) == !!signbit(expected->sum));
    }
}

static void test_add_case(const char *name, const add_case *row)
{
    for (unsigned api = row->k == 1 ? 0u : 1u; api < 2; api++) {
        zstats actual = constant_block(row->n, row->a);
        zstats expected = actual, block = constant_block(row->k, row->b);
        zstats_merge(&expected, &block);
        append_api(&actual, row->b, api, row->k);
        fprintf(stderr, "ADD-%s api%u n=%llu k=%llu: mean %a expected %a; M2 %a expected %a\n",
                name, api, (unsigned long long)row->n,
                (unsigned long long)row->k, actual.mean, row->mean,
                actual.m2, row->m2);
        CHECK(actual.n == row->n + row->k);
        check_contract_value(actual.mean, row->mean);
        check_contract_value(actual.m2, row->m2);
        check_all_fields(&actual, &expected);
    }
}

static void test_add_extremes(void)
{
    static const add_case rows[] = {
        {1,1,DBL_MAX,-DBL_MAX,0,INFINITY},
        {1,1,-DBL_MAX,DBL_MAX,0,INFINITY},
        {1,2,DBL_MAX,-DBL_MAX,-DBL_MAX/3.0,INFINITY},
        {1,2,-DBL_MAX,DBL_MAX,DBL_MAX/3.0,INFINITY},
        {2,1,DBL_MAX,-DBL_MAX,DBL_MAX/3.0,INFINITY},
        {2,1,-DBL_MAX,DBL_MAX,-DBL_MAX/3.0,INFINITY},
        {UINT64_C(1)<<63,(UINT64_C(1)<<63)-1,
         DBL_MAX,-DBL_MAX,0x1.fffffffffffffp959,INFINITY},
        {(UINT64_C(1)<<63)-1,UINT64_C(1)<<63,
         -DBL_MAX,DBL_MAX,0x1.fffffffffffffp959,INFINITY},
        {UINT64_C(1)<<63,(UINT64_C(1)<<63)-1,
         -DBL_MAX,DBL_MAX,-0x1.fffffffffffffp959,INFINITY},
    };
    for (size_t i=0; i<sizeof rows/sizeof rows[0]; i++)
        test_add_case("B1", &rows[i]);
}

static void test_add_nonfinite(void)
{
    static const struct { double a,b,mean; } rows[] = {
        {INFINITY,2,INFINITY}, {2,INFINITY,INFINITY},
        {-INFINITY,2,-INFINITY}, {2,-INFINITY,-INFINITY},
        {INFINITY,-2,INFINITY}, {-2,INFINITY,INFINITY},
        {-INFINITY,-2,-INFINITY}, {-2,-INFINITY,-INFINITY},
        {INFINITY,INFINITY,INFINITY}, {-INFINITY,-INFINITY,-INFINITY},
        {INFINITY,-INFINITY,NAN}, {-INFINITY,INFINITY,NAN},
        {NAN,2,NAN}, {2,NAN,NAN}, {NAN,INFINITY,NAN},
        {INFINITY,NAN,NAN}, {NAN,-INFINITY,NAN}, {-INFINITY,NAN,NAN},
    };
    for (size_t i=0; i<sizeof rows/sizeof rows[0]; i++) {
        for (uint64_t k=1; k<=2; k++) {
            const add_case row = {1,k,rows[i].a,rows[i].b,rows[i].mean,NAN};
            test_add_case("B2", &row);
        }
    }
}

static void test_add_zeros(void)
{
    static const struct { double a,b,mean; } rows[] = {
        {-0.0,-0.0,-0.0}, {0.0,0.0,0.0},
        {-0.0,0.0,0.0}, {0.0,-0.0,0.0},
        {DBL_MAX,DBL_MAX,DBL_MAX}, {-DBL_MAX,-DBL_MAX,-DBL_MAX},
        {7,7,7},
    };
    for (size_t i=0; i<sizeof rows/sizeof rows[0]; i++) {
        for (uint64_t k=1; k<=2; k++) {
            const add_case row = {1,k,rows[i].a,rows[i].b,rows[i].mean,0};
            test_add_case("B3", &row);
        }
    }
}

static void check_append_refusal(zstats original, unsigned api, uint64_t k)
{
    unsigned char before[sizeof original];
    memcpy(before, &original, sizeof original);
    append_api(&original, 0, api, k);
    fprintf(stderr, "ADD-B4 api%u k=%llu: refusal snapshot\n",
            api, (unsigned long long)k);
    CHECK(memcmp(before, &original, sizeof original) == 0);
}

static void test_add_m2_control(double m2)
{
    for (unsigned api=0; api<2; api++) {
        zstats actual = constant_block(1,1);
        actual.m2 = m2;
        zstats expected = actual, block = constant_block(1,3);
        zstats_merge(&expected, &block);
        append_api(&actual, 3, api, 1);
        CHECK(actual.n == 2 && actual.mean == 2);
        check_contract_value(actual.m2, m2);
        check_all_fields(&actual, &expected);
    }
}

static void test_add_refusal(void)
{
    static const uint64_t counts[] = {1,UINT64_MAX-1,UINT64_MAX};
    static const double invalid[] = {-1,-INFINITY};
    for (size_t i=0; i<sizeof counts/sizeof counts[0]; i++) {
        for (size_t j=0; j<sizeof invalid/sizeof invalid[0]; j++) {
            zstats s = constant_block(counts[i],0);
            s.m2 = invalid[j];
            check_append_refusal(s,0,1);
            for (uint64_t k=0; k<=2; k++) check_append_refusal(s,1,k);
        }
    }
    zstats full = constant_block(UINT64_MAX,0);
    check_append_refusal(full,0,1);
    check_append_refusal(full,1,1);
    zstats near = constant_block(UINT64_MAX-1,0);
    check_append_refusal(near,1,2);
    for (unsigned api=0; api<2; api++) {
        zstats accepted = near;
        append_api(&accepted,0,api,1);
        CHECK(accepted.n == UINT64_MAX && accepted.mean == 0 && accepted.m2 == 0);
    }
    zstats_add(NULL,1);
    zstats_add_repeated(NULL,1,0);
    zstats_add_repeated(NULL,1,1);
    zstats_add_repeated(NULL,1,2);
    test_add_m2_control(NAN);
    test_add_m2_control(INFINITY);
}

static void test_add_scaled(void)
{
    static const add_case rows[] = {
        {UINT64_C(1)<<62,UINT64_C(1)<<62,0,0x1p-540,0x1p-541,0x1p-1019},
        {UINT64_C(1)<<62,UINT64_C(1)<<62,0x1p-540,0,0x1p-541,0x1p-1019},
        {1,2,0,0x1p512,0x1.5555555555555p511,0x1.5555555555555p1023},
        {2,1,0x1p512,0,0x1.5555555555555p511,0x1.5555555555555p1023},
        {1,1,0,0x1p512,0x1p511,0x1p1023},
        {1,1,0x1p512,0,0x1p511,0x1p1023},
        {1,1,1,3,2,2}, {1,1,3,1,2,2},
    };
    for (size_t i=0; i<sizeof rows/sizeof rows[0]; i++)
        test_add_case("B5", &rows[i]);
}

static void test_add_empty_row(unsigned dirty, double x, unsigned api, uint64_t k)
{
    zstats actual = {0};
    if (dirty) {
        actual.mean = actual.min = actual.max = NAN;
        actual.m2 = dirty == 1 ? NAN : -INFINITY;
        actual.sum = NAN;
    }
    unsigned char before[sizeof actual];
    memcpy(before, &actual, sizeof actual);
    zstats expected = constant_block(k,x);
    zstats merged = actual;
    zstats_merge(&merged, &expected);
    append_api(&actual,x,api,k);
    fprintf(stderr, "ADD-B6 dirty%u api%u k=%llu: empty payload\n",
            dirty, api, (unsigned long long)k);
    if (k == 0) CHECK(memcmp(before, &actual, sizeof actual) == 0);
    else {
        check_all_fields(&actual, &expected);
        check_all_fields(&actual, &merged);
    }
}

static void test_add_empty(void)
{
    static const double samples[] = {3,NAN,INFINITY,-INFINITY,-0.0};
    for (unsigned dirty=1; dirty<=3; dirty++) {
        for (size_t i=0; i<sizeof samples/sizeof samples[0]; i++) {
            unsigned payload = dirty == 3 ? 0 : dirty;
            test_add_empty_row(payload,samples[i],0,1);
            test_add_empty_row(payload,samples[i],1,1);
            test_add_empty_row(payload,samples[i],1,2);
            test_add_empty_row(payload,samples[i],1,0);
        }
    }
}

static bool test_add_contract(const char *selected)
{
    static const struct { const char *name; void (*run)(void); } groups[] = {
        {"B1",test_add_extremes}, {"B2",test_add_nonfinite},
        {"B3",test_add_zeros}, {"B4",test_add_refusal},
        {"B5",test_add_scaled}, {"B6",test_add_empty},
    };
    bool found = false;
    for (size_t i=0; i<sizeof groups/sizeof groups[0]; i++) {
        if (selected && strcmp(selected,groups[i].name) != 0) continue;
        found = true;
        groups[i].run();
    }
    return found;
}

static void test_cli(void);

int main(void)
{
    const char *add_row = getenv("ZSTATS_ADD_ROW");
    if (add_row) {
        if (!test_add_contract(add_row)) return 2;
        puts("append contract selected group passed");
        return 0;
    }
    const char *contract_row = getenv("ZSTATS_CONTRACT_ROW");
    if (contract_row) {
        char *end;
        unsigned long row = strtoul(contract_row, &end, 10);
        if (*end || row < 1 || row > 27) return 2;
        test_merge_contract((unsigned)row);
        return 0;
    }
    const char *nonfinite_row = getenv("ZSTATS_NONFINITE_ROW");
    if (nonfinite_row) {
        test_nonfinite_merge(nonfinite_row);
        return 0;
    }
    const char *fix_row = getenv("ZSTATS_FIX_ROW");
    if (fix_row) {
        if (strcmp(fix_row, "0") == 0) test_merge_weight(0);
        else if (strcmp(fix_row, "1") == 0) test_merge_weight(1);
        else if (strcmp(fix_row, "2") == 0) test_opposite_merge_weight();
        else return 2;
        return 0;
    }
    test_cli();
    CHECK(test_add_contract(NULL));
    for (unsigned row = 1; row <= 27; row++) test_merge_contract(row);
    test_nonfinite_merge(NULL);
    test_merge_weight(0);
    test_merge_weight(1);
    test_opposite_merge_weight();
    test_empty_and_single();
    test_known_dataset();
    test_repeated_and_merge();
    test_count_overflow_rows();
    test_fuzz_vs_reference();
    puts("test_zstats: all groups passed (empty known repeated merge fuzz)");
    return 0;
}

static FILE *cli_source, *cli_sink, *cli_errors, *cli_failure_sink;
static size_t cli_writes, cli_fail_at, cli_flushes;
static bool cli_close_after_value, cli_close_before_scan, cli_descriptor_closed, cli_source_closed;
static size_t cli_scan_values;
static size_t cli_read_bytes, cli_close_after_bytes;
static size_t cli_realloc_calls, cli_fail_allocation, cli_live_allocations;
static void *cli_token_pointer;
static FILE *real_stdin(void) { return stdin; }
static FILE *real_stdout(void) { return stdout; }
static FILE *real_stderr(void) { return stderr; }
static int cli_printf(const char *format, ...)
{
    if (++cli_writes >= cli_fail_at && cli_fail_at) cli_sink = cli_failure_sink;
    va_list args;
    va_start(args, format);
    int result = vfprintf(cli_sink, format, args);
    va_end(args);
    return result;
}
static void cli_close_descriptor(void)
{
#ifdef _WIN32
    CHECK(_close(_fileno(cli_source)) == 0);
#else
    CHECK(close(fileno(cli_source)) == 0);
#endif
    cli_descriptor_closed = true;
}
static int cli_getc(FILE *stream)
{
    int byte = fgetc(stream);
    if (byte != EOF) {
        cli_read_bytes++;
        bool after_bytes = cli_close_after_bytes && cli_read_bytes == cli_close_after_bytes;
        if (!cli_descriptor_closed && (after_bytes || (cli_close_after_value && byte == ' ')))
            cli_close_descriptor();
    }
    return byte;
}
static void cli_add(zstats *s, double value)
{
    cli_scan_values++;
    zstats_add(s, value);
}
static void *cli_realloc(void *pointer, size_t size)
{
    if (++cli_realloc_calls == cli_fail_allocation) return NULL;
    bool initial = pointer == NULL;
    void *grown = realloc(pointer, size); // raw-alloc-ok:token-allocation-failure-fixture
    if (grown) {
        if (initial) cli_live_allocations++;
        cli_token_pointer = grown;
    }
    return grown;
}
static void cli_free(void *pointer)
{
    if (pointer) {
        CHECK(cli_live_allocations == 1 && pointer == cli_token_pointer);
        cli_live_allocations--;
        cli_token_pointer = NULL;
    }
    free(pointer);
}
[[maybe_unused]] static int cli_flush(FILE *stream)
{
    if (stream == cli_sink) cli_flushes++;
    return fflush(stream);
}
#undef stdin
#undef stdout
#undef stderr
#define stdin cli_source
#define stdout cli_sink
#define stderr cli_errors
#define printf cli_printf
#define fgetc cli_getc
#define zstats_add cli_add
#define realloc cli_realloc
#define free cli_free
#define fflush cli_flush
#define main embedded_cli_main
#include "../app/main.c"
#undef main
#undef fflush
#undef free
#undef realloc
#undef zstats_add
#undef fgetc
#undef printf
#undef stdin
#undef stdout
#undef stderr
#define stdin real_stdin()
#define stdout real_stdout()
#define stderr real_stderr()

static FILE *cli_input_bytes(const void *text, size_t n)
{
    FILE *source = tmpfile();
    CHECK(source != NULL);
    CHECK(setvbuf(source, NULL, _IONBF, 0) == 0);
    CHECK(fwrite(text, 1, n, source) == n && fflush(source) == 0);
    rewind(source);
    return source;
}
static FILE *cli_input(const char *text)
{
    return cli_input_bytes(text, strlen(text));
}
static int cli_invoke(FILE *source, FILE *sink, FILE *errors, int argc, char **args)
{
    cli_source = source;
    cli_sink = sink;
    cli_errors = errors;
    cli_writes = cli_flushes = cli_scan_values = cli_read_bytes = cli_realloc_calls = 0;
    CHECK(cli_live_allocations == 0);
    cli_descriptor_closed = cli_source_closed = false;
    if (cli_close_before_scan) cli_close_descriptor();
    errno = ERANGE;
    int rc = embedded_cli_main(argc, args);
    CHECK(cli_live_allocations == 0);
    /* No new descriptor may be allocated while this FILE retains its now
     * closed descriptor number. Retire it immediately after the invocation. */
    if (cli_descriptor_closed) {
        CHECK(ferror(source));
        CHECK(fclose(source) == EOF);
        cli_source_closed = true;
    }
    cli_source = stdin;
    cli_sink = stdout;
    cli_errors = stderr;
    return rc;
}
static void cli_bytes(FILE *stream, const char *want)
{
    char bytes[512];
    rewind(stream);
    size_t n = fread(bytes, 1, sizeof bytes, stream);
    CHECK(!ferror(stream) && n == strlen(want) && !memcmp(bytes, want, n));
}
static void cli_message(FILE *stream, const char *want)
{
    char bytes[256];
    rewind(stream);
    size_t n = fread(bytes, 1, sizeof bytes - 1, stream);
    bytes[n] = 0;
    CHECK(!ferror(stream) && strstr(bytes, want) != NULL);
}
static void cli_normal(void)
{
    const char *want = "n      2\nmin    1\nmax    2\nmean   1.5\nstddev 0.5\ntotal  3\n";
    FILE *source = cli_input("1 2"), *sink = tmpfile(), *errors = tmpfile();
    CHECK(sink != NULL && errors != NULL);
    char *stdin_args[] = {"zstats", NULL};
    CHECK(cli_invoke(source, sink, errors, 1, stdin_args) == 0);
    CHECK(cli_writes == 6 && cli_flushes == 1);
    cli_bytes(sink, want);
    CHECK(fclose(source) == 0 && fclose(sink) == 0 && fclose(errors) == 0);
    source = cli_input(""); sink = tmpfile(); errors = tmpfile();
    CHECK(sink != NULL && errors != NULL);
    char *args[] = {"zstats", "1", "2", NULL};
    CHECK(cli_invoke(source, sink, errors, 3, args) == 0);
    cli_bytes(sink, want);
    CHECK(fclose(source) == 0 && fclose(sink) == 0 && fclose(errors) == 0);
}
static void cli_empty_and_bad(void)
{
    FILE *source = cli_input(""), *sink = tmpfile(), *errors = tmpfile();
    CHECK(sink != NULL && errors != NULL);
    char *args[] = {"zstats", NULL};
    CHECK(cli_invoke(source, sink, errors, 1, args) == 0);
    cli_bytes(sink, "n      0\nmin    0\nmax    0\nmean   0\nstddev 0\ntotal  0\n");
    CHECK(fclose(source) == 0 && fclose(sink) == 0 && fclose(errors) == 0);
    source = cli_input(""); sink = tmpfile(); errors = tmpfile();
    CHECK(sink != NULL && errors != NULL);
    char *bad[] = {"zstats", "garbage", NULL};
    CHECK(cli_invoke(source, sink, errors, 2, bad) == 2);
    CHECK(cli_writes == 0 && cli_flushes == 0 && ftell(sink) == 0);
    CHECK(fclose(source) == 0 && fclose(sink) == 0 && fclose(errors) == 0);
}
static void cli_nonfinite(void)
{
    for (int from_stdin = 0; from_stdin < 2; from_stdin++) {
        FILE *source = cli_input("nan inf -inf -0");
        FILE *sink = tmpfile(), *errors = tmpfile();
        CHECK(sink != NULL && errors != NULL);
        char *args[] = {"zstats", "nan", "inf", "-inf", "-0", NULL};
        CHECK(cli_invoke(source, sink, errors, from_stdin ? 1 : 5, args) == 0);
        CHECK(cli_writes == 6 && cli_flushes == 1);
        char first[64];
        rewind(sink);
        CHECK(fgets(first, sizeof first, sink) != NULL && strcmp(first, "n      4\n") == 0);
        CHECK(fclose(source) == 0 && fclose(sink) == 0 && fclose(errors) == 0);
    }
}
static void cli_read_failure(bool prefix)
{
    FILE *source = cli_input(prefix ? "1 " : "");
    FILE *sink = tmpfile(), *errors = tmpfile();
    CHECK(source != NULL && sink != NULL && errors != NULL);
    cli_close_after_value = prefix;
    cli_close_before_scan = !prefix;
    char *args[] = {"zstats", NULL};
    int rc = cli_invoke(source, sink, errors, 1, args);
    CHECK(rc == 1);
    cli_close_after_value = false;
    cli_close_before_scan = false;
    CHECK(cli_writes == 0 && cli_flushes == 0 && ftell(sink) == 0);
    CHECK(cli_source_closed && cli_scan_values == (prefix ? 1u : 0u));
    cli_message(errors, "read error");
    CHECK(fclose(sink) == 0 && fclose(errors) == 0);
}
static void cli_write_failure(size_t target, bool buffered)
{
#ifdef _WIN32
    const char *null_path = "NUL";
#else
    const char *null_path = "/dev/null";
#endif
    FILE *source = cli_input(""), *sink = tmpfile(), *errors = tmpfile();
    FILE *bad = fopen(buffered ? "/dev/full" : null_path, buffered ? "w" : "r");
    CHECK(sink != NULL && errors != NULL && bad != NULL);
    char buffer[4096];
    if (buffered) { CHECK(setvbuf(bad, buffer, _IOFBF, sizeof buffer) == 0); }
    cli_failure_sink = bad;
    cli_fail_at = target;
    char *args[] = {"zstats", "1", "2", NULL};
    CHECK(cli_invoke(source, sink, errors, 3, args) == 1 && ferror(bad));
    cli_fail_at = 0;
    cli_failure_sink = NULL;
    CHECK(cli_writes == (buffered ? 6u : target));
    cli_message(errors, "write error");
    CHECK(fclose(source) == 0 && fclose(sink) == 0 && fclose(errors) == 0);
    (void)fclose(bad);
}
static void test_cli_parsing(void);

static void test_cli(void)
{
    test_cli_parsing();
    cli_read_failure(false);
    cli_read_failure(true);
    cli_normal();
    cli_empty_and_bad();
    cli_nonfinite();
    for (size_t target = 1; target <= 6; target++) {
        cli_write_failure(target, false);
#ifdef __linux__
        cli_write_failure(target, true);
#endif
    }
}

static void cli_bad_input(const void *bytes, size_t n)
{
    FILE *source = cli_input_bytes(bytes, n), *sink = tmpfile(), *errors = tmpfile();
    CHECK(sink != NULL && errors != NULL);
    char *args[] = {"zstats", NULL};
    CHECK(cli_invoke(source, sink, errors, 1, args) == 2);
    CHECK(cli_writes == 0 && cli_flushes == 0 && ftell(sink) == 0);
    cli_message(errors, "bad number");
    CHECK(fclose(source) == 0 && fclose(sink) == 0 && fclose(errors) == 0);
}
static void cli_bad_arguments(void)
{
    const char *bad[] = {"", " \t", "1junk", "1 ", "1e9999", "1e-9999"};
    for (size_t i = 0; i < sizeof bad / sizeof bad[0]; i++) {
        FILE *source = cli_input(""), *sink = tmpfile(), *errors = tmpfile();
        CHECK(sink != NULL && errors != NULL);
        char *args[] = {"zstats", "1", (char *)bad[i], NULL};
        CHECK(cli_invoke(source, sink, errors, 3, args) == 2);
        CHECK(cli_writes == 0 && cli_flushes == 0 && ftell(sink) == 0);
        CHECK(fclose(source) == 0 && fclose(sink) == 0 && fclose(errors) == 0);
    }
}
static void cli_complete_tokens(void)
{
    const char *bad[] = {"1 bad 2", "1-2", "3+4", "+", "1e", "1 2junk", "1 1e9999", "1 1e-9999"};
    for (size_t i = 0; i < sizeof bad / sizeof bad[0]; i++) cli_bad_input(bad[i], strlen(bad[i]));
    const char nul[] = {'1', ' ', '2', 0, '3'};
    cli_bad_input(nul, sizeof nul);
}
static void cli_valid_numbers(void)
{
    for (int from_stdin = 0; from_stdin < 2; from_stdin++) {
        FILE *source = cli_input(" \t0x1p0\v+2\f\r\n"), *sink = tmpfile(), *errors = tmpfile();
        CHECK(sink != NULL && errors != NULL);
        char *args[] = {"zstats", " \t0x1p0", "+2", NULL};
        CHECK(cli_invoke(source, sink, errors, from_stdin ? 1 : 3, args) == 0);
        cli_bytes(sink, "n      2\nmin    1\nmax    2\nmean   1.5\nstddev 0.5\ntotal  3\n");
        CHECK(cli_realloc_calls == (from_stdin ? 1u : 0u));
        CHECK(fclose(source) == 0 && fclose(sink) == 0 && fclose(errors) == 0);
    }
    FILE *source = cli_input(" \t\r\n\v\f"), *sink = tmpfile(), *errors = tmpfile();
    CHECK(sink != NULL && errors != NULL);
    char *args[] = {"zstats", NULL};
    CHECK(cli_invoke(source, sink, errors, 1, args) == 0 && cli_realloc_calls == 0);
    cli_bytes(sink, "n      0\nmin    0\nmax    0\nmean   0\nstddev 0\ntotal  0\n");
    CHECK(fclose(source) == 0 && fclose(sink) == 0 && fclose(errors) == 0);
}
static void cli_long_token(void)
{
    static char text[65538];
    memset(text, '0', sizeof text - 2);
    text[sizeof text - 2] = '1';
    text[sizeof text - 1] = 0;
    FILE *source = cli_input(text), *sink = tmpfile(), *errors = tmpfile();
    CHECK(sink != NULL && errors != NULL);
    char *args[] = {"zstats", NULL};
    CHECK(cli_invoke(source, sink, errors, 1, args) == 0);
    CHECK(cli_realloc_calls > 1);
    cli_bytes(sink, "n      1\nmin    1\nmax    1\nmean   1\nstddev 0\ntotal  1\n");
    CHECK(fclose(source) == 0 && fclose(sink) == 0 && fclose(errors) == 0);
}
static void cli_token_allocation_failures(void)
{
    char text[516];
    memcpy(text, "1 ", 2);
    memset(text + 2, '0', 512);
    text[514] = '2'; text[515] = 0;
    for (size_t fail = 1; fail <= 2; fail++) {
        FILE *source = cli_input(text), *sink = tmpfile(), *errors = tmpfile();
        CHECK(sink != NULL && errors != NULL);
        char *args[] = {"zstats", NULL};
        cli_fail_allocation = fail;
        CHECK(cli_invoke(source, sink, errors, 1, args) == 1);
        cli_fail_allocation = 0;
        CHECK(cli_realloc_calls == fail && cli_scan_values == (fail == 1 ? 0u : 1u));
        CHECK(cli_writes == 0 && cli_flushes == 0 && ftell(sink) == 0);
        cli_message(errors, "cannot allocate input token");
        CHECK(fclose(source) == 0 && fclose(sink) == 0 && fclose(errors) == 0);
    }
    struct input_token impossible = {.len = SIZE_MAX};
    cli_realloc_calls = 0;
    CHECK(!token_append(&impossible, '1'));
    CHECK(cli_realloc_calls == 0 && impossible.data == NULL && impossible.len == SIZE_MAX);
}
static void cli_partial_token_error(const char *text, size_t bytes, size_t values)
{
    FILE *source = cli_input(text), *sink = tmpfile(), *errors = tmpfile();
    CHECK(sink != NULL && errors != NULL);
    char *args[] = {"zstats", NULL};
    cli_close_after_bytes = bytes;
    CHECK(cli_invoke(source, sink, errors, 1, args) == 1);
    cli_close_after_bytes = 0;
    CHECK(cli_source_closed && cli_scan_values == values);
    CHECK(cli_writes == 0 && cli_flushes == 0 && ftell(sink) == 0);
    cli_message(errors, "read error");
    CHECK(fclose(sink) == 0 && fclose(errors) == 0);
}
static void test_cli_parsing(void)
{
    cli_bad_arguments();
    cli_complete_tokens();
    cli_valid_numbers();
    cli_long_token();
    cli_token_allocation_failures();
    cli_partial_token_error("1 2", 3, 1);
    cli_partial_token_error("+", 1, 0);
    cli_partial_token_error("1", 1, 0);
}
