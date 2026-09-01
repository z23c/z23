#include "zstats/zstats.h"


#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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

int main(void)
{
    test_empty_and_single();
    test_known_dataset();
    test_repeated_and_merge();
    test_fuzz_vs_reference();
    puts("test_zstats: all groups passed (empty known repeated merge fuzz)");
    return 0;
}
