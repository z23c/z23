#include "zmath/zmath.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(cond) do { \
    if (!(cond)) { \
        fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); \
        exit(1); \
    } \
} while (0)

static void test_checked_u64(void)
{
    uint64_t v = 12345;

    CHECK(zmath_add_u64(1, 2, &v) && v == 3);
    CHECK(zmath_add_u64(UINT64_MAX, 0, &v) && v == UINT64_MAX);
    CHECK(!zmath_add_u64(UINT64_MAX, 1, &v) && v == UINT64_MAX); /* unchanged */
    CHECK(!zmath_add_u64(UINT64_MAX, UINT64_MAX, &v));

    CHECK(zmath_sub_u64(3, 2, &v) && v == 1);
    CHECK(zmath_sub_u64(0, 0, &v) && v == 0);
    v = 77;
    CHECK(!zmath_sub_u64(2, 3, &v) && v == 77);

    CHECK(zmath_mul_u64(3, 4, &v) && v == 12);
    CHECK(zmath_mul_u64(0, UINT64_MAX, &v) && v == 0);
    CHECK(!zmath_mul_u64(1ull << 32, 1ull << 32, &v)); /* 2^64 overflows */
    CHECK(zmath_mul_u64(1ull << 32, (1ull << 32) - 1, &v)
          && v == UINT64_MAX - (1ull << 32) + 1); /* 2^64 - 2^32 */
    v = 88;
    CHECK(!zmath_mul_u64(1ull << 33, 1ull << 32, &v) && v == 88);
    CHECK(!zmath_mul_u64(UINT64_MAX, 2, &v));

    CHECK(!zmath_add_u64(1, 1, NULL));
    CHECK(!zmath_sub_u64(1, 1, NULL));
    CHECK(!zmath_mul_u64(1, 1, NULL));

    size_t s = 0;
    CHECK(zmath_add_size(1, 2, &s) && s == 3);
    CHECK(!zmath_add_size(SIZE_MAX, 1, &s) && s == 3);
    CHECK(zmath_mul_size(6, 7, &s) && s == 42);
    CHECK(!zmath_mul_size(SIZE_MAX, 2, &s) && s == 42);
    CHECK(!zmath_add_size(1, 1, NULL));
}

static void test_checked_i64(void)
{
    int64_t v = 12345;

    CHECK(zmath_add_i64(1, 2, &v) && v == 3);
    CHECK(zmath_add_i64(-1, -2, &v) && v == -3);
    CHECK(zmath_add_i64(INT64_MAX, 0, &v) && v == INT64_MAX);
    CHECK(zmath_add_i64(INT64_MIN, 0, &v) && v == INT64_MIN);
    CHECK(!zmath_add_i64(INT64_MAX, 1, &v) && v == INT64_MIN);
    CHECK(!zmath_add_i64(INT64_MIN, -1, &v));

    CHECK(zmath_sub_i64(1, 2, &v) && v == -1);
    CHECK(zmath_sub_i64(INT64_MIN, 0, &v) && v == INT64_MIN);
    CHECK(!zmath_sub_i64(INT64_MIN, 1, &v));
    CHECK(!zmath_sub_i64(INT64_MAX, -1, &v));
    CHECK(zmath_sub_i64(INT64_MAX, INT64_MAX, &v) && v == 0);
    CHECK(zmath_sub_i64(INT64_MIN, INT64_MIN, &v) && v == 0);

    CHECK(zmath_mul_i64(3, 4, &v) && v == 12);
    CHECK(zmath_mul_i64(-3, 4, &v) && v == -12);
    CHECK(zmath_mul_i64(-3, -4, &v) && v == 12);
    CHECK(zmath_mul_i64(0, INT64_MIN, &v) && v == 0);
    CHECK(zmath_mul_i64(INT64_MIN, 1, &v) && v == INT64_MIN);
    CHECK(zmath_mul_i64(INT64_MAX, 1, &v) && v == INT64_MAX);
    v = 55;
    CHECK(!zmath_mul_i64(INT64_MIN, -1, &v) && v == 55);
    CHECK(!zmath_mul_i64(-1, INT64_MIN, &v));
    CHECK(!zmath_mul_i64(INT64_MAX, 2, &v));
    CHECK(!zmath_mul_i64(INT64_MIN, 2, &v));
    CHECK(!zmath_mul_i64(1ll << 32, 1ll << 32, &v));
    CHECK(!zmath_mul_i64(-(1ll << 32), 1ll << 32, &v));
    CHECK(!zmath_mul_i64(1ll << 31, 1ll << 32, &v)); /* 2^63 overflows */
    CHECK(zmath_mul_i64(1ll << 31, 1ll << 31, &v) && v == (1ll << 62));
    CHECK(zmath_mul_i64(-4611686018427387904ll, -2, &v) == false); /* 2^63 */
    CHECK(zmath_mul_i64(-4611686018427387903ll, -2, &v) && v == 9223372036854775806ll);

    CHECK(!zmath_add_i64(1, 1, NULL));
    CHECK(!zmath_sub_i64(1, 1, NULL));
    CHECK(!zmath_mul_i64(1, 1, NULL));
}

static void test_saturating(void)
{
    CHECK(zmath_sat_add_u64(1, 2) == 3);
    CHECK(zmath_sat_add_u64(UINT64_MAX, 1) == UINT64_MAX);
    CHECK(zmath_sat_sub_u64(1, 2) == 0);
    CHECK(zmath_sat_sub_u64(2, 1) == 1);
    CHECK(zmath_sat_mul_u64(3, 4) == 12);
    CHECK(zmath_sat_mul_u64(UINT64_MAX, 2) == UINT64_MAX);

    CHECK(zmath_sat_add_i64(1, 2) == 3);
    CHECK(zmath_sat_add_i64(INT64_MAX, 1) == INT64_MAX);
    CHECK(zmath_sat_add_i64(INT64_MIN, -1) == INT64_MIN);
    CHECK(zmath_sat_sub_i64(INT64_MIN, 1) == INT64_MIN);
    CHECK(zmath_sat_sub_i64(INT64_MAX, -1) == INT64_MAX);
    CHECK(zmath_sat_sub_i64(1, 2) == -1);
}

static void test_number_theory(void)
{
    CHECK(zmath_div_ceil_u64(10, 3) == 4);
    CHECK(zmath_div_ceil_u64(9, 3) == 3);
    CHECK(zmath_div_ceil_u64(0, 3) == 0);
    CHECK(zmath_div_ceil_u64(10, 0) == 0);
    CHECK(zmath_div_ceil_u64(UINT64_MAX, 1) == UINT64_MAX);

    CHECK(zmath_gcd(0, 0) == 0);
    CHECK(zmath_gcd(12, 0) == 12);
    CHECK(zmath_gcd(0, 7) == 7);
    CHECK(zmath_gcd(12, 18) == 6);
    CHECK(zmath_gcd(17, 31) == 1);
    CHECK(zmath_gcd(1ull << 62, 1ull << 62) == (1ull << 62));

    uint64_t v;
    CHECK(zmath_lcm(4, 6, &v) && v == 12);
    CHECK(zmath_lcm(0, 5, &v) && v == 0);
    CHECK(zmath_lcm(7, 13, &v) && v == 91);
    CHECK(!zmath_lcm(UINT64_MAX, 2, &v));
    CHECK(!zmath_lcm(1, 1, NULL));

    CHECK(zmath_pow_u64(2, 10, &v) && v == 1024);
    CHECK(zmath_pow_u64(3, 0, &v) && v == 1);
    CHECK(zmath_pow_u64(0, 0, &v) && v == 1);
    CHECK(zmath_pow_u64(0, 5, &v) && v == 0);
    CHECK(zmath_pow_u64(1, 1000000, &v) && v == 1);
    CHECK(zmath_pow_u64(2, 63, &v) && v == (1ull << 63));
    CHECK(!zmath_pow_u64(2, 64, &v));
    CHECK(!zmath_pow_u64(UINT64_MAX, 2, &v));
    CHECK(!zmath_pow_u64(2, 1, NULL));

    CHECK(zmath_digits_u64(0) == 1);
    CHECK(zmath_digits_u64(9) == 1);
    CHECK(zmath_digits_u64(10) == 2);
    CHECK(zmath_digits_u64(9999999999999999999ull) == 19);
    CHECK(zmath_digits_u64(UINT64_MAX) == 20);
}

static void test_minmax_clamp_abs(void)
{
    CHECK(zmath_min_i64(-1, 1) == -1);
    CHECK(zmath_max_i64(-1, 1) == 1);
    CHECK(zmath_min_u64(1, 2) == 1);
    CHECK(zmath_max_u64(1, 2) == 2);
    CHECK(zmath_min_i64(INT64_MIN, INT64_MAX) == INT64_MIN);

    CHECK(zmath_clamp_i64(5, 0, 10) == 5);
    CHECK(zmath_clamp_i64(-5, 0, 10) == 0);
    CHECK(zmath_clamp_i64(50, 0, 10) == 10);
    CHECK(zmath_clamp_i64(5, 10, 0) == 10); /* inverted range -> lo */
    CHECK(zmath_clamp_u64(5, 0, 10) == 5);
    CHECK(zmath_clamp_u64(50, 0, 10) == 10);

    CHECK(zmath_abs_i64(0) == 0);
    CHECK(zmath_abs_i64(-5) == 5);
    CHECK(zmath_abs_i64(5) == 5);
    CHECK(zmath_abs_i64(INT64_MIN) == (uint64_t)INT64_MAX + 1);
    CHECK(zmath_abs_i64(INT64_MAX) == (uint64_t)INT64_MAX);
}

static uint64_t rng_state = 0x0123456789abcdefull;
static uint64_t rng_next(void)
{
    rng_state ^= rng_state << 13;
    rng_state ^= rng_state >> 7;
    rng_state ^= rng_state << 17;
    return rng_state;
}

static void test_fuzz_vs_wide(void)
{
    /* Cross-check against __int128 over random operands. */
    for (int i = 0; i < 100000; i++) {
        uint64_t a = rng_next() >> (rng_next() % 64);
        uint64_t b = rng_next() >> (rng_next() % 64);

        __uint128_t w = (__uint128_t)a + b;
        uint64_t r;
        bool ok = zmath_add_u64(a, b, &r);
        CHECK(ok == (w <= UINT64_MAX));
        if (ok) CHECK((__uint128_t)r == w);

        w = (__uint128_t)a * b;
        ok = zmath_mul_u64(a, b, &r);
        CHECK(ok == (w <= UINT64_MAX));
        if (ok) CHECK((__uint128_t)r == w);

        __int128_t sw = (__int128_t)(int64_t)a * (__int128_t)(int64_t)b;
        int64_t sr;
        ok = zmath_mul_i64((int64_t)a, (int64_t)b, &sr);
        CHECK(ok == (sw >= INT64_MIN && sw <= INT64_MAX));
        if (ok) CHECK((__int128_t)sr == sw);

        __int128_t s2 = (__int128_t)(int64_t)a + (int64_t)b;
        ok = zmath_add_i64((int64_t)a, (int64_t)b, &sr);
        CHECK(ok == (s2 >= INT64_MIN && s2 <= INT64_MAX));
        if (ok) CHECK((__int128_t)sr == s2);

        __int128_t s3 = (__int128_t)(int64_t)a - (int64_t)b;
        ok = zmath_sub_i64((int64_t)a, (int64_t)b, &sr);
        CHECK(ok == (s3 >= INT64_MIN && s3 <= INT64_MAX));
        if (ok) CHECK((__int128_t)sr == s3);
    }
}

int main(void)
{
    test_checked_u64();
    test_checked_i64();
    test_saturating();
    test_number_theory();
    test_minmax_clamp_abs();
    test_fuzz_vs_wide();
    puts("test_zmath: all groups passed (u64 i64 sat theory clamp fuzz)");
    return 0;
}
