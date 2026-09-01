#include "zmath/zmath.h"

bool zmath_add_u64(uint64_t a, uint64_t b, uint64_t *out)
{
    if (!out) return false;
    if (a > UINT64_MAX - b) return false;
    *out = a + b;
    return true;
}

bool zmath_sub_u64(uint64_t a, uint64_t b, uint64_t *out)
{
    if (!out) return false;
    if (a < b) return false;
    *out = a - b;
    return true;
}

bool zmath_mul_u64(uint64_t a, uint64_t b, uint64_t *out)
{
    if (!out) return false;
    if (a != 0 && b > UINT64_MAX / a) return false;
    *out = a * b;
    return true;
}

bool zmath_add_i64(int64_t a, int64_t b, int64_t *out)
{
    if (!out) return false;
    if ((b > 0 && a > INT64_MAX - b) || (b < 0 && a < INT64_MIN - b))
        return false;
    *out = a + b;
    return true;
}

bool zmath_sub_i64(int64_t a, int64_t b, int64_t *out)
{
    if (!out) return false;
    if ((b < 0 && a > INT64_MAX + b) || (b > 0 && a < INT64_MIN + b))
        return false;
    *out = a - b;
    return true;
}

bool zmath_mul_i64(int64_t a, int64_t b, int64_t *out)
{
    if (!out) return false;
    if (a == 0 || b == 0) { *out = 0; return true; }
    if (a == -1) {
        if (b == INT64_MIN) return false;
        *out = -b;
        return true;
    }
    if (b == -1) {
        if (a == INT64_MIN) return false;
        *out = -a;
        return true;
    }
    /* |a*b| <= INT64_MAX for same sign, <= -INT64_MIN otherwise. */
    int64_t limit = ((a < 0) == (b < 0)) ? INT64_MAX : INT64_MIN;
    if (a > 0) {
        if (b > 0) { if (a > limit / b) return false; }
        else       { if (b < limit / a) return false; }
    } else {
        if (b > 0) { if (a < limit / b) return false; }
        else       { if (a < limit / b) return false; }
    }
    *out = a * b;
    return true;
}

bool zmath_add_size(size_t a, size_t b, size_t *out)
{
    if (!out) return false;
    if (a > SIZE_MAX - b) return false;
    *out = a + b;
    return true;
}

bool zmath_mul_size(size_t a, size_t b, size_t *out)
{
    if (!out) return false;
    if (a != 0 && b > SIZE_MAX / a) return false;
    *out = a * b;
    return true;
}

uint64_t zmath_sat_add_u64(uint64_t a, uint64_t b)
{
    uint64_t r = a + b;
    return r < a ? UINT64_MAX : r;
}

uint64_t zmath_sat_sub_u64(uint64_t a, uint64_t b)
{
    return a < b ? 0 : a - b;
}

uint64_t zmath_sat_mul_u64(uint64_t a, uint64_t b)
{
    if (a != 0 && b > UINT64_MAX / a) return UINT64_MAX;
    return a * b;
}

int64_t zmath_sat_add_i64(int64_t a, int64_t b)
{
    int64_t r;
    if (!zmath_add_i64(a, b, &r))
        return b > 0 ? INT64_MAX : INT64_MIN;
    return r;
}

int64_t zmath_sat_sub_i64(int64_t a, int64_t b)
{
    int64_t r;
    if (!zmath_sub_i64(a, b, &r))
        return b < 0 ? INT64_MAX : INT64_MIN;
    return r;
}

uint64_t zmath_div_ceil_u64(uint64_t a, uint64_t b)
{
    if (b == 0) return 0;
    return a / b + (a % b != 0 ? 1 : 0);
}

uint64_t zmath_gcd(uint64_t a, uint64_t b)
{
    while (b != 0) {
        uint64_t t = a % b;
        a = b;
        b = t;
    }
    return a;
}

bool zmath_lcm(uint64_t a, uint64_t b, uint64_t *out)
{
    if (!out) return false;
    if (a == 0 || b == 0) { *out = 0; return true; }
    uint64_t g = zmath_gcd(a, b);
    uint64_t reduced = a / g;
    if (reduced > UINT64_MAX / b) return false;
    *out = reduced * b;
    return true;
}

bool zmath_pow_u64(uint64_t base, unsigned exp, uint64_t *out)
{
    if (!out) return false;
    uint64_t result = 1;
    while (exp > 0) {
        if (exp & 1u) {
            if (result != 0 && base > UINT64_MAX / result) return false;
            result *= base;
        }
        exp >>= 1;
        if (exp > 0) {
            if (base != 0 && base > UINT64_MAX / base) return false;
            base *= base;
        }
    }
    *out = result;
    return true;
}

unsigned zmath_digits_u64(uint64_t v)
{
    unsigned n = 1;
    while (v >= 10) {
        v /= 10;
        n++;
    }
    return n;
}

int64_t zmath_min_i64(int64_t a, int64_t b) { return a < b ? a : b; }
int64_t zmath_max_i64(int64_t a, int64_t b) { return a > b ? a : b; }
uint64_t zmath_min_u64(uint64_t a, uint64_t b) { return a < b ? a : b; }
uint64_t zmath_max_u64(uint64_t a, uint64_t b) { return a > b ? a : b; }

int64_t zmath_clamp_i64(int64_t v, int64_t lo, int64_t hi)
{
    if (lo > hi) return lo;
    return v < lo ? lo : (v > hi ? hi : v);
}

uint64_t zmath_clamp_u64(uint64_t v, uint64_t lo, uint64_t hi)
{
    if (lo > hi) return lo;
    return v < lo ? lo : (v > hi ? hi : v);
}

uint64_t zmath_abs_i64(int64_t v)
{
    return v < 0 ? (uint64_t)(-(v + 1)) + 1 : (uint64_t)v;
}
