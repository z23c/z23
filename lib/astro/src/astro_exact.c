/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * astro_exact — the fixed-grid signed scalar every chart value is computed
 * in. The contract, the rounding rule and the exact/cosmetic boundary are
 * stated in full in astro/astro_exact.h; this file is the implementation and
 * assumes that header has been read.
 *
 * Two invariants hold on every value that leaves this file:
 *   - a value with used == 0 is never negative, so zero has one encoding and
 *     astro_exact_identical() is a total equality;
 *   - an invalid value carries no magnitude, so it cannot be mistaken for a
 *     number by a caller that forgot to check.
 */

#include "astro_priv.h"

#include <string.h>

/* EXACT PATH — see astro_priv.h. */
#pragma GCC poison double float

struct astro_exact astro_exact_invalid(void)
{
    struct astro_exact r;
    memset(&r, 0, sizeof(r));
    return r; /* valid == false */
}

struct astro_exact astro_exact_zero(void)
{
    struct astro_exact r;
    memset(&r, 0, sizeof(r));
    r.valid = true;
    return r;
}

bool astro_exact_is_valid(const struct astro_exact *a)
{
    return a != NULL && a->valid;
}

bool astro_exact_is_zero(const struct astro_exact *a)
{
    return a != NULL && a->valid && a->used == 0;
}

bool astro_exact_is_negative(const struct astro_exact *a)
{
    return a != NULL && a->valid && a->used != 0 && a->negative;
}

struct astro_exact astro_exact_from_i64(int64_t v)
{
    bool neg = v < 0;
    /* -INT64_MIN overflows; take the magnitude through uint64_t. */
    uint64_t mag = neg ? (uint64_t)(-(v + 1)) + 1u : (uint64_t)v;

    struct astro_mag m, shifted;
    astro_mag_from_u64(&m, mag);
    if (!astro_mag_shl(&shifted, &m, ASTRO_EXACT_FRAC_BITS))
        return astro_exact_invalid();

    struct astro_exact out;
    if (!astro_exact_pack(&out, &shifted, neg))
        return astro_exact_invalid();
    return out;
}

struct astro_exact astro_exact_ratio(int64_t num, int64_t den)
{
    if (den == 0)
        return astro_exact_invalid();

    bool neg = (num < 0) != (den < 0);
    uint64_t nmag = num < 0 ? (uint64_t)(-(num + 1)) + 1u : (uint64_t)num;
    uint64_t dmag = den < 0 ? (uint64_t)(-(den + 1)) + 1u : (uint64_t)den;

    struct astro_mag n, shifted, q;
    astro_mag_from_u64(&n, nmag);
    if (!astro_mag_shl(&shifted, &n, ASTRO_EXACT_FRAC_BITS))
        return astro_exact_invalid();
    if (!astro_mag_div_u64(&q, NULL, &shifted, dmag))
        return astro_exact_invalid();

    struct astro_exact out;
    if (!astro_exact_pack(&out, &q, neg))
        return astro_exact_invalid();
    return out;
}

int astro_exact_cmp(const struct astro_exact *a, const struct astro_exact *b)
{
    if (!astro_exact_is_valid(a) || !astro_exact_is_valid(b))
        return 0;
    if (a->used == 0 && b->used == 0)
        return 0;
    if (a->negative != b->negative)
        return a->negative ? -1 : 1;

    struct astro_mag ma, mb;
    astro_exact_unpack(&ma, a);
    astro_exact_unpack(&mb, b);
    int c = astro_mag_cmp(&ma, &mb);
    return a->negative ? -c : c;
}

bool astro_exact_identical(const struct astro_exact *a,
                           const struct astro_exact *b)
{
    if (a == NULL || b == NULL)
        return false;
    if (a->valid != b->valid)
        return false;
    if (!a->valid)
        return true; /* every invalid value is the same non-number */
    if (a->used != b->used || a->negative != b->negative)
        return false;
    for (unsigned i = 0; i < a->used; i++) {
        if (a->limb[i] != b->limb[i])
            return false;
    }
    return true;
}

struct astro_exact astro_exact_neg(struct astro_exact a)
{
    if (!a.valid)
        return astro_exact_invalid();
    if (a.used != 0)
        a.negative = !a.negative;
    return a;
}

struct astro_exact astro_exact_abs(struct astro_exact a)
{
    if (!a.valid)
        return astro_exact_invalid();
    a.negative = false;
    return a;
}

/* One signed add/sub kernel. EXACT: the magnitudes are added or subtracted
 * whole, so no information is discarded and the operation is associative. */
static struct astro_exact signed_add(struct astro_exact a, struct astro_exact b,
                                     bool negate_b)
{
    if (!a.valid || !b.valid)
        return astro_exact_invalid();
    if (b.used != 0 && negate_b)
        b.negative = !b.negative;

    struct astro_mag ma, mb, mr;
    astro_exact_unpack(&ma, &a);
    astro_exact_unpack(&mb, &b);

    struct astro_exact out;
    if (a.negative == b.negative) {
        if (!astro_mag_add(&mr, &ma, &mb))
            return astro_exact_invalid();
        if (!astro_exact_pack(&out, &mr, a.negative))
            return astro_exact_invalid();
        return out;
    }

    int c = astro_mag_cmp(&ma, &mb);
    if (c >= 0) {
        if (!astro_mag_sub(&mr, &ma, &mb))
            return astro_exact_invalid();
        if (!astro_exact_pack(&out, &mr, a.negative))
            return astro_exact_invalid();
    } else {
        if (!astro_mag_sub(&mr, &mb, &ma))
            return astro_exact_invalid();
        if (!astro_exact_pack(&out, &mr, b.negative))
            return astro_exact_invalid();
    }
    return out;
}

struct astro_exact astro_exact_add(struct astro_exact a, struct astro_exact b)
{
    return signed_add(a, b, false);
}

struct astro_exact astro_exact_sub(struct astro_exact a, struct astro_exact b)
{
    return signed_add(a, b, true);
}

struct astro_exact astro_exact_mul(struct astro_exact a, struct astro_exact b)
{
    if (!a.valid || !b.valid)
        return astro_exact_invalid();

    struct astro_mag ma, mb, mp, mr;
    astro_exact_unpack(&ma, &a);
    astro_exact_unpack(&mb, &b);
    if (!astro_mag_mul(&mp, &ma, &mb))
        return astro_exact_invalid();
    /* The product carries 2*FRAC_BITS of fraction; shift one copy back off.
     * Truncation toward zero of the magnitude — the module's one rounding
     * rule, stated in astro_exact.h. */
    astro_mag_shr(&mr, &mp, ASTRO_EXACT_FRAC_BITS);

    struct astro_exact out;
    if (!astro_exact_pack(&out, &mr, a.negative != b.negative))
        return astro_exact_invalid();
    return out;
}

struct astro_exact astro_exact_div(struct astro_exact a, struct astro_exact b)
{
    if (!a.valid || !b.valid || b.used == 0)
        return astro_exact_invalid();

    struct astro_mag ma, mb, shifted, q;
    astro_exact_unpack(&ma, &a);
    astro_exact_unpack(&mb, &b);
    if (!astro_mag_shl(&shifted, &ma, ASTRO_EXACT_FRAC_BITS))
        return astro_exact_invalid();
    if (!astro_mag_divmod(&q, NULL, &shifted, &mb))
        return astro_exact_invalid();

    struct astro_exact out;
    if (!astro_exact_pack(&out, &q, a.negative != b.negative))
        return astro_exact_invalid();
    return out;
}

struct astro_exact astro_exact_shr(struct astro_exact a, unsigned bits)
{
    if (!a.valid)
        return astro_exact_invalid();

    struct astro_mag ma, mr;
    astro_exact_unpack(&ma, &a);
    astro_mag_shr(&mr, &ma, bits);

    struct astro_exact out;
    if (!astro_exact_pack(&out, &mr, a.negative))
        return astro_exact_invalid();
    return out;
}

struct astro_exact astro_exact_sqrt(struct astro_exact a)
{
    if (!a.valid || (a.used != 0 && a.negative))
        return astro_exact_invalid();
    if (a.used == 0)
        return astro_exact_zero();

    /* sqrt(V / 2^F) * 2^F == sqrt(V * 2^F), so shift up by one whole grid
     * before taking the integer root. */
    struct astro_mag ma, shifted, root;
    astro_exact_unpack(&ma, &a);
    if (!astro_mag_shl(&shifted, &ma, ASTRO_EXACT_FRAC_BITS))
        return astro_exact_invalid();
    astro_mag_isqrt(&root, &shifted);

    struct astro_exact out;
    if (!astro_exact_pack(&out, &root, false))
        return astro_exact_invalid();
    return out;
}

struct astro_exact astro_exact_mod(struct astro_exact a, struct astro_exact m)
{
    if (!a.valid || !m.valid || m.used == 0 || m.negative)
        return astro_exact_invalid();

    struct astro_mag ma, mm, rem;
    astro_exact_unpack(&ma, &a);
    astro_exact_unpack(&mm, &m);
    if (!astro_mag_divmod(NULL, &rem, &ma, &mm))
        return astro_exact_invalid();

    struct astro_exact out;
    if (!a.negative || astro_mag_is_zero(&rem)) {
        if (!astro_exact_pack(&out, &rem, false))
            return astro_exact_invalid();
        return out;
    }
    /* Negative input: the representative in [0, m) is m - (|a| mod m). */
    struct astro_mag comp;
    if (!astro_mag_sub(&comp, &mm, &rem))
        return astro_exact_invalid();
    if (!astro_exact_pack(&out, &comp, false))
        return astro_exact_invalid();
    return out;
}

bool astro_exact_floor_i64(const struct astro_exact *a, int64_t *out)
{
    if (out == NULL || !astro_exact_is_valid(a))
        return false;

    struct astro_mag ma, whole, shifted_back, diff;
    astro_exact_unpack(&ma, a);
    astro_mag_shr(&whole, &ma, ASTRO_EXACT_FRAC_BITS);
    /* Is there a fractional part? Compare the truncated value shifted back up
     * against the original rather than masking, so the test needs no second
     * width-dependent constant. */
    if (!astro_mag_shl(&shifted_back, &whole, ASTRO_EXACT_FRAC_BITS))
        return false;
    if (!astro_mag_sub(&diff, &ma, &shifted_back))
        return false;
    bool has_frac = !astro_mag_is_zero(&diff);

    if (whole.used > 1)
        return false;
    uint64_t mag = whole.used == 1 ? whole.limb[0] : 0;

    if (!a->negative) {
        if (mag > (uint64_t)INT64_MAX)
            return false;
        *out = (int64_t)mag;
        return true;
    }
    /* floor of a negative rounds AWAY from zero when a fraction was dropped. */
    if (has_frac) {
        if (mag == UINT64_MAX)
            return false;
        mag += 1u;
    }
    if (mag > (uint64_t)INT64_MAX + 1u)
        return false;
    if (mag == (uint64_t)INT64_MAX + 1u) {
        *out = INT64_MIN;
        return true;
    }
    *out = -(int64_t)mag;
    return true;
}

bool astro_exact_format(const struct astro_exact *a, unsigned frac_digits,
                        char *buf, size_t buf_len)
{
    if (buf == NULL || buf_len == 0)
        return false;
    buf[0] = '\0';
    if (!astro_exact_is_valid(a) || frac_digits > 18u)
        return false;

    struct astro_mag ma, whole, back, rem;
    astro_exact_unpack(&ma, a);
    astro_mag_shr(&whole, &ma, ASTRO_EXACT_FRAC_BITS);
    if (!astro_mag_shl(&back, &whole, ASTRO_EXACT_FRAC_BITS))
        return false;
    if (!astro_mag_sub(&rem, &ma, &back))
        return false;

    /* Integer part, decimal digits, most significant last. Sized for the
     * widest value the type can hold (2^640 is 193 decimal digits), so the
     * only reason this function ever refuses is the caller's buffer — never a
     * scratch array of its own that a large but perfectly valid number
     * happened to outgrow. */
    char int_digits[208];
    size_t int_count = 0;
    if (astro_mag_is_zero(&whole)) {
        int_digits[int_count++] = '0';
    } else {
        struct astro_mag cur = whole;
        while (!astro_mag_is_zero(&cur) && int_count < sizeof(int_digits)) {
            uint64_t d = 0;
            struct astro_mag q;
            if (!astro_mag_div_u64(&q, &d, &cur, 10u))
                return false;
            int_digits[int_count++] = (char)('0' + (int)d);
            cur = q;
        }
        if (!astro_mag_is_zero(&cur))
            return false; /* number wider than the digit buffer */
    }

    /* Fractional part: rem * 10^frac_digits >> FRAC_BITS, truncated. */
    uint64_t scale = 1u;
    for (unsigned i = 0; i < frac_digits; i++)
        scale *= 10u;
    struct astro_mag scale_mag, scaled, frac_int;
    astro_mag_from_u64(&scale_mag, scale);
    if (!astro_mag_mul(&scaled, &rem, &scale_mag))
        return false;
    astro_mag_shr(&frac_int, &scaled, ASTRO_EXACT_FRAC_BITS);
    uint64_t frac_val = frac_int.used == 0 ? 0 : frac_int.limb[0];
    if (frac_int.used > 1)
        return false;

    size_t need = int_count + (a->negative ? 1u : 0u) +
                  (frac_digits > 0 ? frac_digits + 1u : 0u) + 1u;
    if (need > buf_len)
        return false;

    size_t pos = 0;
    if (a->negative)
        buf[pos++] = '-';
    for (size_t i = int_count; i > 0; i--)
        buf[pos++] = int_digits[i - 1];
    if (frac_digits > 0) {
        buf[pos++] = '.';
        for (unsigned i = frac_digits; i > 0; i--) {
            buf[pos + i - 1] = (char)('0' + (int)(frac_val % 10u));
            frac_val /= 10u;
        }
        pos += frac_digits;
    }
    buf[pos] = '\0';
    return true;
}
