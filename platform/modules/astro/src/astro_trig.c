/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * astro_trig — sine, cosine and atan2 on the exact grid, by CORDIC.
 *
 * ── Why CORDIC and not a series ──────────────────────────────────────────
 * CORDIC needs only shifts, adds and a table of arctangents. On this module's
 * integer grid every one of those is exact, so the routine's output is a pure
 * function of its input bits and the fixed iteration count — the property the
 * whole module exists to provide. A Taylor or minimax series would need
 * repeated multiplication and division of growing intermediates and would
 * round in more places for no accuracy gain here.
 *
 * ── Why the tables are COMPUTED, not written down ────────────────────────
 * Every constant this file needs — pi, atan(2^-i) for each iteration, and the
 * CORDIC gain — is derived at first use by integer series over the exact type
 * itself. Nothing is transcribed from a decimal literal.
 *
 * That is a deliberate correction of the source this file is adapted from
 * (astro-calc core/rational/{rat_trig,cordic_tables}.c, Apache-2.0, same
 * author). There the tables were hand-written approximations — pi as
 * 103993/33102, the CORDIC gain as 1647/1000, atan(2^-i) rounded to eight
 * decimal digits for i < 4 and replaced outright by 2^-i for every i above
 * that. Eight-digit tables cap the result at roughly eight digits no matter
 * how many iterations run, and the 2^-i substitution is simply a different
 * function. Computing them instead costs a few milliseconds once and makes
 * the accuracy a property of the iteration count rather than of how much
 * patience someone had while typing. (The same source's quadrant fix-up also
 * swapped sine and cosine in the second and fourth quadrants; the mapping
 * below is written out per quadrant so that cannot recur silently.)
 *
 * Provenance of the method: pi via Machin's 1706 formula
 * pi/4 = 4*atan(1/5) - atan(1/239); the rotation itself is Volder's 1959
 * CORDIC. Both are classical results, not data from any external table.
 */

#include "astro_priv.h"

#include <string.h>

/* EXACT PATH — see astro_priv.h. */
#pragma GCC poison double float

/* Iterations, and therefore the size of the arctangent table. Each iteration
 * adds about one bit; 60 puts the rotation's own error near 2^-60 radians,
 * far below the arcminute-scale error of the planetary theory that consumes
 * it, and far above the resolution of anything a chart reports. The number is
 * part of the contract: changing it changes every chart's low bits, so it is
 * a wire-visible constant, not a tuning knob. */
#define ASTRO_CORDIC_ITERS 60u

static bool g_ready;
static bool g_failed;
static struct astro_exact g_pi;
static struct astro_exact g_two_pi;
static struct astro_exact g_half_pi;
static struct astro_exact g_atan_pow2[ASTRO_CORDIC_ITERS];
static struct astro_exact g_inv_gain;

/* ── series used only during table construction ───────────────────────── */

/* atan(1/n) for integer n >= 2, by the alternating series
 *     atan(x) = x - x^3/3 + x^5/5 - ...
 * with x = 1/n. Terms shrink by n^-2 each step, so the loop ends when the
 * term reaches zero on the grid: an exact, data-independent stopping rule
 * rather than a tolerance someone chose. */
static struct astro_exact atan_inv_int(uint64_t n)
{
    if (n < 2u)
        return astro_exact_invalid();
    if (n > 3037000499u) /* n*n must not overflow uint64_t */
        return astro_exact_invalid();

    uint64_t n2 = n * n;
    struct astro_exact term = astro_exact_ratio(1, (int64_t)n);
    struct astro_exact sum = astro_exact_zero();
    uint64_t denom = 1u;
    bool add = true;

    for (unsigned step = 0; step < 512u; step++) {
        if (!astro_exact_is_valid(&term))
            return astro_exact_invalid();
        if (astro_exact_is_zero(&term))
            return sum;

        struct astro_exact piece =
            astro_exact_div(term, astro_exact_from_i64((int64_t)denom));
        sum = add ? astro_exact_add(sum, piece) : astro_exact_sub(sum, piece);
        add = !add;
        denom += 2u;

        term = astro_exact_div(term, astro_exact_from_i64((int64_t)n2));
    }
    return astro_exact_invalid(); /* did not converge in the step budget */
}

/* atan(2^-k) for k >= 1 by the same series, but with every power of the
 * argument produced by a shift instead of a division. k == 0 is atan(1),
 * where the series does not converge usefully; the caller supplies pi/4. */
static struct astro_exact atan_inv_pow2(unsigned k)
{
    struct astro_exact one = astro_exact_from_i64(1);
    struct astro_exact sum = astro_exact_zero();
    uint64_t denom = 1u;
    bool add = true;

    for (unsigned step = 0; step < 512u; step++) {
        unsigned shift = k * (2u * step + 1u);
        if (shift >= ASTRO_EXACT_FRAC_BITS + 64u)
            return sum;

        struct astro_exact term = astro_exact_shr(one, shift);
        if (!astro_exact_is_valid(&term))
            return astro_exact_invalid();
        if (astro_exact_is_zero(&term))
            return sum;

        struct astro_exact piece =
            astro_exact_div(term, astro_exact_from_i64((int64_t)denom));
        sum = add ? astro_exact_add(sum, piece) : astro_exact_sub(sum, piece);
        add = !add;
        denom += 2u;
    }
    return astro_exact_invalid();
}

/* 1/K where K = prod sqrt(1 + 2^-2i) is the CORDIC gain. K^2 is a product of
 * exact grid values, so squaring first means the whole constant needs exactly
 * one square root instead of one per iteration. */
static struct astro_exact cordic_inverse_gain(void)
{
    struct astro_exact one = astro_exact_from_i64(1);
    struct astro_exact k2 = one;
    for (unsigned i = 0; i < ASTRO_CORDIC_ITERS; i++) {
        struct astro_exact t = astro_exact_add(one, astro_exact_shr(one, 2u * i));
        k2 = astro_exact_mul(k2, t);
        if (!astro_exact_is_valid(&k2))
            return astro_exact_invalid();
    }
    return astro_exact_div(one, astro_exact_sqrt(k2));
}

bool astro_trig_tables_ready(void)
{
    if (g_ready)
        return true;
    if (g_failed)
        return false;

    /* pi = 16*atan(1/5) - 4*atan(1/239)  (Machin, 1706). */
    struct astro_exact a5 = atan_inv_int(5u);
    struct astro_exact a239 = atan_inv_int(239u);
    struct astro_exact pi =
        astro_exact_sub(astro_exact_mul(astro_exact_from_i64(16), a5),
                        astro_exact_mul(astro_exact_from_i64(4), a239));
    if (!astro_exact_is_valid(&pi)) {
        g_failed = true;
        return false;
    }

    g_pi = pi;
    g_two_pi = astro_exact_add(pi, pi);
    g_half_pi = astro_exact_shr(pi, 1u);

    /* atan(2^0) == atan(1) == pi/4; the rest come from the shifted series. */
    g_atan_pow2[0] = astro_exact_shr(pi, 2u);
    for (unsigned i = 1; i < ASTRO_CORDIC_ITERS; i++) {
        g_atan_pow2[i] = atan_inv_pow2(i);
        if (!astro_exact_is_valid(&g_atan_pow2[i])) {
            g_failed = true;
            return false;
        }
    }

    g_inv_gain = cordic_inverse_gain();
    if (!astro_exact_is_valid(&g_inv_gain) ||
        !astro_exact_is_valid(&g_two_pi) ||
        !astro_exact_is_valid(&g_half_pi)) {
        g_failed = true;
        return false;
    }

    g_ready = true;
    return true;
}

const struct astro_exact *astro_trig_pi(void)
{
    return astro_trig_tables_ready() ? &g_pi : NULL;
}

const struct astro_exact *astro_trig_two_pi(void)
{
    return astro_trig_tables_ready() ? &g_two_pi : NULL;
}

const struct astro_exact *astro_trig_half_pi(void)
{
    return astro_trig_tables_ready() ? &g_half_pi : NULL;
}

bool astro_prepare(void) { return astro_trig_tables_ready(); }

struct astro_exact astro_exact_pi(void)
{
    return astro_trig_tables_ready() ? g_pi : astro_exact_invalid();
}

struct astro_exact astro_exact_two_pi(void)
{
    return astro_trig_tables_ready() ? g_two_pi : astro_exact_invalid();
}

struct astro_exact astro_exact_degrees_to_radians(struct astro_exact degrees)
{
    if (!astro_trig_tables_ready())
        return astro_exact_invalid();
    return astro_exact_div(astro_exact_mul(degrees, g_pi),
                           astro_exact_from_i64(180));
}

struct astro_exact astro_exact_radians_to_degrees(struct astro_exact radians)
{
    if (!astro_trig_tables_ready())
        return astro_exact_invalid();
    return astro_exact_div(astro_exact_mul(radians, astro_exact_from_i64(180)),
                           g_pi);
}

/* ── the rotation ─────────────────────────────────────────────────────── */

/* Rotation mode on an angle already reduced to [0, pi/2]: drives z to zero
 * and leaves (x, y) = (cos a, sin a). The domain bound matters — CORDIC
 * converges only for |z| <= sum atan(2^-i) ~= 1.7433, and pi/2 ~= 1.5708 is
 * inside it, which is exactly why the caller reduces to one quadrant. */
static void cordic_rotate(struct astro_exact a, struct astro_exact *cos_out,
                          struct astro_exact *sin_out)
{
    struct astro_exact x = g_inv_gain;
    struct astro_exact y = astro_exact_zero();
    struct astro_exact z = a;

    for (unsigned i = 0; i < ASTRO_CORDIC_ITERS; i++) {
        struct astro_exact dx = astro_exact_shr(x, i);
        struct astro_exact dy = astro_exact_shr(y, i);
        bool forward = !astro_exact_is_negative(&z);

        struct astro_exact nx =
            forward ? astro_exact_sub(x, dy) : astro_exact_add(x, dy);
        struct astro_exact ny =
            forward ? astro_exact_add(y, dx) : astro_exact_sub(y, dx);
        struct astro_exact nz = forward
                                    ? astro_exact_sub(z, g_atan_pow2[i])
                                    : astro_exact_add(z, g_atan_pow2[i]);
        x = nx;
        y = ny;
        z = nz;
    }
    *cos_out = x;
    *sin_out = y;
}

/* Reduce to [0, 2*pi), then to a first-quadrant angle plus a quadrant index.
 * Returns false when the tables are unavailable or the input is invalid. */
static bool reduce_quadrant(struct astro_exact angle, struct astro_exact *out,
                            unsigned *quadrant)
{
    if (!astro_trig_tables_ready() || !astro_exact_is_valid(&angle))
        return false;

    struct astro_exact r = astro_exact_mod(angle, g_two_pi);
    if (!astro_exact_is_valid(&r))
        return false;

    if (astro_exact_cmp(&r, &g_half_pi) < 0) {
        *quadrant = 0;
        *out = r;
        return true;
    }
    if (astro_exact_cmp(&r, &g_pi) < 0) {
        *quadrant = 1;
        *out = astro_exact_sub(g_pi, r);
        return astro_exact_is_valid(out);
    }
    struct astro_exact three_half = astro_exact_add(g_pi, g_half_pi);
    if (astro_exact_cmp(&r, &three_half) < 0) {
        *quadrant = 2;
        *out = astro_exact_sub(r, g_pi);
        return astro_exact_is_valid(out);
    }
    *quadrant = 3;
    *out = astro_exact_sub(g_two_pi, r);
    return astro_exact_is_valid(out);
}

/* One place decides both signs, per quadrant, written out. In the source this
 * is adapted from, the second and fourth quadrants read cosine out of the
 * sine register; an exhaustive four-arm switch makes that kind of slip a
 * visible edit rather than an invisible one. */
static void apply_quadrant(unsigned quadrant, struct astro_exact c,
                           struct astro_exact s, struct astro_exact *cos_out,
                           struct astro_exact *sin_out)
{
    switch (quadrant) {
    case 0: /* [0, pi/2)      cos +  sin + */
        *cos_out = c;
        *sin_out = s;
        return;
    case 1: /* [pi/2, pi)     cos -  sin + */
        *cos_out = astro_exact_neg(c);
        *sin_out = s;
        return;
    case 2: /* [pi, 3pi/2)    cos -  sin - */
        *cos_out = astro_exact_neg(c);
        *sin_out = astro_exact_neg(s);
        return;
    default: /* [3pi/2, 2pi)  cos +  sin - */
        *cos_out = c;
        *sin_out = astro_exact_neg(s);
        return;
    }
}

static bool sin_cos(struct astro_exact angle, struct astro_exact *cos_out,
                    struct astro_exact *sin_out)
{
    struct astro_exact reduced;
    unsigned quadrant = 0;
    if (!reduce_quadrant(angle, &reduced, &quadrant))
        return false;

    struct astro_exact c, s;
    cordic_rotate(reduced, &c, &s);
    if (!astro_exact_is_valid(&c) || !astro_exact_is_valid(&s))
        return false;

    apply_quadrant(quadrant, c, s, cos_out, sin_out);
    return astro_exact_is_valid(cos_out) && astro_exact_is_valid(sin_out);
}

struct astro_exact astro_exact_sin(struct astro_exact radians)
{
    struct astro_exact c, s;
    if (!sin_cos(radians, &c, &s))
        return astro_exact_invalid();
    return s;
}

struct astro_exact astro_exact_cos(struct astro_exact radians)
{
    struct astro_exact c, s;
    if (!sin_cos(radians, &c, &s))
        return astro_exact_invalid();
    return c;
}

/* Vectoring mode: drives y to zero and accumulates atan(y0/x0) into z, for
 * x0 > 0 and y0 >= 0, giving a result in [0, pi/2). */
static struct astro_exact cordic_vector(struct astro_exact x,
                                        struct astro_exact y)
{
    struct astro_exact z = astro_exact_zero();

    for (unsigned i = 0; i < ASTRO_CORDIC_ITERS; i++) {
        struct astro_exact dx = astro_exact_shr(x, i);
        struct astro_exact dy = astro_exact_shr(y, i);
        bool y_negative = astro_exact_is_negative(&y);

        struct astro_exact nx =
            y_negative ? astro_exact_sub(x, dy) : astro_exact_add(x, dy);
        struct astro_exact ny =
            y_negative ? astro_exact_add(y, dx) : astro_exact_sub(y, dx);
        struct astro_exact nz = y_negative
                                    ? astro_exact_sub(z, g_atan_pow2[i])
                                    : astro_exact_add(z, g_atan_pow2[i]);
        x = nx;
        y = ny;
        z = nz;
    }
    return z;
}

struct astro_exact astro_exact_atan2(struct astro_exact y, struct astro_exact x)
{
    if (!astro_trig_tables_ready() || !astro_exact_is_valid(&y) ||
        !astro_exact_is_valid(&x))
        return astro_exact_invalid();

    bool y_zero = astro_exact_is_zero(&y);
    bool x_zero = astro_exact_is_zero(&x);

    /* The origin has no angle. Returning zero here would invent a direction
     * for a point that has none, and a caller checking the chart would have
     * no way to tell that apart from a genuine due-east vector. */
    if (y_zero && x_zero)
        return astro_exact_invalid();

    if (x_zero)
        return astro_exact_is_negative(&y) ? astro_exact_neg(g_half_pi)
                                           : g_half_pi;
    /* On the axis the answer is a table entry, not a rotation. Letting the
     * vectoring loop find zero would leave its ~2^-60 residual in a value
     * that is exactly 0 or exactly pi. */
    if (y_zero)
        return astro_exact_is_negative(&x) ? g_pi : astro_exact_zero();

    bool y_neg = astro_exact_is_negative(&y);
    bool x_neg = astro_exact_is_negative(&x);

    struct astro_exact base =
        cordic_vector(astro_exact_abs(x), astro_exact_abs(y));
    if (!astro_exact_is_valid(&base))
        return astro_exact_invalid();

    if (!x_neg)
        return y_neg ? astro_exact_neg(base) : base;
    return y_neg ? astro_exact_sub(base, g_pi) : astro_exact_sub(g_pi, base);
}
