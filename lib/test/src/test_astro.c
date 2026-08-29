/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * lib/astro — the exact fixed-grid arithmetic and the birth chart built on it.
 *
 * ── What this group asserts, and what it deliberately does not ───────────
 * There are almost no golden numbers here. Copying the module's own output
 * into an expectation proves that nobody edited the file, not that the file
 * is right, and it would pass just as happily if every chart were wrong in
 * the same way on every machine. What this group asserts instead are the
 * PROPERTIES the module's contract is written in:
 *
 *  1. DETERMINISM BY CONSTRUCTION, not by assertion. The module's claim is
 *     that a second node recomputing a chart gets identical bits. The two
 *     cases that prove it each build a computation where a `double` control
 *     DEMONSTRABLY DISAGREES WITH ITSELF, and show the exact path does not:
 *       - reassociation: the same VSOP87-shaped sum added forwards and
 *         backwards. In `double` the two orders differ; on the exact grid
 *         they are bit-identical. This is not hypothetical — it is what a
 *         vectorising compiler does to a summation loop, so two honest nodes
 *         built with different flags would disagree.
 *       - absorption: a term far below the ULP of a large running total. In
 *         `double` the term vanishes and adding it a thousand times changes
 *         nothing; on the exact grid every one of them counts.
 *     The tests fail if the double control ACCIDENTALLY AGREES, because a
 *     control that cannot fail proves nothing about the thing it controls.
 *  2. The same input produces byte-identical output twice, over the whole
 *     public chart struct, by memcmp — the check a verifier would make.
 *  3. Hostile and out-of-range input is REFUSED, not absorbed into a
 *     plausible-looking answer: bad calendar dates, the poles, longitudes
 *     off the globe, division by zero, the square root of a negative, the
 *     origin handed to atan2, and arithmetic overflow.
 *  4. The exact/approximate boundary is where astro/astro_exact.h says it is:
 *     the exact readouts are reproducible and astro_exact_to_double() is
 *     LOSSY — asserted by exhibiting two distinct exact values that collapse
 *     to the same double, which is why nothing may be verified through it.
 *  5. The transcendentals are correct, checked against independently known
 *     decimal expansions of pi, sin 1, cos 1, sqrt 2 and atan2(1,1) rather
 *     than against this module's own output.
 *  6. The astronomy lands where an ephemeris says it does, checked coarsely
 *     (sign plus a degree tolerance) so the assertion tracks the accuracy the
 *     header actually claims instead of freezing today's last digit.
 *
 * House idiom note: exactly one TEST block per function. ASSERT jumps to
 * `_test_next`, so a function holding two TEST blocks would jump BACKWARD
 * into an already-run block.
 */

#include "test/test_core.h"

#include "astro/astro_chart.h"
#include "astro/astro_exact.h"
#include "astro/astro_time.h"

#include <stdio.h>
#include <string.h>

/* ── local harness ────────────────────────────────────────────────────── */

static int g_failures;

#define CHECK(cond, ...)                                                     \
    do {                                                                     \
        if (!(cond)) {                                                       \
            printf("  FAIL %s:%d: ", __func__, __LINE__);                    \
            printf(__VA_ARGS__);                                             \
            printf("\n");                                                    \
            g_failures++;                                                    \
        }                                                                    \
    } while (0)

static bool text_is(const struct astro_exact *v, unsigned digits,
                    const char *expect)
{
    char buf[96];
    if (!astro_exact_format(v, digits, buf, sizeof(buf)))
        return false;
    return strcmp(buf, expect) == 0;
}

static void show(const char *label, const struct astro_exact *v)
{
    char buf[96];
    if (!astro_exact_format(v, 18, buf, sizeof(buf)))
        printf("  %s = <unrepresentable>\n", label);
    else
        printf("  %s = %s\n", label, buf);
}

/* ── 1. arithmetic basics and the fail-closed contract ────────────────── */

static void t_basics(void)
{
    struct astro_exact zero = astro_exact_zero();
    struct astro_exact one = astro_exact_from_i64(1);
    struct astro_exact bad = astro_exact_invalid();

    CHECK(astro_exact_is_valid(&zero), "zero must be valid");
    CHECK(astro_exact_is_zero(&zero), "zero must be zero");
    CHECK(!astro_exact_is_valid(&bad), "invalid must not be valid");

    /* A zeroed struct is INVALID, not the number zero. A caller who forgot to
     * initialise must not get a number that looks reasonable. */
    struct astro_exact wiped;
    memset(&wiped, 0, sizeof(wiped));
    CHECK(!astro_exact_is_valid(&wiped), "a zeroed struct must read invalid");

    /* Zero has ONE encoding: negative zero cannot be constructed. */
    struct astro_exact neg_zero = astro_exact_neg(zero);
    CHECK(astro_exact_identical(&neg_zero, &zero), "-0 must equal 0");
    CHECK(!astro_exact_is_negative(&neg_zero), "-0 must not be negative");

    CHECK(text_is(&one, 6, "1.000000"), "1 must format as 1.000000");

    struct astro_exact third = astro_exact_ratio(1, 3);
    CHECK(text_is(&third, 12, "0.333333333333"), "1/3 truncates on the grid");

    struct astro_exact neg = astro_exact_ratio(-7, 2);
    CHECK(text_is(&neg, 3, "-3.500"), "-7/2 must format as -3.500");

    /* Truncation is toward ZERO, so f(-x) == -f(x). A two's-complement shift
     * would round toward negative infinity and break that symmetry. */
    struct astro_exact p = astro_exact_ratio(7, 2);
    struct astro_exact sp = astro_exact_shr(p, 2u);
    struct astro_exact sn = astro_exact_shr(astro_exact_neg(p), 2u);
    CHECK(!astro_exact_is_zero(&sn), "shift of a nonzero value stays a number");
    struct astro_exact expect = astro_exact_neg(sp);
    CHECK(astro_exact_identical(&sn, &expect), "shift must be sign-symmetric");

    int64_t f = 0;
    CHECK(astro_exact_floor_i64(&neg, &f) && f == -4,
          "floor(-3.5) must be -4, not -3");
    CHECK(astro_exact_floor_i64(&p, &f) && f == 3, "floor(3.5) must be 3");

    struct astro_exact m =
        astro_exact_mod(astro_exact_from_i64(-30), astro_exact_from_i64(360));
    CHECK(text_is(&m, 3, "330.000"), "mod must return the [0,m) representative");
}

/* ── 2. fail-closed: refusals, not garbage ────────────────────────────── */

static void t_fail_closed(void)
{
    struct astro_exact one = astro_exact_from_i64(1);
    struct astro_exact zero = astro_exact_zero();
    struct astro_exact bad = astro_exact_invalid();

    struct astro_exact r = astro_exact_div(one, zero);
    CHECK(!astro_exact_is_valid(&r), "division by zero must be invalid");

    r = astro_exact_sqrt(astro_exact_from_i64(-4));
    CHECK(!astro_exact_is_valid(&r), "sqrt of a negative must be invalid");

    r = astro_exact_ratio(1, 0);
    CHECK(!astro_exact_is_valid(&r), "a zero denominator must be invalid");

    r = astro_exact_atan2(zero, zero);
    CHECK(!astro_exact_is_valid(&r), "atan2 at the origin must be invalid");

    r = astro_exact_mod(one, zero);
    CHECK(!astro_exact_is_valid(&r), "mod by zero must be invalid");
    r = astro_exact_mod(one, astro_exact_from_i64(-5));
    CHECK(!astro_exact_is_valid(&r), "mod by a negative must be invalid");

    /* Invalidity PROPAGATES. This is the property that lets a long chart
     * computation check its result once at the end instead of after every
     * step, so it is asserted through every operation, not just one. */
    struct astro_exact poisoned_add = astro_exact_add(bad, one);
    CHECK(!astro_exact_is_valid(&poisoned_add), "add must propagate invalid");
    struct astro_exact chain = astro_exact_mul(astro_exact_add(bad, one), one);
    chain = astro_exact_sub(chain, one);
    chain = astro_exact_div(chain, one);
    chain = astro_exact_sqrt(chain);
    chain = astro_exact_sin(chain);
    CHECK(!astro_exact_is_valid(&chain),
          "invalid must survive a whole chain of operations");

    /* Overflow REFUSES rather than wrapping. Squaring repeatedly walks off
     * the top of the limb array; the answer must become invalid and must
     * never come back as a small plausible number. */
    struct astro_exact big = astro_exact_from_i64(1000000000);
    bool went_invalid = false;
    for (int i = 0; i < 8; i++) {
        big = astro_exact_mul(big, big);
        if (!astro_exact_is_valid(&big)) {
            went_invalid = true;
            break;
        }
    }
    CHECK(went_invalid, "repeated squaring must overflow to invalid, not wrap");
    CHECK(!astro_exact_is_valid(&big), "an overflowed value stays invalid");

    /* A formatter must not print an invalid value as if it were a number. */
    char buf[64];
    CHECK(!astro_exact_format(&bad, 6, buf, sizeof(buf)),
          "formatting an invalid value must fail");
    CHECK(buf[0] == '\0', "a failed format must leave an empty string");
    int64_t out = 12345;
    CHECK(!astro_exact_floor_i64(&bad, &out),
          "floor of an invalid value must fail");
    CHECK(out == 12345, "a failed floor must not touch the out-parameter");
    CHECK(!astro_exact_format(&one, 19u, buf, sizeof(buf)),
          "more than 18 fractional digits must be refused");
    CHECK(!astro_exact_format(&one, 6u, buf, 3u),
          "a buffer too short for the result must be refused");
}

/* ── 3. transcendentals against independently known expansions ────────── */

static void t_transcendentals(void)
{
    CHECK(astro_prepare(), "table setup must succeed");

    struct astro_exact pi = astro_exact_pi();
    CHECK(text_is(&pi, 15, "3.141592653589793"), "pi to 15 places");

    struct astro_exact two_pi = astro_exact_two_pi();
    struct astro_exact doubled = astro_exact_add(pi, pi);
    CHECK(astro_exact_identical(&two_pi, &doubled), "2pi must be pi + pi");

    struct astro_exact one = astro_exact_from_i64(1);
    struct astro_exact s = astro_exact_sin(one);
    struct astro_exact c = astro_exact_cos(one);
    CHECK(text_is(&s, 15, "0.841470984807896"), "sin(1) to 15 places");
    CHECK(text_is(&c, 15, "0.540302305868139"), "cos(1) to 15 places");

    struct astro_exact root2 = astro_exact_sqrt(astro_exact_from_i64(2));
    CHECK(text_is(&root2, 15, "1.414213562373095"), "sqrt(2) to 15 places");

    struct astro_exact quarter = astro_exact_atan2(one, one);
    CHECK(text_is(&quarter, 15, "0.785398163397448"), "atan2(1,1) is pi/4");

    /* Quadrants come out of the signs, not out of a caller-side fix-up. The
     * source this was adapted from swapped sine and cosine in two of the
     * four, so each is asserted separately. */
    struct astro_exact half_pi = astro_exact_shr(pi, 1u);
    struct astro_exact s_q2 = astro_exact_sin(astro_exact_add(half_pi, one));
    struct astro_exact c_q2 = astro_exact_cos(astro_exact_add(half_pi, one));
    CHECK(!astro_exact_is_negative(&s_q2), "sin is positive in quadrant 2");
    CHECK(astro_exact_is_negative(&c_q2), "cos is negative in quadrant 2");

    struct astro_exact s_q3 = astro_exact_sin(astro_exact_add(pi, one));
    struct astro_exact c_q3 = astro_exact_cos(astro_exact_add(pi, one));
    CHECK(astro_exact_is_negative(&s_q3), "sin is negative in quadrant 3");
    CHECK(astro_exact_is_negative(&c_q3), "cos is negative in quadrant 3");

    struct astro_exact q4 = astro_exact_sub(astro_exact_two_pi(), one);
    struct astro_exact s_q4 = astro_exact_sin(q4);
    struct astro_exact c_q4 = astro_exact_cos(q4);
    CHECK(astro_exact_is_negative(&s_q4), "sin is negative in quadrant 4");
    CHECK(!astro_exact_is_negative(&c_q4), "cos is positive in quadrant 4");

    /* sin^2 + cos^2 == 1 to within the rotation's own residual. */
    struct astro_exact unit = astro_exact_add(astro_exact_mul(s, s),
                                              astro_exact_mul(c, c));
    CHECK(text_is(&unit, 15, "0.999999999999999") ||
              text_is(&unit, 15, "1.000000000000000"),
          "sin^2 + cos^2 must be 1 to 15 places");

    /* Negative and large arguments reduce correctly. */
    struct astro_exact far =
        astro_exact_add(one, astro_exact_mul(astro_exact_from_i64(1000),
                                             astro_exact_two_pi()));
    struct astro_exact s_far = astro_exact_sin(far);
    CHECK(text_is(&s_far, 12, "0.841470984807"),
          "sin must reduce an argument 1000 turns away");
    /* And reduce it EXACTLY: multiplying the grid's own 2pi by an integer is
     * lossless, so the reduction returns the argument bit for bit and the two
     * sines are identical rather than merely close. */
    CHECK(astro_exact_identical(&s_far, &s),
          "reduction by whole turns must be exact, not approximate");
}

/* ── 4. DETERMINISM BY CONSTRUCTION — reassociation ───────────────────── */

/* A VSOP87-shaped term set: one dominant amplitude and a tail of small ones,
 * the exact shape whose summation order matters. */
static const int64_t k_series[] = {175347046, 3341656, 34894, 3497, 3418,
                                   3136,      2676,    2343,  1324, 1273,
                                   119,       47,      11,    3,    1};
#define K_SERIES_N (sizeof(k_series) / sizeof(k_series[0]))

static void t_determinism_reassociation(void)
{
    /* THE CONTROL. Summed forwards and backwards in `double`, scaled so the
     * ratio between the largest and smallest term crosses the mantissa. If a
     * compiler reassociates this loop — which is exactly what vectorising it
     * does — two honest nodes get different answers. */
    double dfwd = 0.0;
    for (size_t i = 0; i < K_SERIES_N; i++)
        dfwd += (double)k_series[i] / 3.0;
    double drev = 0.0;
    for (size_t i = K_SERIES_N; i > 0; i--)
        drev += (double)k_series[i - 1] / 3.0;

    /* If the control agrees with itself the experiment proves nothing, so
     * that is a failure of the test, not a pass of the module. */
    CHECK(dfwd != drev,
          "double control must DISAGREE with itself across summation order "
          "(forward %.20g, reverse %.20g); without that this case proves "
          "nothing",
          dfwd, drev);
    printf("  double  forward = %.20g\n", dfwd);
    printf("  double  reverse = %.20g\n", drev);

    /* THE EXPERIMENT. The same sum on the exact grid. Addition here discards
     * no information, so it is associative and both orders MUST agree bit for
     * bit — not approximately, identically. */
    struct astro_exact xfwd = astro_exact_zero();
    for (size_t i = 0; i < K_SERIES_N; i++)
        xfwd = astro_exact_add(xfwd, astro_exact_ratio(k_series[i], 3));
    struct astro_exact xrev = astro_exact_zero();
    for (size_t i = K_SERIES_N; i > 0; i--)
        xrev = astro_exact_add(xrev, astro_exact_ratio(k_series[i - 1], 3));

    CHECK(astro_exact_is_valid(&xfwd) && astro_exact_is_valid(&xrev),
          "both exact sums must be valid");
    CHECK(astro_exact_identical(&xfwd, &xrev),
          "the exact sum must be IDENTICAL in both orders");
    CHECK(memcmp(&xfwd, &xrev, sizeof(xfwd)) == 0,
          "the exact sums must be byte-identical, not merely equal");
    show("exact forward", &xfwd);
    show("exact reverse", &xrev);
}

/* ── 5. DETERMINISM BY CONSTRUCTION — absorption ──────────────────────── */

static void t_determinism_absorption(void)
{
    /* THE CONTROL. A term below the ULP of the running total disappears in
     * `double`: adding it a thousand times changes nothing at all. Whether a
     * given term "counts" then depends on the order and on the width of the
     * register it happened to live in. */
    double base = 175347046.0;
    double tiny = 1e-12;
    double dsum = base;
    for (int i = 0; i < 1000; i++)
        dsum += tiny;
    CHECK(dsum == base,
          "double control must ABSORB the small terms entirely (%.20g vs "
          "%.20g); without that this case proves nothing",
          dsum, base);
    printf("  double  %.1f + 1000 * 1e-12 = %.20g\n", base, dsum);

    /* THE EXPERIMENT. On the exact grid every term counts, and the total is
     * exactly the one arithmetic says it is. */
    struct astro_exact xbase = astro_exact_from_i64(175347046);
    struct astro_exact xtiny = astro_exact_ratio(1, 1000000000000);
    struct astro_exact xsum = xbase;
    for (int i = 0; i < 1000; i++)
        xsum = astro_exact_add(xsum, xtiny);

    CHECK(astro_exact_is_valid(&xsum), "the exact sum must be valid");
    CHECK(!astro_exact_identical(&xsum, &xbase),
          "the exact sum must NOT absorb the small terms");
    struct astro_exact expected = astro_exact_add(
        xbase, astro_exact_mul(astro_exact_from_i64(1000), xtiny));
    CHECK(astro_exact_identical(&xsum, &expected),
          "1000 additions of a term must equal one multiplication by 1000");
    show("exact base + 1000 * 1e-12", &xsum);
    show("exact base + 1000 * tiny ", &expected);
}

/* ── 6. the exact/approximate boundary is where the header says ───────── */

static void t_boundary_is_where_the_header_says(void)
{
    /* Two DISTINCT exact values that collapse to the SAME double. This is the
     * whole argument for astro_exact_to_double() being cosmetic: a verifier
     * comparing through it cannot tell these apart, so nothing that must be
     * agreed on may travel that way. */
    struct astro_exact a = astro_exact_from_i64(175347046);
    struct astro_exact b = astro_exact_add(a, astro_exact_ratio(1, 1000000000));

    CHECK(!astro_exact_identical(&a, &b),
          "the two exact values must genuinely differ");
    CHECK(astro_exact_cmp(&a, &b) != 0, "and must compare unequal");
    double da = astro_exact_to_double(&a);
    double db = astro_exact_to_double(&b);
    CHECK(da == db,
          "two distinct exact values must collapse to one double (%.20g vs "
          "%.20g) — that is why the double is cosmetic",
          da, db);

    /* The exact readouts, by contrast, distinguish them. */
    char ba[64], bb[64];
    CHECK(astro_exact_format(&a, 12, ba, sizeof(ba)), "format a");
    CHECK(astro_exact_format(&b, 12, bb, sizeof(bb)), "format b");
    CHECK(strcmp(ba, bb) != 0,
          "the exact text form must distinguish what the double cannot "
          "(%s vs %s)",
          ba, bb);

    /* An invalid value converts to 0.0 rather than a NaN or a trap, so a
     * caller printing one gets a visibly wrong number and not a crash — but
     * it is indistinguishable from a real zero, which is one more reason the
     * conversion may not be used to decide anything. */
    struct astro_exact bad = astro_exact_invalid();
    CHECK(astro_exact_to_double(&bad) == 0.0,
          "an invalid value must convert to 0.0");
}

/* ── 7. the calendar refuses what is not a date ───────────────────────── */

static void t_calendar(void)
{
    struct astro_instant good = {2000, 1, 1, 12, 0, 0};
    struct astro_exact jd;
    CHECK(astro_instant_is_valid(&good), "J2000 noon must be a valid instant");
    CHECK(astro_instant_julian_day(&good, &jd), "J2000 must convert");
    CHECK(text_is(&jd, 6, "2451545.000000"),
          "2000-01-01T12:00 must be JD 2451545 exactly");

    /* Midnight is half a day earlier — the JD epoch is noon, and getting this
     * backwards shifts every chart by twelve hours. */
    struct astro_instant midnight = {2000, 1, 1, 0, 0, 0};
    CHECK(astro_instant_julian_day(&midnight, &jd) &&
              text_is(&jd, 6, "2451544.500000"),
          "midnight must be half a day before noon");

    static const struct astro_instant k_bad[] = {
        {2023, 2, 29, 0, 0, 0},  /* not a leap year */
        {1900, 2, 29, 0, 0, 0},  /* century, not divisible by 400 */
        {2000, 0, 1, 0, 0, 0},   /* month 0 */
        {2000, 13, 1, 0, 0, 0},  /* month 13 */
        {2000, 4, 31, 0, 0, 0},  /* April has 30 days */
        {2000, 1, 0, 0, 0, 0},   /* day 0 */
        {2000, 1, 1, 24, 0, 0},  /* no hour 24 */
        {2000, 1, 1, 0, 60, 0},  /* no minute 60 */
        {2000, 1, 1, 0, 0, 60},  /* no leap second in this scale */
        {ASTRO_YEAR_MIN - 1, 1, 1, 0, 0, 0},
        {ASTRO_YEAR_MAX + 1, 1, 1, 0, 0, 0},
    };
    for (size_t i = 0; i < sizeof(k_bad) / sizeof(k_bad[0]); i++) {
        CHECK(!astro_instant_is_valid(&k_bad[i]),
              "instant %zu must be refused", i);
        struct astro_exact unused;
        CHECK(!astro_instant_julian_day(&k_bad[i], &unused),
              "instant %zu must not convert", i);
    }

    /* 2000 IS a leap year (divisible by 400) — the case the century rule
     * above would wrongly exclude. */
    struct astro_instant leap = {2000, 2, 29, 0, 0, 0};
    CHECK(astro_instant_is_valid(&leap), "2000-02-29 must be a real date");
    struct astro_instant leap2024 = {2024, 2, 29, 0, 0, 0};
    CHECK(astro_instant_is_valid(&leap2024), "2024-02-29 must be a real date");

    CHECK(!astro_instant_is_valid(NULL), "NULL must be refused");
    CHECK(!astro_instant_julian_day(&good, NULL),
          "a NULL out-parameter must be refused");
}

/* ── 8. the sign split is one decision, not two ───────────────────────── */

static void t_sign_split(void)
{
    struct astro_position p;

    CHECK(astro_position_from_longitude(astro_exact_zero(), &p) &&
              p.sign == ASTRO_SIGN_ARIES && p.degree_in_sign == 0 &&
              p.arcminute == 0 && p.arcsecond == 0,
          "0 degrees is 0 Aries");

    CHECK(astro_position_from_longitude(astro_exact_from_i64(30), &p) &&
              p.sign == ASTRO_SIGN_TAURUS && p.degree_in_sign == 0,
          "30 degrees is 0 Taurus");

    /* A hair under a cusp must be the LAST arcsecond of the previous sign,
     * never 0 degrees of the next one. Deriving the sign from lon/30 and the
     * arcseconds from a separately floored lon*3600 is exactly how those two
     * come apart. */
    struct astro_exact just_under =
        astro_exact_sub(astro_exact_from_i64(30), astro_exact_ratio(1, 1000000));
    CHECK(astro_position_from_longitude(just_under, &p) &&
              p.sign == ASTRO_SIGN_ARIES && p.degree_in_sign == 29 &&
              p.arcminute == 59 && p.arcsecond == 59,
          "just under 30 degrees is 29d59'59\" Aries, got %s %dd%02d'%02d\"",
          astro_sign_name(p.sign), p.degree_in_sign, p.arcminute, p.arcsecond);

    struct astro_exact last =
        astro_exact_sub(astro_exact_from_i64(360), astro_exact_ratio(1, 1000000));
    CHECK(astro_position_from_longitude(last, &p) && p.sign == ASTRO_SIGN_PISCES,
          "just under 360 degrees is Pisces");

    /* Out of range refuses rather than wrapping: a caller who forgot to
     * normalise gets an error, not a silently rotated chart. */
    CHECK(!astro_position_from_longitude(astro_exact_from_i64(360), &p),
          "360 degrees exactly must be refused");
    CHECK(!astro_position_from_longitude(astro_exact_from_i64(-1), &p),
          "a negative longitude must be refused");
    CHECK(!astro_position_from_longitude(astro_exact_invalid(), &p),
          "an invalid longitude must be refused");
    CHECK(!astro_position_from_longitude(astro_exact_zero(), NULL),
          "a NULL out-parameter must be refused");

    CHECK(strcmp(astro_sign_name(ASTRO_SIGN_COUNT), "unknown") == 0,
          "an out-of-range sign names itself unknown");
    CHECK(strcmp(astro_body_name(ASTRO_BODY_COUNT), "unknown") == 0,
          "an out-of-range body names itself unknown");
}

/* ── 9. the chart: reproducible, and refusing what it cannot answer ───── */

static void t_chart_is_reproducible(void)
{
    struct astro_instant when = {1969, 7, 20, 20, 17, 40};
    struct astro_place greenwich = {51477000, -4000};

    struct astro_chart a, b;
    CHECK(astro_chart_compute(&when, &greenwich, &a), "chart must compute");
    CHECK(astro_chart_compute(&when, &greenwich, &b),
          "chart must compute a second time");

    /* THE VERIFIER'S CHECK. Not "the numbers are close" — the whole public
     * struct, byte for byte. Anything less would pass while two nodes
     * disagreed in the low bits of every longitude. */
    CHECK(memcmp(&a, &b, sizeof(a)) == 0,
          "two computations of one chart must be byte-identical");

    /* A different instant must give a different chart, or the byte-identity
     * above would be satisfied by a function that ignores its input. */
    struct astro_instant later = {1969, 7, 21, 20, 17, 40};
    struct astro_chart c;
    CHECK(astro_chart_compute(&later, &greenwich, &c), "later chart computes");
    CHECK(memcmp(&a, &c, sizeof(a)) != 0,
          "a different instant must give a different chart");

    /* A different place moves the ascendant but not the planets: the bodies
     * are geocentric and the ascendant is local. */
    struct astro_place sydney = {-33868000, 151209000};
    struct astro_chart d;
    CHECK(astro_chart_compute(&when, &sydney, &d), "southern chart computes");
    CHECK(memcmp(&a.body, &d.body, sizeof(a.body)) == 0,
          "the bodies must not depend on the observer's place");
    CHECK(memcmp(&a.ascendant, &d.ascendant, sizeof(a.ascendant)) != 0,
          "the ascendant must depend on the observer's place");

    /* Houses are equal houses from the ascendant, as the header states. */
    CHECK(astro_exact_identical(&a.house[0].longitude_deg,
                                &a.ascendant.longitude_deg),
          "house 1 must be the ascendant");
    struct astro_exact seventh = astro_exact_mod(
        astro_exact_add(a.ascendant.longitude_deg, astro_exact_from_i64(180)),
        astro_exact_from_i64(360));
    CHECK(astro_exact_identical(&a.house[6].longitude_deg, &seventh),
          "house 7 must be exactly opposite the ascendant");
}

static void t_chart_refusals(void)
{
    struct astro_instant when = {1969, 7, 20, 20, 17, 40};
    struct astro_place ok = {51477000, -4000};
    struct astro_chart chart;

    CHECK(!astro_chart_compute(NULL, &ok, &chart), "NULL instant refused");
    CHECK(!astro_chart_compute(&when, NULL, &chart), "NULL place refused");
    CHECK(!astro_chart_compute(&when, &ok, NULL), "NULL output refused");

    struct astro_instant bad_date = {2023, 2, 29, 0, 0, 0};
    CHECK(!astro_chart_compute(&bad_date, &ok, &chart),
          "an impossible date must be refused");

    /* The poles have no ascendant. Refusing is the honest answer; a plausible
     * number there would be a chart that looks ordinary and means nothing. */
    static const struct astro_place k_bad_places[] = {
        {ASTRO_LATITUDE_MICRODEG_LIMIT + 1, 0},
        {-ASTRO_LATITUDE_MICRODEG_LIMIT - 1, 0},
        {90000000, 0},
        {-90000000, 0},
        {0, ASTRO_LONGITUDE_MICRODEG_LIMIT + 1},
        {0, -ASTRO_LONGITUDE_MICRODEG_LIMIT - 1},
    };
    for (size_t i = 0; i < sizeof(k_bad_places) / sizeof(k_bad_places[0]); i++) {
        CHECK(!astro_chart_compute(&when, &k_bad_places[i], &chart),
              "place %zu must be refused", i);
    }

    /* The boundary itself is accepted — the refusal is a limit, not an
     * off-by-one that quietly narrows the usable globe. */
    struct astro_place edge = {ASTRO_LATITUDE_MICRODEG_LIMIT,
                               ASTRO_LONGITUDE_MICRODEG_LIMIT};
    CHECK(astro_chart_compute(&when, &edge, &chart),
          "the stated limit must itself be accepted");
}

/* ── 10. the astronomy lands where an ephemeris says it does ──────────── */

/* Geocentric ecliptic longitudes for 2000-01-01 12:00 UT, to WHOLE DEGREES,
 * as published ephemerides give them. Coarse on purpose: the tolerance beside
 * each row is the per-body accuracy astro/astro_chart.h claims, so this case
 * fails if the astronomy drifts AND it fails if the header's accuracy claim
 * stops being true — which a golden copy of today's six-decimal output would
 * do neither of.
 *
 * These also catch the specific defect corrected on the way in: reporting
 * HELIOCENTRIC longitudes as chart positions, which the source did. At this
 * epoch the heliocentric and geocentric longitudes of the inner planets
 * differ by tens of degrees, so an accidental return to that behaviour lands
 * outside every tolerance here rather than looking merely imprecise. */
struct ephemeris_ref {
    enum astro_body body;
    int longitude_deg;
    int tolerance_deg;
};

static void t_chart_matches_an_ephemeris(void)
{
    static const struct ephemeris_ref k_ref[] = {
        {ASTRO_BODY_SUN, 280, 1},
        {ASTRO_BODY_MOON, 222, 3},
        {ASTRO_BODY_MERCURY, 271, 2},
        {ASTRO_BODY_VENUS, 241, 2},
        {ASTRO_BODY_MARS, 327, 2},
        {ASTRO_BODY_JUPITER, 25, 2},
        {ASTRO_BODY_SATURN, 40, 2},
        {ASTRO_BODY_URANUS, 314, 2},
        {ASTRO_BODY_NEPTUNE, 303, 2},
    };

    struct astro_instant j2000 = {2000, 1, 1, 12, 0, 0};
    struct astro_place greenwich = {51477000, -4000};
    struct astro_chart chart;
    CHECK(astro_chart_compute(&j2000, &greenwich, &chart),
          "the J2000 chart must compute");

    for (size_t i = 0; i < sizeof(k_ref) / sizeof(k_ref[0]); i++) {
        const struct astro_position *p = &chart.body[k_ref[i].body];
        int64_t deg = 0;
        if (!astro_exact_floor_i64(&p->longitude_deg, &deg)) {
            CHECK(false, "%s longitude must be readable",
                  astro_body_name(k_ref[i].body));
            continue;
        }
        int64_t diff = deg - k_ref[i].longitude_deg;
        if (diff > 180) diff -= 360;
        if (diff < -180) diff += 360;
        int64_t mag = diff < 0 ? -diff : diff;
        CHECK(mag <= k_ref[i].tolerance_deg,
              "%s at %lld deg, ephemeris says %d (+/- %d)",
              astro_body_name(k_ref[i].body), (long long)deg,
              k_ref[i].longitude_deg, k_ref[i].tolerance_deg);
        printf("  %-8s %3lld deg  %-12s %2dd %02d' %02d\"\n",
               astro_body_name(k_ref[i].body), (long long)deg,
               astro_sign_name(p->sign), p->degree_in_sign, p->arcminute,
               p->arcsecond);
    }

    /* Every body must be somewhere real: a valid longitude, a real sign, and
     * a sexagesimal split inside its own range. */
    for (int b = 0; b < ASTRO_BODY_COUNT; b++) {
        const struct astro_position *p = &chart.body[b];
        CHECK(astro_exact_is_valid(&p->longitude_deg),
              "%s longitude must be valid", astro_body_name((enum astro_body)b));
        CHECK((int)p->sign >= 0 && (int)p->sign < (int)ASTRO_SIGN_COUNT,
              "%s sign in range", astro_body_name((enum astro_body)b));
        CHECK(p->degree_in_sign >= 0 && p->degree_in_sign < 30,
              "%s degree in range", astro_body_name((enum astro_body)b));
        CHECK(p->arcminute >= 0 && p->arcminute < 60, "%s arcminute in range",
              astro_body_name((enum astro_body)b));
        CHECK(p->arcsecond >= 0 && p->arcsecond < 60, "%s arcsecond in range",
              astro_body_name((enum astro_body)b));
    }
}

/* ── entry point ──────────────────────────────────────────────────────── */

int test_astro(void)
{
    g_failures = 0;

    t_basics();
    t_fail_closed();
    t_transcendentals();
    t_determinism_reassociation();
    t_determinism_absorption();
    t_boundary_is_where_the_header_says();
    t_calendar();
    t_sign_split();
    t_chart_is_reproducible();
    t_chart_refusals();
    t_chart_matches_an_ephemeris();

    printf("astro: %s (%d failures)\n", g_failures == 0 ? "OK" : "FAIL",
           g_failures);
    return g_failures;
}
