/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * astro_ephemeris — where the bodies are, in exact arithmetic.
 *
 * Three models live here, and they are genuinely different in quality. Each
 * one's accuracy and provenance is stated at its own table rather than
 * averaged into a single claim for the file, because a caller deciding
 * whether to trust a Moon sign should not have to infer it from a Sun number.
 * The summary and the coplanar-orbit caveat are in astro/astro_chart.h.
 *
 * EVERY COEFFICIENT IS AN INTEGER RATIO. The source these came from wrote
 * them as decimal literals; here each is a numerator over an explicit power
 * of ten, so the value is fixed by the source text and not by a compiler's
 * decimal-to-binary conversion. That is not pedantry: a decimal literal is
 * the last place a platform difference could still enter a computation that
 * is otherwise integer arithmetic end to end.
 */

#include "astro_priv.h"

#include "astro/astro_time.h"

/* EXACT PATH — see astro_priv.h. */
#pragma GCC poison double float

/* Fixed iteration count for Kepler's equation. A convergence test would make
 * the result depend on a tolerance and on how fast an intermediate happened
 * to settle; a fixed count makes it a pure function of the input. Newton's
 * method doubles its correct digits per step, so twelve steps is far past
 * saturation on this grid for every eccentricity here (Mercury's 0.206 is the
 * largest). */
#define ASTRO_KEPLER_STEPS 12u

struct astro_vsop_term {
    int64_t amp;   /* amplitude, in units of 1e-8 (radians or AU) */
    int64_t b_e7;  /* phase, in units of 1e-7 radians */
    int64_t c_e7;  /* frequency, in units of 1e-7 radians per millennium */
};

/* VSOP87 (Bretagnon and Francou, Bureau des Longitudes, 1987), truncated to
 * the largest terms of the Earth's heliocentric longitude and radius. Reached
 * this module through astro-calc's src/core/astro_minimal.c, which selected
 * these terms for roughly one-arcminute solar accuracy. */
static const struct astro_vsop_term k_earth_l0[] = {
    {175347046, 0, 0},
    {3341656, 46692568, 62830758500},
    {34894, 46261000, 125661517000},
    {3497, 27441000, 57533849000},
    {3418, 28289000, 35231000},
    {3136, 36277000, 777137715000},
    {2676, 44181000, 78604194000},
    {2343, 61352000, 39302097000},
    {1324, 7425000, 115067698000},
    {1273, 20371000, 5296910000},
};

static const struct astro_vsop_term k_earth_l1[] = {
    {628331966747, 0, 0},
    {206059, 26782350, 62830758500},
    {4303, 26351000, 125661517000},
    {425, 15900000, 35230000},
    {119, 57960000, 262980000},
};

static const struct astro_vsop_term k_earth_r0[] = {
    {100013989, 0, 0},
    {1670700, 30984635, 62830758500},
    {13956, 30552500, 125661517000},
    {3084, 51985000, 777137715000},
    {1628, 11739000, 57533849000},
};

/* Classical mean elements with linear rates per Julian century, from the same
 * source file. Units: 1e-8 AU for the axes, 1e-8 (dimensionless) for the
 * eccentricities, 1e-8 degrees for the two longitudes. There is no
 * inclination or ascending node in this set, which is why the model is
 * coplanar — see astro_chart.h. */
struct astro_elements {
    int64_t a0_e8, a1_e8; /* semi-major axis, AU */
    int64_t e0_e8, e1_e8; /* eccentricity */
    int64_t l0_e8, l1_e8; /* mean longitude, degrees */
    int64_t w0_e8, w1_e8; /* longitude of perihelion, degrees */
};

static const struct astro_elements k_elements[] = {
    /* Mercury */
    {38709927, 37, 20563593, 1906, 25225032350, 14947267411175, 7745779628,
     16047689},
    /* Venus */
    {72333566, 390, 677672, -4107, 18197909950, 5851781538729, 13160246718,
     268329},
    /* Mars */
    {152371034, 1847, 9339410, 7882, -455343205, 1914030268499, -2394362959,
     44441088},
    /* Jupiter */
    {520288700, -11607, 4838624, -13253, 3439644051, 303474612775, 1472847983,
     21252668},
    /* Saturn */
    {953667594, -125060, 5386179, -50991, 4995424423, 122249362201,
     9259887831, -41897216},
    /* Uranus */
    {1918916464, -196176, 4725744, -4397, 31323810451, 42848202785,
     17095427630, 40805281},
    /* Neptune */
    {3006992276, 26291, 859048, 5105, -5512002969, 21845945325, 4496476227,
     -32241464},
};

/* Index of a body in k_elements[], or -1. */
static int elements_index(enum astro_body body)
{
    switch (body) {
    case ASTRO_BODY_MERCURY: return 0;
    case ASTRO_BODY_VENUS: return 1;
    case ASTRO_BODY_MARS: return 2;
    case ASTRO_BODY_JUPITER: return 3;
    case ASTRO_BODY_SATURN: return 4;
    case ASTRO_BODY_URANUS: return 5;
    case ASTRO_BODY_NEPTUNE: return 6;
    case ASTRO_BODY_SUN:
    case ASTRO_BODY_MOON:
    case ASTRO_BODY_COUNT:
        break;
    }
    return -1;
}

struct astro_exact astro_degrees_normalize(struct astro_exact degrees)
{
    return astro_exact_mod(degrees, astro_exact_from_i64(360));
}

/* Sum amp * cos(b + c*tau) over a term table. Addition on this grid is EXACT,
 * so the sum is the same whatever order the terms are visited in — the
 * property that lets a peer recompute it with a differently vectorised loop
 * and still agree bit for bit. */
static struct astro_exact vsop_sum(const struct astro_vsop_term *terms,
                                   size_t count, struct astro_exact tau)
{
    struct astro_exact sum = astro_exact_zero();
    for (size_t i = 0; i < count; i++) {
        struct astro_exact b = astro_exact_ratio(terms[i].b_e7, 10000000);
        struct astro_exact c = astro_exact_ratio(terms[i].c_e7, 10000000);
        struct astro_exact angle = astro_exact_add(b, astro_exact_mul(c, tau));
        struct astro_exact contribution =
            astro_exact_mul(astro_exact_from_i64(terms[i].amp),
                            astro_exact_cos(angle));
        sum = astro_exact_add(sum, contribution);
    }
    return sum;
}

bool astro_earth_heliocentric(struct astro_exact tau, struct astro_polar *out)
{
    if (out == NULL || !astro_exact_is_valid(&tau))
        return false;

    struct astro_exact l0 =
        vsop_sum(k_earth_l0, sizeof(k_earth_l0) / sizeof(k_earth_l0[0]), tau);
    struct astro_exact l1 =
        vsop_sum(k_earth_l1, sizeof(k_earth_l1) / sizeof(k_earth_l1[0]), tau);
    struct astro_exact r0 =
        vsop_sum(k_earth_r0, sizeof(k_earth_r0) / sizeof(k_earth_r0[0]), tau);

    /* The tables are scaled by 1e8 and the result is radians. */
    struct astro_exact scale = astro_exact_from_i64(100000000);
    struct astro_exact lon_rad =
        astro_exact_div(astro_exact_add(l0, astro_exact_mul(l1, tau)), scale);
    struct astro_exact radius = astro_exact_div(r0, scale);

    struct astro_exact lon_deg =
        astro_degrees_normalize(astro_exact_radians_to_degrees(lon_rad));
    if (!astro_exact_is_valid(&lon_deg) || !astro_exact_is_valid(&radius))
        return false;

    out->longitude_deg = lon_deg;
    out->radius_au = radius;
    return true;
}

/* Solve M = E - e*sin(E) for E by Newton's method, all in radians. */
static struct astro_exact solve_kepler(struct astro_exact mean_anomaly_rad,
                                       struct astro_exact eccentricity)
{
    struct astro_exact e = mean_anomaly_rad;
    for (unsigned i = 0; i < ASTRO_KEPLER_STEPS; i++) {
        struct astro_exact s = astro_exact_sin(e);
        struct astro_exact c = astro_exact_cos(e);
        struct astro_exact f = astro_exact_sub(
            astro_exact_sub(e, astro_exact_mul(eccentricity, s)),
            mean_anomaly_rad);
        struct astro_exact df = astro_exact_sub(
            astro_exact_from_i64(1), astro_exact_mul(eccentricity, c));
        if (astro_exact_is_zero(&df))
            return astro_exact_invalid();
        e = astro_exact_sub(e, astro_exact_div(f, df));
        if (!astro_exact_is_valid(&e))
            return astro_exact_invalid();
    }
    return e;
}

bool astro_planet_heliocentric(enum astro_body body, struct astro_exact t,
                               struct astro_polar *out)
{
    if (out == NULL || !astro_exact_is_valid(&t))
        return false;
    int idx = elements_index(body);
    if (idx < 0)
        return false;

    const struct astro_elements *el = &k_elements[idx];
    struct astro_exact e8 = astro_exact_from_i64(100000000);

    struct astro_exact a = astro_exact_div(
        astro_exact_add(astro_exact_from_i64(el->a0_e8),
                        astro_exact_mul(astro_exact_from_i64(el->a1_e8), t)),
        e8);
    struct astro_exact ecc = astro_exact_div(
        astro_exact_add(astro_exact_from_i64(el->e0_e8),
                        astro_exact_mul(astro_exact_from_i64(el->e1_e8), t)),
        e8);
    struct astro_exact mean_lon = astro_exact_div(
        astro_exact_add(astro_exact_from_i64(el->l0_e8),
                        astro_exact_mul(astro_exact_from_i64(el->l1_e8), t)),
        e8);
    struct astro_exact peri_lon = astro_exact_div(
        astro_exact_add(astro_exact_from_i64(el->w0_e8),
                        astro_exact_mul(astro_exact_from_i64(el->w1_e8), t)),
        e8);

    /* An eccentricity outside [0, 1) is not an orbit this model describes.
     * Refusing is the honest answer; clamping would hand back a position that
     * looks like a planet and is not one. */
    if (astro_exact_is_negative(&ecc))
        return false;
    struct astro_exact one = astro_exact_from_i64(1);
    if (astro_exact_cmp(&ecc, &one) >= 0)
        return false;

    struct astro_exact mean_anom_deg =
        astro_degrees_normalize(astro_exact_sub(mean_lon, peri_lon));
    struct astro_exact mean_anom =
        astro_exact_degrees_to_radians(mean_anom_deg);

    struct astro_exact ea = solve_kepler(mean_anom, ecc);
    if (!astro_exact_is_valid(&ea))
        return false;

    /* True anomaly from the eccentric anomaly, by the half-angle form. It
     * needs an atan2 rather than an atan so the quadrant comes out of the
     * signs instead of out of a fix-up the caller has to remember. */
    struct astro_exact half = astro_exact_shr(ea, 1u);
    struct astro_exact sin_half = astro_exact_sin(half);
    struct astro_exact cos_half = astro_exact_cos(half);
    struct astro_exact ky =
        astro_exact_mul(astro_exact_sqrt(astro_exact_add(one, ecc)), sin_half);
    struct astro_exact kx =
        astro_exact_mul(astro_exact_sqrt(astro_exact_sub(one, ecc)), cos_half);
    struct astro_exact true_anom =
        astro_exact_mul(astro_exact_from_i64(2), astro_exact_atan2(ky, kx));

    struct astro_exact radius = astro_exact_mul(
        a, astro_exact_sub(one, astro_exact_mul(ecc, astro_exact_cos(ea))));
    struct astro_exact lon_deg = astro_degrees_normalize(astro_exact_add(
        astro_exact_radians_to_degrees(true_anom), peri_lon));

    if (!astro_exact_is_valid(&lon_deg) || !astro_exact_is_valid(&radius))
        return false;

    out->longitude_deg = lon_deg;
    out->radius_au = radius;
    return true;
}

/* The three largest periodic terms of the Moon's ecliptic longitude, from
 * astro-calc's core/astro_calc_easy.c. This is the weakest model in the file
 * by a wide margin — about half a degree — and it is here because a chart
 * without a Moon is not a chart. Do not mistake it for a lunar theory. */
bool astro_moon_longitude_deg(struct astro_exact t, struct astro_exact *out)
{
    if (out == NULL || !astro_exact_is_valid(&t))
        return false;

    /* Mean longitude, mean elongation, mean anomaly: degrees, 1e-3 units. */
    struct astro_exact e3 = astro_exact_from_i64(1000);
    struct astro_exact mean_lon = astro_exact_div(
        astro_exact_add(astro_exact_from_i64(218316),
                        astro_exact_mul(astro_exact_from_i64(481267881), t)),
        e3);
    struct astro_exact elong = astro_exact_div(
        astro_exact_add(astro_exact_from_i64(297850),
                        astro_exact_mul(astro_exact_from_i64(445267112), t)),
        e3);
    struct astro_exact anom = astro_exact_div(
        astro_exact_add(astro_exact_from_i64(134963),
                        astro_exact_mul(astro_exact_from_i64(477198868), t)),
        e3);

    struct astro_exact anom_rad =
        astro_exact_degrees_to_radians(astro_degrees_normalize(anom));
    struct astro_exact elong_rad =
        astro_exact_degrees_to_radians(astro_degrees_normalize(elong));
    struct astro_exact two_d_minus_m = astro_exact_degrees_to_radians(
        astro_degrees_normalize(astro_exact_sub(
            astro_exact_mul(astro_exact_from_i64(2), elong), anom)));
    struct astro_exact two_d =
        astro_exact_add(elong_rad, elong_rad);

    struct astro_exact sum = mean_lon;
    sum = astro_exact_add(sum, astro_exact_mul(astro_exact_ratio(6289, 1000),
                                               astro_exact_sin(anom_rad)));
    sum = astro_exact_add(sum, astro_exact_mul(astro_exact_ratio(1274, 1000),
                                               astro_exact_sin(two_d_minus_m)));
    sum = astro_exact_add(sum, astro_exact_mul(astro_exact_ratio(658, 1000),
                                               astro_exact_sin(two_d)));

    struct astro_exact lon = astro_degrees_normalize(sum);
    if (!astro_exact_is_valid(&lon))
        return false;
    *out = lon;
    return true;
}
