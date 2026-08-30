/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * astro_chart — assembles a chart from the ephemeris in astro_ephemeris.c:
 * geocentric longitudes, the ascendant, the house cusps, and the exact
 * sign/degree/arcminute/arcsecond split every consumer reads.
 *
 * The contract, the accuracy of each body and the reasons for the two visible
 * simplifications (coplanar orbits, equal houses) are in astro/astro_chart.h.
 * This file is where the one astronomical correction to the source is made:
 * planetary positions are converted from heliocentric to GEOCENTRIC, because
 * a birth chart is what an observer on the Earth sees and the source reported
 * the Sun-centred value.
 */

#include "astro_priv.h"

#include "astro/astro_time.h"

#include <string.h>

/* EXACT PATH — see astro_priv.h. */
#pragma GCC poison double float

#define ASTRO_ARCSEC_PER_CIRCLE 1296000 /* 360 * 3600 */
#define ASTRO_ARCSEC_PER_SIGN 108000    /* 30 * 3600 */

const char *astro_body_name(enum astro_body body)
{
    switch (body) {
    case ASTRO_BODY_SUN: return "Sun";
    case ASTRO_BODY_MOON: return "Moon";
    case ASTRO_BODY_MERCURY: return "Mercury";
    case ASTRO_BODY_VENUS: return "Venus";
    case ASTRO_BODY_MARS: return "Mars";
    case ASTRO_BODY_JUPITER: return "Jupiter";
    case ASTRO_BODY_SATURN: return "Saturn";
    case ASTRO_BODY_URANUS: return "Uranus";
    case ASTRO_BODY_NEPTUNE: return "Neptune";
    case ASTRO_BODY_COUNT: break;
    }
    return "unknown";
}

const char *astro_sign_name(enum astro_sign sign)
{
    switch (sign) {
    case ASTRO_SIGN_ARIES: return "Aries";
    case ASTRO_SIGN_TAURUS: return "Taurus";
    case ASTRO_SIGN_GEMINI: return "Gemini";
    case ASTRO_SIGN_CANCER: return "Cancer";
    case ASTRO_SIGN_LEO: return "Leo";
    case ASTRO_SIGN_VIRGO: return "Virgo";
    case ASTRO_SIGN_LIBRA: return "Libra";
    case ASTRO_SIGN_SCORPIO: return "Scorpio";
    case ASTRO_SIGN_SAGITTARIUS: return "Sagittarius";
    case ASTRO_SIGN_CAPRICORN: return "Capricorn";
    case ASTRO_SIGN_AQUARIUS: return "Aquarius";
    case ASTRO_SIGN_PISCES: return "Pisces";
    case ASTRO_SIGN_COUNT: break;
    }
    return "unknown";
}

/* One floor of one exact value decides the sign AND the sexagesimal split, so
 * the two can never disagree — the failure mode of deriving the sign from
 * lon/30 and the arcminutes from a separately floored lon*3600, where a value
 * a hair under a cusp can land in one sign at 0 degrees and the next sign at
 * 29 degrees 59 minutes. */
bool astro_position_from_longitude(struct astro_exact longitude_deg,
                                   struct astro_position *out)
{
    if (out == NULL || !astro_exact_is_valid(&longitude_deg))
        return false;
    if (astro_exact_is_negative(&longitude_deg))
        return false;

    struct astro_exact limit = astro_exact_from_i64(360);
    if (astro_exact_cmp(&longitude_deg, &limit) >= 0)
        return false;

    struct astro_exact scaled =
        astro_exact_mul(longitude_deg, astro_exact_from_i64(3600));
    int64_t arcsec = 0;
    if (!astro_exact_floor_i64(&scaled, &arcsec))
        return false;
    if (arcsec < 0 || arcsec >= ASTRO_ARCSEC_PER_CIRCLE)
        return false;

    int64_t sign_index = arcsec / ASTRO_ARCSEC_PER_SIGN;
    int64_t within = arcsec % ASTRO_ARCSEC_PER_SIGN;

    memset(out, 0, sizeof(*out));
    out->longitude_deg = longitude_deg;
    out->sign = (enum astro_sign)sign_index;
    out->degree_in_sign = (int32_t)(within / 3600);
    out->arcminute = (int32_t)((within / 60) % 60);
    out->arcsecond = (int32_t)(within % 60);
    return true;
}

/* Rectangular ecliptic coordinates from polar, in the coplanar model. */
static bool polar_to_xy(const struct astro_polar *p, struct astro_exact *x,
                        struct astro_exact *y)
{
    struct astro_exact rad = astro_exact_degrees_to_radians(p->longitude_deg);
    *x = astro_exact_mul(p->radius_au, astro_exact_cos(rad));
    *y = astro_exact_mul(p->radius_au, astro_exact_sin(rad));
    return astro_exact_is_valid(x) && astro_exact_is_valid(y);
}

/* Greenwich mean sidereal time in degrees, IAU 1982 expression, written as
 * exact ratios. `d` is days from J2000 and `t` is the same interval in Julian
 * centuries. */
static struct astro_exact greenwich_sidereal_deg(struct astro_exact d,
                                                 struct astro_exact t)
{
    struct astro_exact g = astro_exact_ratio(28046061837, 100000000);
    g = astro_exact_add(
        g, astro_exact_mul(astro_exact_ratio(36098564736629, 100000000000), d));
    struct astro_exact t2 = astro_exact_mul(t, t);
    g = astro_exact_add(
        g, astro_exact_mul(astro_exact_ratio(387933, 1000000000), t2));
    struct astro_exact t3 = astro_exact_mul(t2, t);
    g = astro_exact_sub(g, astro_exact_div(t3, astro_exact_from_i64(38710000)));
    return astro_degrees_normalize(g);
}

/* Mean obliquity of the ecliptic in degrees. The two leading terms of the IAU
 * expression; the quadratic and cubic terms are below an arcsecond over this
 * module's whole accepted range and far below its arcminute-scale error. */
static struct astro_exact mean_obliquity_deg(struct astro_exact t)
{
    struct astro_exact eps = astro_exact_ratio(23439291, 1000000);
    return astro_exact_sub(
        eps, astro_exact_mul(astro_exact_ratio(130042, 10000000), t));
}

static bool compute_ascendant(struct astro_exact julian_day,
                              struct astro_exact t,
                              const struct astro_place *where,
                              struct astro_exact *out_deg)
{
    struct astro_exact d =
        astro_exact_sub(julian_day, astro_exact_ratio(4903090, 2));
    struct astro_exact gmst = greenwich_sidereal_deg(d, t);
    struct astro_exact lst = astro_degrees_normalize(astro_exact_add(
        gmst, astro_exact_ratio(where->longitude_microdeg, 1000000)));

    struct astro_exact theta = astro_exact_degrees_to_radians(lst);
    struct astro_exact eps =
        astro_exact_degrees_to_radians(mean_obliquity_deg(t));
    struct astro_exact phi = astro_exact_degrees_to_radians(
        astro_exact_ratio(where->latitude_microdeg, 1000000));

    struct astro_exact cos_phi = astro_exact_cos(phi);
    if (astro_exact_is_zero(&cos_phi))
        return false; /* the pole has no ascendant; refuse rather than invent */
    struct astro_exact tan_phi = astro_exact_div(astro_exact_sin(phi), cos_phi);

    struct astro_exact numer = astro_exact_cos(theta);
    struct astro_exact denom = astro_exact_neg(astro_exact_add(
        astro_exact_mul(astro_exact_sin(theta), astro_exact_cos(eps)),
        astro_exact_mul(tan_phi, astro_exact_sin(eps))));

    struct astro_exact asc_rad = astro_exact_atan2(numer, denom);
    struct astro_exact asc =
        astro_degrees_normalize(astro_exact_radians_to_degrees(asc_rad));
    if (!astro_exact_is_valid(&asc))
        return false;
    *out_deg = asc;
    return true;
}

bool astro_chart_compute(const struct astro_instant *when,
                         const struct astro_place *where,
                         struct astro_chart *out)
{
    if (out == NULL || when == NULL || where == NULL)
        return false;
    if (!astro_instant_is_valid(when))
        return false;
    if (where->latitude_microdeg > ASTRO_LATITUDE_MICRODEG_LIMIT ||
        where->latitude_microdeg < -ASTRO_LATITUDE_MICRODEG_LIMIT)
        return false;
    if (where->longitude_microdeg > ASTRO_LONGITUDE_MICRODEG_LIMIT ||
        where->longitude_microdeg < -ASTRO_LONGITUDE_MICRODEG_LIMIT)
        return false;
    if (!astro_prepare())
        return false;

    struct astro_exact jd;
    if (!astro_instant_julian_day(when, &jd))
        return false;

    struct astro_exact t = astro_julian_centuries(jd);
    struct astro_exact tau = astro_julian_millennia(jd);
    if (!astro_exact_is_valid(&t) || !astro_exact_is_valid(&tau))
        return false;

    struct astro_polar earth;
    if (!astro_earth_heliocentric(tau, &earth))
        return false;

    struct astro_exact earth_x, earth_y;
    if (!polar_to_xy(&earth, &earth_x, &earth_y))
        return false;

    /* Build into a local and publish only on success, so a caller that
     * ignores the return value cannot read a half-filled chart. */
    struct astro_chart chart;
    memset(&chart, 0, sizeof(chart));
    chart.when = *when;
    chart.where = *where;
    chart.julian_day = jd;

    for (int b = 0; b < ASTRO_BODY_COUNT; b++) {
        enum astro_body body = (enum astro_body)b;
        struct astro_exact lon;

        if (body == ASTRO_BODY_SUN) {
            /* The Sun's geocentric direction is opposite the Earth's
             * heliocentric one. Exact by construction, no subtraction of
             * nearly equal vectors. */
            lon = astro_degrees_normalize(astro_exact_add(
                earth.longitude_deg, astro_exact_from_i64(180)));
        } else if (body == ASTRO_BODY_MOON) {
            if (!astro_moon_longitude_deg(t, &lon))
                return false;
        } else {
            struct astro_polar helio;
            if (!astro_planet_heliocentric(body, t, &helio))
                return false;
            struct astro_exact px, py;
            if (!polar_to_xy(&helio, &px, &py))
                return false;
            struct astro_exact dx = astro_exact_sub(px, earth_x);
            struct astro_exact dy = astro_exact_sub(py, earth_y);
            struct astro_exact rad = astro_exact_atan2(dy, dx);
            lon = astro_degrees_normalize(astro_exact_radians_to_degrees(rad));
        }

        if (!astro_position_from_longitude(lon, &chart.body[b]))
            return false;
    }

    struct astro_exact asc;
    if (!compute_ascendant(jd, t, where, &asc))
        return false;
    if (!astro_position_from_longitude(asc, &chart.ascendant))
        return false;

    for (int h = 0; h < 12; h++) {
        struct astro_exact cusp = astro_degrees_normalize(
            astro_exact_add(asc, astro_exact_from_i64((int64_t)h * 30)));
        if (!astro_position_from_longitude(cusp, &chart.house[h]))
            return false;
    }

    *out = chart;
    return true;
}
