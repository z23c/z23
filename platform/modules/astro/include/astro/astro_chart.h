/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * astro_chart — a birth chart: where each body sits on the ecliptic at one
 * instant, seen from one place on Earth.
 *
 * ── What this is for ─────────────────────────────────────────────────────
 * A chart is a deterministic expansion of a small seed. A fictional birth
 * instant plus a fictional place produce nine longitudes, an ascendant and
 * twelve house cusps, and those produce a character's starting attributes.
 * The point is not astronomy for its own sake — it is that the expansion is
 * REPRODUCIBLE: any node given the same seed derives the same character, so
 * a character can be checked instead of trusted.
 *
 * Every value in a chart is a struct astro_exact and is therefore bit-for-bit
 * identical on every platform, compiler and optimisation level. Read
 * astro/astro_exact.h for what that guarantee is and where it stops.
 *
 * ── ACCURACY IS A DIFFERENT AXIS FROM REPRODUCIBILITY ────────────────────
 * These two are constantly confused and they are unrelated here. The
 * arithmetic is exact; the ASTRONOMY is a truncated theory, and the chart is
 * only as close to the real sky as that theory. Both claims are true at once,
 * and neither rescues the other: a chart can be reproduced to the last bit by
 * every node in the world and still be half a degree from where the Moon
 * actually was.
 *
 * Worst-case error against a full ephemeris, over roughly 1800-2050:
 *
 *   Sun               ~1 arcminute   truncated VSOP87 Earth series
 *   Mercury..Neptune  ~2-30 arcmin   mean Keplerian elements, and see below
 *   Moon              ~0.5 degree    a three-term lunar series
 *
 * The planets carry one further approximation worth naming because it is not
 * obvious from the numbers: their orbits are treated as COPLANAR with the
 * ecliptic. The element set this module inherited carries semi-major axis,
 * eccentricity, mean longitude and longitude of perihelion but no inclination
 * or ascending node, so there is no honest way to tilt them. Ignoring
 * inclination costs at most about half a degree of longitude for Mercury
 * (i = 7 degrees) and well under a tenth of a degree for the outer planets.
 * Ecliptic LATITUDE is not reported at all rather than reported as zero.
 *
 * Pluto is deliberately absent. The only Pluto model in the source this was
 * adapted from is a circular orbit at constant angular rate, and Pluto's
 * eccentricity of 0.25 makes that wrong by up to about 28 degrees — more than
 * a whole sign. A body that lands in the wrong sign is worse than a body that
 * is not there, so it is not there.
 *
 * Houses are EQUAL HOUSES from the ascendant: cusp n is ascendant + 30n
 * degrees. That is what the source implemented (its Placidus path was a
 * comment saying TODO) and it is stated here rather than left for a caller to
 * discover by comparing against an ephemeris.
 *
 * ── Provenance ───────────────────────────────────────────────────────────
 * Adapted from the author's astro-calc project (Apache-2.0, same author, same
 * licence), which is the origin of the exact-rational and CORDIC design and
 * of every coefficient below.
 *
 *   - The Earth series is a 20-term truncation of VSOP87, the semi-analytic
 *     planetary theory of Bretagnon and Francou (Bureau des Longitudes,
 *     1987). Those terms reached astro-calc through its
 *     src/core/astro_minimal.c and are reproduced here as exact integer
 *     ratios rather than decimal literals.
 *   - The planetary elements are the classical mean-element set with linear
 *     rates per Julian century, from the same file.
 *   - The lunar series is the three largest periodic terms of the Moon's
 *     longitude, from astro-calc's core/astro_calc_easy.c.
 *   - Sidereal time and the obliquity of the ecliptic use the standard IAU
 *     polynomials.
 *
 * What was NOT carried across, and why, is recorded in the files that
 * replaced it: src/astro_mag.c (three arithmetic defects), src/astro_trig.c
 * (hand-rounded constant tables and a swapped quadrant), and
 * astro/astro_time.h (a leap-second table loaded from a file). One
 * astronomical correction was made rather than inherited: the source reported
 * HELIOCENTRIC planetary longitudes as chart positions. A chart is seen from
 * the Earth, so this module subtracts the Earth's own position and reports
 * geocentric longitudes.
 */

#ifndef ZCL_ASTRO_CHART_H
#define ZCL_ASTRO_CHART_H

#include "astro/astro_exact.h"
#include "astro/astro_time.h"

#include <stdbool.h>
#include <stdint.h>

enum astro_body {
    ASTRO_BODY_SUN = 0,
    ASTRO_BODY_MOON,
    ASTRO_BODY_MERCURY,
    ASTRO_BODY_VENUS,
    ASTRO_BODY_MARS,
    ASTRO_BODY_JUPITER,
    ASTRO_BODY_SATURN,
    ASTRO_BODY_URANUS,
    ASTRO_BODY_NEPTUNE,
    ASTRO_BODY_COUNT
};

enum astro_sign {
    ASTRO_SIGN_ARIES = 0,
    ASTRO_SIGN_TAURUS,
    ASTRO_SIGN_GEMINI,
    ASTRO_SIGN_CANCER,
    ASTRO_SIGN_LEO,
    ASTRO_SIGN_VIRGO,
    ASTRO_SIGN_LIBRA,
    ASTRO_SIGN_SCORPIO,
    ASTRO_SIGN_SAGITTARIUS,
    ASTRO_SIGN_CAPRICORN,
    ASTRO_SIGN_AQUARIUS,
    ASTRO_SIGN_PISCES,
    ASTRO_SIGN_COUNT
};

/* An observing place. Integer microdegrees, not a floating-point pair: the
 * input to a reproducible computation must itself be exact, and a caller
 * handing in a `double` latitude would reintroduce at the boundary exactly
 * the ambiguity this module removes everywhere else. */
struct astro_place {
    int32_t latitude_microdeg;  /* +north, -south */
    int32_t longitude_microdeg; /* +east, -west */
};

#define ASTRO_LATITUDE_MICRODEG_LIMIT 89500000  /* 89.5 degrees */
#define ASTRO_LONGITUDE_MICRODEG_LIMIT 180000000

/* One position on the ecliptic. `longitude_deg` is the authority; the sign
 * and the degree/arcminute/arcsecond breakdown are exact readouts of it, kept
 * in the struct so that two nodes comparing charts compare the same derived
 * integers rather than each deriving them their own way. */
struct astro_position {
    struct astro_exact longitude_deg; /* [0, 360) */
    enum astro_sign sign;
    int32_t degree_in_sign; /* 0..29 */
    int32_t arcminute;      /* 0..59 */
    int32_t arcsecond;      /* 0..59 */
};

struct astro_chart {
    struct astro_instant when;
    struct astro_place where;
    struct astro_exact julian_day;
    struct astro_position body[ASTRO_BODY_COUNT];
    struct astro_position ascendant;
    struct astro_position house[12]; /* equal houses from the ascendant */
};

/* Compute a chart. Returns false — writing nothing useful to *out — when the
 * instant is out of range or malformed, when the place is out of range, or
 * when any intermediate went INVALID. It never returns a partially valid
 * chart: a poisoned intermediate propagates to the refusal instead of being
 * absorbed into a plausible-looking number.
 *
 * Latitudes beyond +/-89.5 degrees are refused rather than approximated. The
 * ascendant depends on tan(latitude), which is unbounded at the pole, and no
 * house system has an agreed answer there; inventing one would be a chart
 * that looks ordinary and means nothing. */
bool astro_chart_compute(const struct astro_instant *when,
                         const struct astro_place *where,
                         struct astro_chart *out);

/* Split an ecliptic longitude in [0, 360) into sign and exact
 * degree/arcminute/arcsecond. Returns false for an invalid or out-of-range
 * longitude. Exposed because a caller deriving character attributes wants the
 * same split this module used, not its own rounding of a printed value. */
bool astro_position_from_longitude(struct astro_exact longitude_deg,
                                   struct astro_position *out);

/* Stable ASCII names. Never NULL: an out-of-range argument yields "unknown",
 * so a caller printing a corrupted enum gets a visible word rather than a
 * crash or an empty column. */
const char *astro_body_name(enum astro_body body);
const char *astro_sign_name(enum astro_sign sign);

#endif /* ZCL_ASTRO_CHART_H */
