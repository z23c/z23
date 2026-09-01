/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * astro_time — a civil instant, and its exact Julian day.
 *
 * ── The instant is FIELDS, never a time_t and never a clock read ─────────
 * The input to a chart is a fictional birth moment supplied by the caller. It
 * is not "now", so this module never reads a clock — there is no
 * clock_gettime, no time(), no timezone database, and nothing here can differ
 * between two nodes because of where or when they are running. A caller who
 * genuinely wants the current instant converts it themselves through the
 * platform port and hands the fields in.
 *
 * ── The time scale, stated rather than implied ───────────────────────────
 * The fields are read as proleptic Gregorian UTC and treated as a UNIFORM
 * scale: no leap seconds, no UT1-UTC, no TT-TDB. That is a deliberate
 * simplification and it has a reason beyond economy. A leap-second table is
 * loaded from somewhere, and two nodes holding different vintages of that
 * table compute different charts from the same input — a divergence that
 * looks exactly like one of them lying. Baking the offsets in instead would
 * freeze a table that the IERS keeps changing. So this module refuses the
 * whole question: its time scale is defined by the arithmetic in
 * astro_time.c and by nothing else, which is what makes a chart a pure
 * function of its input fields.
 *
 * The cost is real and small: relative to Terrestrial Time the scale is off
 * by about 70 seconds today. The Moon, the fastest body here, moves roughly
 * 0.6 arcminutes in that time, which is inside the error of the lunar theory
 * this module ships anyway (see astro_chart.h). For a fictional-character
 * seed it is irrelevant; for ephemeris-grade work this module is the wrong
 * tool and says so.
 *
 * Everything here is EXACT in the sense of astro/astro_exact.h: integer
 * arithmetic only, identical bits on every platform.
 */

#ifndef ZCL_ASTRO_TIME_H
#define ZCL_ASTRO_TIME_H

#include "astro/astro_exact.h"

#include <stdbool.h>
#include <stdint.h>

/* Bounds of an acceptable instant. Outside this range the truncated planetary
 * theory in this module is not merely imprecise, it is wrong by degrees, so
 * the range is a refusal boundary rather than an overflow guard. */
#define ASTRO_YEAR_MIN (-4000)
#define ASTRO_YEAR_MAX 9999

/* A civil instant, proleptic Gregorian. All fields are as written on a
 * calendar and a clock: month 1..12, day 1..(length of that month), hour
 * 0..23, minute 0..59, second 0..59. There is no leap-second 60. */
struct astro_instant {
    int32_t year;
    uint8_t month;
    uint8_t day;
    uint8_t hour;
    uint8_t minute;
    uint8_t second;
};

/* True when every field is in range AND the day exists in that month of that
 * year (Gregorian leap rule). 2023-02-29 is refused, 2024-02-29 accepted. */
bool astro_instant_is_valid(const struct astro_instant *t);

/* Julian day of the instant, exact. Returns false and leaves *out untouched
 * for any instant astro_instant_is_valid() rejects.
 *
 * The integer part uses the standard Fliegel-Van Flandern expression, which
 * is exact in integers; the time of day contributes
 * (seconds_since_midnight / 86400) truncated onto the grid — the one rounding
 * in this file, at 2^-128 of a day, or about 2e-34 seconds. */
bool astro_instant_julian_day(const struct astro_instant *t,
                              struct astro_exact *out);

/* Julian centuries of 36525 days since J2000.0 (JD 2451545.0). The argument
 * every polynomial in astro_chart.c is written in. */
struct astro_exact astro_julian_centuries(struct astro_exact julian_day);

/* Julian millennia of 365250 days since J2000.0 — the argument VSOP87's
 * series are tabulated in. */
struct astro_exact astro_julian_millennia(struct astro_exact julian_day);

#endif /* ZCL_ASTRO_TIME_H */
