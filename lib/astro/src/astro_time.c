/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * astro_time — civil instant to exact Julian day. The scale this module
 * defines, and why it declines to model leap seconds at all, is argued in
 * astro/astro_time.h. Nothing here reads a clock.
 */

#include "astro/astro_time.h"

#include "astro_priv.h"

/* EXACT PATH — see astro_priv.h. */
#pragma GCC poison double float

static bool is_leap_year(int32_t year)
{
    /* Proleptic Gregorian, applied uniformly to negative years too: the
     * calendar this module uses is the arithmetic one, not the historical
     * one, precisely so the result never depends on a locale or an era. */
    if (year % 4 != 0)
        return false;
    if (year % 100 != 0)
        return true;
    return year % 400 == 0;
}

static uint8_t days_in_month(int32_t year, uint8_t month)
{
    static const uint8_t k_days[12] = {31, 28, 31, 30, 31, 30,
                                       31, 31, 30, 31, 30, 31};
    if (month < 1u || month > 12u)
        return 0;
    if (month == 2u && is_leap_year(year))
        return 29u;
    return k_days[month - 1u];
}

bool astro_instant_is_valid(const struct astro_instant *t)
{
    if (t == NULL)
        return false;
    if (t->year < ASTRO_YEAR_MIN || t->year > ASTRO_YEAR_MAX)
        return false;
    if (t->month < 1u || t->month > 12u)
        return false;
    if (t->day < 1u || t->day > days_in_month(t->year, t->month))
        return false;
    /* No hour 24 and no leap-second 60: this module's scale has neither, and
     * silently folding them into the next day would make two spellings of one
     * instant that a verifier could not tell apart. */
    if (t->hour > 23u || t->minute > 59u || t->second > 59u)
        return false;
    return true;
}

bool astro_instant_julian_day(const struct astro_instant *t,
                              struct astro_exact *out)
{
    if (out == NULL || !astro_instant_is_valid(t))
        return false;

    /* Fliegel and Van Flandern's integer expression for the Julian day
     * number at noon. Exact in int64 for every year this module accepts. */
    int64_t y = t->year;
    int64_t m = t->month;
    int64_t d = t->day;

    int64_t a = (14 - m) / 12;
    int64_t yy = y + 4800 - a;
    int64_t mm = m + 12 * a - 3;

    int64_t jdn = d + (153 * mm + 2) / 5 + 365 * yy + yy / 4 - yy / 100 +
                  yy / 400 - 32045;

    /* JD starts at NOON, so a civil day begins half a day earlier. */
    int64_t seconds = (int64_t)t->hour * 3600 + (int64_t)t->minute * 60 +
                      (int64_t)t->second;

    struct astro_exact jd = astro_exact_from_i64(jdn);
    jd = astro_exact_sub(jd, astro_exact_ratio(1, 2));
    jd = astro_exact_add(jd, astro_exact_ratio(seconds, 86400));
    if (!astro_exact_is_valid(&jd))
        return false;

    *out = jd;
    return true;
}

struct astro_exact astro_julian_centuries(struct astro_exact julian_day)
{
    struct astro_exact since =
        astro_exact_sub(julian_day, astro_exact_ratio(4903090, 2));
    return astro_exact_div(since, astro_exact_from_i64(36525));
}

struct astro_exact astro_julian_millennia(struct astro_exact julian_day)
{
    struct astro_exact since =
        astro_exact_sub(julian_day, astro_exact_ratio(4903090, 2));
    return astro_exact_div(since, astro_exact_from_i64(365250));
}
