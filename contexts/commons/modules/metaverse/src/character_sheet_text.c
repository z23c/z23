/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * character_sheet_text — the seed's text form, and only that.
 *
 * The form is the one a character travels in: an owner hands it to a node
 * that does not trust him, the node parses it, recomputes the root, and
 * derives the sheet. So it obeys the same rule
 * metaverse_property_id_format()/parse() obey, for the same reason: ONE VALUE
 * HAS EXACTLY ONE SPELLING. property_id emits lowercase hex only; this file
 * fixes the year at four digits, zero-pads the other date fields to two, and
 * writes the coordinates with no '+' and no leading zeros. Anything else is
 * refused on the way in rather than normalised, because normalising means a
 * character's text form and its root can disagree about which character it
 * is.
 *
 * SRD 5.1 attribution: see metaverse/character_sheet.h. Nothing in this file
 * uses SRD material.
 *
 * No state, no allocation, no I/O. Written by hand rather than through
 * snprintf/sscanf: sscanf("%d") skips leading whitespace and accepts a sign
 * wherever it appears, which is exactly the class of "two spellings of one
 * value" this form exists to prevent — the same defect base/hex.h records in
 * the twelve hex decoders it replaced.
 */

#include "metaverse/character_sheet.h"

#include "astro/astro_chart.h"
#include "astro/astro_time.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>

/* The boundary, enforced by the compiler. See character_sheet.c for the rule
 * and platform/modules/astro/src/astro_priv.h for why the pragma rather than a #define. */
#pragma GCC poison double float

/* ── emit ────────────────────────────────────────────────────────────────── */

/* Append `v` as a zero-padded decimal of exactly `width` digits. Returns
 * false when it does not fit, leaving the caller to fail the whole render
 * rather than emit a truncated one. */
static bool cs_put_padded(char *out, size_t cap, size_t *n, uint32_t v,
                          unsigned width)
{
    char digits[10];
    unsigned i;

    if (width > sizeof digits)
        return false;
    for (i = 0; i < width; i++) {
        digits[width - 1u - i] = (char)('0' + (v % 10u));
        v /= 10u;
    }
    if (v != 0)
        return false; /* the value needs more than `width` digits */
    if (*n + width >= cap)
        return false;
    memcpy(out + *n, digits, width);
    *n += width;
    return true;
}

/* Append `v` as a signed decimal: a '-' only when negative, no '+', and no
 * leading zeros (except the single digit of zero itself). */
static bool cs_put_signed(char *out, size_t cap, size_t *n, int32_t v)
{
    char digits[12];
    unsigned len = 0;
    /* Negate in uint32_t so INT32_MIN has a representation. The callers'
     * values are far inside the range, but a total function costs nothing
     * here and an overflow on a signed negate is undefined behaviour. */
    uint32_t mag = (v < 0) ? (uint32_t)0 - (uint32_t)v : (uint32_t)v;

    if (v < 0) {
        if (*n + 1u >= cap)
            return false;
        out[(*n)++] = '-';
    }
    do {
        digits[len++] = (char)('0' + (mag % 10u));
        mag /= 10u;
    } while (mag != 0 && len < sizeof digits);
    if (mag != 0)
        return false;
    if (*n + len >= cap)
        return false;
    for (unsigned i = 0; i < len; i++)
        out[*n + i] = digits[len - 1u - i];
    *n += len;
    return true;
}

static bool cs_put_char(char *out, size_t cap, size_t *n, char c)
{
    if (*n + 1u >= cap)
        return false;
    out[(*n)++] = c;
    return true;
}

bool character_seed_format(const struct character_seed *seed, char *out,
                           size_t cap)
{
    size_t n = 0;
    size_t name_len;
    uint32_t year_mag;

    if (!out || cap == 0)
        return false;
    out[0] = '\0';
    if (!character_seed_valid(seed))
        return false;

    name_len = strlen(seed->name);

    /* The year is four digits with an optional leading '-'. Four is exact,
     * not a minimum: ASTRO_YEAR_MIN..ASTRO_YEAR_MAX is -4000..9999, so every
     * legal year fits and every legal year fills it. That is what removes the
     * leading-zero ambiguity — "0044" and "44" cannot both be year 44,
     * because only the first is spellable. */
    year_mag = (seed->born.year < 0) ? (uint32_t)0 - (uint32_t)seed->born.year
                                     : (uint32_t)seed->born.year;

    /* ONE failure exit for the whole render. Every step is a short-circuit
     * term of a single condition, so a step that does not fit cannot leave a
     * partially written buffer behind — a truncated seed is not a shorter
     * spelling of this character, it is a DIFFERENT character that would parse
     * and hash to a different root. */
    if (n + name_len >= cap)
        goto refuse;
    memcpy(out + n, seed->name, name_len);
    n += name_len;

    if (!cs_put_char(out, cap, &n, '|') ||
        (seed->born.year < 0 && !cs_put_char(out, cap, &n, '-')) ||
        !cs_put_padded(out, cap, &n, year_mag, 4u) ||
        !cs_put_char(out, cap, &n, '-') ||
        !cs_put_padded(out, cap, &n, seed->born.month, 2u) ||
        !cs_put_char(out, cap, &n, '-') ||
        !cs_put_padded(out, cap, &n, seed->born.day, 2u) ||
        !cs_put_char(out, cap, &n, 'T') ||
        !cs_put_padded(out, cap, &n, seed->born.hour, 2u) ||
        !cs_put_char(out, cap, &n, ':') ||
        !cs_put_padded(out, cap, &n, seed->born.minute, 2u) ||
        !cs_put_char(out, cap, &n, ':') ||
        !cs_put_padded(out, cap, &n, seed->born.second, 2u) ||
        !cs_put_char(out, cap, &n, 'Z') ||
        !cs_put_char(out, cap, &n, '|') ||
        !cs_put_signed(out, cap, &n, seed->where.latitude_microdeg) ||
        !cs_put_char(out, cap, &n, '|') ||
        !cs_put_signed(out, cap, &n, seed->where.longitude_microdeg))
        goto refuse;
    out[n] = '\0';
    return true;

refuse:
    out[0] = '\0';
    return false;
}

/* ── parse ───────────────────────────────────────────────────────────────── */

/* Read exactly `width` decimal digits. Advances *p only on success. */
static bool cs_take_padded(const char **p, unsigned width, uint32_t *out)
{
    const char *s = *p;
    uint32_t v = 0;

    for (unsigned i = 0; i < width; i++) {
        if (s[i] < '0' || s[i] > '9')
            return false;
        v = v * 10u + (uint32_t)(s[i] - '0');
    }
    *p = s + width;
    *out = v;
    return true;
}

static bool cs_take_char(const char **p, char c)
{
    if (**p != c)
        return false;
    (*p)++;
    return true;
}

/* Read a signed decimal in the ONE canonical spelling: an optional '-', then
 * digits with no leading zero unless the whole magnitude is a single '0'.
 * "+5", " 5", "05" and "-0" are all refused, so no value has a second
 * spelling that would round-trip to a different string. Stops at `stop`. */
static bool cs_take_signed(const char **p, char stop, int32_t *out)
{
    const char *s = *p;
    bool negative = false;
    uint64_t mag = 0;
    unsigned digits = 0;

    if (*s == '-') {
        negative = true;
        s++;
    }
    if (*s < '0' || *s > '9')
        return false;
    if (*s == '0' && s[1] >= '0' && s[1] <= '9')
        return false; /* leading zero */
    while (*s >= '0' && *s <= '9') {
        mag = mag * 10u + (uint64_t)(*s - '0');
        if (mag > 0x7fffffffull)
            return false;
        s++;
        digits++;
    }
    if (digits == 0)
        return false;
    if (negative && mag == 0)
        return false; /* "-0" is a second spelling of "0" */
    if (*s != stop)
        return false;
    *p = s;
    *out = negative ? -(int32_t)mag : (int32_t)mag;
    return true;
}

bool character_seed_parse(const char *text, struct character_seed *out)
{
    char name[CHARACTER_NAME_MAX];
    struct astro_instant born;
    struct astro_place where;
    const char *p;
    const char *bar;
    size_t name_len;
    uint32_t year_mag, month, day, hour, minute, second;
    bool year_negative = false;

    if (!out)
        return false;
    memset(out, 0, sizeof *out);
    if (!text)
        return false;

    bar = strchr(text, '|');
    if (!bar)
        return false;
    name_len = (size_t)(bar - text);
    if (name_len == 0 || name_len + 1u > CHARACTER_NAME_MAX)
        return false;
    memcpy(name, text, name_len);
    name[name_len] = '\0';

    p = bar + 1;
    if (*p == '-') {
        year_negative = true;
        p++;
    }
    if (!cs_take_padded(&p, 4u, &year_mag) || !cs_take_char(&p, '-') ||
        !cs_take_padded(&p, 2u, &month) || !cs_take_char(&p, '-') ||
        !cs_take_padded(&p, 2u, &day) || !cs_take_char(&p, 'T') ||
        !cs_take_padded(&p, 2u, &hour) || !cs_take_char(&p, ':') ||
        !cs_take_padded(&p, 2u, &minute) || !cs_take_char(&p, ':') ||
        !cs_take_padded(&p, 2u, &second) || !cs_take_char(&p, 'Z') ||
        !cs_take_char(&p, '|'))
        return false;

    memset(&born, 0, sizeof born);
    born.year = year_negative ? -(int32_t)year_mag : (int32_t)year_mag;
    born.month = (uint8_t)month;
    born.day = (uint8_t)day;
    born.hour = (uint8_t)hour;
    born.minute = (uint8_t)minute;
    born.second = (uint8_t)second;

    memset(&where, 0, sizeof where);
    if (!cs_take_signed(&p, '|', &where.latitude_microdeg))
        return false;
    if (!cs_take_char(&p, '|'))
        return false;
    if (!cs_take_signed(&p, '\0', &where.longitude_microdeg))
        return false;
    /* cs_take_signed stopped at the NUL, so there are no trailing bytes: a
     * string with anything after the longitude is a DIFFERENT string and must
     * not silently parse, exactly as metaverse_property_id_parse() refuses a
     * trailing byte after its 64 hex digits. */

    /* Every remaining rule — the name charset, the calendar, the coordinate
     * limits — is character_seed_make()'s, asked once here rather than
     * duplicated. A parser with its own opinion about validity is a second
     * truth about what a character is. */
    return character_seed_make(name, &born, &where, out);
}
