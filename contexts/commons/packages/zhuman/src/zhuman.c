/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0
 * Purpose: human-readable byte and duration formatting and parsing.
 */
#include "zhuman/zhuman.h"

#include <stdio.h>
#include <string.h>

/* --- Sizes ----------------------------------------------------------- */

static zhuman_err format_bytes(uint64_t bytes, char *out, size_t cap,
                               const char *const units[7], uint64_t base)
{
    if (!out || cap == 0) return ZHUMAN_ERR_NULL;
    int u = 0;
    uint64_t scaled = bytes;
    while (scaled >= base && u < 6) {
        scaled /= base;
        u++;
    }
    uint64_t unit_size = 1;
    for (int i = 0; i < u; i++) unit_size *= base;
    int n;
    if (u == 0 || bytes % unit_size == 0) {
        /* exact whole unit (u==0 always exact; integer multiple) */
        n = snprintf(out, cap, "%llu %s",
                     (unsigned long long)(u == 0 ? bytes : scaled), units[u]);
    } else {
        /* one decimal place */
        uint64_t whole = bytes / unit_size;
        uint64_t tenth = (bytes % unit_size) * 10 / unit_size;
        n = snprintf(out, cap, "%llu.%llu %s",
                     (unsigned long long)whole, (unsigned long long)tenth,
                     units[u]);
    }
    if (n < 0 || (size_t)n >= cap) return ZHUMAN_ERR_SMALL;
    return ZHUMAN_OK;
}

zhuman_err zhuman_format_bytes_iec(uint64_t bytes, char *out, size_t cap)
{
    static const char *const U[7] = {"B", "KiB", "MiB", "GiB", "TiB", "PiB", "EiB"};
    return format_bytes(bytes, out, cap, U, 1024);
}

zhuman_err zhuman_format_bytes_si(uint64_t bytes, char *out, size_t cap)
{
    static const char *const U[7] = {"B", "kB", "MB", "GB", "TB", "PB", "EB"};
    return format_bytes(bytes, out, cap, U, 1000);
}

static int ci_equal(const char *a, const char *b)
{
    while (*a && *b) {
        char ca = *a, cb = *b;
        if (ca >= 'A' && ca <= 'Z') ca += 32;
        if (cb >= 'A' && cb <= 'Z') cb += 32;
        if (ca != cb) return 0;
        a++;
        b++;
    }
    return *a == *b;
}

/* Unit multipliers are at most 2^60 and frac is a single decimal digit. */
static zhuman_err scaled_bytes(uint64_t whole, uint64_t frac,
                               uint64_t mult, uint64_t *out)
{
    if (whole > UINT64_MAX / mult) return ZHUMAN_ERR_OVERFLOW;
    uint64_t value = whole * mult;
    uint64_t fraction = frac * mult / 10;
    if (value > UINT64_MAX - fraction) return ZHUMAN_ERR_OVERFLOW;
    *out = value + fraction;
    return ZHUMAN_OK;
}

/* Parses leading decimal digits into *out, advancing *str past them. */
static zhuman_err parse_decimal_digits(const char **str, uint64_t *out)
{
    uint64_t value = 0;
    while (**str >= '0' && **str <= '9') {
        uint64_t digit = (uint64_t)(**str - '0');
        if (value > (UINT64_MAX - digit) / 10) return ZHUMAN_ERR_OVERFLOW;
        value = value * 10 + digit;
        (*str)++;
    }
    *out = value;
    return ZHUMAN_OK;
}

/* Parses the optional single fractional digit after '.'. */
static zhuman_err parse_tenth_digit(const char **str, uint64_t *frac)
{
    if (**str != '.') return ZHUMAN_OK;
    (*str)++;
    if (!(**str >= '0' && **str <= '9')) return ZHUMAN_ERR_FORMAT;
    *frac = (uint64_t)(**str - '0');
    (*str)++;
    if (**str >= '0' && **str <= '9') return ZHUMAN_ERR_FORMAT; /* >1 dp */
    return ZHUMAN_OK;
}

zhuman_err zhuman_parse_bytes(const char *str, uint64_t *out)
{
    if (!str || !out) return ZHUMAN_ERR_NULL;
    while (*str == ' ') str++;
    if (!*str) return ZHUMAN_ERR_FORMAT;

    /* Parse integer part. */
    uint64_t whole = 0;
    const char *start = str;
    zhuman_err err = parse_decimal_digits(&str, &whole);
    if (err != ZHUMAN_OK) return err;
    if (str == start) return ZHUMAN_ERR_FORMAT;

    /* Optional single fractional digit. */
    uint64_t frac = 0; /* tenths */
    err = parse_tenth_digit(&str, &frac);
    if (err != ZHUMAN_OK) return err;
    while (*str == ' ') str++;

    static const struct { const char *name; uint64_t mult; } UNITS[] = {
        {"",     1},
        {"B",    1},
        {"KiB",  1ull << 10}, {"MiB", 1ull << 20}, {"GiB", 1ull << 30},
        {"TiB",  1ull << 40}, {"PiB", 1ull << 50}, {"EiB", 1ull << 60},
        {"kB",   1000ull},    {"MB",  1000ull * 1000},
        {"GB",   1000ull * 1000 * 1000},
        {"TB",   1000ull * 1000 * 1000 * 1000},
        {"PB",   1000ull * 1000 * 1000 * 1000 * 1000},
        {"EB",   1000ull * 1000 * 1000 * 1000 * 1000 * 1000},
    };
    for (size_t i = 0; i < sizeof UNITS / sizeof UNITS[0]; i++) {
        if (ci_equal(str, UNITS[i].name)) {
            return scaled_bytes(whole, frac, UNITS[i].mult, out);
        }
    }
    return ZHUMAN_ERR_FORMAT;
}

/* --- Durations ------------------------------------------------------- */

/* Appends one whole-unit field for a nonzero value. */
static zhuman_err append_duration_unit(char *out, size_t cap, size_t *off,
                                       uint64_t value, const char *fmt)
{
    if (value == 0) return ZHUMAN_OK;
    int n = snprintf(out + *off, cap - *off, fmt, (unsigned long long)value);
    if (n < 0 || (size_t)n >= cap - *off) return ZHUMAN_ERR_SMALL;
    *off += (size_t)n;
    return ZHUMAN_OK;
}

/* Appends the final seconds field, dropping the trailing space when it is
 * skipped. */
static zhuman_err append_duration_seconds(char *out, size_t cap, size_t *off,
                                          uint64_t s, uint64_t rem)
{
    if (s == 0 && rem == 0 && *off > 0) {
        (*off)--; /* drop trailing space */
        return ZHUMAN_OK;
    }
    int n;
    if (rem > 0)
        n = snprintf(out + *off, cap - *off, "%llu.%03llus",
                     (unsigned long long)s, (unsigned long long)rem);
    else
        n = snprintf(out + *off, cap - *off, "%llus",
                     (unsigned long long)s);
    if (n < 0 || (size_t)n >= cap - *off) return ZHUMAN_ERR_SMALL;
    *off += (size_t)n;
    return ZHUMAN_OK;
}

zhuman_err zhuman_format_duration(uint64_t ms, char *out, size_t cap)
{
    if (!out || cap == 0) return ZHUMAN_ERR_NULL;
    if (ms == 0) {
        if (cap < 5) return ZHUMAN_ERR_SMALL;
        memcpy(out, "0 ms", 5);
        return ZHUMAN_OK;
    }

    uint64_t d = ms / 86400000; ms %= 86400000;
    uint64_t h = ms / 3600000;  ms %= 3600000;
    uint64_t m = ms / 60000;    ms %= 60000;
    uint64_t s = ms / 1000;     uint64_t rem = ms % 1000;

    size_t off = 0;
    zhuman_err err = append_duration_unit(out, cap, &off, d, "%llud ");
    if (err != ZHUMAN_OK) return err;
    err = append_duration_unit(out, cap, &off, h, "%lluh ");
    if (err != ZHUMAN_OK) return err;
    err = append_duration_unit(out, cap, &off, m, "%llum ");
    if (err != ZHUMAN_OK) return err;
    err = append_duration_seconds(out, cap, &off, s, rem);
    if (err != ZHUMAN_OK) return err;
    out[off] = '\0';
    return ZHUMAN_OK;
}

/* Matches one unit suffix, advancing *str past it. */
static zhuman_err parse_duration_unit(const char **str, uint64_t *mult,
                                      unsigned *bit)
{
    static const struct { const char *suffix; uint64_t mult; unsigned bit; }
        UNITS[] = {
        {"ms", 1,        4},
        {"d",  86400000, 0},
        {"h",  3600000,  1},
        {"m",  60000,    2},
        {"s",  1000,     3},
    };
    for (size_t i = 0; i < sizeof UNITS / sizeof UNITS[0]; i++) {
        size_t len = strlen(UNITS[i].suffix);
        if (strncmp(*str, UNITS[i].suffix, len) == 0) {
            *mult = UNITS[i].mult;
            *bit = UNITS[i].bit;
            *str += len;
            return ZHUMAN_OK;
        }
    }
    return ZHUMAN_ERR_FORMAT;
}

/* Parses an optional '.' fraction into milliseconds, setting *has_fraction. */
static zhuman_err parse_fraction_ms(const char **str, uint64_t *frac_ms,
                                    bool *has_fraction)
{
    *frac_ms = 0;
    *has_fraction = false;
    if (**str != '.') return ZHUMAN_OK;
    *has_fraction = true;
    (*str)++;
    if (!(**str >= '0' && **str <= '9')) return ZHUMAN_ERR_FORMAT;
    uint64_t place = 100; /* first digit is tenths of a second */
    while (**str >= '0' && **str <= '9') {
        if (place > 0) {
            *frac_ms += (uint64_t)(**str - '0') * place;
            place /= 10;
        }
        (*str)++;
    }
    return ZHUMAN_OK;
}

/* Checks unit rules and adds one component to the running totals. */
static zhuman_err add_duration_component(uint64_t val, uint64_t frac_ms,
                                         uint64_t mult, unsigned bit,
                                         bool has_fraction, unsigned *seen,
                                         uint64_t *total)
{
    if (has_fraction && bit != 3) return ZHUMAN_ERR_FORMAT; /* "1.5m" rejected */
    if (*seen & (1u << bit)) return ZHUMAN_ERR_FORMAT;  /* repeated unit */
    *seen |= 1u << bit;

    if (val > (UINT64_MAX - frac_ms) / mult) return ZHUMAN_ERR_OVERFLOW;
    uint64_t part = val * mult + frac_ms;
    if (*total > UINT64_MAX - part) return ZHUMAN_ERR_OVERFLOW;
    *total += part;
    return ZHUMAN_OK;
}

/* Parses one value and unit, then adds it to the totals. */
static zhuman_err parse_duration_component(const char **str, unsigned *seen,
                                           uint64_t *total)
{
    if (!(**str >= '0' && **str <= '9')) return ZHUMAN_ERR_FORMAT;

    uint64_t val = 0;
    zhuman_err err = parse_decimal_digits(str, &val);
    if (err != ZHUMAN_OK) return err;

    /* Optional fraction, only meaningful before 's'. */
    uint64_t frac_ms = 0;
    bool has_fraction = false;
    err = parse_fraction_ms(str, &frac_ms, &has_fraction);
    if (err != ZHUMAN_OK) return err;

    uint64_t mult;
    unsigned bit;
    while (**str == ' ') (*str)++; /* allow "0 ms" */
    err = parse_duration_unit(str, &mult, &bit);
    if (err != ZHUMAN_OK) return err;

    return add_duration_component(val, frac_ms, mult, bit, has_fraction,
                                  seen, total);
}

zhuman_err zhuman_parse_duration(const char *str, uint64_t *out_ms)
{
    if (!str || !out_ms) return ZHUMAN_ERR_NULL;
    while (*str == ' ') str++;
    if (!*str) return ZHUMAN_ERR_FORMAT;

    uint64_t total = 0;
    unsigned seen = 0; /* bit per unit: d h m s ms */
    int components = 0;

    while (*str) {
        while (*str == ' ') str++;
        if (!*str) break;
        zhuman_err err = parse_duration_component(&str, &seen, &total);
        if (err != ZHUMAN_OK) return err;
        components++;
    }
    if (components == 0) return ZHUMAN_ERR_FORMAT;
    *out_ms = total;
    return ZHUMAN_OK;
}

const char *zhuman_err_str(zhuman_err e)
{
    switch (e) {
    case ZHUMAN_OK:           return "ok";
    case ZHUMAN_ERR_NULL:     return "null argument";
    case ZHUMAN_ERR_FORMAT:   return "unrecognized format";
    case ZHUMAN_ERR_OVERFLOW: return "value overflow";
    case ZHUMAN_ERR_SMALL:    return "output buffer too small";
    }
    return "unknown error";
}
