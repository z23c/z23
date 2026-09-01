/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: RFC 3339 timestamp parsing and formatting for C23, UTC and
 *          numeric offsets only. Allocation-free, bounded, and total:
 *          every calendar field is range-checked (including leap-year
 *          month lengths); leap seconds ("...:60") are rejected rather
 *          than smeared.
 *
 * Accepted grammar (a strict RFC 3339 profile):
 *
 *   timestamp := date "T" time [ fraction ] offset
 *   date      := YYYY "-" MM "-" DD        (4-digit year, zero-padded)
 *   time      := HH ":" MM ":" SS          (24h clock, SS in 00..59)
 *   fraction  := "." 1*9DIGIT              (nanosecond precision max)
 *   offset    := "Z" | ("+"|"-") HH ":" MM (|offset| < 24h)
 *
 * The parsed instant is returned as Unix seconds (proleptic Gregorian
 * calendar, no leap seconds) plus nanoseconds; the offset is applied,
 * so "1970-01-01T01:00:00+01:00" parses to 0. Format always emits the
 * canonical UTC form "...Z".
 */
#ifndef ZTIME_H
#define ZTIME_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef struct {
  int64_t unix_secs; /* seconds since 1970-01-01T00:00:00Z, may be < 0 */
  uint32_t nanos;    /* 0..999,999,999 */
} ztime_instant;

/* Days in a month for a proleptic Gregorian year (month 1..12).
 * Returns 0 for an out-of-range month. */
int ztime_days_in_month(int64_t year, unsigned month);

/* True for Gregorian leap years. */
bool ztime_is_leap_year(int64_t year);

/* Days since 1970-01-01 for a valid civil date; false when the date is
 * out of range (month/day validity included). */
bool ztime_days_from_civil(int64_t year, unsigned month, unsigned day,
                           int64_t *days_out);

/* Inverse of ztime_days_from_civil. */
void ztime_civil_from_days(int64_t days, int64_t *year_out,
                           unsigned *month_out, unsigned *day_out);

/* Parse an RFC 3339 timestamp over str[0..len). False on any grammar
 * or range violation; *out is zeroed in that case. */
bool ztime_parse_n(const char *str, size_t len, ztime_instant *out);

/* NUL-terminated convenience wrapper. */
bool ztime_parse(const char *str, ztime_instant *out);

/* Format as canonical RFC 3339 UTC ("YYYY-MM-DDTHH:MM:SS[.fffffffff]Z";
 * the fraction is printed only when nanos != 0, with trailing zeros
 * trimmed). Returns the length written, or 0 when the buffer is too
 * small or the instant is out of the representable 4-digit-year range.
 * A buffer of 32 bytes always suffices. */
size_t ztime_format(const ztime_instant *instant, char *out,
                    size_t out_len);

#endif /* ZTIME_H */
