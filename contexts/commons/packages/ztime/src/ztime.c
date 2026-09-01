/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: RFC 3339 parse/format (see the header for the grammar).
 * Civil-date math is the standard era-based algorithm: days are counted
 * from 1970-01-01 with March as the first month so February's leap day
 * ends each 400-year era. */
#include "ztime/ztime.h"

#include <stdio.h>
#include <string.h>

bool ztime_is_leap_year(int64_t year) {
  return (year % 4 == 0 && year % 100 != 0) || year % 400 == 0;
}

int ztime_days_in_month(int64_t year, unsigned month) {
  static const int days[] = {31, 28, 31, 30, 31, 30,
                             31, 31, 30, 31, 30, 31};
  if (month < 1 || month > 12)
    return 0;
  if (month == 2 && ztime_is_leap_year(year))
    return 29;
  return days[month - 1];
}

bool ztime_days_from_civil(int64_t year, unsigned month, unsigned day,
                           int64_t *days_out) {
  if (!days_out)
    return false;
  if (month < 1 || month > 12 || day < 1 ||
      (int64_t)day > ztime_days_in_month(year, month))
    return false;
  int64_t y = month <= 2 ? year - 1 : year;
  int64_t era = (y >= 0 ? y : y - 399) / 400;
  unsigned yoe = (unsigned)(y - era * 400); /* [0, 399] */
  unsigned mp = (month + 9) % 12; /* March = 0 */
  unsigned doy = (153 * mp + 2) / 5 + day - 1;
  unsigned doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
  *days_out = era * 146097 + (int64_t)doe - 719468;
  return true;
}

void ztime_civil_from_days(int64_t days, int64_t *year_out,
                           unsigned *month_out, unsigned *day_out) {
  int64_t z = days + 719468;
  int64_t era = (z >= 0 ? z : z - 146096) / 146097;
  unsigned doe = (unsigned)(z - era * 146097); /* [0, 146096] */
  unsigned yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
  int64_t y = (int64_t)yoe + era * 400;
  unsigned doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
  unsigned mp = (5 * doy + 2) / 153;
  unsigned d = doy - (153 * mp + 2) / 5 + 1;
  unsigned m = mp < 10 ? mp + 3 : mp - 9; /* March = 3 ... February = 14 */
  *year_out = m <= 2 ? y + 1 : y;
  *month_out = m;
  *day_out = d;
}

static bool parse_uint(const char *s, size_t len, uint32_t *out) {
  if (!len)
    return false;
  uint32_t v = 0;
  for (size_t i = 0; i < len; i++) {
    if (s[i] < '0' || s[i] > '9')
      return false;
    uint32_t nv = v * 10 + (uint32_t)(s[i] - '0');
    if (nv < v)
      return false; /* overflow */
    v = nv;
  }
  *out = v;
  return true;
}

bool ztime_parse_n(const char *str, size_t len, ztime_instant *out) {
  if (!out)
    return false;
  memset(out, 0, sizeof(*out));
  /* Minimum: "YYYY-MM-DDTHH:MM:SSZ" = 20 bytes. */
  if (!str || len < 20)
    return false;

  uint32_t year, month, day, hour, min, sec;
  if (!parse_uint(str, 4, &year) || str[4] != '-' ||
      !parse_uint(str + 5, 2, &month) || str[7] != '-' ||
      !parse_uint(str + 8, 2, &day) || str[10] != 'T' ||
      !parse_uint(str + 11, 2, &hour) || str[13] != ':' ||
      !parse_uint(str + 14, 2, &min) || str[16] != ':' ||
      !parse_uint(str + 17, 2, &sec))
    return false;
  size_t pos = 19;

  uint32_t nanos = 0;
  if (pos < len && str[pos] == '.') {
    pos++;
    size_t digits = 0;
    uint32_t frac = 0;
    while (pos < len && str[pos] >= '0' && str[pos] <= '9' &&
           digits < 9) {
      frac = frac * 10 + (uint32_t)(str[pos] - '0');
      digits++;
      pos++;
    }
    if (!digits)
      return false; /* "." with no digits */
    if (pos < len && str[pos] >= '0' && str[pos] <= '9')
      return false; /* beyond nanosecond precision: fail closed */
    while (digits < 9) {
      frac *= 10;
      digits++;
    }
    nanos = frac;
  }

  int64_t offset_secs = 0;
  if (pos < len && str[pos] == 'Z') {
    pos++;
  } else if (pos < len && (str[pos] == '+' || str[pos] == '-')) {
    /* Need exactly 6 more bytes: sign HH ":" MM */
    if (pos + 6 > len)
      return false;
    uint32_t oh, om;
    if (!parse_uint(str + pos + 1, 2, &oh) || str[pos + 3] != ':' ||
        !parse_uint(str + pos + 4, 2, &om))
      return false;
    if (oh > 23 || om > 59)
      return false;
    offset_secs = (int64_t)(oh * 3600 + om * 60);
    if (str[pos] == '-')
      offset_secs = -offset_secs;
    pos += 6;
  } else {
    return false; /* RFC 3339 requires an explicit offset */
  }
  if (pos != len)
    return false; /* trailing garbage */

  if (hour > 23 || min > 59 || sec > 59)
    return false; /* leap seconds rejected, not smeared */
  int64_t days;
  if (!ztime_days_from_civil(year, month, day, &days))
    return false;

  int64_t secs = days * 86400 + (int64_t)hour * 3600 +
                 (int64_t)min * 60 + sec - offset_secs;
  out->unix_secs = secs;
  out->nanos = nanos;
  return true;
}

bool ztime_parse(const char *str, ztime_instant *out) {
  return str && ztime_parse_n(str, strlen(str), out);
}

size_t ztime_format(const ztime_instant *instant, char *out,
                    size_t out_len) {
  if (!instant || !out)
    return 0;
  if (instant->nanos > 999999999u)
    return 0;
  int64_t secs = instant->unix_secs;
  int64_t days = secs / 86400;
  int64_t rem = secs % 86400;
  if (rem < 0) {
    rem += 86400;
    days -= 1;
  }
  int64_t year;
  unsigned month, day;
  ztime_civil_from_days(days, &year, &month, &day);
  if (year < 0 || year > 9999)
    return 0; /* 4-digit-year range only */
  unsigned hour = (unsigned)(rem / 3600);
  unsigned min = (unsigned)((rem % 3600) / 60);
  unsigned sec = (unsigned)(rem % 60);

  int n = snprintf(out, out_len, "%04lld-%02u-%02uT%02u:%02u:%02u",
                   (long long)year, month, day, hour, min, sec);
  if (n < 0 || (size_t)n >= out_len)
    return 0;
  size_t used = (size_t)n;
  if (instant->nanos) {
    char frac[10];
    int fn = snprintf(frac, sizeof(frac), "%09u", instant->nanos);
    if (fn != 9)
      return 0;
    int flen = 9;
    while (frac[flen - 1] == '0')
      flen--;
    if (used + 1 + (size_t)flen + 1 >= out_len)
      return 0;
    out[used++] = '.';
    memcpy(out + used, frac, (size_t)flen);
    used += (size_t)flen;
  }
  if (used + 2 > out_len)
    return 0;
  out[used++] = 'Z';
  out[used] = '\0';
  return used;
}
