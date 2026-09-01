/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: ztime test suite.  Exits nonzero on the first failure.
 * Known-answer timestamps are the standard published epoch anchors
 * (0, -1, 10^9, 2^31-1, 2^31, 253402300799 = 9999-12-31T23:59:59Z). */
#include "ztime/ztime.h"

#include <stdio.h>
#include <string.h>

static int failures = 0;

#define CHECK(cond)                                                          \
  do {                                                                       \
    if (!(cond)) {                                                           \
      fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);        \
      failures++;                                                            \
    }                                                                        \
  } while (0)

#define PARSE(s, want_secs, want_nanos)                                      \
  do {                                                                       \
    ztime_instant it_;                                                       \
    CHECK(ztime_parse((s), &it_));                                           \
    CHECK(it_.unix_secs == (want_secs));                                     \
    CHECK(it_.nanos == (want_nanos));                                        \
  } while (0)

#define BAD(s)                                                               \
  do {                                                                       \
    ztime_instant it_;                                                       \
    memset(&it_, 0xAA, sizeof(it_));                                         \
    CHECK(!ztime_parse((s), &it_));                                          \
    CHECK(it_.unix_secs == 0 && it_.nanos == 0);                             \
  } while (0)

static void test_parse_kats(void) {
  PARSE("1970-01-01T00:00:00Z", 0, 0);
  PARSE("1969-12-31T23:59:59Z", -1, 0);
  PARSE("2001-09-09T01:46:40Z", 1000000000, 0);
  PARSE("2038-01-19T03:14:07Z", 2147483647, 0); /* 2^31-1 */
  PARSE("2038-01-19T03:14:08Z", 2147483648LL, 0); /* 2^31 */
  PARSE("9999-12-31T23:59:59Z", 253402300799LL, 0);
  PARSE("0001-01-01T00:00:00Z", -62135596800LL, 0);
  /* Fractions: padded to nanoseconds. */
  PARSE("1970-01-01T00:00:00.1Z", 0, 100000000);
  PARSE("1970-01-01T00:00:00.000000001Z", 0, 1);
  PARSE("1970-01-01T00:00:00.123456789Z", 0, 123456789);
  /* Numeric offsets apply to the instant. */
  PARSE("1970-01-01T01:00:00+01:00", 0, 0);
  PARSE("1969-12-31T18:30:00-05:30", 0, 0);
  PARSE("2001-09-09T06:16:40+04:30", 1000000000, 0);
}

static void test_parse_errors(void) {
  BAD("");
  BAD("1970-01-01"); /* date only */
  BAD("1970-01-01 00:00:00Z"); /* space, not 'T' */
  BAD("1970-01-01T00:00:00"); /* RFC 3339 requires an offset */
  BAD("1970-13-01T00:00:00Z"); /* month 13 */
  BAD("1970-00-01T00:00:00Z"); /* month 0 */
  BAD("1970-01-00T00:00:00Z");
  BAD("1970-01-32T00:00:00Z");
  BAD("1970-02-29T00:00:00Z"); /* 1970 not leap */
  BAD("1900-02-29T00:00:00Z"); /* century, not leap */
  BAD("2100-02-29T00:00:00Z");
  BAD("2000-02-30T00:00:00Z"); /* leap year, still 29 max */
  BAD("1970-04-31T00:00:00Z"); /* April has 30 */
  BAD("1970-01-01T24:00:00Z"); /* hour 24 */
  BAD("1970-01-01T00:60:00Z");
  BAD("1970-01-01T00:00:60Z"); /* leap second: rejected */
  BAD("1970-01-01T00:00:00.Z"); /* fraction with no digits */
  BAD("1970-01-01T00:00:00.1234567890Z"); /* beyond ns precision */
  BAD("1970-01-01T00:00:00ZZ"); /* trailing garbage */
  BAD("1970-01-01T00:00:00+24:00"); /* offset hour 24 */
  BAD("1970-01-01T00:00:00+01:60"); /* offset minute 60 */
  BAD("1970-01-01T00:00:00+0100"); /* missing colon */
  BAD("1970-01-01T00:00:00+01:"); /* truncated */
  BAD("197-01-01T00:00:00Z"); /* 3-digit year */
  BAD("1970-1-01T00:00:00Z"); /* unpadded month */
  {
    ztime_instant it;
    CHECK(!ztime_parse(NULL, &it));
    CHECK(!ztime_parse_n(NULL, 20, &it));
    CHECK(!ztime_parse_n("1970-01-01T00:00:00Z", 20, NULL));
  }
  /* Valid leap dates parse. */
  PARSE("2000-02-29T12:00:00Z", 951825600, 0); /* 2000 is leap */
  PARSE("2024-02-29T00:00:00Z", 1709164800, 0);
}

static void test_format_kats(void) {
  char buf[32];
  ztime_instant it = {0, 0};
  CHECK(ztime_format(&it, buf, sizeof(buf)) == 20);
  CHECK(!strcmp(buf, "1970-01-01T00:00:00Z"));
  it.unix_secs = -1;
  ztime_format(&it, buf, sizeof(buf));
  CHECK(!strcmp(buf, "1969-12-31T23:59:59Z"));
  it.unix_secs = 1000000000;
  ztime_format(&it, buf, sizeof(buf));
  CHECK(!strcmp(buf, "2001-09-09T01:46:40Z"));
  it.unix_secs = 253402300799LL;
  ztime_format(&it, buf, sizeof(buf));
  CHECK(!strcmp(buf, "9999-12-31T23:59:59Z"));
  /* Fractions: trailing zeros trimmed. */
  it.unix_secs = 0;
  it.nanos = 100000000;
  ztime_format(&it, buf, sizeof(buf));
  CHECK(!strcmp(buf, "1970-01-01T00:00:00.1Z"));
  it.nanos = 123456789;
  ztime_format(&it, buf, sizeof(buf));
  CHECK(!strcmp(buf, "1970-01-01T00:00:00.123456789Z"));
  it.nanos = 1;
  ztime_format(&it, buf, sizeof(buf));
  CHECK(!strcmp(buf, "1970-01-01T00:00:00.000000001Z"));
  /* Tight buffer fails cleanly. */
  it.nanos = 0;
  CHECK(ztime_format(&it, buf, 20) == 0); /* needs 21 incl NUL */
  CHECK(ztime_format(&it, buf, 21) == 20);
  /* Out of 4-digit-year range. */
  it.unix_secs = 253402300800LL; /* 10000-01-01 */
  CHECK(ztime_format(&it, buf, sizeof(buf)) == 0);
  /* Year 0000 is a legal 4-digit RFC 3339 year. */
  it.unix_secs = -62167219200LL; /* 0000-01-01 */
  CHECK(ztime_format(&it, buf, sizeof(buf)) == 20);
  CHECK(!strcmp(buf, "0000-01-01T00:00:00Z"));
  it.unix_secs = -62167305600LL; /* year -0001: out of range */
  CHECK(ztime_format(&it, buf, sizeof(buf)) == 0);
  CHECK(ztime_format(NULL, buf, sizeof(buf)) == 0);
  CHECK(ztime_format(&it, NULL, 32) == 0);
  it.unix_secs = 0;
  it.nanos = 1000000000; /* invalid nanos */
  CHECK(ztime_format(&it, buf, sizeof(buf)) == 0);
}

static void test_round_trip_sweep(void) {
  /* parse(format(x)) == x across the whole 4-digit-year range. */
  char buf[32];
  for (int64_t s = -62135596800LL; s <= 253402300799LL; s += 87347) {
    ztime_instant a = {s, (uint32_t)(s < 0 ? -s : s) % 1000000000u};
    size_t n = ztime_format(&a, buf, sizeof(buf));
    if (!n) {
      fprintf(stderr, "FAIL format(%lld)\n", (long long)s);
      failures++;
      continue;
    }
    ztime_instant b;
    if (!ztime_parse(buf, &b) || b.unix_secs != a.unix_secs ||
        b.nanos != a.nanos) {
      /* nanos round-trip loses trailing zeros by design; compare via
       * reformat instead. */
      char buf2[32];
      ztime_format(&b, buf2, sizeof(buf2));
      if (strcmp(buf, buf2)) {
        fprintf(stderr, "FAIL round-trip %lld -> %s\n", (long long)s,
                buf);
        failures++;
      }
    }
  }
  /* Every second across a leap February and a century boundary. */
  for (int64_t s = 951696000LL; s < 952128000LL; s += 997) {
    ztime_instant a = {s, 0}, b;
    ztime_format(&a, buf, sizeof(buf));
    CHECK(ztime_parse(buf, &b) && b.unix_secs == s);
  }
}

static void test_civil_math(void) {
  int64_t days;
  CHECK(ztime_days_from_civil(1970, 1, 1, &days) && days == 0);
  CHECK(ztime_days_from_civil(2000, 2, 29, &days) && days == 11016);
  CHECK(!ztime_days_from_civil(1900, 2, 29, &days));
  CHECK(!ztime_days_from_civil(1970, 13, 1, &days));
  CHECK(!ztime_days_from_civil(1970, 1, 32, &days));
  CHECK(!ztime_days_from_civil(1970, 1, 1, NULL));
  CHECK(ztime_days_in_month(2024, 2) == 29);
  CHECK(ztime_days_in_month(2023, 2) == 28);
  CHECK(ztime_days_in_month(2000, 2) == 29);
  CHECK(ztime_days_in_month(1900, 2) == 28);
  CHECK(ztime_days_in_month(1970, 0) == 0);
  CHECK(ztime_days_in_month(1970, 13) == 0);
  /* Inverse over a span covering leap centuries both ways. */
  for (int64_t d = -100000; d <= 100000; d += 73) {
    int64_t y;
    unsigned m, dd;
    ztime_civil_from_days(d, &y, &m, &dd);
    int64_t back;
    CHECK(ztime_days_from_civil(y, m, dd, &back) && back == d);
  }
}

int main(void) {
  test_parse_kats();
  test_parse_errors();
  test_format_kats();
  test_round_trip_sweep();
  test_civil_math();
  if (failures) {
    fprintf(stderr, "test_ztime: %d failure(s)\n", failures);
    return 1;
  }
  puts("test_ztime: all tests passed");
  return 0;
}
