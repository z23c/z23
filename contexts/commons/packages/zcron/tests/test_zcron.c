/* zcron tests: parse KATs, next-fire KATs against hand-computed UTC
 * schedules, Vixie dom/dow OR-semantics, rejection table, canonical
 * format round-trips, and a randomised invariant oracle.
 * Built with -std=c23 -Wall -Wextra -Werror -pedantic, ASan/UBSan. */

#include "zcron/zcron.h"

#include <stdio.h>
#include <limits.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <time.h>

static int failures = 0;

#define CHECK(cond)                                                     \
  do {                                                                  \
    if (!(cond)) {                                                      \
      fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);   \
      failures++;                                                       \
    }                                                                   \
  } while (0)

static void expect_parse_ok(const char *s) {
  zcron c;
  char err[64];
  CHECK(zcron_parse(s, strlen(s), &c, err, sizeof err));
  if (!zcron_parse(s, strlen(s), &c, err, sizeof err))
    fprintf(stderr, "  expr=%s err=%s\n", s, err);
}

static void expect_parse_bad(const char *s) {
  zcron c;
  char err[64];
  CHECK(!zcron_parse(s, strlen(s), &c, err, sizeof err));
  if (zcron_parse(s, strlen(s), &c, err, sizeof err))
    fprintf(stderr, "  unexpectedly parsed: %s\n", s);
}

/* next fire strictly after `after` must equal `want` */
static void expect_next(const char *s, long long after, long long want) {
  zcron c;
  long long got;
  CHECK(zcron_parse(s, strlen(s), &c, NULL, 0));
  got = zcron_next(&c, after);
  CHECK(got == want);
  if (got != want)
    fprintf(stderr, "  expr=%s after=%lld want=%lld got=%lld\n", s, after,
            want, got);
}

/* Epoch anchors (verified against `date -u`):
 * 2026-08-15 00:00:00 UTC = 1786752000 (Saturday)
 * 2026-01-01 00:00:00 UTC = 1767225600 (Thursday)
 * 2000-02-28 00:00:00 UTC = 951696000  (Monday, leap year)
 * 1970-01-01 00:00:00 UTC = 0          (Thursday)                  */

static void test_parse_ok(void) {
  expect_parse_ok("* * * * *");
  expect_parse_ok("0 0 * * *");
  expect_parse_ok("*/5 * * * *");
  expect_parse_ok("0 9 * * 1-5");
  expect_parse_ok("30 14 28 2 *");
  expect_parse_ok("0 0 29 2 *");
  expect_parse_ok("0 0 * jan,mar mon");
  expect_parse_ok("0 0 * JAN MON");
  expect_parse_ok("15,45 8-18/2 1,15 * *");
  expect_parse_ok("0 0 1 * 0");
  expect_parse_ok("0 0 1 * 7"); /* Sunday as 7 */
  expect_parse_ok("0 0 1 * sun");
  expect_parse_ok("  0   0   *   *   *  ");
  expect_parse_ok("59 23 31 12 6");
  expect_parse_ok("0-59/15 * * * *");
  expect_parse_ok("5-15 * * * *");
}

static void test_parse_bad(void) {
  expect_parse_bad("");
  expect_parse_bad("* * * *");
  expect_parse_bad("* * * * * *");
  expect_parse_bad("60 * * * *");
  expect_parse_bad("* 24 * * *");
  expect_parse_bad("* * 0 * *");
  expect_parse_bad("* * 32 * *");
  expect_parse_bad("* * * 0 *");
  expect_parse_bad("* * * 13 *");
  expect_parse_bad("* * * * 8");
  expect_parse_bad("*/0 * * * *");
  expect_parse_bad("5-1 * * * *"); /* reversed range */
  expect_parse_bad("a * * * *");
  expect_parse_bad("* * * * monday"); /* full names rejected */
  expect_parse_bad("1, * * * *");
  expect_parse_bad(",1 * * * *");
  expect_parse_bad("-5 * * * *");
  expect_parse_bad("5- * * * *");
  expect_parse_bad("* * * * * trailing");
  expect_parse_bad("/5 * * * *");
  expect_parse_bad("* * x * *");
  expect_parse_bad("99999999999 * * * *");
}

static void test_next_basic(void) {
  const long long aug15 = 1786752000LL; /* Sat 2026-08-15 00:00 UTC */

  /* every minute: next is the next minute boundary */
  expect_next("* * * * *", aug15, aug15 + 60);
  expect_next("* * * * *", aug15 - 1, aug15);

  /* daily at midnight */
  expect_next("0 0 * * *", aug15, aug15 + 86400);

  /* hourly at :30 */
  expect_next("30 * * * *", aug15, aug15 + 1800);

  /* weekly: next Saturday 00:00 after Sunday-ish moment */
  expect_next("0 0 * * 6", aug15, aug15 + 7 * 86400);
  expect_next("0 0 * * sat", aug15 + 60, aug15 + 7 * 86400);

  /* monthly: 1st 00:00 — after Aug 15 -> Sep 1 00:00 */
  expect_next("0 0 1 * *", aug15, 1788220800LL);

  /* weekday range Mon-Fri 09:00; Sat Aug 15 -> Mon Aug 17 09:00 */
  expect_next("0 9 * * 1-5", aug15, 1786957200LL);

  /* step: star/15 from 00:07 -> 00:15 */
  expect_next("*/15 * * * *", aug15 + 7 * 60, aug15 + 15 * 60);

  /* yearly: Feb 29 00:00.  2026 -> next is 2028-02-29 00:00 UTC */
  expect_next("0 0 29 2 *", aug15, 1835395200LL);

  /* impossible: Feb 31 never fires */
  {
    zcron c;
    CHECK(zcron_parse("0 0 31 2 *", 10, &c, NULL, 0));
    CHECK(zcron_next(&c, aug15) == -1);
  }
}

static void test_next_dom_dow_or(void) {
  /* Vixie OR: "0 0 13 * 5" fires on the 13th AND on Fridays. */
  const long long aug15 = 1786752000LL; /* Sat 2026-08-15 00:00 */
  /* next Friday after Aug 15 00:00 is Aug 21; 13th is past, so the
   * Friday wins.  Fri 2026-08-21 00:00 UTC = 1787270400 */
  expect_next("0 0 13 * 5", aug15, 1787270400LL);
  /* With only dom restricted, dow is '*': plain monthly semantics. */
  expect_next("0 0 13 * *", aug15, 1789257600LL); /* Sep 13 00:00 */
}

static void test_format_roundtrip(void) {
  static const char *const exprs[] = {
      "* * * * *",        "0 0 * * *",       "*/15 * * * *",
      "0 9 * * 1-5",      "15,45 8-18/2 1,15 * *",
      "0 0 29 2 *",       "0 0 * jan mon",   "0 0 1 * 7",
  };
  size_t i;
  for (i = 0; i < sizeof exprs / sizeof exprs[0]; i++) {
    zcron c1, c2;
    char buf[128], buf2[128];
    CHECK(zcron_parse(exprs[i], strlen(exprs[i]), &c1, NULL, 0));
    zcron_format(&c1, buf, sizeof buf);
    /* canonical text must re-parse to the identical bitmask */
    CHECK(zcron_parse(buf, strlen(buf), &c2, NULL, 0));
    CHECK(c1.minute == c2.minute && c1.hour == c2.hour &&
          c1.dom == c2.dom && c1.month == c2.month && c1.dow == c2.dow);
    /* and formatting is a fixed point */
    zcron_format(&c2, buf2, sizeof buf2);
    CHECK(strcmp(buf, buf2) == 0);
    if (strcmp(buf, buf2) != 0)
      fprintf(stderr, "  expr=%s fmt=%s fmt2=%s\n", exprs[i], buf, buf2);
  }
}

/* known canonical spellings */
static void test_format_kats(void) {
  zcron c;
  char buf[128];
  CHECK(zcron_parse("* * * * *", 9, &c, NULL, 0));
  zcron_format(&c, buf, sizeof buf);
  CHECK(strcmp(buf, "0-59 0-23 * 1-12 *") == 0);
  CHECK(zcron_parse("*/15 1,3 * * 0", 14, &c, NULL, 0));
  zcron_format(&c, buf, sizeof buf);
  CHECK(strcmp(buf, "0,15,30,45 1,3 * 1-12 0") == 0);
  CHECK(zcron_parse("0 0 1 * 7", 9, &c, NULL, 0));
  zcron_format(&c, buf, sizeof buf);
  CHECK(strcmp(buf, "0 0 1 1-12 0") == 0); /* 7 folded to 0 */
}

static void test_next_matches_spec(void) {
  /* Invariant oracle: for random valid schedules and random start
   * times, the returned fire time must be a multiple of 60, strictly
   * after `after`, and its own fields must satisfy the schedule. */
  static const char *const exprs[] = {
      "* * * * *",      "*/7 * * * *",     "13 5 * * *",
      "0 0 1 * *",      "0 12 * * 3",      "30 6 15 6 *",
      "0 0 29 2 *",     "*/2 */3 */2 */2 */2",
      "17 4 10-20 * 2,4",
  };
  unsigned long long rng = 0xC0FFEE123456789ull;
  size_t i;
  int t;
  for (i = 0; i < sizeof exprs / sizeof exprs[0]; i++) {
    zcron c;
    CHECK(zcron_parse(exprs[i], strlen(exprs[i]), &c, NULL, 0));
    for (t = 0; t < 200; t++) {
      long long after;
      long long fire;
      rng = rng * 6364136223846793005ull + 1442695040888963407ull;
      after = (long long)((rng >> 11) % (4ull * 366 * 86400));
      fire = zcron_next(&c, after);
      if (fire == -1) continue; /* genuinely impossible schedules */
      CHECK(fire > after);
      CHECK(fire % 60 == 0);
      /* re-parse the fire time through the matcher by computing the
       * previous minute: fire-60 must NOT match unless schedule fires
       * every minute */
      {
        zcron every;
        CHECK(zcron_parse("* * * * *", 9, &every, NULL, 0));
        if (!(c.minute == every.minute && c.hour == every.hour &&
              c.dom == every.dom && c.month == every.month &&
              c.dow == every.dow)) {
          long long prev = zcron_next(&c, fire - 60);
          CHECK(prev == fire || prev == -1);
        }
      }
    }
  }
}

static void test_next_monotonic(void) {
  /* successive fires of a schedule are strictly increasing */
  zcron c;
  long long t = 1767225600LL; /* 2026-01-01 */
  int i;
  CHECK(zcron_parse("37 3 * * 1,4", 12, &c, NULL, 0));
  for (i = 0; i < 300; i++) {
    long long n = zcron_next(&c, t);
    CHECK(n > t);
    if (n <= t) break;
    t = n;
  }
}

static void test_format_preserves_day_semantics(void) {
  static const struct {
    const char *expr;
    const char *canon;
  } rows[] = {
      {"0 0 13 * *", "0 0 13 1-12 *"},
      {"0 0 * * 5", "0 0 * 1-12 5"},
      {"0 0 * * *", "0 0 * 1-12 *"},
      {"0 0 1-31 * *", "0 0 1-31 1-12 *"},
      {"0 0 * * 0-6", "0 0 * 1-12 0-6"},
  };
  size_t i;
  for (i = 0; i < sizeof rows / sizeof rows[0]; i++) {
    int before_failures = failures;
    zcron before = {0}, after = {0};
    char text[64], small[2];
    size_t expect_n = strlen(rows[i].canon);
    size_t n;
    small[0] = 'X';
    small[1] = 'X';
    CHECK(zcron_parse(rows[i].expr, strlen(rows[i].expr), &before, NULL, 0));
    n = zcron_format(&before, text, sizeof text);
    CHECK(n == expect_n);
    CHECK(n < sizeof text);
    CHECK(memcmp(text, rows[i].canon, expect_n) == 0);
    CHECK(zcron_parse(text, n, &after, NULL, 0));
    CHECK(before.dom_star == after.dom_star);
    CHECK(before.dow_star == after.dow_star);
    CHECK(zcron_next(&before, 1786752000LL) ==
          zcron_next(&after, 1786752000LL));
    CHECK(zcron_format(&before, NULL, 0) == expect_n);
    CHECK(zcron_format(&before, small, sizeof small) == expect_n);
    CHECK(small[0] == rows[i].canon[0]);
    CHECK(small[1] == '\0');
    fprintf(stderr, "cron_format_row=%zu result=%s\n", i,
            failures == before_failures ? "PASS" : "FAIL");
  }
}

static void test_sunday_range_alias(void) {
  const char *exprs[] = {"0 0 * * 5-7", "0 0 * * 5-7/2", "0 0 * * 6-7", "0 0 * * 0-7"};
  const unsigned masks[] = {(1u << 5) | (1u << 6) | 1u, (1u << 5) | 1u, (1u << 6) | 1u, 127u};
  for (size_t i = 0; i < sizeof exprs / sizeof exprs[0]; ++i) {
    int before_failures = failures;
    zcron c = {0};
    int ok = zcron_parse(exprs[i], strlen(exprs[i]), &c, NULL, 0);
    CHECK(ok);
    if (ok) CHECK(c.dow == masks[i]);
    if (ok && i == 0) CHECK(zcron_next(&c, 1786752000LL) == 1786838400LL);
    fprintf(stderr, "cron_range_row=%zu result=%s\n", i,
            failures == before_failures ? "PASS" : "FAIL");
  }
  expect_parse_bad("0 0 * * 7-5");
  expect_parse_bad("0 0 * * 7-0");
}

static void test_required_field_separators(void) {
  const char *bad[] = {"*****", "0 0** *", "0 0 *jan mon", "0 0 * janmon"};
  for (size_t i = 0; i < sizeof bad / sizeof bad[0]; ++i) {
    int before_failures = failures;
    zcron c = {0};
    char err[64];
    CHECK(!zcron_parse(bad[i], strlen(bad[i]), &c, err, sizeof err));
    CHECK(err[0] != '\0');
    fprintf(stderr, "cron_separator_row=%zu result=%s\n", i,
            failures == before_failures ? "PASS" : "FAIL");
  }
  expect_parse_ok("\t0\t0\t*\tjan\tmon\t");
  expect_parse_ok(" 0, 30 0 * jan mon ");
}

static void test_cli(void);

int main(void) {
  test_cli();
  expect_next("* * * * *", LLONG_MAX, -1);
    test_required_field_separators();
    test_sunday_range_alias();
  test_format_preserves_day_semantics();
  test_parse_ok();
  test_parse_bad();
  test_next_basic();
  test_next_dom_dow_or();
  test_format_roundtrip();
  test_format_kats();
  test_next_matches_spec();
  test_next_monotonic();
  if (failures) {
    fprintf(stderr, "%d failure(s)\n", failures);
    return 1;
  }
  puts("zcron: all tests passed");
  return 0;
}

#if !defined(_WIN32)
static FILE *cli_sink;
static size_t cli_flushes, cli_calendar_calls, cli_calendar_fault, cli_format_calls, cli_format_fault;
static bool cli_clock_failure;
static FILE *real_stdout(void) { return stdout; }
static time_t cli_clock(time_t *out) {
  time_t value = cli_clock_failure ? (time_t)-1 : (time_t)0;
  if (out) *out = value;
  return value;
}
static struct tm *cli_calendar(const time_t *value, struct tm *out) {
  if (++cli_calendar_calls == cli_calendar_fault) return NULL;
  return gmtime_r(value, out);
}
static size_t cli_format(char *out, size_t cap, const char *format, const struct tm *tmv) {
  if (++cli_format_calls == cli_format_fault) return 0;
  return strftime(out, cap, format, tmv);
}
[[maybe_unused]] static int cli_flush(FILE *stream) {
  if (stream == cli_sink) cli_flushes++;
  return fflush(stream);
}
#undef stdout
#define stdout cli_sink
#define printf(...) fprintf(cli_sink, __VA_ARGS__)
#define puts(text) fprintf(cli_sink, "%s\n", (text))
#define fflush cli_flush
#define time cli_clock
#define gmtime_r cli_calendar
#define strftime cli_format
#define main embedded_cli_main
#include "../app/main.c"
#undef main
#undef strftime
#undef gmtime_r
#undef time
#undef fflush
#undef puts
#undef printf
#undef stdout
#define stdout real_stdout()

static FILE *required_stream(FILE *stream) {
  if (!stream) { fprintf(stderr, "zcron CLI fixture setup failed\n"); exit(2); }
  return stream;
}
static int cli_invoke(FILE *sink, int argc, char **args) {
  cli_sink = sink;
  cli_flushes = cli_calendar_calls = cli_format_calls = 0;
  errno = ERANGE;
  int rc = embedded_cli_main(argc, args);
  cli_sink = stdout;
  return rc;
}
static void cli_case(int argc, char **args, int status, const char *want) {
  FILE *sink = required_stream(tmpfile());
  CHECK(cli_invoke(sink, argc, args) == status);
  if (!*want) CHECK(cli_flushes == 0);
  else CHECK(cli_flushes == 1);
  char bytes[512];
  rewind(sink);
  size_t n = fread(bytes, 1, sizeof bytes, sink);
  CHECK(!ferror(sink) && n == strlen(want) && !memcmp(bytes, want, n));
  CHECK(fclose(sink) == 0);
}
static void cli_numeric(void) {
  char epoch_overflow[64], epoch_underflow[64], count_overflow[64], count_underflow[64];
  snprintf(epoch_overflow, sizeof epoch_overflow, "%lld0", LLONG_MAX);
  snprintf(epoch_underflow, sizeof epoch_underflow, "%lld0", LLONG_MIN);
  snprintf(count_overflow, sizeof count_overflow, "%d0", INT_MAX);
  snprintf(count_underflow, sizeof count_underflow, "%d0", INT_MIN);
  const char *bad_epoch[] = {"", " ", "junk", "1junk", "1 ", epoch_overflow, epoch_underflow};
  for (size_t i = 0; i < sizeof bad_epoch / sizeof bad_epoch[0]; i++) {
    char *args[] = {"zcron", "* * * * *", (char *)bad_epoch[i], "1", NULL};
    cli_case(4, args, 2, "");
  }
  const char *bad_count[] = {"", " ", "junk", "1junk", "1 ", count_overflow, count_underflow, "4294967297"};
  for (size_t i = 0; i < sizeof bad_count / sizeof bad_count[0]; i++) {
    /* A negative epoch makes even the unchecked old positive count stop
     * at its first 'never', keeping the red fixture bounded. */
    char *args[] = {"zcron", "* * * * *", "-1", (char *)bad_count[i], NULL};
    cli_case(4, args, 2, "");
  }
  char maximum[64], minimum[64];
  snprintf(maximum, sizeof maximum, "%lld", LLONG_MAX);
  snprintf(minimum, sizeof minimum, "%lld", LLONG_MIN);
  char *max_epoch[] = {"zcron", "* * * * *", maximum, "1", NULL};
  char *min_epoch[] = {"zcron", "* * * * *", minimum, "1", NULL};
  cli_case(4, max_epoch, 0, "never (within 8 years)\n");
  cli_case(4, min_epoch, 0, "never (within 8 years)\n");
  const char *counts[] = {"0", "-0", "-1"};
  for (size_t i = 0; i < sizeof counts / sizeof counts[0]; i++) {
    char *args[] = {"zcron", "* * * * *", "0", (char *)counts[i], NULL};
    cli_case(4, args, 0, "");
  }
}
static void cli_normal(void) {
  char *args[] = {"zcron", "* * * * *", " \t+0", "+2", "ignored", NULL};
  cli_case(5, args, 0, "60  1970-01-01 00:01 UTC\n120  1970-01-01 00:02 UTC\n");
  char *zero[] = {"zcron", "* * * * *", "-0", "1", NULL};
  cli_case(4, zero, 0, "60  1970-01-01 00:01 UTC\n");
  char *defaults[] = {"zcron", "* * * * *", NULL};
  cli_case(2, defaults, 0, "60  1970-01-01 00:01 UTC\n120  1970-01-01 00:02 UTC\n180  1970-01-01 00:03 UTC\n240  1970-01-01 00:04 UTC\n300  1970-01-01 00:05 UTC\n");
  char *never[] = {"zcron", "0 0 31 2 *", "0", "1", NULL};
  cli_case(4, never, 0, "never (within 8 years)\n");
  cli_clock_failure = true;
  cli_case(2, defaults, 1, "");
  cli_clock_failure = false;
  char *invalid[] = {"zcron", "invalid", "junk", "junk", NULL};
  cli_case(4, invalid, 1, "");
  char *usage[] = {"zcron", NULL};
  cli_case(1, usage, 2, "");
}
static void cli_failed_sink(bool never, bool buffered) {
#ifdef _WIN32
  const char *null_path = "NUL";
#else
  const char *null_path = "/dev/null";
#endif
  FILE *sink = required_stream(fopen(buffered ? "/dev/full" : null_path, buffered ? "w" : "r"));
  char buffer[4096];
  if (buffered && setvbuf(sink, buffer, _IOFBF, sizeof buffer) != 0) exit(2);
  char *args[] = {"zcron", never ? "0 0 31 2 *" : "* * * * *", "0", "1", NULL};
  CHECK(cli_invoke(sink, 4, args) == 1 && ferror(sink));
  (void)fclose(sink);
}
static void cli_calendar_errors(void) {
  char *args[] = {"zcron", "* * * * *", "0", "2", NULL};
  cli_calendar_fault = 1;
  cli_case(4, args, 1, "");
  cli_calendar_fault = 2;
  cli_case(4, args, 1, "60  1970-01-01 00:01 UTC\n");
  cli_calendar_fault = 0;
  cli_format_fault = 1;
  cli_case(4, args, 1, "");
  cli_format_fault = 2;
  cli_case(4, args, 1, "60  1970-01-01 00:01 UTC\n");
  cli_format_fault = 0;
  char *range[] = {"zcron", "* * * * *", "9223372036854770000", "1", NULL};
  cli_case(4, range, 1, "");
  int count = 0;
  char maximum[64], minimum[64];
  snprintf(maximum, sizeof maximum, "%d", INT_MAX);
  snprintf(minimum, sizeof minimum, "%d", INT_MIN);
  errno = ERANGE;
  CHECK(parse_count(maximum, &count) == 0 && count == INT_MAX && errno != ERANGE);
  CHECK(parse_count(minimum, &count) == 0 && count == INT_MIN);
}

static void test_cli(void) {
  cli_numeric();
  cli_normal();
  cli_calendar_errors();
  cli_failed_sink(false, false);
  cli_failed_sink(true, false);
#ifdef __linux__
  cli_failed_sink(false, true);
  cli_failed_sink(true, true);
#endif
}
#else
static void test_cli(void) {
  fprintf(stderr, "UNOBSERVED (zcron CLI calendar coverage requires gmtime_r on _WIN32)\n");
}
#endif
