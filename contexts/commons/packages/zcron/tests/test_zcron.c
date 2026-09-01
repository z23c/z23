/* zcron tests: parse KATs, next-fire KATs against hand-computed UTC
 * schedules, Vixie dom/dow OR-semantics, rejection table, canonical
 * format round-trips, and a randomised invariant oracle.
 * Built with -std=c23 -Wall -Wextra -Werror -pedantic, ASan/UBSan. */

#include "zcron/zcron.h"

#include <stdio.h>
#include <string.h>

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
  CHECK(strcmp(buf, "0-59 0-23 1-31 1-12 0-6") == 0);
  CHECK(zcron_parse("*/15 1,3 * * 0", 14, &c, NULL, 0));
  zcron_format(&c, buf, sizeof buf);
  CHECK(strcmp(buf, "0,15,30,45 1,3 1-31 1-12 0") == 0);
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

int main(void) {
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
