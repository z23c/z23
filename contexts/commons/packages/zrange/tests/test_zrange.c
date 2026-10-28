/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: zrange test suite.  Exits nonzero on the first failure.
 * The caret/tilde expansion tables and prerelease gating are the npm
 * CLI's documented behaviour, transcribed as known-answer tests. */
#include "zrange/zrange.h"

#include <stdio.h>
#include <string.h>

static FILE *cli_source, *cli_sink;
#undef stdin
#define stdin cli_source
#define printf(...) fprintf(cli_sink, __VA_ARGS__)
#define main zrange_cli_main
#include "../app/main.c"
#undef main
#undef printf
#undef stdin

static int failures = 0;

#define CHECK(cond)                                                          \
  do {                                                                       \
    if (!(cond)) {                                                           \
      fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);        \
      failures++;                                                            \
    }                                                                        \
  } while (0)

/* Range r matches version v. */
#define SAT(r, v) CHECK(zrange_test((r), (v)))
#define NSAT(r, v) CHECK(!zrange_test((r), (v)))

/* Range text fails to parse. */
#define BAD(r)                                                                \
  do {                                                                       \
    zrange rr;                                                               \
    CHECK(!zrange_parse((r), &rr));                                          \
  } while (0)

/* Range parses and yields the expected comparator/set counts. */
#define SHAPE(r, nsets, ncomps)                                               \
  do {                                                                       \
    zrange rr;                                                               \
    CHECK(zrange_parse((r), &rr));                                           \
    CHECK(rr.set_count == (nsets));                                          \
    CHECK(rr.comp_count == (ncomps));                                        \
  } while (0)

static void test_explicit_operators(void) {
  SAT("=1.2.3", "1.2.3");
  NSAT("=1.2.3", "1.2.4");
  NSAT("=1.2.3", "1.2.3-rc.1"); /* prerelease gated, see below */
  SAT("1.2.3", "1.2.3"); /* bare version is EQ */
  SAT("<1.2.3", "1.2.2");
  NSAT("<1.2.3", "1.2.3");
  SAT("<=1.2.3", "1.2.3");
  SAT(">1.2.3", "1.2.4");
  NSAT(">1.2.3", "1.2.3");
  SAT(">=1.2.3", "1.2.3");
  SAT(">=1.2.3 <2.0.0", "1.5.0");
  NSAT(">=1.2.3 <2.0.0", "1.2.2");
  NSAT(">=1.2.3 <2.0.0", "2.0.0");
  SAT(">=1.2.3\t<2.0.0", "1.5.0"); /* tab is whitespace too */
}

static void test_caret_expansions(void) {
  /* npm: ^1.2.3 := >=1.2.3 <2.0.0 */
  SHAPE("^1.2.3", 1, 2);
  SAT("^1.2.3", "1.2.3");
  SAT("^1.2.3", "1.9.9");
  NSAT("^1.2.3", "2.0.0");
  NSAT("^1.2.3", "1.2.2");
  /* npm: ^0.2.3 := >=0.2.3 <0.3.0 */
  SAT("^0.2.3", "0.2.3");
  SAT("^0.2.3", "0.2.9");
  NSAT("^0.2.3", "0.3.0");
  /* npm: ^0.0.3 := >=0.0.3 <0.0.4 */
  SAT("^0.0.3", "0.0.3");
  NSAT("^0.0.3", "0.0.4");
  /* npm: ^0.0.0 := >=0.0.0 <0.0.1 (exact) */
  SAT("^0.0.0", "0.0.0");
  NSAT("^0.0.0", "0.0.1");
}

static void test_tilde_expansions(void) {
  /* npm: ~1.2.3 := >=1.2.3 <1.3.0 */
  SHAPE("~1.2.3", 1, 2);
  SAT("~1.2.3", "1.2.3");
  SAT("~1.2.3", "1.2.9");
  NSAT("~1.2.3", "1.3.0");
  NSAT("~1.2.3", "1.2.2");
  SAT("~0.2.3", "0.2.9");
  NSAT("~0.2.3", "0.3.0");
}

static void test_unions(void) {
  SHAPE("<1.2.3 || >=2.0.0 <3.0.0", 2, 3);
  SAT("<1.2.3 || >=2.0.0 <3.0.0", "1.0.0");
  SAT("<1.2.3 || >=2.0.0 <3.0.0", "2.5.0");
  NSAT("<1.2.3 || >=2.0.0 <3.0.0", "1.5.0");
  NSAT("<1.2.3 || >=2.0.0 <3.0.0", "3.0.0");
  SAT("^1.2.3||^2.0.0", "1.9.0");
  SAT("^1.2.3||^2.0.0", "2.3.4");
}

static void test_prerelease_gating(void) {
  /* npm: a prerelease version needs a comparator with the SAME
   * [major,minor,patch] that itself carries a prerelease. */
  NSAT(">=1.2.3 <2.0.0", "1.5.0-beta");
  NSAT(">=1.2.3 <2.0.0", "2.0.0-rc.1");
  SAT(">=1.2.3-rc.1 <2.0.0", "1.2.3-rc.2");
  NSAT(">=1.2.3-rc.1 <2.0.0", "1.5.0-beta"); /* different triple */
  SAT(">=1.2.3-rc.1 <2.0.0", "1.2.3"); /* release is not gated */
  SAT("=1.2.3-rc.1", "1.2.3-rc.1");
  NSAT("=1.2.3-rc.1", "1.2.3-rc.2");
  /* Union: one set gates out, the other admits. */
  SAT(">=1.2.3-rc.1 <2.0.0 || >=2.0.0-rc.1 <3.0.0", "2.0.0-rc.2");
}

static void test_parse_errors(void) {
  BAD(""); /* empty range */
  BAD("   ");
  BAD("|");
  BAD("||");
  BAD("1.2.3 | 2.0.0"); /* single '|' is not union */
  BAD("|| 1.2.3"); /* empty leading set */
  BAD("1.2.3 ||"); /* empty trailing set */
  BAD("1.2.3 || || 2.0.0"); /* empty middle set */
  BAD("1.2.x"); /* wildcards unsupported */
  BAD("*");
  BAD("1.2.3 - 2.0.0"); /* hyphen ranges unsupported */
  BAD("01.2.3"); /* leading-zero version */
  BAD("1.2"); /* partial versions unsupported */
  BAD("^");
  BAD("~");
  BAD(">=");
  BAD("<= 1.2.3"); /* operator must attach to the version */
  SHAPE("1.2.3", 1, 1);
  BAD(NULL); /* NULL input */
  {
    zrange rr;
    CHECK(!zrange_parse_n(NULL, 5, &rr));
    CHECK(!zrange_parse_n("1.2.3", 5, NULL));
  }
}

static void test_bounds(void) {
  /* 17 comparators overflow ZRANGE_MAX_COMPARATORS(16). */
  {
    char buf[256];
    size_t n = 0;
    for (int i = 0; i < 17; i++)
      n += (size_t)snprintf(buf + n, sizeof(buf) - n, ">=1.0.%d ", i);
    zrange rr;
    CHECK(!zrange_parse(buf, &rr));
  }
  /* 5 sets overflow ZRANGE_MAX_SETS(4). */
  BAD("1.0.0 || 1.0.1 || 1.0.2 || 1.0.3 || 1.0.4");
  SHAPE("1.0.0 || 1.0.1 || 1.0.2 || 1.0.3", 4, 4);
  /* Failed parse zeroes the output struct. */
  {
    zrange rr;
    memset(&rr, 0xAA, sizeof(rr));
    CHECK(!zrange_parse("1.2.x", &rr));
    CHECK(rr.set_count == 0 && rr.comp_count == 0);
  }
  /* ^/~ overflow at the version ceiling fails closed. */
  BAD("^18446744073709551615.0.0");
  BAD("^0.18446744073709551615.0");
  BAD("^0.0.18446744073709551615");
  BAD("~1.18446744073709551615.0");
}

static void test_satisfies_edge_args(void) {
  CHECK(!zrange_satisfies(NULL, NULL));
  zrange rr;
  zsemver v;
  CHECK(zrange_parse("^1.2.3", &rr));
  CHECK(zsemver_parse("1.5.0", &v));
  CHECK(zrange_satisfies(&rr, &v));
  CHECK(!zrange_satisfies(&rr, NULL));
  CHECK(!zrange_satisfies(NULL, &v));
  /* Zeroed range has no sets and satisfies nothing. */
  memset(&rr, 0, sizeof(rr));
  CHECK(!zrange_satisfies(&rr, &v));
  /* parse_n honours explicit lengths (no NUL required). */
  const char *embed = "xx^1.2.3yy";
  CHECK(zrange_parse_n(embed + 2, 6, &rr));
  CHECK(rr.set_count == 1 && rr.comp_count == 2);
}

static void test_expansion_order_and_failure_clear(void) {
  zrange parsed;
  const unsigned char zero[sizeof(zrange)] = {0};
  CHECK(zrange_parse("^1.2.3-rc.1 || ~0.2.3", &parsed));
  CHECK(parsed.set_count == 2 && parsed.comp_count == 4);
  CHECK(parsed.sets[0].start == 0 && parsed.sets[0].count == 2);
  CHECK(parsed.sets[1].start == 2 && parsed.sets[1].count == 2);
  CHECK(parsed.comps[0].op == ZRANGE_GE && parsed.comps[0].version.prerelease);
  CHECK(parsed.comps[1].op == ZRANGE_LT && parsed.comps[1].version.major == 2);
  CHECK(parsed.comps[2].op == ZRANGE_GE && parsed.comps[2].version.minor == 2);
  CHECK(parsed.comps[3].op == ZRANGE_LT && parsed.comps[3].version.minor == 3);
  memset(&parsed, 0xA5, sizeof parsed);
  CHECK(!zrange_parse("1.2.3 || ^0.0.18446744073709551615", &parsed));
  CHECK(memcmp(&parsed, zero, sizeof parsed) == 0);
}

static void test_null_wrapper_state(void) {
  zrange parsed;
  const unsigned char zero[sizeof(zrange)] = {0};
  memset(&parsed, 0xA5, sizeof parsed);
  CHECK(!zrange_parse(NULL, &parsed) && memcmp(&parsed, zero, sizeof parsed) == 0);
}

static bool cli_result(FILE *source, FILE *output, int status, const char *want) {
  cli_source = source;
  cli_sink = output;
  char *args[] = {"zrange", "=1.2.3", NULL};
  if (zrange_cli_main(2, args) != status) return false;
  rewind(output);
  char bytes[32];
  size_t n = fread(bytes, 1, sizeof bytes, output);
  return !ferror(output) && n == strlen(want) && memcmp(bytes, want, n) == 0;
}

static bool cli_padding(FILE *source, size_t count) {
  char bytes[4096];
  memset(bytes, '\n', sizeof bytes);
  while (count) {
    size_t n = count < sizeof bytes ? count : sizeof bytes;
    if (fwrite(bytes, 1, n, source) != n) return false;
    count -= n;
  }
  return true;
}

static bool cli_payload(FILE *source, size_t length, const char *version, bool tail) {
  size_t n = strlen(version);
  if (length < n) return false;
  if (tail)
    return cli_padding(source, length - n) && fputs(version, source) >= 0;
  return fputs(version, source) >= 0 && cli_padding(source, length - n);
}

static int cli_bound_case(size_t length, const char *prefix, int status, bool tail) {
  FILE *source = tmpfile(), *output = tmpfile();
  int bad = 1;
  if (!source || !output) goto cleanup;
  if (!cli_payload(source, length, prefix, tail) ||
      fflush(source) != 0) goto cleanup;
  rewind(source);
  if (!cli_result(source, output, status, status == 0 ? "1.2.3\n" : "")) goto cleanup;
  bad = 0;
cleanup:
  if (source && fclose(source) != 0) bad = 1;
  if (output && fclose(output) != 0) bad = 1;
  return bad;
}

static void test_cli_bound(void) {
  CHECK(cli_bound_case(MAX_INPUT - 1, "1.2.3\n", 0, false) == 0);
  CHECK(cli_bound_case(MAX_INPUT, "1.2.3\n", 0, false) == 0);
  CHECK(cli_bound_case(MAX_INPUT + 1, "1.2.3\n", 2, false) == 0);
  CHECK(cli_bound_case(MAX_INPUT, "2.0.0\n", 1, false) == 0);
  CHECK(cli_bound_case(MAX_INPUT, "1.2.3", 0, true) == 0);
  CHECK(cli_bound_case(6, "1.2.3\n", 0, false) == 0);
  CHECK(cli_bound_case(5, "1.2.3", 0, false) == 0);
#if defined(_WIN32)
  FILE *source = fopen("NUL", "w");
#else
  FILE *source = fopen("/dev/null", "w");
#endif
  FILE *output = tmpfile();
  if (source && output) {
    CHECK(cli_result(source, output, 2, ""));
    CHECK(ferror(source));
  } else CHECK(false);
  if (source) CHECK(fclose(source) == 0);
  if (output) CHECK(fclose(output) == 0);
}

int main(void) {
  test_cli_bound();
  test_null_wrapper_state();
  test_expansion_order_and_failure_clear();
  test_explicit_operators();
  test_caret_expansions();
  test_tilde_expansions();
  test_unions();
  test_prerelease_gating();
  test_parse_errors();
  test_bounds();
  test_satisfies_edge_args();
  if (failures) {
    fprintf(stderr, "test_zrange: %d failure(s)\n", failures);
    return 1;
  }
  puts("test_zrange: all tests passed");
  return 0;
}
