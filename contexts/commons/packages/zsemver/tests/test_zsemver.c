/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: zsemver test suite.  Exits nonzero on the first failure. */
#include "zsemver/zsemver.h"

#include <stdio.h>
#include <string.h>

static FILE *cli_source, *cli_sink;
static unsigned cli_output_flushes;
static int cli_fflush(FILE *stream) {
  if (stream == cli_sink) cli_output_flushes++;
  return fflush(stream);
}
#undef stdin
#undef stdout
#define stdin cli_source
#define stdout cli_sink
#define printf(...) fprintf(cli_sink, __VA_ARGS__)
#define fflush cli_fflush
#define main zsemver_cli_main
#include "../app/main.c"
#undef main
#undef printf
#undef fflush
#undef stdout
#undef stdin

static int failures = 0;

#define CHECK(cond)                                                          \
  do {                                                                       \
    if (!(cond)) {                                                           \
      fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);        \
      failures++;                                                            \
    }                                                                        \
  } while (0)

static bool parses(const char *s) {
  zsemver v;
  return zsemver_parse(s, &v);
}

static void test_valid_grammar(void) {
  zsemver v;
  CHECK(parses("0.0.0"));
  CHECK(parses("1.2.3"));
  CHECK(parses("10.20.30"));
  CHECK(parses("1.0.0-alpha"));
  CHECK(parses("1.0.0-alpha.1"));
  CHECK(parses("1.0.0-0.3.7"));
  CHECK(parses("1.0.0-x-y-z.-"));
  CHECK(parses("1.0.0+build.42"));
  CHECK(parses("1.0.0-rc.1+build.5"));
  CHECK(parses("1.0.0+0build.leading-zeros-ok.009"));

  CHECK(zsemver_parse("18446744073709551615.0.0", &v));
  CHECK(v.major == UINT64_MAX);

  CHECK(!parses("1.2.3-alpha+b+c")); /* '+' is not an identifier char */
}

static void test_invalid_grammar(void) {
  CHECK(!parses(""));
  CHECK(!parses("1"));
  CHECK(!parses("1.2"));
  CHECK(!parses("1.2."));
  CHECK(!parses("1.2.3."));
  CHECK(!parses("01.2.3"));   /* leading zero major */
  CHECK(!parses("1.02.3"));   /* leading zero minor */
  CHECK(!parses("1.2.03"));   /* leading zero patch */
  CHECK(!parses("v1.2.3"));   /* no v prefix in strict semver */
  CHECK(!parses("1.2.3-"));   /* empty prerelease */
  CHECK(!parses("1.2.3-01")); /* numeric prerelease leading zero */
  CHECK(!parses("1.2.3-a..b"));
  CHECK(!parses("1.2.3-a.b."));
  CHECK(!parses("1.2.3+"));     /* empty build */
  CHECK(!parses("1.2.3+b..c"));
  CHECK(!parses("1.2.3-alpha x"));
  CHECK(!parses("1.2.3-alpha+build x"));
  CHECK(!parses("18446744073709551616.0.0")); /* overflow */
  CHECK(!parses("1.2.3-α"));                /* non-ASCII identifier */
  CHECK(!parses(nullptr));
  {
    zsemver v;
    CHECK(!zsemver_parse_n(nullptr, 5, &v));
    CHECK(!zsemver_parse_n("1.2.3", 0, &v));
  }
}

/* The semver.org item-11 ordering example must sort strictly ascending. */
static void test_precedence_spec_chain(void) {
  static const char *const chain[] = {
      "1.0.0-alpha", "1.0.0-alpha.1", "1.0.0-alpha.beta", "1.0.0-beta",
      "1.0.0-beta.2", "1.0.0-beta.11", "1.0.0-rc.1",     "1.0.0",
  };
  for (size_t i = 0; i + 1 < sizeof(chain) / sizeof(chain[0]); i++) {
    zsemver a, b;
    CHECK(zsemver_parse(chain[i], &a));
    CHECK(zsemver_parse(chain[i + 1], &b));
    if (zsemver_compare(&a, &b) != -1)
      fprintf(stderr, "chain: %s !< %s\n", chain[i], chain[i + 1]);
    CHECK(zsemver_compare(&a, &b) == -1);
    CHECK(zsemver_compare(&b, &a) == 1);
    CHECK(zsemver_compare(&a, &a) == 0);
  }
}

static void test_precedence_edges(void) {
  zsemver a, b;
  CHECK(zsemver_parse("1.0.0+build.1", &a));
  CHECK(zsemver_parse("1.0.0+build.2", &b));
  CHECK(zsemver_compare(&a, &b) == 0); /* build metadata ignored */

  CHECK(zsemver_parse("2.0.0", &a));
  CHECK(zsemver_parse("10.0.0", &b));
  CHECK(zsemver_compare(&a, &b) == -1); /* numeric, not lexical */

  CHECK(zsemver_parse("1.0.0-2", &a));
  CHECK(zsemver_parse("1.0.0-10", &b));
  CHECK(zsemver_compare(&a, &b) == -1); /* numeric identifiers by value */

  CHECK(zsemver_parse("1.0.0-9", &a));
  CHECK(zsemver_parse("1.0.0-a", &b));
  CHECK(zsemver_compare(&a, &b) == -1); /* numeric < alphanumeric */

  CHECK(zsemver_parse("1.0.0-rc.1", &a));
  CHECK(zsemver_parse("1.0.0", &b));
  CHECK(zsemver_compare(&a, &b) == -1); /* prerelease < release */

  CHECK(zsemver_parse("1.0.0", &a));
  CHECK(zsemver_parse("1.0.0", &b));
  CHECK(zsemver_compare(&a, &b) == 0);

  CHECK(zsemver_compare(nullptr, &a) == 0); /* NULL tolerance */
}

static void test_borrowed_fields(void) {
  const char *input = "1.22.333-rc.9+meta";
  zsemver v;
  CHECK(zsemver_parse(input, &v));
  CHECK(v.major == 1 && v.minor == 22 && v.patch == 333);
  CHECK(v.prerelease == input + 9); /* borrows the input */
  CHECK(v.prerelease_len == 4);
  CHECK(memcmp(v.prerelease, "rc.9", 4) == 0);
  CHECK(v.build != nullptr && v.build_len == 4);
  CHECK(memcmp(v.build, "meta", 4) == 0);
}

static bool semver_fields_zero(const zsemver *v) {
  return v->major == 0 && v->minor == 0 && v->patch == 0 &&
         v->prerelease == NULL && v->prerelease_len == 0 &&
         v->build == NULL && v->build_len == 0;
}

static void test_failed_parse_zeroes(void) {
  static const char *const bad[] = {
    NULL, "1", "1.2", "1.2.3-", "1.2.3-01", "1.2.3-alpha+",
    "1.2.3-alpha+b..c", "1.2.3!", "1.18446744073709551616.0",
  };
  for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
    zsemver v;
    memset(&v, 0xAA, sizeof(v));
    bool ok = bad[i] ? zsemver_parse_n(bad[i], strlen(bad[i]), &v)
                     : zsemver_parse(NULL, &v);
    bool zero = semver_fields_zero(&v);
    CHECK(!ok && zero);
    fprintf(stderr, "semver_zero_row=%zu result=%s\n", i,
            !ok && zero ? "PASS" : "FAIL");
  }
}


static bool cli_equal(FILE *a, FILE *b) {
  rewind(a); rewind(b);
  for (;;) {
    char aa[4096], bb[4096];
    size_t an = fread(aa, 1, sizeof aa, a), bn = fread(bb, 1, sizeof bb, b);
    if (ferror(a) || ferror(b) || an != bn || memcmp(aa, bb, an) != 0) return false;
    if (!an) return true;
  }
}

static bool cli_result(FILE *source, FILE *output, FILE *want, int status) {
  if (fflush(source) != 0 || fflush(want) != 0) return false;
  rewind(source);
  cli_source = source; cli_sink = output;
  if (zsemver_cli_main() != status) return false;
  if (status) return ftell(output) == 0;
  return cli_equal(output, want);
}

static bool cli_rows(FILE *source, FILE *want, const char *line, size_t count) {
  for (size_t i = 0; i < count; i++)
    if (fputs(line, source) < 0 || fputs(line, want) < 0) return false;
  return true;
}

static int cli_close(FILE *source, FILE *output, FILE *want, int bad) {
  FILE *streams[] = {source, output, want};
  for (size_t i = 0; i < sizeof streams / sizeof streams[0]; i++)
    if (streams[i] && fclose(streams[i]) != 0) bad = 1;
  return bad;
}

static int cli_bound_case(const char *line, size_t count, const char *tail,
                          int status) {
  FILE *source = tmpfile(), *output = tmpfile(), *want = tmpfile();
  int bad = 1;
  if (!source || !output || !want) goto cleanup;
  if (!cli_rows(source, want, line, count)) goto cleanup;
  if (fputs(tail, source) < 0) goto cleanup;
  if (*tail && status == 0) {
    if (fputs(tail, want) < 0 || fputc('\n', want) == EOF) goto cleanup;
  }
  if (!cli_result(source, output, want, status)) goto cleanup;
  bad = 0;
cleanup:
  return cli_close(source, output, want, bad);
}

static void test_cli_bound(void) {
  CHECK(cli_bound_case("1.2.3+abcdefghi\n", MAX_LINES - 1, "1.2.3+abcdefghi", 0) == 0);
  CHECK(cli_bound_case("1.2.3+abcdefghi\n", MAX_LINES, "", 0) == 0);
  CHECK(cli_bound_case("1.2.3+abcdefghi\n", MAX_LINES, "\n", 2) == 0);
  CHECK(cli_bound_case("1.2.3+abcdefghi\n", MAX_LINES - 1, "1.2.3+abcdefghij", 0) == 0);
  CHECK(cli_bound_case("1.2.3\n", MAX_LINES, "", 0) == 0);
  CHECK(cli_bound_case("1.2.3\n", MAX_LINES + 1, "", 2) == 0);
}

static void test_cli_ordering(void) {
  FILE *source = tmpfile(), *output = tmpfile(), *want = tmpfile();
  if (!source || !output || !want) { CHECK(false); goto cleanup; }
  CHECK(fputs("2.0.0\n1.0.0+b\n1.0.0+a\n1.0.0-rc.1\n", source) >= 0);
  CHECK(fputs("1.0.0-rc.1\n1.0.0+b\n1.0.0+a\n2.0.0\n", want) >= 0);
  CHECK(cli_result(source, output, want, 0));
cleanup:
  if (source) CHECK(fclose(source) == 0);
  if (output) CHECK(fclose(output) == 0);
  if (want) CHECK(fclose(want) == 0);
}

static void test_cli_read_error(void) {
#if defined(_WIN32)
  FILE *source = fopen("NUL", "w");
#else
  FILE *source = fopen("/dev/null", "w");
#endif
  FILE *output = tmpfile();
  if (source && output) {
    cli_source = source; cli_sink = output;
    CHECK(zsemver_cli_main() == 2);
    CHECK(ferror(source) && ftell(output) == 0);
  } else CHECK(false);
  if (source) CHECK(fclose(source) == 0);
  if (output) CHECK(fclose(output) == 0);
}

static int cli_output_cleanup(FILE *source, FILE *output, int bad) {
  if (source && fclose(source) != 0) bad = 1;
  if (output) (void)fclose(output);
  return bad;
}

static int cli_sink_case(const char *text, bool buffered, int status) {
  FILE *source = tmpfile();
#if defined(__linux__)
  FILE *output = fopen(buffered ? "/dev/full" : "/dev/null", buffered ? "w" : "r");
#elif defined(_WIN32)
  FILE *output = fopen("NUL", "r");
#else
  FILE *output = fopen("/dev/null", "r");
#endif
  int bad = 1;
  char buffer[4096];
  if (!source || !output) goto cleanup;
  if (buffered && setvbuf(output, buffer, _IOFBF, sizeof buffer) != 0) goto cleanup;
  if (fputs(text, source) < 0 || fflush(source) != 0) goto cleanup;
  rewind(source);
  cli_source = source; cli_sink = output; cli_output_flushes = 0;
  if (zsemver_cli_main() != status) goto cleanup;
  if (status == 2 ? !ferror(output) : (ferror(output) || cli_output_flushes != 0)) goto cleanup;
  bad = 0;
cleanup:
  return cli_output_cleanup(source, output, bad);
}

static void test_cli_output(void) {
  CHECK(cli_sink_case("2.0.0\n1.0.0\n", false, 2) == 0);
  CHECK(cli_sink_case("", false, 0) == 0);
  CHECK(cli_sink_case("\n\r\n\n", false, 0) == 0);
#if defined(__linux__)
  CHECK(cli_sink_case("2.0.0\n1.0.0\n", true, 2) == 0);
  CHECK(cli_sink_case("", true, 0) == 0);
  CHECK(cli_sink_case("\n\r\n\n", true, 0) == 0);
#endif
}

int main(void) {
  test_cli_output();
  test_cli_bound();
  test_cli_ordering();
  test_cli_read_error();
  test_failed_parse_zeroes();
  test_valid_grammar();
  test_invalid_grammar();
  test_precedence_spec_chain();
  test_precedence_edges();
  test_borrowed_fields();
  if (failures) {
    fprintf(stderr, "zsemver: %d failure(s)\n", failures);
    return 1;
  }
  printf("zsemver: all tests passed\n");
  return 0;
}
