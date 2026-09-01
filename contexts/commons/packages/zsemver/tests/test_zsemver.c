/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: zsemver test suite.  Exits nonzero on the first failure. */
#include "zsemver/zsemver.h"

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

int main(void) {
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
