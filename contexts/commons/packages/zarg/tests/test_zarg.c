/* Tests for zarg — bounded argv parser.
 * Groups: kat, conv, err, usage, null, fuzz. */
#include "zarg/zarg.h"

#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int g_fail = 0;
#define CHECK(cond)                                                     \
  do {                                                                  \
    if (!(cond)) {                                                      \
      fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);   \
      g_fail = 1;                                                       \
    }                                                                   \
  } while (0)

static const zarg_opt SPEC[] = {
  {'v', "verbose", ZARG_BOOL, "increase verbosity"},
  {'q', "quiet", ZARG_BOOL, "silence output"},
  {'o', "output", ZARG_STR, "output file"},
  {'n', "count", ZARG_I64, "repeat count"},
  {'s', "size", ZARG_U64, "byte size"},
  {'f', "factor", ZARG_F64, "scaling factor"},
  {0, "dry-run", ZARG_BOOL, "simulate only"},
};

static zarg_err parse_all(const zarg_opt *spec, size_t nspec, int argc,
                          char **argv, zarg_item *items, size_t *nitems,
                          size_t max_items) {
  zarg_parser p;
  size_t n = 0;
  zarg_err e = zarg_init(&p, spec, nspec, argc, argv);
  if (e != ZARG_OK) return e;
  for (;;) {
    zarg_item it;
    e = zarg_next(&p, &it);
    if (e != ZARG_OK) {
      *nitems = n;
      return e;
    }
    if (n < max_items) items[n] = it;
    n++;
    if (it.kind == ZARG_ITEM_END) break;
  }
  *nitems = n;
  return ZARG_OK;
}

/* ---- KAT streams ---------------------------------------------------- */

static void test_kat(void) {
  zarg_item items[32];
  size_t n = 0;

  /* Simple bundle + glued value + long = value + positionals. */
  {
    char *argv[] = {"prog", "-vq", "-ob.txt", "--count=5", "in1", "in2"};
    zarg_err e = parse_all(SPEC, 7, 6, argv, items, &n, 32);
    CHECK(e == ZARG_OK && n == 7);
    CHECK(items[0].kind == ZARG_ITEM_OPT && items[0].spec_index == 0);
    CHECK(items[1].kind == ZARG_ITEM_OPT && items[1].spec_index == 1);
    CHECK(items[2].kind == ZARG_ITEM_OPT && items[2].spec_index == 2 &&
          strcmp(items[2].value, "b.txt") == 0);
    CHECK(items[3].kind == ZARG_ITEM_OPT && items[3].spec_index == 3 &&
          items[3].i64 == 5);
    CHECK(items[4].kind == ZARG_ITEM_POS && items[4].pos_index == 0 &&
          strcmp(items[4].text, "in1") == 0);
    CHECK(items[5].kind == ZARG_ITEM_POS &&
          strcmp(items[5].text, "in2") == 0);
    CHECK(items[6].kind == ZARG_ITEM_END);
  }

  /* Bundle ending in a value-taking option, value from next argv. */
  {
    char *argv[] = {"prog", "-vqo", "out.c", "-n", "-42"};
    zarg_err e = parse_all(SPEC, 7, 5, argv, items, &n, 32);
    CHECK(e == ZARG_OK && n == 5);
    CHECK(items[0].spec_index == 0 && items[1].spec_index == 1);
    CHECK(items[2].spec_index == 2 && strcmp(items[2].value, "out.c") == 0);
    CHECK(items[3].spec_index == 3 && items[3].i64 == -42);
  }

  /* "--" terminates options; lone "-" is positional; "--x" after --. */
  {
    char *argv[] = {"prog", "a", "--", "-v", "-", "--count=1"};
    zarg_err e = parse_all(SPEC, 7, 6, argv, items, &n, 32);
    CHECK(e == ZARG_OK && n == 5);
    CHECK(items[0].kind == ZARG_ITEM_POS && strcmp(items[0].text, "a") == 0);
    CHECK(items[1].kind == ZARG_ITEM_POS && strcmp(items[1].text, "-v") == 0);
    CHECK(items[2].kind == ZARG_ITEM_POS && strcmp(items[2].text, "-") == 0);
    CHECK(items[3].kind == ZARG_ITEM_POS &&
          strcmp(items[3].text, "--count=1") == 0);
    CHECK(items[3].pos_index == 3);
  }

  /* Long option value from next argv; u64/f64 conversions. */
  {
    char *argv[] = {"prog", "--size", "4096", "--factor=2.5", "--dry-run"};
    zarg_err e = parse_all(SPEC, 7, 5, argv, items, &n, 32);
    CHECK(e == ZARG_OK && n == 4);
    CHECK(items[0].spec_index == 4 && items[0].u64 == 4096);
    CHECK(items[1].spec_index == 5 && fabs(items[1].f64 - 2.5) < 1e-12);
    CHECK(items[2].spec_index == 6 && items[2].value == NULL);
  }

  /* Empty argv: immediate END. */
  {
    char *argv[] = {"prog"};
    zarg_err e = parse_all(SPEC, 7, 1, argv, items, &n, 32);
    CHECK(e == ZARG_OK && n == 1 && items[0].kind == ZARG_ITEM_END);
  }

  /* Empty spec: all option-looking tokens are unknown. */
  {
    char *argv[] = {"prog", "x", "y"};
    zarg_err e = parse_all(NULL, 0, 3, argv, items, &n, 32);
    CHECK(e == ZARG_OK && n == 3);
    CHECK(items[0].kind == ZARG_ITEM_POS && items[1].kind == ZARG_ITEM_POS);
  }

  /* i64 extremes and negative zero. */
  {
    char *argv[] = {"prog", "-n", "-9223372036854775808",
                    "--count=9223372036854775807"};
    zarg_err e = parse_all(SPEC, 7, 4, argv, items, &n, 32);
    CHECK(e == ZARG_OK);
    CHECK(items[0].i64 == INT64_MIN);
    CHECK(items[1].i64 == INT64_MAX);
  }
  {
    char *argv[] = {"prog", "-f", "-0.0"};
    zarg_err e = parse_all(SPEC, 7, 3, argv, items, &n, 32);
    CHECK(e == ZARG_OK && signbit(items[0].f64) != 0);
  }
}

/* ---- conversions ----------------------------------------------------- */

static void test_conv(void) {
  int64_t i64 = 0;
  uint64_t u64 = 0;
  double f64 = 0;

  CHECK(zarg_conv_i64("0", &i64) == ZARG_OK && i64 == 0);
  CHECK(zarg_conv_i64("+17", &i64) == ZARG_OK && i64 == 17);
  CHECK(zarg_conv_i64(" 5", &i64) == ZARG_ERR_BADVALUE);
  CHECK(zarg_conv_i64("5 ", &i64) == ZARG_ERR_BADVALUE);
  CHECK(zarg_conv_i64("0x10", &i64) == ZARG_ERR_BADVALUE);
  CHECK(zarg_conv_i64("5e3", &i64) == ZARG_ERR_BADVALUE);
  CHECK(zarg_conv_i64("9223372036854775808", &i64) == ZARG_ERR_BADVALUE);
  CHECK(zarg_conv_i64("", &i64) == ZARG_ERR_BADVALUE);
  CHECK(zarg_conv_i64("-", &i64) == ZARG_ERR_BADVALUE);

  CHECK(zarg_conv_u64("18446744073709551615", &u64) == ZARG_OK &&
        u64 == UINT64_MAX);
  CHECK(zarg_conv_u64("18446744073709551616", &u64) == ZARG_ERR_BADVALUE);
  CHECK(zarg_conv_u64("-1", &u64) == ZARG_ERR_BADVALUE);
  CHECK(zarg_conv_u64("+9", &u64) == ZARG_OK && u64 == 9);

  CHECK(zarg_conv_f64("1e3", &f64) == ZARG_OK && f64 == 1000.0);
  CHECK(zarg_conv_f64(".5", &f64) == ZARG_OK && f64 == 0.5);
  CHECK(zarg_conv_f64("1e999", &f64) == ZARG_ERR_BADVALUE); /* overflow */
  CHECK(zarg_conv_f64("1e-999", &f64) == ZARG_OK); /* underflow to 0 ok */
  CHECK(zarg_conv_f64("nan", &f64) == ZARG_OK && isnan(f64));
  CHECK(zarg_conv_f64("abc", &f64) == ZARG_ERR_BADVALUE);
}

/* ---- error paths ------------------------------------------------------ */

static void test_err(void) {
  zarg_item items[8];
  size_t n = 0;
  zarg_parser p;

  /* Unknown short, unknown long, bool with =value, missing value,
   * bad typed value, sticky error + err_index. */
  {
    char *argv[] = {"prog", "-z"};
    CHECK(parse_all(SPEC, 7, 2, argv, items, &n, 8) == ZARG_ERR_UNKNOWN);
  }
  {
    char *argv[] = {"prog", "--nope"};
    CHECK(parse_all(SPEC, 7, 2, argv, items, &n, 8) == ZARG_ERR_UNKNOWN);
  }
  {
    char *argv[] = {"prog", "--verbose=1"};
    CHECK(parse_all(SPEC, 7, 2, argv, items, &n, 8) == ZARG_ERR_BADVALUE);
  }
  {
    char *argv[] = {"prog", "-o"};
    CHECK(parse_all(SPEC, 7, 2, argv, items, &n, 8) == ZARG_ERR_MISSING);
  }
  {
    char *argv[] = {"prog", "--count"};
    CHECK(parse_all(SPEC, 7, 2, argv, items, &n, 8) == ZARG_ERR_MISSING);
  }
  {
    char *argv[] = {"prog", "-n", "abc"};
    CHECK(parse_all(SPEC, 7, 3, argv, items, &n, 8) == ZARG_ERR_BADVALUE);
  }
  {
    char *argv[] = {"prog", "--size=-1"};
    CHECK(parse_all(SPEC, 7, 2, argv, items, &n, 8) == ZARG_ERR_BADVALUE);
  }
  /* Error is sticky and err_index names the token. */
  {
    char *argv[] = {"prog", "pos", "-z", "later"};
    zarg_item it;
    CHECK(zarg_init(&p, SPEC, 7, 4, argv) == ZARG_OK);
    CHECK(zarg_next(&p, &it) == ZARG_OK && it.kind == ZARG_ITEM_POS);
    CHECK(zarg_next(&p, &it) == ZARG_ERR_UNKNOWN && p.err_index == 2);
    CHECK(zarg_next(&p, &it) == ZARG_ERR_UNKNOWN); /* sticky */
  }
  /* Over-long long name → RANGE. */
  {
    char longtok[80] = "--";
    char *argv[] = {"prog", longtok};
    memset(longtok + 2, 'a', 70);
    longtok[72] = '\0';
    CHECK(parse_all(SPEC, 7, 2, argv, items, &n, 8) == ZARG_ERR_RANGE);
  }
  /* Bad spec tables. */
  {
    const zarg_opt bad1[] = {{0, NULL, ZARG_BOOL, NULL}};
    const zarg_opt bad2[] = {{'a', "x", ZARG_BOOL, NULL},
                             {0, "x", ZARG_BOOL, NULL}};
    const zarg_opt bad3[] = {{'-', NULL, ZARG_BOOL, NULL}};
    const zarg_opt bad4[] = {{0, "no way", ZARG_BOOL, NULL}};
    char *argv[] = {"prog"};
    CHECK(zarg_init(&p, bad1, 1, 1, argv) == ZARG_ERR_USAGE);
    CHECK(zarg_init(&p, bad2, 2, 1, argv) == ZARG_ERR_USAGE);
    CHECK(zarg_init(&p, bad3, 1, 1, argv) == ZARG_ERR_USAGE);
    CHECK(zarg_init(&p, bad4, 1, 1, argv) == ZARG_ERR_USAGE);
  }
}

/* ---- usage rendering --------------------------------------------------- */

static void test_usage(void) {
  char big[4096];
  char small[24];
  size_t need = zarg_usage(SPEC, 7, "prog", big, sizeof(big));
  CHECK(need == strlen(big));
  CHECK(need > 100);
  CHECK(strstr(big, "usage: prog [options]") != NULL);
  CHECK(strstr(big, "-v, --verbose") != NULL);
  CHECK(strstr(big, "-o, --output <str>") != NULL);
  CHECK(strstr(big, "-n, --count <int>") != NULL);
  CHECK(strstr(big, "--dry-run") != NULL);
  /* Truncated: still NUL-terminated, length reports full need. */
  CHECK(zarg_usage(SPEC, 7, "prog", small, sizeof(small)) == need);
  CHECK(small[sizeof(small) - 1] == '\0');
  CHECK(strlen(small) == sizeof(small) - 1);
  /* Measuring mode. */
  CHECK(zarg_usage(SPEC, 7, "prog", NULL, 0) == need);
  /* No prog line: still parses, starts with the spec indent. */
  {
    char buf[4096];
    size_t k = zarg_usage(SPEC, 7, NULL, buf, sizeof(buf));
    CHECK(k == strlen(buf) && buf[0] == ' ' && buf[1] == ' ' &&
          buf[2] == '-' && buf[3] == 'v');
    CHECK(strstr(buf, "usage:") == NULL);
  }
  /* Bad spec → empty output. */
  {
    const zarg_opt bad[] = {{0, NULL, ZARG_BOOL, NULL}};
    char buf[8] = "xxxxxxx";
    CHECK(zarg_usage(bad, 1, "p", buf, sizeof(buf)) == 0 && buf[0] == '\0');
  }
}

/* ---- NULL safety ------------------------------------------------------- */

static void test_null(void) {
  zarg_parser p;
  zarg_item it;
  char *argv[] = {"prog", "-v"};
  CHECK(zarg_init(NULL, SPEC, 7, 2, argv) == ZARG_ERR_ARG);
  CHECK(zarg_init(&p, SPEC, 7, 2, NULL) == ZARG_ERR_ARG);
  CHECK(zarg_init(&p, SPEC, 7, -1, argv) == ZARG_ERR_ARG);
  CHECK(zarg_init(&p, NULL, 1, 2, argv) == ZARG_ERR_ARG);
  CHECK(zarg_next(NULL, &it) == ZARG_ERR_ARG);
  CHECK(zarg_next(&p, NULL) == ZARG_ERR_ARG);
  CHECK(zarg_conv_i64(NULL, NULL) == ZARG_ERR_ARG);
  CHECK(zarg_conv_u64(NULL, NULL) == ZARG_ERR_ARG);
  CHECK(zarg_conv_f64(NULL, NULL) == ZARG_ERR_ARG);
  /* NULL entry inside argv. */
  {
    char *bad[] = {"prog", NULL, "-v"};
    CHECK(zarg_init(&p, SPEC, 7, 3, bad) == ZARG_OK);
    CHECK(zarg_next(&p, &it) == ZARG_ERR_ARG);
  }
}

/* ---- fuzz --------------------------------------------------------------- */

static uint64_t rng_state = 0x243F6A8885A308D3ull;
static uint64_t rng_next(void) {
  rng_state ^= rng_state << 13;
  rng_state ^= rng_state >> 7;
  rng_state ^= rng_state << 17;
  return rng_state;
}

static void test_fuzz(void) {
  /* Random tokens against the fixed spec: never crash, error or not
   * the parser must terminate and stay within bounds. */
  static const char *pieces[] = {
      "-v", "-q", "-vq", "-qv", "-o", "-oval", "--output", "--output=x",
      "--count", "--count=3", "--count=-3", "--size", "--size=8",
      "--factor", "--factor=0.25", "--dry-run", "--", "-", "pos", "",
      "--unknown", "-z", "--count=zz", "--verbose=1", "-n", "12", "-3.5",
      "9223372036854775808", "--=", "---", "--dry-run=x"};
  enum { NPIECES = sizeof(pieces) / sizeof(pieces[0]) };
  int trial;
  for (trial = 0; trial < 4000; trial++) {
    char *argv[16];
    int argc = 1 + (int)(rng_next() % 12);
    int i;
    zarg_parser p;
    zarg_item it;
    zarg_err e;
    size_t emitted = 0;
    argv[0] = (char *)"fuzz";
    for (i = 1; i < argc; i++)
      argv[i] = (char *)pieces[rng_next() % NPIECES];
    e = zarg_init(&p, SPEC, 7, argc, argv);
    CHECK(e == ZARG_OK);
    while ((e = zarg_next(&p, &it)) == ZARG_OK) {
      emitted++;
      CHECK(emitted <= 96); /* hard termination guard */
      if (it.kind == ZARG_ITEM_END) break;
      if (it.kind == ZARG_ITEM_OPT) CHECK(it.spec_index < 7);
    }
    if (e != ZARG_OK) {
      CHECK(p.err == e);
      CHECK(p.err_index < (size_t)argc + 1);
    }
  }
}

int main(void) {
  test_kat();
  test_conv();
  test_err();
  test_usage();
  test_null();
  test_fuzz();
  if (g_fail) {
    fprintf(stderr, "test_zarg: FAILURES\n");
    return 1;
  }
  printf("test_zarg: all groups passed (kat conv err usage null fuzz)\n");
  return 0;
}
