/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: KAT, state-machine, bounds, and stress tests for zjson. */
#ifndef ZJSON_TEST_FORMATTER
#define ZJSON_TEST_FORMATTER
#endif
/* Compile the controlled witness from the actual writer source. Namespace
 * its API before the header so ordinary package objects can also be linked. */
#define zjson_init zjson_fixture_init
#define zjson_status_of zjson_fixture_status_of
#define zjson_status_name zjson_fixture_status_name
#define zjson_len zjson_fixture_len
#define zjson_obj_open zjson_fixture_obj_open
#define zjson_obj_close zjson_fixture_obj_close
#define zjson_arr_open zjson_fixture_arr_open
#define zjson_arr_close zjson_fixture_arr_close
#define zjson_key_n zjson_fixture_key_n
#define zjson_key zjson_fixture_key
#define zjson_str_n zjson_fixture_str_n
#define zjson_str zjson_fixture_str
#define zjson_i64 zjson_fixture_i64
#define zjson_u64 zjson_fixture_u64
#define zjson_f64 zjson_fixture_f64
#define zjson_bool zjson_fixture_bool
#define zjson_null zjson_fixture_null
#define zjson_finish zjson_fixture_finish
#include "zjson/zjson.h"

#include <math.h>
#include <locale.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(cond)                                                          \
  do {                                                                       \
    if (!(cond)) {                                                           \
      fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);        \
      return 1;                                                              \
    }                                                                        \
  } while (0)

#include "../src/zjson.c"
#undef snprintf
#undef localeconv

/* Keep the writer namespace/witness intact; the CLI only uses its ordinary
 * object/string paths. The injected read failure follows one real fgets. */
static FILE *cli_source, *cli_sink;
static bool cli_fail_read, cli_read_failed;
static unsigned cli_reads;
static char *cli_fgets(char *dst, int cap, FILE *source) {
  if (source == cli_source && cli_fail_read && cli_reads++ > 0) {
    cli_read_failed = true;
    return NULL;
  }
  return fgets(dst, cap, source);
}
static int cli_ferror(FILE *stream) {
  if (stream == cli_source && cli_read_failed) return 1;
  return ferror(stream);
}
#undef stdin
#undef stdout
#define stdin cli_source
#define stdout cli_sink
#define fgets cli_fgets
#define ferror cli_ferror
#define main zjson_cli_main
#include "../app/main.c"
#undef main
#undef fgets
#undef ferror
#undef stdout
#undef stdin

static int expect(zjson *w, const char *want);
/* Controlled libc fixture: no locale installation or global locale change. */
static const char *test_radix = ".";
static int format_fault;
static unsigned locale_calls;
static unsigned locale_witness_rows;
struct lconv *zjson_test_localeconv(void) {
  ++locale_calls;
  static struct lconv info;
  info.decimal_point = (char *)test_radix;
  return &info;
}
int zjson_test_snprintf(char *out, size_t cap, const char *fmt, ...) {
  if (format_fault) {
    if (cap) out[0] = '\0';
    return format_fault < 0 ? -1 : (int)cap;
  }
  char tmp[64];
  va_list args;
  va_start(args, fmt);
  int n = vsnprintf(tmp, sizeof tmp, fmt, args);
  va_end(args);
  if (n < 0 || (size_t)n >= sizeof tmp) return -1;
  char *point = strchr(tmp, '.');
  if (point) {
    size_t r = strlen(test_radix);
    if ((size_t)n + r >= sizeof tmp) return -1;
    memmove(point + r, point + 1, strlen(point + 1) + 1);
    memcpy(point, test_radix, r);
    n += (int)r - 1;
  }
  if (cap) {
    size_t copy = (size_t)n < cap - 1 ? (size_t)n : cap - 1;
    memcpy(out, tmp, copy);
    out[copy] = '\0';
  }
  return n;
}
static int test_locale_formatter(void) {
  const char *radices[] = {",", "\xd9\xab"};
  for (size_t i = 0; i < sizeof radices / sizeof radices[0]; ++i) {
    char buf[64]; zjson w;
    zjson_init(&w, buf, sizeof buf);
    test_radix = radices[i];
    zjson_status st = zjson_f64(&w, 1.5);
    test_radix = ".";
    CHECK(st == ZJSON_OK);
    CHECK(expect(&w, "1.5") == 0);
    ++locale_witness_rows;
  }
  for (int fault = -1; fault <= 1; fault += 2) {
    for (int kind = 0; kind < 3; ++kind) {
      char buf[64]; zjson w;
      zjson_init(&w, buf, sizeof buf);
      unsigned calls_before = locale_calls;
      format_fault = fault;
      zjson_status st = kind == 0 ? zjson_i64(&w, -23) :
                        kind == 1 ? zjson_u64(&w, 23) : zjson_f64(&w, 1.5);
      format_fault = 0;
      /* Float faults must stop before normalization touches tmp; the later
       * emit_number guard alone cannot establish this boundary. */
      CHECK(kind != 2 || locale_calls == calls_before);
      CHECK(st == ZJSON_ENCODING);
      CHECK(zjson_len(&w) == 0);
      CHECK(zjson_bool(&w, true) == ZJSON_ENCODING);
      ++locale_witness_rows;
    }
  }
  return 0;
}

/* Build a document with a generous buffer and compare to expected. */
static int expect(zjson *w, const char *want) {
  size_t len = 0;
  CHECK(zjson_finish(w, &len) == ZJSON_OK);
  CHECK(len == strlen(want));
  CHECK(memcmp(w->buf, want, len) == 0);
  CHECK(w->buf[len] == '\0'); /* terminator written when room */
  return 0;
}

#define FRESH(name, cap)                                                     \
  static char buf_##name[(cap) + 1];                                         \
  zjson name;                                                                \
  zjson_init(&name, buf_##name, (cap))

static int test_kat_basics(void) {
  {
    FRESH(w, 64);
    CHECK(zjson_obj_open(&w) == ZJSON_OK);
    CHECK(zjson_obj_close(&w) == ZJSON_OK);
    CHECK(expect(&w, "{}") == 0);
  }
  {
    FRESH(w, 64);
    CHECK(zjson_arr_open(&w) == ZJSON_OK);
    CHECK(zjson_arr_close(&w) == ZJSON_OK);
    CHECK(expect(&w, "[]") == 0);
  }
  {
    FRESH(w, 128);
    CHECK(zjson_obj_open(&w) == ZJSON_OK);
    CHECK(zjson_key(&w, "a") == ZJSON_OK);
    CHECK(zjson_i64(&w, 1) == ZJSON_OK);
    CHECK(zjson_obj_close(&w) == ZJSON_OK);
    CHECK(expect(&w, "{\"a\":1}") == 0);
  }
  {
    FRESH(w, 128);
    CHECK(zjson_arr_open(&w) == ZJSON_OK);
    CHECK(zjson_i64(&w, 1) == ZJSON_OK);
    CHECK(zjson_bool(&w, true) == ZJSON_OK);
    CHECK(zjson_null(&w) == ZJSON_OK);
    CHECK(zjson_str(&w, "x") == ZJSON_OK);
    CHECK(zjson_arr_close(&w) == ZJSON_OK);
    CHECK(expect(&w, "[1,true,null,\"x\"]") == 0);
  }
  {
    FRESH(w, 256);
    CHECK(zjson_obj_open(&w) == ZJSON_OK);
    CHECK(zjson_key(&w, "a") == ZJSON_OK);
    CHECK(zjson_arr_open(&w) == ZJSON_OK);
    CHECK(zjson_i64(&w, 1) == ZJSON_OK);
    CHECK(zjson_bool(&w, true) == ZJSON_OK);
    CHECK(zjson_arr_close(&w) == ZJSON_OK);
    CHECK(zjson_key(&w, "b") == ZJSON_OK);
    CHECK(zjson_obj_open(&w) == ZJSON_OK);
    CHECK(zjson_key(&w, "c") == ZJSON_OK);
    CHECK(zjson_f64(&w, -2.5) == ZJSON_OK);
    CHECK(zjson_obj_close(&w) == ZJSON_OK);
    CHECK(zjson_obj_close(&w) == ZJSON_OK);
    CHECK(expect(&w, "{\"a\":[1,true],\"b\":{\"c\":-2.5}}") == 0);
  }
  {
    /* empty key and empty string are legal */
    FRESH(w, 64);
    CHECK(zjson_obj_open(&w) == ZJSON_OK);
    CHECK(zjson_key(&w, "") == ZJSON_OK);
    CHECK(zjson_str(&w, "") == ZJSON_OK);
    CHECK(zjson_obj_close(&w) == ZJSON_OK);
    CHECK(expect(&w, "{\"\":\"\"}") == 0);
  }
  {
    /* scalar at the top level is a complete document */
    FRESH(w, 16);
    CHECK(zjson_bool(&w, false) == ZJSON_OK);
    CHECK(expect(&w, "false") == 0);
  }
  return 0;
}

static int test_escapes(void) {
  /* every mandatory escape, one control char per case */
  static const struct {
    char in;
    const char *out;
  } cases[] = {
      {'"', "\\\""},   {'\\', "\\\\"}, {'\b', "\\b"}, {'\t', "\\t"},
      {'\n', "\\n"},   {'\f', "\\f"},  {'\r', "\\r"}, {0x01, "\\u0001"},
      {0x1f, "\\u001f"}, {0x00, "\\u0000"},
  };
  for (size_t i = 0; i < sizeof cases / sizeof cases[0]; i++) {
    FRESH(w, 32);
    char want[16];
    snprintf(want, sizeof want, "\"%s\"", cases[i].out);
    CHECK(zjson_str_n(&w, &cases[i].in, 1) == ZJSON_OK);
    CHECK(expect(&w, want) == 0);
  }
  {
    /* DEL and non-ASCII pass through unescaped; UTF-8 preserved */
    FRESH(w, 64);
    const char *s = "h\x7fllo \xc3\xa9 \xe2\x82\xac \xf0\x9f\x98\x80";
    CHECK(zjson_str(&w, s) == ZJSON_OK);
    size_t len = 0;
    CHECK(zjson_finish(&w, &len) == ZJSON_OK);
    CHECK(len == strlen(s) + 2);
    CHECK(memcmp(w.buf + 1, s, strlen(s)) == 0);
  }
  {
    /* invalid UTF-8 rejected, sticky, nothing emitted */
    FRESH(w, 64);
    const char bad[] = {(char)0xc0, (char)0xaf, 0};
    CHECK(zjson_str_n(&w, bad, 2) == ZJSON_ENCODING);
    CHECK(zjson_len(&w) == 0);
    CHECK(zjson_str(&w, "ok") == ZJSON_ENCODING);
    size_t len = 99;
    CHECK(zjson_finish(&w, &len) == ZJSON_ENCODING);
  }
  return 0;
}

static int test_numbers(void) {
  {
    FRESH(w, 256);
    CHECK(zjson_arr_open(&w) == ZJSON_OK);
    CHECK(zjson_i64(&w, 0) == ZJSON_OK);
    CHECK(zjson_i64(&w, -1) == ZJSON_OK);
    CHECK(zjson_i64(&w, INT64_MIN) == ZJSON_OK);
    CHECK(zjson_i64(&w, INT64_MAX) == ZJSON_OK);
    CHECK(zjson_arr_close(&w) == ZJSON_OK);
    CHECK(expect(&w, "[0,-1,-9223372036854775808,9223372036854775807]") == 0);
  }
  {
    FRESH(w, 64);
    CHECK(zjson_arr_open(&w) == ZJSON_OK);
    CHECK(zjson_u64(&w, 0) == ZJSON_OK);
    CHECK(zjson_u64(&w, UINT64_MAX) == ZJSON_OK);
    CHECK(zjson_arr_close(&w) == ZJSON_OK);
    CHECK(expect(&w, "[0,18446744073709551615]") == 0);
  }
  {
    FRESH(w, 64);
    CHECK(zjson_arr_open(&w) == ZJSON_OK);
    CHECK(zjson_f64(&w, 1.0) == ZJSON_OK);
    CHECK(zjson_f64(&w, -0.0) == ZJSON_OK);
    CHECK(zjson_f64(&w, 0.5) == ZJSON_OK);
    CHECK(zjson_arr_close(&w) == ZJSON_OK);
    CHECK(expect(&w, "[1,-0,0.5]") == 0);
  }
  {
    /* %.17g round-trips through strtod for arbitrary doubles */
    static const double vals[] = {0.1, 1.0 / 3.0, 1e300, -1e-300,
                                  3.141592653589793, 2.2250738585072014e-308};
    for (size_t i = 0; i < sizeof vals / sizeof vals[0]; i++) {
      FRESH(w, 64);
      CHECK(zjson_f64(&w, vals[i]) == ZJSON_OK);
      size_t len = 0;
      CHECK(zjson_finish(&w, &len) == ZJSON_OK);
      CHECK(strtod(w.buf, NULL) == vals[i]);
    }
  }
  {
    /* NaN and Inf cannot be represented; sticky ENCODING */
    FRESH(w, 64);
    CHECK(zjson_f64(&w, NAN) == ZJSON_ENCODING);
    CHECK(zjson_len(&w) == 0);
    FRESH(w2, 64);
    CHECK(zjson_f64(&w2, INFINITY) == ZJSON_ENCODING);
    FRESH(w3, 64);
    CHECK(zjson_f64(&w3, -INFINITY) == ZJSON_ENCODING);
  }
  return 0;
}

/* Each violation on a fresh writer; the error must be sticky. */
static int test_state_errors(void) {
  {
    FRESH(w, 64); /* second top-level value */
    CHECK(zjson_i64(&w, 1) == ZJSON_OK);
    CHECK(zjson_i64(&w, 2) == ZJSON_STATE);
    CHECK(zjson_bool(&w, true) == ZJSON_STATE);
    CHECK(zjson_finish(&w, NULL) == ZJSON_STATE);
  }
  {
    FRESH(w, 64); /* key at top level */
    CHECK(zjson_key(&w, "a") == ZJSON_STATE);
  }
  {
    FRESH(w, 64); /* key inside an array */
    CHECK(zjson_arr_open(&w) == ZJSON_OK);
    CHECK(zjson_key(&w, "a") == ZJSON_STATE);
  }
  {
    FRESH(w, 64); /* object value without a key */
    CHECK(zjson_obj_open(&w) == ZJSON_OK);
    CHECK(zjson_i64(&w, 1) == ZJSON_STATE);
  }
  {
    FRESH(w, 64); /* key where a value belongs */
    CHECK(zjson_obj_open(&w) == ZJSON_OK);
    CHECK(zjson_key(&w, "a") == ZJSON_OK);
    CHECK(zjson_key(&w, "b") == ZJSON_STATE);
  }
  {
    FRESH(w, 64); /* close mismatch: object closed as array */
    CHECK(zjson_obj_open(&w) == ZJSON_OK);
    CHECK(zjson_arr_close(&w) == ZJSON_STATE);
  }
  {
    FRESH(w, 64); /* close mismatch: array closed as object */
    CHECK(zjson_arr_open(&w) == ZJSON_OK);
    CHECK(zjson_obj_close(&w) == ZJSON_STATE);
  }
  {
    FRESH(w, 64); /* close at depth 0 */
    CHECK(zjson_obj_close(&w) == ZJSON_STATE);
    FRESH(w2, 64);
    CHECK(zjson_arr_close(&w2) == ZJSON_STATE);
  }
  {
    FRESH(w, 64); /* object closed with a dangling key */
    CHECK(zjson_obj_open(&w) == ZJSON_OK);
    CHECK(zjson_key(&w, "a") == ZJSON_OK);
    CHECK(zjson_obj_close(&w) == ZJSON_STATE);
  }
  {
    FRESH(w, 64); /* finish with an open container */
    CHECK(zjson_arr_open(&w) == ZJSON_OK);
    CHECK(zjson_i64(&w, 1) == ZJSON_OK);
    CHECK(zjson_finish(&w, NULL) == ZJSON_STATE);
    CHECK(zjson_arr_close(&w) == ZJSON_STATE); /* sticky */
  }
  {
    FRESH(w, 64); /* finish on an empty writer */
    CHECK(zjson_finish(&w, NULL) == ZJSON_STATE);
  }
  return 0;
}

static int test_depth(void) {
  FRESH(w, 256);
  for (int i = 0; i < ZJSON_MAX_DEPTH; i++)
    CHECK(zjson_arr_open(&w) == ZJSON_OK);
  CHECK(zjson_arr_open(&w) == ZJSON_DEPTH); /* 33rd refused */
  CHECK(zjson_arr_open(&w) == ZJSON_DEPTH); /* sticky */
  size_t len = 0;
  CHECK(zjson_finish(&w, &len) == ZJSON_DEPTH);

  FRESH(ok, 256); /* exactly ZJSON_MAX_DEPTH is fine (keyed nesting) */
  for (int i = 0; i < ZJSON_MAX_DEPTH; i++) {
    if (i > 0)
      CHECK(zjson_key(&ok, "k") == ZJSON_OK);
    CHECK(zjson_obj_open(&ok) == ZJSON_OK);
  }
  for (int i = 0; i < ZJSON_MAX_DEPTH; i++)
    CHECK(zjson_obj_close(&ok) == ZJSON_OK);
  size_t olen = 0;
  CHECK(zjson_finish(&ok, &olen) == ZJSON_OK);
  /* 32 braces each way plus 31 `"k":` member prefixes */
  CHECK(olen == 2 * (size_t)ZJSON_MAX_DEPTH + 31 * 4);
  return 0;
}

static int test_overflow(void) {
  static const char doc[] = "{\"k\":\"v\"}";
  const size_t need = sizeof doc - 1;
  {
    static char buf_exact[16]; /* exact fit (need == 10) */
    zjson w;
    zjson_init(&w, buf_exact, need);
    CHECK(zjson_obj_open(&w) == ZJSON_OK);
    CHECK(zjson_key(&w, "k") == ZJSON_OK);
    CHECK(zjson_str(&w, "v") == ZJSON_OK);
    CHECK(zjson_obj_close(&w) == ZJSON_OK);
    CHECK(expect(&w, doc) == 0);
  }
  {
    static char buf_short[16]; /* one byte short: measured, sticky */
    zjson w;
    zjson_init(&w, buf_short, need - 1);
    CHECK(zjson_obj_open(&w) == ZJSON_OK);
    CHECK(zjson_key(&w, "k") == ZJSON_OK);
    CHECK(zjson_str(&w, "v") == ZJSON_OK);
    CHECK(zjson_obj_close(&w) == ZJSON_OVERFLOW);
    CHECK(zjson_len(&w) == need); /* exact size still reported */
    CHECK(zjson_i64(&w, 1) == ZJSON_OVERFLOW); /* sticky */
    size_t len = 0;
    CHECK(zjson_finish(&w, &len) == ZJSON_OVERFLOW);
    CHECK(len == need);
  }
  {
    zjson w; /* NULL buffer: everything overflows, nothing crashes */
    zjson_init(&w, NULL, 128);
    CHECK(zjson_arr_open(&w) == ZJSON_OVERFLOW);
    CHECK(zjson_len(&w) == 1);
  }
  {
    zjson w; /* zero capacity */
    zjson_init(&w, NULL, 0);
    CHECK(zjson_null(&w) == ZJSON_OVERFLOW);
    CHECK(zjson_len(&w) == 4);
  }
  return 0;
}

static int test_null_safety(void) {
  CHECK(zjson_status_of(NULL) == ZJSON_STATE);
  CHECK(zjson_len(NULL) == 0);
  CHECK(zjson_obj_open(NULL) == ZJSON_STATE);
  CHECK(zjson_obj_close(NULL) == ZJSON_STATE);
  CHECK(zjson_arr_open(NULL) == ZJSON_STATE);
  CHECK(zjson_arr_close(NULL) == ZJSON_STATE);
  CHECK(zjson_key(NULL, "a") == ZJSON_STATE);
  CHECK(zjson_str(NULL, "a") == ZJSON_STATE);
  CHECK(zjson_i64(NULL, 1) == ZJSON_STATE);
  CHECK(zjson_u64(NULL, 1) == ZJSON_STATE);
  CHECK(zjson_f64(NULL, 1.0) == ZJSON_STATE);
  CHECK(zjson_bool(NULL, true) == ZJSON_STATE);
  CHECK(zjson_null(NULL) == ZJSON_STATE);
  CHECK(zjson_finish(NULL, NULL) == ZJSON_STATE);
  zjson_init(NULL, NULL, 0); /* no crash */

  FRESH(w, 64); /* NULL string is an encoding error, not a crash */
  CHECK(zjson_str_n(&w, NULL, 3) == ZJSON_ENCODING);
  FRESH(w2, 64);
  CHECK(zjson_str(&w2, NULL) == ZJSON_ENCODING);
  FRESH(w3, 64);
  CHECK(zjson_obj_open(&w3) == ZJSON_OK);
  CHECK(zjson_key(&w3, NULL) == ZJSON_ENCODING);
  CHECK(zjson_status_name(ZJSON_DEPTH) != NULL);
  CHECK(strcmp(zjson_status_name(ZJSON_OVERFLOW), "overflow") == 0);
  return 0;
}

/* Handle one byte outside strings: a quote opens a string, brackets
 * nest; false rejects an over-depth open or an unmatched close. */
static bool balanced_structural_byte(unsigned char c, size_t *sp,
                                     char *stack, bool *in_str) {
  if (c == '"')
    *in_str = true;
  else if (c == '{' || c == '[') {
    if (*sp > ZJSON_MAX_DEPTH)
      return false;
    stack[(*sp)++] = (char)c;
  } else if (c == '}' || c == ']') {
    if (*sp == 0)
      return false;
    char o = stack[--*sp];
    if ((o == '{') != (c == '}'))
      return false;
  }
  return true;
}

/* Structural validator: balance brackets outside strings, reject raw
 * control bytes inside strings. */
static bool balanced(const char *s, size_t n) {
  char stack[ZJSON_MAX_DEPTH + 1];
  size_t sp = 0;
  bool in_str = false, esc = false;
  for (size_t i = 0; i < n; i++) {
    unsigned char c = (unsigned char)s[i];
    if (in_str) {
      if (esc)
        esc = false;
      else if (c == '\\')
        esc = true;
      else if (c == '"')
        in_str = false;
      else if (c < 0x20)
        return false;
      continue;
    }
    if (!balanced_structural_byte(c, &sp, stack, &in_str))
      return false;
  }
  return !in_str && !esc && sp == 0;
}

static uint64_t rng_state = 0x9e3779b97f4a7c15ull;
static uint64_t rnd(void) {
  rng_state ^= rng_state << 13;
  rng_state ^= rng_state >> 7;
  rng_state ^= rng_state << 17;
  return rng_state;
}

/* Valid-UTF-8 fragments, including every escape-worthy byte. */
static const char *frags[] = {
    "a",  "Z",        "0", " ",         "\"", "\\",
    "\n", "\t",       "\x01", "\x1f",   "~",  "\xc3\xa9",
    "\xe2\x82\xac", "\xf0\x9f\x98\x80",
};

static void gen_string(zjson *w) {
  char tmp[64];
  size_t n = 0;
  size_t parts = rnd() % 4;
  for (size_t i = 0; i < parts && n < sizeof tmp - 5; i++) {
    const char *f = frags[rnd() % (sizeof frags / sizeof frags[0])];
    size_t fl = strlen(f);
    memcpy(tmp + n, f, fl);
    n += fl;
  }
  zjson_str_n(w, tmp, n);
}

static void gen_value(zjson *w, unsigned depth) {
  unsigned pick = depth >= 6 ? rnd() % 5 : rnd() % 7;
  switch (pick) {
  case 0: zjson_i64(w, (int64_t)rnd()); break;
  case 1: zjson_u64(w, rnd()); break;
  case 2: zjson_bool(w, (rnd() & 1) != 0); break;
  case 3: zjson_null(w); break;
  case 4: gen_string(w); break;
  case 5: {
    zjson_arr_open(w);
    unsigned elems = rnd() % 5;
    for (unsigned i = 0; i < elems; i++)
      gen_value(w, depth + 1);
    zjson_arr_close(w);
    break;
  }
  default: {
    zjson_obj_open(w);
    unsigned elems = rnd() % 5;
    for (unsigned i = 0; i < elems; i++) {
      char key[24];
      int kn = snprintf(key, sizeof key, "k%u", (unsigned)(rnd() % 1000));
      zjson_key_n(w, key, (size_t)kn);
      gen_value(w, depth + 1);
    }
    zjson_obj_close(w);
    break;
  }
  }
}

static int test_stress(void) {
  static char buf[1 << 16];
  for (unsigned trial = 0; trial < 2000; trial++) {
    zjson w;
    zjson_init(&w, buf, sizeof buf);
    gen_value(&w, 0);
    size_t len = 0;
    CHECK(zjson_finish(&w, &len) == ZJSON_OK);
    CHECK(len < sizeof buf);
    CHECK(balanced(buf, len));
  }
  return 0;
}

static bool cli_capture(FILE *source, FILE *output, int status,
                         const char *want, size_t want_len, bool fail_read) {
  cli_source = source; cli_sink = output;
  cli_fail_read = fail_read; cli_read_failed = false; cli_reads = 0;
  int rc = zjson_cli_main();
  cli_fail_read = false;
  if (rc != status || (fail_read && !cli_read_failed)) return false;
  if (!want) return true;
  rewind(output);
  char got[8192];
  size_t n = fread(got, 1, sizeof got, output);
  return !ferror(output) && n == want_len && memcmp(got, want, n) == 0;
}

static int cli_close(FILE *source, FILE *output, int bad) {
  if (source && fclose(source) != 0) bad = 1;
  if (output && fclose(output) != 0) bad = 1;
  return bad;
}

static int cli_data(const char *data, size_t len, int status,
                     const char *want, size_t want_len, bool fail_read) {
  FILE *source = tmpfile(), *output = tmpfile();
  int bad = 1;
  if (!source || !output) goto cleanup;
  if (fwrite(data, 1, len, source) != len || fflush(source) != 0) goto cleanup;
  rewind(source);
  if (!cli_capture(source, output, status, want, want_len, fail_read)) goto cleanup;
  bad = 0;
cleanup:
  return cli_close(source, output, bad);
}

static int test_cli_lines(void) {
  for (size_t length = 4094; length <= 4096; length++) {
    for (unsigned newline = 0; newline < 2; newline++) {
      char text[4096], want[4110];
      memset(text, 'x', length);
      text[0] = 'k'; text[1] = '\t';
      if (newline) text[length - 1] = '\n';
      size_t value_len = length - 2 - newline;
      memcpy(want, "{\"k\":\"", 6);
      memset(want + 6, 'x', value_len);
      memcpy(want + 6 + value_len, "\"}\n", 3);
      CHECK(cli_data(text, length, length <= 4095 ? 0 : 1,
                     length <= 4095 ? want : "", length <= 4095 ? value_len + 9 : 0,
                     false) == 0);
    }
  }
  return 0;
}

static int test_cli_reads(void) {
  CHECK(cli_data("k\tv\n", 4, 1, "", 0, true) == 0);
  CHECK(cli_data("k\tv\nbad\n", 8, 1, "", 0, false) == 0);
#if defined(_WIN32)
  FILE *source = fopen("NUL", "w");
#else
  FILE *source = fopen("/dev/null", "w");
#endif
  FILE *output = tmpfile();
  bool ok = source && output && cli_capture(source, output, 1, "", 0, false) &&
      ferror(source);
  return cli_close(source, output, ok ? 0 : 1);
}

static int cli_sink_case(bool empty, bool buffered) {
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
  if (fputs(empty ? "" : "k\tv\n", source) < 0 || fflush(source) != 0) goto cleanup;
  rewind(source);
  if (!cli_capture(source, output, 1, NULL, 0, false) || !ferror(output)) goto cleanup;
  bad = 0;
cleanup:
  if (source && fclose(source) != 0) bad = 1;
  if (output) (void)fclose(output);
  return bad;
}

static int test_cli_output(void) {
  CHECK(cli_data("", 0, 0, "{}\n", 3, false) == 0);
  CHECK(cli_data("k\tv\n", 4, 0, "{\"k\":\"v\"}\n", 10, false) == 0);
  CHECK(cli_sink_case(false, false) == 0);
  CHECK(cli_sink_case(true, false) == 0);
#if defined(__linux__)
  CHECK(cli_sink_case(false, true) == 0);
  CHECK(cli_sink_case(true, true) == 0);
#endif
  return 0;
}

static int test_cli(void) {
  return test_cli_lines() + test_cli_reads() + test_cli_output();
}

int main(void) {
  struct {
    const char *name;
    int (*fn)(void);
  } tests[] = {
      {"cli", test_cli},
      {"locale_formatter", test_locale_formatter},
      {"kat_basics", test_kat_basics},   {"escapes", test_escapes},
      {"numbers", test_numbers},         {"state_errors", test_state_errors},
      {"depth", test_depth},             {"overflow", test_overflow},
      {"null_safety", test_null_safety}, {"stress", test_stress},
  };
  for (size_t i = 0; i < sizeof tests / sizeof tests[0]; i++) {
    if (tests[i].fn() != 0) {
      fprintf(stderr, "test %s FAILED\n", tests[i].name);
      return 1;
    }
  }
  CHECK(locale_witness_rows == 8);
  printf("locale witness: 2 separators and 6 formatter faults passed\n");
  printf("all %zu zjson tests passed\n", sizeof tests / sizeof tests[0]);
  return 0;
}
