/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: KAT, state-machine, bounds, and stress tests for zjson. */
#include "zjson/zjson.h"

#include <math.h>
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
    if (c == '"')
      in_str = true;
    else if (c == '{' || c == '[') {
      if (sp > ZJSON_MAX_DEPTH)
        return false;
      stack[sp++] = (char)c;
    } else if (c == '}' || c == ']') {
      if (sp == 0)
        return false;
      char o = stack[--sp];
      if ((o == '{') != (c == '}'))
        return false;
    }
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

int main(void) {
  struct {
    const char *name;
    int (*fn)(void);
  } tests[] = {
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
  printf("all %zu zjson tests passed\n", sizeof tests / sizeof tests[0]);
  return 0;
}
