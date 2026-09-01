/* Tests for ztoml — bounded TOML-subset pull parser.
 * Groups: kat, types, arr, err, decode, null, fuzz. */
#include "ztoml/ztoml.h"

#include <math.h>
#include <stdio.h>
#include <string.h>

static int g_fail = 0;
#define CHECK(cond)                                                     \
  do {                                                                  \
    if (!(cond)) {                                                      \
      fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);   \
      g_fail = 1;                                                       \
    }                                                                   \
  } while (0)

typedef struct {
  ztoml_ev ev[64];
  size_t n;
} evlog;

/* Parse the whole document, recording events. Returns the terminal
 * error (ZTOML_OK when DONE was reached). */
static ztoml_err parse_all(const char *doc, evlog *log) {
  ztoml t;
  ztoml_err e = ztoml_init(&t, doc, strlen(doc));
  log->n = 0;
  if (e != ZTOML_OK) return e;
  for (;;) {
    ztoml_ev ev;
    e = ztoml_next(&t, &ev);
    if (e != ZTOML_OK) return e;
    if (log->n < 64) log->ev[log->n] = ev;
    log->n++;
    if (ev.kind == ZTOML_EV_DONE) return ZTOML_OK;
  }
}

static int slice_eq(const ztoml_ev *ev, const char *s) {
  return strlen(s) == ev->len && memcmp(ev->ptr, s, ev->len) == 0;
}

/* ---- golden document ----------------------------------------------------- */

static void test_kat(void) {
  const char *doc =
      "# comment\n"
      "title = \"TOML Example\"\n"
      "\n"
      "[owner]\n"
      "name = \"Tom\"\n"
      "age = 30\n"
      "score = 99.5\n"
      "active = true\n"
      "lucky = [1, 2, 3]\n"
      "\n"
      "[deps.zlib]\n"
      "rev = 'abc123'\n";
  evlog log;
  CHECK(parse_all(doc, &log) == ZTOML_OK);
  CHECK(log.ev[0].kind == ZTOML_EV_KEY && slice_eq(&log.ev[0], "title"));
  CHECK(log.ev[1].kind == ZTOML_EV_VALUE &&
        log.ev[1].vtype == ZTOML_V_STR_BASIC &&
        slice_eq(&log.ev[1], "TOML Example"));
  CHECK(log.ev[2].kind == ZTOML_EV_SECTION && slice_eq(&log.ev[2], "owner"));
  CHECK(log.ev[3].kind == ZTOML_EV_KEY && slice_eq(&log.ev[3], "name"));
  CHECK(log.ev[4].vtype == ZTOML_V_STR_BASIC && slice_eq(&log.ev[4], "Tom"));
  CHECK(log.ev[5].kind == ZTOML_EV_KEY && slice_eq(&log.ev[5], "age"));
  CHECK(log.ev[6].vtype == ZTOML_V_INT && log.ev[6].i64 == 30);
  CHECK(log.ev[8].vtype == ZTOML_V_FLOAT &&
        fabs(log.ev[8].f64 - 99.5) < 1e-12);
  CHECK(log.ev[10].vtype == ZTOML_V_BOOL && log.ev[10].boolean == 1);
  /* lucky = [1,2,3]: KEY, OPEN, 1, 2, 3, CLOSE */
  CHECK(log.ev[11].kind == ZTOML_EV_KEY && slice_eq(&log.ev[11], "lucky"));
  CHECK(log.ev[12].kind == ZTOML_EV_ARR_OPEN);
  CHECK(log.ev[13].vtype == ZTOML_V_INT && log.ev[13].i64 == 1);
  CHECK(log.ev[14].i64 == 2 && log.ev[15].i64 == 3);
  CHECK(log.ev[16].kind == ZTOML_EV_ARR_CLOSE);
  CHECK(log.ev[17].kind == ZTOML_EV_SECTION &&
        slice_eq(&log.ev[17], "deps.zlib"));
  CHECK(log.ev[18].kind == ZTOML_EV_KEY && slice_eq(&log.ev[18], "rev"));
  CHECK(log.ev[19].vtype == ZTOML_V_STR_LIT &&
        slice_eq(&log.ev[19], "abc123"));
  CHECK(log.ev[20].kind == ZTOML_EV_DONE);
  CHECK(log.n == 21);
}

/* ---- value types ------------------------------------------------------------ */

static void test_types(void) {
  static const struct {
    const char *doc;
    ztoml_vtype vt;
    int64_t i64;
    double f64;
    int boolean;
  } KAT[] = {
      {"k = 0", ZTOML_V_INT, 0, 0, 0},
      {"k = +17", ZTOML_V_INT, 17, 0, 0},
      {"k = -42", ZTOML_V_INT, -42, 0, 0},
      {"k = 1_000", ZTOML_V_INT, 1000, 0, 0},
      {"k = 0xDEADBEEF", ZTOML_V_INT, 0xDEADBEEF, 0, 0},
      {"k = 0o755", ZTOML_V_INT, 493, 0, 0},
      {"k = 0b1101", ZTOML_V_INT, 13, 0, 0},
      {"k = 9223372036854775807", ZTOML_V_INT, INT64_MAX, 0, 0},
      {"k = -9223372036854775808", ZTOML_V_INT, INT64_MIN, 0, 0},
      {"k = 3.14", ZTOML_V_FLOAT, 0, 3.14, 0},
      {"k = -0.5e2", ZTOML_V_FLOAT, 0, -50.0, 0},
      {"k = 1e6", ZTOML_V_FLOAT, 0, 1e6, 0},
      {"k = 2_000.5", ZTOML_V_FLOAT, 0, 2000.5, 0},
      {"k = inf", ZTOML_V_FLOAT, 0, HUGE_VAL, 0},
      {"k = -inf", ZTOML_V_FLOAT, 0, -HUGE_VAL, 0},
      {"k = true", ZTOML_V_BOOL, 0, 0, 1},
      {"k = false", ZTOML_V_BOOL, 0, 0, 0},
      {"k = \"\"", ZTOML_V_STR_BASIC, 0, 0, 0},
      {"k = ''", ZTOML_V_STR_LIT, 0, 0, 0},
  };
  size_t i;
  for (i = 0; i < sizeof(KAT) / sizeof(KAT[0]); i++) {
    evlog log;
    ztoml_err e = parse_all(KAT[i].doc, &log);
    if (e != ZTOML_OK || log.n != 3 || log.ev[1].vtype != KAT[i].vt) {
      fprintf(stderr, "FAIL type: \"%s\" -> err=%d n=%zu vt=%d\n",
              KAT[i].doc, (int)e, log.n, (int)log.ev[1].vtype);
      g_fail = 1;
      continue;
    }
    switch (KAT[i].vt) {
    case ZTOML_V_INT: CHECK(log.ev[1].i64 == KAT[i].i64); break;
    case ZTOML_V_FLOAT:
      if (isinf(KAT[i].f64))
        CHECK(log.ev[1].f64 == KAT[i].f64);
      else
        CHECK(fabs(log.ev[1].f64 - KAT[i].f64) < 1e-9 ||
              fabs(log.ev[1].f64 - KAT[i].f64) <
                  fabs(KAT[i].f64) * 1e-12);
      break;
    case ZTOML_V_BOOL: CHECK(log.ev[1].boolean == KAT[i].boolean); break;
    default: break;
    }
  }
  /* nan is nan. */
  {
    evlog log;
    CHECK(parse_all("k = nan", &log) == ZTOML_OK);
    CHECK(log.ev[1].vtype == ZTOML_V_FLOAT && isnan(log.ev[1].f64));
  }
}

/* ---- arrays -------------------------------------------------------------------- */

static void test_arr(void) {
  evlog log;
  /* Nested arrays with newlines and comments. */
  const char *doc =
      "m = [\n"
      "  [1, 2], # inner\n"
      "  [3,\n"
      "   4,],\n"
      "]\n";
  CHECK(parse_all(doc, &log) == ZTOML_OK);
  CHECK(log.n == 12); /* KEY OPEN OPEN 1 2 CLOSE OPEN 3 4 CLOSE CLOSE DONE */
  CHECK(log.ev[0].kind == ZTOML_EV_KEY);
  CHECK(log.ev[1].kind == ZTOML_EV_ARR_OPEN);
  CHECK(log.ev[2].kind == ZTOML_EV_ARR_OPEN);
  CHECK(log.ev[3].i64 == 1 && log.ev[4].i64 == 2);
  CHECK(log.ev[5].kind == ZTOML_EV_ARR_CLOSE);
  CHECK(log.ev[6].kind == ZTOML_EV_ARR_OPEN);
  CHECK(log.ev[7].i64 == 3 && log.ev[8].i64 == 4);
  CHECK(log.ev[9].kind == ZTOML_EV_ARR_CLOSE);
  CHECK(log.ev[10].kind == ZTOML_EV_ARR_CLOSE);
  CHECK(log.ev[11].kind == ZTOML_EV_DONE);
  /* Empty array. */
  CHECK(parse_all("e = []", &log) == ZTOML_OK && log.n == 4);
  CHECK(log.ev[1].kind == ZTOML_EV_ARR_OPEN &&
        log.ev[2].kind == ZTOML_EV_ARR_CLOSE);
  /* Mixed scalar array. */
  CHECK(parse_all("mix = [1, \"two\", 3.0, true]", &log) == ZTOML_OK);
  CHECK(log.n == 8);
  CHECK(log.ev[2].vtype == ZTOML_V_INT && log.ev[3].vtype == ZTOML_V_STR_BASIC &&
        log.ev[4].vtype == ZTOML_V_FLOAT && log.ev[5].vtype == ZTOML_V_BOOL);
}

/* ---- error table -------------------------------------------------------------------- */

static void test_err(void) {
  static const struct {
    const char *doc;
    ztoml_err err;
  } BAD[] = {
      {"k", ZTOML_ERR_SYNTAX},              /* key without = */
      {"k = ", ZTOML_ERR_SYNTAX},           /* missing value */
      {"= 1", ZTOML_ERR_SYNTAX},
      {"k = 01", ZTOML_ERR_SYNTAX},         /* leading zero: strtoll junk? see below */
      {"k = 1_", ZTOML_ERR_SYNTAX},         /* trailing underscore */
      {"k = _1", ZTOML_ERR_SYNTAX},
      {"k = 1__2", ZTOML_ERR_SYNTAX},
      {"k = 9223372036854775808", ZTOML_ERR_BADVALUE},
      {"k = 1e999", ZTOML_ERR_BADVALUE},
      {"k = 5.", ZTOML_ERR_SYNTAX},
      {"k = .5", ZTOML_ERR_SYNTAX},
      {"k = \"unterminated", ZTOML_ERR_SYNTAX},
      {"k = \"bad\nstring\"", ZTOML_ERR_SYNTAX},
      {"k = 1979-05-27 07:32:00", ZTOML_ERR_SYNTAX}, /* datetime */
      {"k = 1979-05-27", ZTOML_ERR_SYNTAX},          /* date-like: trailing junk */
      {"[[tbl]]", ZTOML_ERR_SYNTAX},
      {"[]", ZTOML_ERR_SYNTAX},
      {"[a", ZTOML_ERR_SYNTAX},
      {"[a.] ", ZTOML_ERR_SYNTAX},
      {"k = [1 2]", ZTOML_ERR_SYNTAX},   /* missing comma */
      {"k = [,1]", ZTOML_ERR_SYNTAX},    /* leading comma */
      {"k = [1, 2", ZTOML_ERR_SYNTAX},   /* unclosed */
      {"k = \"a\" \"b\"", ZTOML_ERR_SYNTAX}, /* two values one line */
      {"k = 1 k2 = 2", ZTOML_ERR_SYNTAX},    /* two pairs one line */
      {"k = yes", ZTOML_ERR_SYNTAX},     /* not a boolean */
      {"k = 0x", ZTOML_ERR_SYNTAX},
      {"k = -0x1", ZTOML_ERR_SYNTAX},    /* sign on non-dec */
  };
  size_t i;
  for (i = 0; i < sizeof(BAD) / sizeof(BAD[0]); i++) {
    evlog log;
    ztoml_err e = parse_all(BAD[i].doc, &log);
    if (e != BAD[i].err) {
      fprintf(stderr, "FAIL err: \"%s\" -> %d (want %d)\n", BAD[i].doc,
              (int)e, (int)BAD[i].err);
      g_fail = 1;
    }
  }
  /* Sticky error with offset. */
  {
    ztoml t;
    ztoml_ev ev;
    CHECK(ztoml_init(&t, "ok = 1\nbad!\n", 13) == ZTOML_OK);
    CHECK(ztoml_next(&t, &ev) == ZTOML_OK); /* KEY ok */
    CHECK(ztoml_next(&t, &ev) == ZTOML_OK); /* VALUE 1 */
    CHECK(ztoml_next(&t, &ev) == ZTOML_ERR_SYNTAX);
    CHECK(t.err_off == 10); /* '!' */
    CHECK(ztoml_next(&t, &ev) == ZTOML_ERR_SYNTAX); /* sticky */
  }
  /* Depth bound. */
  {
    char doc[64] = "k = ";
    size_t i;
    for (i = 0; i < ZTOML_MAX_DEPTH + 2; i++) strcat(doc, "[");
    evlog log;
    CHECK(parse_all(doc, &log) == ZTOML_ERR_RANGE);
  }
}

/* ---- string decode ------------------------------------------------------------------- */

static void test_decode(void) {
  char buf[64];
  CHECK(ztoml_str_decode("plain", 5, buf, sizeof(buf)) == 5 &&
        strcmp(buf, "plain") == 0);
  CHECK(ztoml_str_decode("a\\nb\\t\\\\c", 9, buf, sizeof(buf)) == 6 &&
        memcmp(buf, "a\nb\t\\c", 6) == 0);
  CHECK(ztoml_str_decode("\\u0041\\u00E9", 12, buf, sizeof(buf)) == 3 &&
        memcmp(buf, "A\xC3\xA9", 3) == 0);
  CHECK(ztoml_str_decode("\\U0001F600", 10, buf, sizeof(buf)) == 4 &&
        memcmp(buf, "\xF0\x9F\x98\x80", 4) == 0);
  /* malformed */
  CHECK(ztoml_str_decode("\\q", 2, buf, sizeof(buf)) == SIZE_MAX);
  CHECK(ztoml_str_decode("\\u12", 4, buf, sizeof(buf)) == SIZE_MAX);
  CHECK(ztoml_str_decode("\\uD800", 6, buf, sizeof(buf)) == SIZE_MAX);
  CHECK(ztoml_str_decode("\\U00110000", 10, buf, sizeof(buf)) == SIZE_MAX);
  CHECK(ztoml_str_decode("trailing\\", 9, buf, sizeof(buf)) == SIZE_MAX);
  /* measuring + truncation */
  CHECK(ztoml_str_decode("a\\nb", 4, NULL, 0) == 3);
  {
    char small[3];
    CHECK(ztoml_str_decode("abcde", 5, small, sizeof(small)) == 5);
    CHECK(strlen(small) == 2);
  }
}

/* ---- NULL safety ----------------------------------------------------------------------- */

static void test_null(void) {
  ztoml t;
  ztoml_ev ev;
  char buf[8];
  CHECK(ztoml_init(NULL, "x", 1) == ZTOML_ERR_ARG);
  CHECK(ztoml_init(&t, NULL, 1) == ZTOML_ERR_ARG);
  CHECK(ztoml_init(&t, NULL, 0) == ZTOML_OK); /* empty doc ok */
  CHECK(ztoml_next(&t, &ev) == ZTOML_OK && ev.kind == ZTOML_EV_DONE);
  CHECK(ztoml_next(NULL, &ev) == ZTOML_ERR_ARG);
  CHECK(ztoml_next(&t, NULL) == ZTOML_ERR_ARG);
  CHECK(ztoml_str_decode(NULL, 3, buf, sizeof(buf)) == SIZE_MAX);
  /* over-long doc */
  CHECK(ztoml_init(&t, "x", ZTOML_MAX + 1) == ZTOML_ERR_RANGE);
}

/* ---- fuzz -------------------------------------------------------------------------------- */

static uint64_t rng_state = 0x8F2A1B3C4D5E6F70ull;
static uint64_t rng_next(void) {
  rng_state ^= rng_state << 13;
  rng_state ^= rng_state >> 7;
  rng_state ^= rng_state << 17;
  return rng_state;
}

static void test_fuzz(void) {
  /* Generated documents: random sections/pairs of random scalar types
   * must parse to a balanced event stream. Mutated documents must
   * never crash the parser. */
  int trial;
  for (trial = 0; trial < 2500; trial++) {
    char doc[512];
    size_t n = 0, pairs = rng_next() % 8, k;
    int depth = 0;
    ztoml t;
    ztoml_ev ev;
    n += (size_t)snprintf(doc + n, sizeof(doc) - n, "[s%llu]\n",
                          (unsigned long long)(rng_next() % 1000));
    for (k = 0; k < pairs; k++) {
      switch (rng_next() % 6) {
      case 0: n += (size_t)snprintf(doc + n, sizeof(doc) - n,
                                    "k%zu = %lld\n", k,
                                    (long long)(int64_t)rng_next());
        break;
      case 1: n += (size_t)snprintf(doc + n, sizeof(doc) - n,
                                    "k%zu = %g\n", k,
                                    (double)(int64_t)(rng_next() % 1000) /
                                        4.0);
        break;
      case 2: n += (size_t)snprintf(doc + n, sizeof(doc) - n,
                                    "k%zu = \"v%zu\"\n", k, k);
        break;
      case 3: n += (size_t)snprintf(doc + n, sizeof(doc) - n,
                                    "k%zu = %s\n", k,
                                    (rng_next() & 1) ? "true" : "false");
        break;
      case 4: n += (size_t)snprintf(doc + n, sizeof(doc) - n,
                                    "k%zu = [1, 2, [3]]\n", k);
        break;
      default: n += (size_t)snprintf(doc + n, sizeof(doc) - n,
                                     "# comment %zu\n", k);
        break;
      }
    }
    /* generated: must parse clean and balanced */
    CHECK(ztoml_init(&t, doc, n) == ZTOML_OK);
    for (;;) {
      ztoml_err e = ztoml_next(&t, &ev);
      CHECK(e == ZTOML_OK);
      if (ev.kind == ZTOML_EV_ARR_OPEN) depth++;
      if (ev.kind == ZTOML_EV_ARR_CLOSE) depth--;
      CHECK(depth >= 0 && depth <= (int)ZTOML_MAX_DEPTH);
      if (ev.kind == ZTOML_EV_DONE) break;
    }
    CHECK(depth == 0);
    /* mutated: corrupt random bytes, must never crash */
    {
      char mut[512];
      memcpy(mut, doc, n + 1);
      mut[rng_next() % (n ? n : 1)] = (char)(rng_next() % 256);
      if (n > 2) mut[rng_next() % n] = (char)(rng_next() % 256);
      ztoml_init(&t, mut, n);
      while (ztoml_next(&t, &ev) == ZTOML_OK && ev.kind != ZTOML_EV_DONE)
        ;
    }
  }
}

int main(void) {
  test_kat();
  test_types();
  test_arr();
  test_err();
  test_decode();
  test_null();
  test_fuzz();
  if (g_fail) {
    fprintf(stderr, "test_ztoml: FAILURES\n");
    return 1;
  }
  printf("test_ztoml: all groups passed (kat types arr err decode null fuzz)\n");
  return 0;
}
