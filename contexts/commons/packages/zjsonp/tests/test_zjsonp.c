/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: KAT, grammar, bounds, decode, and property tests for
 *          zjsonp. Round-trip property: anything the zjson writer
 *          (companion package) emits must parse here, event for
 *          event. */
#include "zjsonp/zjsonp.h"

#include <stdio.h>
#include <string.h>

#define CHECK(cond)                                                          \
  do {                                                                       \
    if (!(cond)) {                                                           \
      fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);        \
      return 1;                                                              \
    }                                                                        \
  } while (0)

/* Collect all events; returns the terminal status. */
static zjsonp_status slurp(const char *doc, zjsonp_event *evs,
                           size_t cap, size_t *n_out) {
  zjsonp p;
  zjsonp_init(&p, doc, strlen(doc));
  size_t n = 0;
  for (;;) {
    zjsonp_event ev;
    zjsonp_status st = zjsonp_next(&p, &ev);
    if (st != ZJRP_OK) {
      *n_out = n;
      return st;
    }
    if (n < cap)
      evs[n] = ev;
    n++;
  }
}

static int test_kat(void) {
  zjsonp_event evs[32];
  size_t n = 0;
  {
    CHECK(slurp("{}", evs, 32, &n) == ZJRP_DONE);
    CHECK(n == 2 && evs[0].kind == ZJRP_OBJ_OPEN &&
          evs[1].kind == ZJRP_OBJ_CLOSE);
  }
  {
    CHECK(slurp("[]", evs, 32, &n) == ZJRP_DONE);
    CHECK(n == 2 && evs[0].kind == ZJRP_ARR_OPEN &&
          evs[1].kind == ZJRP_ARR_CLOSE);
  }
  {
    CHECK(slurp("{\"a\":1,\"b\":[true,null,\"x\"]}", evs, 32, &n) ==
          ZJRP_DONE);
    CHECK(n == 10);
    CHECK(evs[0].kind == ZJRP_OBJ_OPEN);
    CHECK(evs[1].kind == ZJRP_KEY && evs[1].len == 1);
    CHECK(evs[2].kind == ZJRP_NUM && evs[2].len == 1);
    CHECK(evs[3].kind == ZJRP_KEY);
    CHECK(evs[4].kind == ZJRP_ARR_OPEN);
    CHECK(evs[5].kind == ZJRP_BOOL && evs[5].len == 4);
    CHECK(evs[6].kind == ZJRP_NULL);
    CHECK(evs[7].kind == ZJRP_STR && evs[7].len == 1);
    CHECK(evs[8].kind == ZJRP_ARR_CLOSE);
    CHECK(evs[9].kind == ZJRP_OBJ_CLOSE);
  }
  {
    /* whitespace everywhere it is allowed */
    CHECK(slurp(" { \n\t\"a\" : [ 1 , 2 ] \r\n}  \n", evs, 32, &n) ==
          ZJRP_DONE);
    CHECK(n == 7);
  }
  {
    /* scalars at the top level */
    CHECK(slurp("42", evs, 32, &n) == ZJRP_DONE && n == 1 &&
          evs[0].kind == ZJRP_NUM);
    CHECK(slurp(" \"hi\" ", evs, 32, &n) == ZJRP_DONE && n == 1);
    CHECK(slurp("true", evs, 32, &n) == ZJRP_DONE && n == 1);
  }
  return 0;
}

static int test_syntax_errors(void) {
  static const char *bad[] = {
      "",           /* empty input */
      "  ",         /* whitespace only */
      "{",          /* unterminated */
      "[1,2",       /* unterminated */
      "{\"a\":}",   /* key with no value */
      "{\"a\" 1}",  /* missing colon */
      "{a:1}",      /* unquoted key */
      "[1,]",       /* trailing comma */
      "{\"a\":1,}", /* trailing comma in object */
      "[,1]",       /* leading comma */
      "[1 2]",      /* missing comma */
      "[1]x",       /* trailing garbage */
      "1 2",        /* two top-level values */
      "[01]",       /* leading zero */
      "[-]",        /* bare minus */
      "[1.]",       /* bare fraction point */
      "[1e]",       /* bare exponent */
      "[+1]",       /* leading plus */
      "[.5]",       /* bare point */
      "['x']",      /* single quotes */
      "[\"a",       /* unterminated string */
      "[\"a\x01\"]", /* raw control byte */
      "[\"\\x\"]",  /* bad escape */
      "[\"\\u12\"]", /* short unicode escape */
      "[\"\\u12xz\"]", /* bad hex */
      "[tru]",      /* bad literal */
      "[nulL]",     /* case */
      "{]",         /* mismatched close */
      "[}",         /* mismatched close */
      "{\"a\":1}}", /* extra close */
  };
  for (size_t i = 0; i < sizeof bad / sizeof bad[0]; i++) {
    zjsonp p;
    zjsonp_init(&p, bad[i], strlen(bad[i]));
    zjsonp_event ev;
    zjsonp_status st = ZJRP_OK;
    unsigned guard = 0;
    while (st == ZJRP_OK && guard++ < 1000)
      st = zjsonp_next(&p, &ev);
    if (st != ZJRP_SYNTAX) {
      fprintf(stderr, "FAIL syntax case %zu (%s): got %s\n", i, bad[i],
              zjsonp_status_name(st));
      return 1;
    }
  }
  return 0;
}

static int test_utf8(void) {
  zjsonp_event evs[8];
  size_t n = 0;
  /* valid multibyte strings pass */
  CHECK(slurp("[\"h\xc3\xa9llo\",\"\xe2\x82\xac\",\"\xf0\x9f\x98\x80\"]",
              evs, 8, &n) == ZJRP_DONE);
  CHECK(n == 5);
  /* invalid UTF-8 in a string is a syntax error */
  const char bad[] = {'[', '"', (char)0xc0, (char)0xaf, '"', ']', 0};
  zjsonp p;
  zjsonp_init(&p, bad, 6);
  zjsonp_event ev;
  CHECK(zjsonp_next(&p, &ev) == ZJRP_OK); /* arr open */
  CHECK(zjsonp_next(&p, &ev) == ZJRP_SYNTAX);
  return 0;
}

static int test_decode(void) {
  char out[64];
  {
    zjsonp_event evs[4];
    size_t n = 0;
    CHECK(slurp("\"a\\nb\\t\\u0041\\u00e9\\u20ac\"", evs, 4, &n) ==
          ZJRP_DONE);
    size_t dn = zjsonp_str_decode("\"a\\nb\\t\\u0041\\u00e9\\u20ac\"",
                                  &evs[0], out, sizeof out);
    CHECK(dn == strlen("a\nb\tA\xc3\xa9\xe2\x82\xac"));
    CHECK(memcmp(out, "a\nb\tA\xc3\xa9\xe2\x82\xac", dn) == 0);
  }
  {
    /* surrogate pair decodes to one code point */
    zjsonp_event evs[4];
    size_t n = 0;
    const char *doc = "\"\\ud83d\\ude00\""; /* U+1F600 */
    CHECK(slurp(doc, evs, 4, &n) == ZJRP_DONE);
    size_t dn = zjsonp_str_decode(doc, &evs[0], out, sizeof out);
    CHECK(dn == 4 && memcmp(out, "\xf0\x9f\x98\x80", 4) == 0);
  }
  {
    /* lone surrogates rejected at decode */
    zjsonp_event evs[4];
    size_t n = 0;
    const char *doc = "\"\\ud83d x\"";
    CHECK(slurp(doc, evs, 4, &n) == ZJRP_DONE); /* raw scan passes */
    CHECK(zjsonp_str_decode(doc, &evs[0], out, sizeof out) == SIZE_MAX);
  }
  {
    /* measuring: cap 0 returns the needed length */
    zjsonp_event evs[4];
    size_t n = 0;
    const char *doc = "\"ab\\u0041\"";
    CHECK(slurp(doc, evs, 4, &n) == ZJRP_DONE);
    CHECK(zjsonp_str_decode(doc, &evs[0], NULL, 0) == 3);
    CHECK(zjsonp_str_decode(doc, &evs[0], out, 2) == 3);
    CHECK(out[0] == 'a' && out[1] == 'b'); /* partial write bounded */
  }
  {
    /* decode rejects non-string events and NULL args */
    zjsonp_event ev = {ZJRP_NUM, 0, 1};
    CHECK(zjsonp_str_decode("1", &ev, out, 64) == SIZE_MAX);
    CHECK(zjsonp_str_decode(NULL, &ev, out, 64) == SIZE_MAX);
  }
  return 0;
}

static int test_numbers(void) {
  zjsonp_event evs[4];
  size_t n = 0;
  int64_t iv;
  double dv;
  {
    CHECK(slurp("-9223372036854775808", evs, 4, &n) == ZJRP_DONE);
    CHECK(zjsonp_num_i64("-9223372036854775808", &evs[0], &iv));
    CHECK(iv == INT64_MIN);
  }
  {
    const char *doc = "9223372036854775807";
    CHECK(slurp(doc, evs, 4, &n) == ZJRP_DONE);
    CHECK(zjsonp_num_i64(doc, &evs[0], &iv) && iv == INT64_MAX);
  }
  {
    const char *doc = "9223372036854775808"; /* overflow */
    CHECK(slurp(doc, evs, 4, &n) == ZJRP_DONE);
    CHECK(!zjsonp_num_i64(doc, &evs[0], &iv));
  }
  {
    const char *doc = "1.5";
    CHECK(slurp(doc, evs, 4, &n) == ZJRP_DONE);
    CHECK(!zjsonp_num_i64(doc, &evs[0], &iv)); /* fraction is not i64 */
    CHECK(zjsonp_num_f64(doc, &evs[0], &dv) && dv == 1.5);
  }
  {
    const char *doc = "[-0,1e300,-2.5e-3]";
    CHECK(slurp(doc, evs, 4, &n) == ZJRP_DONE && n == 5);
    CHECK(zjsonp_num_f64(doc, &evs[1], &dv) && dv == 0.0 &&
          1.0 / dv < 0); /* negative zero preserved */
    CHECK(zjsonp_num_f64(doc, &evs[2], &dv) && dv == 1e300);
    CHECK(zjsonp_num_f64(doc, &evs[3], &dv) && dv == -2.5e-3);
  }
  {
    /* NULL and kind misuse */
    zjsonp_event ev = {ZJRP_STR, 0, 1};
    CHECK(!zjsonp_num_i64("1", &ev, &iv));
    CHECK(!zjsonp_num_f64("1", NULL, &dv));
  }
  return 0;
}

static int test_depth(void) {
  /* 32 levels parse; the 33rd fails with ZJRP_DEPTH */
  char doc[2 * (ZJRP_MAX_DEPTH + 2) + 1];
  for (int i = 0; i < ZJRP_MAX_DEPTH; i++)
    doc[i] = '[';
  for (int i = 0; i < ZJRP_MAX_DEPTH; i++)
    doc[ZJRP_MAX_DEPTH + i] = ']';
  doc[2 * ZJRP_MAX_DEPTH] = '\0';
  zjsonp_event evs[2 * ZJRP_MAX_DEPTH + 2];
  size_t n = 0;
  CHECK(slurp(doc, evs, 2 * ZJRP_MAX_DEPTH + 2, &n) == ZJRP_DONE);
  CHECK(n == 2 * ZJRP_MAX_DEPTH);

  char deep[2 * (ZJRP_MAX_DEPTH + 2) + 2];
  for (int i = 0; i < ZJRP_MAX_DEPTH + 1; i++)
    deep[i] = '[';
  deep[ZJRP_MAX_DEPTH + 1] = '\0';
  zjsonp p;
  zjsonp_init(&p, deep, strlen(deep));
  zjsonp_event ev;
  zjsonp_status st = ZJRP_OK;
  while (st == ZJRP_OK)
    st = zjsonp_next(&p, &ev);
  CHECK(st == ZJRP_DEPTH);
  return 0;
}

static int test_pos_and_null(void) {
  zjsonp p;
  zjsonp_init(&p, "[1,x]", 5);
  zjsonp_event ev;
  CHECK(zjsonp_next(&p, &ev) == ZJRP_OK);
  CHECK(zjsonp_next(&p, &ev) == ZJRP_OK);
  CHECK(zjsonp_next(&p, &ev) == ZJRP_SYNTAX);
  CHECK(zjsonp_pos(&p) == 3); /* at the 'x' */
  CHECK(zjsonp_next(NULL, &ev) == ZJRP_SYNTAX);
  CHECK(zjsonp_next(&p, NULL) == ZJRP_SYNTAX);
  CHECK(zjsonp_pos(NULL) == 0);
  zjsonp_init(NULL, "x", 1); /* no crash */
  CHECK(strcmp(zjsonp_status_name(ZJRP_DEPTH), "depth") == 0);
  return 0;
}

static uint64_t rng_state = 0x6a09e667f3bcc909ull;
static uint64_t rnd(void) {
  rng_state ^= rng_state << 13;
  rng_state ^= rng_state >> 7;
  rng_state ^= rng_state << 17;
  return rng_state;
}

/* Append a random valid JSON value to buf, depth-bounded. */
static size_t gen_value(char *buf, size_t n, size_t cap, unsigned depth) {
  static const char *strs[] = {"\"\"", "\"abc\"", "\"a\\nb\"",
                               "\"\\u00e9\"", "\"h\xc3\xa9\""};
  static const char *nums[] = {"0", "-1", "42", "1.5", "-2.5e-3",
                               "1e300", "9223372036854775807"};
  unsigned pick = depth >= 5 ? rnd() % 4 : rnd() % 6;
  const char *s = NULL;
  if (pick < 2)
    s = strs[rnd() % 5];
  else if (pick < 4)
    s = nums[rnd() % 7];
  if (s) {
    size_t sl = strlen(s);
    if (n + sl >= cap)
      return n;
    memcpy(buf + n, s, sl);
    return n + sl;
  }
  if (pick == 4) { /* array */
    if (n + 2 >= cap)
      return n;
    buf[n++] = '[';
    unsigned elems = rnd() % 4;
    for (unsigned i = 0; i < elems; i++) {
      if (i && n < cap)
        buf[n++] = ',';
      n = gen_value(buf, n, cap, depth + 1);
    }
    if (n < cap)
      buf[n++] = ']';
    return n;
  }
  /* object */
  if (n + 2 >= cap)
    return n;
  buf[n++] = '{';
  unsigned elems = rnd() % 4;
  for (unsigned i = 0; i < elems; i++) {
    if (i && n < cap)
      buf[n++] = ',';
    if (n + 4 < cap) {
      n += (size_t)snprintf(buf + n, cap - n, "\"k%u\":",
                            (unsigned)(rnd() % 100));
      n = gen_value(buf, n, cap, depth + 1);
    }
  }
  if (n < cap)
    buf[n++] = '}';
  return n;
}

static int test_fuzz(void) {
  static char doc[4096];
  zjsonp_event evs[512];
  for (unsigned trial = 0; trial < 4000; trial++) {
    size_t len = gen_value(doc, 0, sizeof doc - 1, 0);
    doc[len] = '\0';
    size_t n = 0;
    zjsonp_status st = slurp(doc, evs, 512, &n);
    if (st != ZJRP_DONE) {
      fprintf(stderr, "FAIL fuzz trial %u: %s: %s\n", trial,
              zjsonp_status_name(st), doc);
      return 1;
    }
    /* balance: opens == closes */
    size_t opens = 0, closes = 0;
    for (size_t i = 0; i < n; i++) {
      if (evs[i].kind == ZJRP_OBJ_OPEN || evs[i].kind == ZJRP_ARR_OPEN)
        opens++;
      if (evs[i].kind == ZJRP_OBJ_CLOSE || evs[i].kind == ZJRP_ARR_CLOSE)
        closes++;
    }
    CHECK(opens == closes);

    /* mutate: flip one byte; parser must terminate cleanly */
    if (len > 0) {
      doc[rnd() % len] = (char)(rnd() & 0xff);
      zjsonp p;
      zjsonp_init(&p, doc, len);
      zjsonp_event ev;
      zjsonp_status mst = ZJRP_OK;
      unsigned guard = 0;
      while (mst == ZJRP_OK && guard++ < 2000)
        mst = zjsonp_next(&p, &ev);
      CHECK(mst == ZJRP_DONE || mst == ZJRP_SYNTAX ||
            mst == ZJRP_DEPTH);
      (void)mst;
    }
  }
  return 0;
}

int main(void) {
  struct {
    const char *name;
    int (*fn)(void);
  } tests[] = {
      {"kat", test_kat},       {"syntax_errors", test_syntax_errors},
      {"utf8", test_utf8},     {"decode", test_decode},
      {"numbers", test_numbers}, {"depth", test_depth},
      {"pos_and_null", test_pos_and_null}, {"fuzz", test_fuzz},
  };
  for (size_t i = 0; i < sizeof tests / sizeof tests[0]; i++) {
    if (tests[i].fn() != 0) {
      fprintf(stderr, "test %s FAILED\n", tests[i].name);
      return 1;
    }
  }
  printf("all %zu zjsonp tests passed\n", sizeof tests / sizeof tests[0]);
  return 0;
}
