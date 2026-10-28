/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: KAT, grammar, bounds, decode, and property tests for
 *          zjsonp. Round-trip property: anything the zjson writer
 *          (companion package) emits must parse here, event for
 *          event. */
#include "zjsonp/zjsonp.h"

#include <stdio.h>
#include <string.h>

#define main zjsonp_cli_main
#include "../app/main.c"
#undef main

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

static int test_string_error_offsets(void) {
  static const struct { const char *text; size_t pos; } rows[] = {
    {"\"a\001b\"", 2},
    {"\"a\\q\"", 3},
    {"\"a\\u0X00\"", 5},
    {"\"abc", 4},
    {"\"a\x80\"", 2},
    {"\"a\\u00", 6},
    {"\"a\\", 3},
    {"-", 1}, {"1.", 2}, {"1e", 2}, {"1e+", 3},
    {"1eX", 2}, {"truX", 3}, {"nul", 3}
  };
  int failures = 0;
  for (size_t i = 0; i < sizeof rows / sizeof rows[0]; i++) {
    zjsonp parser;
    zjsonp_event event;
    zjsonp_init(&parser, rows[i].text, strlen(rows[i].text));
    if (!(zjsonp_next(&parser, &event) == ZJRP_SYNTAX &&
          zjsonp_pos(&parser) == rows[i].pos)) {
      fprintf(stderr, "FAIL token offset row %zu: expected %zu, got %zu\n",
              i, rows[i].pos, zjsonp_pos(&parser));
      failures++;
    }
  }
  return failures != 0;
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

static int test_decode_raw_utf8(void) {
  static const struct {
    const char *doc;
    const char *want;
  } cases[] = {
      {"\"\xc3\xa9\"", "\xc3\xa9"},
      {"\"\xe2\x82\xac\"", "\xe2\x82\xac"},
      {"\"\xf0\x9f\x98\x80\"", "\xf0\x9f\x98\x80"},
      {"\"A\xc3\xa9\\n\\u20ac\xf0\x9f\x98\x80\"",
       "A\xc3\xa9\n\xe2\x82\xac\xf0\x9f\x98\x80"},
      {"\"\\u00e9\\u20ac\\ud83d\\ude00\"",
       "\xc3\xa9\xe2\x82\xac\xf0\x9f\x98\x80"},
  };
  for (size_t i = 0; i < sizeof cases / sizeof cases[0]; i++) {
    zjsonp_event evs[4];
    size_t n = 0, want_len = strlen(cases[i].want);
    CHECK(slurp(cases[i].doc, evs, 4, &n) == ZJRP_DONE && n == 1);
    /* Measurement alone fails on the base: e.g. raw U+00E9 becomes 4 bytes. */
    CHECK(zjsonp_str_decode(cases[i].doc, &evs[0], NULL, 0) == want_len);
    for (size_t cap = 0; cap <= want_len + 1; cap++) {
      char out[32];
      memset(out, 0x5a, sizeof out);
      CHECK(zjsonp_str_decode(cases[i].doc, &evs[0], out, cap) == want_len);
      size_t written = cap < want_len ? cap : want_len;
      CHECK(memcmp(out, cases[i].want, written) == 0);
      for (size_t k = written; k < sizeof out; k++)
        CHECK(out[k] == 0x5a); /* no terminator or write past the byte prefix */
    }
  }
  /* The same decoding path applies to raw UTF-8 object keys. */
  const char *doc = "{\"\xc3\xa9\":0}";
  zjsonp_event evs[4];
  size_t n = 0;
  char out[4] = {0};
  CHECK(slurp(doc, evs, 4, &n) == ZJRP_DONE && n == 4);
  CHECK(evs[1].kind == ZJRP_KEY);
  CHECK(zjsonp_str_decode(doc, &evs[1], out, sizeof out) == 2);
  CHECK(memcmp(out, "\xc3\xa9", 2) == 0);
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

/* Map a pick value to a random string or number token, or NULL for
 * a container pick. */
static const char *gen_pick_scalar(unsigned pick) {
  static const char *strs[] = {"\"\"", "\"abc\"", "\"a\\nb\"",
                               "\"\\u00e9\"", "\"h\xc3\xa9\""};
  static const char *nums[] = {"0", "-1", "42", "1.5", "-2.5e-3",
                               "1e300", "9223372036854775807"};
  if (pick < 2)
    return strs[rnd() % 5];
  if (pick < 4)
    return nums[rnd() % 7];
  return NULL;
}

/* Append a scalar token if it fits in cap; returns the resulting length. */
static size_t gen_append_scalar(char *buf, size_t n, size_t cap,
                                const char *s) {
  size_t sl = strlen(s);
  if (n + sl >= cap)
    return n;
  memcpy(buf + n, s, sl);
  return n + sl;
}

/* Append the ',' between generated list elements when there is room. */
static size_t gen_comma(char *buf, size_t n, size_t cap, unsigned i) {
  if (i && n < cap)
    buf[n++] = ',';
  return n;
}

/* Append a random valid JSON value to buf, depth-bounded. */
static size_t gen_value(char *buf, size_t n, size_t cap, unsigned depth) {
  unsigned pick = depth >= 5 ? rnd() % 4 : rnd() % 6;
  const char *s = gen_pick_scalar(pick);
  if (s)
    return gen_append_scalar(buf, n, cap, s);
  if (pick == 4) { /* array */
    if (n + 2 >= cap)
      return n;
    buf[n++] = '[';
    unsigned elems = rnd() % 4;
    for (unsigned i = 0; i < elems; i++) {
      n = gen_comma(buf, n, cap, i);
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
    n = gen_comma(buf, n, cap, i);
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

static int test_terminal_syntax(void) {
  const char doc[] = "{\"\xff\"\"valid\":1}";
  zjsonp p;
  zjsonp_event ev;
  zjsonp_init(&p, doc, sizeof doc - 1);
  if (zjsonp_next(&p, &ev) != ZJRP_OK ||
      zjsonp_next(&p, &ev) != ZJRP_SYNTAX) return 1;
  CHECK(zjsonp_next(&p, &ev) == ZJRP_SYNTAX);
  return 0;
}

static int test_negative_zero_integer(void) {
  const char doc[] = "-0";
  zjsonp p;
  zjsonp_event ev;
  int64_t value = 123;
  zjsonp_init(&p, doc, sizeof doc - 1);
  if (zjsonp_next(&p, &ev) != ZJRP_OK) return 1;
  CHECK(zjsonp_num_i64(doc, &ev, &value) && value == 0);
  return 0;
}

static bool cli_text_input(FILE *source) {
  rewind(source);
#if defined(_WIN32)
  return _setmode(_fileno(source), _O_TEXT) != -1;
#else
  return true;
#endif
}

static bool cli_preserves_bytes(FILE *source, const char *bytes, size_t size) {
  size_t len = 0;
  return cli_read(source, &len) && len == size && memcmp(input, bytes, size) == 0;
}

static int test_cli_binary_input(void) {
  const char bytes[] = {'0', '\r', '\n', 0x1a, 'x'};
  FILE *source = tmpfile(), *output = tmpfile();
  int failed = 1;
  if (!source || !output) goto cleanup;
  if (fwrite(bytes, 1, sizeof bytes, source) != sizeof bytes ||
      fflush(source) != 0) goto cleanup;
  if (!cli_text_input(source) || !cli_preserves_bytes(source, bytes, sizeof bytes))
    goto cleanup;
  if (!cli_text_input(source) || cli_run(source, output) != 1) goto cleanup;
  failed = 0;
cleanup:
  if (source && fclose(source) != 0) failed = 1;
  if (output && fclose(output) != 0) failed = 1;
  return failed;
}

static bool cli_boundary_document(FILE *source, size_t size, char last) {
  char spaces[4096];
  memset(spaces, ' ', sizeof spaces);
  if (fputc('0', source) == EOF) return false;
  size -= 2;
  while (size) {
    size_t n = size < sizeof spaces ? size : sizeof spaces;
    if (fwrite(spaces, 1, n, source) != n) return false;
    size -= n;
  }
  if (fputc(last, source) == EOF || fflush(source) != 0) return false;
  rewind(source);
  return true;
}

static int cli_boundary_case(size_t size, char last, int expected) {
  FILE *source = tmpfile();
  FILE *output = tmpfile();
  int failed = 1;
  if (!source || !output) goto cleanup;
  if (!cli_boundary_document(source, size, last)) goto cleanup;
  if (cli_run(source, output) != expected) goto cleanup;
  if (expected == 2 && ftell(output) != 0) goto cleanup;
  failed = 0;
cleanup:
  if (source && fclose(source) != 0) failed = 1;
  if (output && fclose(output) != 0) failed = 1;
  return failed;
}

static int test_cli_input_bound(void) {
  CHECK(cli_boundary_case(MAX_INPUT - 1, ' ', 0) == 0);
  CHECK(cli_boundary_case(MAX_INPUT, ' ', 0) == 0);
  CHECK(cli_boundary_case(MAX_INPUT + 1, ' ', 2) == 0);
  CHECK(cli_boundary_case(MAX_INPUT, 'x', 1) == 0);
  return 0;
}

static bool cli_output_matches(FILE *source, FILE *output) {
  if (cli_run(source, output) != 0) return false;
  rewind(output);
  char buf[64] = {0};
  size_t n = fread(buf, 1, sizeof buf - 1, output);
  return !ferror(output) && n == strlen("obj-open\nobj-close\n") &&
         strcmp(buf, "obj-open\nobj-close\n") == 0;
}

static int test_cli_output(void) {
  FILE *source = tmpfile();
  FILE *output = tmpfile();
  /* A compiler-mapped source path need not exist at the test's cwd. */
#if defined(_WIN32)
  FILE *readonly = fopen("NUL", "r");
#else
  FILE *readonly = fopen("/dev/null", "r");
#endif
  int failed = 1;
  if (!source || !output || !readonly) goto cleanup;
  if (fputs("{}", source) == EOF || fflush(source) != 0) goto cleanup;
  rewind(source);
  if (!cli_output_matches(source, output)) goto cleanup;
  rewind(source);
  if (cli_run(source, readonly) != 2 || !ferror(readonly)) goto cleanup;
  failed = 0;
cleanup:
  if (source && fclose(source) != 0) failed = 1;
  if (output && fclose(output) != 0) failed = 1;
  if (readonly) (void)fclose(readonly);
  return failed;
}

static int test_phase_boundaries(void) {
  const char *doc = "{\"n\":-12.5e+2,\"s\":\"\\ud83d\\ude00\"}";
  static const struct { zjsonp_event_kind kind; size_t off, len; } want[] = {
    {ZJRP_OBJ_OPEN, 0, 0}, {ZJRP_KEY, 2, 1}, {ZJRP_NUM, 5, 8},
    {ZJRP_KEY, 15, 1}, {ZJRP_STR, 19, 12}, {ZJRP_OBJ_CLOSE, 32, 0}
  };
  zjsonp p;
  zjsonp_init(&p, doc, strlen(doc));
  for (size_t i = 0; i < sizeof want / sizeof want[0]; i++) {
    zjsonp_event ev;
    CHECK(zjsonp_next(&p, &ev) == ZJRP_OK);
    CHECK(ev.kind == want[i].kind && ev.off == want[i].off && ev.len == want[i].len);
  }
  zjsonp_event ev;
  CHECK(zjsonp_next(&p, &ev) == ZJRP_DONE);
  zjsonp_init(&p, "[1e+]", 5);
  CHECK(zjsonp_next(&p, &ev) == ZJRP_OK);
  CHECK(zjsonp_next(&p, &ev) == ZJRP_SYNTAX && zjsonp_pos(&p) == 4);
  CHECK(zjsonp_next(&p, &ev) == ZJRP_SYNTAX && zjsonp_pos(&p) == 4);
  return 0;
}

static int test_bad_surrogate_pairs(void) {
  static const char *const docs[] = {"\"\\udc00\"", "\"\\ud800\\u0041\""};
  for (size_t i = 0; i < sizeof docs / sizeof docs[0]; i++) {
    zjsonp_event events[2];
    size_t n = 0;
    CHECK(slurp(docs[i], events, 2, &n) == ZJRP_DONE && n == 1);
    CHECK(zjsonp_str_decode(docs[i], &events[0], NULL, 0) == SIZE_MAX);
  }
  return 0;
}

int main(void) {
  struct {
    const char *name;
    int (*fn)(void);
  } tests[] = {
      {"cli_binary_input", test_cli_binary_input},
      {"cli_output", test_cli_output},
      {"cli_input_bound", test_cli_input_bound},
      {"terminal_syntax", test_terminal_syntax},
      {"phase_boundaries", test_phase_boundaries},
      {"bad_surrogate_pairs", test_bad_surrogate_pairs},
      {"negative_zero_integer", test_negative_zero_integer},
      {"kat", test_kat},       {"syntax_errors", test_syntax_errors},
      {"utf8", test_utf8},     {"decode", test_decode},
      {"decode_raw_utf8", test_decode_raw_utf8},
      {"numbers", test_numbers}, {"depth", test_depth},
      {"pos_and_null", test_pos_and_null}, {"fuzz", test_fuzz},
  };
  for (size_t i = 0; i < sizeof tests / sizeof tests[0]; i++) {
    if (tests[i].fn() != 0) {
      fprintf(stderr, "test %s FAILED\n", tests[i].name);
      return 1;
    }
  }
  if (test_string_error_offsets()) return 1;
  printf("all %zu zjsonp tests passed\n", sizeof tests / sizeof tests[0]);
  return 0;
}
