/* Tests for zbits — fixed-size bitset.
 * Groups: basic, bulk, rank, first, ops, err, fuzz. */
#include "zbits/zbits.h"

#include <stdio.h>
#include <string.h>

static FILE *cli_sink, *cli_errors;
static FILE *cli_real_stdout(void) { return stdout; }
static FILE *cli_real_stderr(void) { return stderr; }
static unsigned cli_output_flushes;
static int cli_fflush(FILE *stream) {
  if (stream == cli_sink) cli_output_flushes++;
  return fflush(stream);
}
#undef stdout
#undef stderr
#define stdout cli_sink
#define stderr cli_errors
#define printf(...) fprintf(cli_sink, __VA_ARGS__)
#define putchar(c) fputc((c), cli_sink)
#define fflush cli_fflush
#define main zbits_cli_main
#include "../app/main.c"
#undef main
#undef putchar
#undef fflush
#undef printf
#undef stderr
#undef stdout
/* UCRT exposes these streams only as macros. Restore test diagnostics and
 * stream ownership through accessors captured before the app mappings. */
#define stdout cli_real_stdout()
#define stderr cli_real_stderr()

static int g_fail = 0;
#define CHECK(cond)                                                     \
  do {                                                                  \
    if (!(cond)) {                                                      \
      fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);   \
      g_fail = 1;                                                       \
    }                                                                   \
  } while (0)

#define NB 130 /* deliberately crosses 3 words + partial tail */

static void test_basic(void) {
  uint64_t w[3];
  CHECK(zbits_words(NB) == 3);
  CHECK(zbits_init(w, NB) == ZBITS_OK);
  CHECK(zbits_count(w, NB) == 0);
  CHECK(zbits_set(w, NB, 0) == ZBITS_OK);
  CHECK(zbits_set(w, NB, 63) == ZBITS_OK);
  CHECK(zbits_set(w, NB, 64) == ZBITS_OK);
  CHECK(zbits_set(w, NB, NB - 1) == ZBITS_OK);
  CHECK(zbits_count(w, NB) == 4);
  CHECK(zbits_test(w, NB, 0) == 1 && zbits_test(w, NB, 1) == 0);
  CHECK(zbits_test(w, NB, NB - 1) == 1);
  CHECK(zbits_flip(w, NB, 0) == ZBITS_OK && zbits_test(w, NB, 0) == 0);
  CHECK(zbits_clear(w, NB, NB - 1) == ZBITS_OK &&
        zbits_test(w, NB, NB - 1) == 0);
  CHECK(zbits_count(w, NB) == 2);
  CHECK(zbits_set(w, NB, NB) == ZBITS_ERR_RANGE);
  CHECK(zbits_test(w, NB, NB) == -1);
}

static void test_bulk(void) {
  uint64_t w[3];
  zbits_init(w, NB);
  CHECK(zbits_set_all(w, NB) == ZBITS_OK);
  CHECK(zbits_count(w, NB) == NB); /* tail trimmed */
  CHECK(zbits_first_clear(w, NB) == SIZE_MAX);
  CHECK(zbits_flip_all(w, NB) == ZBITS_OK);
  CHECK(zbits_count(w, NB) == 0);
  CHECK(zbits_first_set(w, NB) == SIZE_MAX);
  CHECK(zbits_flip_all(w, NB) == ZBITS_OK);
  CHECK(zbits_count(w, NB) == NB);
  CHECK(zbits_clear_all(w, NB) == ZBITS_OK);
  CHECK(zbits_count(w, NB) == 0);
}

static void test_rank_first(void) {
  uint64_t w[3];
  size_t i;
  zbits_init(w, NB);
  zbits_set(w, NB, 5);
  zbits_set(w, NB, 64);
  zbits_set(w, NB, 100);
  CHECK(zbits_first_set(w, NB) == 5);
  CHECK(zbits_first_clear(w, NB) == 0);
  CHECK(zbits_rank(w, NB, 0) == 0);
  CHECK(zbits_rank(w, NB, 5) == 0);
  CHECK(zbits_rank(w, NB, 6) == 1);
  CHECK(zbits_rank(w, NB, 64) == 1);
  CHECK(zbits_rank(w, NB, 65) == 2);
  CHECK(zbits_rank(w, NB, 101) == 3);
  CHECK(zbits_rank(w, NB, NB) == 3);
  /* rank over full range matches test() sum */
  {
    size_t sum = 0;
    for (i = 0; i < NB; i++) sum += (size_t)zbits_test(w, NB, i);
    CHECK(zbits_rank(w, NB, NB) == sum);
  }
}

static void test_ops(void) {
  uint64_t a[3], b[3], d[3];
  zbits_init(a, NB);
  zbits_init(b, NB);
  zbits_set(a, NB, 1);
  zbits_set(a, NB, 70);
  zbits_set(b, NB, 70);
  zbits_set(b, NB, 129);
  CHECK(zbits_or(d, a, b, NB) == ZBITS_OK);
  CHECK(zbits_count(d, NB) == 3);
  CHECK(zbits_test(d, NB, 1) == 1 && zbits_test(d, NB, 129) == 1);
  CHECK(zbits_and(d, a, b, NB) == ZBITS_OK);
  CHECK(zbits_count(d, NB) == 1 && zbits_test(d, NB, 70) == 1);
  CHECK(zbits_andnot(d, a, b, NB) == ZBITS_OK);
  CHECK(zbits_count(d, NB) == 1 && zbits_test(d, NB, 1) == 1);
  /* aliasing */
  CHECK(zbits_and(a, a, b, NB) == ZBITS_OK);
  CHECK(zbits_count(a, NB) == 1 && zbits_test(a, NB, 70) == 1);
}

static void test_err(void) {
  uint64_t w[3];
  CHECK(zbits_words(0) == SIZE_MAX);
  CHECK(zbits_init(NULL, NB) == ZBITS_ERR_ARG);
  CHECK(zbits_init(w, 0) == ZBITS_ERR_ARG);
  CHECK(zbits_init(w, ZBITS_MAX + 1) == ZBITS_ERR_ARG);
  CHECK(zbits_set(NULL, NB, 0) == ZBITS_ERR_ARG);
  CHECK(zbits_clear(w, NB, NB) == ZBITS_ERR_RANGE);
  CHECK(zbits_flip(w, NB, NB + 5) == ZBITS_ERR_RANGE);
  CHECK(zbits_count(NULL, NB) == SIZE_MAX);
  CHECK(zbits_rank(w, NB, NB + 1) == SIZE_MAX);
  CHECK(zbits_first_set(NULL, NB) == SIZE_MAX);
  CHECK(zbits_or(w, w, NULL, NB) == ZBITS_ERR_ARG);
  CHECK(zbits_and(NULL, w, w, NB) == ZBITS_ERR_ARG);
}

/* ---- fuzz against a byte-array model --------------------------------------- */

static uint64_t rng_state = 0x9E3779B97F4A7C15ull;
static uint64_t rng_next(void) {
  rng_state ^= rng_state << 13;
  rng_state ^= rng_state >> 7;
  rng_state ^= rng_state << 17;
  return rng_state;
}

static void test_fuzz(void) {
  int trial;
  for (trial = 0; trial < 800; trial++) {
    size_t nbits = 1 + rng_next() % 300;
    size_t nw = zbits_words(nbits);
    uint64_t w[8], wa[8], wb[8];
    unsigned char model[300];
    size_t i;
    int step;
    CHECK(nw <= 8);
    memset(model, 0, sizeof(model));
    CHECK(zbits_init(w, nbits) == ZBITS_OK);
    for (step = 0; step < 120; step++) {
      size_t idx = rng_next() % nbits;
      switch (rng_next() % 5) {
      case 0:
        CHECK(zbits_set(w, nbits, idx) == ZBITS_OK);
        model[idx] = 1;
        break;
      case 1:
        CHECK(zbits_clear(w, nbits, idx) == ZBITS_OK);
        model[idx] = 0;
        break;
      case 2:
        CHECK(zbits_flip(w, nbits, idx) == ZBITS_OK);
        model[idx] ^= 1;
        break;
      case 3:
        CHECK(zbits_test(w, nbits, idx) == model[idx]);
        break;
      default: {
        /* random bulk op vs second set */
        memcpy(wa, w, sizeof(w));
        for (i = 0; i < nw; i++) wb[i] = rng_next();
        {
          unsigned char m2[300];
          size_t cnt = 0;
          for (i = 0; i < nbits; i++)
            m2[i] = (unsigned char)((wb[i / 64] >> (i % 64)) & 1);
          CHECK(zbits_and(w, wa, wb, nbits) == ZBITS_OK);
          for (i = 0; i < nbits; i++) {
            int want = model[i] & m2[i];
            CHECK(zbits_test(w, nbits, i) == want);
            model[i] = (unsigned char)want;
            cnt += (size_t)model[i];
          }
          CHECK(zbits_count(w, nbits) == cnt);
        }
        break;
      }
      }
    }
    /* final consistency: count + rank + first_set */
    {
      size_t cnt = 0;
      for (i = 0; i < nbits; i++) {
        CHECK(zbits_test(w, nbits, i) == model[i]);
        cnt += model[i];
        CHECK(zbits_rank(w, nbits, i) == cnt - model[i]);
      }
      CHECK(zbits_count(w, nbits) == cnt);
      if (cnt == 0)
        CHECK(zbits_first_set(w, nbits) == SIZE_MAX);
      else {
        size_t fs = zbits_first_set(w, nbits);
        CHECK(fs != SIZE_MAX && model[fs] == 1);
        for (i = 0; i < fs; i++) CHECK(model[i] == 0);
      }
    }
  }
}

static void test_count_ignores_storage_tail(void) {
  const size_t sizes[] = {1, 65, 130};
  for (size_t row = 0; row < sizeof sizes / sizeof sizes[0]; row++) {
    uint64_t words[3] = {UINT64_MAX, UINT64_MAX, UINT64_MAX};
    const uint64_t before[3] = {UINT64_MAX, UINT64_MAX, UINT64_MAX};
    size_t count = zbits_count(words, sizes[row]);
    int ok = count == sizes[row] &&
             count == zbits_rank(words, sizes[row], sizes[row]) &&
             memcmp(words, before, sizeof words) == 0;
    fprintf(stderr, "tail_count_row=%zu nbits=%zu result=%s\n", row,
            sizes[row], ok ? "PASS" : "FAIL");
    CHECK(ok);
  }
}

static int cli_run(FILE *output, FILE *errors, int argc, char **args) {
  cli_sink = output; cli_errors = errors; cli_output_flushes = 0;
  int rc = zbits_cli_main(argc, args);
  cli_sink = stdout; cli_errors = stderr;
  return rc;
}

static bool cli_text(FILE *stream, const char *want) {
  rewind(stream);
  char bytes[256];
  size_t n = fread(bytes, 1, sizeof bytes, stream);
  return !ferror(stream) && n == strlen(want) && memcmp(bytes, want, n) == 0;
}

static int cli_case(int argc, char **args, int status, const char *want,
                     const char *diagnostic) {
  FILE *output = tmpfile(), *errors = tmpfile();
  int bad = 1;
  if (!output || !errors) goto cleanup;
  if (cli_run(output, errors, argc, args) != status) goto cleanup;
  if (!want[0] && cli_output_flushes != 0) goto cleanup;
  if (!cli_text(output, want) || !cli_text(errors, diagnostic)) goto cleanup;
  bad = 0;
cleanup:
  if (output && fclose(output) != 0) bad = 1;
  if (errors && fclose(errors) != 0) bad = 1;
  return bad;
}

static int cli_sink_case(int argc, char **args, bool buffered) {
#if defined(__linux__)
  FILE *output = fopen(buffered ? "/dev/full" : "/dev/null", buffered ? "w" : "r");
#elif defined(_WIN32)
  FILE *output = fopen("NUL", "r");
#else
  FILE *output = fopen("/dev/null", "r");
#endif
  FILE *errors = tmpfile();
  int bad = 1;
  char buffer[4096];
  if (!output || !errors) goto cleanup;
  if (buffered && setvbuf(output, buffer, _IOFBF, sizeof buffer) != 0) goto cleanup;
  if (cli_run(output, errors, argc, args) != 1 || !ferror(output)) goto cleanup;
  if (!cli_text(errors, "zbits: output write failed\n")) goto cleanup;
  bad = 0;
cleanup:
  if (output) (void)fclose(output);
  if (errors && fclose(errors) != 0) bad = 1;
  return bad;
}

static void test_cli_output(void) {
  const struct { char *op, *a, *b; int status; const char *want; } rows[] = {
      {"count", "101", NULL, 0, "2\n"},
      {"rank", "101", "2", 0, "1\n"},
      {"first-set", "101", NULL, 0, "0\n"},
      {"first-clear", "101", NULL, 0, "1\n"},
      {"first-set", "000", NULL, 1, "none\n"},
      {"first-clear", "111", NULL, 1, "none\n"},
      {"flip-all", "101", NULL, 0, "010\n"},
      {"or", "101", "010", 0, "111\n"},
      {"and", "101", "110", 0, "100\n"},
      {"andnot", "101", "110", 0, "001\n"}
  };
  for (size_t i = 0; i < sizeof rows / sizeof rows[0]; i++) {
    char *args[] = {"zbits", rows[i].op, rows[i].a, rows[i].b, NULL};
    int argc = rows[i].b ? 4 : 3;
    CHECK(cli_case(argc, args, rows[i].status, rows[i].want, "") == 0);
    CHECK(cli_sink_case(argc, args, false) == 0);
#if defined(__linux__)
    CHECK(cli_sink_case(argc, args, true) == 0);
#endif
  }
}

static void test_cli_errors(void) {
  char *bad[] = {"zbits", "count", "10x", NULL};
  CHECK(cli_case(3, bad, 1, "", "zbits: bad input\n") == 0);
  char *rank[] = {"zbits", "rank", "101", "4", NULL};
  CHECK(cli_case(4, rank, 1, "", "zbits: bad input\n") == 0);
  const char *usage = "usage: zbits <count|first-set|first-clear|flip-all> BITS\n"
      "       zbits rank BITS I\n       zbits <or|and|andnot> A B\n";
  char *missing[] = {"zbits", "count", NULL};
  CHECK(cli_case(2, missing, 2, "", usage) == 0);
  char *comment_only[] = {"zbits", "xor-not", "101", "010", NULL};
  CHECK(cli_case(4, comment_only, 2, "", usage) == 0);
}

int main(void) {
  cli_sink = stdout; cli_errors = stderr;
  test_cli_output();
  test_cli_errors();
  test_count_ignores_storage_tail();
  test_basic();
  test_bulk();
  test_rank_first();
  test_ops();
  test_err();
  test_fuzz();
  if (g_fail) {
    fprintf(stderr, "test_zbits: FAILURES\n");
    return 1;
  }
  printf("test_zbits: all groups passed (basic bulk rank first ops err fuzz)\n");
  return 0;
}
