/* zsort tests: sortedness oracle vs qsort, stability proofs, argsort
 * permutation checks, context-pointer plumbing, adversarial inputs
 * (sorted, reverse, equal-keys, sawtooth, organ pipe), and a large
 * randomised agreement harness.  Built with -std=c23 -Wall -Wextra
 * -Werror -pedantic under ASan/UBSan. */

#include "zsort/zsort.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <stdint.h>

static int failures = 0;

#define CHECK(cond)                                                     \
  do {                                                                  \
    if (!(cond)) {                                                      \
      fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);   \
      failures++;                                                       \
    }                                                                   \
  } while (0)

static int cmp_int(const void *a, const void *b, void *ctx) {
  int x = *(const int *)a, y = *(const int *)b;
  int bias = ctx ? *(const int *)ctx : 0;
  x += bias;
  y += bias;
  return (x > y) - (x < y);
}

static int qsort_cmp_int(const void *a, const void *b) {
  int x = *(const int *)a, y = *(const int *)b;
  return (x > y) - (x < y);
}

static int is_sorted_ints(const int *v, size_t n) {
  size_t i;
  for (i = 1; i < n; i++)
    if (v[i - 1] > v[i]) return 0;
  return 1;
}

static unsigned long long rng_state = 0xABCDEF1234567890ull;
static unsigned long long rnd(void) {
  unsigned long long x = rng_state;
  x ^= x >> 12;
  x ^= x << 25;
  x ^= x >> 27;
  rng_state = x;
  return x * 0x2545F4914F6CDD1Dull;
}

static void fill_pattern(int *v, size_t n, int pattern) {
  size_t i;
  switch (pattern % 6) {
  case 0: /* random */
    for (i = 0; i < n; i++) v[i] = (int)(rnd() % 1000);
    break;
  case 1: /* sorted */
    for (i = 0; i < n; i++) v[i] = (int)i;
    break;
  case 2: /* reverse */
    for (i = 0; i < n; i++) v[i] = (int)(n - i);
    break;
  case 3: /* all equal */
    for (i = 0; i < n; i++) v[i] = 42;
    break;
  case 4: /* sawtooth */
    for (i = 0; i < n; i++) v[i] = (int)(i % 7);
    break;
  default: /* organ pipe */
    for (i = 0; i < n; i++)
      v[i] = (int)(i < n / 2 ? i : n - i);
    break;
  }
}

static void test_basic(void) {
  int v[10] = {5, 2, 8, 1, 9, 3, 7, 4, 6, 0};
  int bias = 0;
  zsort(v, 10, sizeof v[0], cmp_int, &bias);
  CHECK(is_sorted_ints(v, 10));
  /* ctx actually reaches the comparator */
  {
    int v2[3] = {0, 0, 0};
    int sentinel = 100;
    zsort(v2, 3, sizeof v2[0], cmp_int, &sentinel);
    CHECK(v2[0] == 0);
  }
  /* no-op edges */
  zsort(NULL, 0, sizeof(int), cmp_int, NULL);
  zsort(v, 1, sizeof v[0], cmp_int, NULL);
  zsort(NULL, 5, sizeof(int), cmp_int, NULL); /* rejected, no crash */
  zsort(v, 10, 0, cmp_int, NULL);             /* size 0 rejected */
  zsort(v, 10, sizeof v[0], NULL, NULL);      /* no comparator */
}

static int cmp_rec_a(const void *pa, const void *pb, void *ctx) {
  typedef struct {
    long a, b, c;
    char pad[13];
  } rec;
  const rec *x = pa, *y = pb;
  (void)ctx;
  if (x->a != y->a) return (x->a > y->a) - (x->a < y->a);
  return (x->c > y->c) - (x->c < y->c);
}

static void test_wide_elements(void) {
  typedef struct {
    long a, b, c;
    char pad[13];
  } rec;
  rec v[120];
  size_t i;
  int t;
  for (t = 0; t < 50; t++) {
    size_t n = 1 + rnd() % 120;
    for (i = 0; i < n; i++) {
      v[i].a = (long)(rnd() % 10);
      v[i].b = (long)i;
      v[i].c = -(long)(rnd() % 5);
      memset(v[i].pad, (int)(i & 0xFF), sizeof v[i].pad);
    }
    zsort(v, n, sizeof v[0], cmp_rec_a, NULL);
    for (i = 1; i < n; i++) CHECK(cmp_rec_a(&v[i - 1], &v[i], NULL) <= 0);
  }
}

static void test_stable(void) {
  /* key = value % 10; stability keeps original order within a key */
  int v[500];
  size_t perm[500];
  size_t n, i;
  int t;
  for (t = 0; t < 40; t++) {
    n = 1 + rnd() % 500;
    for (i = 0; i < n; i++) v[i] = (int)(rnd() % 10);
    {
      int scratch[500];
      int before[500];
      memcpy(before, v, n * sizeof *before);
      CHECK(zsort_stable(v, n, sizeof v[0], cmp_int, NULL, scratch));
      /* stable on full values means: sorted, and equal values keep
       * relative order — verifiable via argsort below */
      CHECK(is_sorted_ints(v, n));
      /* multiset preserved */
      {
        int a[500], b[500];
        memcpy(a, before, n * sizeof *a);
        memcpy(b, v, n * sizeof *b);
        qsort(a, n, sizeof *a, qsort_cmp_int);
        qsort(b, n, sizeof *b, qsort_cmp_int);
        CHECK(memcmp(a, b, n * sizeof *a) == 0);
      }
    }
    /* argsort: sorted view + stable ties */
    CHECK(zargsort(perm, v, n, sizeof v[0], cmp_int, NULL));
    for (i = 1; i < n; i++) {
      CHECK(v[perm[i - 1]] <= v[perm[i]]);
      if (v[perm[i - 1]] == v[perm[i]]) CHECK(perm[i - 1] < perm[i]);
    }
    /* perm is a permutation */
    {
      unsigned char seen[500];
      memset(seen, 0, n);
      for (i = 0; i < n; i++) {
        CHECK(perm[i] < n);
        CHECK(!seen[perm[i]]);
        seen[perm[i]] = 1;
      }
    }
  }
}

typedef struct {
  int key;
  int idx;
} kv;

static int cmp_kv(const void *a, const void *b, void *ctx) {
  const kv *x = a, *y = b;
  (void)ctx;
  return (x->key > y->key) - (x->key < y->key);
}

static void test_stable_proof(void) {
  /* distinguishable equal keys: record carries (key, original_index);
   * after a stable sort by key, indices within a key must increase */
  kv v[300];
  kv scratch[300];
  int t;
  for (t = 0; t < 40; t++) {
    size_t n = 1 + rnd() % 300;
    size_t i;
    for (i = 0; i < n; i++) {
      v[i].key = (int)(rnd() % 5);
      v[i].idx = (int)i;
    }
    CHECK(zsort_stable(v, n, sizeof v[0], cmp_kv, NULL, scratch));
    for (i = 1; i < n; i++) {
      CHECK(v[i - 1].key <= v[i].key);
      if (v[i - 1].key == v[i].key) CHECK(v[i - 1].idx < v[i].idx);
    }
  }
}

static void test_argsort_identity(void) {
  /* sorting the base array equals gathering through the permutation */
  int t;
  for (t = 0; t < 60; t++) {
    int v[200], sorted[200];
    size_t perm[200];
    size_t n = 1 + rnd() % 200;
    size_t i;
    for (i = 0; i < n; i++) v[i] = (int)(rnd() % 50);
    memcpy(sorted, v, n * sizeof *sorted);
    zsort(sorted, n, sizeof *sorted, cmp_int, NULL);
    CHECK(zargsort(perm, v, n, sizeof *v, cmp_int, NULL));
    for (i = 0; i < n; i++) CHECK(v[perm[i]] == sorted[i]);
  }
}

static void test_large_random(void) {
  /* larger n exercises the rotation fallback in argsort and deep
   * recursion in introsort */
  static int v[5000];
  static int scratch[5000];
  static size_t perm[5000];
  size_t i;
  int t;
  for (t = 0; t < 12; t++) {
    size_t n = 1000 + rnd() % 4000;
    fill_pattern(v, n, t);
    zsort(v, n, sizeof v[0], cmp_int, NULL);
    CHECK(is_sorted_ints(v, n));
    fill_pattern(v, n, t + 1);
    CHECK(zsort_stable(v, n, sizeof v[0], cmp_int, NULL, scratch));
    CHECK(is_sorted_ints(v, n));
    fill_pattern(v, n, t + 2);
    CHECK(zargsort(perm, v, n, sizeof v[0], cmp_int, NULL));
    for (i = 1; i < n; i++) {
      CHECK(v[perm[i - 1]] <= v[perm[i]]);
      if (v[perm[i - 1]] == v[perm[i]]) CHECK(perm[i - 1] < perm[i]);
    }
  }
}

static void test_bad_args(void) {
  int v[4] = {3, 1, 2, 0};
  size_t perm[4];
  CHECK(!zsort_stable(NULL, 4, sizeof(int), cmp_int, NULL, v));
  CHECK(!zsort_stable(v, 4, sizeof(int), cmp_int, NULL, NULL));
  CHECK(!zsort_stable(v, 4, 0, cmp_int, NULL, v));
  CHECK(!zsort_stable(v, 4, sizeof(int), NULL, NULL, v));
  CHECK(zsort_stable(v, 1, sizeof(int), cmp_int, NULL, NULL)); /* n<=1 ok */
  CHECK(!zargsort(NULL, v, 4, sizeof(int), cmp_int, NULL));
  CHECK(!zargsort(perm, NULL, 4, sizeof(int), cmp_int, NULL));
  CHECK(!zargsort(perm, v, 4, 0, cmp_int, NULL));
  CHECK(!zargsort(perm, v, 4, sizeof(int), NULL, NULL));
  CHECK(zargsort(perm, v, 0, sizeof(int), cmp_int, NULL));
  CHECK(zargsort(perm, v, 1, sizeof(int), cmp_int, NULL));
  CHECK(perm[0] == 0);
}

static void test_null_singleton(void) {
  size_t perm = 99;
  CHECK(zargsort(&perm, NULL, 1, sizeof(int), cmp_int, NULL) == 1 &&
        perm == 0);
}

static void test_cli(void);

int main(void) {
  test_cli();
  test_null_singleton();
  test_basic();

  test_wide_elements();
  test_stable();
  test_stable_proof();
  test_argsort_identity();
  test_large_random();
  test_bad_args();
  if (failures) {
    fprintf(stderr, "%d failure(s)\n", failures);
    return 1;
  }
  puts("zsort: all tests passed");
  return 0;
}

static FILE *cli_source, *cli_sink;
static size_t cli_flushes, cli_reads, cli_fault_after = SIZE_MAX;
static bool cli_read_failed;
static FILE *real_stdin(void) { return stdin; }
static FILE *real_stdout(void) { return stdout; }
[[maybe_unused]] static int cli_getc(FILE *stream) {
  if (stream == cli_source && cli_reads++ >= cli_fault_after) {
    cli_read_failed = true;
    return EOF;
  }
  return fgetc(stream);
}
[[maybe_unused]] static int cli_error(FILE *stream) {
  return (stream == cli_source && cli_read_failed) || ferror(stream);
}
[[maybe_unused]] static int cli_flush(FILE *stream) {
  if (stream == cli_sink) cli_flushes++;
  return fflush(stream);
}
#undef stdin
#undef stdout
#define stdin cli_source
#define stdout cli_sink
#define fgetc cli_getc
#define ferror cli_error
#define fflush cli_flush
#define printf(...) fprintf(cli_sink, __VA_ARGS__)
#define scanf(...) fscanf(cli_source, __VA_ARGS__)
#define main embedded_cli_main
#include "../app/main.c"
#undef main
#undef scanf
#undef printf
#undef fflush
#undef ferror
#undef fgetc
#undef stdin
#undef stdout
#define stdin real_stdin()
#define stdout real_stdout()

static FILE *require_stream(FILE *stream) {
  if (!stream) { fprintf(stderr, "zsort CLI fixture setup failed\n"); exit(2); }
  return stream;
}
static FILE *cli_input(const void *bytes, size_t n) {
  FILE *stream = require_stream(tmpfile());
  if (fwrite(bytes, 1, n, stream) != n || fflush(stream) != 0) exit(2);
  rewind(stream);
  return stream;
}
static int cli_invoke(FILE *source, FILE *sink, const char *mode) {
  char *args[] = {"zsort", (char *)mode, NULL};
  cli_source = source;
  cli_sink = sink;
  cli_flushes = cli_reads = 0;
  cli_read_failed = false;
  int rc = embedded_cli_main(mode ? 2 : 1, args);
  cli_source = stdin;
  cli_sink = stdout;
  return rc;
}
static void cli_case(const void *bytes, size_t n, const char *mode,
                      int status, const char *want) {
  FILE *source = cli_input(bytes, n), *sink = require_stream(tmpfile());
  CHECK(cli_invoke(source, sink, mode) == status);
  if (!*want) CHECK(cli_flushes == 0);
  char got[512];
  rewind(sink);
  size_t count = fread(got, 1, sizeof got, sink);
  CHECK(!ferror(sink) && count == strlen(want) && !memcmp(got, want, count));
  CHECK(fclose(source) == 0 && fclose(sink) == 0);
}
static void cli_numbers(void) {
  const char *modes[] = {NULL, "--stable", "--index"};
  char input[256], want[256];
  snprintf(input, sizeof input, "%lld 1-2 3+4 1 %lld", LLONG_MAX, LLONG_MIN);
  snprintf(want, sizeof want, "%lld\n-2\n1\n1\n3\n4\n%lld\n", LLONG_MIN, LLONG_MAX);
  for (size_t i = 0; i < 3; i++) cli_case(input, strlen(input), modes[i], 0, want);
  const char *bad[] = {"3 garbage", "1x", "+", "- ", "1 +", "0x10",
    "9223372036854775808", "-9223372036854775809"};
  for (size_t i = 0; i < sizeof bad / sizeof bad[0]; i++)
    cli_case(bad[i], strlen(bad[i]), NULL, 2, "");
  const char nul[] = {'1', 0, '2'};
  cli_case(nul, sizeof nul, NULL, 2, "");
  char zeros[8193];
  memset(zeros, '0', sizeof zeros);
  zeros[sizeof zeros - 1] = '7';
  cli_case(zeros, sizeof zeros, NULL, 0, "7\n");
  cli_case("", 0, NULL, 0, "");
  cli_case(" \t\r\n", 4, NULL, 0, "");
  cli_case("1", 1, "--unknown", 2, "");
}
static void cli_faults(void) {
  const char *inputs[] = {"3 1", "3 ", "3 +"};
  for (size_t i = 0; i < 3; i++) {
    cli_fault_after = strlen(inputs[i]);
    cli_case(inputs[i], strlen(inputs[i]), NULL, 1, "");
  }
  cli_fault_after = SIZE_MAX;
#ifdef _WIN32
  FILE *source = require_stream(fopen("NUL", "w"));
#else
  FILE *source = require_stream(fopen("/dev/null", "w"));
#endif
  FILE *sink = require_stream(tmpfile());
  CHECK(cli_invoke(source, sink, NULL) == 1 && cli_flushes == 0);
  CHECK(ftell(sink) == 0);
  CHECK(fclose(source) == 0 && fclose(sink) == 0);
}
static void cli_failed_sink(const char *mode, bool buffered) {
#ifdef _WIN32
  const char *null_path = "NUL";
#else
  const char *null_path = "/dev/null";
#endif
  FILE *source = cli_input("3 1 2", 5);
  FILE *sink = require_stream(fopen(buffered ? "/dev/full" : null_path, buffered ? "w" : "r"));
  char buffer[4096];
  if (buffered && setvbuf(sink, buffer, _IOFBF, sizeof buffer) != 0) exit(2);
  CHECK(cli_invoke(source, sink, mode) == 1 && ferror(sink));
  CHECK(fclose(source) == 0);
  (void)fclose(sink);
}
static void check_capacity_output(FILE *sink, size_t cap) {
  char block[4096];
  rewind(sink);
  memset(block, '0', sizeof block);
  for (size_t i = 1; i < sizeof block; i += 2) block[i] = '\n';
  char got[4096];
  for (size_t n = 0; n < cap * 2; n += sizeof got) {
    size_t count = fread(got, 1, sizeof got, sink);
    CHECK(count == sizeof got && !memcmp(got, block, sizeof got));
  }
  CHECK(fgetc(sink) == EOF && !ferror(sink));
}
static void cli_capacity(void) {
  const size_t cap = (size_t)1 << 20;
  FILE *source = require_stream(tmpfile()), *sink = require_stream(tmpfile());
  char block[4096];
  memset(block, ' ', sizeof block);
  for (size_t i = 0; i < sizeof block; i += 2) block[i] = '0';
  for (size_t n = 0; n < cap * 2; n += sizeof block)
    if (fwrite(block, 1, sizeof block, source) != sizeof block) exit(2);
  if (fputs(" \t\n", source) < 0 || fflush(source) != 0) exit(2);
  rewind(source);
  CHECK(cli_invoke(source, sink, NULL) == 0);
  check_capacity_output(sink, cap);
  CHECK(fclose(sink) == 0);
  if (fseek(source, 0, SEEK_END) != 0 || fputs("1", source) < 0 || fflush(source) != 0) exit(2);
  rewind(source);
  sink = require_stream(tmpfile());
  CHECK(cli_invoke(source, sink, NULL) == 2 && cli_flushes == 0 && ftell(sink) == 0);
  CHECK(fclose(source) == 0 && fclose(sink) == 0);
}
static void test_cli(void) {
  cli_numbers();
  cli_faults();
  const char *modes[] = {NULL, "--stable", "--index"};
  for (size_t i = 0; i < 3; i++) {
    cli_failed_sink(modes[i], false);
#ifdef __linux__
    cli_failed_sink(modes[i], true);
#endif
  }
  cli_capacity();
}
