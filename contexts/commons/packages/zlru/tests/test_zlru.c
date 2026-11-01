/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: zlru test suite.  Exits nonzero on the first failure. */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include "zlru/zlru.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#if !defined(_WIN32)
#include <unistd.h>
#endif

static int failures = 0;

#define CHECK(cond)                                                          \
  do {                                                                       \
    if (!(cond)) {                                                           \
      fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);        \
      failures++;                                                            \
    }                                                                        \
  } while (0)

/* Values are (void*)(intptr_t)n in these tests; a destructor records
 * the values it saw. */
static int destroyed[64];
static size_t destroyed_len; /* recorded (capped) for destroyed_has */
static size_t destroyed_calls; /* exact total destructor calls */

static void record_destroy(void *ctx, const char *key, void *value) {
  (void)ctx;
  (void)key;
  destroyed_calls++;
  if (destroyed_len < sizeof(destroyed) / sizeof(destroyed[0]))
    destroyed[destroyed_len++] = (int)(intptr_t)value;
}

static bool destroyed_has(int v) {
  for (size_t i = 0; i < destroyed_len; i++)
    if (destroyed[i] == v)
      return true;
  return false;
}

#define VP(n) ((void *)(intptr_t)(n))

static void test_basic(void) {
  destroyed_len = 0;
  destroyed_calls = 0;
  zlru *c = zlru_create(4, record_destroy, NULL, (zmap_alloc){0});
  CHECK(c != NULL);
  CHECK(zlru_capacity(c) == 4);
  CHECK(zlru_size(c) == 0);
  CHECK(zlru_get(c, "missing") == NULL);
  CHECK(zlru_put(c, "a", VP(1)));
  CHECK(zlru_put(c, "b", VP(2)));
  CHECK(zlru_size(c) == 2);
  CHECK(zlru_get(c, "a") == VP(1));
  CHECK(zlru_get(c, "b") == VP(2));
  CHECK(destroyed_len == 0);
  zlru_destroy(c);
  CHECK(destroyed_has(1) && destroyed_has(2));
  CHECK(destroyed_len == 2);
}

static void test_eviction_order(void) {
  destroyed_len = 0;
  destroyed_calls = 0;
  zlru *c = zlru_create(3, record_destroy, NULL, (zmap_alloc){0});
  CHECK(c);
  zlru_put(c, "a", VP(1)); /* LRU -> MRU: a */
  zlru_put(c, "b", VP(2)); /* a b */
  zlru_put(c, "c", VP(3)); /* a b c */
  zlru_get(c, "a");        /* b c a  (a promoted) */
  zlru_put(c, "d", VP(4)); /* evicts b: c a d */
  CHECK(zlru_size(c) == 3);
  CHECK(zlru_get(c, "b") == NULL);
  CHECK(destroyed_len == 1 && destroyed[0] == 2);
  zlru_put(c, "e", VP(5)); /* evicts c: a d e */
  CHECK(destroyed_has(3));
  CHECK(zlru_get(c, "a") == VP(1));
  CHECK(zlru_get(c, "d") == VP(4));
  CHECK(zlru_get(c, "e") == VP(5));
  zlru_destroy(c);
}

static void test_replace(void) {
  destroyed_len = 0;
  destroyed_calls = 0;
  zlru *c = zlru_create(2, record_destroy, NULL, (zmap_alloc){0});
  CHECK(c);
  zlru_put(c, "k", VP(1));
  zlru_put(c, "k", VP(2)); /* replace: destructor on 1 */
  CHECK(zlru_size(c) == 1);
  CHECK(zlru_get(c, "k") == VP(2));
  CHECK(destroyed_len == 1 && destroyed[0] == 1);
  /* Replace promotes: put x, re-put k (now MRU), then y evicts x. */
  zlru_put(c, "x", VP(3)); /* k x */
  zlru_put(c, "k", VP(2)); /* replace again: x k */
  CHECK(destroyed_calls == 2);
  zlru_put(c, "y", VP(4)); /* evicts x (LRU), keeps k */
  CHECK(zlru_get(c, "x") == NULL);
  CHECK(zlru_get(c, "k") == VP(2));
  zlru_destroy(c);
}

static void test_erase(void) {
  destroyed_len = 0;
  destroyed_calls = 0;
  zlru *c = zlru_create(4, record_destroy, NULL, (zmap_alloc){0});
  CHECK(c);
  zlru_put(c, "a", VP(1));
  zlru_put(c, "b", VP(2));
  zlru_put(c, "c", VP(3));
  zlru_erase(c, "b"); /* middle */
  CHECK(destroyed_len == 1 && destroyed[0] == 2);
  zlru_erase(c, "absent"); /* no-op */
  CHECK(zlru_size(c) == 2);
  zlru_erase(c, "a");
  zlru_erase(c, "c");
  CHECK(zlru_size(c) == 0);
  /* Cache still works after being emptied. */
  zlru_put(c, "z", VP(9));
  CHECK(zlru_get(c, "z") == VP(9));
  zlru_destroy(c);
}

static void test_capacity_one(void) {
  destroyed_len = 0;
  destroyed_calls = 0;
  zlru *c = zlru_create(1, record_destroy, NULL, (zmap_alloc){0});
  CHECK(c);
  zlru_put(c, "a", VP(1));
  zlru_put(c, "b", VP(2)); /* evicts a immediately */
  CHECK(zlru_size(c) == 1);
  CHECK(zlru_get(c, "a") == NULL);
  CHECK(zlru_get(c, "b") == VP(2));
  CHECK(destroyed_len == 1 && destroyed[0] == 1);
  zlru_destroy(c);
}

static bool collect_key(void *ctx, const char *key, void *value) {
  (void)value;
  strcat(ctx, key);
  strcat(ctx, " ");
  return true;
}

static void test_visit_order(void) {
  zlru *c = zlru_create(8, NULL, NULL, (zmap_alloc){0});
  CHECK(c);
  zlru_put(c, "a", VP(1));
  zlru_put(c, "b", VP(2));
  zlru_put(c, "c", VP(3));
  zlru_get(c, "a"); /* promote a: order b? no: c? order is b? recompute */
  /* MRU order now: a c b */
  char acc[64] = "";
  zlru_visit_mru_first(c, collect_key, acc);
  CHECK(!strcmp(acc, "a c b "));
  /* The visit must not promote: same order again. */
  memset(acc, 0, sizeof(acc));
  zlru_visit_mru_first(c, collect_key, acc);
  CHECK(!strcmp(acc, "a c b "));
  zlru_destroy(c);
}

static bool stop_after_two(void *ctx, const char *key, void *value) {
  static int seen;
  (void)key;
  (void)value;
  (*(int *)ctx)++;
  seen = *(int *)ctx;
  return seen % 3 != 0 ? true : false;
}

static void test_visit_early_stop(void) {
  zlru *c = zlru_create(8, NULL, NULL, (zmap_alloc){0});
  zlru_put(c, "a", VP(1));
  zlru_put(c, "b", VP(2));
  zlru_put(c, "c", VP(3));
  int seen = 0;
  zlru_visit_mru_first(c, stop_after_two, &seen);
  CHECK(seen >= 1);
  zlru_destroy(c);
}

/* Allocator that fails after a fixed number of allocations. */
typedef struct {
  size_t remaining;
} fail_ctx;

static void *fail_alloc(void *ctx, size_t size) {
  fail_ctx *f = ctx;
  if (!f->remaining)
    return NULL;
  f->remaining--;
  void *p = calloc(1, size);
  return p;
}

static void fail_dealloc(void *ctx, void *ptr) {
  (void)ctx;
  free(ptr);
}

static void test_alloc_failure(void) {
  /* create fails when the map allocation is denied. */
  {
    fail_ctx f = {1}; /* cache struct only */
    zmap_alloc a = {&f, fail_alloc, fail_dealloc};
    zlru *c = zlru_create(4, NULL, NULL, a);
    CHECK(c == NULL);
  }
  /* put fails cleanly when the node allocation is denied. */
  {
    fail_ctx f = {64};
    zmap_alloc a = {&f, fail_alloc, fail_dealloc};
    zlru *c = zlru_create(4, record_destroy, NULL, a);
    CHECK(c);
    zlru_put(c, "a", VP(1));
    f.remaining = 0;
    destroyed_len = 0;
    destroyed_calls = 0;
    CHECK(!zlru_put(c, "b", VP(2)));
    CHECK(zlru_size(c) == 1); /* unchanged */
    CHECK(zlru_get(c, "a") == VP(1)); /* still intact */
    CHECK(destroyed_len == 0);
    zlru_destroy(c);
  }
  /* create with capacity 0 is rejected. */
  CHECK(zlru_create(0, NULL, NULL, (zmap_alloc){0}) == NULL);
}

static void test_null_safety(void) {
  zlru_destroy(NULL);
  CHECK(zlru_get(NULL, "k") == NULL);
  CHECK(!zlru_put(NULL, "k", VP(1)));
  zlru_erase(NULL, "k");
  CHECK(zlru_size(NULL) == 0);
  CHECK(zlru_capacity(NULL) == 0);
  zlru_visit_mru_first(NULL, collect_key, NULL);
  zlru *c = zlru_create(2, NULL, NULL, (zmap_alloc){0});
  CHECK(c);
  CHECK(zlru_get(c, NULL) == NULL);
  CHECK(!zlru_put(c, NULL, VP(1)));
  zlru_erase(c, NULL);
  zlru_visit_mru_first(c, NULL, NULL);
  zlru_destroy(c);
}

static bool count_visit(void *ctx, const char *key, void *value) {
  (void)key;
  (void)value;
  (*(size_t *)ctx)++;
  return true;
}

static void test_stress(void) {
  /* Churn: 10k puts (211 distinct keys) over capacity 97 with periodic
   * gets and erases. Invariants: size never exceeds capacity, the list
   * walk visits exactly size() nodes, and every inserted value is
   * destroyed exactly once (replace, eviction, erase, and final
   * destroy are the only exits). */
  destroyed_len = 0;
  destroyed_calls = 0;
  destroyed_calls = 0;
  zlru *c = zlru_create(97, record_destroy, NULL, (zmap_alloc){0});
  CHECK(c);
  for (int i = 0; i < 10000; i++) {
    char key[32];
    int k = (int)((unsigned)i * 2654435761u % 211);
    snprintf(key, sizeof(key), "k%d", k);
    CHECK(zlru_put(c, key, VP(i + 1)));
    if (i % 13 == 0)
      zlru_get(c, "k42");
    if (i % 17 == 0)
      zlru_erase(c, "k7");
    CHECK(zlru_size(c) <= 97);
    size_t walked = 0;
    zlru_visit_mru_first(c, count_visit, &walked);
    CHECK(walked == zlru_size(c));
  }
  size_t final_size = zlru_size(c);
  zlru_destroy(c);
  CHECK(destroyed_calls == 10000); /* every value destroyed once */
  CHECK(final_size <= 97);
}

/* Reuse the library suite's checked allocation-refusal callbacks. */
static int cli_allocation_failure;
static fail_ctx cli_allocator;
static zlru *cli_create(size_t capacity, zlru_destroy_fn destroy,
                         void *ctx, zmap_alloc allocator) {
  if (cli_allocation_failure) {
    cli_allocator.remaining = cli_allocation_failure == 1 ? 0 : 64;
    allocator = (zmap_alloc){&cli_allocator, fail_alloc, fail_dealloc};
  }
  return zlru_create(capacity, destroy, ctx, allocator);
}

static bool cli_put(zlru *cache, const char *key, void *value) {
  if (cli_allocation_failure == 2) cli_allocator.remaining = 0;
  return zlru_put(cache, key, value);
}

static FILE *zlru_fixture_stdin;
static FILE *zlru_fixture_stdout;
static FILE *zlru_fixture_stderr;
static FILE *zlru_real_stdin(void) { return stdin; }
static FILE *zlru_real_stdout(void) { return stdout; }
static FILE *zlru_real_stderr(void) { return stderr; }
static int zlru_fixture_printf(const char *format, ...) {
  va_list args;
  va_start(args, format);
  int result = vfprintf(zlru_fixture_stdout, format, args);
  va_end(args);
  return result;
}
#undef stdin
#define stdin zlru_fixture_stdin
#undef stdout
#define stdout zlru_fixture_stdout
#undef stderr
#define stderr zlru_fixture_stderr
#define printf zlru_fixture_printf
#define zlru_create cli_create
#define zlru_put cli_put
#define main zlru_fixture_main
#include "../app/main.c"
#undef main
#undef zlru_create
#undef zlru_put
#undef stdin
#define stdin (zlru_real_stdin())
#undef stdout
#define stdout (zlru_real_stdout())
#undef stderr
#define stderr (zlru_real_stderr())
#undef printf

static void test_cli_input_limit(void) {
#if !defined(_WIN32)
  static char fixture[MAX_INPUT + 1u];
  for (unsigned final_key = 0; final_key < 2; final_key++) {
    memset(fixture, '\n', sizeof(fixture));
    if (final_key) fixture[MAX_INPUT - 1u] = 'x';
    FILE *in = fmemopen(fixture, MAX_INPUT, "r");
    CHECK(in != NULL);
    if (!in) continue;
    zlru_fixture_stdin = in;
    char *argv[] = {"zlru", "1", NULL};
    CHECK(zlru_fixture_main(2, argv) == 0);
    CHECK(fclose(in) == 0);
    zlru_fixture_stdin = NULL;
  }
#endif
}

#if !defined(_WIN32)
static const char *expected_cli_output(const char *trace) {
  return trace[0] ?
      "MISS a\nHIT a\n# 2 keys: 1 hits, 1 misses, hit rate 0.500\n" :
      "# 0 keys: 0 hits, 0 misses, hit rate 0.000\n";
}

/* A zero-length memory stream is not portable; an empty trace reads /dev/null. */
static FILE *open_cli_trace(const char *trace) {
  return trace[0] ? fmemopen((void *)trace, strlen(trace), "r")
                  : fopen("/dev/null", "r");
}

/* mode 0: writable; 1: deferred flush refusal; 2: immediate write refusal. */
static void exercise_cli_output(const char *trace, int mode) {
  char output[128] = {0}, diagnostic[128] = {0}, buffer[BUFSIZ];
  FILE *in = open_cli_trace(trace);
  FILE *out = mode ? fopen("/dev/null", "w") :
                      fmemopen(output, sizeof(output), "w");
  FILE *err = fmemopen(diagnostic, sizeof(diagnostic), "w");
  CHECK(in && out && err);
  if (!in || !out || !err) {
    if (in) CHECK(fclose(in) == 0);
    if (out) CHECK(fclose(out) == 0);
    if (err) CHECK(fclose(err) == 0);
    return;
  }
  CHECK(setvbuf(out, buffer, mode == 2 ? _IONBF : _IOFBF,
               sizeof(buffer)) == 0);
  if (mode) CHECK(close(fileno(out)) == 0);
  zlru_fixture_stdin = in;
  zlru_fixture_stdout = out;
  zlru_fixture_stderr = err;
  char *argv[] = {"zlru", "1", NULL};
  int result = zlru_fixture_main(2, argv);
  CHECK(result == (mode ? 2 : 0));
  CHECK(fflush(err) == 0);
  if (mode) {
    CHECK(strcmp(diagnostic, "zlru: write error\n") == 0);
  } else {
    CHECK(fflush(out) == 0);
    CHECK(diagnostic[0] == '\0');
    CHECK(strcmp(output, expected_cli_output(trace)) == 0);
  }
  zlru_fixture_stdin = NULL;
  zlru_fixture_stdout = stdout;
  zlru_fixture_stderr = stderr;
  CHECK(fclose(in) == 0);
  CHECK(fclose(err) == 0);
  /* The deliberately closed descriptor must keep this stream failing. */
  int closed = fclose(out);
  CHECK(mode ? closed == EOF : closed == 0);
}
#endif

#if !defined(_WIN32)
static FILE *diagnostic_input(int row) {
  static char long_key[MAX_LINE + 1u];
  if (row == 0) return fopen("/dev/null", "w");
  if (row == 4) {
    memset(long_key, 'x', sizeof(long_key));
    return fmemopen(long_key, sizeof(long_key), "r");
  }
  if (row == 5)
    return fmemopen((void *)"a\n", 2, "r");
  return fopen("/dev/null", "r");
}

static void close_diagnostic_fixture(FILE *in, FILE *out, FILE *err, int mode) {
  if (in) CHECK(fclose(in) == 0);
  if (out) CHECK(fclose(out) == 0);
  if (err) {
    int closed = fclose(err);
    CHECK(mode ? closed == EOF : closed == 0);
  }
}

static void check_cli_diagnostic(FILE *err, const char *got,
                                  const char *expected, int mode) {
  int flushed = fflush(err);
  if (mode) CHECK(flushed == EOF || ferror(err));
  else {
    CHECK(flushed == 0);
    CHECK(strcmp(got, expected) == 0);
  }
}

static void exercise_cli_diagnostic(int row, int mode) {
  static const char *const expected[] = {
    "zlru: read error or input over 16 MiB bound\n",
    "usage: zlru CAPACITY < keys\n",
    "zlru: capacity must be 1..16000000\n",
    "zlru: allocation failure\n",
    "zlru: key over 4096 bytes\n",
    "zlru: allocation failure\n"
  };
  char output[128] = {0}, diagnostic[128] = {0}, buffer[BUFSIZ];
  FILE *in = diagnostic_input(row);
  FILE *out = fmemopen(output, sizeof(output), "w");
  FILE *err = mode ? fopen("/dev/null", "w") :
                     fmemopen(diagnostic, sizeof(diagnostic), "w");
  CHECK(in && out && err);
  if (!in || !out || !err) {
    close_diagnostic_fixture(in, out, err, 0);
    return;
  }
  CHECK(setvbuf(err, buffer, mode == 2 ? _IONBF : _IOFBF,
               sizeof(buffer)) == 0);
  if (mode) CHECK(close(fileno(err)) == 0);
  zlru_fixture_stdin = in;
  zlru_fixture_stdout = out;
  zlru_fixture_stderr = err;
  cli_allocation_failure = row == 3 ? 1 : (row == 5 ? 2 : 0);
  char *argv[] = {"zlru", row == 2 ? "0" : "1", NULL};
  int result = zlru_fixture_main(row == 1 ? 1 : 2, argv);
  cli_allocation_failure = 0;
  zlru_fixture_stdin = stdin;
  zlru_fixture_stdout = stdout;
  zlru_fixture_stderr = stderr;
  CHECK(result == 2);
  CHECK(fflush(out) == 0);
  CHECK(strcmp(output, row == 5 ? "MISS a\n" : "") == 0);
  check_cli_diagnostic(err, diagnostic, expected[row], mode);
  close_diagnostic_fixture(in, out, err, mode);
}

static void exercise_cli_secondary(int mode) {
  char buffer[BUFSIZ], error_buffer[BUFSIZ];
  FILE *in = fopen("/dev/null", "r");
  FILE *out = fopen("/dev/null", "w");
  FILE *err = fopen("/dev/null", "w");
  CHECK(in && out && err);
  if (!in || !out || !err) {
    close_diagnostic_fixture(in, out, err, 0);
    return;
  }
  CHECK(setvbuf(out, buffer, mode == 2 ? _IONBF : _IOFBF,
               sizeof(buffer)) == 0);
  CHECK(setvbuf(err, error_buffer, mode == 2 ? _IONBF : _IOFBF,
               sizeof(error_buffer)) == 0);
  CHECK(close(fileno(out)) == 0);
  CHECK(close(fileno(err)) == 0);
  zlru_fixture_stdin = in;
  zlru_fixture_stdout = out;
  zlru_fixture_stderr = err;
  char *argv[] = {"zlru", "1", NULL};
  int result = zlru_fixture_main(2, argv);
  zlru_fixture_stdin = stdin;
  zlru_fixture_stdout = stdout;
  zlru_fixture_stderr = stderr;
  CHECK(result == 2);
  CHECK(fflush(out) == EOF || ferror(out));
  check_cli_diagnostic(err, "", "", mode);
  CHECK(fclose(in) == 0);
  CHECK(fclose(out) == EOF);
  CHECK(fclose(err) == EOF);
}

static void test_cli_diagnostics(void) {
  for (int row = 0; row < 6; row++) {
    for (int mode = 0; mode < 3; mode++) {
      fprintf(stderr, "CLI control diagnostic%d mode=%d\n", row, mode);
      exercise_cli_diagnostic(row, mode);
    }
  }
  for (int mode = 1; mode < 3; mode++) {
    fprintf(stderr, "CLI control secondary mode=%d\n", mode);
    exercise_cli_secondary(mode);
  }
}
#endif

static void test_cli_output_refusal(void) {
#if !defined(_WIN32)
  for (int mode = 0; mode < 3; mode++) {
    fprintf(stderr, "CLI row empty mode=%d\n", mode);
    exercise_cli_output("", mode);
    fprintf(stderr, "CLI row trace mode=%d\n", mode);
    exercise_cli_output("a\na\n", mode);
  }
  test_cli_diagnostics();
#else
  fprintf(stderr, "zlru: required CLI refusal coverage unavailable on _WIN32\n");
  failures++;
#endif
}

int main(void) {
  zlru_fixture_stdin = stdin;
  zlru_fixture_stdout = stdout;
  zlru_fixture_stderr = stderr;
  test_basic();
  test_eviction_order();
  test_replace();
  test_erase();
  test_capacity_one();
  test_visit_order();
  test_visit_early_stop();
  test_alloc_failure();
  test_null_safety();
  test_stress();
  test_cli_input_limit();
  test_cli_output_refusal();
  if (failures) {
    fprintf(stderr, "test_zlru: %d failure(s)\n", failures);
    return 1;
  }
  puts("test_zlru: all tests passed");
  return 0;
}
