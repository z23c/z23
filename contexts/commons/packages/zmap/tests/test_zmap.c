/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: zmap test suite.  Exits nonzero on the first failure. */
#include "zmap/zmap.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static FILE *cli_source, *cli_sink;
static unsigned cli_output_flushes;
static int cli_fflush(FILE *stream) {
  if (stream == cli_sink) cli_output_flushes++;
  return fflush(stream);
}
#undef stdin
#undef stdout
#define stdin cli_source
#define stdout cli_sink
#define printf(...) fprintf(cli_sink, __VA_ARGS__)
#define fflush cli_fflush
#define main zmap_cli_main
#include "../app/main.c"
#undef main
#undef printf
#undef fflush
#undef stdout
#undef stdin

static int failures = 0;

#define CHECK(cond)                                                          \
  do {                                                                       \
    if (!(cond)) {                                                           \
      fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);        \
      failures++;                                                            \
    }                                                                        \
  } while (0)

static void test_insert_lookup_replace(void) {
  zmap *m = zmap_create();
  CHECK(m != nullptr);
  CHECK(zmap_size(m) == 0);
  CHECK(zmap_get(m, "absent") == nullptr);
  CHECK(!zmap_contains(m, "absent"));

  CHECK(zmap_put(m, "one", (void *)1, nullptr));
  CHECK(zmap_put(m, "two", (void *)2, nullptr));
  CHECK(zmap_size(m) == 2);
  CHECK(zmap_get(m, "one") == (void *)1);
  CHECK(zmap_get(m, "two") == (void *)2);

  void *old = nullptr;
  CHECK(zmap_put(m, "one", (void *)11, &old));
  CHECK(old == (void *)1);
  CHECK(zmap_size(m) == 2);
  CHECK(zmap_get(m, "one") == (void *)11);

  zmap_destroy(m, nullptr, nullptr);
}

static void test_key_copied(void) {
  zmap *m = zmap_create();
  char key[] = "mutable";
  CHECK(zmap_put(m, key, (void *)7, nullptr));
  key[0] = 'X'; /* mutating the caller's string must not affect the map */
  CHECK(zmap_get(m, "mutable") == (void *)7);
  CHECK(!zmap_contains(m, "Xutable"));
  zmap_destroy(m, nullptr, nullptr);
}

static void test_erase_cycle(void) {
  zmap *m = zmap_create();
  CHECK(zmap_put(m, "a", (void *)1, nullptr));
  CHECK(zmap_put(m, "b", (void *)2, nullptr));
  CHECK(zmap_erase(m, "a") == (void *)1);
  CHECK(zmap_get(m, "a") == nullptr);
  CHECK(zmap_erase(m, "a") == nullptr); /* double erase is a no-op */
  CHECK(zmap_size(m) == 1);
  CHECK(zmap_get(m, "b") == (void *)2);
  /* Re-insert the erased key. */
  CHECK(zmap_put(m, "a", (void *)3, nullptr));
  CHECK(zmap_get(m, "a") == (void *)3);
  CHECK(zmap_size(m) == 2);
  zmap_destroy(m, nullptr, nullptr);
}

static void test_tombstone_churn_no_blowup(void) {
  zmap *m = zmap_create();
  /* Insert and erase the same volume many times; capacity must stay
   * bounded because rehashing drops tombstones. */
  for (int round = 0; round < 50; round++) {
    char key[32];
    for (int i = 0; i < 64; i++) {
      snprintf(key, sizeof(key), "r%d-k%d", round, i);
      CHECK(zmap_put(m, key, (void *)(ptrdiff_t)i, nullptr));
    }
    for (int i = 0; i < 64; i++) {
      snprintf(key, sizeof(key), "r%d-k%d", round, i);
      CHECK(zmap_erase(m, key) == (void *)(ptrdiff_t)i);
    }
  }
  CHECK(zmap_size(m) == 0);
  /* 64 live entries at a time need at most a 128-slot table (grow at 3/4
   * of 128 = 96).  Allow generous slack but prove no runaway growth. */
  CHECK(zmap_capacity(m) <= 256);
  zmap_destroy(m, nullptr, nullptr);
}

/* Test hook: a constant hash forces every key into one probe chain. */
static uint64_t hash_constant(const char *key, size_t len) {
  (void)key;
  (void)len;
  return 42;
}

static void test_forced_collisions(void) {
  zmap *m = zmap_create_ex(nullptr, hash_constant);
  CHECK(m != nullptr);
  char key[32];
  for (int i = 0; i < 500; i++) {
    snprintf(key, sizeof(key), "k%d", i);
    CHECK(zmap_put(m, key, (void *)(ptrdiff_t)(i + 1), nullptr));
  }
  CHECK(zmap_size(m) == 500);
  for (int i = 0; i < 500; i++) {
    snprintf(key, sizeof(key), "k%d", i);
    CHECK(zmap_get(m, key) == (void *)(ptrdiff_t)(i + 1));
  }
  /* Erase the whole chain in a scrambled order. */
  for (int i = 499; i >= 0; i -= 2) {
    snprintf(key, sizeof(key), "k%d", i);
    CHECK(zmap_erase(m, key) == (void *)(ptrdiff_t)(i + 1));
  }
  for (int i = 0; i < 500; i += 2) {
    snprintf(key, sizeof(key), "k%d", i);
    CHECK(zmap_get(m, key) == (void *)(ptrdiff_t)(i + 1));
  }
  zmap_destroy(m, nullptr, nullptr);
}

static void test_iteration_complete(void) {
  zmap *m = zmap_create();
  char key[32];
  for (int i = 0; i < 100; i++) {
    snprintf(key, sizeof(key), "item-%d", i);
    CHECK(zmap_put(m, key, (void *)(ptrdiff_t)(i + 1), nullptr));
  }
  bool seen[100] = {0};
  size_t count = 0;
  const char *k = nullptr;
  for (zmap_iter it = ZMAP_ITER_INIT; zmap_next(m, &it, &k, nullptr);) {
    int n = -1;
    CHECK(sscanf(k, "item-%d", &n) == 1);
    CHECK(n >= 0 && n < 100);
    CHECK(!seen[n]);
    seen[n] = true;
    count++;
  }
  CHECK(count == 100);
  zmap_destroy(m, nullptr, nullptr);
}

static size_t dtor_calls;

static void counting_dtor(void *ctx, const char *key, void *value) {
  (void)ctx;
  (void)key;
  (void)value;
  dtor_calls++;
}

static void test_destructor_called(void) {
  zmap *m = zmap_create();
  CHECK(zmap_put(m, "x", (void *)1, nullptr));
  CHECK(zmap_put(m, "y", (void *)2, nullptr));
  dtor_calls = 0;
  zmap_destroy(m, counting_dtor, nullptr);
  CHECK(dtor_calls == 2);
}

static void *counting_alloc(void *ctx, size_t size) {
  int *budget = ctx;
  if (*budget <= 0)
    return nullptr;
  (*budget)--;
  return calloc(1, size);
}

static void counting_dealloc(void *ctx, void *ptr) {
  (void)ctx;
  free(ptr);
}

static void test_failing_allocator(void) {
  static int budget;
  /* Budget of 1: map struct allocates, table fails. */
  budget = 1;
  zmap_alloc a = {.ctx = &budget,
                  .alloc = counting_alloc,
                  .dealloc = counting_dealloc};
  CHECK(zmap_create_ex(&a, nullptr) == nullptr);
  /* Budget of 2: map + table allocate, first key copy fails -> put fails
   * cleanly and the map stays usable for destroy. */
  budget = 2;
  zmap *m = zmap_create_ex(&a, nullptr);
  CHECK(m != nullptr);
  CHECK(!zmap_put(m, "key", (void *)1, nullptr));
  CHECK(zmap_size(m) == 0);
  zmap_destroy(m, nullptr, nullptr);
}

static void test_clear_reuse(void) {
  zmap *m = zmap_create();
  CHECK(zmap_put(m, "k", (void *)1, nullptr));
  zmap_clear(m, nullptr, nullptr);
  CHECK(zmap_size(m) == 0);
  CHECK(zmap_get(m, "k") == nullptr);
  CHECK(zmap_put(m, "k2", (void *)2, nullptr));
  CHECK(zmap_get(m, "k2") == (void *)2);
  zmap_destroy(m, nullptr, nullptr);
}

static void test_100k_smoke(void) {
  zmap *m = zmap_create();
  char key[32];
  for (int i = 0; i < 100000; i++) {
    snprintf(key, sizeof(key), "smoke-key-%d", i);
    CHECK(zmap_put(m, key, (void *)(ptrdiff_t)i, nullptr));
  }
  CHECK(zmap_size(m) == 100000);
  /* Load bound 3/4: 100k entries must fit in 262144 slots, never more. */
  CHECK(zmap_capacity(m) <= 262144);
  for (int i = 0; i < 100000; i += 7) {
    snprintf(key, sizeof(key), "smoke-key-%d", i);
    CHECK(zmap_get(m, key) == (void *)(ptrdiff_t)i);
  }
  /* Erase half, confirm size and spot lookups. */
  for (int i = 0; i < 100000; i += 2) {
    snprintf(key, sizeof(key), "smoke-key-%d", i);
    CHECK(zmap_erase(m, key) == (void *)(ptrdiff_t)i);
  }
  CHECK(zmap_size(m) == 50000);
  snprintf(key, sizeof(key), "smoke-key-%d", 99999);
  CHECK(zmap_get(m, key) == (void *)(ptrdiff_t)99999);
  zmap_destroy(m, nullptr, nullptr);
}

static void test_clear_erased_slots(void) {
  zmap *m = zmap_create_ex(NULL, hash_constant);
  if (!m) abort();
  size_t initial = zmap_capacity(m);
  char key[32];
  for (int i = 0; i < 11; i++) {
    snprintf(key, sizeof key, "old%d", i);
    if (!zmap_put(m, key, (void *)1, NULL)) abort();
  }
  for (int i = 0; i < 10; i++) {
    snprintf(key, sizeof key, "old%d", i);
    (void)zmap_erase(m, key);
  }
  zmap_clear(m, NULL, NULL);
  for (int i = 0; i < 12; i++) {
    snprintf(key, sizeof key, "new%d", i);
    if (!zmap_put(m, key, (void *)1, NULL)) abort();
  }
  CHECK(zmap_capacity(m) > initial);
  zmap_destroy(m, NULL, NULL);
}

static void test_failed_growth_preserves_capacity(void) {
  int budget = 100;
  zmap_alloc a = {.ctx = &budget, .alloc = counting_alloc,
                  .dealloc = counting_dealloc};
  zmap *m = zmap_create_ex(&a, NULL);
  if (!m) abort();
  char key[32];
  for (int i = 0; i < 11; i++) {
    snprintf(key, sizeof key, "old%d", i);
    if (!zmap_put(m, key, (void *)1, NULL)) abort();
  }
  size_t before = zmap_capacity(m);
  budget = 1;
  bool inserted = zmap_put(m, "new", (void *)2, NULL);
  CHECK(!inserted && zmap_capacity(m) == before && zmap_size(m) == 11);
  zmap_destroy(m, NULL, NULL);
}

static void test_clear_tombstone_growth(void) {
  zmap *m = zmap_create_ex(nullptr, hash_constant);
  if (!m) exit(2);
  char key[16];
  for (int i = 0; i < 11; i++) {
    snprintf(key, sizeof key, "old-%d", i);
    if (!zmap_put(m, key, (void *)1, nullptr)) exit(2);
  }
  for (int i = 0; i < 10; i++) {
    snprintf(key, sizeof key, "old-%d", i);
    (void)zmap_erase(m, key);
  }
  zmap_clear(m, nullptr, nullptr);
  for (int i = 0; i < 12; i++) {
    snprintf(key, sizeof key, "new-%d", i);
    if (!zmap_put(m, key, (void *)1, nullptr)) exit(2);
  }
  CHECK(zmap_capacity(m) == 32);
  zmap_destroy(m, nullptr, nullptr);
}

static void test_clear_retains_capacity(void) {
  int budget = 100;
  zmap_alloc a = {.ctx = &budget, .alloc = counting_alloc,
                  .dealloc = counting_dealloc};
  zmap *m = zmap_create_ex(&a, nullptr);
  if (!m) exit(2);
  char key[32];
  for (int i = 0; i < 40; i++) {
    snprintf(key, sizeof key, "key-%d", i);
    if (!zmap_put(m, key, (void *)1, nullptr)) exit(2);
  }
  size_t capacity = zmap_capacity(m);
  CHECK(capacity > 16);
  zmap_clear(m, nullptr, nullptr);
  CHECK(zmap_capacity(m) == capacity);
  CHECK(zmap_size(m) == 0);
  /* Only key copies may allocate: reuse must not grow the retained table. */
  budget = 12;
  for (int i = 0; i < 12; i++) {
    snprintf(key, sizeof key, "new-%d", i);
    CHECK(zmap_put(m, key, (void *)1, nullptr));
  }
  CHECK(budget == 0);
  CHECK(zmap_capacity(m) == capacity && zmap_size(m) == 12);
  for (int i = 0; i < 12; i++) {
    snprintf(key, sizeof key, "new-%d", i);
    CHECK(zmap_get(m, key) == (void *)1);
  }
  zmap_destroy(m, nullptr, nullptr);
}

static void test_failed_growth_unchanged(void) {
  int budget = 100;
  zmap_alloc a = {.ctx = &budget, .alloc = counting_alloc,
                  .dealloc = counting_dealloc};
  zmap *m = zmap_create_ex(&a, nullptr);
  if (!m) exit(2);
  char key[32];
  for (int i = 0; i < 11; i++) {
    snprintf(key, sizeof key, "key-%d", i);
    if (!zmap_put(m, key, (void *)1, nullptr)) exit(2);
  }
  budget = 1;
  if (zmap_put(m, "new", (void *)1, nullptr)) exit(2);
  CHECK(zmap_capacity(m) == 16);
  zmap_destroy(m, nullptr, nullptr);
}

static bool cli_result(FILE *source, FILE *output, int status, const char *want) {
  cli_source = source; cli_sink = output;
  char *args[] = {"wordfreq", NULL};
  if (zmap_cli_main(1, args) != status) return false;
  rewind(output);
  char bytes[128];
  size_t n = fread(bytes, 1, sizeof bytes, output);
  return !ferror(output) && n == strlen(want) && memcmp(bytes, want, n) == 0;
}

static bool cli_padding(FILE *source, size_t count) {
  char bytes[16384];
  memset(bytes, ' ', sizeof bytes);
  while (count) {
    size_t n = count < sizeof bytes ? count : sizeof bytes;
    if (fwrite(bytes, 1, n, source) != n) return false;
    count -= n;
  }
  return true;
}

static int cli_bound_case(size_t length, int status) {
  FILE *source = tmpfile(), *output = tmpfile();
  int bad = 1;
  if (!source || !output || length < 1) goto cleanup;
  if (!cli_padding(source, length - 1) || fputc('z', source) == EOF ||
      fflush(source) != 0) goto cleanup;
  rewind(source);
  if (!cli_result(source, output, status, status == 0 ? "      1 z\n" : "")) goto cleanup;
  bad = 0;
cleanup:
  if (source && fclose(source) != 0) bad = 1;
  if (output && fclose(output) != 0) bad = 1;
  return bad;
}

static void test_cli_bound(void) {
  CHECK(cli_bound_case(MAX_INPUT - 1, 0) == 0);
  CHECK(cli_bound_case(MAX_INPUT, 0) == 0);
  CHECK(cli_bound_case(MAX_INPUT + 1, 2) == 0);
}

static void test_cli_controls(void) {
  FILE *source = tmpfile(), *output = tmpfile();
  if (!source || !output) { CHECK(false); goto cleanup; }
  CHECK(fputs("b a b c a", source) >= 0 && fflush(source) == 0);
  rewind(source);
  CHECK(cli_result(source, output, 0, "      2 a\n      2 b\n      1 c\n"));
cleanup:
  if (source) CHECK(fclose(source) == 0);
  if (output) CHECK(fclose(output) == 0);
}

static void test_cli_read_error(void) {
#if defined(_WIN32)
  FILE *source = fopen("NUL", "w");
#else
  FILE *source = fopen("/dev/null", "w");
#endif
  FILE *output = tmpfile();
  if (source && output) {
    CHECK(cli_result(source, output, 2, ""));
    CHECK(ferror(source));
  } else CHECK(false);
  if (source) CHECK(fclose(source) == 0);
  if (output) CHECK(fclose(output) == 0);
}

static int cli_output_cleanup(FILE *source, FILE *output, int bad) {
  if (source && fclose(source) != 0) bad = 1;
  if (output) (void)fclose(output);
  return bad;
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
  if (fputs(empty ? "" : "a a b\n", source) < 0 || fflush(source) != 0) goto cleanup;
  rewind(source);
  cli_source = source; cli_sink = output; cli_output_flushes = 0;
  char *args[] = {"wordfreq", NULL};
  if (zmap_cli_main(1, args) != (empty ? 0 : 2)) goto cleanup;
  if (empty ? (ferror(output) || cli_output_flushes != 0) : !ferror(output)) goto cleanup;
  bad = 0;
cleanup:
  return cli_output_cleanup(source, output, bad);
}

static void test_cli_output(void) {
  CHECK(cli_sink_case(false, false) == 0);
  CHECK(cli_sink_case(true, false) == 0);
#if defined(__linux__)
  CHECK(cli_sink_case(false, true) == 0);
  CHECK(cli_sink_case(true, true) == 0);
#endif
}

int main(void) {
  test_cli_output();
  test_cli_bound();
  test_cli_controls();
  test_cli_read_error();
    test_failed_growth_unchanged();
    test_clear_retains_capacity();
    test_clear_tombstone_growth();
  test_failed_growth_preserves_capacity();
  test_clear_erased_slots();
  test_insert_lookup_replace();
  test_key_copied();
  test_erase_cycle();
  test_tombstone_churn_no_blowup();
  test_forced_collisions();
  test_iteration_complete();
  test_destructor_called();
  test_failing_allocator();
  test_clear_reuse();
  test_100k_smoke();
  if (failures) {
    fprintf(stderr, "zmap: %d failure(s)\n", failures);
    return 1;
  }
  puts("zmap: all tests passed");
  return 0;
}
