/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: zmap test suite.  Exits nonzero on the first failure. */
#include "zmap/zmap.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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
  char key[16];
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
  char key[16];
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

int main(void) {
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
