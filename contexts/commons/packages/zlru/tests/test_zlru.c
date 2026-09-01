/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: zlru test suite.  Exits nonzero on the first failure. */
#include "zlru/zlru.h"

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

int main(void) {
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
  if (failures) {
    fprintf(stderr, "test_zlru: %d failure(s)\n", failures);
    return 1;
  }
  puts("test_zlru: all tests passed");
  return 0;
}
