/* Tests for zring — fixed-capacity byte ring buffer.
 * Groups: basic, wrap, bulk, peek, err, null, fuzz. */
#include "zring/zring.h"

#include <stdint.h>
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

static void test_basic(void) {
  unsigned char store[4];
  zring r;
  unsigned char b = 0;
  CHECK(zring_init(&r, store, 4) == ZRING_OK);
  CHECK(zring_is_empty(&r) && !zring_is_full(&r));
  CHECK(zring_len(&r) == 0 && zring_avail(&r) == 4);
  CHECK(zring_get(&r, &b) == ZRING_ERR_EMPTY);
  CHECK(zring_put(&r, 1) == ZRING_OK);
  CHECK(zring_put(&r, 2) == ZRING_OK);
  CHECK(zring_put(&r, 3) == ZRING_OK);
  CHECK(zring_put(&r, 4) == ZRING_OK);
  CHECK(zring_is_full(&r));
  CHECK(zring_put(&r, 5) == ZRING_ERR_FULL);
  CHECK(zring_len(&r) == 4 && zring_avail(&r) == 0);
  CHECK(zring_peek(&r, &b) == ZRING_OK && b == 1);
  CHECK(zring_len(&r) == 4); /* peek does not consume */
  CHECK(zring_get(&r, &b) == ZRING_OK && b == 1);
  CHECK(zring_get(&r, &b) == ZRING_OK && b == 2);
  CHECK(zring_get(&r, &b) == ZRING_OK && b == 3);
  CHECK(zring_get(&r, &b) == ZRING_OK && b == 4);
  CHECK(zring_is_empty(&r));
  CHECK(zring_get(&r, &b) == ZRING_ERR_EMPTY);
  /* Reusable after drain. */
  CHECK(zring_put(&r, 9) == ZRING_OK);
  CHECK(zring_get(&r, &b) == ZRING_OK && b == 9);
}

static void test_wrap(void) {
  unsigned char store[3];
  zring r;
  unsigned char b = 0;
  size_t i;
  CHECK(zring_init(&r, store, 3) == ZRING_OK);
  /* Hammer the wrap point: FIFO order must survive thousands of
   * wraparounds. */
  for (i = 0; i < 3000; i++) {
    CHECK(zring_put(&r, (unsigned char)(i & 7)) == ZRING_OK);
    CHECK(zring_put(&r, (unsigned char)((i + 1) & 7)) == ZRING_OK);
    CHECK(zring_get(&r, &b) == ZRING_OK && b == (unsigned char)(i & 7));
    CHECK(zring_get(&r, &b) == ZRING_OK &&
          b == (unsigned char)((i + 1) & 7));
  }
  CHECK(zring_is_empty(&r));
}

static void test_bulk(void) {
  unsigned char store[8];
  zring r;
  unsigned char out[8];
  CHECK(zring_init(&r, store, 8) == ZRING_OK);
  /* Write more than cap: takes what fits. */
  CHECK(zring_write(&r, "abcdefgh", 8) == 8);
  CHECK(zring_write(&r, "zz", 2) == 0); /* full */
  CHECK(zring_read(&r, out, 3) == 3 && memcmp(out, "abc", 3) == 0);
  /* Wrap-crossing write then read: only 3 free after the read. */
  CHECK(zring_write(&r, "12345", 5) == 3);
  CHECK(zring_is_full(&r));
  CHECK(zring_read(&r, out, 8) == 8 &&
        memcmp(out, "defgh123", 8) == 0);
  CHECK(zring_is_empty(&r));
  /* Short read. */
  CHECK(zring_write(&r, "xy", 2) == 2);
  CHECK(zring_read(&r, out, 8) == 2 && memcmp(out, "xy", 2) == 0);
}

static void test_peek_drop(void) {
  unsigned char store[6];
  zring r;
  unsigned char out[6];
  CHECK(zring_init(&r, store, 6) == ZRING_OK);
  CHECK(zring_write(&r, "hello!", 6) == 6);
  CHECK(zring_peek_at(&r, 0, out, 2) == 2 && memcmp(out, "he", 2) == 0);
  CHECK(zring_peek_at(&r, 4, out, 2) == 2 && memcmp(out, "o!", 2) == 0);
  CHECK(zring_peek_at(&r, 5, out, 3) == 1 && out[0] == '!');
  CHECK(zring_peek_at(&r, 6, out, 1) == 0);
  CHECK(zring_len(&r) == 6);
  /* Drop across the wrap point. */
  CHECK(zring_read(&r, out, 2) == 2);
  CHECK(zring_write(&r, "12", 2) == 2);
  CHECK(zring_drop(&r, 3) == 3);
  CHECK(zring_len(&r) == 3);
  CHECK(zring_read(&r, out, 6) == 3 && memcmp(out, "!12", 3) == 0);
  CHECK(zring_drop(&r, 9) == 0);
}

static void test_err_null(void) {
  unsigned char store[2];
  unsigned char b;
  zring r;
  CHECK(zring_init(NULL, store, 2) == ZRING_ERR_ARG);
  CHECK(zring_init(&r, NULL, 2) == ZRING_ERR_ARG);
  CHECK(zring_init(&r, NULL, 0) == ZRING_OK); /* zero-cap ring */
  CHECK(zring_put(&r, 1) == ZRING_ERR_FULL);
  CHECK(zring_get(&r, &b) == ZRING_ERR_EMPTY);
  CHECK(zring_init(&r, store, 2) == ZRING_OK);
  CHECK(zring_put(NULL, 1) == ZRING_ERR_ARG);
  CHECK(zring_get(&r, NULL) == ZRING_ERR_ARG);
  CHECK(zring_peek(&r, NULL) == ZRING_ERR_ARG);
  CHECK(zring_write(&r, NULL, 3) == 0);
  CHECK(zring_read(&r, NULL, 3) == 0);
  CHECK(zring_peek_at(&r, 0, NULL, 3) == 0);
  CHECK(zring_drop(NULL, 1) == 0);
  CHECK(zring_len(NULL) == 0 && zring_avail(NULL) == 0);
  CHECK(zring_is_empty(NULL) && !zring_is_full(NULL));
  CHECK(zring_reset(NULL) == ZRING_ERR_ARG);
  CHECK(zring_reset(&r) == ZRING_OK && zring_len(&r) == 0);
}

/* ---- fuzz against a reference model ---------------------------------------- */

static uint64_t rng_state = 0xD1B54A32D192ED03ull;
static uint64_t rng_next(void) {
  rng_state ^= rng_state << 13;
  rng_state ^= rng_state >> 7;
  rng_state ^= rng_state << 17;
  return rng_state;
}

static void test_fuzz(void) {
  /* Model: plain array queue. Random write/read/peek/drop bursts must
   * match the ring exactly, across arbitrary wrap states. */
  int trial;
  for (trial = 0; trial < 2000; trial++) {
    unsigned char store[64];
    unsigned char model[64];
    size_t mhead = 0, mcount = 0;
    const size_t cap = 1 + rng_next() % 64;
    zring r;
    int step;
    CHECK(zring_init(&r, store, cap) == ZRING_OK);
    for (step = 0; step < 200; step++) {
      unsigned char tmp[64];
      size_t n = rng_next() % 20, i, got;
      switch (rng_next() % 4) {
      case 0: /* write */
        for (i = 0; i < n; i++) tmp[i] = (unsigned char)rng_next();
        got = zring_write(&r, tmp, n);
        CHECK(got == (n < cap - mcount ? n : cap - mcount));
        for (i = 0; i < got; i++) model[(mhead + mcount + i) % 64] = tmp[i];
        mcount += got;
        break;
      case 1: /* read */
        got = zring_read(&r, tmp, n);
        CHECK(got == (n < mcount ? n : mcount));
        for (i = 0; i < got; i++)
          CHECK(tmp[i] == model[(mhead + i) % 64]);
        mhead = (mhead + got) % 64;
        mcount -= got;
        break;
      case 2: /* peek_at */
        got = zring_peek_at(&r, n, tmp, sizeof(tmp));
        CHECK(got == (mcount > n ? (mcount - n < 64 ? mcount - n : 64)
                                 : 0));
        for (i = 0; i < got; i++)
          CHECK(tmp[i] == model[(mhead + n + i) % 64]);
        break;
      default: /* drop */
        got = zring_drop(&r, n);
        CHECK(got == (n < mcount ? n : mcount));
        mhead = (mhead + got) % 64;
        mcount -= got;
        break;
      }
      CHECK(zring_len(&r) == mcount);
      CHECK(zring_avail(&r) == cap - mcount);
    }
  }
}

int main(void) {
  test_basic();
  test_wrap();
  test_bulk();
  test_peek_drop();
  test_err_null();
  test_fuzz();
  if (g_fail) {
    fprintf(stderr, "test_zring: FAILURES\n");
    return 1;
  }
  printf("test_zring: all groups passed (basic wrap bulk peek err null fuzz)\n");
  return 0;
}
