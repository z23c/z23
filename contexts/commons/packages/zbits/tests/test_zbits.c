/* Tests for zbits — fixed-size bitset.
 * Groups: basic, bulk, rank, first, ops, err, fuzz. */
#include "zbits/zbits.h"

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

int main(void) {
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
