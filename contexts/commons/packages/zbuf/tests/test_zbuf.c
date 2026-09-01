/* Tests for zbuf — bounded growable byte buffer.
 * Groups: basic, printf, bound, sticky, null, fuzz. */
#include "zbuf/zbuf.h"

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
  zbuf b;
  CHECK(zbuf_init(&b, 4096) == ZBUF_OK);
  CHECK(zbuf_len(&b) == 0 && strcmp(zbuf_cstr(&b), "") == 0);
  CHECK(zbuf_str(&b, "hello") == ZBUF_OK);
  CHECK(zbuf_put(&b, ' ') == ZBUF_OK);
  CHECK(zbuf_str(&b, "world") == ZBUF_OK);
  CHECK(zbuf_len(&b) == 11 && strcmp(zbuf_cstr(&b), "hello world") == 0);
  CHECK(zbuf_write(&b, "\0x", 2) == ZBUF_OK); /* embedded NUL kept */
  CHECK(zbuf_len(&b) == 13 && b.data[11] == '\0' && b.data[12] == 'x');
  zbuf_clear(&b);
  CHECK(zbuf_len(&b) == 0 && strcmp(zbuf_cstr(&b), "") == 0);
  zbuf_free(&b);
  CHECK(zbuf_len(&b) == 0 && b.data == NULL);
}

static void test_printf(void) {
  zbuf b;
  zbuf_init(&b, 4096);
  CHECK(zbuf_printf(&b, "%d %s %.2f", 42, "x", 1.005) == ZBUF_OK);
  CHECK(strcmp(zbuf_cstr(&b), "42 x 1.00") == 0 ||
        strcmp(zbuf_cstr(&b), "42 x 1.01") == 0);
  CHECK(zbuf_printf(&b, "%c%03d", '!', 7) == ZBUF_OK);
  CHECK(strstr(zbuf_cstr(&b), "!007") != NULL);
  zbuf_free(&b);
}

static void test_bound(void) {
  zbuf b;
  zbuf_init(&b, 8);
  CHECK(zbuf_write(&b, "12345678", 8) == ZBUF_OK); /* exactly full */
  CHECK(zbuf_put(&b, '9') == ZBUF_ERR_FULL);
  CHECK(zbuf_len(&b) == 8); /* failed write changed nothing */
  zbuf_free(&b);
}

static void test_sticky(void) {
  zbuf b;
  zbuf_init(&b, 4);
  CHECK(zbuf_str(&b, "abcd") == ZBUF_OK);
  CHECK(zbuf_str(&b, "ef") == ZBUF_ERR_FULL);
  CHECK(zbuf_status(&b) == ZBUF_ERR_FULL);
  CHECK(zbuf_str(&b, "g") == ZBUF_ERR_FULL);  /* sticky */
  CHECK(zbuf_put(&b, 'g') == ZBUF_ERR_FULL);  /* sticky */
  CHECK(zbuf_len(&b) == 4 && strcmp(zbuf_cstr(&b), "abcd") == 0);
  zbuf_clear(&b);                             /* clear resets */
  CHECK(zbuf_status(&b) == ZBUF_OK);
  CHECK(zbuf_str(&b, "xy") == ZBUF_OK);
  zbuf_free(&b);
}

static void test_null(void) {
  zbuf b;
  CHECK(zbuf_init(NULL, 8) == ZBUF_ERR_ARG);
  CHECK(zbuf_put(NULL, 'x') == ZBUF_ERR_ARG);
  CHECK(zbuf_str(NULL, "x") == ZBUF_ERR_ARG);
  CHECK(zbuf_printf(NULL, "x") == ZBUF_ERR_ARG);
  CHECK(zbuf_len(NULL) == 0);
  CHECK(strcmp(zbuf_cstr(NULL), "") == 0);
  CHECK(zbuf_status(NULL) == ZBUF_ERR_ARG);
  zbuf_init(&b, 8);
  CHECK(zbuf_write(&b, NULL, 3) == ZBUF_ERR_ARG);
  CHECK(zbuf_write(&b, NULL, 0) == ZBUF_OK);
  CHECK(zbuf_str(&b, NULL) == ZBUF_ERR_ARG);
  CHECK(zbuf_status(&b) == ZBUF_OK); /* ARG is not sticky */
  zbuf_free(NULL);                   /* tolerated */
  zbuf_clear(NULL);                  /* tolerated */
  zbuf_free(&b);
}

/* ---- fuzz against a reference model ---------------------------------------- */

static uint64_t rng_state = 0xE5C1A94F0B3D7628ull;
static uint64_t rng_next(void) {
  rng_state ^= rng_state << 13;
  rng_state ^= rng_state >> 7;
  rng_state ^= rng_state << 17;
  return rng_state;
}

static void test_fuzz(void) {
  int trial;
  for (trial = 0; trial < 1500; trial++) {
    zbuf b;
    unsigned char model[512];
    size_t mlen = 0;
    size_t max = 1 + rng_next() % 512;
    int step, failed = 0;
    zbuf_init(&b, max);
    for (step = 0; step < 100; step++) {
      unsigned char tmp[32];
      size_t n = rng_next() % 32, i;
      for (i = 0; i < n; i++) tmp[i] = (unsigned char)rng_next();
      if (rng_next() % 8 == 0) { /* clear */
        zbuf_clear(&b);
        mlen = 0;
        failed = 0;
        continue;
      }
      {
        zbuf_err e = zbuf_write(&b, tmp, n);
        if (!failed && mlen + n <= max) {
          CHECK(e == ZBUF_OK);
          memcpy(model + mlen, tmp, n);
          mlen += n;
        } else {
          if (!failed) {
            CHECK(e == ZBUF_ERR_FULL);
            failed = 1;
          } else {
            CHECK(e == ZBUF_ERR_FULL); /* sticky */
          }
        }
      }
      CHECK(zbuf_len(&b) == mlen);
      CHECK(mlen == 0 || memcmp(b.data, model, mlen) == 0);
    }
    zbuf_free(&b);
  }
}

int main(void) {
  test_basic();
  test_printf();
  test_bound();
  test_sticky();
  test_null();
  test_fuzz();
  if (g_fail) {
    fprintf(stderr, "test_zbuf: FAILURES\n");
    return 1;
  }
  printf("test_zbuf: all groups passed (basic printf bound sticky null fuzz)\n");
  return 0;
}
