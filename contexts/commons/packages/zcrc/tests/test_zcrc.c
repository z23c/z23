/* zcrc tests: published check vectors, streaming/one-shot agreement,
 * a bit-by-bit reference oracle, and split-update invariance.
 * Built with -std=c23 -Wall -Wextra -Werror -pedantic, ASan/UBSan. */

#include "zcrc/zcrc.h"

#include <stdio.h>
#include <stdint.h>
#include <string.h>

static int failures = 0;

#define CHECK(cond)                                                     \
  do {                                                                  \
    if (!(cond)) {                                                      \
      fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);   \
      failures++;                                                       \
    }                                                                   \
  } while (0)

/* ---------- published vectors ---------------------------------------
 * Sources: RFC 1662 / zlib test suite (CRC-32) and RFC 3720
 * (CRC-32C).  All for ASCII "123456789".                        */
static void test_check_vectors(void) {
  const char *s = "123456789";
  CHECK(zcrc32(s, 9) == 0xCBF43926u);
  CHECK(zcrc32c(s, 9) == 0xE3069283u);
  /* empty input */
  CHECK(zcrc32("", 0) == 0u);
  CHECK(zcrc32c("", 0) == 0u);
  /* single bytes (computed via the reference below too) */
  CHECK(zcrc32("a", 1) == 0xE8B7BE43u);
  CHECK(zcrc32c("a", 1) == 0xC1D04330u);
}

/* ---------- bit-by-bit reference ------------------------------------ */
static uint32_t ref_crc(const void *data, size_t len, uint32_t poly) {
  const unsigned char *p = data;
  uint32_t c = 0xFFFFFFFFu;
  size_t i;
  int k;
  for (i = 0; i < len; i++) {
    c ^= p[i];
    for (k = 0; k < 8; k++) c = (c & 1) ? (c >> 1) ^ poly : (c >> 1);
  }
  return c ^ 0xFFFFFFFFu;
}

static unsigned long long rng_state = 0xFEEDFACE12345678ull;
static unsigned long long rnd(void) {
  unsigned long long x = rng_state;
  x ^= x >> 12;
  x ^= x << 25;
  x ^= x >> 27;
  rng_state = x;
  return x * 0x2545F4914F6CDD1Dull;
}

static void test_reference_oracle(void) {
  unsigned char buf[1024];
  int t;
  for (t = 0; t < 5000; t++) {
    size_t len = rnd() % sizeof buf;
    size_t i;
    for (i = 0; i < len; i++) buf[i] = (unsigned char)(rnd() >> 32);
    CHECK(zcrc32(buf, len) == ref_crc(buf, len, 0xEDB88320u));
    CHECK(zcrc32c(buf, len) == ref_crc(buf, len, 0x82F63B78u));
  }
}

/* ---------- streaming invariance ------------------------------------ */
static void test_streaming(void) {
  unsigned char buf[512];
  int t;
  for (t = 0; t < 3000; t++) {
    size_t len = rnd() % sizeof buf;
    size_t cut1 = len ? rnd() % len : 0;
    size_t cut2 = len ? cut1 + rnd() % (len - cut1) : 0;
    size_t i;
    uint32_t s32, s32c;
    for (i = 0; i < len; i++) buf[i] = (unsigned char)(rnd() >> 40);
    s32 = zcrc32_init();
    s32 = zcrc32_update(s32, buf, cut1);
    s32 = zcrc32_update(s32, buf + cut1, cut2 - cut1);
    s32 = zcrc32_update(s32, buf + cut2, len - cut2);
    CHECK(zcrc32_final(s32) == zcrc32(buf, len));
    s32c = zcrc32c_init();
    s32c = zcrc32c_update(s32c, buf, cut1);
    s32c = zcrc32c_update(s32c, buf + cut1, cut2 - cut1);
    s32c = zcrc32c_update(s32c, buf + cut2, len - cut2);
    CHECK(zcrc32c_final(s32c) == zcrc32c(buf, len));
  }
}

/* ---------- misc ------------------------------------------------------ */
static void test_misc(void) {
  /* NULL data leaves state unchanged */
  uint32_t s = zcrc32_init();
  uint32_t s2 = zcrc32_update(s, NULL, 10);
  CHECK(s2 == s);
  CHECK(zcrc32(NULL, 5) == zcrc32("", 0));
  CHECK(zcrc32c(NULL, 5) == zcrc32c("", 0));
  /* all-ones and all-zeros buffers differ between the two variants */
  {
    unsigned char zeros[64];
    unsigned char ones[64];
    memset(zeros, 0, sizeof zeros);
    memset(ones, 0xFF, sizeof ones);
    CHECK(zcrc32(zeros, sizeof zeros) != zcrc32c(zeros, sizeof zeros));
    CHECK(zcrc32(ones, sizeof ones) != zcrc32c(ones, sizeof ones));
  }
}

int main(void) {
  test_check_vectors();
  test_reference_oracle();
  test_streaming();
  test_misc();
  if (failures) {
    fprintf(stderr, "%d failure(s)\n", failures);
    return 1;
  }
  puts("zcrc: all tests passed");
  return 0;
}
