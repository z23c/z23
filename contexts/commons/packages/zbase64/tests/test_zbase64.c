/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: zbase64 test suite.  Exits nonzero on the first failure. */
#include "zbase64/zbase64.h"

#include <stdio.h>
#include <string.h>

static int failures = 0;

#define CHECK(cond)                                                          \
  do {                                                                       \
    if (!(cond)) {                                                           \
      fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);        \
      failures++;                                                            \
    }                                                                        \
  } while (0)

static void test_rfc4648_vectors(void) {
  static const struct {
    const char *plain;
    const char *coded;
  } vectors[] = {
      {"",       ""},
      {"f",      "Zg=="},
      {"fo",     "Zm8="},
      {"foo",    "Zm9v"},
      {"foob",   "Zm9vYg=="},
      {"fooba",  "Zm9vYmE="},
      {"foobar", "Zm9vYmFy"},
  };
  char enc[64];
  uint8_t dec[64];
  size_t dec_len = 0;
  for (size_t i = 0; i < sizeof(vectors) / sizeof(vectors[0]); i++) {
    size_t plen = strlen(vectors[i].plain);
    CHECK(zbase64_encode_len(plen) == strlen(vectors[i].coded));
    CHECK(zbase64_encode((const uint8_t *)vectors[i].plain, plen, enc,
                         sizeof(enc)));
    CHECK(strcmp(enc, vectors[i].coded) == 0);
    CHECK(zbase64_decode(vectors[i].coded, strlen(vectors[i].coded), dec,
                         sizeof(dec), &dec_len));
    CHECK(dec_len == plen);
    CHECK(memcmp(dec, vectors[i].plain, plen) == 0);
  }
}

static void test_urlsafe(void) {
  /* 0xfb 0xff 0xfe maps to '+/..' in the standard alphabet and '-_..' in
   * the URL-safe one. */
  static const uint8_t raw[] = {0xfb, 0xff, 0xfe, 0x01};
  char enc[16];
  CHECK(zbase64_encode(raw, sizeof(raw), enc, sizeof(enc)));
  CHECK(strcmp(enc, "+//+AQ==") == 0);
  CHECK(zbase64url_encode(raw, sizeof(raw), enc, sizeof(enc)));
  CHECK(strcmp(enc, "-__-AQ==") == 0);

  uint8_t dec[8];
  size_t n = 0;
  CHECK(zbase64url_decode("-__-AQ==", 8, dec, sizeof(dec), &n));
  CHECK(n == sizeof(raw) && memcmp(dec, raw, n) == 0);
  CHECK(zbase64url_decode("-__-AQ", 6, dec, sizeof(dec), &n)); /* no pad */
  CHECK(n == sizeof(raw) && memcmp(dec, raw, n) == 0);

  /* Alphabets never mix. */
  CHECK(!zbase64_decode("-__-AQ==", 8, dec, sizeof(dec), &n));
  CHECK(!zbase64url_decode("+//+AQ==", 8, dec, sizeof(dec), &n));
}

static void test_strict_rejections(void) {
  uint8_t dec[16];
  size_t n = 0;
  CHECK(!zbase64_decode("Zg=", 3, dec, sizeof(dec), &n));     /* short */
  CHECK(!zbase64_decode("Zg===", 5, dec, sizeof(dec), &n));   /* long */
  CHECK(!zbase64_decode("Z===", 4, dec, sizeof(dec), &n));    /* pad>2 */
  CHECK(!zbase64_decode("Zm 9v", 5, dec, sizeof(dec), &n));   /* space */
  CHECK(!zbase64_decode("Zm9v\n", 5, dec, sizeof(dec), &n));  /* newline */
  CHECK(!zbase64_decode("Zh==", 4, dec, sizeof(dec), &n));    /* pad bits
                                                                 nonzero */
  CHECK(!zbase64_decode("Zm9=", 4, dec, sizeof(dec), &n));    /* leftover
                                                                 bits */
  CHECK(!zbase64url_decode("A", 1, dec, sizeof(dec), &n));    /* 1 sextet */
  CHECK(!zbase64url_decode("AAA=A", 5, dec, sizeof(dec), &n));/* mid pad */
  CHECK(!zbase64_decode(nullptr, 4, dec, sizeof(dec), &n));
  CHECK(!zbase64_decode("Zm9v", 4, nullptr, 16, &n));
  /* Output cap too small. */
  CHECK(!zbase64_decode("Zm9v", 4, dec, 2, &n));
  /* A rejected decode reports no partial length. */
  CHECK(n == 0);
}

static void test_roundtrip_all_bytes(void) {
  uint8_t raw[256];
  for (size_t i = 0; i < sizeof(raw); i++)
    raw[i] = (uint8_t)i;
  char enc[zbase64_encode_len(sizeof(raw)) + 1];
  uint8_t dec[sizeof(raw)];
  size_t n = 0;
  CHECK(zbase64_encode(raw, sizeof(raw), enc, sizeof(enc)));
  CHECK(zbase64_decode(enc, strlen(enc), dec, sizeof(dec), &n));
  CHECK(n == sizeof(raw) && memcmp(dec, raw, n) == 0);
  CHECK(zbase64url_encode(raw, sizeof(raw), enc, sizeof(enc)));
  CHECK(zbase64url_decode(enc, strlen(enc), dec, sizeof(dec), &n));
  CHECK(n == sizeof(raw) && memcmp(dec, raw, n) == 0);
}

static void test_size_arithmetic(void) {
  CHECK(zbase64_encode_len(0) == 0);
  CHECK(zbase64_encode_len(1) == 4);
  CHECK(zbase64_encode_len(2) == 4);
  CHECK(zbase64_encode_len(3) == 4);
  CHECK(zbase64_encode_len(4) == 8);
  /* Encode into the exact cap (plus NUL) and one byte short. */
  char enc[9];
  static const uint8_t four[] = {1, 2, 3, 4};
  CHECK(zbase64_encode(four, 4, enc, 9));
  CHECK(!zbase64_encode(four, 4, enc, 8));
  CHECK(!zbase64_encode(nullptr, 4, enc, sizeof(enc)));
  CHECK(zbase64_encode(nullptr, 0, enc, sizeof(enc))); /* empty ok */
  CHECK(enc[0] == '\0');
}

int main(void) {
  test_rfc4648_vectors();
  test_urlsafe();
  test_strict_rejections();
  test_roundtrip_all_bytes();
  test_size_arithmetic();
  if (failures) {
    fprintf(stderr, "zbase64: %d failure(s)\n", failures);
    return 1;
  }
  printf("zbase64: all tests passed\n");
  return 0;
}
