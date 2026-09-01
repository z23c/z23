/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: zutf8 test suite.  Exits nonzero on the first failure.
 * Byte-level known-answer tests follow RFC 3629 and the Unicode
 * "well-formed UTF-8 byte sequences" table (boundary values, overlong
 * forms, surrogates, and the U+10FFFF ceiling). */
#include "zutf8/zutf8.h"

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

#define VALID(s) CHECK(zutf8_validate_n((s), sizeof(s) - 1))
#define INVALID(s) CHECK(!zutf8_validate_n((s), sizeof(s) - 1))

/* Decode one sequence and expect cp/length. */
#define DEC(s, want_cp, want_len)                                            \
  do {                                                                       \
    uint32_t cp_ = 0;                                                        \
    size_t used_ = 0;                                                        \
    CHECK(zutf8_decode_n((s), sizeof(s) - 1, &cp_, &used_) == ZUTF8_OK);     \
    CHECK(cp_ == (want_cp));                                                 \
    CHECK(used_ == (want_len));                                              \
  } while (0)

#define DEC_STATUS(s, want)                                                  \
  do {                                                                       \
    uint32_t cp_;                                                            \
    size_t used_ = 99;                                                       \
    CHECK(zutf8_decode_n((s), sizeof(s) - 1, &cp_, &used_) == (want));       \
    CHECK(used_ == 0);                                                       \
  } while (0)

static void test_valid_kats(void) {
  VALID("");
  VALID("hello, world");
  VALID("\x7F"); /* U+007F: top of ASCII */
  VALID("\xC2\x80"); /* U+0080: first 2-byte */
  VALID("\xDF\xBF"); /* U+07FF: last 2-byte */
  VALID("\xC2\xA2"); /* U+00A2 CENT SIGN */
  VALID("\xE0\xA0\x80"); /* U+0800: first 3-byte */
  VALID("\xED\x9F\xBF"); /* U+D7FF: below surrogates */
  VALID("\xEE\x80\x80"); /* U+E000: above surrogates */
  VALID("\xEF\xBF\xBF"); /* U+FFFF: last 3-byte */
  VALID("\xE2\x82\xAC"); /* U+20AC EURO */
  VALID("\xF0\x90\x80\x80"); /* U+10000: first 4-byte */
  VALID("\xF0\x90\x8D\x88"); /* U+10348 GOTHIC HWAIR */
  VALID("\xF4\x8F\xBF\xBF"); /* U+10FFFF: the ceiling */
  VALID("a\xC2\xA2" "b\xE2\x82\xAC" "c\xF0\x90\x8D\x88" "d"); /* mixed */
  /* Embedded NUL is a valid code point for _n APIs. */
  CHECK(zutf8_validate_n("a\0b", 3));
  CHECK(zutf8_count_n("a\0b", 3) == 3);
}

static void test_decode_kats(void) {
  DEC("A", 0x41, 1);
  DEC("\xC2\xA2", 0xA2, 2);
  DEC("\xDF\xBF", 0x7FF, 2);
  DEC("\xE0\xA0\x80", 0x800, 3);
  DEC("\xE2\x82\xAC", 0x20AC, 3);
  DEC("\xEF\xBF\xBF", 0xFFFF, 3);
  DEC("\xF0\x90\x80\x80", 0x10000, 4);
  DEC("\xF4\x8F\xBF\xBF", 0x10FFFF, 4);
  /* Trailing bytes beyond the sequence are not consumed. */
  {
    uint32_t cp;
    size_t used;
    CHECK(zutf8_decode_n("\xC2\xA2xy", 4, &cp, &used) == ZUTF8_OK);
    CHECK(cp == 0xA2 && used == 2);
  }
}

static void test_invalid_kats(void) {
  INVALID("\x80"); /* lone continuation */
  INVALID("\xBF");
  INVALID("\xC0\x80"); /* overlong NUL */
  INVALID("\xC1\xBF"); /* overlong U+007F */
  INVALID("\xC2"); /* truncated 2-byte */
  INVALID("\xC2" "A"); /* bad continuation */
  INVALID("\xE0\x80\x80"); /* overlong 3-byte */
  INVALID("\xE0\x9F\xBF"); /* overlong boundary */
  INVALID("\xE1\x80"); /* truncated 3-byte */
  INVALID("\xE2\x82" "A"); /* bad third byte */
  INVALID("\xED\xA0\x80"); /* surrogate U+D800 */
  INVALID("\xED\xBF\xBF"); /* surrogate U+DFFF */
  INVALID("\xF0\x80\x80\x80"); /* overlong 4-byte */
  INVALID("\xF0\x8F\xBF\xBF"); /* overlong boundary */
  INVALID("\xF0\x90\x80"); /* truncated 4-byte */
  INVALID("\xF4\x90\x80\x80"); /* U+110000: above the ceiling */
  INVALID("\xF5\x80\x80\x80"); /* 0xF5 never valid */
  INVALID("\xFE");
  INVALID("\xFF");
  INVALID("ok then \xFF");
  INVALID("\xE2\x82\xAC\x80"); /* valid then stray continuation */
}

static void test_decode_status(void) {
  DEC_STATUS("\x80", ZUTF8_INVALID);
  DEC_STATUS("\xC2", ZUTF8_TRUNCATED);
  DEC_STATUS("\xE2\x82", ZUTF8_TRUNCATED);
  DEC_STATUS("\xF0\x90\x80", ZUTF8_TRUNCATED);
  {
    uint32_t cp;
    size_t used;
    CHECK(zutf8_decode_n("", 0, &cp, &used) == ZUTF8_TRUNCATED);
    CHECK(zutf8_decode_n(NULL, 5, &cp, &used) == ZUTF8_INVALID);
    CHECK(zutf8_decode_n("A", 1, NULL, &used) == ZUTF8_INVALID);
    CHECK(zutf8_decode_n("A", 1, &cp, NULL) == ZUTF8_OK);
  }
}

static void test_encode_kats(void) {
  char out[4];
  CHECK(zutf8_encode(0x41, out) == 1 && out[0] == 'A');
  CHECK(zutf8_encode(0x7F, out) == 1 && (unsigned char)out[0] == 0x7F);
  CHECK(zutf8_encode(0x80, out) == 2 && (unsigned char)out[0] == 0xC2 &&
        (unsigned char)out[1] == 0x80);
  CHECK(zutf8_encode(0x7FF, out) == 2 && (unsigned char)out[0] == 0xDF &&
        (unsigned char)out[1] == 0xBF);
  CHECK(zutf8_encode(0x800, out) == 3 && (unsigned char)out[0] == 0xE0 &&
        (unsigned char)out[1] == 0xA0 && (unsigned char)out[2] == 0x80);
  CHECK(zutf8_encode(0x20AC, out) == 3 && (unsigned char)out[0] == 0xE2 &&
        (unsigned char)out[1] == 0x82 && (unsigned char)out[2] == 0xAC);
  CHECK(zutf8_encode(0xFFFF, out) == 3 && (unsigned char)out[0] == 0xEF &&
        (unsigned char)out[1] == 0xBF && (unsigned char)out[2] == 0xBF);
  CHECK(zutf8_encode(0x10000, out) == 4 && (unsigned char)out[0] == 0xF0 &&
        (unsigned char)out[1] == 0x90);
  CHECK(zutf8_encode(0x10FFFF, out) == 4 && (unsigned char)out[0] == 0xF4 &&
        (unsigned char)out[1] == 0x8F && (unsigned char)out[2] == 0xBF &&
        (unsigned char)out[3] == 0xBF);
  /* Rejections: surrogates and above the ceiling. */
  CHECK(zutf8_encode(0xD800, out) == 0);
  CHECK(zutf8_encode(0xDFFF, out) == 0);
  CHECK(zutf8_encode(0x110000, out) == 0);
  CHECK(zutf8_encode(UINT32_MAX, out) == 0);
  /* NULL out measures only. */
  CHECK(zutf8_encode(0x20AC, NULL) == 3);
  /* Embedded NUL encodes as one byte. */
  CHECK(zutf8_encode(0, out) == 1 && out[0] == 0);
}

static void test_round_trip_sweep(void) {
  /* Every Unicode scalar value must round-trip encode->decode. */
  for (uint32_t cp = 0; cp <= 0x110000u; cp++) {
    char out[4];
    size_t n = zutf8_encode(cp, out);
    if (cp >= 0xD800u && cp <= 0xDFFFu) {
      CHECK(n == 0);
      continue;
    }
    if (cp > 0x10FFFFu) {
      CHECK(n == 0);
      continue;
    }
    if (!n) {
      fprintf(stderr, "FAIL encode(U+%04X) rejected\n", cp);
      failures++;
      continue;
    }
    uint32_t back;
    size_t used;
    if (zutf8_decode_n(out, n, &back, &used) != ZUTF8_OK || back != cp ||
        used != n) {
      fprintf(stderr, "FAIL round-trip U+%04X\n", cp);
      failures++;
    }
  }
}

static void test_count(void) {
  CHECK(zutf8_count_n("", 0) == 0);
  CHECK(zutf8_count_n("abc", 3) == 3);
  CHECK(zutf8_count_n("h\xC3\xA9llo", 6) == 5); /* "héllo" */
  CHECK(zutf8_count_n("\xF0\x90\x8D\x88", 4) == 1);
  CHECK(zutf8_count_n("\xFF", 1) == SIZE_MAX);
  CHECK(zutf8_count_n(NULL, 0) == 0);
  CHECK(zutf8_count_n(NULL, 3) == SIZE_MAX);
  CHECK(!zutf8_validate(NULL));
  CHECK(zutf8_validate_n(NULL, 0));
  CHECK(zutf8_validate("plain ascii"));
  CHECK(!zutf8_validate("\xC2")); /* truncated */
}

int main(void) {
  test_valid_kats();
  test_decode_kats();
  test_invalid_kats();
  test_decode_status();
  test_encode_kats();
  test_round_trip_sweep();
  test_count();
  if (failures) {
    fprintf(stderr, "test_zutf8: %d failure(s)\n", failures);
    return 1;
  }
  puts("test_zutf8: all tests passed");
  return 0;
}
