/* Tests for zutf16 — strict UTF-8 <-> UTF-16LE transcoding.
 * Groups: kat, err, roundtrip, null, fuzz. */
#include "zutf16/zutf16.h"

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

/* ---- known answers ------------------------------------------------------ */

static void test_kat(void) {
  static const struct {
    const char *utf8;       /* C string */
    const unsigned char *u16; /* LE bytes */
    size_t u16len;
  } KAT[] = {
      {"", (const unsigned char *)"", 0},
      {"A", (const unsigned char *)"\x41\x00", 2},
      {"\xC3\xA9", (const unsigned char *)"\xE9\x00", 2},     /* é */
      {"\xE2\x82\xAC", (const unsigned char *)"\xAC\x20", 2}, /* € */
      {"\xF0\x9F\x98\x80",
       (const unsigned char *)"\x3D\xD8\x00\xDE", 4},         /* 😀 */
      {"A\xC3\xA9\xE2\x82\xAC\xF0\x9F\x98\x80" "z",
       (const unsigned char *)"\x41\x00\xE9\x00\xAC\x20\x3D\xD8\x00\xDE"
                              "\x7A\x00",
       12},
  };
  size_t i;
  for (i = 0; i < sizeof(KAT) / sizeof(KAT[0]); i++) {
    unsigned char u16[64];
    char u8[64];
    size_t n8 = strlen(KAT[i].utf8);
    size_t need = zutf16_from_utf8(u16, sizeof(u16), KAT[i].utf8, n8);
    if (need != KAT[i].u16len ||
        memcmp(u16, KAT[i].u16, KAT[i].u16len) != 0) {
      fprintf(stderr, "FAIL kat enc: case %zu\n", i);
      g_fail = 1;
    }
    need = zutf16_to_utf8(u8, sizeof(u8), KAT[i].u16, KAT[i].u16len);
    if (need != n8 || memcmp(u8, KAT[i].utf8, n8) != 0) {
      fprintf(stderr, "FAIL kat dec: case %zu\n", i);
      g_fail = 1;
    }
  }
  /* Length queries. */
  CHECK(zutf16_units_from_utf8("A\xC3\xA9\xF0\x9F\x98\x80", 7) == 4);
  CHECK(zutf8_bytes_from_utf16("\x3D\xD8\x00\xDE", 4) == 4);
  /* Unit helpers. */
  {
    uint16_t u[2];
    uint32_t cp = 0;
    CHECK(zutf16_encode_cp(u, 0x1F600) == 2 && u[0] == 0xD83D &&
          u[1] == 0xDE00);
    CHECK(zutf16_encode_cp(u, 0x41) == 1 && u[0] == 0x41);
    CHECK(zutf16_encode_cp(u, 0xD800) == 0);
    CHECK(zutf16_encode_cp(u, 0x110000) == 0);
    CHECK(zutf16_decode_cp("\xC3\xA9", 2, &cp) == 2 && cp == 0xE9);
    CHECK(zutf16_decode_cp("\xC3\xA9", 1, &cp) == SIZE_MAX);
  }
}

/* ---- malformed inputs ----------------------------------------------------- */

static void test_err(void) {
  static const struct {
    const unsigned char *s;
    size_t n;
  } BAD8[] = {
      {(const unsigned char *)"\x80", 1},        /* stray continuation */
      {(const unsigned char *)"\xC0\xAF", 2},    /* overlong '/' */
      {(const unsigned char *)"\xC1\xBF", 2},    /* overlong */
      {(const unsigned char *)"\xE0\x80\xAF", 3},/* overlong 3 */
      {(const unsigned char *)"\xED\xA0\x80", 3},/* U+D800 encoded */
      {(const unsigned char *)"\xF4\x90\x80\x80", 4}, /* > U+10FFFF */
      {(const unsigned char *)"\xF5\x80\x80\x80", 4}, /* bad lead */
      {(const unsigned char *)"\xC3", 1},        /* truncated */
      {(const unsigned char *)"\xE2\x82", 2},    /* truncated */
      {(const unsigned char *)"\xC3\x28", 2},    /* bad continuation */
  };
  static const struct {
    const unsigned char *s;
    size_t n;
  } BAD16[] = {
      {(const unsigned char *)"\x41", 1},            /* odd length */
      {(const unsigned char *)"\x00\xD8", 2},        /* lone high */
      {(const unsigned char *)"\x00\xDC", 2},        /* lone low */
      {(const unsigned char *)"\x00\xD8\x41\x00", 4},/* high + non-low */
      {(const unsigned char *)"\x00\xD8", 2},
      {(const unsigned char *)"\x3D\xD8\x00", 3},    /* truncated pair */
  };
  size_t i;
  char out[32];
  for (i = 0; i < sizeof(BAD8) / sizeof(BAD8[0]); i++)
    CHECK(zutf16_from_utf8(out, sizeof(out), BAD8[i].s, BAD8[i].n) ==
          SIZE_MAX);
  for (i = 0; i < sizeof(BAD16) / sizeof(BAD16[0]); i++)
    CHECK(zutf16_to_utf8(out, sizeof(out), BAD16[i].s, BAD16[i].n) ==
          SIZE_MAX);
}

/* ---- round trip -------------------------------------------------------------- */

static void test_roundtrip(void) {
  /* Every valid codepoint: cp -> UTF-16 units -> UTF-8 -> cp. */
  uint32_t cp;
  for (cp = 0; cp <= 0x10FFFF; cp++) {
    uint16_t u[2];
    unsigned char le[4];
    char back[8];
    uint32_t got = 0;
    size_t nu, nb, used;
    if (cp >= 0xD800 && cp <= 0xDFFF) continue;
    nu = zutf16_encode_cp(u, cp);
    CHECK(nu == (cp < 0x10000 ? 1u : 2u));
    le[0] = (unsigned char)(u[0] & 0xFF);
    le[1] = (unsigned char)(u[0] >> 8);
    if (nu == 2) {
      le[2] = (unsigned char)(u[1] & 0xFF);
      le[3] = (unsigned char)(u[1] >> 8);
    }
    nb = zutf16_to_utf8(back, sizeof(back), le, nu * 2);
    CHECK(nb != SIZE_MAX);
    used = zutf16_decode_cp(back, nb, &got);
    CHECK(used == nb && got == cp);
    if (g_fail) return;
  }
}

/* ---- NULL / bounds ---------------------------------------------------------------- */

static void test_null(void) {
  char out[8];
  uint32_t cp;
  CHECK(zutf16_from_utf8(out, sizeof(out), NULL, 2) == SIZE_MAX);
  CHECK(zutf16_from_utf8(out, sizeof(out), NULL, 0) == 0);
  CHECK(zutf16_to_utf8(out, sizeof(out), NULL, 2) == SIZE_MAX);
  CHECK(zutf16_to_utf8(out, sizeof(out), NULL, 0) == 0);
  CHECK(zutf16_decode_cp(NULL, 1, &cp) == 0);
  CHECK(zutf16_decode_cp("A", 1, NULL) == 0);
  CHECK(zutf16_encode_cp(NULL, 0x41) == 0);
  /* Truncated output: needed length still reported. */
  CHECK(zutf16_from_utf8(out, 3, "AB", 2) == 4);
  CHECK(zutf16_to_utf8(out, 3, "\x41\x00\x42\x00", 4) == 2);
}

/* ---- fuzz -------------------------------------------------------------------------------- */

static uint64_t rng_state = 0x1B873593D7E4A2F1ull;
static uint64_t rng_next(void) {
  rng_state ^= rng_state << 13;
  rng_state ^= rng_state >> 7;
  rng_state ^= rng_state << 17;
  return rng_state;
}

static void test_fuzz(void) {
  int trial;
  for (trial = 0; trial < 3000; trial++) {
    /* Build a valid UTF-8 string from random codepoints, transcode
     * both ways, compare byte-for-byte. Then mutate and ensure the
     * decoder never crashes. */
    char u8[256];
    unsigned char le[512];
    char back[256];
    size_t n = 0, cps = rng_next() % 40, k, nb, nb2;
    for (k = 0; k < cps; k++) {
      uint32_t cp;
      do {
        cp = (uint32_t)(rng_next() % 0x110000);
      } while (cp >= 0xD800 && cp <= 0xDFFF);
      if (cp < 0x80) u8[n++] = (char)cp;
      else if (cp < 0x800) {
        u8[n++] = (char)(0xC0 | (cp >> 6));
        u8[n++] = (char)(0x80 | (cp & 0x3F));
      } else if (cp < 0x10000) {
        u8[n++] = (char)(0xE0 | (cp >> 12));
        u8[n++] = (char)(0x80 | ((cp >> 6) & 0x3F));
        u8[n++] = (char)(0x80 | (cp & 0x3F));
      } else {
        u8[n++] = (char)(0xF0 | (cp >> 18));
        u8[n++] = (char)(0x80 | ((cp >> 12) & 0x3F));
        u8[n++] = (char)(0x80 | ((cp >> 6) & 0x3F));
        u8[n++] = (char)(0x80 | (cp & 0x3F));
      }
    }
    nb = zutf16_from_utf8(le, sizeof(le), u8, n);
    CHECK(nb != SIZE_MAX && nb % 2 == 0);
    nb2 = zutf16_to_utf8(back, sizeof(back), le, nb);
    CHECK(nb2 == n && (n == 0 || memcmp(back, u8, n) == 0));
    /* Mutate. */
    if (n > 0) {
      size_t pos = rng_next() % n;
      char save = u8[pos];
      u8[pos] = (char)(rng_next() % 256);
      (void)zutf16_from_utf8(le, sizeof(le), u8, n);
      u8[pos] = save;
    }
    if (nb > 0) {
      size_t pos = rng_next() % nb;
      unsigned char save = le[pos];
      le[pos] = (unsigned char)(rng_next() % 256);
      (void)zutf16_to_utf8(back, sizeof(back), le, nb);
      le[pos] = save;
    }
  }
}

int main(void) {
  test_kat();
  test_err();
  test_roundtrip();
  test_null();
  test_fuzz();
  if (g_fail) {
    fprintf(stderr, "test_zutf16: FAILURES\n");
    return 1;
  }
  printf("test_zutf16: all groups passed (kat err roundtrip null fuzz)\n");
  return 0;
}
