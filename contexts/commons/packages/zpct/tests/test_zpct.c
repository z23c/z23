/* Tests for zpct — RFC 3986 percent-encoding.
 * Groups: kat, roundtrip, err, trunc, null, fuzz. */
#include "zpct/zpct.h"

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

/* ---- known answers ------------------------------------------------------ */

static void test_kat(void) {
  static const struct {
    const char *in, *out;
    zpct_set set;
  } ENC[] = {
      {"", "", ZPCT_UNRESERVED},
      {"abc-_.~", "abc-_.~", ZPCT_UNRESERVED},
      {"AZaz09", "AZaz09", ZPCT_UNRESERVED},
      {" ", "%20", ZPCT_UNRESERVED},
      {"%", "%25", ZPCT_UNRESERVED},
      {"a b&c=d", "a%20b%26c%3Dd", ZPCT_UNRESERVED},
      {"a b&c=d", "a%20b&c=d", ZPCT_SUBDELIM},
      {"user@host:80", "user%40host%3A80", ZPCT_UNRESERVED},
      {"user@host:80", "user@host:80", ZPCT_PCHAR},
      {"+", "%2B", ZPCT_UNRESERVED},
      {"+", "+", ZPCT_SUBDELIM},
      {"/", "%2F", ZPCT_UNRESERVED}, /* slash always escaped here */
  };
  size_t i;
  for (i = 0; i < sizeof(ENC) / sizeof(ENC[0]); i++) {
    char buf[64];
    size_t need =
        zpct_encode(buf, sizeof(buf), ENC[i].in, strlen(ENC[i].in),
                    ENC[i].set);
    if (need != strlen(ENC[i].out) || strcmp(buf, ENC[i].out) != 0) {
      fprintf(stderr, "FAIL enc: \"%s\" set=%d -> \"%s\" (want \"%s\")\n",
              ENC[i].in, (int)ENC[i].set, buf, ENC[i].out);
      g_fail = 1;
    }
  }
  /* Encode of embedded NUL / 0xFF bytes (strlen-unfriendly). */
  {
    const unsigned char in[2] = {0x00, 0xFF};
    char buf[16];
    CHECK(zpct_encode(buf, sizeof(buf), in, 2, ZPCT_UNRESERVED) == 6 &&
          memcmp(buf, "%00%FF", 6) == 0);
  }
  /* Decode known answers, incl. lowercase hex and decoded NUL. */
  {
    char buf[64];
    size_t len = 999;
    CHECK(zpct_decode(buf, sizeof(buf), "a%20b", 5, &len) == 3 &&
          len == 3 && strcmp(buf, "a b") == 0);
    CHECK(zpct_decode(buf, sizeof(buf), "%61%62%63", 9, &len) == 3 &&
          strcmp(buf, "abc") == 0);
    CHECK(zpct_decode(buf, sizeof(buf), "%00", 3, &len) == 1 && len == 1 &&
          buf[0] == '\0');
    CHECK(zpct_decode(buf, sizeof(buf), "plain", 5, NULL) == 5);
  }
}

/* ---- round trip ------------------------------------------------------------ */

static void test_roundtrip(void) {
  /* Every byte value survives encode->decode in every set. */
  unsigned char all[256];
  char enc[256 * 3 + 8];
  char dec[264];
  size_t i, n, dlen = 0;
  int set;
  for (i = 0; i < 256; i++) all[i] = (unsigned char)i;
  for (set = ZPCT_UNRESERVED; set <= ZPCT_PCHAR; set++) {
    n = zpct_encode(enc, sizeof(enc), all, 256, (zpct_set)set);
    CHECK(n != SIZE_MAX && n <= 768);
    CHECK(zpct_decode(dec, sizeof(dec), enc, n, &dlen) == 256);
    CHECK(dlen == 256 && memcmp(dec, all, 256) == 0);
  }
}

/* ---- malformed decode ----------------------------------------------------------- */

static void test_err(void) {
  char buf[16];
  CHECK(zpct_decode(buf, sizeof(buf), "%", 1, NULL) == SIZE_MAX);
  CHECK(zpct_decode(buf, sizeof(buf), "%A", 2, NULL) == SIZE_MAX);
  CHECK(zpct_decode(buf, sizeof(buf), "%zz", 3, NULL) == SIZE_MAX);
  CHECK(zpct_decode(buf, sizeof(buf), "%2", 2, NULL) == SIZE_MAX);
  CHECK(zpct_decode(buf, sizeof(buf), "a%", 2, NULL) == SIZE_MAX);
  CHECK(zpct_decode(buf, sizeof(buf), "%1x", 3, NULL) == SIZE_MAX);
  CHECK(zpct_encode(buf, sizeof(buf), "x", 1, (zpct_set)9) == SIZE_MAX);
  CHECK(zpct_is_unescaped('a', (zpct_set)9) == 0);
  CHECK(zpct_is_unescaped('a', ZPCT_UNRESERVED) == 1);
  CHECK(zpct_is_unescaped(' ', ZPCT_PCHAR) == 0);
  /* Over-long input. */
  {
    static char big[ZPCT_MAX + 2];
    memset(big, 'a', ZPCT_MAX + 1);
    big[ZPCT_MAX + 1] = '\0';
    CHECK(zpct_encode(buf, sizeof(buf), big, ZPCT_MAX + 1,
                      ZPCT_UNRESERVED) == SIZE_MAX);
    CHECK(zpct_decode(buf, sizeof(buf), big, ZPCT_MAX + 1, NULL) ==
          SIZE_MAX);
  }
}

/* ---- truncation / measuring -------------------------------------------------------- */

static void test_trunc(void) {
  char small[5];
  size_t need = zpct_encode(small, sizeof(small), "a b c", 5,
                            ZPCT_UNRESERVED);
  CHECK(need == 9); /* a%20b%20c */
  CHECK(strlen(small) == 4 && memcmp(small, "a%20", 4) == 0);
  /* Truncation never splits... (may split a triplet; that's allowed:
   * needed length still reported, output NUL-terminated). */
  need = zpct_decode(small, sizeof(small), "a%20b%20c", 9, NULL);
  CHECK(need == 5 && strcmp(small, "a b ") == 0);
  /* Measuring mode. */
  CHECK(zpct_encode(NULL, 0, "a b", 3, ZPCT_UNRESERVED) == 5);
  CHECK(zpct_decode(NULL, 0, "a%20b", 5, NULL) == 3);
}

/* ---- NULL safety ----------------------------------------------------------------------- */

static void test_null(void) {
  char buf[8] = "xxxxxxx";
  CHECK(zpct_encode(buf, sizeof(buf), NULL, 3, ZPCT_UNRESERVED) ==
        SIZE_MAX);
  CHECK(zpct_encode(buf, sizeof(buf), NULL, 0, ZPCT_UNRESERVED) == 0);
  CHECK(zpct_decode(buf, sizeof(buf), NULL, 3, NULL) == SIZE_MAX);
  CHECK(zpct_decode(buf, sizeof(buf), NULL, 0, NULL) == 0);
}

/* ---- fuzz --------------------------------------------------------------------------------- */

static uint64_t rng_state = 0xB5297A4D3E9C2D17ull;
static uint64_t rng_next(void) {
  rng_state ^= rng_state << 13;
  rng_state ^= rng_state >> 7;
  rng_state ^= rng_state << 17;
  return rng_state;
}

static void test_fuzz(void) {
  int trial;
  for (trial = 0; trial < 4000; trial++) {
    unsigned char src[128];
    char enc[400], dec[128], dec2[128];
    size_t n = rng_next() % 128, i, en, dn = 0, dn2 = 0;
    zpct_set set = (zpct_set)(rng_next() % 3);
    for (i = 0; i < n; i++) src[i] = (unsigned char)rng_next();
    /* encode/decode round trip */
    en = zpct_encode(enc, sizeof(enc), src, n, set);
    CHECK(en != SIZE_MAX);
    CHECK(zpct_decode(dec, sizeof(dec), enc, en, &dn) == n && dn == n);
    CHECK(n == 0 || memcmp(dec, src, n) == 0);
    /* mutate: random single-byte corruption must either decode
     * differently or fail — never crash or overrun */
    if (en > 0) {
      size_t pos = rng_next() % en;
      char save = enc[pos];
      enc[pos] = (char)(rng_next() % 256);
      (void)zpct_decode(dec2, sizeof(dec2), enc, en, &dn2);
      CHECK(dn2 <= en);
      enc[pos] = save;
    }
  }
}

int main(void) {
  test_kat();
  test_roundtrip();
  test_err();
  test_trunc();
  test_null();
  test_fuzz();
  if (g_fail) {
    fprintf(stderr, "test_zpct: FAILURES\n");
    return 1;
  }
  printf("test_zpct: all groups passed (kat roundtrip err trunc null fuzz)\n");
  return 0;
}
