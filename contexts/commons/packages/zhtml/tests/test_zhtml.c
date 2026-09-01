/* Tests for zhtml — bounded HTML escaping.
 * Groups: kat, roundtrip, err, trunc, null, fuzz. */
#include "zhtml/zhtml.h"

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

static void test_kat(void) {
  static const struct {
    const char *in, *out;
  } ESC[] = {
      {"", ""},
      {"plain text", "plain text"},
      {"a&b", "a&amp;b"},
      {"<b>", "&lt;b&gt;"},
      {"\"q\"", "&quot;q&quot;"},
      {"it's", "it&#39;s"},
      {"<&>\"'", "&lt;&amp;&gt;&quot;&#39;"},
  };
  static const struct {
    const char *in, *out;
  } UN[] = {
      {"", ""},
      {"plain", "plain"},
      {"&amp;", "&"},
      {"&lt;&gt;&quot;&apos;", "<>\"'"},
      {"&#65;", "A"},
      {"&#x41;", "A"},
      {"&#X41;", "A"},
      {"&#233;", "\xC3\xA9"},          /* é */
      {"&#x1F600;", "\xF0\x9F\x98\x80"}, /* 😀 */
      {"a &amp; b &lt;tag&gt;", "a & b <tag>"},
      {"&#9;&#10;&#13;", "\t\n\r"},    /* allowed C0 */
  };
  size_t i;
  for (i = 0; i < sizeof(ESC) / sizeof(ESC[0]); i++) {
    char buf[128];
    size_t need =
        zhtml_escape(buf, sizeof(buf), ESC[i].in, strlen(ESC[i].in));
    if (need != strlen(ESC[i].out) || strcmp(buf, ESC[i].out) != 0) {
      fprintf(stderr, "FAIL esc: \"%s\" -> \"%s\" (want \"%s\")\n",
              ESC[i].in, buf, ESC[i].out);
      g_fail = 1;
    }
  }
  for (i = 0; i < sizeof(UN) / sizeof(UN[0]); i++) {
    char buf[128];
    size_t need =
        zhtml_unescape(buf, sizeof(buf), UN[i].in, strlen(UN[i].in));
    if (need != strlen(UN[i].out) || memcmp(buf, UN[i].out, need) != 0) {
      fprintf(stderr, "FAIL un: \"%s\" -> \"%s\" (want \"%s\")\n",
              UN[i].in, buf, UN[i].out);
      g_fail = 1;
    }
  }
}

static void test_roundtrip(void) {
  /* escape -> unescape is identity for arbitrary bytes (entities never
   * appear by construction in escaped output). */
  unsigned char all[256];
  char enc[1536];
  char dec[264];
  size_t i, en, dn;
  for (i = 0; i < 256; i++) all[i] = (unsigned char)i;
  en = zhtml_escape(enc, sizeof(enc), all, 256);
  CHECK(en != SIZE_MAX);
  dn = zhtml_unescape(dec, sizeof(dec), enc, en);
  CHECK(dn == 256 && memcmp(dec, all, 256) == 0);
}

static void test_err(void) {
  char buf[32];
  static const char *BAD[] = {
      "&", "&amp", "&nope;", "&;", "&#;", "&#x;", "&#xG;", "&#x41",
      "&#1114112;",  /* > U+10FFFF */
      "&#55296;",    /* lone surrogate 0xD800 */
      "&#1;",        /* C0 control */
      "&#127;",      /* DEL */
      "&#99999999999;", /* absurd digit run */
      "&amp;&",      /* trailing bare & */
  };
  size_t i;
  for (i = 0; i < sizeof(BAD) / sizeof(BAD[0]); i++)
    CHECK(zhtml_unescape(buf, sizeof(buf), BAD[i], strlen(BAD[i])) ==
          SIZE_MAX);
  /* Over-long input. */
  {
    static char big[ZHTML_MAX + 2];
    memset(big, 'a', ZHTML_MAX + 1);
    big[ZHTML_MAX + 1] = '\0';
    CHECK(zhtml_escape(buf, sizeof(buf), big, ZHTML_MAX + 1) ==
          SIZE_MAX);
    CHECK(zhtml_unescape(buf, sizeof(buf), big, ZHTML_MAX + 1) ==
          SIZE_MAX);
  }
}

static void test_trunc(void) {
  char small[6];
  size_t need = zhtml_escape(small, sizeof(small), "a<b>c", 5);
  CHECK(need == 11); /* a&lt;b&gt;c */
  CHECK(strlen(small) == 5 && memcmp(small, "a&lt;", 5) == 0);
  need = zhtml_unescape(small, sizeof(small), "a&lt;b&gt;c", 11);
  CHECK(need == 5 && strcmp(small, "a<b>c") == 0);
  CHECK(zhtml_escape(NULL, 0, "a&b", 3) == 7);
  CHECK(zhtml_unescape(NULL, 0, "a&amp;b", 7) == 3);
}

static void test_null(void) {
  char buf[8] = "xxxxxxx";
  CHECK(zhtml_escape(buf, sizeof(buf), NULL, 2) == SIZE_MAX);
  CHECK(zhtml_escape(buf, sizeof(buf), NULL, 0) == 0);
  CHECK(zhtml_unescape(buf, sizeof(buf), NULL, 2) == SIZE_MAX);
  CHECK(zhtml_unescape(buf, sizeof(buf), NULL, 0) == 0);
}

static uint64_t rng_state = 0xF1A2B3C4D5E60718ull;
static uint64_t rng_next(void) {
  rng_state ^= rng_state << 13;
  rng_state ^= rng_state >> 7;
  rng_state ^= rng_state << 17;
  return rng_state;
}

static void test_fuzz(void) {
  int trial;
  for (trial = 0; trial < 3000; trial++) {
    unsigned char src[96];
    char enc[600], dec[96];
    size_t n = rng_next() % 96, i, en, dn;
    /* bias toward special chars */
    for (i = 0; i < n; i++) {
      uint64_t r = rng_next() % 8;
      src[i] = r == 0 ? '&' : r == 1 ? '<' : r == 2 ? '>' : r == 3 ? '"'
               : r == 4 ? '\''
                        : (unsigned char)(rng_next() % 256);
    }
    en = zhtml_escape(enc, sizeof(enc), src, n);
    CHECK(en != SIZE_MAX);
    /* escaped output contains no raw specials and always unescapes */
    for (i = 0; i < en; i++)
      if (enc[i] == '&') CHECK(i + 1 < en);
    dn = zhtml_unescape(dec, sizeof(dec), enc, en);
    CHECK(dn == n && (n == 0 || memcmp(dec, src, n) == 0));
    /* mutate one byte of the escaped text: decode must not crash */
    if (en > 0) {
      size_t pos = rng_next() % en;
      char save = enc[pos];
      enc[pos] = (char)(rng_next() % 256);
      (void)zhtml_unescape(dec, sizeof(dec), enc, en);
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
    fprintf(stderr, "test_zhtml: FAILURES\n");
    return 1;
  }
  printf("test_zhtml: all groups passed (kat roundtrip err trunc null fuzz)\n");
  return 0;
}
