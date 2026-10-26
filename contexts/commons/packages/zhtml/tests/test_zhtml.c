/* Tests for zhtml — bounded HTML escaping.
 * Groups: kat, roundtrip, err, trunc, null, fuzz. */
#include "zhtml/zhtml.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

static FILE *cli_source, *cli_sink;
#undef stdin
#undef stdout
#define stdin cli_source
#define stdout cli_sink
#define putchar(c) fputc((c), cli_sink)
#define main zhtml_cli_main
#include "../app/main.c"
#undef main
#undef putchar
#undef stdout
#undef stdin

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

static void test_numeric_leading_zero_range(void) {
  static const char *rows[] = {"&#000000065;", "&#x000000041;"};
  char out[8];
  for (size_t i = 0; i < sizeof rows / sizeof rows[0]; i++) {
    size_t n = zhtml_unescape(out, sizeof out, rows[i], strlen(rows[i]));
    CHECK(n == 1 && out[0] == 'A' && out[1] == 0);
  }
  static char largest[ZHTML_MAX];
  largest[0] = '&'; largest[1] = '#';
  memset(largest + 2, '0', sizeof largest - 5);
  largest[sizeof largest - 3] = '6';
  largest[sizeof largest - 2] = '5';
  largest[sizeof largest - 1] = ';';
  CHECK(zhtml_unescape(out, sizeof out, largest, sizeof largest) == 1 &&
        out[0] == 'A' && out[1] == 0);
}

static int cli_case(const void *data, size_t len, char **args, int argc,
                    int status, const void *want, size_t want_len) {
  FILE *source = tmpfile(), *output = tmpfile();
  int bad = 1;
  if (!source || !output) goto cleanup;
  if (fwrite(data, 1, len, source) != len || fflush(source) != 0) goto cleanup;
  rewind(source);
  cli_source = source; cli_sink = output;
  if (zhtml_cli_main(argc, args) != status) goto cleanup;
  if (want) {
    rewind(output);
    unsigned char got[2 * ZHTML_MAX + 128];
    size_t n = fread(got, 1, sizeof got, output);
    if (ferror(output) || n != want_len || memcmp(got, want, n) != 0) goto cleanup;
  }
  bad = 0;
cleanup:
  if (source && fclose(source) != 0) bad = 1;
  if (output && fclose(output) != 0) bad = 1;
  return bad;
}

static int cli_unescape(const void *data, size_t len, int status,
                        const void *want, size_t want_len) {
  char *args[] = {"zhtml", "unescape", NULL};
  return cli_case(data, len, args, 2, status, want, want_len);
}

static void test_cli_splits(void) {
  const char *entities[] = {"&amp;", "&lt;", "&gt;", "&quot;", "&apos;",
                            "&#65;", "&#128512;", "&#x1F600;"};
  unsigned char text[3 * 8192 + 64], want[sizeof text];
  for (size_t e = 0; e < sizeof entities / sizeof entities[0]; e++) {
    size_t n = strlen(entities[e]);
    for (size_t split = 1; split < n; split++) {
      size_t start = 8192 - split;
      memset(text, 'a', sizeof text);
      text[10] = 0; /* Raw bytes before the split entity must survive. */
      memcpy(text + start, entities[e], n);
      memcpy(text + start + n, "&lt;Z", 5);
      size_t len = sizeof text;
      size_t decoded = zhtml_unescape((char *)want, sizeof want, text, len);
      CHECK(decoded != SIZE_MAX && decoded < sizeof want);
      if (decoded != SIZE_MAX && decoded < sizeof want)
        CHECK(cli_unescape(text, len, 0, want, decoded) == 0);
    }
  }
}

static void test_cli_entity_bounds(void) {
  static unsigned char text[2 * ZHTML_MAX + 16];
  text[0] = 'P'; text[1] = '&'; text[2] = '#';
  memset(text + 3, '0', ZHTML_MAX - 5);
  text[ZHTML_MAX - 2] = '6'; text[ZHTML_MAX - 1] = '5';
  text[ZHTML_MAX] = ';'; text[ZHTML_MAX + 1] = 'Q';
  CHECK(cli_unescape(text, ZHTML_MAX + 2, 0, "PAQ", 3) == 0);
  memmove(text + ZHTML_MAX + 1, text + ZHTML_MAX, 2);
  text[ZHTML_MAX] = '0'; /* One byte beyond the entity bound. */
  CHECK(cli_unescape(text, ZHTML_MAX + 3, 1, NULL, 0) == 0);
  memset(text, 'x', sizeof text);
  CHECK(cli_unescape(text, sizeof text, 0, text, sizeof text) == 0);
  const char *bad[] = {"&", "&#", "&#x", "&amp", "&#65", "&#x41",
                        "&unknown;", "&bad&amp;", "&bad;&amp"};
  for (size_t i = 0; i < sizeof bad / sizeof bad[0]; i++)
    CHECK(cli_unescape(bad[i], strlen(bad[i]), 1, NULL, 0) == 0);
}

static void test_cli_controls(void) {
  char *escape[] = {"zhtml", "escape", NULL};
  CHECK(cli_case("<&", 2, escape, 2, 0, "&lt;&amp;", 9) == 0);
  char *argv[] = {"zhtml", "unescape", "&amp;", "&#65;", NULL};
  CHECK(cli_case("", 0, argv, 4, 0, "&\nA\n", 4) == 0);
  char *escaped[] = {"zhtml", "escape", "<&", NULL};
  CHECK(cli_case("", 0, escaped, 3, 0, "&lt;&amp;\n", 10) == 0);
}

static void test_cli_read_error(void) {
#if defined(_WIN32)
  FILE *source = fopen("NUL", "w");
#else
  FILE *source = fopen("/dev/null", "w");
#endif
  FILE *output = tmpfile();
  if (source && output) {
    cli_source = source; cli_sink = output;
    char *args[] = {"zhtml", "unescape", NULL};
    CHECK(zhtml_cli_main(2, args) == 1);
    CHECK(ferror(source) && ftell(output) == 0);
  } else CHECK(false);
  if (source) CHECK(fclose(source) == 0);
  if (output) CHECK(fclose(output) == 0);
}

int main(void) {
  test_cli_splits();
  test_cli_entity_bounds();
  test_cli_controls();
  test_cli_read_error();
  test_numeric_leading_zero_range();
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
