/* zmime tests: registry KATs, Content-Type parse KATs and rejection
 * table, format round-trips, quoting rules, and a randomised
 * token-invariant oracle.  Built with -std=c23 -Wall -Wextra -Werror
 * -pedantic under ASan/UBSan. */

#include "zmime/zmime.h"

#include <stdio.h>
#include <string.h>

static int failures = 0;

#define CHECK(cond)                                                     \
  do {                                                                  \
    if (!(cond)) {                                                      \
      fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);   \
      failures++;                                                       \
    }                                                                   \
  } while (0)

static void test_registry(void) {
  CHECK(strcmp(zmime_from_extension("html", 4), "text/html") == 0);
  CHECK(strcmp(zmime_from_extension(".html", 5), "text/html") == 0);
  CHECK(strcmp(zmime_from_extension("HTML", 4), "text/html") == 0);
  CHECK(strcmp(zmime_from_extension("json", 4), "engine/application/json") == 0);
  CHECK(strcmp(zmime_from_extension("png", 3), "image/png") == 0);
  CHECK(strcmp(zmime_from_extension("c", 1), "text/x-c") == 0);
  CHECK(strcmp(zmime_from_extension("toml", 4), "engine/application/toml") == 0);
  CHECK(strcmp(zmime_from_extension("wasm", 4), "engine/application/wasm") == 0);
  /* unknown and edge inputs fall back */
  CHECK(strcmp(zmime_from_extension("zzz", 3),
               "engine/application/octet-stream") == 0);
  CHECK(strcmp(zmime_from_extension("", 0), "engine/application/octet-stream") == 0);
  CHECK(strcmp(zmime_from_extension(NULL, 3),
               "engine/application/octet-stream") == 0);
  CHECK(strcmp(zmime_from_extension("superlongext", 12),
               "engine/application/octet-stream") == 0);
  CHECK(strcmp(zmime_from_extension(".", 1), "engine/application/octet-stream") ==
        0);
  /* reverse */
  {
    const char *e = zmime_to_extension("text/html", 9);
    CHECK(e && (strcmp(e, "htm") == 0 || strcmp(e, "html") == 0));
  }
  CHECK(strcmp(zmime_to_extension("Application/JSON", 16), "json") == 0);
  CHECK(zmime_to_extension("engine/application/x-not-registered", 26) == NULL);
  CHECK(zmime_to_extension(NULL, 5) == NULL);
}

static void expect_parse(const char *s, const char *type, const char *subtype,
                         const char *charset, size_t nparams) {
  zmime_content_type ct;
  CHECK(zmime_parse_content_type(s, strlen(s), &ct));
  if (!zmime_parse_content_type(s, strlen(s), &ct)) return;
  CHECK(strcmp(ct.type, type) == 0);
  CHECK(strcmp(ct.subtype, subtype) == 0);
  CHECK(strcmp(ct.charset, charset) == 0);
  CHECK(ct.nparams == nparams);
}

static void expect_bad(const char *s) {
  zmime_content_type ct;
  CHECK(!zmime_parse_content_type(s, strlen(s), &ct));
  if (zmime_parse_content_type(s, strlen(s), &ct))
    fprintf(stderr, "  unexpectedly parsed: %s\n", s);
}

static void test_parse_kats(void) {
  expect_parse("text/html", "text", "html", "", 0);
  expect_parse("TEXT/HTML", "text", "html", "", 0);
  expect_parse("text/html; charset=utf-8", "text", "html", "utf-8", 1);
  expect_parse("text/html;charset=UTF-8", "text", "html", "utf-8", 1);
  expect_parse("text/html; charset=\"utf-8\"", "text", "html", "utf-8", 1);
  expect_parse("engine/application/json; charset=utf-8; x-a=b", "application",
               "json", "utf-8", 2);
  expect_parse("multipart/form-data; boundary=something", "multipart",
               "form-data", "", 1);
  expect_parse("text/plain ; charset=iso-8859-1 ; x=1", "text", "plain",
               "iso-8859-1", 2);
  expect_parse(" engine/application/pdf", "application", "pdf", "", 0);
  expect_parse("image/svg+xml", "image", "svg+xml", "", 0);
  /* quoted values with escapes and spaces */
  {
    zmime_content_type ct;
    const char *s = "a/b; x=\"hello world\"; y=\"q\\\"z\"";
    CHECK(zmime_parse_content_type(s, strlen(s), &ct));
    if (zmime_parse_content_type(s, strlen(s), &ct)) {
      CHECK(ct.nparams == 2);
      CHECK(strcmp(ct.params[0].value, "hello world") == 0);
      CHECK(strcmp(ct.params[1].value, "q\"z") == 0);
    }
  }
}

static void test_parse_bad(void) {
  expect_bad("");
  expect_bad("texthtml");
  expect_bad("/html");
  expect_bad("text/");
  expect_bad("text/html;");
  expect_bad("text/html; charset");
  expect_bad("text/html; charset=");
  expect_bad("text/html; =utf-8");
  expect_bad("text/html; charset=\"utf-8"); /* unterminated */
  expect_bad("text/html; charset=\"bad\x01\""); /* control char */
  expect_bad("text/html extra");
  expect_bad("text /html");
  expect_bad("text/h tml");
  expect_bad("text//html");
  expect_bad("text/html;;charset=utf-8");
  expect_bad("text/html, charset=utf-8");
}

static void test_format_roundtrip(void) {
  static const char *const vals[] = {
      "text/html",
      "text/html; charset=utf-8",
      "engine/application/json; charset=utf-8; x-a=b",
      "multipart/form-data; boundary=something",
      "a/b; x=\"hello world\"",
  };
  size_t i;
  for (i = 0; i < sizeof vals / sizeof vals[0]; i++) {
    zmime_content_type ct, ct2;
    char buf[256], buf2[256];
    CHECK(zmime_parse_content_type(vals[i], strlen(vals[i]), &ct));
    zmime_format_content_type(&ct, buf, sizeof buf);
    CHECK(zmime_parse_content_type(buf, strlen(buf), &ct2));
    CHECK(strcmp(ct.type, ct2.type) == 0);
    CHECK(strcmp(ct.subtype, ct2.subtype) == 0);
    CHECK(ct.nparams == ct2.nparams);
    zmime_format_content_type(&ct2, buf2, sizeof buf2);
    CHECK(strcmp(buf, buf2) == 0); /* formatting is a fixed point */
    if (strcmp(buf, buf2) != 0)
      fprintf(stderr, "  in=%s fmt=%s fmt2=%s\n", vals[i], buf, buf2);
  }
  /* known canonical spellings */
  {
    zmime_content_type ct;
    char buf[256];
    CHECK(zmime_parse_content_type("TEXT/HTML; Charset=UTF-8", 24, &ct));
    zmime_format_content_type(&ct, buf, sizeof buf);
    /* type/subtype/param names normalise to lowercase; param values
     * keep their case (they can be case-sensitive) */
    CHECK(strcmp(buf, "text/html; charset=UTF-8") == 0);
    CHECK(strcmp(ct.charset, "utf-8") == 0);
    CHECK(zmime_parse_content_type("a/b; x=\"hi there\"", 17, &ct));
    zmime_format_content_type(&ct, buf, sizeof buf);
    CHECK(strcmp(buf, "a/b; x=\"hi there\"") == 0);
  }
}

static void test_edges(void) {
  zmime_content_type ct;
  char buf[256];
  /* more than 8 parameters: parse succeeds, first 8 retained */
  {
    const char *s = "a/b; p1=1; p2=2; p3=3; p4=4; p5=5; p6=6; p7=7; p8=8;"
                    " p9=9; p10=10";
    CHECK(zmime_parse_content_type(s, strlen(s), &ct));
    CHECK(ct.nparams == 10);
    CHECK(strcmp(ct.params[7].name, "p8") == 0);
    zmime_format_content_type(&ct, buf, sizeof buf);
    CHECK(strstr(buf, "p8=8") != NULL);
    CHECK(strstr(buf, "p9") == NULL);
  }
  /* NULL and measurement */
  CHECK(!zmime_parse_content_type(NULL, 3, &ct));
  CHECK(!zmime_parse_content_type("a/b", 3, NULL));
  CHECK(zmime_format_content_type(NULL, buf, sizeof buf) == 0);
  CHECK(buf[0] == '\0');
  CHECK(zmime_parse_content_type("text/html", 9, &ct));
  CHECK(zmime_format_content_type(&ct, NULL, 0) == strlen("text/html"));
}

/* randomised token oracle: any charset of token chars round-trips;
 * injecting a non-token separator breaks parsing */
static void test_fuzz(void) {
  static const char tok[] =
      "abcdefghijklmnopqrstuvwxyz0123456789!#$%&'*+-.^_`|~";
  unsigned long long rng = 0x77AABBCCDDEEFF11ull;
  int t;
  for (t = 0; t < 3000; t++) {
    char s[256];
    char b1[64], b2[64], b3[64];
    size_t i, n1, n2, n3;
    zmime_content_type ct;
    rng = rng * 6364136223846793005ull + 1442695040888963407ull;
    n1 = 1 + (rng >> 20) % 20;
    n2 = 1 + (rng >> 30) % 20;
    n3 = 1 + (rng >> 40) % 20;
    for (i = 0; i < n1; i++) b1[i] = tok[(rng >> (i % 20)) % (sizeof tok - 1)];
    for (i = 0; i < n2; i++)
      b2[i] = tok[(rng >> ((i + 7) % 20)) % (sizeof tok - 1)];
    for (i = 0; i < n3; i++)
      b3[i] = tok[(rng >> ((i + 13) % 20)) % (sizeof tok - 1)];
    b1[n1] = b2[n2] = b3[n3] = '\0';
    snprintf(s, sizeof s, "%s/%s; charset=%s", b1, b2, b3);
    CHECK(zmime_parse_content_type(s, strlen(s), &ct));
    {
      /* lowercase comparison */
      char want[64];
      size_t j;
      for (j = 0; j <= n1; j++) {
        char c2 = b1[j];
        if (c2 >= 'A' && c2 <= 'Z') c2 = (char)(c2 + 32);
        want[j] = c2;
      }
      CHECK(strcmp(ct.type, want) == 0);
    }
    /* poison with a space in the type: must fail */
    snprintf(s, sizeof s, "%s %s/%s", b1, b1, b2);
    if (strlen(s) < sizeof s - 1)
      CHECK(!zmime_parse_content_type(s, strlen(s), &ct));
  }
}

int main(void) {
  test_registry();
  test_parse_kats();
  test_parse_bad();
  test_format_roundtrip();
  test_edges();
  test_fuzz();
  if (failures) {
    fprintf(stderr, "%d failure(s)\n", failures);
    return 1;
  }
  puts("zmime: all tests passed");
  return 0;
}
