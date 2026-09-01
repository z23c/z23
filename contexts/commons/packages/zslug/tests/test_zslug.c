/* zslug tests: golden KATs, fold-table exhaustiveness, truncation,
 * canonical-form checker, and a randomised idempotence oracle.
 * Built with -std=c23 -Wall -Wextra -Werror -pedantic and ASan/UBSan. */

#include "zslug/zslug.h"

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

static int failures = 0;

#define CHECK(cond)                                                     \
  do {                                                                  \
    if (!(cond)) {                                                      \
      fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);   \
      failures++;                                                       \
    }                                                                   \
  } while (0)

static void expect_slug(const char *in, const char *want) {
  char buf[512];
  size_t n = zslug(in, strlen(in), buf, sizeof buf, NULL);
  CHECK(strcmp(buf, want) == 0);
  CHECK(n == strlen(want));
  if (strcmp(buf, want) != 0)
    fprintf(stderr, "  input=%s want=%s got=%s\n", in, want, buf);
}

static void test_basic_kats(void) {
  expect_slug("Hello, World!", "hello-world");
  expect_slug("  leading and trailing  ", "leading-and-trailing");
  expect_slug("already-a-slug", "already-a-slug");
  expect_slug("a", "a");
  expect_slug("", "");
  expect_slug("!!!", "");
  expect_slug("C23 is fun", "c23-is-fun");
  expect_slug("one  two\tthree\nfour", "one-two-three-four");
  expect_slug("42", "42");
  expect_slug("3.14 & 2.72", "3-14-2-72");
  expect_slug("under_score_kept? no", "under-score-kept-no");
}

static void test_latin1_folds(void) {
  /* UTF-8 encodings of common Latin-1 letters. */
  expect_slug("H\xC3\xA9llo W\xC3\xB6rld", "hello-world");      /* é ö */
  expect_slug("Cr\xC3\xA8" "me Br\xC3\xBBl\xC3\xA9" "e", "creme-brulee");
  expect_slug("\xC3\x9F" "tra\xC3\x9F" "e", "sstrasse");          /* ß */
  expect_slug("Sm\xC3\xB8" "rrebr\xC3\xB8" "d", "smorrebrod");    /* ø */
  expect_slug("\xC3\x86" "sop", "aesop");                        /* Æ */
  expect_slug("ni\xC3\xB1o", "nino");
  expect_slug("\xC3\xBEorn", "thorn");                           /* þ */
  expect_slug("\xC3\xB0" "ale", "dale");                         /* ð */
  /* U+00D7 multiplication sign and U+00F7 division sign: no fold. */
  expect_slug("2\xC3\x97" "2", "2-2");
  expect_slug("4\xC3\xB7" "2", "4-2");
}

static void test_beyond_latin1(void) {
  /* Greek and CJK are out of scope: they become separators. */
  expect_slug("\xCE\xB1\xCE\xB2\xCE\xB3", "");                   /* αβγ */
  expect_slug("a\xE4\xB8\xAD" "b", "a-b");                       /* 中 */
  /* Malformed UTF-8: stray continuation bytes, overlong encodings. */
  expect_slug("a\x80\xBF" "b", "a-b");
  expect_slug("a\xC0\xAF" "b", "a-b");
  expect_slug("a\xED\xA0\x80" "b", "a-b");                       /* surrogate */
  expect_slug("a\xF4\x90\x80\x80" "b", "a-b");                   /* > U+10FFFF */
}

static void test_full_latin1_table(void) {
  /* Every codepoint U+00C0..U+00FF between word chars; the slug must
   * be "a", "axa", or "ax<letter(s)>a" shaped and canonical. */
  static const char *const expect[0x40] = {
      "axaa", "axaa", "axaa", "axaa", "axaa", "axaa", "axaea", "axca",
      "axea", "axea", "axea", "axea", "axia", "axia", "axia", "axia",
      "axda", "axna", "axoa", "axoa", "axoa", "axoa", "axoa", "ax-a",
      "axoa", "axua", "axua", "axua", "axua", "axya", "axtha", "axssa",
      "axaa", "axaa", "axaa", "axaa", "axaa", "axaa", "axaea", "axca",
      "axea", "axea", "axea", "axea", "axia", "axia", "axia", "axia",
      "axda", "axna", "axoa", "axoa", "axoa", "axoa", "axoa", "ax-a",
      "axoa", "axua", "axua", "axua", "axua", "axya", "axtha", "axya",
  };
  unsigned cp;
  for (cp = 0xC0; cp <= 0xFF; cp++) {
    char in[8];
    char buf[64];
    size_t n;
    snprintf(in, sizeof in, "aX"); /* placeholder, rebuilt below */
    /* build the 2-byte UTF-8 encoding explicitly */
    in[0] = 'a';
    in[1] = 'X';
    in[2] = (char)(0xC0 | (cp >> 6));
    in[3] = (char)(0x80 | (cp & 0x3F));
    in[4] = 'A';
    in[5] = '\0';
    n = zslug(in, 5, buf, sizeof buf, NULL);
    CHECK(strcmp(buf, expect[cp - 0xC0]) == 0);
    CHECK(n == strlen(expect[cp - 0xC0]));
    if (strcmp(buf, expect[cp - 0xC0]) != 0)
      fprintf(stderr, "  cp=U+%04lX got=%s want=%s\n", (unsigned long)cp, buf,
              expect[cp - 0xC0]);
  }
}

static void test_truncation(void) {
  char buf[256];
  zslug_opts o = zslug_default_opts();
  size_t n;

  /* max_len at a word boundary */
  o.max_len = 11;
  n = zslug("hello world again", 17, buf, sizeof buf, &o);
  CHECK(n == 17 - 0 || n == strlen("hello-world-again"));
  CHECK(strcmp(buf, "hello-world") == 0);

  /* max_len mid-word: cut back to previous separator */
  o.max_len = 8;
  n = zslug("hello world again", 17, buf, sizeof buf, &o);
  CHECK(n == strlen("hello-world-again"));
  CHECK(strcmp(buf, "hello") == 0);

  /* max_len inside the first word: raw cut, no separator to find */
  o.max_len = 3;
  n = zslug("hello world", 11, buf, sizeof buf, &o);
  CHECK(n == 11);
  CHECK(strcmp(buf, "hel") == 0);

  /* small output buffer still NUL-terminates and reports full length */
  {
    char tiny[6];
    memset(tiny, 0x7F, sizeof tiny);
    n = zslug("hello world", 11, tiny, sizeof tiny, NULL);
    CHECK(n == 11);
    CHECK(strcmp(tiny, "hello") == 0);
  }

  /* measurement with NULL output */
  n = zslug("hello world", 11, NULL, 0, NULL);
  CHECK(n == 11);
}

static void test_canonical(void) {
  CHECK(zslug_is_canonical("hello-world", 11, NULL));
  CHECK(zslug_is_canonical("a", 1, NULL));
  CHECK(!zslug_is_canonical("", 0, NULL));
  CHECK(!zslug_is_canonical("-hello", 6, NULL));
  CHECK(!zslug_is_canonical("hello-", 6, NULL));
  CHECK(!zslug_is_canonical("hello--world", 12, NULL));
  CHECK(!zslug_is_canonical("Hello", 5, NULL));
  CHECK(!zslug_is_canonical("hello world", 11, NULL));
  CHECK(!zslug_is_canonical("hello_world", 11, NULL));
  CHECK(!zslug_is_canonical(NULL, 3, NULL));
  {
    zslug_opts o = zslug_default_opts();
    o.max_len = 5;
    CHECK(zslug_is_canonical("hello", 5, &o));
    CHECK(!zslug_is_canonical("hello!", 6, &o));
    CHECK(!zslug_is_canonical("hello-world", 11, &o));
    o.max_len = 0;
    o.sep = '_';
    CHECK(zslug_is_canonical("hello_world", 11, &o));
    CHECK(!zslug_is_canonical("hello-world", 11, &o));
  }
}

static void test_options(void) {
  char buf[64];
  zslug_opts o = zslug_default_opts();

  o.sep = '_';
  zslug("Hello, World", 12, buf, sizeof buf, &o);
  CHECK(strcmp(buf, "hello_world") == 0);

  o.sep = 0; /* zero separator falls back to '-' */
  zslug("a b", 3, buf, sizeof buf, &o);
  CHECK(strcmp(buf, "a-b") == 0);

  o = zslug_default_opts();
  o.fold_case = 0;
  zslug("Hello World", 11, buf, sizeof buf, &o);
  CHECK(strcmp(buf, "Hello-World") == 0);

  /* NULL input */
  CHECK(zslug(NULL, 5, buf, sizeof buf, NULL) == 0);
  CHECK(buf[0] == '\0');
}

/* xorshift64* for a deterministic fuzz oracle. */
static uint64_t rng_state = 0x9E3779B97F4A7C15ull;
static uint64_t rnd(void) {
  uint64_t x = rng_state;
  x ^= x >> 12;
  x ^= x << 25;
  x ^= x >> 27;
  rng_state = x;
  return x * 0x2545F4914F6CDD1Dull;
}

static void test_fuzz_idempotent(void) {
  /* slug(slug(x)) == slug(x): the slug function is a projection onto
   * canonical slugs.  Also: output of a slug is always canonical, and
   * the reported length always matches the materialised string. */
  static const char alphabet[] =
      "abzAZ09 -_!.,\xC3\xA9\xC3\x9F\xE4\xB8\xAD\x80\xC0";
  static const char seps[] = "-_!.,~+";
  char in[96];
  char s1[192], s2[192];
  int t;
  for (t = 0; t < 4000; t++) {
    size_t len = (size_t)(rnd() % 64);
    size_t i;
    size_t n1, n2;
    zslug_opts o = zslug_default_opts();
    if (rnd() % 3 == 0) o.sep = seps[rnd() % (sizeof seps - 1)];
    for (i = 0; i < len; i++)
      in[i] = alphabet[rnd() % (sizeof alphabet - 1)];
    n1 = zslug(in, len, s1, sizeof s1, &o);
    CHECK(n1 == strlen(s1));
    if (n1 > 0) CHECK(zslug_is_canonical(s1, strlen(s1), &o));
    n2 = zslug(s1, strlen(s1), s2, sizeof s2, &o);
    CHECK(n2 == n1);
    CHECK(strcmp(s1, s2) == 0);
  }
}

static void test_fuzz_bounded(void) {
  /* With max_len set, output never exceeds it and stays canonical. */
  char in[128];
  char s1[256];
  int t;
  for (t = 0; t < 4000; t++) {
    size_t len = (size_t)(rnd() % 100);
    size_t i;
    zslug_opts o = zslug_default_opts();
    size_t n;
    o.max_len = 1 + (size_t)(rnd() % 40);
    for (i = 0; i < len; i++) in[i] = (char)(' ' + (rnd() % 95));
    n = zslug(in, len, s1, sizeof s1, &o);
    (void)n;
    CHECK(strlen(s1) <= o.max_len);
    if (s1[0]) CHECK(zslug_is_canonical(s1, strlen(s1), &o));
  }
}

int main(void) {
  test_basic_kats();
  test_latin1_folds();
  test_beyond_latin1();
  test_full_latin1_table();
  test_truncation();
  test_canonical();
  test_options();
  test_fuzz_idempotent();
  test_fuzz_bounded();
  if (failures) {
    fprintf(stderr, "%d failure(s)\n", failures);
    return 1;
  }
  puts("zslug: all tests passed");
  return 0;
}
