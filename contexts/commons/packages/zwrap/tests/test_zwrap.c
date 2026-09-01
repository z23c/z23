/* zwrap tests: golden wraps, codepoint-accurate widths with multibyte
 * UTF-8, long-word policies, newline preservation, NULL/measurement,
 * and a randomised width-invariant oracle.  Real consumer of zutf8.
 * Built with -std=c23 -Wall -Wextra -Werror -pedantic, ASan/UBSan. */

#include "zwrap/zwrap.h"

#include "zutf8/zutf8.h"

#include <stdio.h>
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

static void expect_wrap_at(const char *in, size_t width, int break_long,
                           const char *want) {
  char buf[2048];
  zwrap_opts o = zwrap_default_opts();
  size_t n;
  o.width = width;
  o.break_long = break_long;
  n = zwrap(in, strlen(in), buf, sizeof buf, &o);
  CHECK(strcmp(buf, want) == 0);
  CHECK(n == strlen(want));
  if (strcmp(buf, want) != 0)
    fprintf(stderr, "  in=%s width=%zu\n  want=[%s]\n  got =[%s]\n", in,
            width, want, buf);
}

static void expect_wrap(const char *in, size_t width, const char *want) {
  expect_wrap_at(in, width, 1, want);
}

static void test_kats(void) {
  expect_wrap("the quick brown fox", 10, "the quick\nbrown fox");
  expect_wrap("the quick brown fox", 11, "the quick\nbrown fox");
  expect_wrap("the quick brown fox", 19, "the quick brown fox");
  expect_wrap("hello world", 72, "hello world");
  expect_wrap("aaa bbb ccc ddd", 7, "aaa bbb\nccc ddd");
  expect_wrap("aaa bbb ccc ddd", 3, "aaa\nbbb\nccc\nddd");
  expect_wrap("", 10, "");
  expect_wrap("word", 10, "word");
  /* multiple spaces collapse at wrap points */
  expect_wrap("aaa   bbb", 5, "aaa\nbbb");
  /* leading spaces are dropped */
  expect_wrap("   hello", 10, "hello");
  /* existing newlines preserved */
  expect_wrap("one\ntwo three", 10, "one\ntwo three");
  expect_wrap("a\n\nb", 10, "a\n\nb");
  /* tabs are blanks */
  expect_wrap("aaa\tbbb", 5, "aaa\nbbb");
}

static void test_long_words(void) {
  /* break_long: hard-break at width, codepoint granularity */
  expect_wrap("abcdefgh", 3, "abc\ndef\ngh");
  expect_wrap_at("abcdefgh", 3, 0, "abcdefgh"); /* overflow intact */
  expect_wrap("xx abcdefgh yy", 5, "xx\nabcde\nfgh\nyy");
  expect_wrap_at("xx abcdefgh yy", 5, 0, "xx\nabcdefgh\nyy");
}

static void test_utf8_width(void) {
  /* 3 codepoints of 3 bytes each; width counts codepoints */
  expect_wrap("\xE4\xB8\xAD\xE6\x96\x87\xE5\xAD\x97", 2,
              "\xE4\xB8\xAD\xE6\x96\x87\n\xE5\xAD\x97");
  /* mixed ascii and multibyte */
  expect_wrap("a\xC3\xA9 b\xC3\xA9", 3, "a\xC3\xA9\nb\xC3\xA9");
  /* never splits a sequence even when hard-breaking */
  {
    const char *in = "\xF0\x9F\x98\x80\xF0\x9F\x98\x81\xF0\x9F\x98\x82";
    expect_wrap(in, 1,
                "\xF0\x9F\x98\x80\n\xF0\x9F\x98\x81\n\xF0\x9F\x98\x82");
  }
}

static void test_invalid_utf8(void) {
  /* undecodable bytes pass through, count one column */
  expect_wrap("a\xFF" "b c", 3, "a\xFF" "b\nc");
  expect_wrap("\xC0\xAF", 10, "\xC0\xAF");
}

static void test_measure_and_null(void) {
  const char *in = "the quick brown fox";
  char buf[16];
  size_t n;
  CHECK(zwrap(NULL, 5, buf, sizeof buf, NULL) == 0);
  CHECK(buf[0] == '\0');
  n = zwrap(in, strlen(in), NULL, 0, NULL);
  CHECK(n == strlen("the quick brown fox"));
  {
    zwrap_opts o = zwrap_default_opts();
    o.width = 10;
    n = zwrap(in, strlen(in), NULL, 0, &o);
    CHECK(n == strlen("the quick\nbrown fox"));
    n = zwrap(in, strlen(in), buf, sizeof buf, &o);
    CHECK(n == strlen("the quick\nbrown fox"));
    CHECK(strcmp(buf, "the quick\nbrown") == 0); /* raw byte truncation */
  }
}

/* width invariant: every output line is at most `width` codepoints,
 * unless a single word overflows with break_long == 0; and output is
 * valid UTF-8 whenever input is. */
static void test_fuzz_invariant(void) {
  static const char *const pieces[] = {
      "a", "bb", "ccc", "dddd", "eeeee", "\xC3\xA9", "\xE4\xB8\xAD",
      "\xF0\x9F\x98\x80", " ", "  ", "\t", "\n", "supercalifrag",
  };
  unsigned long long rng = 0x1122334455667788ull;
  int t;
  for (t = 0; t < 3000; t++) {
    char in[256];
    char out[768];
    size_t in_len = 0;
    size_t width;
    int break_long;
    zwrap_opts o;
    size_t k;
    int npieces;
    rng = rng * 6364136223846793005ull + 1442695040888963407ull;
    npieces = (int)((rng >> 20) % 30);
    width = 1 + (size_t)((rng >> 32) % 12);
    break_long = (int)((rng >> 40) & 1);
    for (k = 0; k < (size_t)npieces; k++) {
      const char *p = pieces[(rng >> (k % 20)) % 13];
      size_t pl = strlen(p);
      if (in_len + pl >= sizeof in) break;
      memcpy(in + in_len, p, pl);
      in_len += pl;
    }
    o.width = width;
    o.break_long = break_long;
    zwrap(in, in_len, out, sizeof out, &o);
    /* check every line */
    {
      const char *line = out;
      while (*line) {
        const char *nl = strchr(line, '\n');
        size_t lb = nl ? (size_t)(nl - line) : strlen(line);
        size_t cps = zutf8_count_n(line, lb);
        /* count_n returns SIZE_MAX for invalid; our inputs are always
         * valid UTF-8 here (pieces are), so count must succeed */
        CHECK(cps != (size_t)-1);
        if (break_long) {
          CHECK(cps <= width);
          if (cps > width)
            fprintf(stderr, "  width=%zu line=[%.*s] cps=%zu\n", width,
                    (int)lb, line, cps);
        }
        if (!nl) break;
        line = nl + 1;
      }
    }
    /* no trailing spaces on wrapped lines when break_long */
    if (break_long) {
      const char *p = out;
      while (*p) {
        const char *nl = strchr(p, '\n');
        size_t lb = nl ? (size_t)(nl - p) : strlen(p);
        if (lb > 0) CHECK(p[lb - 1] != ' ');
        if (!nl) break;
        p = nl + 1;
      }
    }
  }
}

int main(void) {
  test_kats();
  test_long_words();
  test_utf8_width();
  test_invalid_utf8();
  test_measure_and_null();
  test_fuzz_invariant();
  if (failures) {
    fprintf(stderr, "%d failure(s)\n", failures);
    return 1;
  }
  puts("zwrap: all tests passed");
  return 0;
}
