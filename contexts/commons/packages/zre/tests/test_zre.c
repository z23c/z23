/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: zre test suite.  Exits nonzero on the first failure.
 *
 * The adversarial block is the point of the library: patterns that send
 * backtracking engines exponential must complete here in bounded time.
 * Each is matched many times over long non-matching input inside a plain
 * counted loop — deterministic, no clocks, no sleeps. */
#include "zre/zre.h"

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

/* Compile or fail the test. */
static zre_prog *compile(const char *pat) {
  zre_prog *prog = NULL;
  char err[128];
  zre_status st = zre_compile(pat, strlen(pat), &prog, err, sizeof(err));
  if (st != ZRE_OK)
    fprintf(stderr, "FAIL compile \"%s\": %s\n", pat, err);
  else if (!prog)
    fprintf(stderr, "FAIL compile \"%s\": NULL prog\n", pat);
  return prog;
}

/* Full search match test. */
static void M(const char *pat, const char *text) {
  zre_prog *p = compile(pat);
  CHECK(p != NULL);
  if (p) {
    CHECK(zre_match(p, text, strlen(text), NULL, 0));
    zre_free(p);
  }
}

static void NM(const char *pat, const char *text) {
  zre_prog *p = compile(pat);
  CHECK(p != NULL);
  if (p) {
    CHECK(!zre_match(p, text, strlen(text), NULL, 0));
    zre_free(p);
  }
}

/* Match and check the whole-match span. */
static void SPAN(const char *pat, const char *text, size_t s, size_t e) {
  zre_prog *p = compile(pat);
  CHECK(p != NULL);
  if (p) {
    zre_span caps[ZRE_MAX_CAPS];
    bool m = zre_match(p, text, strlen(text), caps, ZRE_MAX_CAPS);
    CHECK(m);
    if (m && (caps[0].start != s || caps[0].end != e))
      fprintf(stderr, "FAIL span \"%s\" on \"%s\": got [%zu,%zu) want "
              "[%zu,%zu)\n", pat, text, caps[0].start, caps[0].end, s, e);
    CHECK(caps[0].start == s && caps[0].end == e);
    zre_free(p);
  }
}

/* Pattern must fail to compile with exactly this named error. */
static void CERR(const char *pat, zre_status want) {
  zre_prog *prog = NULL;
  char err[128];
  zre_status st = zre_compile(pat, strlen(pat), &prog, err, sizeof(err));
  if (st != want)
    fprintf(stderr, "FAIL compile \"%s\": got %s, want %s\n", pat,
            zre_strerror(st), zre_strerror(want));
  else
    CHECK(prog == NULL && err[0] != '\0');
  zre_free(prog);
}

static void test_literals(void) {
  M("", "");
  M("", "abc"); /* empty pattern matches empty at 0 */
  M("abc", "abc");
  M("abc", "xxabcxx"); /* unanchored search */
  NM("abc", "abd");
  NM("abc", "ab");
  M("\\$5", "a $5 b");
}

static void test_dot(void) {
  M("a.c", "abc");
  M("a.c", "axc");
  NM("a.c", "a\nc"); /* '.' excludes newline */
  NM("a.c", "ac");
  M("a.*c", "a123c");
  SPAN(".*", "abc", 0, 3);
  /* Byte-oriented: 0x80 is one byte and matches '.' once. */
  M("a.c", "a\x80" "c");
}

static void test_star_plus_quest(void) {
  M("ab*c", "ac");
  M("ab*c", "abbbbc");
  NM("ab*c", "abbbbd");
  M("ab+c", "abc");
  NM("ab+c", "ac");
  M("ab?c", "ac");
  M("ab?c", "abc");
  NM("^ab?c$", "abbc");
  SPAN("a*", "aaa", 0, 3);  /* greedy */
  SPAN("a*", "bbb", 0, 0);  /* empty match at leftmost position */
  SPAN("ba*", "aabaa", 2, 5); /* leftmost */
  SPAN("colou?r", "the colour!", 4, 10);
}

static void test_counted(void) {
  M("^a{3}$", "aaa");
  NM("^a{3}$", "aa");
  NM("^a{3}$", "aaaa");
  M("^a{2,}$", "aaaaa");
  NM("^a{2,}$", "a");
  M("^a{2,4}$", "aa");
  M("^a{2,4}$", "aaaa");
  NM("^a{2,4}$", "a");
  NM("^a{2,4}$", "aaaaa");
  M("^(ab){2}$", "abab");
  NM("^(ab){2}$", "ab");
  M("^a{0}$", "");
  M("^a{0,2}$", "a");
  M("^a{0,}$", "aaa");
  SPAN("a{2,4}", "aaaaa", 0, 4); /* greedy upper bound */
  M("a{b}", "a{b}"); /* '{' not before a digit is literal */
  M("^\\d{3}-\\d{4}$", "555-1234");
  NM("^\\d{3}-\\d{4}$", "55-1234");
}

static void test_classes(void) {
  M("[abc]", "a");
  NM("^[abc]$", "d");
  M("^[a-z]$", "m");
  NM("^[a-z]$", "M");
  M("^[a-zA-Z0-9_]+$", "Some_Id9");
  M("^[^0-9]+$", "abc");
  NM("^[^0-9]+$", "ab3");
  M("^[]a]$", "]"); /* ']' first is a literal */
  M("^[a\\-z]$", "-"); /* escaped '-' is literal */
  NM("^[a\\-z]$", "m");
  M("^[a-]$", "-"); /* '-' last is literal */
  M("^[^a-z]$", "0");
  M("^[\\d]+$", "123"); /* shorthand inside class */
  NM("^[\\d]+$", "12a");
  M("^[\\D]+$", "abc"); /* negated shorthand inside class */
  NM("^[\\D]+$", "ab1");
  M("^[\\x41-C]$", "B"); /* escaped range endpoints */
  M("^[\\]\\[]$", "]");
  CERR("[abc", ZRE_ERR_CLASS);
  CERR("[^", ZRE_ERR_CLASS);
  CERR("[z-a]", ZRE_ERR_CLASS);
  CERR("[a-\\d]", ZRE_ERR_CLASS);
}

static void test_escapes(void) {
  M("^\\d+$", "12345");
  NM("^\\d+$", "123a");
  M("^\\D+$", "abc!");
  M("^\\w+$", "word_9");
  NM("^\\w+$", "no way");
  M("^\\W$", " ");
  M("^a\\sb$", "a\tb");
  M("^\\S+$", "nospace");
  NM("^\\S+$", "has space");
  M("^\\x41\\x42$", "AB");
  M("a\\*b", "a*b");
  M("a\\+b\\?", "a+b?");
  M("\\\\", "a\\b");
  M("\\[x\\]", "[x]");
  M("\\(\\)", "()");
  M("a\\|b", "a|b");
  CERR("a\\", ZRE_ERR_ESCAPE);
  CERR("\\q", ZRE_ERR_ESCAPE);
  CERR("\\x4", ZRE_ERR_ESCAPE);
  CERR("\\xzz", ZRE_ERR_ESCAPE);
  CERR("\\1", ZRE_ERR_UNSUPPORTED); /* backreference */
}

static void test_anchors(void) {
  M("^abc", "abcdef");
  NM("^abc", "xabc");
  M("abc$", "xabc");
  NM("abc$", "abcx");
  M("^abc$", "abc");
  NM("^abc$", "abc\n");
  M("^$", "");
  NM("^$", "x");
  M("^a*$", "aaa");
  M("^a*$", "");
  CERR("^*", ZRE_ERR_REPEAT); /* repeat of an anchor */
  /* Mid-pattern anchors compile but pin an absolute position: '^' after
   * consuming 'a', or '$' before a trailing 'b', can never hold. */
  NM("a^b", "ab");
  NM("a^b", "a^b");
  NM("a$b", "ab");
  NM("a$b", "xa$b");
}

static void test_groups_captures(void) {
  zre_prog *p = compile("^(a+)(b+)$");
  CHECK(p != NULL);
  CHECK(zre_groups(p) == 2);
  if (p) {
    zre_span caps[ZRE_MAX_CAPS];
    CHECK(zre_match(p, "aaabb", 5, caps, ZRE_MAX_CAPS));
    CHECK(caps[0].start == 0 && caps[0].end == 5);
    CHECK(caps[1].start == 0 && caps[1].end == 3);
    CHECK(caps[2].start == 3 && caps[2].end == 5);
    zre_free(p);
  }
  /* Non-participating group reports ZRE_NOMATCH. */
  p = compile("(a)|(b)");
  CHECK(p != NULL);
  CHECK(zre_groups(p) == 2);
  if (p) {
    zre_span caps[ZRE_MAX_CAPS];
    CHECK(zre_match(p, "xb", 2, caps, ZRE_MAX_CAPS));
    CHECK(caps[0].start == 1 && caps[0].end == 2);
    CHECK(caps[1].start == ZRE_NOMATCH && caps[1].end == ZRE_NOMATCH);
    CHECK(caps[2].start == 1 && caps[2].end == 2);
    zre_free(p);
  }
  /* Nested and empty groups. */
  p = compile("^((a)(b))$");
  CHECK(p != NULL);
  CHECK(zre_groups(p) == 3);
  if (p) {
    zre_span caps[ZRE_MAX_CAPS];
    CHECK(zre_match(p, "ab", 2, caps, ZRE_MAX_CAPS));
    CHECK(caps[1].start == 0 && caps[1].end == 2);
    CHECK(caps[2].start == 0 && caps[2].end == 1);
    CHECK(caps[3].start == 1 && caps[3].end == 2);
    zre_free(p);
  }
  p = compile("^()x$");
  CHECK(p != NULL);
  if (p) {
    zre_span caps[ZRE_MAX_CAPS];
    CHECK(zre_match(p, "x", 1, caps, ZRE_MAX_CAPS));
    CHECK(caps[1].start == 0 && caps[1].end == 0);
    zre_free(p);
  }
  /* Non-capturing groups don't consume slots. */
  p = compile("(?:ab)+(c)");
  CHECK(p != NULL);
  CHECK(zre_groups(p) == 1);
  if (p) {
    zre_span caps[ZRE_MAX_CAPS];
    CHECK(zre_match(p, "ababc", 5, caps, ZRE_MAX_CAPS));
    CHECK(caps[0].start == 0 && caps[0].end == 5);
    CHECK(caps[1].start == 4 && caps[1].end == 5);
    zre_free(p);
  }
  /* Fewer caps than groups: array is truncated, extra max_caps cleared. */
  p = compile("(a)(b)");
  CHECK(p != NULL);
  if (p) {
    zre_span caps[2] = {{7, 7}, {7, 7}};
    CHECK(zre_match(p, "ab", 2, caps, 2));
    CHECK(caps[0].start == 0 && caps[0].end == 2);
    CHECK(caps[1].start == 0 && caps[1].end == 1);
    zre_free(p);
  }
}

static void test_alternation(void) {
  M("a|b", "a");
  M("a|b", "b");
  NM("^a|b$", "c");
  M("ab|cd", "cd"); /* lowest precedence: (ab)|(cd) */
  M("^ab|cd$", "ab");
  M("^ab|cd$", "cd");
  NM("^ab|cd$", "ac");
  M("a|", "a");
  M("a|", "x"); /* empty alternative matches empty at 0 */
  M("|a", "a");
  M("^(a|b)*c$", "ababac");
  M("^foo|bar$", "bar");
  SPAN("a|ab", "ab", 0, 1);    /* leftmost-first: left alternative wins */
  SPAN("ab|a", "ab", 0, 2);    /* left alternative still wins */
  SPAN("b|ab", "xab", 1, 3);   /* leftmost position beats branch order */
  SPAN("(a|ab)(c|bcd)", "abcd", 0, 4); /* Perl order: a+bcd beats ab+c */
}

static void test_invalid_patterns(void) {
  CERR("(", ZRE_ERR_UNBALANCED);
  CERR(")", ZRE_ERR_UNBALANCED);
  CERR("(a", ZRE_ERR_UNBALANCED);
  CERR("a)", ZRE_ERR_UNBALANCED);
  CERR("(a|b", ZRE_ERR_UNBALANCED);
  CERR("*a", ZRE_ERR_REPEAT);
  CERR("+", ZRE_ERR_REPEAT);
  CERR("a**", ZRE_ERR_REPEAT);
  CERR("a*?", ZRE_ERR_REPEAT); /* lazy quantifiers do not exist */
  CERR("a{2}{3}", ZRE_ERR_REPEAT);
  CERR("a{2,1}", ZRE_ERR_REPEAT);
  CERR("a{256}", ZRE_ERR_REPEAT);
  CERR("a{1,999}", ZRE_ERR_REPEAT);
  CERR("a{2", ZRE_ERR_REPEAT);
  M("a{,3}", "a{,3}"); /* '{' not before a digit is a literal brace */
  CERR("(?=a)b", ZRE_ERR_UNSUPPORTED); /* lookahead */
  CERR("(?!a)b", ZRE_ERR_UNSUPPORTED);
  CERR("(?<x>a)", ZRE_ERR_UNSUPPORTED);
  /* Nesting bound: ZRE_MAX_NEST + 1 nested non-capturing groups (they do
   * not consume capture slots). */
  {
    char pat[4 * (ZRE_MAX_NEST + 2) + 1];
    size_t n = 0;
    for (size_t i = 0; i < ZRE_MAX_NEST + 1; i++) {
      pat[n++] = '(';
      pat[n++] = '?';
      pat[n++] = ':';
      pat[n++] = 'a';
    }
    pat[n] = '\0';
    CERR(pat, ZRE_ERR_NEST);
  }
  /* Group count bound: ZRE_MAX_GROUPS + 1 groups. */
  CERR("(a)(a)(a)(a)(a)(a)(a)(a)(a)", ZRE_ERR_GROUPS);
  /* Pattern length bound. */
  {
    static char big[ZRE_MAX_PATTERN + 1];
    memset(big, 'a', sizeof(big));
    zre_prog *prog = NULL;
    char err[128];
    CHECK(zre_compile(big, sizeof(big), &prog, err, sizeof(err)) ==
          ZRE_ERR_TOO_LONG);
    CHECK(prog == NULL);
  }
  /* Program size bound: (?:a{255}){255} expands to 65025 instructions. */
  CERR("(?:a{255}){255}", ZRE_ERR_PROGRAM);
  /* NULL arguments. */
  {
    zre_prog *prog = NULL;
    CHECK(zre_compile(NULL, 1, &prog, NULL, 0) == ZRE_ERR_ARG);
    CHECK(zre_compile("a", 1, NULL, NULL, 0) == ZRE_ERR_ARG);
  }
}

static void test_semantics(void) {
  /* Greedy: longest path under thread priority. */
  SPAN("a+", "aaaa", 0, 4);
  SPAN("(a+)(a*)", "aaaa", 0, 4);
  zre_prog *p = compile("(a+)(a*)");
  CHECK(p != NULL);
  if (p) {
    zre_span caps[ZRE_MAX_CAPS];
    CHECK(zre_match(p, "aaaa", 4, caps, ZRE_MAX_CAPS));
    CHECK(caps[1].start == 0 && caps[1].end == 4); /* first group eats all */
    CHECK(caps[2].start == 4 && caps[2].end == 4);
    zre_free(p);
  }
  /* Empty-match handling: empty star bodies terminate and match. */
  M("^(a*)*$", "aaa");
  M("^(a*)*$", "");
  M("^()*$", "");
  M("^(a|)*$", "aa");
  M("(?:)*x", "x");
  NM("^(a+)+$", ""); /* plus still needs one 'a' */
}

static void test_adversarial(void) {
  /* Each of these is exponential for a backtracking engine. Here they are
   * O(prog x len); iterated over long input they stay trivially fast. */
  static const char *pats[] = {
      "(a*)*b",   "^(a*)*$",   "(a|a)*b",  "^(a|aa)+$",
      "([a-zA-Z]+)*b", "(a|b|ab)*c", "(.*)*x", "(a?)*b",
  };
  char text[513];
  memset(text, 'a', 512);
  text[512] = '\0';
  for (size_t i = 0; i < sizeof(pats) / sizeof(pats[0]); i++) {
    zre_prog *p = compile(pats[i]);
    CHECK(p != NULL);
    if (!p)
      continue;
    /* '$'-terminated patterns match all-a input; poison the tail so the
     * only way to win is exhaustively splitting the star runs — the case
     * that destroys backtrackers. */
    bool anchored = pats[i][strlen(pats[i]) - 1] == '$';
    if (anchored)
      text[511] = '!';
    for (int iter = 0; iter < 10; iter++)
      CHECK(!zre_match(p, text, 512, NULL, 0));
    /* And the same patterns still match when they should. */
    if (anchored) {
      text[511] = 'a';
      CHECK(zre_match(p, text, 512, NULL, 0));
    } else {
      text[511] = pats[i][strlen(pats[i]) - 1]; /* the trailing literal */
      CHECK(zre_match(p, text, 512, NULL, 0));
      text[511] = 'a';
    }
    zre_free(p);
  }
  /* Wide alternation over long text. */
  zre_prog *p = compile("(aa|ab|ba|bb)*c");
  CHECK(p != NULL);
  if (p) {
    for (int iter = 0; iter < 10; iter++)
      CHECK(!zre_match(p, text, 512, NULL, 0));
    zre_free(p);
  }
}

static void test_explicit_lengths(void) {
  /* Embedded NULs in pattern (via \\x00) and text, with explicit lengths. */
  zre_prog *prog = NULL;
  CHECK(zre_compile("a\\x00b", 6, &prog, NULL, 0) == ZRE_OK);
  CHECK(prog != NULL);
  if (prog) {
    CHECK(zre_match(prog, "xa\0by", 5, NULL, 0));
    CHECK(!zre_match(prog, "xa\0by", 3, NULL, 0)); /* "xa\0": incomplete */
    zre_free(prog);
  }
  CHECK(!zre_match(NULL, "a", 1, NULL, 0));
  prog = NULL;
  CHECK(zre_compile("a", 1, &prog, NULL, 0) == ZRE_OK);
  if (prog) {
    CHECK(!zre_match(prog, NULL, 1, NULL, 0));
    zre_free(prog);
  }
}

int main(void) {
  test_literals();
  test_dot();
  test_star_plus_quest();
  test_counted();
  test_classes();
  test_escapes();
  test_anchors();
  test_groups_captures();
  test_alternation();
  test_invalid_patterns();
  test_semantics();
  test_adversarial();
  test_explicit_lengths();
  if (failures) {
    fprintf(stderr, "zre: %d failure(s)\n", failures);
    return 1;
  }
  printf("zre: all tests passed\n");
  return 0;
}
