/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: zglob test suite.  Exits nonzero on the first failure. */
#include "zglob/zglob.h"

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

#define M(p, s) CHECK(zglob_match((p), (s)))
#define NM(p, s) CHECK(!zglob_match((p), (s)))

static void test_literals(void) {
  M("", "");
  NM("", "a");
  NM("a", "");
  M("abc", "abc");
  NM("abc", "abd");
  NM("abc", "abcd");
  NM("abcd", "abc");
}

static void test_star(void) {
  M("*", "");
  M("*", "anything at all");
  M("a*", "a");
  M("a*", "abc");
  M("*c", "abc");
  M("*c", "c");
  M("a*c", "abc");
  M("a*c", "ac");
  M("a*c", "abbbc");
  NM("a*c", "abd");
  M("*a*b*", "xxaxxbxx");
  M("*a*b*", "ab");
  NM("*a*b*", "ba"); /* order matters */
  M("**", "xx");
  M("a**c", "abc");
}

static void test_question(void) {
  M("?", "x");
  NM("?", "");
  NM("?", "xy");
  M("a?c", "abc");
  NM("a?c", "ac");
  M("???", "abc");
  NM("???", "ab");
}

static void test_classes(void) {
  M("[abc]", "a");
  M("[abc]", "b");
  NM("[abc]", "d");
  NM("[abc]", "");
  M("[a-z]", "m");
  NM("[a-z]", "M");
  M("[a-z0-9]", "7");
  M("[!abc]", "d");
  NM("[!abc]", "a");
  M("[!a-z]", "M");
  NM("[!a-z]", "m");
  M("[]a]", "]"); /* ']' first is a literal */
  M("[]a]", "a");
  M("[\\]]", "]");
  M("[a\\-z]", "-"); /* escaped '-' is a literal, not a range */
  NM("[a\\-z]", "m");
  M("[a-c-e]", "-"); /* range then literal '-' */
  M("[a-c-e]", "b");
  M("x[a-c]y", "xby");
  NM("x[a-c]y", "xy");
}

static void test_escapes(void) {
  M("a\\*c", "a*c");
  NM("a\\*c", "abc");
  M("\\?", "?");
  M("\\\\", "\\");
  M("a\\[b", "a[b");
}

static void test_malformed_patterns(void) {
  NM("[abc", "a");  /* unterminated class */
  NM("[abc", "[abc");
  NM("[!", "x");    /* unterminated negated class */
  NM("a\\", "a\\"); /* trailing escape is incomplete */
  NM("a\\", "a");
}

static void test_pathological(void) {
  /* Classic star-backtracking stress: must terminate promptly. */
  char text[256];
  memset(text, 'a', sizeof(text) - 1);
  text[sizeof(text) - 1] = '\0';
  NM("a*a*a*a*a*b", text);
  M("a*a*a*a*a*a", text);
}

static void test_lengths(void) {
  CHECK(zglob_match_n("a*c", 3, "abc", 3));
  CHECK(!zglob_match_n("a*c", 3, "abc", 2)); /* "ab" */
  CHECK(zglob_match_n("*", 1, "", 0));
  CHECK(!zglob_match_n(nullptr, 1, "a", 1));
  CHECK(!zglob_match_n("*", 1, nullptr, 0));
  CHECK(!zglob_match(nullptr, "a"));
}

int main(void) {
  test_literals();
  test_star();
  test_question();
  test_classes();
  test_escapes();
  test_malformed_patterns();
  test_pathological();
  test_lengths();
  if (failures) {
    fprintf(stderr, "zglob: %d failure(s)\n", failures);
    return 1;
  }
  printf("zglob: all tests passed\n");
  return 0;
}
