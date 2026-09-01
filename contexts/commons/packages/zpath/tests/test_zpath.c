/* Tests for zpath — bounded lexical path manipulation.
 * Groups: norm, join, dirbase, ext, trunc, null, fuzz. */
#include "zpath/zpath.h"

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

/* ---- normalize --------------------------------------------------------- */

static void test_norm(void) {
  static const struct {
    const char *in, *out;
  } KAT[] = {
      {"", "."},
      {".", "."},
      {"./", "."},
      {"a", "a"},
      {"a/b/c", "a/b/c"},
      {"a/./b", "a/b"},
      {"a//b", "a/b"},
      {"a/b/", "a/b"},
      {"/", "/"},
      {"//", "/"},
      {"///a//b//", "/a/b"},
      {"/a/./b/../c", "/a/c"},
      {"/a/../../c", "/c"},
      {"/..", "/"},
      {"..", ".."},
      {"../..", "../.."},
      {"../../x", "../../x"},
      {"a/../../b", "../b"},
      {"a/b/../../../c", "../c"},
      {"./a", "a"},
      {"a/./.", "a"},
      {"foo/../bar/..", "."},
      {"/a/b/../..", "/"},
      {"a/b/c/../../..", "."},
      {"....//a", "..../a"},
      {"a/..../b", "a/..../b"},
  };
  size_t i;
  for (i = 0; i < sizeof(KAT) / sizeof(KAT[0]); i++) {
    char buf[ZPATH_MAX + 8];
    size_t need = zpath_normalize(buf, sizeof(buf), KAT[i].in);
    if (need != strlen(KAT[i].out) || strcmp(buf, KAT[i].out) != 0) {
      fprintf(stderr, "FAIL norm: \"%s\" -> \"%s\" (want \"%s\")\n",
              KAT[i].in, buf, KAT[i].out);
      g_fail = 1;
    }
  }
}

/* ---- join ---------------------------------------------------------------- */

static void test_join(void) {
  static const struct {
    const char *a, *b, *out;
  } KAT[] = {
      {"", "", ""},
      {"", "b", "b"},
      {"a", "", "a/"},
      {"a", "b", "a/b"},
      {"a/", "b", "a/b"},
      {"a", "/b", "/b"},      /* absolute b wins */
      {"/", "b", "/b"},
      {"/a", "b/c", "/a/b/c"},
      {"a//", "b", "a//b"},   /* lexical: only one separator added */
  };
  size_t i;
  for (i = 0; i < sizeof(KAT) / sizeof(KAT[0]); i++) {
    char buf[ZPATH_MAX * 2 + 8];
    size_t need = zpath_join(buf, sizeof(buf), KAT[i].a, KAT[i].b);
    if (need != strlen(KAT[i].out) || strcmp(buf, KAT[i].out) != 0) {
      fprintf(stderr, "FAIL join: \"%s\" + \"%s\" -> \"%s\" (want \"%s\")\n",
              KAT[i].a, KAT[i].b, buf, KAT[i].out);
      g_fail = 1;
    }
  }
}

/* ---- dirname / basename --------------------------------------------------- */

static void test_dirbase(void) {
  static const struct {
    const char *in, *dir, *base;
  } KAT[] = {
      {"", ".", "."},
      {"/", "/", "/"},
      {"//", "/", "/"},
      {"/a", "/", "a"},
      {"/a/", "/", "a"},
      {"/a/b", "/a", "b"},
      {"/a/b/", "/a", "b"},
      {"a", ".", "a"},
      {"a/b", "a", "b"},
      {"a/b/c", "a/b", "c"},
      {"a/", ".", "a"},
      {"///a//b//", "///a", "b"},
      {".", ".", "."},
      {"..", ".", ".."},
      {"/a/b/c.txt", "/a/b", "c.txt"},
  };
  size_t i;
  for (i = 0; i < sizeof(KAT) / sizeof(KAT[0]); i++) {
    char d[ZPATH_MAX + 8], b[ZPATH_MAX + 8];
    size_t nd = zpath_dirname(d, sizeof(d), KAT[i].in);
    size_t nb = zpath_basename(b, sizeof(b), KAT[i].in, NULL);
    if (nd != strlen(KAT[i].dir) || strcmp(d, KAT[i].dir) != 0) {
      fprintf(stderr, "FAIL dirname: \"%s\" -> \"%s\" (want \"%s\")\n",
              KAT[i].in, d, KAT[i].dir);
      g_fail = 1;
    }
    if (nb != strlen(KAT[i].base) || strcmp(b, KAT[i].base) != 0) {
      fprintf(stderr, "FAIL basename: \"%s\" -> \"%s\" (want \"%s\")\n",
              KAT[i].in, b, KAT[i].base);
      g_fail = 1;
    }
  }
  /* Suffix stripping. */
  {
    char b[64];
    CHECK(zpath_basename(b, sizeof(b), "a/b.c", ".c") == 1 &&
          strcmp(b, "b") == 0);
    CHECK(zpath_basename(b, sizeof(b), "a/b.c", "b.c") == 3 &&
          strcmp(b, "b.c") == 0); /* suffix == whole name: keep */
    CHECK(zpath_basename(b, sizeof(b), "b.c", "") == 3 &&
          strcmp(b, "b.c") == 0); /* empty suffix: no-op */
  }
}

/* ---- extension -------------------------------------------------------------- */

static void test_ext(void) {
  CHECK(zpath_ext("a/b.txt") != NULL &&
        strcmp(zpath_ext("a/b.txt"), ".txt") == 0);
  CHECK(zpath_ext("a/b.tar.gz") != NULL &&
        strcmp(zpath_ext("a/b.tar.gz"), ".gz") == 0);
  CHECK(zpath_ext("a/b") == NULL);
  CHECK(zpath_ext("a/.hidden") == NULL);
  CHECK(zpath_ext("a/.") == NULL);
  CHECK(zpath_ext("a/..") == NULL);
  CHECK(zpath_ext("a.b/c") == NULL); /* dot in a parent dir */
  CHECK(zpath_ext("file.") != NULL && strcmp(zpath_ext("file."), ".") == 0);
  CHECK(zpath_ext("") == NULL);
  CHECK(zpath_ext(NULL) == NULL);
  CHECK(zpath_isabs("/a") && !zpath_isabs("a") && !zpath_isabs("") &&
        !zpath_isabs(NULL));
}

/* ---- truncation / measuring -------------------------------------------------- */

static void test_trunc(void) {
  char small[4];
  size_t need;
  /* normalize: needed length reported, output NUL-terminated. */
  need = zpath_normalize(small, sizeof(small), "aaa/bbb");
  CHECK(need == 7);
  CHECK(strlen(small) == 3 && memcmp(small, "aaa", 3) == 0);
  /* join. */
  need = zpath_join(small, sizeof(small), "aa", "bb");
  CHECK(need == 5 && strcmp(small, "aa/") == 0);
  /* measuring mode (NULL dst). */
  CHECK(zpath_normalize(NULL, 0, "/a/b") == 4);
  CHECK(zpath_join(NULL, 0, "a", "b") == 3);
  CHECK(zpath_dirname(NULL, 0, "a/b") == 1);
  CHECK(zpath_basename(NULL, 0, "a/b", NULL) == 1);
  /* over-long input rejected. */
  {
    static char big[ZPATH_MAX + 2];
    memset(big, 'a', ZPATH_MAX + 1);
    big[ZPATH_MAX + 1] = '\0';
    CHECK(zpath_normalize(small, sizeof(small), big) == SIZE_MAX);
    CHECK(zpath_join(small, sizeof(small), "a", big) == SIZE_MAX);
    CHECK(zpath_dirname(small, sizeof(small), big) == SIZE_MAX);
    CHECK(zpath_basename(small, sizeof(small), big, NULL) == SIZE_MAX);
    CHECK(zpath_validate(big) == ZPATH_ERR_RANGE);
    CHECK(zpath_ext(big) == NULL);
  }
}

/* ---- NULL safety ---------------------------------------------------------------- */

static void test_null(void) {
  char buf[16] = "xxxxxxxxxxxxxxx";
  CHECK(zpath_normalize(buf, sizeof(buf), NULL) == SIZE_MAX);
  CHECK(zpath_join(buf, sizeof(buf), NULL, "b") == SIZE_MAX);
  CHECK(zpath_join(buf, sizeof(buf), "a", NULL) == SIZE_MAX);
  CHECK(zpath_dirname(buf, sizeof(buf), NULL) == SIZE_MAX);
  CHECK(zpath_basename(buf, sizeof(buf), NULL, NULL) == SIZE_MAX);
  CHECK(zpath_validate(NULL) == ZPATH_ERR_ARG);
  CHECK(buf[0] == '\0' || buf[0] == 'x'); /* no crash; output incidental */
}

/* ---- fuzz -------------------------------------------------------------------------- */

static uint64_t rng_state = 0x9E3779B97F4A7C15ull;
static uint64_t rng_next(void) {
  rng_state ^= rng_state << 13;
  rng_state ^= rng_state >> 7;
  rng_state ^= rng_state << 17;
  return rng_state;
}

static void test_fuzz(void) {
  /* Alphabet of '/', '.', 'a' exercises every code path. Invariants:
   * never crash; need == strlen(result) when untruncated; normalize is
   * idempotent; normalized output never contains "//", "/./", or a
   * trailing '/' (except root). */
  int trial;
  for (trial = 0; trial < 6000; trial++) {
    char in[64], out1[ZPATH_MAX + 8], out2[ZPATH_MAX + 8];
    size_t n = rng_next() % 48, i;
    for (i = 0; i < n; i++) {
      uint64_t r = rng_next() % 5;
      in[i] = r < 2 ? '/' : r < 4 ? '.' : 'a';
    }
    in[n] = '\0';
    {
      size_t need = zpath_normalize(out1, sizeof(out1), in);
      CHECK(need != SIZE_MAX);
      CHECK(need == strlen(out1));
      CHECK(zpath_normalize(out2, sizeof(out2), out1) == need);
      CHECK(strcmp(out1, out2) == 0); /* idempotent */
      CHECK(strstr(out1, "//") == NULL);
      CHECK(strstr(out1, "/./") == NULL);
      if (need > 1) CHECK(out1[need - 1] != '/');
    }
    /* join + dirname/basename never crash on the same alphabet. */
    {
      char j[ZPATH_MAX * 2 + 8], d[ZPATH_MAX + 8], b[ZPATH_MAX + 8];
      char other[16];
      size_t m = rng_next() % 12;
      for (i = 0; i < m; i++)
        other[i] = (rng_next() % 3) == 0 ? '/' : (rng_next() % 2) ? '.' : 'z';
      other[m] = '\0';
      CHECK(zpath_join(j, sizeof(j), in, other) != SIZE_MAX);
      CHECK(zpath_dirname(d, sizeof(d), in) != SIZE_MAX);
      CHECK(zpath_basename(b, sizeof(b), in, other) != SIZE_MAX);
      (void)zpath_ext(in);
    }
  }
}

int main(void) {
  test_norm();
  test_join();
  test_dirbase();
  test_ext();
  test_trunc();
  test_null();
  test_fuzz();
  if (g_fail) {
    fprintf(stderr, "test_zpath: FAILURES\n");
    return 1;
  }
  printf("test_zpath: all groups passed (norm join dirbase ext trunc null fuzz)\n");
  return 0;
}
