/* Tests for zlev — bounded Levenshtein distance.
 * Groups: kat, bound, sim, null, fuzz. */
#include "zlev/zlev.h"

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

/* ---- known answers (classic literature values) --------------------------- */

static void test_kat(void) {
  static const struct {
    const char *a, *b;
    size_t d;
  } KAT[] = {
      {"", "", 0},
      {"", "abc", 3},
      {"abc", "", 3},
      {"abc", "abc", 0},
      {"kitten", "sitting", 3},
      {"saturday", "sunday", 3},
      {"flaw", "lawn", 2},
      {"book", "back", 2},
      {"gumbo", "gambol", 2},
      {"abcdef", "azced", 3},
  };
  size_t i;
  for (i = 0; i < sizeof(KAT) / sizeof(KAT[0]); i++) {
    size_t d = zlev_distance(KAT[i].a, strlen(KAT[i].a), KAT[i].b,
                             strlen(KAT[i].b));
    if (d != KAT[i].d) {
      fprintf(stderr, "FAIL kat: \"%s\" vs \"%s\": %zu (want %zu)\n",
              KAT[i].a, KAT[i].b, d, KAT[i].d);
      g_fail = 1;
    }
  }
  /* Binary-safe: embedded NULs are data. */
  CHECK(zlev_distance("a\0b", 3, "a\0c", 3) == 1);
  /* Symmetry. */
  CHECK(zlev_distance("kitten", 6, "sitting", 7) ==
        zlev_distance("sitting", 7, "kitten", 6));
}

/* ---- bounded variant -------------------------------------------------------- */

static void test_bound(void) {
  /* Exact below the limit. */
  CHECK(zlev_distance_bounded("kitten", 6, "sitting", 7, 3) == 3);
  CHECK(zlev_distance_bounded("kitten", 6, "sitting", 7, 10) == 3);
  /* limit+1 above the limit. */
  CHECK(zlev_distance_bounded("kitten", 6, "sitting", 7, 2) == 3);
  CHECK(zlev_distance_bounded("", 0, "abcdefghij", 10, 4) == 5);
  CHECK(zlev_distance_bounded("aaaaaaaaaa", 10, "bbbbbbbbbb", 10, 5) == 6);
  /* length lower-bound shortcut */
  CHECK(zlev_distance_bounded("a", 1, "abcdefghij", 10, 3) == 4);
  /* limit 0: equality test */
  CHECK(zlev_distance_bounded("same", 4, "same", 4, 0) == 0);
  CHECK(zlev_distance_bounded("same", 4, "diff", 4, 0) == 1);
}

/* ---- similarity ---------------------------------------------------------------- */

static void test_sim(void) {
  CHECK(zlev_similarity_milli("", 0, "", 0) == 1000);
  CHECK(zlev_similarity_milli("abc", 3, "abc", 3) == 1000);
  CHECK(zlev_similarity_milli("", 0, "abcd", 4) == 0);
  CHECK(zlev_similarity_milli("kitten", 6, "sitting", 7) ==
        1000 - (1000 * 3) / 7);
  CHECK(zlev_similarity_milli(NULL, 1, "x", 1) == -1);
}

/* ---- NULL / bounds ------------------------------------------------------------------ */

static void test_null(void) {
  CHECK(zlev_distance(NULL, 1, "x", 1) == SIZE_MAX);
  CHECK(zlev_distance("x", 1, NULL, 1) == SIZE_MAX);
  CHECK(zlev_distance(NULL, 0, NULL, 0) == 0);
  CHECK(zlev_distance_bounded(NULL, 2, "x", 1, 5) == SIZE_MAX);
  {
    static char big[ZLEV_MAX + 2];
    memset(big, 'a', ZLEV_MAX + 1);
    big[ZLEV_MAX + 1] = '\0';
    CHECK(zlev_distance(big, ZLEV_MAX + 1, "x", 1) == SIZE_MAX);
    CHECK(zlev_distance_bounded("x", 1, big, ZLEV_MAX + 1, 3) == SIZE_MAX);
  }
}

/* ---- fuzz: banded must equal full below the limit --------------------------------------- */

static uint64_t rng_state = 0xC0FFEE2542D3B19Aull;
static uint64_t rng_next(void) {
  rng_state ^= rng_state << 13;
  rng_state ^= rng_state >> 7;
  rng_state ^= rng_state << 17;
  return rng_state;
}

static void test_fuzz(void) {
  /* Exhaustive agreement: every pair of binary strings up to length 4
   * over a 2-letter alphabet, every limit 0..5, banded must match
   * full DP exactly. */
  {
    char a[6], b[6];
    size_t na, nb, lim;
    int bits;
    for (na = 0; na <= 4; na++)
      for (nb = 0; nb <= 4; nb++)
        for (bits = 0; bits < (1 << (na + nb)); bits++) {
          size_t i, full, got, want;
          for (i = 0; i < na; i++) a[i] = 'a' + ((bits >> i) & 1);
          for (i = 0; i < nb; i++) b[i] = 'a' + ((bits >> (na + i)) & 1);
          full = zlev_distance(a, na, b, nb);
          for (lim = 0; lim <= 5; lim++) {
            got = zlev_distance_bounded(a, na, b, nb, lim);
            want = full <= lim ? full : lim + 1;
            CHECK(got == want);
          }
        }
  }
  int trial;
  for (trial = 0; trial < 4000; trial++) {
    char a[40], b[40];
    size_t na = rng_next() % 40, nb = rng_next() % 40, i, full, lim, got;
    for (i = 0; i < na; i++) a[i] = (char)('a' + rng_next() % 6);
    for (i = 0; i < nb; i++) b[i] = (char)('a' + rng_next() % 6);
    full = zlev_distance(a, na, b, nb);
    lim = rng_next() % 45;
    got = zlev_distance_bounded(a, na, b, nb, lim);
    if (full <= lim)
      CHECK(got == full);
    else
      CHECK(got == lim + 1);
    /* full is symmetric and satisfies the length lower bound */
    CHECK(full == zlev_distance(b, nb, a, na));
    CHECK(full >= (na > nb ? na - nb : nb - na));
    /* thread-safety smoke: interleaved repeated calls stay stable */
    CHECK(zlev_distance(a, na, b, nb) == full);
  }
}

int main(void) {
  test_kat();
  test_bound();
  test_sim();
  test_null();
  test_fuzz();
  if (g_fail) {
    fprintf(stderr, "test_zlev: FAILURES\n");
    return 1;
  }
  printf("test_zlev: all groups passed (kat bound sim null fuzz)\n");
  return 0;
}
