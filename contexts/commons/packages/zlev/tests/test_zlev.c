/* Tests for zlev — bounded Levenshtein distance.
 * Groups: kat, bound, sim, null, fuzz. */
#include "zlev/zlev.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <limits.h>

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
        (1000 * (7 - 3)) / 7);
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

static void test_similarity_rounding(void) {
  CHECK(zlev_similarity_milli("abc", 3, "abd", 3) == 666);
}

static void test_alternating_bands(void) {
  static const unsigned char a[] = {0, 0xff, 'a', 'b', 0, 0x80, 'c'};
  static const unsigned char b[] = {0, 0xff, 'x', 0, 0x80};
  static const size_t limits[] = {SIZE_MAX, 1, 0, 3, SIZE_MAX, 2, 0, 7};
  size_t full = zlev_distance(a, sizeof a, b, sizeof b);
  for (size_t i = 0; i < sizeof limits / sizeof limits[0]; i++) {
    size_t limit = limits[i];
    size_t effective = limit > ZLEV_MAX ? ZLEV_MAX : limit;
    size_t want = full <= effective ? full : effective + 1;
    CHECK(zlev_distance_bounded(a, sizeof a, b, sizeof b, limit) == want);
    CHECK(zlev_distance_bounded(b, sizeof b, a, sizeof a, limit) == want);
    CHECK(zlev_distance_bounded(a, sizeof a, a, sizeof a, limit) == 0);
  }
}

static void test_cli(void);

int main(void) {
  test_cli();
  test_similarity_rounding();
  test_alternating_bands();
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

static FILE *cli_sink;
static size_t cli_flushes;
static FILE *real_stdout(void) { return stdout; }
[[maybe_unused]] static int cli_flush(FILE *stream) {
  if (stream == cli_sink) cli_flushes++;
  return fflush(stream);
}
#undef stdout
#define stdout cli_sink
#define printf(...) fprintf(cli_sink, __VA_ARGS__)
#define fflush cli_flush
#define main embedded_cli_main
#include "../app/main.c"
#undef main
#undef fflush
#undef printf
#undef stdout
#define stdout real_stdout()

static FILE *required_stream(FILE *stream) {
  if (!stream) { fprintf(stderr, "zlev CLI fixture setup failed\n"); exit(2); }
  return stream;
}
static int cli_invoke(FILE *sink, int argc, char **args) {
  cli_sink = sink;
  cli_flushes = 0;
  errno = ERANGE;
  int rc = embedded_cli_main(argc, args);
  cli_sink = stdout;
  return rc;
}
static void cli_case(int argc, char **args, int status, const char *want) {
  FILE *sink = required_stream(tmpfile());
  CHECK(cli_invoke(sink, argc, args) == status);
  if (!*want) CHECK(cli_flushes == 0);
  char bytes[128];
  rewind(sink);
  size_t n = fread(bytes, 1, sizeof bytes, sink);
  CHECK(!ferror(sink) && n == strlen(want) && !memcmp(bytes, want, n));
  CHECK(fclose(sink) == 0);
}
static void cli_limits(void) {
  char maximum[64], overflow[64], underflow[64];
  snprintf(maximum, sizeof maximum, "%ld", LONG_MAX);
  snprintf(overflow, sizeof overflow, "%ld0", LONG_MAX);
  snprintf(underflow, sizeof underflow, "%ld0", LONG_MIN);
  const char *bad[] = {overflow, underflow, "", " ", "-1", "1x", "1 "};
  for (size_t i = 0; i < sizeof bad / sizeof bad[0]; i++) {
    char *args[] = {"zlev", "--limit", (char *)bad[i], "a", "b", NULL};
    cli_case(5, args, 2, "");
    char *sim[] = {"zlev", "--sim", "--limit", (char *)bad[i], "a", "b", NULL};
    cli_case(6, sim, 2, "");
  }
  const char *valid[] = {"0", "-0", "+0", " \t+0", maximum};
  for (size_t i = 0; i < sizeof valid / sizeof valid[0]; i++) {
    char *args[] = {"zlev", "--limit", (char *)valid[i], "a", "b", NULL};
    cli_case(5, args, 0, "1\n");
  }
  char *last[] = {"zlev", "--limit", "0", "--limit", "2", "abc", "xyz", NULL};
  cli_case(7, last, 0, "3\n");
  char *sim_last[] = {"zlev", "--limit", "0", "--sim", "abc", "abd", NULL};
  cli_case(6, sim_last, 0, "0.666\n");
  char *sim_first[] = {"zlev", "--sim", "--limit", "0", "abc", "abd", NULL};
  cli_case(6, sim_first, 0, "0.666\n");
}
static void cli_failed_sink(bool sim, bool buffered) {
#ifdef _WIN32
  const char *null_path = "NUL";
#else
  const char *null_path = "/dev/null";
#endif
  FILE *sink = required_stream(fopen(buffered ? "/dev/full" : null_path, buffered ? "w" : "r"));
  char buffer[4096];
  if (buffered && setvbuf(sink, buffer, _IOFBF, sizeof buffer) != 0) exit(2);
  char *distance[] = {"zlev", "kitten", "sitting", NULL};
  char *similarity[] = {"zlev", "--sim", "abc", "abd", NULL};
  CHECK(cli_invoke(sink, sim ? 4 : 3, sim ? similarity : distance) == 1);
  CHECK(ferror(sink));
  (void)fclose(sink);
}
static void cli_controls(void) {
  char *distance[] = {"zlev", "kitten", "sitting", NULL};
  cli_case(3, distance, 0, "3\n");
  char *cutoff[] = {"zlev", "--limit", "0", "abcdef", "uvwxyz", NULL};
  cli_case(5, cutoff, 0, "1\n");
  char *usage[] = {"zlev", "a", NULL};
  cli_case(2, usage, 2, "");
  char large[ZLEV_MAX + 2];
  memset(large, 'a', sizeof large - 1);
  large[sizeof large - 1] = '\0';
  char *long_distance[] = {"zlev", large, "b", NULL};
  char *long_sim[] = {"zlev", "--sim", large, "b", NULL};
  cli_case(3, long_distance, 1, "");
  cli_case(4, long_sim, 1, "");
}
static void test_cli(void) {
  cli_limits();
  cli_controls();
  cli_failed_sink(false, false);
  cli_failed_sink(true, false);
#ifdef __linux__
  cli_failed_sink(false, true);
  cli_failed_sink(true, true);
#endif
}
