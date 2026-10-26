/* Tests for zpath — bounded lexical path manipulation.
 * Groups: norm, join, dirbase, ext, trunc, null, fuzz. */
#include "zpath/zpath.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

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

static void test_join_maximum(void) {
  static char a[ZPATH_MAX + 1], b[ZPATH_MAX + 1];
  static char out[ZPATH_MAX * 2u + 2u];
  char small[2] = {'x', 'x'};
  memset(a, 'a', ZPATH_MAX);
  memset(b, 'b', ZPATH_MAX);
  CHECK(zpath_join(out, sizeof(out), a, b) == ZPATH_MAX * 2u + 1u &&
        memcmp(out, a, ZPATH_MAX) == 0 && out[ZPATH_MAX] == '/' &&
        memcmp(out + ZPATH_MAX + 1u, b, ZPATH_MAX + 1u) == 0);
  CHECK(zpath_join(NULL, 0, a, b) == ZPATH_MAX * 2u + 1u);
  CHECK(zpath_join(small, sizeof(small), a, b) == ZPATH_MAX * 2u + 1u &&
        small[0] == 'a' && small[1] == 0);
}

static void test_cli(void);

int main(void) {
  test_cli();
  test_join_maximum();
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

static FILE *cli_sink, *cli_errors;
static size_t cli_writes, cli_flushes;
static FILE *real_stdout(void) { return stdout; }
static FILE *real_stderr(void) { return stderr; }
static FILE *cli_output(void) {
  cli_writes++;
  return cli_sink;
}
[[maybe_unused]] static int cli_flush(FILE *stream) {
  if (stream == cli_sink) cli_flushes++;
  return fflush(stream);
}
#undef stdout
#undef stderr
#define stdout cli_sink
#define stderr cli_errors
#define printf(...) fprintf(cli_output(), __VA_ARGS__)
#define fflush cli_flush
#define main embedded_cli_main
#include "../app/main.c"
#undef main
#undef fflush
#undef printf
#undef stdout
#undef stderr
#define stdout real_stdout()
#define stderr real_stderr()

static FILE *required_stream(FILE *stream) {
  if (!stream) { fprintf(stderr, "zpath CLI fixture setup failed\n"); exit(2); }
  return stream;
}
static int cli_invoke(FILE *sink, FILE *errors, int argc, char **args) {
  cli_sink = sink; cli_errors = errors;
  cli_writes = cli_flushes = 0;
  int rc = embedded_cli_main(argc, args);
  cli_sink = stdout; cli_errors = stderr;
  return rc;
}
static void cli_case(int argc, char **args, int status, const char *want) {
  FILE *sink = required_stream(tmpfile()), *errors = required_stream(tmpfile());
  CHECK(cli_invoke(sink, errors, argc, args) == status);
  if (!*want) CHECK(cli_flushes == 0);
  char bytes[1024];
  rewind(sink);
  size_t n = fread(bytes, 1, sizeof bytes, sink);
  CHECK(!ferror(sink) && n == strlen(want) && !memcmp(bytes, want, n));
  CHECK(fclose(sink) == 0 && fclose(errors) == 0);
}
static void cli_normal(void) {
  char *norm[] = {"zpath", "normalize", "a/./b", "", NULL};
  cli_case(4, norm, 0, "a/b\n.\n");
  char *dir[] = {"zpath", "dirname", "a/b", "/a", NULL};
  cli_case(4, dir, 0, "a\n/\n");
  char *join[] = {"zpath", "join", "a", "b", NULL};
  cli_case(4, join, 0, "a/b\n");
  char *base[] = {"zpath", "basename", "a/file.txt", ".txt", NULL};
  cli_case(4, base, 0, "file\n");
  char *ext[] = {"zpath", "ext", "a.txt", "plain", NULL};
  cli_case(4, ext, 0, ".txt\n\n");
  char *absolute[] = {"zpath", "isabs", "/a", "relative", NULL};
  cli_case(4, absolute, 1, "/a: absolute\nrelative: relative\n");
}
static void cli_invalid_operands(void) {
  static char long_path[ZPATH_MAX + 2];
  memset(long_path, 'a', sizeof long_path - 1);
  const char *commands[] = {"normalize", "dirname"};
  for (size_t i = 0; i < 2; i++) {
    char *mixed[] = {"zpath", (char *)commands[i], "a/b", long_path, "c/d", NULL};
    cli_case(5, mixed, 1, i ? "a\nc\n" : "a/b\nc/d\n");
    char *all_bad[] = {"zpath", (char *)commands[i], long_path, NULL};
    cli_case(3, all_bad, 1, "");
  }
  char *join[] = {"zpath", "join", long_path, "x", NULL};
  cli_case(4, join, 1, "");
  char *base[] = {"zpath", "basename", long_path, NULL};
  cli_case(3, base, 1, "");
  char *usage[] = {"zpath", "join", "a", NULL};
  cli_case(3, usage, 2, "");
  char *unknown[] = {"zpath", "unknown", "a", NULL};
  cli_case(3, unknown, 2, "");
}
static void cli_write_failure(const char *command, bool buffered) {
#ifdef _WIN32
  const char *null_path = "NUL";
#else
  const char *null_path = "/dev/null";
#endif
  FILE *sink = required_stream(fopen(buffered ? "/dev/full" : null_path, buffered ? "w" : "r"));
  FILE *errors = required_stream(tmpfile());
  char buffer[4096];
  if (buffered && setvbuf(sink, buffer, _IOFBF, sizeof buffer) != 0) exit(2);
  char *args[] = {"zpath", (char *)command, "a/b", "c", NULL};
  CHECK(cli_invoke(sink, errors, 4, args) == 1 && ferror(sink));
  if (!buffered) CHECK(cli_writes == 1);
  char diagnostic[256];
  rewind(errors);
  size_t n = fread(diagnostic, 1, sizeof diagnostic - 1, errors);
  diagnostic[n] = 0;
  CHECK(!ferror(errors) && strstr(diagnostic, "write error") != NULL);
  CHECK(fclose(errors) == 0);
  (void)fclose(sink);
}
static void cli_relative_and_mixed(void) {
  FILE *sink = required_stream(tmpfile()), *errors = required_stream(tmpfile());
  char *relative[] = {"zpath", "isabs", "a", NULL};
  CHECK(cli_invoke(sink, errors, 3, relative) == 1);
  CHECK(ftell(errors) == 0);
  CHECK(fclose(sink) == 0 && fclose(errors) == 0);
#ifdef __linux__
  sink = required_stream(fopen("/dev/full", "w"));
  errors = required_stream(tmpfile());
  char buffer[4096];
  CHECK(setvbuf(sink, buffer, _IOFBF, sizeof buffer) == 0);
  static char long_path[ZPATH_MAX + 2];
  memset(long_path, 'a', sizeof long_path - 1);
  char *mixed[] = {"zpath", "normalize", "a/b", long_path, "c/d", NULL};
  CHECK(cli_invoke(sink, errors, 5, mixed) == 1 && ferror(sink));
  CHECK(cli_writes == 2 && cli_flushes == 1);
  char diagnostic[256];
  rewind(errors);
  size_t n = fread(diagnostic, 1, sizeof diagnostic - 1, errors);
  diagnostic[n] = 0;
  CHECK(strstr(diagnostic, "input too long") != NULL && strstr(diagnostic, "write error") != NULL);
  CHECK(fclose(errors) == 0);
  (void)fclose(sink);
#endif
}
static void test_cli(void) {
  cli_normal();
  cli_invalid_operands();
  const char *commands[] = {"normalize", "dirname", "join", "basename", "ext", "isabs"};
  for (size_t i = 0; i < 6; i++) {
    cli_write_failure(commands[i], false);
#ifdef __linux__
    cli_write_failure(commands[i], true);
#endif
  }
  cli_relative_and_mixed();
}
