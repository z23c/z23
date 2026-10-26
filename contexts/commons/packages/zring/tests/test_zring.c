/* Tests for zring — fixed-capacity byte ring buffer.
 * Groups: basic, wrap, bulk, peek, err, null, fuzz. */
#include "zring/zring.h"

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

static void test_basic(void) {
  unsigned char store[4];
  zring r;
  unsigned char b = 0;
  CHECK(zring_init(&r, store, 4) == ZRING_OK);
  CHECK(zring_is_empty(&r) && !zring_is_full(&r));
  CHECK(zring_len(&r) == 0 && zring_avail(&r) == 4);
  CHECK(zring_get(&r, &b) == ZRING_ERR_EMPTY);
  CHECK(zring_put(&r, 1) == ZRING_OK);
  CHECK(zring_put(&r, 2) == ZRING_OK);
  CHECK(zring_put(&r, 3) == ZRING_OK);
  CHECK(zring_put(&r, 4) == ZRING_OK);
  CHECK(zring_is_full(&r));
  CHECK(zring_put(&r, 5) == ZRING_ERR_FULL);
  CHECK(zring_len(&r) == 4 && zring_avail(&r) == 0);
  CHECK(zring_peek(&r, &b) == ZRING_OK && b == 1);
  CHECK(zring_len(&r) == 4); /* peek does not consume */
  CHECK(zring_get(&r, &b) == ZRING_OK && b == 1);
  CHECK(zring_get(&r, &b) == ZRING_OK && b == 2);
  CHECK(zring_get(&r, &b) == ZRING_OK && b == 3);
  CHECK(zring_get(&r, &b) == ZRING_OK && b == 4);
  CHECK(zring_is_empty(&r));
  CHECK(zring_get(&r, &b) == ZRING_ERR_EMPTY);
  /* Reusable after drain. */
  CHECK(zring_put(&r, 9) == ZRING_OK);
  CHECK(zring_get(&r, &b) == ZRING_OK && b == 9);
}

static void test_wrap(void) {
  unsigned char store[3];
  zring r;
  unsigned char b = 0;
  size_t i;
  CHECK(zring_init(&r, store, 3) == ZRING_OK);
  /* Hammer the wrap point: FIFO order must survive thousands of
   * wraparounds. */
  for (i = 0; i < 3000; i++) {
    CHECK(zring_put(&r, (unsigned char)(i & 7)) == ZRING_OK);
    CHECK(zring_put(&r, (unsigned char)((i + 1) & 7)) == ZRING_OK);
    CHECK(zring_get(&r, &b) == ZRING_OK && b == (unsigned char)(i & 7));
    CHECK(zring_get(&r, &b) == ZRING_OK &&
          b == (unsigned char)((i + 1) & 7));
  }
  CHECK(zring_is_empty(&r));
}

static void test_bulk(void) {
  unsigned char store[8];
  zring r;
  unsigned char out[8];
  CHECK(zring_init(&r, store, 8) == ZRING_OK);
  /* Write more than cap: takes what fits. */
  CHECK(zring_write(&r, "abcdefgh", 8) == 8);
  CHECK(zring_write(&r, "zz", 2) == 0); /* full */
  CHECK(zring_read(&r, out, 3) == 3 && memcmp(out, "abc", 3) == 0);
  /* Wrap-crossing write then read: only 3 free after the read. */
  CHECK(zring_write(&r, "12345", 5) == 3);
  CHECK(zring_is_full(&r));
  CHECK(zring_read(&r, out, 8) == 8 &&
        memcmp(out, "defgh123", 8) == 0);
  CHECK(zring_is_empty(&r));
  /* Short read. */
  CHECK(zring_write(&r, "xy", 2) == 2);
  CHECK(zring_read(&r, out, 8) == 2 && memcmp(out, "xy", 2) == 0);
}

static void test_peek_drop(void) {
  unsigned char store[6];
  zring r;
  unsigned char out[6];
  CHECK(zring_init(&r, store, 6) == ZRING_OK);
  CHECK(zring_write(&r, "hello!", 6) == 6);
  CHECK(zring_peek_at(&r, 0, out, 2) == 2 && memcmp(out, "he", 2) == 0);
  CHECK(zring_peek_at(&r, 4, out, 2) == 2 && memcmp(out, "o!", 2) == 0);
  CHECK(zring_peek_at(&r, 5, out, 3) == 1 && out[0] == '!');
  CHECK(zring_peek_at(&r, 6, out, 1) == 0);
  CHECK(zring_len(&r) == 6);
  /* Drop across the wrap point. */
  CHECK(zring_read(&r, out, 2) == 2);
  CHECK(zring_write(&r, "12", 2) == 2);
  CHECK(zring_drop(&r, 3) == 3);
  CHECK(zring_len(&r) == 3);
  CHECK(zring_read(&r, out, 6) == 3 && memcmp(out, "!12", 3) == 0);
  CHECK(zring_drop(&r, 9) == 0);
}

static void test_err_null(void) {
  unsigned char store[2];
  unsigned char b;
  zring r;
  CHECK(zring_init(NULL, store, 2) == ZRING_ERR_ARG);
  CHECK(zring_init(&r, NULL, 2) == ZRING_ERR_ARG);
  CHECK(zring_init(&r, NULL, 0) == ZRING_OK); /* zero-cap ring */
  CHECK(zring_put(&r, 1) == ZRING_ERR_FULL);
  CHECK(zring_get(&r, &b) == ZRING_ERR_EMPTY);
  CHECK(zring_init(&r, store, 2) == ZRING_OK);
  CHECK(zring_put(NULL, 1) == ZRING_ERR_ARG);
  CHECK(zring_get(&r, NULL) == ZRING_ERR_ARG);
  CHECK(zring_peek(&r, NULL) == ZRING_ERR_ARG);
  CHECK(zring_write(&r, NULL, 3) == 0);
  CHECK(zring_read(&r, NULL, 3) == 0);
  CHECK(zring_peek_at(&r, 0, NULL, 3) == 0);
  CHECK(zring_drop(NULL, 1) == 0);
  CHECK(zring_len(NULL) == 0 && zring_avail(NULL) == 0);
  CHECK(zring_is_empty(NULL) && !zring_is_full(NULL));
  CHECK(zring_reset(NULL) == ZRING_ERR_ARG);
  CHECK(zring_reset(&r) == ZRING_OK && zring_len(&r) == 0);
}

/* ---- fuzz against a reference model ---------------------------------------- */

static uint64_t rng_state = 0xD1B54A32D192ED03ull;
static uint64_t rng_next(void) {
  rng_state ^= rng_state << 13;
  rng_state ^= rng_state >> 7;
  rng_state ^= rng_state << 17;
  return rng_state;
}

static void test_fuzz(void) {
  /* Model: plain array queue. Random write/read/peek/drop bursts must
   * match the ring exactly, across arbitrary wrap states. */
  int trial;
  for (trial = 0; trial < 2000; trial++) {
    unsigned char store[64];
    unsigned char model[64];
    size_t mhead = 0, mcount = 0;
    const size_t cap = 1 + rng_next() % 64;
    zring r;
    int step;
    CHECK(zring_init(&r, store, cap) == ZRING_OK);
    for (step = 0; step < 200; step++) {
      unsigned char tmp[64];
      size_t n = rng_next() % 20, i, got;
      switch (rng_next() % 4) {
      case 0: /* write */
        for (i = 0; i < n; i++) tmp[i] = (unsigned char)rng_next();
        got = zring_write(&r, tmp, n);
        CHECK(got == (n < cap - mcount ? n : cap - mcount));
        for (i = 0; i < got; i++) model[(mhead + mcount + i) % 64] = tmp[i];
        mcount += got;
        break;
      case 1: /* read */
        got = zring_read(&r, tmp, n);
        CHECK(got == (n < mcount ? n : mcount));
        for (i = 0; i < got; i++)
          CHECK(tmp[i] == model[(mhead + i) % 64]);
        mhead = (mhead + got) % 64;
        mcount -= got;
        break;
      case 2: /* peek_at */
        got = zring_peek_at(&r, n, tmp, sizeof(tmp));
        CHECK(got == (mcount > n ? (mcount - n < 64 ? mcount - n : 64)
                                 : 0));
        for (i = 0; i < got; i++)
          CHECK(tmp[i] == model[(mhead + n + i) % 64]);
        break;
      default: /* drop */
        got = zring_drop(&r, n);
        CHECK(got == (n < mcount ? n : mcount));
        mhead = (mhead + got) % 64;
        mcount -= got;
        break;
      }
      CHECK(zring_len(&r) == mcount);
      CHECK(zring_avail(&r) == cap - mcount);
    }
  }
}

static void test_large_drop_counter_arithmetic(void) {
  /* Counter-only synthetic state: drop never reads or writes storage.
   * This does not qualify a physically backed SIZE_MAX-capacity ring. */
  unsigned char unused = 0;
  zring r = {&unused, SIZE_MAX, SIZE_MAX - 2u, 3};
  CHECK(zring_drop(&r, 3) == 3 && r.head == 1 && r.count == 0);
  r.head = SIZE_MAX - 1u;
  r.count = SIZE_MAX;
  CHECK(zring_drop(&r, SIZE_MAX) == SIZE_MAX &&
        r.head == SIZE_MAX - 1u && r.count == 0);
}

static void test_cli(void);

int main(void) {
  test_cli();
  test_large_drop_counter_arithmetic();
  test_basic();
  test_wrap();
  test_bulk();
  test_peek_drop();
  test_err_null();
  test_fuzz();
  if (g_fail) {
    fprintf(stderr, "test_zring: FAILURES\n");
    return 1;
  }
  printf("test_zring: all groups passed (basic wrap bulk peek err null fuzz)\n");
  return 0;
}

static FILE *cli_source, *cli_sink, *cli_errors;
static size_t cli_flushes;
static FILE *real_stdin(void) { return stdin; }
static FILE *real_stdout(void) { return stdout; }
static FILE *real_stderr(void) { return stderr; }
[[maybe_unused]] static int cli_flush(FILE *stream) {
  if (stream == cli_sink) cli_flushes++;
  return fflush(stream);
}
#undef stdin
#undef stdout
#undef stderr
#define stdin cli_source
#define stdout cli_sink
#define stderr cli_errors
#define fflush cli_flush
#define main embedded_cli_main
#include "../app/main.c"
#undef main
#undef fflush
#undef stdin
#undef stdout
#undef stderr
#define stdin real_stdin()
#define stdout real_stdout()
#define stderr real_stderr()

static FILE *required_stream(FILE *stream) {
  if (!stream) { fprintf(stderr, "zring CLI fixture: stream setup failed\n"); exit(2); }
  return stream;
}
static FILE *input_bytes(const unsigned char *bytes, size_t n) {
  FILE *source = required_stream(tmpfile());
  if (fwrite(bytes, 1, n, source) != n || fflush(source) != 0) exit(2);
  rewind(source);
  return source;
}
static int cli_invoke(FILE *source, FILE *sink, FILE *errors, const char *cap) {
  cli_source = source;
  cli_sink = sink;
  cli_errors = errors;
  cli_flushes = 0;
  char *args[] = {"zring", (char *)cap, NULL};
  int rc = embedded_cli_main(cap ? 2 : 1, args);
  cli_source = stdin;
  cli_sink = stdout;
  cli_errors = stderr;
  return rc;
}
static void check_errors(FILE *stream, const char *want, bool success) {
  char text[256];
  rewind(stream);
  size_t n = fread(text, 1, sizeof text - 1, stream);
  CHECK(!ferror(stream));
  text[n] = '\0';
  CHECK(strstr(text, want) != NULL);
  CHECK((strstr(text, "ok:") != NULL) == success);
}
static void cli_binary(const char *cap) {
  unsigned char bytes[8193], got[8194];
  for (size_t i = 0; i < sizeof bytes; i++) bytes[i] = (unsigned char)i;
  FILE *source = input_bytes(bytes, sizeof bytes);
  FILE *sink = required_stream(tmpfile()), *errors = required_stream(tmpfile());
  CHECK(cli_invoke(source, sink, errors, cap) == 0);
  rewind(sink);
  size_t n = fread(got, 1, sizeof got, sink);
  CHECK(n == sizeof bytes && !memcmp(got, bytes, sizeof bytes) && !ferror(sink));
  check_errors(errors, "ok: 8193 bytes pumped", true);
  CHECK(fclose(source) == 0 && fclose(sink) == 0 && fclose(errors) == 0);
}
static void cli_failed_output(bool buffered) {
#ifdef _WIN32
  const char *null_path = "NUL";
#else
  const char *null_path = "/dev/null";
#endif
  FILE *source = input_bytes((const unsigned char *)"abc", 3);
  FILE *sink = required_stream(fopen(buffered ? "/dev/full" : null_path, buffered ? "w" : "r"));
  FILE *errors = required_stream(tmpfile());
  char buffer[4096];
  if (buffered && setvbuf(sink, buffer, _IOFBF, sizeof buffer) != 0) exit(2);
  CHECK(cli_invoke(source, sink, errors, "16") == 1);
  check_errors(errors, "write error", false);
  CHECK(ferror(sink));
  CHECK(fclose(source) == 0 && fclose(errors) == 0);
  (void)fclose(sink);
}
static void cli_unused_output(const char *cap, int status, const char *message) {
#ifdef _WIN32
  FILE *sink = required_stream(fopen("NUL", "r"));
#else
  FILE *sink = required_stream(fopen("/dev/null", "r"));
#endif
  FILE *source = input_bytes((const unsigned char *)"", 0);
  FILE *errors = required_stream(tmpfile());
  CHECK(cli_invoke(source, sink, errors, cap) == status);
  CHECK(cli_flushes == 0 && !ferror(sink));
  check_errors(errors, message, status == 0);
  CHECK(fclose(source) == 0 && fclose(sink) == 0 && fclose(errors) == 0);
}
static void cli_failed_input(void) {
#ifdef _WIN32
  FILE *source = required_stream(fopen("NUL", "w"));
#else
  FILE *source = required_stream(fopen("/dev/null", "w"));
#endif
  FILE *sink = required_stream(tmpfile()), *errors = required_stream(tmpfile());
  CHECK(cli_invoke(source, sink, errors, "16") == 1);
  CHECK(cli_flushes == 0 && ftell(sink) == 0);
  check_errors(errors, "error reading stdin", false);
  CHECK(fclose(source) == 0 && fclose(sink) == 0 && fclose(errors) == 0);
}
static void test_cli(void) {
  cli_binary("1");
  cli_binary("16");
  cli_binary("65536");
  cli_failed_output(false);
#ifdef __linux__
  cli_failed_output(true);
#endif
  cli_unused_output(NULL, 0, "ok: 0 bytes pumped");
  cli_unused_output("0", 2, "bad capacity");
  cli_failed_input();
}
