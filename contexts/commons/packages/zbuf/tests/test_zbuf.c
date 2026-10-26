/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. */
/* Tests for zbuf — bounded growable byte buffer.
 * Groups: basic, printf, bound, sticky, null, fuzz. */
#include "zbuf/zbuf.h"
#include <stdbool.h>
#include <stdlib.h>

#include <stdint.h>
#include <stdio.h>
#include <string.h>
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

static void test_maximum(void) {
  zbuf b = {0};
  CHECK(zbuf_init(&b, SIZE_MAX) == ZBUF_ERR_ARG);
  CHECK(b.data == NULL && b.len == 0 && b.cap == 0 && b.max == 0);
  CHECK(b.err == ZBUF_OK);
  CHECK(zbuf_init(&b, SIZE_MAX - 1) == ZBUF_OK);
  CHECK(zbuf_put(&b, 'x') == ZBUF_OK);
  if (b.data == NULL) return;
  unsigned char *data = b.data;
  size_t cap = b.cap;
  CHECK(zbuf_write(&b, "x", SIZE_MAX - 1) == ZBUF_ERR_FULL);
  CHECK(zbuf_put(&b, 'y') == ZBUF_ERR_FULL);
  CHECK(b.data == data && b.cap == cap && b.len == 1);
  CHECK(b.data[0] == 'x' && b.data[1] == '\0');
  zbuf_free(&b);
}

static void test_invalid_init_preserves(void) {
  zbuf b;
  CHECK(zbuf_init(&b, 3) == ZBUF_OK);
  CHECK(zbuf_str(&b, "abc") == ZBUF_OK);
  if (b.data == NULL) return;
  CHECK(zbuf_put(&b, 'd') == ZBUF_ERR_FULL);
  zbuf saved = b;
  CHECK(zbuf_init(&b, SIZE_MAX) == ZBUF_ERR_ARG);
  CHECK(b.data == saved.data && b.len == saved.len && b.cap == saved.cap);
  CHECK(b.max == saved.max && b.err == ZBUF_ERR_FULL);
  CHECK(memcmp(saved.data, "abc", 4) == 0);
  zbuf_free(&saved);
}

static void test_zero_maximum(void) {
  zbuf b;
  CHECK(zbuf_init(&b, 0) == ZBUF_OK);
  CHECK(zbuf_write(&b, NULL, 0) == ZBUF_OK);
  CHECK(b.len == 0 && b.cap == 1 && b.data != NULL);
  CHECK(strcmp(zbuf_cstr(&b), "") == 0);
  unsigned char *data = b.data;
  CHECK(zbuf_put(&b, 'x') == ZBUF_ERR_FULL);
  CHECK(zbuf_write(&b, NULL, 0) == ZBUF_ERR_FULL);
  CHECK(b.data == data && b.len == 0 && strcmp(zbuf_cstr(&b), "") == 0);
  zbuf_clear(&b);
  CHECK(zbuf_status(&b) == ZBUF_OK);
  CHECK(zbuf_write(&b, NULL, 0) == ZBUF_OK);
  zbuf_free(&b);
}

static void test_basic(void) {
  zbuf b;
  CHECK(zbuf_init(&b, 4096) == ZBUF_OK);
  CHECK(zbuf_len(&b) == 0 && strcmp(zbuf_cstr(&b), "") == 0);
  CHECK(zbuf_str(&b, "hello") == ZBUF_OK);
  CHECK(zbuf_put(&b, ' ') == ZBUF_OK);
  CHECK(zbuf_str(&b, "world") == ZBUF_OK);
  CHECK(zbuf_len(&b) == 11 && strcmp(zbuf_cstr(&b), "hello world") == 0);
  CHECK(zbuf_write(&b, "\0x", 2) == ZBUF_OK); /* embedded NUL kept */
  CHECK(zbuf_len(&b) == 13 && b.data[11] == '\0' && b.data[12] == 'x');
  zbuf_clear(&b);
  CHECK(zbuf_len(&b) == 0 && strcmp(zbuf_cstr(&b), "") == 0);
  zbuf_free(&b);
  CHECK(zbuf_len(&b) == 0 && b.data == NULL);
}

static void test_printf(void) {
  zbuf b;
  zbuf_init(&b, 4096);
  CHECK(zbuf_printf(&b, "%d %s %.2f", 42, "x", 1.005) == ZBUF_OK);
  CHECK(strcmp(zbuf_cstr(&b), "42 x 1.00") == 0 ||
        strcmp(zbuf_cstr(&b), "42 x 1.01") == 0);
  CHECK(zbuf_printf(&b, "%c%03d", '!', 7) == ZBUF_OK);
  CHECK(strstr(zbuf_cstr(&b), "!007") != NULL);
  zbuf_free(&b);
}

static void test_bound(void) {
  zbuf b;
  zbuf_init(&b, 8);
  CHECK(zbuf_write(&b, "12345678", 8) == ZBUF_OK); /* exactly full */
  CHECK(zbuf_put(&b, '9') == ZBUF_ERR_FULL);
  CHECK(zbuf_len(&b) == 8); /* failed write changed nothing */
  zbuf_free(&b);
}

static void test_sticky(void) {
  zbuf b;
  zbuf_init(&b, 4);
  CHECK(zbuf_str(&b, "abcd") == ZBUF_OK);
  CHECK(zbuf_str(&b, "ef") == ZBUF_ERR_FULL);
  CHECK(zbuf_status(&b) == ZBUF_ERR_FULL);
  CHECK(zbuf_str(&b, "g") == ZBUF_ERR_FULL);  /* sticky */
  CHECK(zbuf_put(&b, 'g') == ZBUF_ERR_FULL);  /* sticky */
  CHECK(zbuf_len(&b) == 4 && strcmp(zbuf_cstr(&b), "abcd") == 0);
  zbuf_clear(&b);                             /* clear resets */
  CHECK(zbuf_status(&b) == ZBUF_OK);
  CHECK(zbuf_str(&b, "xy") == ZBUF_OK);
  zbuf_free(&b);
}

static void test_null(void) {
  zbuf b;
  CHECK(zbuf_init(NULL, 8) == ZBUF_ERR_ARG);
  CHECK(zbuf_put(NULL, 'x') == ZBUF_ERR_ARG);
  CHECK(zbuf_str(NULL, "x") == ZBUF_ERR_ARG);
  CHECK(zbuf_printf(NULL, "x") == ZBUF_ERR_ARG);
  CHECK(zbuf_len(NULL) == 0);
  CHECK(strcmp(zbuf_cstr(NULL), "") == 0);
  CHECK(zbuf_status(NULL) == ZBUF_ERR_ARG);
  zbuf_init(&b, 8);
  CHECK(zbuf_write(&b, NULL, 3) == ZBUF_ERR_ARG);
  CHECK(zbuf_write(&b, NULL, 0) == ZBUF_OK);
  CHECK(zbuf_str(&b, NULL) == ZBUF_ERR_ARG);
  CHECK(zbuf_status(&b) == ZBUF_OK); /* ARG is not sticky */
  zbuf_free(NULL);                   /* tolerated */
  zbuf_clear(NULL);                  /* tolerated */
  zbuf_free(&b);
}

/* ---- fuzz against a reference model ---------------------------------------- */

static uint64_t rng_state = 0xE5C1A94F0B3D7628ull;
static uint64_t rng_next(void) {
  rng_state ^= rng_state << 13;
  rng_state ^= rng_state >> 7;
  rng_state ^= rng_state << 17;
  return rng_state;
}

static void test_fuzz(void) {
  int trial;
  for (trial = 0; trial < 1500; trial++) {
    zbuf b;
    unsigned char model[512];
    size_t mlen = 0;
    size_t max = 1 + rng_next() % 512;
    int step, failed = 0;
    zbuf_init(&b, max);
    for (step = 0; step < 100; step++) {
      unsigned char tmp[32];
      size_t n = rng_next() % 32, i;
      for (i = 0; i < n; i++) tmp[i] = (unsigned char)rng_next();
      if (rng_next() % 8 == 0) { /* clear */
        zbuf_clear(&b);
        mlen = 0;
        failed = 0;
        continue;
      }
      {
        zbuf_err e = zbuf_write(&b, tmp, n);
        if (!failed && mlen + n <= max) {
          CHECK(e == ZBUF_OK);
          memcpy(model + mlen, tmp, n);
          mlen += n;
        } else {
          if (!failed) {
            CHECK(e == ZBUF_ERR_FULL);
            failed = 1;
          } else {
            CHECK(e == ZBUF_ERR_FULL); /* sticky */
          }
        }
      }
      CHECK(zbuf_len(&b) == mlen);
      CHECK(mlen == 0 || memcmp(b.data, model, mlen) == 0);
    }
    zbuf_free(&b);
  }
}

static void test_sticky_invalid_arguments(void) {
  int failed = 0;
  for (int row = 0; row < 3; row++) {
    zbuf b;
    CHECK(zbuf_init(&b, 1) == ZBUF_OK);
    CHECK(zbuf_str(&b, "x") == ZBUF_OK);
    CHECK(zbuf_put(&b, 'y') == ZBUF_ERR_FULL);
    zbuf_err e;
    switch (row) {
    case 0: e = zbuf_write(&b, NULL, 1); break;
    case 1: e = zbuf_str(&b, NULL); break;
    default: e = zbuf_printf(&b, NULL); break;
    }
    if (e != ZBUF_ERR_FULL || zbuf_len(&b) != 1 ||
        strcmp(zbuf_cstr(&b), "x") != 0) {
      fprintf(stderr, "FAIL sticky_invalid row=%d err=%d\n", row, e);
      failed = 1;
    }
    zbuf_free(&b);
  }
  CHECK(!failed);
}

static void test_format_own_string(void) {
  const size_t sizes[] = {32, 300};
  for (size_t row = 0; row < sizeof sizes / sizeof sizes[0]; row++) {
    zbuf b;
    char seed[300];
    size_t n = sizes[row] - 1;
    memset(seed, row ? 'b' : 'c', n);
    seed[n] = 0;
    CHECK(zbuf_init(&b, 1024) == ZBUF_OK);
    CHECK(zbuf_str(&b, seed) == ZBUF_OK);
    CHECK(b.data != NULL && b.cap >= n + 2);
    if (!b.data || b.cap < n + 2) { zbuf_free(&b); continue; }
    zbuf_clear(&b);
    CHECK(zbuf_printf(&b, "X%s", (const char *)b.data) == ZBUF_OK);
    CHECK(b.len == n + 1 && b.cap >= n + 2);
    if (b.len == n + 1 && b.cap >= n + 2) {
      CHECK(b.data[0] == 'X' && memcmp(b.data + 1, seed, n) == 0);
      CHECK(b.data[n + 1] == 0);
    }
    zbuf_free(&b);
  }
}

static void test_refused_borrowed_format(void) {
  zbuf b;
  CHECK(zbuf_init(&b, 15) == ZBUF_OK);
  CHECK(zbuf_str(&b, "123456789012345") == ZBUF_OK);
  if (!b.data || b.len != 15 || b.cap < 16) { zbuf_free(&b); return; }
  unsigned char *data = b.data;
  size_t cap = b.cap;
  CHECK(zbuf_printf(&b, "%s", (const char *)b.data) == ZBUF_ERR_FULL);
  CHECK(b.data == data && b.cap == cap && b.len == 15);
  if (b.data == data && b.cap >= 16 && b.len == 15)
    CHECK(memcmp(b.data, "123456789012345", 16) == 0);
  zbuf_free(&b);
}
/* Compile the real implementation under test-local names and an allocator
 * that uses package-owned storage and retains the poisoned old block. */
static size_t moving_bytes;
static zbuf moving_live, moving_retired, format_storage;
static unsigned moving_relocations;
static bool fail_fixture_realloc;
static bool fail_fixture_malloc;
static bool fail_fixture_render;

/* Use the package's ordinary allocation path; each fixture request is bounded. */
static bool fixture_storage(zbuf *out, size_t bytes) {
  static const unsigned char zeroes[4096] = {0};
  if (bytes == 0 || bytes > sizeof zeroes) return false;
  if (zbuf_init(out, bytes - 1) != ZBUF_OK) return false;
  if (zbuf_write(out, zeroes, bytes - 1) != ZBUF_OK) {
    zbuf_free(out);
    return false;
  }
  return out->data != NULL && out->cap >= bytes;
}

static void *moving_realloc(void *ptr, size_t bytes) {
  if (fail_fixture_realloc) return NULL;
  if (ptr != moving_live.data) { CHECK(false); return NULL; }
  zbuf next = {0};
  if (!fixture_storage(&next, bytes)) return NULL;
  if (ptr) {
    CHECK(next.data != ptr);
    memcpy(next.data, ptr, moving_bytes < bytes ? moving_bytes : bytes);
    zbuf_free(&moving_retired);
    moving_retired = moving_live;
    /* Keep the old block readable and terminated, but with different bytes. */
    memset(moving_retired.data, 0xA5, moving_bytes - 1);
    moving_retired.data[moving_bytes - 1] = 0;
    moving_relocations++;
  }
  moving_live = next;
  moving_bytes = bytes;
  return moving_live.data;
}

static void *fixture_malloc(size_t bytes) {
  if (fail_fixture_malloc) return NULL;
  if (format_storage.data) { CHECK(false); return NULL; }
  return fixture_storage(&format_storage, bytes) ? format_storage.data : NULL;
}

static void fixture_release(void *ptr) {
  if (!ptr) return;
  if (ptr == moving_live.data) {
    zbuf_free(&moving_live);
    moving_bytes = 0;
  } else if (ptr == format_storage.data) {
    zbuf_free(&format_storage);
  } else {
    CHECK(false);
  }
}

static int fixture_vsnprintf(char *out, size_t cap, const char *fmt, va_list ap) {
  int written = vsnprintf(out, cap, fmt, ap);
  if (out && fail_fixture_render) return -1;
  return written;
}

#define zbuf_err_str fixture_zbuf_err_str
#define zbuf_init fixture_zbuf_init
#define zbuf_free fixture_zbuf_free
#define zbuf_clear fixture_zbuf_clear
#define zbuf_write fixture_zbuf_write
#define zbuf_put fixture_zbuf_put
#define zbuf_str fixture_zbuf_str
#define zbuf_vprintf fixture_zbuf_vprintf
#define zbuf_printf fixture_zbuf_printf
#define zbuf_cstr fixture_zbuf_cstr
#define zbuf_len fixture_zbuf_len
#define zbuf_status fixture_zbuf_status
#define realloc moving_realloc
#define malloc fixture_malloc
#define free fixture_release
#define vsnprintf fixture_vsnprintf
#include "../src/zbuf.c"
#undef vsnprintf
#undef free
#undef malloc
#undef realloc
#undef zbuf_err_str
#undef zbuf_init
#undef zbuf_free
#undef zbuf_clear
#undef zbuf_write
#undef zbuf_put
#undef zbuf_str
#undef zbuf_vprintf
#undef zbuf_printf
#undef zbuf_cstr
#undef zbuf_len
#undef zbuf_status

static void test_forced_slice_move(void) {
  zbuf b;
  unsigned char seed[63];
  for (size_t i = 0; i < sizeof seed; i++) seed[i] = (unsigned char)('a' + i % 26);
  moving_relocations = 0;
  CHECK(fixture_zbuf_init(&b, 256) == ZBUF_OK);
  CHECK(fixture_zbuf_write(&b, seed, sizeof seed) == ZBUF_OK);
  if (!b.data) return;
  CHECK(fixture_zbuf_write(&b, b.data + 13, 50) == ZBUF_OK);
  CHECK(moving_relocations == 1);
  if (b.len != 113 || b.cap < 114) {
    CHECK(b.len == 113 && b.cap >= 114);
    fixture_zbuf_free(&b);
    return;
  }
  CHECK(b.len == 113 && memcmp(b.data, seed, 63) == 0);
  CHECK(memcmp(b.data + 63, seed + 13, 50) == 0 && b.data[113] == 0);
  fixture_zbuf_free(&b);
}

static void test_forced_format_move(void) {
  zbuf b;
  char seed[512];
  memset(seed, 'a', sizeof seed - 1);
  seed[sizeof seed - 1] = 0;
  moving_relocations = 0;
  CHECK(fixture_zbuf_init(&b, 2048) == ZBUF_OK);
  CHECK(fixture_zbuf_str(&b, seed) == ZBUF_OK);
  if (!b.data) return;
  CHECK(fixture_zbuf_printf(&b, "%s", fixture_zbuf_cstr(&b)) == ZBUF_OK);
  CHECK(moving_relocations == 1);
  if (b.len != 1022 || b.cap < 1023) {
    CHECK(b.len == 1022 && b.cap >= 1023);
    fixture_zbuf_free(&b);
    return;
  }
  CHECK(b.len == 1022 && memcmp(b.data, seed, 511) == 0);
  CHECK(memcmp(b.data + 511, seed, 511) == 0 && b.data[1022] == 0);
  fixture_zbuf_free(&b);
}

static void test_borrowed_format_move(void) {
  zbuf b;
  char expected[65];
  CHECK(snprintf(expected, sizeof expected, "%064d", 7) == 64);
  moving_relocations = 0;
  CHECK(fixture_zbuf_init(&b, 256) == ZBUF_OK);
  CHECK(fixture_zbuf_str(&b, "%064d") == ZBUF_OK);
  if (!b.data) return;
  CHECK(fixture_zbuf_printf(&b, (const char *)b.data, 7) == ZBUF_OK);
  CHECK(moving_relocations == 1);
  if (b.len != 69 || b.cap < 70) {
    CHECK(b.len == 69 && b.cap >= 70);
    fixture_zbuf_free(&b);
    return;
  }
  CHECK(b.len == 69 && memcmp(b.data, "%064d", 5) == 0);
  CHECK(memcmp(b.data + 5, expected, sizeof expected) == 0);
  fixture_zbuf_free(&b);
}

static void test_format_refusal_state(void) {
  char seed[512];
  memset(seed, 'a', sizeof seed - 1);
  seed[sizeof seed - 1] = 0;
  for (unsigned row = 0; row < 3; row++) {
    zbuf b;
    CHECK(fixture_zbuf_init(&b, 2048) == ZBUF_OK);
    CHECK(fixture_zbuf_str(&b, seed) == ZBUF_OK);
    if (!b.data) return;
    zbuf before = b;
    moving_relocations = 0;
    fail_fixture_render = row == 0;
    fail_fixture_malloc = row == 1;
    fail_fixture_realloc = row == 2;
    zbuf_err expected = row == 0 ? ZBUF_ERR_FULL : ZBUF_ERR_OOM;
    CHECK(fixture_zbuf_printf(&b, "%s", fixture_zbuf_cstr(&b)) == expected);
    fail_fixture_render = false;
    fail_fixture_malloc = false;
    fail_fixture_realloc = false;
    CHECK(b.data == before.data && b.cap == before.cap && b.len == before.len);
    CHECK(b.max == before.max && b.err == expected && moving_relocations == 0);
    CHECK(memcmp(b.data, seed, sizeof seed) == 0);
    CHECK(fixture_zbuf_put(&b, 'x') == expected);
    fixture_zbuf_free(&b);
  }
}

static void test_cli(void);

int main(void) {
  test_cli();
  test_forced_format_move();
  test_borrowed_format_move();
  test_format_refusal_state();
  test_forced_slice_move();
  zbuf_free(&moving_retired);
  test_format_own_string();
  test_refused_borrowed_format();
    test_sticky_invalid_arguments();

  test_maximum();
  test_invalid_init_preserves();
  test_zero_maximum();
  test_basic();
  test_printf();
  test_bound();
  test_sticky();
  test_null();
  test_fuzz();
  if (g_fail) {
    fprintf(stderr, "test_zbuf: FAILURES\n");
    return 1;
  }
  printf("test_zbuf: all groups passed (basic printf bound sticky null fuzz borrowed_format refusal)\n");
  return 0;
}

static FILE *cli_source, *cli_sink, *cli_errors;
static size_t cli_flushes, cli_frees;
static bool cli_read_fault, cli_init_fault, cli_stale_errno;
static FILE *real_stdin(void) { return stdin; }
static FILE *real_stdout(void) { return stdout; }
static FILE *real_stderr(void) { return stderr; }
static void cli_free(zbuf *b) {
  zbuf_free(b);
  CHECK(b->data == NULL && b->len == 0 && b->cap == 0 && b->err == ZBUF_OK);
  cli_frees++;
}
static zbuf_err cli_init(zbuf *b, size_t max) {
  if (cli_init_fault) *b = (zbuf){0};
  return zbuf_init(b, cli_init_fault ? SIZE_MAX : max);
}
static int cli_error(FILE *stream) {
  return (stream == cli_source && cli_read_fault) || ferror(stream);
}
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
#define ferror cli_error
#define zbuf_free cli_free
#define zbuf_init cli_init
#define main embedded_cli_main
#include "../app/main.c"
#undef main
#undef zbuf_init
#undef zbuf_free
#undef ferror
#undef fflush
#undef stdin
#undef stdout
#undef stderr
#define stdin real_stdin()
#define stdout real_stdout()
#define stderr real_stderr()

static FILE *require_stream(FILE *stream) {
  if (!stream) { fprintf(stderr, "zbuf CLI fixture setup failed\n"); exit(2); }
  return stream;
}
static FILE *cli_input(const char *text) {
  FILE *source = require_stream(tmpfile());
  if (fputs(text, source) < 0 || fflush(source) != 0) exit(2);
  rewind(source);
  return source;
}
static int cli_invoke(FILE *source, FILE *sink, FILE *errors, const char *max) {
  char *args[] = {"zbuf", (char *)max, NULL};
  cli_source = source;
  cli_sink = sink;
  cli_errors = errors;
  cli_flushes = cli_frees = 0;
  if (cli_stale_errno) errno = ERANGE;
  int rc = embedded_cli_main(max ? 2 : 1, args);
  cli_source = stdin;
  cli_sink = stdout;
  cli_errors = stderr;
  return rc;
}
static void check_bytes(FILE *stream, const char *want) {
  char bytes[256];
  rewind(stream);
  size_t n = fread(bytes, 1, sizeof bytes, stream);
  CHECK(!ferror(stream) && n == strlen(want) && !memcmp(bytes, want, n));
}
static void check_message(FILE *stream, const char *want, bool success) {
  char bytes[256];
  rewind(stream);
  size_t n = fread(bytes, 1, sizeof bytes - 1, stream);
  bytes[n] = '\0';
  CHECK(!ferror(stream) && strstr(bytes, want) != NULL);
  CHECK((strstr(bytes, "ok:") != NULL) == success);
}
static void cli_case(const char *input, const char *max, int status,
                      const char *want, const char *message) {
  FILE *source = cli_input(input), *sink = require_stream(tmpfile());
  FILE *errors = require_stream(tmpfile());
  CHECK(cli_invoke(source, sink, errors, max) == status);
  check_bytes(sink, want);
  check_message(errors, message, status == 0);
  if (!*want) CHECK(cli_flushes == 0);
  CHECK(cli_frees == (status == 2 ? 0u : 1u));
  if (status == 2) CHECK(ftell(source) == 0);
  CHECK(fclose(source) == 0 && fclose(sink) == 0 && fclose(errors) == 0);
}
static void cli_maximum(void) {
  const char *bad[] = {"", " ", "-1", "1junk", "1 ",
    "999999999999999999999999999999999", "-999999999999999999999999999999999"};
  for (size_t i = 0; i < sizeof bad / sizeof bad[0]; i++)
    cli_case("a\n", bad[i], 2, "", "bad max");
  char maximum[64];
  snprintf(maximum, sizeof maximum, "%ld", LONG_MAX);
  cli_case("a\n", maximum, 0, "     1\ta\n", "ok: 1 lines, 9 bytes");
  cli_case("a\n", "9", 0, "     1\ta\n", "ok:");
  cli_case("a\n", "8", 1, "", "buffer bound reached");
  cli_case("a\n", "10", 0, "     1\ta\n", "ok:");
  cli_stale_errno = true;
  cli_case("a\n", " \t+9", 0, "     1\ta\n", "ok:");
  cli_stale_errno = false;
  cli_case("", "-0", 0, "", "ok: 0 lines, 0 bytes");
  cli_case("", "0", 0, "", "ok: 0 lines, 0 bytes");
}
static void cli_failed_sink(bool buffered) {
#ifdef _WIN32
  const char *null_path = "NUL";
#else
  const char *null_path = "/dev/null";
#endif
  FILE *source = cli_input("a\n"), *errors = require_stream(tmpfile());
  FILE *sink = require_stream(fopen(buffered ? "/dev/full" : null_path, buffered ? "w" : "r"));
  char buffer[4096];
  if (buffered && setvbuf(sink, buffer, _IOFBF, sizeof buffer) != 0) exit(2);
  CHECK(cli_invoke(source, sink, errors, NULL) == 1);
  CHECK(cli_frees == 1 && ferror(sink));
  check_message(errors, "write error", false);
  CHECK(fclose(source) == 0 && fclose(errors) == 0);
  (void)fclose(sink);
}
static void cli_failures(void) {
  cli_read_fault = true;
  cli_case("a\n", NULL, 1, "", "error reading stdin");
  cli_read_fault = false;
  cli_init_fault = true;
  cli_case("a\n", NULL, 2, "", "initialization failed");
  cli_init_fault = false;
#ifdef _WIN32
  FILE *source = require_stream(fopen("NUL", "w"));
#else
  FILE *source = require_stream(fopen("/dev/null", "w"));
#endif
  FILE *sink = require_stream(tmpfile()), *errors = require_stream(tmpfile());
  CHECK(cli_invoke(source, sink, errors, NULL) == 1);
  CHECK(cli_frees == 1 && cli_flushes == 0 && ftell(sink) == 0);
  check_message(errors, "error reading stdin", false);
  CHECK(fclose(source) == 0 && fclose(sink) == 0 && fclose(errors) == 0);
}
static void test_cli(void) {
  cli_maximum();
  cli_case("a\nb\n", NULL, 0, "     1\ta\n     2\tb\n", "ok: 2 lines, 18 bytes");
  cli_failed_sink(false);
#ifdef __linux__
  cli_failed_sink(true);
#endif
  cli_failures();
}
