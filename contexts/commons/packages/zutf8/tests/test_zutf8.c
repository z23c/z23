/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: zutf8 test suite.  Exits nonzero on the first failure.
 * Byte-level known-answer tests follow RFC 3629 and the Unicode
 * "well-formed UTF-8 byte sequences" table (boundary values, overlong
 * forms, surrogates, and the U+10FFFF ceiling). */
#include "zutf8/zutf8.h"

#include <stdio.h>
#include <stdarg.h>
#include <string.h>

/* Exercise the shipped CLI with owned ISO C streams, without redirecting
 * the test runner's standard streams. tmpfile removes only its own fixture. */
static FILE *cli_input, *cli_output, *cli_error;
enum { CLI_NO_FAULT, CLI_WRITE_FAULT, CLI_FLUSH_FAULT, CLI_CLOSE_FAULT };
static int cli_fault;
static bool cli_write_failed;
static int cli_printf(const char *format, ...) {
  if (cli_fault == CLI_WRITE_FAULT) {
    cli_write_failed = true;
    return -1;
  }
  va_list args;
  va_start(args, format);
  int result = vfprintf(cli_output, format, args);
  va_end(args);
  return result;
}
static int cli_fclose(FILE *stream) {
  bool fail = stream == cli_output && cli_fault == CLI_CLOSE_FAULT;
  if (stream == cli_output)
    cli_output = NULL;
  if (stream == cli_error)
    cli_error = NULL;
  int result = fclose(stream);
  return fail ? EOF : result;
}
static int cli_ferror(FILE *stream) {
  return (stream == cli_output && cli_write_failed) || ferror(stream);
}
static int cli_fflush(FILE *stream) {
  if (stream == cli_output && cli_fault == CLI_FLUSH_FAULT)
    return EOF;
  return fflush(stream);
}
#define ZUTF8_CLI_STDIO 1
#define ZUTF8_CLI_STDIN cli_input
#define ZUTF8_CLI_STDOUT cli_output
#define ZUTF8_CLI_STDERR cli_error
#define ZUTF8_CLI_PRINTF cli_printf
#define ZUTF8_CLI_FCLOSE cli_fclose
#define ZUTF8_CLI_FERROR cli_ferror
#define ZUTF8_CLI_FFLUSH cli_fflush
#define main zutf8_cli_main
#include "../app/main.c"
#undef main
#undef ZUTF8_CLI_STDIO
#undef ZUTF8_CLI_STDIN
#undef ZUTF8_CLI_STDOUT
#undef ZUTF8_CLI_STDERR
#undef ZUTF8_CLI_PRINTF
#undef ZUTF8_CLI_FCLOSE
#undef ZUTF8_CLI_FERROR
#undef ZUTF8_CLI_FFLUSH
/* CHECK diagnostics keep using the actual runner stream. */

static int failures = 0;

#define CHECK(cond)                                                          \
  do {                                                                       \
    if (!(cond)) {                                                           \
      fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);        \
      failures++;                                                            \
    }                                                                        \
  } while (0)

#define VALID(s) CHECK(zutf8_validate_n((s), sizeof(s) - 1))
#define INVALID(s) CHECK(!zutf8_validate_n((s), sizeof(s) - 1))

/* Decode one sequence and expect cp/length. */
#define DEC(s, want_cp, want_len)                                            \
  do {                                                                       \
    uint32_t cp_ = 0;                                                        \
    size_t used_ = 0;                                                        \
    CHECK(zutf8_decode_n((s), sizeof(s) - 1, &cp_, &used_) == ZUTF8_OK);     \
    CHECK(cp_ == (want_cp));                                                 \
    CHECK(used_ == (want_len));                                              \
  } while (0)

#define DEC_STATUS(s, want)                                                  \
  do {                                                                       \
    uint32_t cp_;                                                            \
    size_t used_ = 99;                                                       \
    CHECK(zutf8_decode_n((s), sizeof(s) - 1, &cp_, &used_) == (want));       \
    CHECK(used_ == 0);                                                       \
  } while (0)

static void test_valid_kats(void) {
  VALID("");
  VALID("hello, world");
  VALID("\x7F"); /* U+007F: top of ASCII */
  VALID("\xC2\x80"); /* U+0080: first 2-byte */
  VALID("\xDF\xBF"); /* U+07FF: last 2-byte */
  VALID("\xC2\xA2"); /* U+00A2 CENT SIGN */
  VALID("\xE0\xA0\x80"); /* U+0800: first 3-byte */
  VALID("\xED\x9F\xBF"); /* U+D7FF: below surrogates */
  VALID("\xEE\x80\x80"); /* U+E000: above surrogates */
  VALID("\xEF\xBF\xBF"); /* U+FFFF: last 3-byte */
  VALID("\xE2\x82\xAC"); /* U+20AC EURO */
  VALID("\xF0\x90\x80\x80"); /* U+10000: first 4-byte */
  VALID("\xF0\x90\x8D\x88"); /* U+10348 GOTHIC HWAIR */
  VALID("\xF4\x8F\xBF\xBF"); /* U+10FFFF: the ceiling */
  VALID("a\xC2\xA2" "b\xE2\x82\xAC" "c\xF0\x90\x8D\x88" "d"); /* mixed */
  /* Embedded NUL is a valid code point for _n APIs. */
  CHECK(zutf8_validate_n("a\0b", 3));
  CHECK(zutf8_count_n("a\0b", 3) == 3);
}

static void test_decode_kats(void) {
  DEC("A", 0x41, 1);
  DEC("\xC2\xA2", 0xA2, 2);
  DEC("\xDF\xBF", 0x7FF, 2);
  DEC("\xE0\xA0\x80", 0x800, 3);
  DEC("\xE2\x82\xAC", 0x20AC, 3);
  DEC("\xEF\xBF\xBF", 0xFFFF, 3);
  DEC("\xF0\x90\x80\x80", 0x10000, 4);
  DEC("\xF4\x8F\xBF\xBF", 0x10FFFF, 4);
  /* Trailing bytes beyond the sequence are not consumed. */
  {
    uint32_t cp;
    size_t used;
    CHECK(zutf8_decode_n("\xC2\xA2xy", 4, &cp, &used) == ZUTF8_OK);
    CHECK(cp == 0xA2 && used == 2);
  }
}

static void test_invalid_kats(void) {
  INVALID("\x80"); /* lone continuation */
  INVALID("\xBF");
  INVALID("\xC0\x80"); /* overlong NUL */
  INVALID("\xC1\xBF"); /* overlong U+007F */
  INVALID("\xC2"); /* truncated 2-byte */
  INVALID("\xC2" "A"); /* bad continuation */
  INVALID("\xE0\x80\x80"); /* overlong 3-byte */
  INVALID("\xE0\x9F\xBF"); /* overlong boundary */
  INVALID("\xE1\x80"); /* truncated 3-byte */
  INVALID("\xE2\x82" "A"); /* bad third byte */
  INVALID("\xED\xA0\x80"); /* surrogate U+D800 */
  INVALID("\xED\xBF\xBF"); /* surrogate U+DFFF */
  INVALID("\xF0\x80\x80\x80"); /* overlong 4-byte */
  INVALID("\xF0\x8F\xBF\xBF"); /* overlong boundary */
  INVALID("\xF0\x90\x80"); /* truncated 4-byte */
  INVALID("\xF4\x90\x80\x80"); /* U+110000: above the ceiling */
  INVALID("\xF5\x80\x80\x80"); /* 0xF5 never valid */
  INVALID("\xFE");
  INVALID("\xFF");
  INVALID("ok then \xFF");
  INVALID("\xE2\x82\xAC\x80"); /* valid then stray continuation */
}

static void test_decode_status(void) {
  DEC_STATUS("\x80", ZUTF8_INVALID);
  DEC_STATUS("\xC2", ZUTF8_TRUNCATED);
  DEC_STATUS("\xE2\x82", ZUTF8_TRUNCATED);
  DEC_STATUS("\xF0\x90\x80", ZUTF8_TRUNCATED);
  {
    uint32_t cp;
    size_t used;
    CHECK(zutf8_decode_n("", 0, &cp, &used) == ZUTF8_TRUNCATED);
    CHECK(zutf8_decode_n(NULL, 5, &cp, &used) == ZUTF8_INVALID);
    CHECK(zutf8_decode_n("A", 1, NULL, &used) == ZUTF8_INVALID);
    CHECK(zutf8_decode_n("A", 1, &cp, NULL) == ZUTF8_OK);
  }
}

/* ASCII and two-byte acceptance KATs for zutf8_encode. */
static void test_encode_kats_short(void) {
  char out[4];
  CHECK(zutf8_encode(0x41, out) == 1 && out[0] == 'A');
  CHECK(zutf8_encode(0x7F, out) == 1 && (unsigned char)out[0] == 0x7F);
  CHECK(zutf8_encode(0x80, out) == 2 && (unsigned char)out[0] == 0xC2 &&
        (unsigned char)out[1] == 0x80);
  CHECK(zutf8_encode(0x7FF, out) == 2 && (unsigned char)out[0] == 0xDF &&
        (unsigned char)out[1] == 0xBF);
}

/* Three-byte acceptance KATs for zutf8_encode. */
static void test_encode_kats_three_byte(void) {
  char out[4];
  CHECK(zutf8_encode(0x800, out) == 3 && (unsigned char)out[0] == 0xE0 &&
        (unsigned char)out[1] == 0xA0 && (unsigned char)out[2] == 0x80);
  CHECK(zutf8_encode(0x20AC, out) == 3 && (unsigned char)out[0] == 0xE2 &&
        (unsigned char)out[1] == 0x82 && (unsigned char)out[2] == 0xAC);
  CHECK(zutf8_encode(0xFFFF, out) == 3 && (unsigned char)out[0] == 0xEF &&
        (unsigned char)out[1] == 0xBF && (unsigned char)out[2] == 0xBF);
}

/* Four-byte acceptance KATs for zutf8_encode. */
static void test_encode_kats_four_byte(void) {
  char out[4];
  CHECK(zutf8_encode(0x10000, out) == 4 && (unsigned char)out[0] == 0xF0 &&
        (unsigned char)out[1] == 0x90);
  CHECK(zutf8_encode(0x10FFFF, out) == 4 && (unsigned char)out[0] == 0xF4 &&
        (unsigned char)out[1] == 0x8F && (unsigned char)out[2] == 0xBF &&
        (unsigned char)out[3] == 0xBF);
}

/* Rejection KATs for zutf8_encode. */
static void test_encode_kats_rejections(void) {
  char out[4];
  /* Rejections: surrogates and above the ceiling. */
  CHECK(zutf8_encode(0xD800, out) == 0);
  CHECK(zutf8_encode(0xDFFF, out) == 0);
  CHECK(zutf8_encode(0x110000, out) == 0);
  CHECK(zutf8_encode(UINT32_MAX, out) == 0);
}

/* NULL-out sizing and embedded-NUL KATs for zutf8_encode. */
static void test_encode_kats_null_and_nul(void) {
  char out[4];
  /* NULL out measures only. */
  CHECK(zutf8_encode(0x20AC, NULL) == 3);
  /* Embedded NUL encodes as one byte. */
  CHECK(zutf8_encode(0, out) == 1 && out[0] == 0);
}

static void test_encode_kats(void) {
  test_encode_kats_short();
  test_encode_kats_three_byte();
  test_encode_kats_four_byte();
  test_encode_kats_rejections();
  test_encode_kats_null_and_nul();
}

static void test_round_trip_sweep(void) {
  /* Every Unicode scalar value must round-trip encode->decode. */
  for (uint32_t cp = 0; cp <= 0x110000u; cp++) {
    char out[4];
    size_t n = zutf8_encode(cp, out);
    if (cp >= 0xD800u && cp <= 0xDFFFu) {
      CHECK(n == 0);
      continue;
    }
    if (cp > 0x10FFFFu) {
      CHECK(n == 0);
      continue;
    }
    if (!n) {
      fprintf(stderr, "FAIL encode(U+%04X) rejected\n", cp);
      failures++;
      continue;
    }
    uint32_t back;
    size_t used;
    if (zutf8_decode_n(out, n, &back, &used) != ZUTF8_OK || back != cp ||
        used != n) {
      fprintf(stderr, "FAIL round-trip U+%04X\n", cp);
      failures++;
    }
  }
}

static void test_count(void) {
  CHECK(zutf8_count_n("", 0) == 0);
  CHECK(zutf8_count_n("abc", 3) == 3);
  CHECK(zutf8_count_n("h\xC3\xA9llo", 6) == 5); /* "héllo" */
  CHECK(zutf8_count_n("\xF0\x90\x8D\x88", 4) == 1);
  CHECK(zutf8_count_n("\xFF", 1) == SIZE_MAX);
  CHECK(zutf8_count_n(NULL, 0) == 0);
  CHECK(zutf8_count_n(NULL, 3) == SIZE_MAX);
  CHECK(!zutf8_validate(NULL));
  CHECK(zutf8_validate_n(NULL, 0));
  CHECK(zutf8_validate("plain ascii"));
  CHECK(!zutf8_validate("\xC2")); /* truncated */
}

static void close_cli_streams(void) {
  if (cli_output)
    CHECK(cli_fclose(cli_output) == 0);
  if (cli_error)
    CHECK(cli_fclose(cli_error) == 0);
  if (cli_input)
    CHECK(fclose(cli_input) == 0);
  cli_input = NULL;
}

static bool open_cli_streams(void) {
  cli_fault = CLI_NO_FAULT;
  cli_write_failed = false;
  cli_input = tmpfile();
  cli_output = tmpfile();
  cli_error = tmpfile();
  if (cli_input && cli_output && cli_error)
    return true;
  CHECK(false);
  close_cli_streams();
  return false;
}

static void test_cli_capacity_row(size_t length, int expected) {
  if (!open_cli_streams())
    return;
  static const char chunk[65536] = {0};
  size_t remaining = length;
  while (remaining) {
    size_t n = remaining < sizeof(chunk) ? remaining : sizeof(chunk);
    if (fwrite(chunk, 1, n, cli_input) != n) {
      CHECK(false);
      close_cli_streams();
      return;
    }
    remaining -= n;
  }
  CHECK(fflush(cli_input) == 0);
  rewind(cli_input);
  char name[] = "zutf8";
  char *args[] = {name, NULL};
  int status = zutf8_cli_main(1, args);
  if (status != expected) {
    fprintf(stderr, "FAIL CLI capacity %zu: expected %d, got %d\n",
            length, expected, status);
    failures++;
  }
  close_cli_streams();
}

static void test_cli_capacity(void) {
  test_cli_capacity_row(MAX_INPUT - 1, 0); /* positive control */
  test_cli_capacity_row(MAX_INPUT, 0);     /* exact-limit regression */
  test_cli_capacity_row(MAX_INPUT + 1, 2); /* refusal control */
}

static void test_cli_output_row(int fault, const char *row, int expected) {
  if (!open_cli_streams())
    return;
  CHECK(cli_fflush(cli_input) == 0); /* successful fixture setup control */
  cli_fault = fault;
  char name[] = "zutf8", count[] = "--count";
  char *args[] = {name, count, NULL};
  int status = zutf8_cli_main(2, args);
  if (status != expected) {
    fprintf(stderr, "FAIL CLI output %s: expected %d, got %d\n",
            row, expected, status);
    failures++;
  }
  /* Reclaim streams the defective CLI failed to close, without injecting
   * a second failure into the fixture cleanup. */
  cli_fault = CLI_NO_FAULT;
  cli_write_failed = false;
  close_cli_streams();
}

static void test_cli_output(void) {
  test_cli_output_row(CLI_NO_FAULT, "normal", 0); /* positive control */
  test_cli_output_row(CLI_WRITE_FAULT, "write", 2);
  test_cli_output_row(CLI_FLUSH_FAULT, "flush", 2);
  test_cli_output_row(CLI_CLOSE_FAULT, "close", 2);
}

int main(void) {
  test_valid_kats();
  test_decode_kats();
  test_invalid_kats();
  test_decode_status();
  test_encode_kats();
  test_round_trip_sweep();
  test_count();
  test_cli_capacity();
  test_cli_output();
  if (failures) {
    fprintf(stderr, "test_zutf8: %d failure(s)\n", failures);
    return 1;
  }
  puts("test_zutf8: all tests passed");
  return 0;
}
