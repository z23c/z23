/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: zbase64 test suite.  Exits nonzero on the first failure. */
#include "zbase64/zbase64.h"

#include <stdio.h>
#include <string.h>

#define main b64_cli_main
#include "../app/main.c"
#undef main

static int failures = 0;

#define CHECK(cond)                                                          \
  do {                                                                       \
    if (!(cond)) {                                                           \
      fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);        \
      failures++;                                                            \
    }                                                                        \
  } while (0)

static void test_rfc4648_vectors(void) {
  static const struct {
    const char *plain;
    const char *coded;
  } vectors[] = {
      {"",       ""},
      {"f",      "Zg=="},
      {"fo",     "Zm8="},
      {"foo",    "Zm9v"},
      {"foob",   "Zm9vYg=="},
      {"fooba",  "Zm9vYmE="},
      {"foobar", "Zm9vYmFy"},
  };
  char enc[64];
  uint8_t dec[64];
  size_t dec_len = 0;
  for (size_t i = 0; i < sizeof(vectors) / sizeof(vectors[0]); i++) {
    size_t plen = strlen(vectors[i].plain);
    CHECK(zbase64_encode_len(plen) == strlen(vectors[i].coded));
    CHECK(zbase64_encode((const uint8_t *)vectors[i].plain, plen, enc,
                         sizeof(enc)));
    CHECK(strcmp(enc, vectors[i].coded) == 0);
    CHECK(zbase64_decode(vectors[i].coded, strlen(vectors[i].coded), dec,
                         sizeof(dec), &dec_len));
    CHECK(dec_len == plen);
    CHECK(memcmp(dec, vectors[i].plain, plen) == 0);
  }
}

static void test_urlsafe(void) {
  /* 0xfb 0xff 0xfe maps to '+/..' in the standard alphabet and '-_..' in
   * the URL-safe one. */
  static const uint8_t raw[] = {0xfb, 0xff, 0xfe, 0x01};
  char enc[16];
  CHECK(zbase64_encode(raw, sizeof(raw), enc, sizeof(enc)));
  CHECK(strcmp(enc, "+//+AQ==") == 0);
  CHECK(zbase64url_encode(raw, sizeof(raw), enc, sizeof(enc)));
  CHECK(strcmp(enc, "-__-AQ==") == 0);

  uint8_t dec[8];
  size_t n = 0;
  CHECK(zbase64url_decode("-__-AQ==", 8, dec, sizeof(dec), &n));
  CHECK(n == sizeof(raw) && memcmp(dec, raw, n) == 0);
  CHECK(zbase64url_decode("-__-AQ", 6, dec, sizeof(dec), &n)); /* no pad */
  CHECK(n == sizeof(raw) && memcmp(dec, raw, n) == 0);

  /* Alphabets never mix. */
  CHECK(!zbase64_decode("-__-AQ==", 8, dec, sizeof(dec), &n));
  CHECK(!zbase64url_decode("+//+AQ==", 8, dec, sizeof(dec), &n));
}

static void test_strict_rejections(void) {
  uint8_t dec[16];
  size_t n = 0;
  CHECK(!zbase64_decode("Zg=", 3, dec, sizeof(dec), &n));     /* short */
  CHECK(!zbase64_decode("Zg===", 5, dec, sizeof(dec), &n));   /* long */
  CHECK(!zbase64_decode("Z===", 4, dec, sizeof(dec), &n));    /* pad>2 */
  CHECK(!zbase64_decode("Zm 9v", 5, dec, sizeof(dec), &n));   /* space */
  CHECK(!zbase64_decode("Zm9v\n", 5, dec, sizeof(dec), &n));  /* newline */
  CHECK(!zbase64_decode("Zh==", 4, dec, sizeof(dec), &n));    /* pad bits
                                                                 nonzero */
  CHECK(!zbase64_decode("Zm9=", 4, dec, sizeof(dec), &n));    /* leftover
                                                                 bits */
  CHECK(!zbase64url_decode("A", 1, dec, sizeof(dec), &n));    /* 1 sextet */
  CHECK(!zbase64url_decode("AAA=A", 5, dec, sizeof(dec), &n));/* mid pad */
  CHECK(!zbase64_decode(nullptr, 4, dec, sizeof(dec), &n));
  CHECK(!zbase64_decode("Zm9v", 4, nullptr, 16, &n));
  /* Output cap too small. */
  CHECK(!zbase64_decode("Zm9v", 4, dec, 2, &n));
  /* A rejected decode reports no partial length. */
  CHECK(n == 0);
}

static void test_roundtrip_all_bytes(void) {
  uint8_t raw[256];
  for (size_t i = 0; i < sizeof(raw); i++)
    raw[i] = (uint8_t)i;
  char enc[zbase64_encode_len(sizeof(raw)) + 1];
  uint8_t dec[sizeof(raw)];
  size_t n = 0;
  CHECK(zbase64_encode(raw, sizeof(raw), enc, sizeof(enc)));
  CHECK(zbase64_decode(enc, strlen(enc), dec, sizeof(dec), &n));
  CHECK(n == sizeof(raw) && memcmp(dec, raw, n) == 0);
  CHECK(zbase64url_encode(raw, sizeof(raw), enc, sizeof(enc)));
  CHECK(zbase64url_decode(enc, strlen(enc), dec, sizeof(dec), &n));
  CHECK(n == sizeof(raw) && memcmp(dec, raw, n) == 0);
}

static void test_size_overflow(void) {
  const size_t groups = SIZE_MAX / 4u;
  const size_t largest_input = groups * 3u;
  const size_t largest_output = groups * 4u;
  CHECK(zbase64_encode_len(SIZE_MAX) == SIZE_MAX);
  CHECK(zbase64_encode_len(largest_input + 1u) == SIZE_MAX);
  CHECK(zbase64_encode_len(largest_input) == largest_output);
  CHECK(zbase64_encode_len(largest_input - 1u) == largest_output);
  CHECK(zbase64_encode_len(largest_input - 2u) == largest_output);
  CHECK(largest_output < SIZE_MAX); /* There is room to represent the NUL. */

  /* Baseline size-query assertions fail without touching a purported huge
   * span. Exercise rejection only once the size query has the new contract. */
  if (zbase64_encode_len(SIZE_MAX) != SIZE_MAX ||
      zbase64_encode_len(largest_input + 1u) != SIZE_MAX)
    return;
  static const uint8_t byte = 0;
  const size_t lengths[] = {largest_input + 1u, SIZE_MAX - 1u, SIZE_MAX};
  bool (*const encoders[])(const uint8_t *, size_t, char *, size_t) = {
      zbase64_encode, zbase64url_encode};
  char out[9], saved[9];
  memset(saved, '!', sizeof(saved));
  for (size_t e = 0; e < 2; e++) {
    for (size_t i = 0; i < sizeof(lengths) / sizeof(lengths[0]); i++) {
      memcpy(out, saved, sizeof(out));
      CHECK(!encoders[e](&byte, lengths[i], out, sizeof(out)));
      CHECK(memcmp(out, saved, sizeof(out)) == 0);
      CHECK(!encoders[e](&byte, lengths[i], out, SIZE_MAX));
      CHECK(memcmp(out, saved, sizeof(out)) == 0);
    }
  }
}

static void test_encode_capacity_canaries(void) {
  static const uint8_t four[] = {1, 2, 3, 4};
  bool (*const encoders[])(const uint8_t *, size_t, char *, size_t) = {
      zbase64_encode, zbase64url_encode};
  char out[9], saved[9];
  memset(saved, '!', sizeof(saved));
  for (size_t e = 0; e < 2; e++) {
    memcpy(out, saved, sizeof(out));
    CHECK(!encoders[e](four, sizeof(four), out, sizeof(out) - 1u));
    CHECK(memcmp(out, saved, sizeof(out)) == 0);
    CHECK(encoders[e](four, sizeof(four), out, sizeof(out)));
    CHECK(memcmp(out, "AQIDBA==", sizeof(out)) == 0);
  }
}

static void test_size_arithmetic(void) {
  CHECK(zbase64_encode_len(0) == 0);
  CHECK(zbase64_encode_len(1) == 4);
  CHECK(zbase64_encode_len(2) == 4);
  CHECK(zbase64_encode_len(3) == 4);
  CHECK(zbase64_encode_len(4) == 8);
  /* Encode into the exact cap (plus NUL) and one byte short. */
  char enc[9];
  static const uint8_t four[] = {1, 2, 3, 4};
  CHECK(zbase64_encode(four, 4, enc, 9));
  CHECK(!zbase64_encode(four, 4, enc, 8));
  CHECK(!zbase64_encode(nullptr, 4, enc, sizeof(enc)));
  CHECK(zbase64_encode(nullptr, 0, enc, sizeof(enc))); /* empty ok */
  CHECK(enc[0] == '\0');
}

static void test_rejected_output_canaries(void) {
  static const struct { const char *in; size_t cap; bool url; } rows[] = {
    {"Zh==", 8, false}, {"Zm9=", 8, false}, {"Zm?=", 8, false},
    {"Zm9v", 2, false}, {"Zh", 8, true}, {"Zm?", 8, true},
    {"Zm9v", 2, true},
  };
  for (size_t i = 0; i < sizeof rows / sizeof rows[0]; i++) {
    uint8_t out[8], saved[8];
    memset(saved, '!', sizeof saved);
    memcpy(out, saved, sizeof out);
    size_t n = 123;
    bool ok = rows[i].url
      ? zbase64url_decode(rows[i].in, strlen(rows[i].in), out, rows[i].cap, &n)
      : zbase64_decode(rows[i].in, strlen(rows[i].in), out, rows[i].cap, &n);
    CHECK(!ok && n == 0 && memcmp(out, saved, sizeof out) == 0);
  }
}

static int cli_case(char *flag, const void *data, size_t size, int status,
                    const void *expected, size_t expected_size) {
  FILE *source = tmpfile(), *output = tmpfile();
  int failed = 1;
  if (!source || !output) goto cleanup;
  if (fwrite(data, 1, size, source) != size || fflush(source) != 0) goto cleanup;
  rewind(source);
  char *argv[] = {"b64", flag, NULL};
  if (cli_run(flag ? 2 : 1, argv, source, output) != status) goto cleanup;
  rewind(output);
  unsigned char bytes[256];
  size_t n = fread(bytes, 1, sizeof bytes, output);
  if (ferror(output) || n != expected_size) goto cleanup;
  if (n && memcmp(bytes, expected, n) != 0) goto cleanup;
  failed = 0;
cleanup:
  if (source && fclose(source) != 0) failed = 1;
  if (output && fclose(output) != 0) failed = 1;
  return failed;
}

static void test_cli_vectors(void) {
  const unsigned char binary[] = {255, 255};
  CHECK(cli_case(NULL, binary, 2, 0, "//8=\n", 5) == 0);
  CHECK(cli_case("-u", binary, 2, 0, "__8=\n", 5) == 0);
  CHECK(cli_case("-d", "//8=\n", 5, 0, binary, 2) == 0);
  CHECK(cli_case(NULL, "", 0, 0, "\n", 1) == 0);
  CHECK(cli_case("-u", "", 0, 0, "\n", 1) == 0);
  unsigned char plain[55];
  char folded[78];
  memset(plain, 'a', sizeof plain);
  for (size_t i = 0; i < 72; i += 4) memcpy(folded + i, "YWFh", 4);
  memcpy(folded + 72, "\nYQ==\n", 6);
  CHECK(cli_case(NULL, plain, sizeof plain, 0, folded, sizeof folded) == 0);
  CHECK(cli_case("-d", folded, sizeof folded, 0, plain, sizeof plain) == 0);
  const char *bad[] = {"Zg== ", "Zg==\r\n", "Zh==", "Zg="};
  for (size_t i = 0; i < sizeof bad / sizeof bad[0]; i++)
    CHECK(cli_case("-d", bad[i], strlen(bad[i]), 2, "", 0) == 0);
}

static bool cli_rejects_stream(char *flag, FILE *bad, FILE *good, bool input_error) {
  char *argv[] = {"b64", flag, NULL};
  FILE *source = input_error ? bad : good;
  FILE *output = input_error ? good : bad;
  return cli_run(flag ? 2 : 1, argv, source, output) == 2 && ferror(bad) &&
         (!input_error || ftell(good) == 0);
}

static int cli_stream_error(char *flag, bool input_error) {
#if defined(_WIN32)
  const char *null_path = "NUL";
#else
  const char *null_path = "/dev/null";
#endif
  FILE *bad = fopen(null_path, input_error ? "w" : "r");
  FILE *good = tmpfile();
  int failed = 1;
  if (!bad || !good) goto cleanup;
  if (!input_error) {
    if (fputs("Zg==", good) < 0 || fflush(good) != 0) goto cleanup;
    rewind(good);
  }
  if (!cli_rejects_stream(flag, bad, good, input_error)) goto cleanup;
  failed = 0;
cleanup:
  if (bad) (void)fclose(bad);
  if (good && fclose(good) != 0) failed = 1;
  return failed;
}

static bool cli_fill(FILE *f, size_t size) {
  unsigned char zeros[4096] = {0};
  while (size) {
    size_t n = size < sizeof zeros ? size : sizeof zeros;
    if (fwrite(zeros, 1, n, f) != n) return false;
    size -= n;
  }
  if (fflush(f) != 0) return false;
  rewind(f);
  return true;
}

static int cli_bound_case(size_t size, size_t cap, bool expected) {
  FILE *source = tmpfile();
  if (!source) return 1;
  size_t len = 0;
  bool ok = cli_fill(source, size);
  if (ok) ok = cli_read(source, input, cap, &len) == expected;
  if (ok && expected) ok = len == size;
  if (fclose(source) != 0) ok = false;
  return ok ? 0 : 1;
}

static void test_cli_errors_and_bounds(void) {
  CHECK(cli_stream_error(NULL, true) == 0);
  CHECK(cli_stream_error(NULL, false) == 0);
  CHECK(cli_stream_error("-u", false) == 0);
  CHECK(cli_stream_error("-d", false) == 0);
  CHECK(cli_bound_case(31, 32, true) == 0);
  CHECK(cli_bound_case(32, 32, true) == 0);
  CHECK(cli_bound_case(33, 32, false) == 0);
  CHECK(cli_bound_case(MAX_INPUT, MAX_INPUT, true) == 0);
}

int main(void) {
  test_cli_vectors();
  test_cli_errors_and_bounds();
  test_rejected_output_canaries();
  test_rfc4648_vectors();
  test_urlsafe();
  test_strict_rejections();
  test_roundtrip_all_bytes();
  test_size_arithmetic();
  test_size_overflow();
  test_encode_capacity_canaries();
  if (failures) {
    fprintf(stderr, "zbase64: %d failure(s)\n", failures);
    return 1;
  }
  printf("zbase64: all tests passed\n");
  return 0;
}
