/* Tests for zb32 — RFC 4648 base32.
 * Groups: kat, err, roundtrip, null, fuzz. */
#include "zb32/zb32.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define main zb32_cli_main
#include "../app/main.c"
#undef main

static int g_fail = 0;
#define CHECK(cond)                                                     \
  do {                                                                  \
    if (!(cond)) {                                                      \
      fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);   \
      g_fail = 1;                                                       \
    }                                                                   \
  } while (0)

/* RFC 4648 test vectors. */
static void test_kat(void) {
  static const struct {
    const char *plain, *b32;
  } KAT[] = {
      {"", ""},
      {"f", "MY======"},
      {"fo", "MZXQ===="},
      {"foo", "MZXW6==="},
      {"foob", "MZXW6YQ="},
      {"fooba", "MZXW6YTB"},
      {"foobar", "MZXW6YTBOI======"},
  };
  size_t i;
  for (i = 0; i < sizeof(KAT) / sizeof(KAT[0]); i++) {
    char enc[64];
    unsigned char dec[64];
    size_t n = strlen(KAT[i].plain);
    size_t en = zb32_encode(enc, sizeof(enc), KAT[i].plain, n);
    if (en != strlen(KAT[i].b32) || strcmp(enc, KAT[i].b32) != 0) {
      fprintf(stderr, "FAIL enc: \"%s\" -> \"%s\" (want \"%s\")\n",
              KAT[i].plain, enc, KAT[i].b32);
      g_fail = 1;
    }
    if (zb32_decode(dec, sizeof(dec), KAT[i].b32, strlen(KAT[i].b32)) != n ||
        memcmp(dec, KAT[i].plain, n) != 0) {
      fprintf(stderr, "FAIL dec: \"%s\"\n", KAT[i].b32);
      g_fail = 1;
    }
    CHECK(zb32_encoded_len(n) == en);
    CHECK(zb32_decoded_len(KAT[i].b32, strlen(KAT[i].b32)) == n);
  }
}

static void test_err(void) {
  unsigned char out[16];
  static const char *BAD[] = {
      "M",          /* not multiple of 8 */
      "MY=====",    /* 7 chars */
      "MY=======",  /* 9 chars */
      "M=======" ,  /* 1 value char: invalid shape */
      "MZXW6YT=BO", /* char after pad (and len wrong) */
      "MY======MY======", /* padding mid-stream */
      "MZ======",   /* 3 pads for shape needing 6 */
      "MZXW6YQ==",  /* 2 pads, need 1 */
      "my======",   /* lowercase */
      "M!======",   /* bad char */
      "0189====",   /* digits 0/1/8/9 not in alphabet */
      "MZXW6YTBB======", /* 15: not multiple of 8 */
  };
  size_t i;
  for (i = 0; i < sizeof(BAD) / sizeof(BAD[0]); i++)
    CHECK(zb32_decode(out, sizeof(out), BAD[i], strlen(BAD[i])) ==
          SIZE_MAX);
  /* Non-canonical leftover bits: "MZ======" decodes 'f' with the low
   * 2 bits of 'Z' set — not canonical. "MB======" likewise. */
  CHECK(zb32_decode(out, sizeof(out), "MZ======", 8) == SIZE_MAX);
  CHECK(zb32_decode(out, sizeof(out), "MB======", 8) == SIZE_MAX);
}

static void test_roundtrip(void) {
  /* All byte values, all lengths 0..40: round trip exactly. */
  unsigned char src[41];
  char enc[80];
  unsigned char dec[48];
  size_t i, n;
  for (i = 0; i < 41; i++) src[i] = (unsigned char)(i * 37 + 5);
  for (n = 0; n <= 40; n++) {
    size_t en = zb32_encode(enc, sizeof(enc), src, n);
    size_t dn;
    CHECK(en == zb32_encoded_len(n));
    dn = zb32_decode(dec, sizeof(dec), enc, en);
    CHECK(dn == n && (n == 0 || memcmp(dec, src, n) == 0));
  }
}

static void test_null_trunc(void) {
  char enc[10];
  unsigned char dec[8];
  CHECK(zb32_encode(enc, sizeof(enc), NULL, 3) == SIZE_MAX);
  CHECK(zb32_encode(enc, sizeof(enc), NULL, 0) == 0);
  CHECK(zb32_decode(dec, sizeof(dec), NULL, 8) == SIZE_MAX);
  CHECK(zb32_decode(dec, sizeof(dec), NULL, 0) == 0);
  /* truncation: needed length reported, output clipped */
  CHECK(zb32_encode(enc, 9, "foobar", 6) == 16);
  CHECK(strcmp(enc, "MZXW6YTB") == 0);
  CHECK(zb32_encode(NULL, 0, "f", 1) == 8);
  CHECK(zb32_decode(NULL, 0, "MY======", 8) == 1);
  CHECK(zb32_decode(dec, 0, "MY======", 8) == 1); /* cap 0: no write */
  CHECK(zb32_encoded_len(ZB32_MAX + 1) == SIZE_MAX);
}

static uint64_t rng_state = 0x77AA11BB22CC33D4ull;
static uint64_t rng_next(void) {
  rng_state ^= rng_state << 13;
  rng_state ^= rng_state >> 7;
  rng_state ^= rng_state << 17;
  return rng_state;
}

static void test_fuzz(void) {
  int trial;
  for (trial = 0; trial < 3000; trial++) {
    unsigned char src[64];
    char enc[120];
    unsigned char dec[64];
    size_t n = rng_next() % 64, i, en, dn;
    for (i = 0; i < n; i++) src[i] = (unsigned char)rng_next();
    en = zb32_encode(enc, sizeof(enc), src, n);
    CHECK(en != SIZE_MAX && en == zb32_encoded_len(n));
    dn = zb32_decode(dec, sizeof(dec), enc, en);
    CHECK(dn == n && (n == 0 || memcmp(dec, src, n) == 0));
    /* mutate: never crash */
    if (en > 0) {
      size_t pos = rng_next() % en;
      char save = enc[pos];
      enc[pos] = (char)(rng_next() % 256);
      (void)zb32_decode(dec, sizeof(dec), enc, en);
      enc[pos] = save;
    }
  }
}

static void test_decoded_bound(void) {
  static char wire[(ZB32_MAX / 5 + 1) * 8];
  memset(wire, 'A', sizeof wire);
  CHECK(zb32_decoded_len(wire, sizeof wire) == SIZE_MAX);
}

static int cli_case(char *mode, const char *data, int status, const char *expected) {
  FILE *source = tmpfile(), *output = tmpfile();
  int failed = 1;
  if (!source || !output) goto cleanup;
  if (fputs(data, source) < 0 || fflush(source) != 0) goto cleanup;
  rewind(source);
  char *argv[] = {"zb32", mode, NULL};
  if (cli_run(2, argv, source, output) != status) goto cleanup;
  rewind(output);
  char bytes[64];
  size_t n = fread(bytes, 1, sizeof bytes, output);
  if (ferror(output) || n != strlen(expected)) goto cleanup;
  if (memcmp(bytes, expected, n) != 0) goto cleanup;
  failed = 0;
cleanup:
  if (source && fclose(source) != 0) failed = 1;
  if (output && fclose(output) != 0) failed = 1;
  return failed;
}

static int cli_bound(char *mode, size_t size, int status, long output_size) {
  FILE *source = tmpfile(), *output = tmpfile();
  int failed = 1;
  if (!source || !output) goto cleanup;
  for (size_t i = 0; i < size; i++)
    if (fputc('A', source) == EOF) goto cleanup;
  if (fflush(source) != 0) goto cleanup;
  rewind(source);
  char *argv[] = {"zb32", mode, NULL};
  if (cli_run(2, argv, source, output) != status) goto cleanup;
  if (ftell(output) != output_size) goto cleanup;
  failed = 0;
cleanup:
  if (source && fclose(source) != 0) failed = 1;
  if (output && fclose(output) != 0) failed = 1;
  return failed;
}

static int cli_output_error(const char *path, const char *access) {
  FILE *source = tmpfile(), *output = fopen(path, access);
  int failed = 1;
  char buffer[4096];
  if (!source || !output) goto cleanup;
  if (setvbuf(output, buffer, _IOFBF, sizeof buffer) != 0) goto cleanup;
  if (fputs("f", source) < 0 || fflush(source) != 0) goto cleanup;
  rewind(source);
  char *argv[] = {"zb32", "encode", NULL};
  if (cli_run(2, argv, source, output) != 1 || !ferror(output)) goto cleanup;
  failed = 0;
cleanup:
  if (source && fclose(source) != 0) failed = 1;
  if (output) (void)fclose(output);
  return failed;
}

static void test_cli(void) {
  CHECK(cli_case("encode", "foo", 0, "MZXW6===") == 0);
  CHECK(cli_case("decode", "MZXW6===", 0, "foo") == 0);
  CHECK(cli_case("encode", "", 0, "") == 0);
  CHECK(cli_case("decode", "MZ======", 1, "") == 0);
  CHECK(cli_case("decode", "MY======\n", 1, "") == 0);
  CHECK(cli_bound("encode", 40959, 0, 65536) == 0);
  CHECK(cli_bound("encode", 40960, 0, 65536) == 0);
  CHECK(cli_bound("encode", 40961, 1, 0) == 0);
  CHECK(cli_bound("decode", 40960, 0, 25600) == 0);
#if defined(_WIN32)
  CHECK(cli_output_error("NUL", "r") == 0);
#else
  CHECK(cli_output_error("/dev/null", "r") == 0);
#endif
#if defined(__linux__)
  CHECK(cli_output_error("/dev/full", "w") == 0);
#endif
}

int main(void) {
  test_cli();
  test_decoded_bound();
  test_kat();
  test_err();
  test_roundtrip();
  test_null_trunc();
  test_fuzz();
  if (g_fail) {
    fprintf(stderr, "test_zb32: FAILURES\n");
    return 1;
  }
  printf("test_zb32: all groups passed (kat err roundtrip null fuzz)\n");
  return 0;
}
