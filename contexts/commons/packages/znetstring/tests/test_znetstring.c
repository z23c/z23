/* znetstring tests — hand-written known-answer and fault cases.
 *
 * Covers: round trips across sizes, the classic spec examples,
 * strict-format rejections (leading zeros, bad terminator, non-digit
 * length, oversized length), truncation detection, prefix probing
 * for stream framing, and argument errors.
 */
#include "znetstring/znetstring.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int failures = 0;

#define CHECK(cond)                                                     \
  do {                                                                  \
    if (!(cond)) {                                                      \
      fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);  \
      failures++;                                                       \
    }                                                                   \
  } while (0)

static void test_kat(void)
{
    struct { const char *wire; const char *payload; size_t plen; } kats[] = {
        { "0:,", "", 0 },
        { "3:abc,", "abc", 3 },
        { "5:hello,", "hello", 5 },
        { "12:hello world!,", "hello world!", 12 },
        { "10:0123456789,", "0123456789", 10 },
    };
    for (size_t k = 0; k < sizeof(kats) / sizeof(kats[0]); k++) {
        znetstring ns;
        CHECK(znetstring_parse(kats[k].wire, strlen(kats[k].wire), &ns)
              == ZNETSTRING_OK);
        CHECK(ns.payload_len == kats[k].plen);
        CHECK(ns.consumed == strlen(kats[k].wire));
        CHECK(memcmp(ns.payload, kats[k].payload, kats[k].plen) == 0);

        char out[64];
        size_t out_len = 0;
        CHECK(znetstring_encode((const uint8_t *)kats[k].payload,
                                kats[k].plen, out, sizeof(out), &out_len)
              == ZNETSTRING_OK);
        CHECK(out_len == strlen(kats[k].wire));
        CHECK(memcmp(out, kats[k].wire, out_len) == 0);
    }
}

static void test_roundtrip_sizes(void)
{
    /* Powers-of-ten boundaries exercise the length-field width. */
    static const size_t sizes[] = { 0, 1, 9, 10, 99, 100, 999, 1000,
                                    4095, 4096, 65535 };
    uint8_t *payload = malloc(65536);
    char *wire = malloc(65536 + 16);
    CHECK(payload && wire);
    if (!payload || !wire) { free(payload); free(wire); return; }
    for (size_t i = 0; i < 65536; i++) payload[i] = (uint8_t)(i * 131u + 7u);

    for (size_t s = 0; s < sizeof(sizes) / sizeof(sizes[0]); s++) {
        size_t n = sizes[s];
        size_t wl = 0;
        CHECK(znetstring_encode(payload, n, wire, 65536 + 16, &wl)
              == ZNETSTRING_OK);
        CHECK(wl == znetstring_encoded_len(n));
        znetstring ns;
        CHECK(znetstring_parse(wire, wl, &ns) == ZNETSTRING_OK);
        CHECK(ns.payload_len == n);
        CHECK(ns.consumed == wl);
        CHECK(memcmp(ns.payload, payload, n) == 0);
    }
    free(payload);
    free(wire);
}

static void test_stream_framing(void)
{
    /* Consecutive netstrings parse by advancing over `consumed`. */
    const char *stream = "3:foo,0:,5:hello,";
    size_t off = 0, total = strlen(stream);
    const char *expect[] = { "foo", "", "hello" };
    for (int k = 0; k < 3; k++) {
        znetstring ns;
        CHECK(znetstring_parse(stream + off, total - off, &ns)
              == ZNETSTRING_OK);
        CHECK(ns.payload_len == strlen(expect[k]));
        CHECK(memcmp(ns.payload, expect[k], ns.payload_len) == 0);
        off += ns.consumed;
    }
    CHECK(off == total);
}

static void test_rejects(void)
{
    struct { const char *wire; znetstring_err err; } bad[] = {
        { "03:abc,", ZNETSTRING_ERR_FORMAT },   /* leading zero */
        { ":abc,", ZNETSTRING_ERR_FORMAT },     /* no digits */
        { "x:abc,", ZNETSTRING_ERR_FORMAT },    /* non-digit */
        { "3;abc,", ZNETSTRING_ERR_FORMAT },    /* wrong separator */
        { "3:abc;", ZNETSTRING_ERR_FORMAT },    /* wrong terminator */
        { "3:ab", ZNETSTRING_ERR_FORMAT },      /* truncated payload */
        { "3", ZNETSTRING_ERR_FORMAT },         /* truncated after digits */
        { "3:", ZNETSTRING_ERR_FORMAT },        /* truncated after ':' */
        { "3:abc", ZNETSTRING_ERR_FORMAT },     /* missing comma */
        { "16777217:x", ZNETSTRING_ERR_RANGE }, /* over ZNETSTRING_MAX */
    };
    for (size_t k = 0; k < sizeof(bad) / sizeof(bad[0]); k++) {
        znetstring ns;
        CHECK(znetstring_parse(bad[k].wire, strlen(bad[k].wire), &ns)
              == bad[k].err);
    }
}

static void test_prefix(void)
{
    CHECK(znetstring_prefix("5:hello,", 8) == 1);
    CHECK(znetstring_prefix("5:hello", 7) == 1);   /* completable */
    CHECK(znetstring_prefix("5:he", 4) == 1);      /* completable */
    CHECK(znetstring_prefix("5:", 2) == 1);
    CHECK(znetstring_prefix("5", 1) == 1);
    CHECK(znetstring_prefix("", 0) == 0);
    CHECK(znetstring_prefix("5;he", 4) == 0);      /* bad separator */
    CHECK(znetstring_prefix("05:he", 5) == 0);     /* leading zero */
    CHECK(znetstring_prefix("x", 1) == 0);
    CHECK(znetstring_prefix("5:hello; ", 8) == 0); /* wrong terminator */
}

static void test_args(void)
{
    znetstring ns;
    char out[16];
    size_t ol;
    CHECK(znetstring_parse(NULL, 3, &ns) == ZNETSTRING_ERR_ARG);
    CHECK(znetstring_parse("0:,", 3, NULL) == ZNETSTRING_ERR_ARG);
    CHECK(znetstring_encode(NULL, 1, out, sizeof(out), &ol)
          == ZNETSTRING_ERR_ARG);
    CHECK(znetstring_encode((const uint8_t *)"a", 1, NULL, 16, &ol)
          == ZNETSTRING_ERR_ARG);
    /* Empty payload with NULL pointer is allowed (no deref). */
    CHECK(znetstring_encode(NULL, 0, out, sizeof(out), &ol)
          == ZNETSTRING_OK);
    CHECK(ol == 3 && memcmp(out, "0:,", 3) == 0);
    /* Capacity checks. */
    CHECK(znetstring_encode((const uint8_t *)"abc", 3, out, 5, &ol)
          == ZNETSTRING_ERR_CAP);
    CHECK(znetstring_encode((const uint8_t *)"abc", 3, out, 6, &ol)
          == ZNETSTRING_OK);
    CHECK(znetstring_encoded_len(ZNETSTRING_MAX + 1) == 0);
}

static void test_err_str(void)
{
    CHECK(strcmp(znetstring_err_str(ZNETSTRING_OK), "ok") == 0);
    for (int e = 0; e <= 4; e++) CHECK(znetstring_err_str((znetstring_err)e) != NULL);
}

int main(void)
{
    test_kat();
    test_roundtrip_sizes();
    test_stream_framing();
    test_rejects();
    test_prefix();
    test_args();
    test_err_str();
    if (failures) {
        fprintf(stderr, "znetstring: %d failure(s)\n", failures);
        return 1;
    }
    puts("znetstring: all tests passed");
    return 0;
}
