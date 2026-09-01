/* zsha1 tests — RFC 3174 known-answer suite plus streaming and
 * padding-boundary cases.
 *
 * The classic messages and digests come from RFC 3174 section 7 and
 * FIPS 180-1. Also covered: chunked updates equal one-shot results at
 * every split point, the million-'a' case, and NULL-argument
 * robustness.
 */
#include "zsha1/zsha1.h"

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

static void hex_of(const void *data, size_t n, char out[ZSHA1_HEX_LEN + 1])
{
    zsha1_digest_hex(data, n, out);
    out[ZSHA1_HEX_LEN] = '\0';
}

static void test_rfc3174_suite(void)
{
    struct { const char *msg; const char *hex; } kat[] = {
        { "", "da39a3ee5e6b4b0d3255bfef95601890afd80709" },
        { "abc", "a9993e364706816aba3e25717850c26c9cd0d89d" },
        { "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
          "84983e441c3bd26ebaae4aa1f95129e5e54670f1" },
        { "The quick brown fox jumps over the lazy dog",
          "2fd4e1c67a2d28fced849ee1bb76e7391b93eb12" },
        { "The quick brown fox jumps over the lazy cog",
          "de9f2c7fd25e1b3afad3e85a0bd17d9b100db4b3" },
    };
    for (size_t k = 0; k < sizeof(kat) / sizeof(kat[0]); k++) {
        char got[ZSHA1_HEX_LEN + 1];
        hex_of(kat[k].msg, strlen(kat[k].msg), got);
        if (strcmp(got, kat[k].hex) != 0)
            fprintf(stderr, "  sha1(\"%s\") = %s, want %s\n",
                    kat[k].msg, got, kat[k].hex);
        CHECK(strcmp(got, kat[k].hex) == 0);
    }
}

static void test_million_a(void)
{
    /* RFC 3174 case: SHA-1 of 1,000,000 'a' bytes. */
    zsha1 ctx;
    zsha1_init(&ctx);
    uint8_t chunk[1000];
    memset(chunk, 'a', sizeof(chunk));
    for (int i = 0; i < 1000; i++) zsha1_update(&ctx, chunk, sizeof(chunk));
    uint8_t d[ZSHA1_DIGEST_LEN];
    zsha1_final(&ctx, d);
    char got[ZSHA1_HEX_LEN + 1];
    zsha1_hex(d, got);
    got[ZSHA1_HEX_LEN] = '\0';
    CHECK(strcmp(got, "34aa973cd4c4daa4f61eeb2bdbad27316534016f") == 0);
}

static void test_streaming_equals_oneshot(void)
{
    /* Every split point across block boundaries must agree with the
     * one-shot digest. */
    uint8_t buf[200];
    for (size_t i = 0; i < sizeof(buf); i++)
        buf[i] = (uint8_t)(i * 17u + 3u);

    uint8_t want[ZSHA1_DIGEST_LEN];
    zsha1_digest(buf, sizeof(buf), want);

    for (size_t split = 0; split <= sizeof(buf); split++) {
        zsha1 ctx;
        zsha1_init(&ctx);
        zsha1_update(&ctx, buf, split);
        zsha1_update(&ctx, buf + split, sizeof(buf) - split);
        uint8_t got[ZSHA1_DIGEST_LEN];
        zsha1_final(&ctx, got);
        if (memcmp(got, want, ZSHA1_DIGEST_LEN) != 0)
            fprintf(stderr, "  split %zu mismatch\n", split);
        CHECK(memcmp(got, want, ZSHA1_DIGEST_LEN) == 0);
    }

    /* Byte-at-a-time feeding. */
    zsha1 ctx;
    zsha1_init(&ctx);
    for (size_t i = 0; i < sizeof(buf); i++) zsha1_update(&ctx, buf + i, 1);
    uint8_t got[ZSHA1_DIGEST_LEN];
    zsha1_final(&ctx, got);
    CHECK(memcmp(got, want, ZSHA1_DIGEST_LEN) == 0);
}

static void test_length_edges(void)
{
    /* Lengths around 55/56/64/120 stress the padding path. */
    static const size_t lens[] = { 0, 1, 54, 55, 56, 57, 63, 64, 65,
                                   118, 119, 120, 127, 128 };
    uint8_t buf[128];
    for (size_t i = 0; i < sizeof(buf); i++) buf[i] = (uint8_t)(i * 41u);

    for (size_t k = 0; k < sizeof(lens) / sizeof(lens[0]); k++) {
        size_t n = lens[k];
        uint8_t a[ZSHA1_DIGEST_LEN], b[ZSHA1_DIGEST_LEN];
        zsha1_digest(buf, n, a);
        zsha1 ctx;
        zsha1_init(&ctx);
        size_t head = n < 9 ? n : 9; /* awkward split */
        zsha1_update(&ctx, buf, head);
        zsha1_update(&ctx, buf + head, n - head);
        zsha1_final(&ctx, b);
        CHECK(memcmp(a, b, ZSHA1_DIGEST_LEN) == 0);
    }
}

static void test_null_args(void)
{
    zsha1 ctx;
    zsha1_init(NULL);              /* must not crash */
    zsha1_init(&ctx);
    zsha1_update(&ctx, NULL, 0);   /* no-op */
    zsha1_update(NULL, "x", 1);    /* no-op */
    uint8_t d[ZSHA1_DIGEST_LEN];
    zsha1_final(&ctx, d);          /* digest of empty input */
    char got[ZSHA1_HEX_LEN + 1];
    zsha1_hex(d, got);
    got[ZSHA1_HEX_LEN] = '\0';
    CHECK(strcmp(got, "da39a3ee5e6b4b0d3255bfef95601890afd80709") == 0);

    char h[ZSHA1_HEX_LEN + 1];
    hex_of(NULL, 0, h);
    CHECK(strcmp(h, "da39a3ee5e6b4b0d3255bfef95601890afd80709") == 0);
}

static void test_context_reuse_after_final(void)
{
    zsha1 ctx;
    uint8_t d[ZSHA1_DIGEST_LEN];
    char g1[ZSHA1_HEX_LEN + 1], g2[ZSHA1_HEX_LEN + 1];

    zsha1_init(&ctx);
    zsha1_update(&ctx, "abc", 3);
    zsha1_final(&ctx, d);
    zsha1_hex(d, g1);
    g1[ZSHA1_HEX_LEN] = '\0';

    zsha1_init(&ctx);
    zsha1_update(&ctx, "abc", 3);
    zsha1_final(&ctx, d);
    zsha1_hex(d, g2);
    g2[ZSHA1_HEX_LEN] = '\0';

    CHECK(strcmp(g1, g2) == 0);
    CHECK(strcmp(g1, "a9993e364706816aba3e25717850c26c9cd0d89d") == 0);
}

int main(void)
{
    test_rfc3174_suite();
    test_million_a();
    test_streaming_equals_oneshot();
    test_length_edges();
    test_null_args();
    test_context_reuse_after_final();
    if (failures) {
        fprintf(stderr, "zsha1: %d failure(s)\n", failures);
        return 1;
    }
    puts("zsha1: all tests passed");
    return 0;
}
