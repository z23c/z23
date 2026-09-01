/* zmd5 tests — RFC 1321 test suite plus streaming and boundary cases.
 *
 * The seven classic messages and digests come from RFC 1321 section
 * A.5. Also covered: chunked updates equal one-shot results at every
 * split point around block boundaries, million-'a' extension case,
 * and NULL-argument robustness.
 */
#include "zmd5/zmd5.h"

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

static void hex_of(const void *data, size_t n, char out[ZMD5_HEX_LEN + 1])
{
    zmd5_digest_hex(data, n, out);
    out[ZMD5_HEX_LEN] = '\0';
}

static void test_rfc1321_suite(void)
{
    struct { const char *msg; const char *hex; } kat[] = {
        { "", "d41d8cd98f00b204e9800998ecf8427e" },
        { "a", "0cc175b9c0f1b6a831c399e269772661" },
        { "abc", "900150983cd24fb0d6963f7d28e17f72" },
        { "message digest", "f96b697d7cb7938d525a2f31aaf161d0" },
        { "abcdefghijklmnopqrstuvwxyz", "c3fcd3d76192e4007dfb496cca67e13b" },
        { "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
          "d174ab98d277d9f5a5611c2c9f419d9f" },
        { "123456789012345678901234567890123456789012345678901234567890"
          "12345678901234567890", "57edf4a22be3c955ac49da2e2107b67a" },
    };
    for (size_t k = 0; k < sizeof(kat) / sizeof(kat[0]); k++) {
        char got[ZMD5_HEX_LEN + 1];
        hex_of(kat[k].msg, strlen(kat[k].msg), got);
        if (strcmp(got, kat[k].hex) != 0)
            fprintf(stderr, "  md5(\"%s\") = %s, want %s\n",
                    kat[k].msg, got, kat[k].hex);
        CHECK(strcmp(got, kat[k].hex) == 0);
    }
}

static void test_million_a(void)
{
    /* Classic extension case: MD5 of 1,000,000 'a' bytes. */
    zmd5 ctx;
    zmd5_init(&ctx);
    uint8_t chunk[1000];
    memset(chunk, 'a', sizeof(chunk));
    for (int i = 0; i < 1000; i++) zmd5_update(&ctx, chunk, sizeof(chunk));
    uint8_t d[ZMD5_DIGEST_LEN];
    zmd5_final(&ctx, d);
    char got[ZMD5_HEX_LEN + 1];
    zmd5_hex(d, got);
    got[ZMD5_HEX_LEN] = '\0';
    CHECK(strcmp(got, "7707d6ae4e027c70eea2a935c2296f21") == 0);
}

static void test_streaming_equals_oneshot(void)
{
    /* Every split point across block boundaries must agree with the
     * one-shot digest. 200 bytes spans 4 blocks incl. padding edge
     * cases at 55/56/63/64. */
    uint8_t buf[200];
    for (size_t i = 0; i < sizeof(buf); i++)
        buf[i] = (uint8_t)(i * 31u + 5u);

    uint8_t want[ZMD5_DIGEST_LEN];
    zmd5_digest(buf, sizeof(buf), want);

    for (size_t split = 0; split <= sizeof(buf); split++) {
        zmd5 ctx;
        zmd5_init(&ctx);
        zmd5_update(&ctx, buf, split);
        zmd5_update(&ctx, buf + split, sizeof(buf) - split);
        uint8_t got[ZMD5_DIGEST_LEN];
        zmd5_final(&ctx, got);
        if (memcmp(got, want, ZMD5_DIGEST_LEN) != 0)
            fprintf(stderr, "  split %zu mismatch\n", split);
        CHECK(memcmp(got, want, ZMD5_DIGEST_LEN) == 0);
    }

    /* Byte-at-a-time feeding. */
    zmd5 ctx;
    zmd5_init(&ctx);
    for (size_t i = 0; i < sizeof(buf); i++) zmd5_update(&ctx, buf + i, 1);
    uint8_t got[ZMD5_DIGEST_LEN];
    zmd5_final(&ctx, got);
    CHECK(memcmp(got, want, ZMD5_DIGEST_LEN) == 0);
}

static void test_length_edges(void)
{
    /* Lengths 55, 56, 63, 64, 119, 120 stress the padding path. */
    static const size_t lens[] = { 0, 1, 54, 55, 56, 57, 63, 64, 65,
                                   118, 119, 120, 127, 128 };
    uint8_t buf[128];
    for (size_t i = 0; i < sizeof(buf); i++) buf[i] = (uint8_t)(i ^ 0xa5u);

    for (size_t k = 0; k < sizeof(lens) / sizeof(lens[0]); k++) {
        size_t n = lens[k];
        uint8_t a[ZMD5_DIGEST_LEN], b[ZMD5_DIGEST_LEN];
        zmd5_digest(buf, n, a);
        zmd5 ctx;
        zmd5_init(&ctx);
        /* Split awkwardly: 7-byte head, then the rest. */
        size_t head = n < 7 ? n : 7;
        zmd5_update(&ctx, buf, head);
        zmd5_update(&ctx, buf + head, n - head);
        zmd5_final(&ctx, b);
        CHECK(memcmp(a, b, ZMD5_DIGEST_LEN) == 0);
    }
}

static void test_null_args(void)
{
    zmd5 ctx;
    zmd5_init(NULL);              /* must not crash */
    zmd5_init(&ctx);
    zmd5_update(&ctx, NULL, 0);   /* no-op */
    zmd5_update(NULL, "x", 1);    /* no-op */
    uint8_t d[ZMD5_DIGEST_LEN];
    zmd5_final(&ctx, d);          /* digest of empty input */
    char got[ZMD5_HEX_LEN + 1];
    zmd5_hex(d, got);
    got[ZMD5_HEX_LEN] = '\0';
    CHECK(strcmp(got, "d41d8cd98f00b204e9800998ecf8427e") == 0);

    char h[ZMD5_HEX_LEN + 1];
    hex_of(NULL, 0, h);           /* NULL data, zero length = empty */
    CHECK(strcmp(h, "d41d8cd98f00b204e9800998ecf8427e") == 0);
}

static void test_context_reuse_after_final(void)
{
    /* final zeroizes; re-init must produce clean state. */
    zmd5 ctx;
    uint8_t d[ZMD5_DIGEST_LEN];
    char g1[ZMD5_HEX_LEN + 1], g2[ZMD5_HEX_LEN + 1];

    zmd5_init(&ctx);
    zmd5_update(&ctx, "abc", 3);
    zmd5_final(&ctx, d);
    zmd5_hex(d, g1);
    g1[ZMD5_HEX_LEN] = '\0';

    zmd5_init(&ctx);
    zmd5_update(&ctx, "abc", 3);
    zmd5_final(&ctx, d);
    zmd5_hex(d, g2);
    g2[ZMD5_HEX_LEN] = '\0';

    CHECK(strcmp(g1, g2) == 0);
    CHECK(strcmp(g1, "900150983cd24fb0d6963f7d28e17f72") == 0);
}

int main(void)
{
    test_rfc1321_suite();
    test_million_a();
    test_streaming_equals_oneshot();
    test_length_edges();
    test_null_args();
    test_context_reuse_after_final();
    if (failures) {
        fprintf(stderr, "zmd5: %d failure(s)\n", failures);
        return 1;
    }
    puts("zmd5: all tests passed");
    return 0;
}
