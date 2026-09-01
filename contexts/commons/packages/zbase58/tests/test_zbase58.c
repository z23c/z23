#include "zbase58/zbase58.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(cond) do { \
    if (!(cond)) { \
        fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); \
        exit(1); \
    } \
} while (0)

static size_t unhex(const char *hex, uint8_t *out)
{
    size_t n = strlen(hex) / 2;
    for (size_t i = 0; i < n; i++) {
        unsigned v = 0;
        sscanf(hex + 2 * i, "%2x", &v);
        out[i] = (uint8_t)v;
    }
    return n;
}

static void expect_encode(const char *hex, const char *want)
{
    uint8_t bin[64];
    size_t blen = unhex(hex, bin);
    char out[256];
    size_t n = 0;
    CHECK(zbase58_encode(bin, blen, out, sizeof out, &n) == ZBASE58_OK);
    CHECK(n == strlen(want));
    CHECK(strcmp(out, want) == 0);
}

static void expect_decode(const char *b58, const char *want_hex)
{
    uint8_t want[64];
    size_t wlen = unhex(want_hex, want);
    uint8_t out[64];
    size_t n = 0;
    CHECK(zbase58_decode(b58, strlen(b58), out, sizeof out, &n, NULL)
          == ZBASE58_OK);
    CHECK(n == wlen);
    CHECK(wlen == 0 || memcmp(out, want, n) == 0);
}

static void test_known_vectors(void)
{
    /* Cross-checked against an independent Python implementation. */
    expect_encode("48656c6c6f20576f726c6421", "2NEpo7TZRRrLZSi2U");
    expect_encode("54686520717569636b2062726f776e20666f78206a756d7073206f7665"
                  "7220746865206c617a7920646f67",
                  "7DdiPPYtxLjCD3wA1po2rvZHTDYjkZYiEtazrfiwJcwnKCizhGFhBGHeRdx");
    expect_encode("000000616263", "111ZiCa");
    expect_encode("ffffffff", "7YXq9G");
    expect_encode("", "");
    expect_encode("00", "1");
    expect_encode("000102030405060708090a0b0c0d0e0f101112131415161718191a1b"
                  "1c1d1e1f",
                  "1thX6LZfHDZZKUs92febYZhYRcXddmzfzF2NvTkPNE");

    expect_decode("2NEpo7TZRRrLZSi2U", "48656c6c6f20576f726c6421");
    expect_decode("111ZiCa", "000000616263");
    expect_decode("7YXq9G", "ffffffff");
    expect_decode("", "");
    expect_decode("1", "00");
    expect_decode("111", "000000");

    /* Alphabet sanity: 58 chars, no 0 O I l. */
    CHECK(zbase58_char_value('1') == 0);
    CHECK(zbase58_char_value('9') == 8);
    CHECK(zbase58_char_value('A') == 9);
    CHECK(zbase58_char_value('z') == 57);
    CHECK(zbase58_char_value('0') == -1);
    CHECK(zbase58_char_value('O') == -1);
    CHECK(zbase58_char_value('I') == -1);
    CHECK(zbase58_char_value('l') == -1);
}

static void test_errors(void)
{
    char enc[64];
    uint8_t dec[64];
    size_t n, pos;

    /* Bad characters with position. */
    CHECK(zbase58_decode("20NEpo7", 7, dec, sizeof dec, &n, &pos)
          == ZBASE58_ERR_BAD_CHAR);
    CHECK(pos == 1);
    CHECK(zbase58_decode("abcO", 4, dec, sizeof dec, &n, &pos)
          == ZBASE58_ERR_BAD_CHAR);
    CHECK(pos == 3);

    /* Small buffers. */
    const uint8_t four_ff[4] = {0xff, 0xff, 0xff, 0xff};
    CHECK(zbase58_encode(four_ff, 4, enc, 4, &n) == ZBASE58_ERR_SMALL);
    CHECK(n == 6); /* "7YXq9G" needs 6 chars + NUL */
    CHECK(zbase58_decode("7YXq9G", 6, dec, 3, &n, NULL)
          == ZBASE58_ERR_SMALL);

    /* NULL handling. */
    CHECK(zbase58_encode(NULL, 1, enc, sizeof enc, &n) == ZBASE58_ERR_NULL);
    CHECK(zbase58_encode(four_ff, 4, NULL, 64, &n) == ZBASE58_ERR_NULL);
    CHECK(zbase58_encode(four_ff, 4, enc, 64, NULL) == ZBASE58_ERR_NULL);
    CHECK(zbase58_encode(four_ff, 4, enc, 0, &n) == ZBASE58_ERR_SMALL);
    CHECK(zbase58_decode(NULL, 1, dec, 64, &n, NULL) == ZBASE58_ERR_NULL);
    CHECK(zbase58_decode("7YXq9G", 6, NULL, 64, &n, NULL) == ZBASE58_ERR_NULL);
    CHECK(zbase58_decode("7YXq9G", 6, dec, 64, NULL, NULL) == ZBASE58_ERR_NULL);
}

static uint64_t rng_state = 0x0123456789abcdefull;
static uint32_t rng_next(void)
{
    rng_state ^= rng_state << 13;
    rng_state ^= rng_state >> 7;
    rng_state ^= rng_state << 17;
    return (uint32_t)(rng_state >> 32);
}

static void test_roundtrip_fuzz(void)
{
    for (int iter = 0; iter < 5000; iter++) {
        size_t len = (size_t)(rng_next() % 49u);
        uint8_t bin[48];
        for (size_t i = 0; i < len; i++) bin[i] = (uint8_t)rng_next();
        /* Sometimes force leading zeros. */
        if (iter % 3 == 0 && len > 0) {
            size_t z = (size_t)(rng_next() % 4u) + 1;
            if (z > len) z = len;
            memset(bin, 0, z);
        }

        char enc[zbase58_encoded_max(48) + 8];
        size_t en = 0;
        CHECK(zbase58_encode(bin, len, enc, sizeof enc, &en) == ZBASE58_OK);
        CHECK(en < sizeof enc);

        uint8_t back[48];
        size_t bn = 0;
        CHECK(zbase58_decode(enc, en, back, sizeof back, &bn, NULL)
              == ZBASE58_OK);
        CHECK(bn == len);
        CHECK(len == 0 || memcmp(bin, back, len) == 0);
    }

    /* Sizing helpers are honest upper bounds. */
    CHECK(zbase58_encoded_max(0) >= 2);
    CHECK(zbase58_encoded_max(32) >= 45);
    CHECK(zbase58_decoded_max(45) >= 33);
}

static void test_err_str(void)
{
    CHECK(strcmp(zbase58_err_str(ZBASE58_OK), "ok") == 0);
    CHECK(strstr(zbase58_err_str(ZBASE58_ERR_BAD_CHAR), "Base58") != NULL);
    CHECK(zbase58_err_str((zbase58_err)999) != NULL);
}

int main(void)
{
    test_known_vectors();
    test_errors();
    test_roundtrip_fuzz();
    test_err_str();
    puts("test_zbase58: all groups passed (vectors errors fuzz errstr)");
    return 0;
}
