#include "zhex/zhex.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(cond) do { \
    if (!(cond)) { \
        fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); \
        exit(1); \
    } \
} while (0)

static void test_encode(void)
{
    char out[32];

    /* Known vectors. */
    const uint8_t empty[1] = {0};
    CHECK(zhex_encode(empty, 0, out) == ZHEX_OK);

    const uint8_t b1[] = {0x00, 0xff, 0x0a, 0xa0, 0x55};
    CHECK(zhex_encode(b1, sizeof b1, out) == ZHEX_OK);
    CHECK(memcmp(out, "00ff0aa055", 10) == 0);

    CHECK(zhex_encode_upper(b1, sizeof b1, out) == ZHEX_OK);
    CHECK(memcmp(out, "00FF0AA055", 10) == 0);

    /* Length helpers. */
    CHECK(zhex_encoded_len(0) == 0);
    CHECK(zhex_encoded_len(1) == 2);
    CHECK(zhex_encoded_len(255) == 510);
    CHECK(zhex_decoded_len(10) == 5);
    CHECK(zhex_decoded_len(9) == 4); /* floor; decode rejects odd */

    /* NULL handling. */
    CHECK(zhex_encode(NULL, 3, out) == ZHEX_ERR_NULL);
    CHECK(zhex_encode(b1, sizeof b1, NULL) == ZHEX_ERR_NULL);
}

static void test_decode(void)
{
    uint8_t out[16];
    size_t bad = 999;

    const char *hex = "00ff0aa055";
    const uint8_t want[] = {0x00, 0xff, 0x0a, 0xa0, 0x55};
    CHECK(zhex_decode(hex, 10, out, &bad) == ZHEX_OK);
    CHECK(memcmp(out, want, sizeof want) == 0);

    /* Uppercase and mixed accepted. */
    CHECK(zhex_decode("00FF0Aa055", 10, out, &bad) == ZHEX_OK);
    CHECK(memcmp(out, want, sizeof want) == 0);

    /* cstr variant. */
    CHECK(zhex_decode_cstr("deadBEEF", out, NULL) == ZHEX_OK);
    CHECK(out[0] == 0xde && out[1] == 0xad && out[2] == 0xbe && out[3] == 0xef);

    /* Odd length rejected. */
    CHECK(zhex_decode("abc", 3, out, &bad) == ZHEX_ERR_ODD_LEN);

    /* Bad char position: first nibble bad. */
    CHECK(zhex_decode("zz", 2, out, &bad) == ZHEX_ERR_BAD_CHAR);
    CHECK(bad == 0);
    /* Second nibble bad. */
    CHECK(zhex_decode("0z", 2, out, &bad) == ZHEX_ERR_BAD_CHAR);
    CHECK(bad == 1);
    /* Later pair. */
    CHECK(zhex_decode("0011xx", 6, out, &bad) == ZHEX_ERR_BAD_CHAR);
    CHECK(bad == 4);
    /* Bytes before the error remain valid. */
    CHECK(out[0] == 0x00 && out[1] == 0x11);

    /* NULL handling. */
    CHECK(zhex_decode(NULL, 2, out, NULL) == ZHEX_ERR_NULL);
    CHECK(zhex_decode("00", 2, NULL, NULL) == ZHEX_ERR_NULL);
    CHECK(zhex_decode_cstr(NULL, out, NULL) == ZHEX_ERR_NULL);
    /* Empty input is valid. */
    CHECK(zhex_decode("", 0, NULL, NULL) == ZHEX_OK);
}

static void test_digit(void)
{
    CHECK(zhex_digit_value('0') == 0);
    CHECK(zhex_digit_value('9') == 9);
    CHECK(zhex_digit_value('a') == 10);
    CHECK(zhex_digit_value('f') == 15);
    CHECK(zhex_digit_value('A') == 10);
    CHECK(zhex_digit_value('F') == 15);
    CHECK(zhex_digit_value('g') == -1);
    CHECK(zhex_digit_value('G') == -1);
    CHECK(zhex_digit_value(' ') == -1);
    CHECK(zhex_digit_value('/') == -1);
    CHECK(zhex_digit_value(':') == -1);
}

static uint64_t rng_state = 0x9e3779b97f4a7c15ull;
static uint32_t rng_next(void)
{
    rng_state ^= rng_state << 13;
    rng_state ^= rng_state >> 7;
    rng_state ^= rng_state << 17;
    return (uint32_t)(rng_state >> 32);
}

static void test_roundtrip(void)
{
    /* Exhaustive over all 256 byte values, then randomized buffers. */
    for (int v = 0; v < 256; v++) {
        uint8_t b = (uint8_t)v;
        char hex[2];
        uint8_t back = 0;
        CHECK(zhex_encode(&b, 1, hex) == ZHEX_OK);
        CHECK(zhex_decode(hex, 2, &back, NULL) == ZHEX_OK);
        CHECK(back == b);
    }

    for (int iter = 0; iter < 5000; iter++) {
        size_t len = (size_t)(rng_next() % 65u);
        uint8_t bin[64];
        char hex[128];
        uint8_t back[64];
        for (size_t i = 0; i < len; i++) bin[i] = (uint8_t)rng_next();
        CHECK(zhex_encode(bin, len, hex) == ZHEX_OK);
        CHECK(zhex_decode(hex, len * 2, back, NULL) == ZHEX_OK);
        CHECK(len == 0 || memcmp(bin, back, len) == 0);
    }
}

static void test_err_str(void)
{
    CHECK(strcmp(zhex_err_str(ZHEX_OK), "ok") == 0);
    CHECK(strstr(zhex_err_str(ZHEX_ERR_ODD_LEN), "odd") != NULL);
    CHECK(strstr(zhex_err_str(ZHEX_ERR_BAD_CHAR), "hex") != NULL);
    CHECK(zhex_err_str((zhex_err)999) != NULL);
}

int main(void)
{
    test_encode();
    test_decode();
    test_digit();
    test_roundtrip();
    test_err_str();
    puts("test_zhex: all groups passed (encode decode digit roundtrip errstr)");
    return 0;
}
