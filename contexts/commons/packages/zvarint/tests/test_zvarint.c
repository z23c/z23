#include "zvarint/zvarint.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(cond) do { \
    if (!(cond)) { \
        fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); \
        exit(1); \
    } \
} while (0)

static void test_known_vectors(void)
{
    uint8_t buf[ZVARINT_MAX_LEN];
    size_t n = 0;

    /* LEB128 reference values. */
    CHECK(zvarint_encode_u64(0, buf, sizeof buf, &n) == ZVARINT_OK);
    CHECK(n == 1 && buf[0] == 0x00);

    CHECK(zvarint_encode_u64(1, buf, sizeof buf, &n) == ZVARINT_OK);
    CHECK(n == 1 && buf[0] == 0x01);

    CHECK(zvarint_encode_u64(127, buf, sizeof buf, &n) == ZVARINT_OK);
    CHECK(n == 1 && buf[0] == 0x7f);

    CHECK(zvarint_encode_u64(128, buf, sizeof buf, &n) == ZVARINT_OK);
    CHECK(n == 2 && buf[0] == 0x80 && buf[1] == 0x01);

    CHECK(zvarint_encode_u64(624485, buf, sizeof buf, &n) == ZVARINT_OK);
    CHECK(n == 3 && buf[0] == 0xe5 && buf[1] == 0x8e && buf[2] == 0x26);

    CHECK(zvarint_encode_u64(UINT64_MAX, buf, sizeof buf, &n) == ZVARINT_OK);
    CHECK(n == 10 && buf[0] == 0xff && buf[9] == 0x01);

    /* Length helpers agree with encoding. */
    CHECK(zvarint_len_u64(0) == 1);
    CHECK(zvarint_len_u64(127) == 1);
    CHECK(zvarint_len_u64(128) == 2);
    CHECK(zvarint_len_u64(UINT64_MAX) == 10);
}

static void test_zigzag(void)
{
    CHECK(zvarint_zigzag_encode(0) == 0);
    CHECK(zvarint_zigzag_encode(-1) == 1);
    CHECK(zvarint_zigzag_encode(1) == 2);
    CHECK(zvarint_zigzag_encode(-2) == 3);
    CHECK(zvarint_zigzag_encode(2) == 4);
    CHECK(zvarint_zigzag_encode(INT64_MAX) == UINT64_MAX - 1);
    CHECK(zvarint_zigzag_encode(INT64_MIN) == UINT64_MAX);

    CHECK(zvarint_zigzag_decode(0) == 0);
    CHECK(zvarint_zigzag_decode(1) == -1);
    CHECK(zvarint_zigzag_decode(2) == 1);
    CHECK(zvarint_zigzag_decode(3) == -2);
    CHECK(zvarint_zigzag_decode(UINT64_MAX) == INT64_MIN);

    /* int64 extremes round trip through the wire format. */
    uint8_t buf[ZVARINT_MAX_LEN];
    size_t n, c;
    int64_t s;
    CHECK(zvarint_encode_i64(INT64_MIN, buf, sizeof buf, &n) == ZVARINT_OK);
    CHECK(n == 10);
    CHECK(zvarint_decode_i64(buf, n, &s, &c, 1) == ZVARINT_OK);
    CHECK(s == INT64_MIN && c == 10);
    CHECK(zvarint_encode_i64(INT64_MAX, buf, sizeof buf, &n) == ZVARINT_OK);
    CHECK(n == 10);
    CHECK(zvarint_decode_i64(buf, n, &s, &c, 1) == ZVARINT_OK);
    CHECK(s == INT64_MAX);
}

static void test_errors(void)
{
    uint8_t buf[ZVARINT_MAX_LEN];
    uint64_t v;
    size_t c;

    /* Truncated: continuation bit set, buffer ends. */
    const uint8_t trunc[] = {0x80};
    CHECK(zvarint_decode_u64(trunc, sizeof trunc, &v, &c, 0)
          == ZVARINT_ERR_TRUNCATED);

    /* Overflow: 11 continuation bytes. */
    const uint8_t over[] = {0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0x01};
    CHECK(zvarint_decode_u64(over, sizeof over, &v, &c, 0)
          == ZVARINT_ERR_OVERFLOW);

    /* Overflow: 10th byte carries more than one payload bit. */
    const uint8_t over2[] = {0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0x02};
    CHECK(zvarint_decode_u64(over2, sizeof over2, &v, &c, 0)
          == ZVARINT_ERR_OVERFLOW);

    /* 10th byte exactly 0x01 is legal (UINT64_MAX). */
    const uint8_t max[] = {0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0x01};
    CHECK(zvarint_decode_u64(max, sizeof max, &v, &c, 0) == ZVARINT_OK);
    CHECK(v == UINT64_MAX && c == 10);

    /* Non-canonical: 0x80 0x00 means zero in two bytes. */
    const uint8_t noncanon[] = {0x80, 0x00};
    CHECK(zvarint_decode_u64(noncanon, 2, &v, &c, 0) == ZVARINT_OK);
    CHECK(v == 0 && c == 2);
    CHECK(zvarint_decode_u64(noncanon, 2, &v, &c, 1)
          == ZVARINT_ERR_NONCANONICAL);

    /* NULL arguments. */
    CHECK(zvarint_decode_u64(NULL, 1, &v, &c, 0) == ZVARINT_ERR_NULL);
    CHECK(zvarint_decode_u64(buf, 1, NULL, &c, 0) == ZVARINT_ERR_NULL);
    CHECK(zvarint_encode_u64(1, NULL, 10, NULL) == ZVARINT_ERR_NULL);

    /* Output capacity too small. */
    CHECK(zvarint_encode_u64(128, buf, 1, NULL) == ZVARINT_ERR_TRUNCATED);

    /* Trailing bytes after a varint are fine; consumed points past it. */
    const uint8_t seq[] = {0x01, 0x02, 0x03};
    CHECK(zvarint_decode_u64(seq, 3, &v, &c, 1) == ZVARINT_OK);
    CHECK(v == 1 && c == 1);
}

static uint64_t rng_state = 0x243f6a8885a308d3ull;
static uint64_t rng_next(void)
{
    rng_state ^= rng_state << 13;
    rng_state ^= rng_state >> 7;
    rng_state ^= rng_state << 17;
    return rng_state;
}

static void test_roundtrip(void)
{
    uint8_t buf[ZVARINT_MAX_LEN];
    size_t n, c;

    /* Boundary values: every 7-bit group edge. */
    for (int shift = 0; shift < 64; shift++) {
        uint64_t base = (shift == 63) ? UINT64_MAX : ((1ull << shift) - 1);
        for (int d = -1; d <= 1; d++) {
            uint64_t v = base + (uint64_t)d;
            if (d < 0 && base == 0) continue;
            CHECK(zvarint_encode_u64(v, buf, sizeof buf, &n) == ZVARINT_OK);
            CHECK(n == zvarint_len_u64(v));
            uint64_t back;
            CHECK(zvarint_decode_u64(buf, n, &back, &c, 1) == ZVARINT_OK);
            CHECK(back == v && c == n);
            /* Own encoding is always canonical under strict mode. */
            CHECK(zvarint_decode_u64(buf, n, &back, &c, 1) == ZVARINT_OK);
        }
    }

    /* Random unsigned. */
    for (int i = 0; i < 20000; i++) {
        uint64_t v = rng_next();
        /* Vary magnitude so small values get exercised too. */
        v >>= (rng_next() % 64);
        CHECK(zvarint_encode_u64(v, buf, sizeof buf, &n) == ZVARINT_OK);
        uint64_t back;
        CHECK(zvarint_decode_u64(buf, n, &back, &c, 1) == ZVARINT_OK);
        CHECK(back == v && c == n);
    }

    /* Random signed. */
    for (int i = 0; i < 20000; i++) {
        int64_t s = (int64_t)rng_next();
        s >>= (int)(rng_next() % 63);
        CHECK(zvarint_encode_i64(s, buf, sizeof buf, &n) == ZVARINT_OK);
        CHECK(n == zvarint_len_i64(s));
        int64_t back;
        CHECK(zvarint_decode_i64(buf, n, &back, &c, 1) == ZVARINT_OK);
        CHECK(back == s && c == n);
    }
}

static void test_err_str(void)
{
    CHECK(strcmp(zvarint_err_str(ZVARINT_OK), "ok") == 0);
    CHECK(strstr(zvarint_err_str(ZVARINT_ERR_TRUNCATED), "mid-varint") != NULL);
    CHECK(zvarint_err_str((zvarint_err)999) != NULL);
}

int main(void)
{
    test_known_vectors();
    test_zigzag();
    test_errors();
    test_roundtrip();
    test_err_str();
    puts("test_zvarint: all groups passed (vectors zigzag errors roundtrip errstr)");
    return 0;
}
