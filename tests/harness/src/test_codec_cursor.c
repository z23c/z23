/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: atomicity, truncation, bounds, and round-trip cursor proofs. */
#include "test/test_core.h"
#include "codec/cursor.h"
#include <stdint.h>
#include <string.h>

static int codec_test_kat(void)
{
    int failures = 0;
    TEST("codec cursor: fixed-width little-endian KAT and exact capacity") {
        uint8_t wire[27];
        struct zcl_codec_writer w;
        zcl_codec_writer_init(&w, wire, sizeof(wire));
        ASSERT(zcl_codec_write_u8(&w, 0xa5));
        ASSERT(zcl_codec_write_u16le(&w, 0x1234));
        ASSERT(zcl_codec_write_u32le(&w, UINT32_C(0x89abcdef)));
        ASSERT(zcl_codec_write_u64le(&w, UINT64_C(0x0123456789abcdef)));
        ASSERT(zcl_codec_write_i32le(&w, -2));
        ASSERT(zcl_codec_write_i64le(&w, INT64_MIN));
        size_t written = 0;
        ASSERT(zcl_codec_writer_finish(&w, &written) && written == sizeof(wire));
        static const uint8_t want[27] = {
            0xa5, 0x34, 0x12, 0xef, 0xcd, 0xab, 0x89,
            0xef, 0xcd, 0xab, 0x89, 0x67, 0x45, 0x23, 0x01,
            0xfe, 0xff, 0xff, 0xff,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80,
        };
        ASSERT(memcmp(wire, want, sizeof(want)) == 0);
        struct zcl_codec_reader r;
        zcl_codec_reader_init(&r, wire, sizeof(wire));
        uint8_t a; uint16_t b; uint32_t c; uint64_t d; int32_t e; int64_t f;
        ASSERT(zcl_codec_read_u8(&r, &a) && a == 0xa5);
        ASSERT(zcl_codec_read_u16le(&r, &b) && b == 0x1234);
        ASSERT(zcl_codec_read_u32le(&r, &c) && c == UINT32_C(0x89abcdef));
        ASSERT(zcl_codec_read_u64le(&r, &d) && d == UINT64_C(0x0123456789abcdef));
        ASSERT(zcl_codec_read_i32le(&r, &e) && e == -2);
        ASSERT(zcl_codec_read_i64le(&r, &f) && f == INT64_MIN);
        ASSERT(zcl_codec_reader_finish(&r));
        PASS();
    } _test_next:;
    return failures;
}

static int codec_test_failures(void)
{
    int failures = 0;
    TEST("codec cursor: truncation, sticky errors, atomic failure and trailing data") {
        uint8_t canonical[32];
        struct zcl_codec_writer w;
        zcl_codec_writer_init(&w, canonical, sizeof(canonical));
        ASSERT(zcl_codec_write_u16_string(&w, "foundation", 10));
        ASSERT(zcl_codec_write_u64le(&w, 99));
        size_t length = 0;
        ASSERT(zcl_codec_writer_finish(&w, &length));
        for (size_t cut = 0; cut < length; cut++) {
            struct zcl_codec_reader r;
            char text[16]; memset(text, 0x5a, sizeof(text));
            uint16_t text_len = 77; uint64_t number = 88;
            zcl_codec_reader_init(&r, canonical, cut);
            bool ok = zcl_codec_read_u16_string(&r, text, sizeof(text),
                                                &text_len) &&
                      zcl_codec_read_u64le(&r, &number) &&
                      zcl_codec_reader_finish(&r);
            ASSERT(!ok);
        }
        uint8_t canary[6]; memset(canary, 0x6d, sizeof(canary));
        zcl_codec_writer_init(&w, canary + 1, 4);
        ASSERT(zcl_codec_write_u8(&w, 1));
        size_t before = w.position;
        uint8_t snapshot[6]; memcpy(snapshot, canary, sizeof(canary));
        ASSERT(!zcl_codec_write_u32le(&w, 7));
        ASSERT(w.position == before && memcmp(canary, snapshot, sizeof(canary)) == 0);
        ASSERT(w.error == ZCL_CODEC_BOUNDS);
        ASSERT(!zcl_codec_write_u8(&w, 2) && w.position == before);
        uint8_t short_prefix[1] = {0};
        struct zcl_codec_reader short_reader;
        uint16_t untouched_len = 77;
        zcl_codec_reader_init(&short_reader, short_prefix,
                              sizeof(short_prefix));
        ASSERT(!zcl_codec_read_u16_bytes(&short_reader, NULL, 0,
                                         &untouched_len));
        ASSERT(short_reader.error == ZCL_CODEC_BOUNDS &&
               short_reader.position == 0 && untouched_len == 77);
        uint8_t empty_wire[2] = {0, 0};
        struct zcl_codec_reader empty_reader;
        zcl_codec_reader_init(&empty_reader, empty_wire, sizeof(empty_wire));
        ASSERT(zcl_codec_read_u16_bytes(&empty_reader, NULL, 0,
                                        &untouched_len));
        ASSERT(untouched_len == 0 && zcl_codec_reader_finish(&empty_reader));
        struct zcl_codec_reader trailing;
        zcl_codec_reader_init(&trailing, canonical, length);
        char text[16]; uint16_t text_len;
        ASSERT(zcl_codec_read_u16_string(&trailing, text, sizeof(text), &text_len));
        ASSERT(!zcl_codec_reader_finish(&trailing));
        ASSERT(trailing.error == ZCL_CODEC_TRAILING);
        PASS();
    } _test_next:;
    return failures;
}

static int codec_test_properties(void)
{
    int failures = 0;
    TEST("codec cursor: length overflow and deterministic property round trips") {
        uint8_t storage[256]; struct zcl_codec_writer w;
        memset(storage, 0x4c, sizeof(storage));
        zcl_codec_writer_init(&w, storage, sizeof(storage));
        ASSERT(!zcl_codec_write_u16_bytes(&w, storage, (size_t)UINT16_MAX + 1u));
        ASSERT(w.error == ZCL_CODEC_LENGTH && w.position == 0);
        for (uint32_t seed = 1; seed <= 1000; seed++) {
            uint32_t x = seed * UINT32_C(747796405) + UINT32_C(2891336453);
            uint64_t y = ((uint64_t)x << 32) | (x ^ UINT32_C(0xa5a5a5a5));
            size_t n = x % 31u; uint8_t bytes[31], decoded[31];
            for (size_t i = 0; i < n; i++) bytes[i] = (uint8_t)(x + i);
            zcl_codec_writer_init(&w, storage, sizeof(storage));
            ASSERT(zcl_codec_write_u32le(&w, x));
            ASSERT(zcl_codec_write_u64le(&w, y));
            ASSERT(zcl_codec_write_u16_bytes(&w, bytes, n));
            size_t used = 0; ASSERT(zcl_codec_writer_finish(&w, &used));
            struct zcl_codec_reader r; zcl_codec_reader_init(&r, storage, used);
            uint32_t rx; uint64_t ry; uint16_t got = 99;
            memset(decoded, 0, sizeof(decoded));
            ASSERT(zcl_codec_read_u32le(&r, &rx) && rx == x);
            ASSERT(zcl_codec_read_u64le(&r, &ry) && ry == y);
            ASSERT(zcl_codec_read_u16_bytes(&r, decoded, sizeof(decoded), &got));
            ASSERT(got == n && memcmp(bytes, decoded, got) == 0);
            ASSERT(zcl_codec_reader_finish(&r));
        }
        PASS();
    } _test_next:;
    return failures;
}

int test_codec_cursor(void)
{
    return codec_test_kat() + codec_test_failures() + codec_test_properties();
}
