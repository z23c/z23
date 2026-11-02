/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: atomicity, truncation, bounds, and round-trip cursor proofs. */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "test/test_core.h"
#include "codec/cursor.h"
#include <stdint.h>
#include <string.h>
#if !defined(_WIN32)
#include <sys/mman.h>
#include <sys/wait.h>
#endif

#if !defined(_WIN32)
static void codec_guarded_child(const char *source)
{
    alarm(5);
    uint8_t wire[2] = {0x5a, 0x5a};
    struct zcl_codec_writer w;
    const size_t lengths[2] = {(size_t)UINT16_MAX + 1u, SIZE_MAX};
    for (size_t i = 0; i < 2; i++) {
        zcl_codec_writer_init(&w, wire, sizeof(wire));
        if (zcl_codec_write_u16_string(&w, source, lengths[i]) ||
            w.error != ZCL_CODEC_LENGTH || w.position != 0 ||
            wire[0] != 0x5a || wire[1] != 0x5a) _exit(1);
    }
    w.error = ZCL_CODEC_BOUNDS;
    if (zcl_codec_write_u16_string(&w, source, 2) ||
        w.error != ZCL_CODEC_BOUNDS || w.position != 0 ||
        wire[0] != 0x5a || wire[1] != 0x5a) _exit(2);
    if (zcl_codec_write_u16_string(NULL, source, 2)) _exit(3);
    _exit(0);
}
#endif

static bool codec_guarded_refusals(void)
{
#if !defined(_WIN32)
    long page = sysconf(_SC_PAGESIZE);
    if (page <= 0 || (size_t)page > SIZE_MAX / 2u) return false;
    size_t extent = (size_t)page * 2u;
    char *mapping = mmap(NULL, extent, PROT_READ | PROT_WRITE,
                         MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (mapping == MAP_FAILED) return false;
    if (mprotect(mapping + page, (size_t)page, PROT_NONE) != 0) {
        (void)munmap(mapping, extent);
        return false;
    }
    mapping[page - 1] = 'x';
    pid_t child = fork();
    if (child == 0) codec_guarded_child(mapping + page - 1);
    int status = 0;
    pid_t waited = -1;
    if (child > 0) {
        do { waited = waitpid(child, &status, 0); }
        while (waited < 0 && errno == EINTR);
    }
    bool unmapped = munmap(mapping, extent) == 0;
    return unmapped && child > 0 && waited == child &&
           WIFEXITED(status) && WEXITSTATUS(status) == 0;
#else
    /* This required protected-page witness cannot pass without execution. */
    return false;
#endif
}

static int codec_test_string_bounds(void)
{
    int failures = 0;
    TEST("codec cursor: refuse impossible strings before scanning") {
        static char source[65536];
        memset(source, 'x', sizeof(source));
        source[65535] = '\0';
        uint8_t wire[2] = {0x5a, 0x5a};
        struct zcl_codec_writer w;
        zcl_codec_writer_init(&w, wire, sizeof(wire));
        ASSERT(!zcl_codec_write_u16_string(&w, source, sizeof(source)));
        ASSERT(w.error == ZCL_CODEC_LENGTH && w.position == 0);
        ASSERT(wire[0] == 0x5a && wire[1] == 0x5a);
        PASS();
    } _test_next:;
    return failures;
}

static int codec_test_string_controls(void)
{
    int failures = 0;
    TEST("codec cursor: string refusal guard and in-range controls") {
        ASSERT(codec_guarded_refusals());
        uint8_t wire[4] = {0x5a, 0x5a, 0x5a, 0x5a};
        struct zcl_codec_writer w;
        zcl_codec_writer_init(&w, wire + 1, 2);
        ASSERT(zcl_codec_write_u16_string(&w, NULL, 0) && w.position == 2);
        ASSERT(wire[0] == 0x5a && wire[1] == 0 && wire[2] == 0 && wire[3] == 0x5a);
        zcl_codec_writer_init(&w, wire, sizeof(wire));
        ASSERT(zcl_codec_write_u16_string(&w, "xy", 2) && w.position == 4);
        ASSERT(wire[0] == 2 && wire[1] == 0 && wire[2] == 'x' && wire[3] == 'y');
        uint8_t before[4]; memcpy(before, wire, sizeof(wire));
        zcl_codec_writer_init(&w, wire, sizeof(wire));
        ASSERT(!zcl_codec_write_u16_string(&w, "x\0", 2));
        ASSERT(w.error == ZCL_CODEC_INVALID && w.position == 0);
        ASSERT(memcmp(wire, before, sizeof(wire)) == 0);
        zcl_codec_writer_init(&w, wire, 3);
        ASSERT(!zcl_codec_write_u16_string(&w, "xy", 2));
        ASSERT(w.error == ZCL_CODEC_BOUNDS && w.position == 0);
        ASSERT(memcmp(wire, before, sizeof(wire)) == 0);
        PASS();
    } _test_next:;
    return failures;
}

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

static int codec_test_invalid_buffer_guidance(void)
{
    int failures = 0;
    TEST("codec cursor: invalid buffer guidance and sticky refusal") {
        struct zcl_codec_reader r;
        uint8_t out = 77;
        zcl_codec_reader_init(&r, NULL, 1);
        ASSERT(!zcl_codec_read_u8(&r, &out));
        ASSERT(r.error == ZCL_CODEC_INVALID);
        ASSERT(r.position == 0 && out == 77);
        const char *message = zcl_codec_error_string(r.error);
        ASSERT(strstr(message, "buffer"));
        ASSERT(strstr(message, "non-NULL"));
        ASSERT(strstr(message, "nonzero length"));
        ASSERT(strstr(message, "reinitialize"));
        ASSERT(!zcl_codec_read_u8(&r, &out));
        ASSERT(r.error == ZCL_CODEC_INVALID && r.position == 0 && out == 77);
        uint8_t input = 23;
        zcl_codec_reader_init(&r, &input, 1);
        ASSERT(zcl_codec_read_u8(&r, &out) && out == input);
        ASSERT(zcl_codec_reader_finish(&r));
        PASS();
    } _test_next:;
    return failures;
}

static int codec_test_invalid_output_guidance(void)
{
    int failures = 0;
    TEST("codec cursor: invalid output guidance and retained input") {
        struct zcl_codec_reader r;
        uint8_t input = 23, out = 77;
        zcl_codec_reader_init(&r, &input, 1);
        ASSERT(!zcl_codec_read_u8(&r, NULL));
        ASSERT(r.error == ZCL_CODEC_INVALID && r.position == 0);
        const char *message = zcl_codec_error_string(r.error);
        ASSERT(strstr(message, "output"));
        ASSERT(strstr(message, "non-NULL"));
        ASSERT(strstr(message, "reinitialize"));
        ASSERT(!zcl_codec_read_u8(&r, &out));
        ASSERT(r.error == ZCL_CODEC_INVALID && r.position == 0);
        ASSERT(input == 23 && out == 77);
        PASS();
    } _test_next:;
    return failures;
}

static int codec_test_invalid_string_guidance(void)
{
    int failures = 0;
    TEST("codec cursor: embedded NUL guidance and atomic refusal") {
        const uint8_t input[4] = {2, 0, 'x', 0};
        struct zcl_codec_reader r;
        char out[3] = {'a', 'b', 'c'};
        uint16_t length = 77;
        zcl_codec_reader_init(&r, input, sizeof(input));
        ASSERT(!zcl_codec_read_u16_string(&r, out, sizeof(out), &length));
        ASSERT(r.error == ZCL_CODEC_INVALID && r.position == 0);
        ASSERT(memcmp(out, "abc", sizeof(out)) == 0 && length == 77);
        const char *message = zcl_codec_error_string(r.error);
        ASSERT(strstr(message, "remove embedded NUL"));
        ASSERT(strstr(message, "reinitialize"));
        ASSERT(!zcl_codec_read_u16_string(&r, out, sizeof(out), &length));
        ASSERT(r.error == ZCL_CODEC_INVALID && r.position == 0);
        ASSERT(memcmp(out, "abc", sizeof(out)) == 0 && length == 77);
        PASS();
    } _test_next:;
    return failures;
}

static int codec_test_take(void)
{
    int failures = 0;
    TEST("codec cursor: zero-copy take is bounded and sticky") {
        const uint8_t input[4] = {1, 2, 3, 4};
        struct zcl_codec_reader r;
        zcl_codec_reader_init(&r, input, sizeof(input));
        const uint8_t *p = zcl_codec_take(&r, 4);
        ASSERT(p == input && r.position == 4 && r.error == ZCL_CODEC_OK);
        ASSERT(zcl_codec_take(&r, 0) == input + 4);
        ASSERT(r.error == ZCL_CODEC_OK && r.position == 4);
        ASSERT(zcl_codec_take(&r, 1) == NULL);
        ASSERT(r.error == ZCL_CODEC_BOUNDS && r.position == 4);

        zcl_codec_reader_init(&r, input, sizeof(input));
        ASSERT(zcl_codec_take(&r, 5) == NULL);
        ASSERT(r.error == ZCL_CODEC_BOUNDS && r.position == 0);
        ASSERT(zcl_codec_take(&r, 0) == NULL);
        ASSERT(zcl_codec_take(&r, 1) == NULL);
        ASSERT(r.error == ZCL_CODEC_BOUNDS && r.position == 0);

        zcl_codec_reader_init(&r, input, sizeof(input));
        ASSERT(zcl_codec_take(&r, 3) == input);
        ASSERT(zcl_codec_take(&r, 2) == NULL && r.position == 3);
        ASSERT(zcl_codec_take(&r, SIZE_MAX) == NULL);
        ASSERT(zcl_codec_take(NULL, 1) == NULL);
        PASS();
    } _test_next:;
    return failures;
}

int test_codec_cursor(void)
{
    return codec_test_take() + codec_test_kat() + codec_test_failures() + codec_test_properties() +
           codec_test_string_bounds() + codec_test_string_controls() +
           codec_test_invalid_buffer_guidance() +
           codec_test_invalid_output_guidance() + codec_test_invalid_string_guidance();
}
