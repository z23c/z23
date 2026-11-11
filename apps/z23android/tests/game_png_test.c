/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#include "util/png_writer.h"
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <zlib.h>

typedef bool (*encode_fn)(const uint8_t *, uint32_t, uint32_t, uint8_t *, size_t, size_t *);

static uint32_t big_endian(const uint8_t *p)
{
    return (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 | (uint32_t)p[2] << 8 | p[3];
}

static void unchanged(const uint8_t *output, size_t n)
{
    for (size_t i = 0; i < n; ++i) assert(output[i] == 0xa5);
}

static bool ihdr_matches(const uint8_t *chunk, uint32_t len, uint32_t width, uint32_t height,
                         size_t channels)
{
    return len == 13 && big_endian(chunk) == width && big_endian(chunk + 4) == height &&
        chunk[8] == 8 && chunk[9] == (channels == 4 ? 6 : 2);
}

static void walk_chunks(const uint8_t *output, size_t written, uint32_t width, uint32_t height,
                        size_t channels, size_t *idat, size_t *idat_len)
{
    size_t pos = 8;
    unsigned ihdr = 0, data = 0, end = 0;
    *idat = 0;
    *idat_len = 0;
    while (pos < written) {
        assert(written - pos >= 12);
        uint32_t len = big_endian(output + pos);
        assert(len <= written - pos - 12);
        uLong crc = crc32(0, NULL, 0);
        crc = crc32(crc, output + pos + 4, len + 4);
        assert((uint32_t)crc == big_endian(output + pos + 8 + len));
        if (!memcmp(output + pos + 4, "IHDR", 4)) {
            ++ihdr;
            assert(ihdr_matches(output + pos + 8, len, width, height, channels));
        } else if (!memcmp(output + pos + 4, "IDAT", 4)) {
            ++data;
            *idat = pos + 8;
            *idat_len = len;
        } else if (!memcmp(output + pos + 4, "IEND", 4)) {
            ++end;
            assert(len == 0);
        }
        pos += len + 12;
    }
    assert(pos == written && ihdr == 1 && data == 1 && end == 1 && *idat_len);
}

static void pixels_match(const uint8_t *pixels, const uint8_t *filtered, uint32_t width,
                         uint32_t height, size_t channels)
{
    size_t row = (size_t)width * channels;
    for (uint32_t y = 0; y < height; ++y) {
        assert(filtered[y * (row + 1)] == 0);
        assert(!memcmp(filtered + y * (row + 1) + 1, pixels + y * row, row));
    }
}

static void verify(const uint8_t *pixels, uint32_t width, uint32_t height,
                   size_t channels, encode_fn encode)
{
    size_t filtered_len = ((size_t)width * channels + 1) * height;
    size_t cap = (size_t)width * height * channels + 65536;
    uint8_t *output = malloc(cap), *filtered = malloc(filtered_len);
    assert(output && filtered);
    size_t queried = 0, written = 0, idat = 0, idat_len = 0;
    assert(encode(pixels, width, height, NULL, 0, &queried) && queried > 57 && queried < cap);
    memset(output, 0xa5, cap);
    assert(!encode(pixels, width, height, output, queried - 1, &written));
    assert(written == queried);
    unchanged(output, queried - 1);
    assert(encode(pixels, width, height, output, cap, &written) && written == queried);
    static const uint8_t signature[] = {137, 80, 78, 71, 13, 10, 26, 10};
    assert(!memcmp(output, signature, sizeof(signature)));
    walk_chunks(output, written, width, height, channels, &idat, &idat_len);
    uLongf decoded_len = filtered_len;
    assert(uncompress(filtered, &decoded_len, output + idat, idat_len) == Z_OK);
    assert(decoded_len == filtered_len);
    pixels_match(pixels, filtered, width, height, channels);
    printf("game PNG %ux%u channels=%zu bytes=%zu\n", width, height, channels, written);
    if (width == 640) assert(written < 700000);
    free(filtered);
    free(output);
}

static void run(uint32_t width, uint32_t height, size_t channels)
{
    size_t count = (size_t)width * height;
    uint8_t *pixels = malloc(count * channels);
    assert(pixels);
    uint32_t random = 0x12345678;
    for (uint32_t y = 0; y < height; ++y) {
        for (uint32_t x = 0; x < width; ++x) {
            random ^= random << 13;
            random ^= random >> 17;
            random ^= random << 5;
            for (size_t c = 0; c < channels; ++c) {
                uint8_t value = (uint8_t)random;
                if (y < height / 2) value = (uint8_t)((x & 15) * 16 + c * 17);
                else if (y < height * 3 / 4) value = (uint8_t)(y + c * 31);
                pixels[((size_t)y * width + x) * channels + c] = value;
            }
        }
    }
    verify(pixels, width, height, channels, channels == 4 ? png_encode_rgba : png_encode_rgb);
    free(pixels);
}

static void invalid_leaves_destination(void)
{
    static const uint8_t pixels[] = {1, 2, 3, 4, 5, 6};
    uint8_t output[32];
    memset(output, 0xa5, sizeof(output));
    size_t written = 123;
    assert(!png_encode_rgb(NULL, 1, 1, output, sizeof(output), &written));
    assert(written == 0);
    unchanged(output, sizeof(output));
    written = 123;
    assert(!png_encode_rgb(pixels, 0, 1, output, sizeof(output), &written));
    assert(written == 0);
    unchanged(output, sizeof(output));
    written = 123;
    assert(!png_encode_rgb(pixels, 1, 0, output, sizeof(output), &written));
    assert(written == 0);
    unchanged(output, sizeof(output));
    assert(!png_encode_rgb(pixels, 1, 1, output, sizeof(output), NULL));
    unchanged(output, sizeof(output));
    written = 123;
    assert(!png_encode_rgba(NULL, 1, 1, output, sizeof(output), &written));
    assert(written == 0);
    unchanged(output, sizeof(output));
}

int main(void)
{
    invalid_leaves_destination();
    run(1, 1, 3);
    run(1, 1, 4);
    run(2, 3, 3);
    run(2, 3, 4);
    run(640, 360, 3);
    run(640, 360, 4);
    puts("game PNG tests passed");
    return 0;
}
