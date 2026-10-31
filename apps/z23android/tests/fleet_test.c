/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#include "fleet.h"
#include "quirc.h"
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static uint32_t u32(const unsigned char *p)
{ return (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24; }

/* Fills out with n characters cycling through alphabet, then a terminator. */
static void fill(char *out, size_t n, const char *alphabet)
{
    size_t k = strlen(alphabet);
    for (size_t i = 0; i < n; ++i) out[i] = alphabet[i % k];
    out[n] = 0;
}

/* Encodes payload as a fleet receipt BMP, decodes the pixels with quirc and checks the payload. */
static void qr_roundtrip(const char *payload)
{
    size_t size = 0, n = strlen(payload);
    unsigned char *bmp = zapp_fleet_qr_bmp(payload, &size);
    assert(bmp && size >= 54 && bmp[0] == 'B' && bmp[1] == 'M');
    int side = (int)u32(bmp + 18);
    assert(side > 0 && u32(bmp + 22) == (uint32_t)side && u32(bmp + 10) == 54);
    size_t stride = ((size_t)side * 3 + 3) & ~(size_t)3;
    assert(size == 54 + stride * (size_t)side);
    struct quirc *q = quirc_new();
    assert(q && quirc_resize(q, side, side) == 0);
    int width, height;
    unsigned char *image = quirc_begin(q, &width, &height);
    assert(width == side && height == side);
    for (int y = 0; y < side; ++y) for (int x = 0; x < side; ++x)
        image[y * side + x] = bmp[54 + (size_t)(side - 1 - y) * stride + (size_t)x * 3];
    quirc_end(q);
    assert(quirc_count(q) == 1);
    struct quirc_code code; struct quirc_data data;
    quirc_extract(q, 0, &code);
    assert(quirc_decode(&code, &data) == QUIRC_SUCCESS);
    assert(data.payload_len == (int)n);
    assert(memcmp(data.payload, payload, n) == 0);
    quirc_destroy(q); free(bmp);
}

int main(void)
{
    char token[8192], input[2334];
    memset(input, 'a', 200); input[200] = 0;
    assert(zapp_fleet_invite_text(input, token, sizeof(token)) && !strcmp(token, input));
    input[10] = ':';
    assert(!zapp_fleet_invite_text(input, token, sizeof(token)));
    assert(!zapp_fleet_invite_text("https://example.com/", token, sizeof(token)));
    char payload[201];
    fill(payload, 200, "abcdefghijklmnopqrstuvwx0123456789");
    qr_roundtrip(payload);
    fill(input, 2332, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_");
    assert(zapp_fleet_invite_text(input, token, sizeof(token)) && strlen(token) == 2332);
    qr_roundtrip(input);
    memset(input, 'a', 2333); input[2333] = 0;
    size_t size = 7;
    assert(!zapp_fleet_qr_bmp(input, &size));
    puts("fleet invitation and QR tests passed"); return 0;
}
