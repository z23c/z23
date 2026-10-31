/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#include "fleet.h"
#include "qrcodegen.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

bool zapp_fleet_invite_char(char c)
{
    return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
           (c >= '0' && c <= '9') || c == '-' || c == '_';
}

bool zapp_fleet_invite_text(const char *text, char *token, size_t cap)
{
    static const char prefix[] = "z23 fleet join ";
    if (!text || !token || !cap) return false;
    token[0] = '\0';
    if (!strncmp(text, prefix, sizeof(prefix) - 1)) text += sizeof(prefix) - 1;
    size_t n = strlen(text);
    if (n < 128 || n > 2332 || n >= cap) return false;
    for (size_t i = 0; i < n; ++i) {
        if (!zapp_fleet_invite_char(text[i])) return false;
    }
    memcpy(token, text, n + 1);
    return true;
}

static void put32(unsigned char *out, uint32_t value)
{ for (unsigned i = 0; i < 4; ++i) out[i] = (unsigned char)(value >> (8 * i)); }

unsigned char *zapp_fleet_qr_bmp(const char *text, size_t *size)
{
    if (!text || !text[0] || !size || strlen(text) > 2332) return NULL;
    *size = 0;
    uint8_t temp[qrcodegen_BUFFER_LEN_MAX], code[qrcodegen_BUFFER_LEN_MAX];
    if (!qrcodegen_encodeText(text, temp, code, qrcodegen_Ecc_LOW,
                              qrcodegen_VERSION_MIN, qrcodegen_VERSION_MAX,
                              qrcodegen_Mask_AUTO, true)) return NULL;
    int count = qrcodegen_getSize(code), side = (count + 8) * 3;
    size_t stride = ((size_t)side * 3 + 3) & ~(size_t)3;
    size_t bytes = 54 + stride * (size_t)side;
    unsigned char *bmp = calloc(1, bytes);
    if (!bmp) return NULL;
    bmp[0] = 'B'; bmp[1] = 'M'; put32(bmp + 2, (uint32_t)bytes); put32(bmp + 10, 54);
    put32(bmp + 14, 40); put32(bmp + 18, (uint32_t)side); put32(bmp + 22, (uint32_t)side);
    bmp[26] = 1; bmp[28] = 24; put32(bmp + 34, (uint32_t)(stride * (size_t)side));
    for (int y = 0; y < side; ++y) for (int x = 0; x < side; ++x) {
        int qx = x / 3 - 4, qy = (side - 1 - y) / 3 - 4;
        unsigned char c = qx >= 0 && qy >= 0 && qx < count && qy < count &&
            qrcodegen_getModule(code, qx, qy) ? 0 : 255;
        size_t at = 54 + (size_t)y * stride + (size_t)x * 3;
        bmp[at] = bmp[at + 1] = bmp[at + 2] = c;
    }
    *size = bytes;
    return bmp;
}
