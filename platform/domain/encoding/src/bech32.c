/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2017 Pieter Wuille
 * Copyright 2026 Rhett Creighton
 *
 * Pure BIP-173 Bech32 codec. See platform/domain/encoding/bech32.h for the
 * contract; this file has no I/O, RNG, clock, or persistence.
 */

#include "domain/encoding/bech32.h"

#include <string.h>

/* Both entry points cap the whole string at 1023/1024 chars, so the checksum
 * scratch below was always bounded — but spelling it `uint8_t buf[total]` made
 * it a variable-length array, a stack allocation sized by a runtime value.
 * That is the construct `-Wvla` exists to forbid: if a future edit moves or
 * weakens the length check, a VLA becomes stack exhaustion while a fixed array
 * becomes a bounds check that fails loudly.
 *
 * Worst case for the expanded buffer is hrp_len*2 + 1 + values_len + 6 with
 * hrp_len + values_len <= 1022 and hrp_len maximal, i.e. 2051. */
#define BECH32_MAX_STRING 1024u
#define BECH32_SCRATCH    (2u * BECH32_MAX_STRING + 8u) /* 2056 */

static const char CHARSET[] = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";

static const int8_t CHARSET_REV[128] = {
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    15, -1, 10, 17, 21, 20, 26, 30,  7,  5, -1, -1, -1, -1, -1, -1,
    -1, 29, -1, 24, 13, 25,  9,  8, 23, -1, 18, 22, 31, 27, 19, -1,
     1,  0,  3, 16, 11, 28, 12, 14,  6,  4,  2, -1, -1, -1, -1, -1,
    -1, 29, -1, 24, 13, 25,  9,  8, 23, -1, 18, 22, 31, 27, 19, -1,
     1,  0,  3, 16, 11, 28, 12, 14,  6,  4,  2, -1, -1, -1, -1, -1
};

static uint32_t polymod(const uint8_t *values, size_t len)
{
    uint32_t c = 1;
    for (size_t i = 0; i < len; i++) {
        uint8_t c0 = c >> 25;
        c = ((c & 0x1ffffff) << 5) ^ values[i];
        if (c0 & 1)  c ^= 0x3b6a57b2;
        if (c0 & 2)  c ^= 0x26508e6d;
        if (c0 & 4)  c ^= 0x1ea119fa;
        if (c0 & 8)  c ^= 0x3d4233dd;
        if (c0 & 16) c ^= 0x2a1462b3;
    }
    return c;
}

static size_t expand_hrp(const char *hrp, size_t hrp_len, uint8_t *out)
{
    for (size_t i = 0; i < hrp_len; i++)
        out[i] = (uint8_t)(hrp[i]) >> 5;
    out[hrp_len] = 0;
    for (size_t i = 0; i < hrp_len; i++)
        out[hrp_len + 1 + i] = (uint8_t)(hrp[i]) & 0x1f;
    return hrp_len * 2 + 1;
}

static bool create_checksum(const char *hrp, size_t hrp_len,
                             const uint8_t *values, size_t values_len,
                             uint8_t checksum[6])
{
    size_t exp_len = hrp_len * 2 + 1;
    size_t total = exp_len + values_len + 6;
    if (total > BECH32_SCRATCH)
        return false; /* unreachable given the caller's cap; never overflow */
    uint8_t buf[BECH32_SCRATCH];
    expand_hrp(hrp, hrp_len, buf);
    memcpy(buf + exp_len, values, values_len);
    memset(buf + exp_len + values_len, 0, 6);
    uint32_t mod = polymod(buf, total) ^ 1;
    for (size_t i = 0; i < 6; i++)
        checksum[i] = (mod >> (5 * (5 - i))) & 31;
    return true;
}

static bool verify_checksum(const char *hrp, size_t hrp_len,
                              const uint8_t *values, size_t values_len)
{
    size_t exp_len = hrp_len * 2 + 1;
    size_t total = exp_len + values_len;
    if (total > BECH32_SCRATCH)
        return false; /* unreachable given the caller's cap; never overflow */
    uint8_t buf[BECH32_SCRATCH];
    expand_hrp(hrp, hrp_len, buf);
    memcpy(buf + exp_len, values, values_len);
    return polymod(buf, total) == 1;
}

bool domain_encoding_bech32_encode(char *out, size_t out_size,
                                   const char *hrp, const uint8_t *values, size_t values_len)
{
    size_t hrp_len = strlen(hrp);
    size_t needed = hrp_len + 1 + values_len + 6 + 1;
    /* Symmetric with the 1023-char cap in bech32_decode: a string our own
     * decoder would reject is not worth building, and the cap bounds the
     * create_checksum stack VLA below (~2 KB worst case). */
    if (needed > BECH32_MAX_STRING)
        return false;
    if (needed > out_size)
        return false;

    uint8_t checksum[6];
    if (!create_checksum(hrp, hrp_len, values, values_len, checksum))
        return false;

    size_t pos = 0;
    memcpy(out, hrp, hrp_len);
    pos += hrp_len;
    out[pos++] = '1';
    for (size_t i = 0; i < values_len; i++) {
        if (values[i] >= 32) return false;
        out[pos++] = CHARSET[values[i]];
    }
    for (size_t i = 0; i < 6; i++)
        out[pos++] = CHARSET[checksum[i]];
    out[pos] = '\0';
    return true;
}

bool domain_encoding_bech32_decode(char *hrp_out, size_t hrp_size,
                                   uint8_t *data_out, size_t data_size, size_t *data_len,
                                   const char *str)
{
    size_t str_len = strlen(str);
    if (str_len > 1023)
        return false;

    bool has_lower = false, has_upper = false;
    for (size_t i = 0; i < str_len; i++) {
        unsigned char c = str[i];
        if (c < 33 || c > 126) return false;
        if (c >= 'a' && c <= 'z') has_lower = true;
        if (c >= 'A' && c <= 'Z') has_upper = true;
    }
    if (has_lower && has_upper)
        return false;

    size_t sep = 0;
    bool found = false;
    for (size_t i = str_len; i > 0; i--) {
        if (str[i - 1] == '1') {
            sep = i - 1;
            found = true;
            break;
        }
    }
    if (!found || sep == 0 || sep + 7 > str_len)
        return false;

    size_t hrp_len = sep;
    size_t vals_len = str_len - 1 - sep;

    if (hrp_len + 1 > hrp_size)
        return false;
    if (vals_len > BECH32_MAX_STRING)
        return false; /* unreachable given the 1023-char cap; never overflow */

    uint8_t values[BECH32_MAX_STRING];
    for (size_t i = 0; i < vals_len; i++) {
        unsigned char c = str[sep + 1 + i];
        if (c < 33 || c > 126) return false;
        int8_t rev = CHARSET_REV[c];
        if (rev == -1) return false;
        values[i] = (uint8_t)rev;
    }

    for (size_t i = 0; i < hrp_len; i++) {
        unsigned char c = str[i];
        hrp_out[i] = (c >= 'A' && c <= 'Z') ? (c - 'A') + 'a' : c;
    }
    hrp_out[hrp_len] = '\0';

    if (!verify_checksum(hrp_out, hrp_len, values, vals_len))
        return false;

    size_t result_len = vals_len - 6;
    if (data_len)
        *data_len = result_len;
    if (result_len > data_size)
        return false;

    memcpy(data_out, values, result_len);
    return true;
}
