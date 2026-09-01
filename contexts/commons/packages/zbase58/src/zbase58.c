#include "zbase58/zbase58.h"

#include <string.h>

static const char ALPHABET[58] =
    "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

size_t zbase58_encoded_max(size_t bin_len)
{
    /* log(256)/log(58) ≈ 1.366; +2 covers rounding and terminator. */
    return bin_len * 138 / 100 + 2;
}

size_t zbase58_decoded_max(size_t b58_len)
{
    /* log(58)/log(256) ≈ 0.733. */
    return b58_len * 733 / 1000 + 1;
}

int zbase58_char_value(char c)
{
    const char *p = memchr(ALPHABET, c, sizeof ALPHABET);
    return p ? (int)(p - ALPHABET) : -1;
}

zbase58_err zbase58_encode(const uint8_t *bin, size_t bin_len,
                           char *out, size_t cap, size_t *out_len)
{
    if (!out || !out_len) return ZBASE58_ERR_NULL;
    if (!bin && bin_len > 0) return ZBASE58_ERR_NULL;

    /* Count leading zero bytes. */
    size_t zeros = 0;
    while (zeros < bin_len && bin[zeros] == 0) zeros++;

    /* Big-endian base-256 to base-58 via repeated division.
     * Worst-case b58 digits bounded by encoded_max. */
    size_t max_digits = zbase58_encoded_max(bin_len);
    if (cap < 1) return ZBASE58_ERR_SMALL;

    /* Work on a bounded digit buffer (value per digit 0..57). */
    uint8_t digits[1024 * 8]; /* generous stack bound */
    if (max_digits > sizeof digits) return ZBASE58_ERR_SMALL;

    size_t ndigits = 0;
    for (size_t i = zeros; i < bin_len; i++) {
        uint32_t carry = bin[i];
        for (size_t j = 0; j < ndigits; j++) {
            carry += (uint32_t)digits[j] << 8;
            digits[j] = (uint8_t)(carry % 58);
            carry /= 58;
        }
        while (carry > 0) {
            if (ndigits >= sizeof digits) return ZBASE58_ERR_SMALL;
            digits[ndigits++] = (uint8_t)(carry % 58);
            carry /= 58;
        }
    }

    size_t need = zeros + ndigits + 1; /* leading '1's + digits + NUL */
    if (cap < need) {
        *out_len = need - 1;
        return ZBASE58_ERR_SMALL;
    }

    size_t o = 0;
    for (size_t i = 0; i < zeros; i++) out[o++] = '1';
    for (size_t i = 0; i < ndigits; i++)
        out[o++] = ALPHABET[digits[ndigits - 1 - i]];
    out[o] = '\0';
    *out_len = o;
    return ZBASE58_OK;
}

zbase58_err zbase58_decode(const char *b58, size_t b58_len,
                           uint8_t *out, size_t cap,
                           size_t *out_len, size_t *bad_pos)
{
    if (!b58 || !out_len) return ZBASE58_ERR_NULL;
    if (!out && b58_len > 0) return ZBASE58_ERR_NULL;
    if (bad_pos) *bad_pos = 0;

    /* Count leading '1's -> leading zero bytes. */
    size_t ones = 0;
    while (ones < b58_len && b58[ones] == '1') ones++;

    uint8_t bytes[1024 * 6];
    if (zbase58_decoded_max(b58_len) > sizeof bytes)
        return ZBASE58_ERR_SMALL;

    size_t nbytes = 0;
    for (size_t i = ones; i < b58_len; i++) {
        int val = zbase58_char_value(b58[i]);
        if (val < 0) {
            if (bad_pos) *bad_pos = i;
            return ZBASE58_ERR_BAD_CHAR;
        }
        uint32_t carry = (uint32_t)val;
        for (size_t j = 0; j < nbytes; j++) {
            carry += (uint32_t)bytes[j] * 58;
            bytes[j] = (uint8_t)(carry & 0xff);
            carry >>= 8;
        }
        while (carry > 0) {
            if (nbytes >= sizeof bytes) return ZBASE58_ERR_SMALL;
            bytes[nbytes++] = (uint8_t)(carry & 0xff);
            carry >>= 8;
        }
    }

    size_t need = ones + nbytes;
    if (cap < need) return ZBASE58_ERR_SMALL;

    size_t o = 0;
    for (size_t i = 0; i < ones; i++) out[o++] = 0;
    for (size_t i = 0; i < nbytes; i++)
        out[o++] = bytes[nbytes - 1 - i];
    *out_len = o;
    return ZBASE58_OK;
}

const char *zbase58_err_str(zbase58_err e)
{
    switch (e) {
    case ZBASE58_OK:          return "ok";
    case ZBASE58_ERR_NULL:    return "null argument";
    case ZBASE58_ERR_SMALL:   return "output buffer too small";
    case ZBASE58_ERR_BAD_CHAR: return "character outside Base58 alphabet";
    }
    return "unknown error";
}
