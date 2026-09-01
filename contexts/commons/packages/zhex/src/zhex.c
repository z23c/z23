#include "zhex/zhex.h"

#include <string.h>

static const char LOWER_DIGITS[16] = "0123456789abcdef";
static const char UPPER_DIGITS[16] = "0123456789ABCDEF";

size_t zhex_encoded_len(size_t bin_len)
{
    return bin_len * 2u;
}

size_t zhex_decoded_len(size_t hex_len)
{
    return hex_len / 2u;
}

int zhex_digit_value(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static zhex_err encode_with(const uint8_t *bin, size_t bin_len, char *out,
                            const char digits[16])
{
    if (!out) return ZHEX_ERR_NULL;
    if (!bin && bin_len > 0) return ZHEX_ERR_NULL;
    for (size_t i = 0; i < bin_len; i++) {
        out[2 * i]     = digits[bin[i] >> 4];
        out[2 * i + 1] = digits[bin[i] & 0x0f];
    }
    return ZHEX_OK;
}

zhex_err zhex_encode(const uint8_t *bin, size_t bin_len, char *out)
{
    return encode_with(bin, bin_len, out, LOWER_DIGITS);
}

zhex_err zhex_encode_upper(const uint8_t *bin, size_t bin_len, char *out)
{
    return encode_with(bin, bin_len, out, UPPER_DIGITS);
}

zhex_err zhex_decode(const char *hex, size_t hex_len,
                     uint8_t *out, size_t *bad_pos)
{
    if (bad_pos) *bad_pos = 0;
    if (!hex) return ZHEX_ERR_NULL;
    if (!out && hex_len > 0) return ZHEX_ERR_NULL;
    if (hex_len % 2u != 0) return ZHEX_ERR_ODD_LEN;
    for (size_t i = 0; i < hex_len; i += 2) {
        int hi = zhex_digit_value(hex[i]);
        int lo = zhex_digit_value(hex[i + 1]);
        if (hi < 0 || lo < 0) {
            if (bad_pos) *bad_pos = (hi < 0) ? i : i + 1;
            return ZHEX_ERR_BAD_CHAR;
        }
        out[i / 2] = (uint8_t)((hi << 4) | lo);
    }
    return ZHEX_OK;
}

zhex_err zhex_decode_cstr(const char *hex, uint8_t *out, size_t *bad_pos)
{
    if (!hex) return ZHEX_ERR_NULL;
    return zhex_decode(hex, strlen(hex), out, bad_pos);
}

const char *zhex_err_str(zhex_err e)
{
    switch (e) {
    case ZHEX_OK:           return "ok";
    case ZHEX_ERR_NULL:     return "null argument";
    case ZHEX_ERR_ODD_LEN:  return "odd input length";
    case ZHEX_ERR_BAD_CHAR: return "non-hex character";
    case ZHEX_ERR_SMALL:    return "output buffer too small";
    }
    return "unknown error";
}
