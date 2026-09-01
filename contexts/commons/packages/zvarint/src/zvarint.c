#include "zvarint/zvarint.h"

uint64_t zvarint_zigzag_encode(int64_t s)
{
    return ((uint64_t)s << 1) ^ (uint64_t)(s >> 63);
}

int64_t zvarint_zigzag_decode(uint64_t v)
{
    return (int64_t)((v >> 1) ^ (uint64_t)(-(int64_t)(v & 1)));
}

size_t zvarint_len_u64(uint64_t v)
{
    size_t n = 1;
    while (v >= 0x80) {
        v >>= 7;
        n++;
    }
    return n;
}

size_t zvarint_len_i64(int64_t s)
{
    return zvarint_len_u64(zvarint_zigzag_encode(s));
}

zvarint_err zvarint_encode_u64(uint64_t v, uint8_t *out, size_t out_cap,
                               size_t *out_len)
{
    if (!out) return ZVARINT_ERR_NULL;
    size_t need = zvarint_len_u64(v);
    if (out_cap < need) return ZVARINT_ERR_TRUNCATED;
    size_t i = 0;
    do {
        uint8_t b = (uint8_t)(v & 0x7f);
        v >>= 7;
        if (v != 0) b |= 0x80;
        out[i++] = b;
    } while (v != 0);
    if (out_len) *out_len = i;
    return ZVARINT_OK;
}

zvarint_err zvarint_encode_i64(int64_t s, uint8_t *out, size_t out_cap,
                               size_t *out_len)
{
    return zvarint_encode_u64(zvarint_zigzag_encode(s), out, out_cap, out_len);
}

zvarint_err zvarint_decode_u64(const uint8_t *buf, size_t len,
                               uint64_t *value, size_t *consumed,
                               int strict_canonical)
{
    if (!buf || !value) return ZVARINT_ERR_NULL;
    uint64_t v = 0;
    size_t i = 0;
    for (;;) {
        if (i >= len) return ZVARINT_ERR_TRUNCATED;
        if (i >= ZVARINT_MAX_LEN) return ZVARINT_ERR_OVERFLOW;
        uint8_t b = buf[i];
        if (i == 9 && b > 1) /* 10th byte may only contribute 1 bit */
            return ZVARINT_ERR_OVERFLOW;
        v |= (uint64_t)(b & 0x7f) << (7 * i);
        i++;
        if ((b & 0x80) == 0) break;
    }
    if (strict_canonical && i > 1 && buf[i - 1] == 0)
        return ZVARINT_ERR_NONCANONICAL;
    *value = v;
    if (consumed) *consumed = i;
    return ZVARINT_OK;
}

zvarint_err zvarint_decode_i64(const uint8_t *buf, size_t len,
                               int64_t *value, size_t *consumed,
                               int strict_canonical)
{
    if (!value) return ZVARINT_ERR_NULL;
    uint64_t uv;
    zvarint_err e = zvarint_decode_u64(buf, len, &uv, consumed,
                                       strict_canonical);
    if (e != ZVARINT_OK) return e;
    *value = zvarint_zigzag_decode(uv);
    return ZVARINT_OK;
}

const char *zvarint_err_str(zvarint_err e)
{
    switch (e) {
    case ZVARINT_OK:              return "ok";
    case ZVARINT_ERR_NULL:        return "null argument";
    case ZVARINT_ERR_TRUNCATED:   return "buffer ended mid-varint";
    case ZVARINT_ERR_OVERFLOW:    return "more than 64 payload bits";
    case ZVARINT_ERR_NONCANONICAL: return "non-canonical encoding";
    }
    return "unknown error";
}
