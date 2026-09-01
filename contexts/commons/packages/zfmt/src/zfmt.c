#include "zfmt/zfmt.h"

#include <string.h>

void zfmt_init(zfmt *f, char *buf, size_t cap)
{
    if (!f) return;
    f->buf = buf;
    f->cap = cap;
    f->len = 0;
    f->failed = !buf || cap == 0;
    if (!f->failed) buf[0] = '\0';
}

static bool append_raw(zfmt *f, const char *p, size_t n)
{
    if (f->failed) return false;
    if (n > f->cap - f->len - 1) { /* no room for bytes + NUL */
        /* Truncate to keep a valid partial string. */
        size_t room = f->cap - f->len - 1;
        if (room > 0 && p) {
            memcpy(f->buf + f->len, p, room);
            f->len += room;
            f->buf[f->len] = '\0';
        }
        f->failed = true;
        return false;
    }
    if (n > 0) {
        memcpy(f->buf + f->len, p, n);
        f->len += n;
        f->buf[f->len] = '\0';
    }
    return true;
}

bool zfmt_span(zfmt *f, const char *p, size_t len)
{
    if (!f) return false;
    if (!p && len > 0) { f->failed = true; return false; }
    return append_raw(f, p, len);
}

bool zfmt_str(zfmt *f, const char *s)
{
    if (!f) return false;
    if (!s) { f->failed = true; return false; }
    return append_raw(f, s, strlen(s));
}

bool zfmt_char(zfmt *f, char c)
{
    if (!f) return false;
    return append_raw(f, &c, 1);
}

bool zfmt_u64(zfmt *f, uint64_t v)
{
    if (!f) return false;
    char tmp[20];
    int n = 0;
    do {
        tmp[n++] = (char)('0' + v % 10);
        v /= 10;
    } while (v != 0);
    char rev[20];
    for (int i = 0; i < n; i++) rev[i] = tmp[n - 1 - i];
    return append_raw(f, rev, (size_t)n);
}

bool zfmt_i64(zfmt *f, int64_t v)
{
    if (!f) return false;
    if (v < 0) {
        /* INT64_MIN-safe: negate via unsigned. */
        uint64_t mag = (uint64_t)(-(v + 1)) + 1;
        return append_raw(f, "-", 1) && zfmt_u64(f, mag);
    }
    return zfmt_u64(f, (uint64_t)v);
}

bool zfmt_hex64(zfmt *f, uint64_t v)
{
    if (!f) return false;
    static const char digits[] = "0123456789abcdef";
    char tmp[16];
    for (int i = 0; i < 16; i++)
        tmp[i] = digits[(v >> (60 - 4 * i)) & 0x0f];
    return append_raw(f, tmp, 16);
}

bool zfmt_u64_pad(zfmt *f, uint64_t v, unsigned width)
{
    if (!f) return false;
    char tmp[20];
    int n = 0;
    do {
        tmp[n++] = (char)('0' + v % 10);
        v /= 10;
    } while (v != 0);
    if (width > 64) width = 64;
    for (unsigned i = (unsigned)n; i < width; i++)
        if (!zfmt_char(f, '0')) return false;
    char rev[20];
    for (int i = 0; i < n; i++) rev[i] = tmp[n - 1 - i];
    return append_raw(f, rev, (size_t)n);
}

bool zfmt_double(zfmt *f, double v, unsigned precision)
{
    if (!f) return false;
    if (precision > 9) precision = 9;

    if (v != v) return append_raw(f, "nan", 3);
    if (v > 1.7976931348623157e308) return append_raw(f, "inf", 3);
    if (v < -1.7976931348623157e308) return append_raw(f, "-inf", 4);

    bool neg = v < 0;
    if (neg) v = -v;

    /* This is fixed-point formatting with 53-bit mantissa precision;
     * good for values up to about 2^53 / 10^precision. */
    if (v > 9007199254740992.0) return append_raw(f, "huge", 4);

    uint64_t scale = 1;
    for (unsigned i = 0; i < precision; i++) scale *= 10;
    uint64_t scaled = (uint64_t)(v * (double)scale + 0.5); /* round half up */
    uint64_t whole = scaled / scale;
    uint64_t frac = scaled % scale;

    bool ok = true;
    if (neg) ok = append_raw(f, "-", 1);
    ok = ok && zfmt_u64(f, whole);
    if (precision > 0) {
        ok = ok && zfmt_char(f, '.');
        ok = ok && zfmt_u64_pad(f, frac, precision);
    }
    return ok;
}

bool zfmt_repeat(zfmt *f, char c, size_t count)
{
    if (!f) return false;
    bool ok = true;
    for (size_t i = 0; i < count; i++)
        ok = zfmt_char(f, c) && ok;
    return ok && !f->failed;
}

void zfmt_reset(zfmt *f)
{
    if (!f) return;
    f->len = 0;
    f->failed = !f->buf || f->cap == 0;
    if (!f->failed) f->buf[0] = '\0';
}

bool zfmt_ok(const zfmt *f)
{
    return f && !f->failed;
}

const char *zfmt_cstr(const zfmt *f)
{
    if (!f || f->failed) return "";
    return f->buf;
}

size_t zfmt_len(const zfmt *f)
{
    return f ? f->len : 0;
}
