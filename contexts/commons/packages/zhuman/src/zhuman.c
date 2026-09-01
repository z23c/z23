#include "zhuman/zhuman.h"

#include <stdio.h>
#include <string.h>

/* --- Sizes ----------------------------------------------------------- */

static zhuman_err format_bytes(uint64_t bytes, char *out, size_t cap,
                               const char *const units[7], uint64_t base)
{
    if (!out || cap == 0) return ZHUMAN_ERR_NULL;
    int u = 0;
    uint64_t scaled = bytes;
    while (scaled >= base && u < 6) {
        scaled /= base;
        u++;
    }
    uint64_t unit_size = 1;
    for (int i = 0; i < u; i++) unit_size *= base;
    int n;
    if (u == 0 || bytes % unit_size == 0) {
        /* exact whole unit (u==0 always exact; integer multiple) */
        n = snprintf(out, cap, "%llu %s",
                     (unsigned long long)(u == 0 ? bytes : scaled), units[u]);
    } else {
        /* one decimal place */
        uint64_t whole = bytes / unit_size;
        uint64_t tenth = (bytes % unit_size) * 10 / unit_size;
        n = snprintf(out, cap, "%llu.%llu %s",
                     (unsigned long long)whole, (unsigned long long)tenth,
                     units[u]);
    }
    if (n < 0 || (size_t)n >= cap) return ZHUMAN_ERR_SMALL;
    return ZHUMAN_OK;
}

zhuman_err zhuman_format_bytes_iec(uint64_t bytes, char *out, size_t cap)
{
    static const char *const U[7] = {"B", "KiB", "MiB", "GiB", "TiB", "PiB", "EiB"};
    return format_bytes(bytes, out, cap, U, 1024);
}

zhuman_err zhuman_format_bytes_si(uint64_t bytes, char *out, size_t cap)
{
    static const char *const U[7] = {"B", "kB", "MB", "GB", "TB", "PB", "EB"};
    return format_bytes(bytes, out, cap, U, 1000);
}

static int ci_equal(const char *a, const char *b)
{
    while (*a && *b) {
        char ca = *a, cb = *b;
        if (ca >= 'A' && ca <= 'Z') ca += 32;
        if (cb >= 'A' && cb <= 'Z') cb += 32;
        if (ca != cb) return 0;
        a++;
        b++;
    }
    return *a == *b;
}

zhuman_err zhuman_parse_bytes(const char *str, uint64_t *out)
{
    if (!str || !out) return ZHUMAN_ERR_NULL;
    while (*str == ' ') str++;
    if (!*str) return ZHUMAN_ERR_FORMAT;

    /* Parse integer part. */
    uint64_t whole = 0;
    int digits = 0;
    while (*str >= '0' && *str <= '9') {
        if (whole > (UINT64_MAX - 9) / 10) return ZHUMAN_ERR_OVERFLOW;
        whole = whole * 10 + (uint64_t)(*str - '0');
        str++;
        digits++;
    }
    if (!digits) return ZHUMAN_ERR_FORMAT;

    /* Optional single fractional digit. */
    uint64_t frac = 0; /* tenths */
    if (*str == '.') {
        str++;
        if (!(*str >= '0' && *str <= '9')) return ZHUMAN_ERR_FORMAT;
        frac = (uint64_t)(*str - '0');
        str++;
        if (*str >= '0' && *str <= '9') return ZHUMAN_ERR_FORMAT; /* >1 dp */
    }
    while (*str == ' ') str++;

    static const struct { const char *name; uint64_t mult; } UNITS[] = {
        {"",     1},
        {"B",    1},
        {"KiB",  1ull << 10}, {"MiB", 1ull << 20}, {"GiB", 1ull << 30},
        {"TiB",  1ull << 40}, {"PiB", 1ull << 50}, {"EiB", 1ull << 60},
        {"kB",   1000ull},    {"MB",  1000ull * 1000},
        {"GB",   1000ull * 1000 * 1000},
        {"TB",   1000ull * 1000 * 1000 * 1000},
        {"PB",   1000ull * 1000 * 1000 * 1000 * 1000},
        {"EB",   1000ull * 1000 * 1000 * 1000 * 1000 * 1000},
    };
    for (size_t i = 0; i < sizeof UNITS / sizeof UNITS[0]; i++) {
        if (ci_equal(str, UNITS[i].name)) {
            uint64_t m = UNITS[i].mult;
            if (whole > UINT64_MAX / m) return ZHUMAN_ERR_OVERFLOW;
            uint64_t v = whole * m + frac * m / 10;
            *out = v;
            return ZHUMAN_OK;
        }
    }
    return ZHUMAN_ERR_FORMAT;
}

/* --- Durations ------------------------------------------------------- */

zhuman_err zhuman_format_duration(uint64_t ms, char *out, size_t cap)
{
    if (!out || cap == 0) return ZHUMAN_ERR_NULL;
    if (ms == 0) {
        if (cap < 5) return ZHUMAN_ERR_SMALL;
        memcpy(out, "0 ms", 5);
        return ZHUMAN_OK;
    }

    uint64_t d = ms / 86400000; ms %= 86400000;
    uint64_t h = ms / 3600000;  ms %= 3600000;
    uint64_t m = ms / 60000;    ms %= 60000;
    uint64_t s = ms / 1000;     uint64_t rem = ms % 1000;

    size_t off = 0;
    int n = 0;
    if (d > 0) {
        n = snprintf(out + off, cap - off, "%llud ", (unsigned long long)d);
        if (n < 0 || (size_t)n >= cap - off) return ZHUMAN_ERR_SMALL;
        off += (size_t)n;
    }
    if (h > 0) {
        n = snprintf(out + off, cap - off, "%lluh ", (unsigned long long)h);
        if (n < 0 || (size_t)n >= cap - off) return ZHUMAN_ERR_SMALL;
        off += (size_t)n;
    }
    if (m > 0) {
        n = snprintf(out + off, cap - off, "%llum ", (unsigned long long)m);
        if (n < 0 || (size_t)n >= cap - off) return ZHUMAN_ERR_SMALL;
        off += (size_t)n;
    }
    if (s > 0 || rem > 0 || off == 0) {
        if (rem > 0)
            n = snprintf(out + off, cap - off, "%llu.%03llus",
                         (unsigned long long)s, (unsigned long long)rem);
        else
            n = snprintf(out + off, cap - off, "%llus",
                         (unsigned long long)s);
        if (n < 0 || (size_t)n >= cap - off) return ZHUMAN_ERR_SMALL;
        off += (size_t)n;
    } else {
        off--; /* drop trailing space */
    }
    out[off] = '\0';
    return ZHUMAN_OK;
}

zhuman_err zhuman_parse_duration(const char *str, uint64_t *out_ms)
{
    if (!str || !out_ms) return ZHUMAN_ERR_NULL;
    while (*str == ' ') str++;
    if (!*str) return ZHUMAN_ERR_FORMAT;

    uint64_t total = 0;
    unsigned seen = 0; /* bit per unit: d h m s ms */
    int components = 0;

    while (*str) {
        while (*str == ' ') str++;
        if (!*str) break;
        if (!(*str >= '0' && *str <= '9')) return ZHUMAN_ERR_FORMAT;

        uint64_t val = 0;
        while (*str >= '0' && *str <= '9') {
            if (val > (UINT64_MAX - 9) / 10) return ZHUMAN_ERR_OVERFLOW;
            val = val * 10 + (uint64_t)(*str - '0');
            str++;
        }
        /* Optional fraction, only meaningful before 's'. */
        uint64_t frac_ms = 0;
        if (*str == '.') {
            str++;
            if (!(*str >= '0' && *str <= '9')) return ZHUMAN_ERR_FORMAT;
            uint64_t place = 100; /* first digit is tenths of a second */
            while (*str >= '0' && *str <= '9') {
                if (place > 0) {
                    frac_ms += (uint64_t)(*str - '0') * place;
                    place /= 10;
                }
                str++;
            }
        }

        uint64_t mult;
        unsigned bit;
        while (*str == ' ') str++; /* allow "0 ms" */
        if (str[0] == 'm' && str[1] == 's') {
            mult = 1; bit = 4; str += 2;
        } else if (str[0] == 'd') {
            mult = 86400000; bit = 0; str++;
        } else if (str[0] == 'h') {
            mult = 3600000; bit = 1; str++;
        } else if (str[0] == 'm') {
            mult = 60000; bit = 2; str++;
        } else if (str[0] == 's') {
            mult = 1000; bit = 3; str++;
        } else {
            return ZHUMAN_ERR_FORMAT;
        }
        if (frac_ms && bit != 3) return ZHUMAN_ERR_FORMAT; /* "1.5m" rejected */
        if (seen & (1u << bit)) return ZHUMAN_ERR_FORMAT;  /* repeated unit */
        seen |= 1u << bit;

        if (val > (UINT64_MAX - frac_ms) / mult) return ZHUMAN_ERR_OVERFLOW;
        uint64_t part = val * mult + frac_ms;
        if (total > UINT64_MAX - part) return ZHUMAN_ERR_OVERFLOW;
        total += part;
        components++;
    }
    if (components == 0) return ZHUMAN_ERR_FORMAT;
    *out_ms = total;
    return ZHUMAN_OK;
}

const char *zhuman_err_str(zhuman_err e)
{
    switch (e) {
    case ZHUMAN_OK:           return "ok";
    case ZHUMAN_ERR_NULL:     return "null argument";
    case ZHUMAN_ERR_FORMAT:   return "unrecognized format";
    case ZHUMAN_ERR_OVERFLOW: return "value overflow";
    case ZHUMAN_ERR_SMALL:    return "output buffer too small";
    }
    return "unknown error";
}
