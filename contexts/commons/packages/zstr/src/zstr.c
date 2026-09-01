#include "zstr/zstr.h"

#include <string.h>

/* Bounded strlen: scans at most cap bytes (C23 has no strnlen). */
static size_t bounded_len(const char *s, size_t cap)
{
    size_t n = 0;
    while (n < cap && s[n] != '\0') n++;
    return n;
}

size_t zstr_copy(char *dst, size_t cap, const char *src)
{
    if (!src) return 0;
    size_t n = strlen(src);
    if (dst && cap > 0) {
        size_t take = n < cap - 1 ? n : cap - 1;
        memcpy(dst, src, take);
        dst[take] = '\0';
    }
    return n;
}

size_t zstr_concat(char *dst, size_t cap, const char *src)
{
    if (!src) return 0;
    size_t src_len = strlen(src);
    if (!dst || cap == 0) return src_len;
    size_t dst_len = bounded_len(dst, cap);
    size_t room = cap - dst_len;
    if (room > 0) {
        size_t take = src_len < room - 1 ? src_len : room - 1;
        memcpy(dst + dst_len, src, take);
        dst[dst_len + take] = '\0';
    }
    return dst_len + src_len;
}

static bool is_space(char c)
{
    return c == ' ' || c == '\t' || c == '\n' || c == '\r'
        || c == '\f' || c == '\v';
}

char *zstr_trim(char *s)
{
    if (!s) return NULL;
    char *start = s;
    while (*start && is_space(*start)) start++;
    char *end = start + strlen(start);
    while (end > start && is_space(end[-1])) end--;
    *end = '\0';
    if (start != s) memmove(s, start, (size_t)(end - start) + 1);
    return s;
}

char *zstr_to_lower(char *s)
{
    if (!s) return NULL;
    for (char *p = s; *p; p++)
        if (*p >= 'A' && *p <= 'Z') *p += 32;
    return s;
}

char *zstr_to_upper(char *s)
{
    if (!s) return NULL;
    for (char *p = s; *p; p++)
        if (*p >= 'a' && *p <= 'z') *p -= 32;
    return s;
}

static char fold(char c)
{
    return (c >= 'A' && c <= 'Z') ? (char)(c + 32) : c;
}

int zstr_casecmp(const char *a, const char *b)
{
    if (!a && !b) return 0;
    if (!a) return -1;
    if (!b) return 1;
    while (*a && *b) {
        char ca = fold(*a), cb = fold(*b);
        if (ca != cb) return (unsigned char)ca - (unsigned char)cb;
        a++;
        b++;
    }
    return (unsigned char)fold(*a) - (unsigned char)fold(*b);
}

bool zstr_case_equal(const char *a, const char *b)
{
    return zstr_casecmp(a, b) == 0;
}

bool zstr_starts_with(const char *s, const char *prefix)
{
    if (!s || !prefix) return false;
    while (*prefix) {
        if (*s != *prefix) return false;
        s++;
        prefix++;
    }
    return true;
}

bool zstr_ends_with(const char *s, const char *suffix)
{
    if (!s || !suffix) return false;
    size_t sl = strlen(s), xl = strlen(suffix);
    return xl <= sl && memcmp(s + sl - xl, suffix, xl) == 0;
}

size_t zstr_count(const char *s, const char *needle)
{
    if (!s || !needle || !*needle) return 0;
    size_t n = 0;
    size_t nl = strlen(needle);
    while ((s = strstr(s, needle)) != NULL) {
        n++;
        s += nl;
    }
    return n;
}

void zstr_split_init(zstr_split_it *it, const char *s, char delim)
{
    if (!it) return;
    it->cur = s;
    it->delim = delim;
    it->done = (s == NULL);
}

bool zstr_split_next(zstr_split_it *it, zstr_span *out)
{
    if (!it || !out || it->done || !it->cur) return false;
    const char *start = it->cur;
    const char *sep = strchr(start, it->delim);
    if (sep) {
        out->ptr = start;
        out->len = (size_t)(sep - start);
        it->cur = sep + 1;
    } else {
        out->ptr = start;
        out->len = strlen(start);
        it->done = true;
    }
    return true;
}
