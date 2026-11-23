/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: strict UTF-8 decode, encode and boundary stepping. */
#include "gui/draw.h"

#define REPL 0xFFFDu

uint32_t gui_utf8_next(const char *s, size_t len, size_t *i)
{
    const unsigned char *p = (const unsigned char *)s + *i;
    size_t left = len - *i;
    unsigned c = p[0];
    if (c < 0x80) { *i += 1; return c; }
    size_t need;
    uint32_t cp, min;
    if (c >= 0xC2 && c <= 0xDF) { need = 1; cp = c & 0x1Fu; min = 0x80; }
    else if (c >= 0xE0 && c <= 0xEF) { need = 2; cp = c & 0x0Fu; min = 0x800; }
    else if (c >= 0xF0 && c <= 0xF4) { need = 3; cp = c & 0x07u; min = 0x10000; }
    else { *i += 1; return REPL; }
    if (left <= need) { *i += 1; return REPL; }
    for (size_t k = 1; k <= need; k++) {
        if ((p[k] & 0xC0u) != 0x80u) { *i += 1; return REPL; }
        cp = (cp << 6) | (p[k] & 0x3Fu);
    }
    if (cp < min || cp > 0x10FFFFu || (cp >= 0xD800u && cp <= 0xDFFFu)) {
        *i += 1;
        return REPL;
    }
    *i += need + 1;
    return cp;
}

size_t gui_utf8_encode(uint32_t cp, char out[4])
{
    if (cp > 0x10FFFFu || (cp >= 0xD800u && cp <= 0xDFFFu)) cp = REPL;
    if (cp < 0x80) { out[0] = (char)cp; return 1; }
    if (cp < 0x800) {
        out[0] = (char)(0xC0u | (cp >> 6));
        out[1] = (char)(0x80u | (cp & 0x3Fu));
        return 2;
    }
    if (cp < 0x10000) {
        out[0] = (char)(0xE0u | (cp >> 12));
        out[1] = (char)(0x80u | ((cp >> 6) & 0x3Fu));
        out[2] = (char)(0x80u | (cp & 0x3Fu));
        return 3;
    }
    out[0] = (char)(0xF0u | (cp >> 18));
    out[1] = (char)(0x80u | ((cp >> 12) & 0x3Fu));
    out[2] = (char)(0x80u | ((cp >> 6) & 0x3Fu));
    out[3] = (char)(0x80u | (cp & 0x3Fu));
    return 4;
}

size_t gui_utf8_prev(const char *s, size_t len, size_t i)
{
    if (i == 0) return 0;
    if (i > len) i = len;
    size_t j = i - 1;
    while (j > 0 && i - j < 4 && ((unsigned char)s[j] & 0xC0u) == 0x80u) j--;
    size_t k = j;
    (void)gui_utf8_next(s, len, &k);
    return k == i ? j : i - 1;
}

bool gui_utf8_valid(const char *s, size_t len)
{
    size_t i = 0;
    while (i < len) {
        size_t before = i;
        uint32_t cp = gui_utf8_next(s, len, &i);
        if (cp == REPL && i - before == 1) return false;
    }
    return true;
}
