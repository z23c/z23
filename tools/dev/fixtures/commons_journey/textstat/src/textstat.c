/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * textstat — see include/textstat/textstat.h. Pure functions over a caller
 * buffer: no allocation, no I/O, no global state, so a reproducing node
 * gets the same answer with no environment at all. */

#include "textstat/textstat.h"

static int textstat_is_space(char c)
{
    return c == ' ' || c == '\t' || c == '\n' || c == '\r' ||
           c == '\v' || c == '\f';
}

size_t textstat_lines(const char *text, size_t len)
{
    if (!text || len == 0) return 0;
    size_t lines = 0;
    for (size_t i = 0; i < len; i++) {
        if (text[i] == '\r') {
            lines++;
            if (i + 1 < len && text[i + 1] == '\n') i++;
        } else if (text[i] == '\n') {
            lines++;
        }
    }
    /* A final line without its newline still reached the reader's eyes. */
    if (text[len - 1] != '\n' && text[len - 1] != '\r') lines++;
    return lines;
}

size_t textstat_words(const char *text, size_t len)
{
    if (!text) return 0;
    size_t words = 0;
    int inside = 0;
    for (size_t i = 0; i < len; i++) {
        if (textstat_is_space(text[i])) { inside = 0; continue; }
        if (!inside) { inside = 1; words++; }
    }
    return words;
}

size_t textstat_bytes(const char *text, size_t len)
{
    return text ? len : 0;
}
