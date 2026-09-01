/* Copyright 2026 Rhett Creighton - MIT License
 * Purpose: count logical lines in the tiny-lines C23 fixture. */
#include "tiny_lines.h"

bool tiny_count_lines(const char *text, size_t length, size_t *out_lines)
{
    if (out_lines)
        *out_lines = 0;
    if ((!text && length != 0) || !out_lines)
        return false;
    if (length == 0)
        return true;
    size_t lines = 1;
    for (size_t i = 0; i < length; i++) {
        if (text[i] == '\0')
            return false;
        if (text[i] == '\n' && i + 1 < length)
            lines++;
    }
    *out_lines = lines;
    return true;
}
