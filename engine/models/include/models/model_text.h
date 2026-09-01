/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

#ifndef ZCL_DB_MODEL_TEXT_H
#define ZCL_DB_MODEL_TEXT_H

#include <ctype.h>
#include <stdbool.h>
#include <string.h>

static inline void model_trim_ascii(char *str)
{
    size_t len;
    size_t start = 0;
    size_t end;

    if (!str || str[0] == '\0')
        return;
    len = strlen(str);
    while (start < len && isspace((unsigned char)str[start]))
        start++;
    end = len;
    while (end > start && isspace((unsigned char)str[end - 1]))
        end--;
    if (start > 0)
        memmove(str, str + start, end - start);
    str[end - start] = '\0';
}

static inline void model_ascii_upcase(char *str)
{
    if (!str)
        return;
    for (; *str; ++str)
        *str = (char)toupper((unsigned char)*str);
}

static inline void model_ascii_downcase(char *str)
{
    if (!str)
        return;
    for (; *str; ++str)
        *str = (char)tolower((unsigned char)*str);
}

static inline bool model_string_is_printable(const char *str)
{
    if (!str || str[0] == '\0')
        return false;
    for (const unsigned char *p = (const unsigned char *)str; *p; ++p) {
        if (!isprint(*p))
            return false;
    }
    return true;
}

static inline bool model_string_is_alnum(const char *str)
{
    if (!str || str[0] == '\0')
        return false;
    for (const unsigned char *p = (const unsigned char *)str; *p; ++p) {
        if (!isalnum(*p))
            return false;
    }
    return true;
}

static inline bool model_string_is_hex(const char *str)
{
    if (!str || str[0] == '\0')
        return false;
    for (const unsigned char *p = (const unsigned char *)str; *p; ++p) {
        if (!isxdigit(*p))
            return false;
    }
    return true;
}

#endif
