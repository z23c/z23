/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: pathname glob matching on Windows where UCRT has no fnmatch. */

#ifndef ZCL_PLATFORM_FNMATCH_H
#define ZCL_PLATFORM_FNMATCH_H

#if !defined(_WIN32)
#if defined(__GNUC__)
#pragma GCC system_header
#endif
#include_next <fnmatch.h>
#else

#include <stdbool.h>
#include <string.h>

#define FNM_NOMATCH 1
#define FNM_PATHNAME 0x01
#define FNM_NOESCAPE 0x02
#define FNM_PERIOD 0x04
#define FNM_CASEFOLD 0x08

static inline char platform_fnmatch_fold(char value, int flags)
{
    if ((flags & FNM_CASEFOLD) != 0 && value >= 'A' && value <= 'Z')
        return (char)(value - 'A' + 'a');
    return value;
}

static inline bool platform_fnmatch_class(const char **pattern_io, char value,
                                          int flags)
{
    const char *pattern = *pattern_io;
    bool negate = *pattern == '!' || *pattern == '^';
    if (negate) pattern++;
    bool matched = false;
    char folded = platform_fnmatch_fold(value, flags);
    while (*pattern && *pattern != ']') {
        char first = *pattern++;
        if (first == '\\' && (flags & FNM_NOESCAPE) == 0 && *pattern)
            first = *pattern++;
        first = platform_fnmatch_fold(first, flags);
        if (*pattern == '-' && pattern[1] && pattern[1] != ']') {
            pattern++;
            char last = *pattern++;
            if (last == '\\' && (flags & FNM_NOESCAPE) == 0 && *pattern)
                last = *pattern++;
            last = platform_fnmatch_fold(last, flags);
            if (folded >= first && folded <= last)
                matched = true;
        } else if (folded == first) {
            matched = true;
        }
    }
    if (*pattern != ']')
        return false;
    *pattern_io = pattern + 1;
    return negate ? !matched : matched;
}

static inline bool platform_fnmatch_impl(const char *pattern,
                                         const char *text, int flags,
                                         bool component_start)
{
    while (*pattern) {
        if (*pattern == '*') {
            if ((flags & FNM_PERIOD) != 0 && component_start && *text == '.')
                return false;
            while (*pattern == '*') pattern++;
            if (!*pattern)
                return (flags & FNM_PATHNAME) == 0 || strchr(text, '/') == NULL;
            for (const char *candidate = text;; candidate++) {
                if (platform_fnmatch_impl(pattern, candidate, flags,
                                          component_start))
                    return true;
                if (!*candidate ||
                    ((flags & FNM_PATHNAME) != 0 && *candidate == '/'))
                    return false;
                component_start = *candidate == '/';
            }
        }
        if (!*text)
            return false;
        if ((flags & FNM_PERIOD) != 0 && component_start && *text == '.' &&
            (*pattern == '?' || *pattern == '['))
            return false;
        if (*pattern == '?') {
            if ((flags & FNM_PATHNAME) != 0 && *text == '/')
                return false;
            pattern++;
            component_start = *text == '/';
            text++;
            continue;
        }
        if (*pattern == '[') {
            if ((flags & FNM_PATHNAME) != 0 && *text == '/')
                return false;
            const char *after = pattern + 1;
            if (!platform_fnmatch_class(&after, *text, flags))
                return false;
            pattern = after;
            component_start = *text == '/';
            text++;
            continue;
        }
        char expected = *pattern++;
        if (expected == '\\' && (flags & FNM_NOESCAPE) == 0 && *pattern)
            expected = *pattern++;
        if (platform_fnmatch_fold(expected, flags) !=
            platform_fnmatch_fold(*text, flags))
            return false;
        component_start = *text == '/';
        text++;
    }
    return *text == '\0';
}

static inline int fnmatch(const char *pattern, const char *text, int flags)
{
    if (!pattern || !text)
        return FNM_NOMATCH;
    return platform_fnmatch_impl(pattern, text, flags, true)
        ? 0 : FNM_NOMATCH;
}

#endif
#endif
