/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: Convert UTF-8 Windows paths to wide, long-path-capable form. */
#ifndef ZCL_PLATFORM_WINDOWS_PATH_H
#define ZCL_PLATFORM_WINDOWS_PATH_H

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#include <wchar.h>

static inline bool platform_windows_wide_path(const char *utf8,
                                              wchar_t out[32768])
{
    if (!utf8 || !utf8[0]) return false;
    wchar_t plain[32768];
    int n = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, utf8, -1,
                                plain, 32768);
    if (n <= 0) return false;
    for (int i = 0; i < n - 1; i++)
        if (plain[i] == L'/') plain[i] = L'\\';
    if (wcsncmp(plain, L"\\\\?\\", 4) == 0) {
        wmemcpy(out, plain, (size_t)n);
        return true;
    }
    if (plain[0] == L'\\' && plain[1] == L'\\') {
        if ((size_t)n + 6 >= 32768) return false;
        wmemcpy(out, L"\\\\?\\UNC\\", 8);
        wmemcpy(out + 8, plain + 2, (size_t)n - 2);
        return true;
    }
    if (plain[0] && plain[1] == L':' && plain[2] == L'\\') {
        if ((size_t)n + 4 >= 32768) return false;
        wmemcpy(out, L"\\\\?\\", 4);
        wmemcpy(out + 4, plain, (size_t)n);
        return true;
    }
    wmemcpy(out, plain, (size_t)n);
    return true;
}

/* Strict UTF-8 validity (the byte-domain image of MB_ERR_INVALID_CHARS:
 * rejects overlongs, surrogates, and code points past U+10FFFF). */
static inline bool zcl_windows_path_utf8_valid(const char *s)
{
    const unsigned char *p = (const unsigned char *)s;
    while (*p) {
        unsigned c = *p;
        size_t need = 0;
        unsigned lo = 0x80u, hi = 0xBFu;
        if (c < 0x80u) {
            p++;
            continue;
        } else if (c >= 0xC2u && c <= 0xDFu) {
            need = 1;
        } else if (c >= 0xE0u && c <= 0xEFu) {
            need = 2;
            lo = c == 0xE0u ? 0xA0u : 0x80u;
            hi = c == 0xEDu ? 0x9Fu : 0xBFu;
        } else if (c >= 0xF0u && c <= 0xF4u) {
            need = 3;
            lo = c == 0xF0u ? 0x90u : 0x80u;
            hi = c == 0xF4u ? 0x8Fu : 0xBFu;
        } else {
            return false;
        }
        p++;
        for (size_t i = 0; i < need; i++, p++) {
            unsigned d = *p;
            unsigned l = i == 0 ? lo : 0x80u;
            unsigned h = i == 0 ? hi : 0xBFu;
            if (d < l || d > h)
                return false;
        }
    }
    return true;
}

/* UTF-8 form of platform_windows_wide_path for CRT fopen/open callers.
 * Rewrites '/' to '\\', extends a drive-absolute path with `\\?\` and a
 * UNC path with `\\?\UNC\`, and leaves an already-extended path extended.
 * Returns false on null, empty, invalid UTF-8, or when `out` is too small.
 * Callers try the original path first and use this only after that open
 * fails, so a short path that already succeeded is unchanged. */
static inline bool platform_windows_extended_utf8(const char *utf8,
                                                  char *out, size_t out_size)
{
    if (!utf8 || !utf8[0] || !out || out_size == 0)
        return false;
    if (!zcl_windows_path_utf8_valid(utf8))
        return false;
    size_t n = strlen(utf8);
    bool bs0 = utf8[0] == '\\' || utf8[0] == '/';
    bool bs1 = n >= 2 && (utf8[1] == '\\' || utf8[1] == '/');
    bool bs2 = n >= 3 && (utf8[2] == '\\' || utf8[2] == '/');
    bool bs3 = n >= 4 && (utf8[3] == '\\' || utf8[3] == '/');
    const char *prefix = "";
    size_t prefix_len = 0;
    size_t skip = 0;
    if (n >= 4 && bs0 && bs1 && utf8[2] == '?' && bs3) {
        /* Already extended. */
    } else if (n >= 2 && bs0 && bs1) {
        prefix = "\\\\?\\UNC\\";
        prefix_len = 8;
        skip = 2;
    } else if (n >= 3 && utf8[1] == ':' && bs2) {
        prefix = "\\\\?\\";
        prefix_len = 4;
    }
    if (prefix_len + (n - skip) + 1u > out_size)
        return false;
    memcpy(out, prefix, prefix_len);
    for (size_t i = 0; i <= n - skip; i++) {
        char c = utf8[skip + i];
        out[prefix_len + i] = c == '/' ? '\\' : c;
    }
    return true;
}
#endif

#endif
