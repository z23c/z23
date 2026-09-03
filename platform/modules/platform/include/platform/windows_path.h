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
#endif

#endif
