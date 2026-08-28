/* Copyright 2026 Rhett Creighton - Apache License 2.0 */
#include "platform/disk_space.h"

#include <stddef.h>

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <wchar.h>

static bool disk_space_wide(const char *utf8, wchar_t out[32768])
{
    if (!utf8 || !utf8[0]) return false;
    wchar_t plain[32768];
    int n = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, utf8, -1,
                                plain, 32768);
    if (n <= 0) return false;
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
    if (plain[0] && plain[1] == L':' &&
        (plain[2] == L'\\' || plain[2] == L'/')) {
        if ((size_t)n + 4 >= 32768) return false;
        wmemcpy(out, L"\\\\?\\", 4);
        wmemcpy(out + 4, plain, (size_t)n);
        return true;
    }
    wmemcpy(out, plain, (size_t)n);
    return true;
}

bool platform_disk_space_available(const char *path, uint64_t *available)
{
    wchar_t wide[32768];
    if (!available || !disk_space_wide(path, wide)) return false;
    ULARGE_INTEGER caller_available;
    if (!GetDiskFreeSpaceExW(wide, &caller_available, NULL, NULL))
        return false;
    *available = caller_available.QuadPart;
    return true;
}

#else

#include <sys/statvfs.h>

bool platform_disk_space_available(const char *path, uint64_t *available)
{
    if (!path || !path[0] || !available) return false;
    struct statvfs status;
    if (statvfs(path, &status) != 0) return false;
    uint64_t blocks = (uint64_t)status.f_bavail;
    uint64_t fragment_size = (uint64_t)status.f_frsize;
    if (fragment_size != 0 && blocks > UINT64_MAX / fragment_size)
        return false;
    *available = blocks * fragment_size;
    return true;
}

#endif
