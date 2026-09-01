/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: POSIX (statvfs) and Win32 (GetDiskFreeSpaceExW) implementation of
 * platform/disk_space.h, including the \\?\ long-path escaping Windows needs
 * for drive, UNC, and already-extended paths. */
#include "platform/disk_space.h"
#include "windows_path_internal.h"

#include <stddef.h>

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <wchar.h>

bool platform_disk_space_available(const char *path, uint64_t *available)
{
    wchar_t wide[32768];
    if (!available || !platform_windows_wide_path(path, wide)) return false;
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
