/* Copyright 2026 Rhett Creighton - Apache License 2.0 */
#ifndef ZCL_PLATFORM_SYS_STATVFS_H
#define ZCL_PLATFORM_SYS_STATVFS_H
#if defined(_WIN32)
#include <errno.h>
#include <stdint.h>
#include <windows.h>

struct statvfs {
    uint64_t f_bavail;
    uint64_t f_frsize;
};

static inline int statvfs(const char *path, struct statvfs *out)
{
    wchar_t wide[32768];
    ULARGE_INTEGER available;
    if (!path || !out ||
        !MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, path, -1, wide,
                             32768) ||
        !GetDiskFreeSpaceExW(wide, &available, NULL, NULL)) {
        errno = EIO;
        return -1;
    }
    out->f_frsize = 1;
    out->f_bavail = available.QuadPart;
    return 0;
}
#else
#if defined(__GNUC__)
#pragma GCC system_header
#endif
#include_next <sys/statvfs.h>
#endif
#endif
