/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: directory creation across POSIX and the Win32 CRT. */

#ifndef ZCL_PLATFORM_DIRECTORY_COMPAT_H
#define ZCL_PLATFORM_DIRECTORY_COMPAT_H

#if defined(_WIN32)
#include <direct.h>
#include <errno.h>
#include <fcntl.h>
#include <io.h>
#include <windows.h>
#else
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

static inline int platform_directory_create(const char *path, int mode)
{
#if defined(_WIN32)
    (void)mode;
    return _mkdir(path);
#else
    return mkdir(path, (mode_t)mode);
#endif
}

static inline int platform_directory_open(const char *path)
{
#if defined(_WIN32)
    wchar_t wide[32768];
    if (!path || !MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, path, -1,
                                      wide, 32768)) {
        errno = EINVAL;
        return -1;
    }
    HANDLE handle = CreateFileW(wide, 0,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL,
        OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, NULL);
    if (handle == INVALID_HANDLE_VALUE) {
        errno = ENOENT;
        return -1;
    }
    int fd = _open_osfhandle((intptr_t)handle, O_RDONLY | O_BINARY);
    if (fd < 0) CloseHandle(handle);
    return fd;
#else
    return open(path, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
#endif
}

#if defined(_WIN32)
/* This header is force-included before application headers on Windows. The
 * native CRT declaration above is therefore complete before the project-wide
 * two-argument spelling is redirected through the platform seam. */
#define mkdir(path, mode) platform_directory_create((path), (mode))
#endif

#endif
