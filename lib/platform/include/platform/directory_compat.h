/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: directory creation across POSIX and the Win32 CRT. */

#ifndef ZCL_PLATFORM_DIRECTORY_COMPAT_H
#define ZCL_PLATFORM_DIRECTORY_COMPAT_H

#if defined(_WIN32)
#include <direct.h>
#else
#include <sys/stat.h>
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

#endif
