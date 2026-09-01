/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: portable atomic replace for ordinary state files. Windows CRT
 * rename() refuses when the destination exists, so durable tmp-file writers
 * must cross this seam instead of acquiring platform conditionals. */

#include "platform/path_replace.h"

#include <errno.h>

#if defined(_WIN32)
#include "windows_path_internal.h"

#include <string.h>
#include <windows.h>
#else
#include <stdio.h>
#endif

#if defined(_WIN32)
static void path_replace_set_errno(DWORD error)
{
    switch (error) {
    case ERROR_FILE_NOT_FOUND:
    case ERROR_PATH_NOT_FOUND:
        errno = ENOENT;
        break;
    case ERROR_ACCESS_DENIED:
        errno = EACCES;
        break;
    case ERROR_SHARING_VIOLATION:
    case ERROR_LOCK_VIOLATION:
        errno = EBUSY;
        break;
    case ERROR_FILE_EXISTS:
    case ERROR_ALREADY_EXISTS:
        errno = EEXIST;
        break;
    case ERROR_NOT_SAME_DEVICE:
        errno = EXDEV;
        break;
    case ERROR_FILENAME_EXCED_RANGE:
        errno = ENAMETOOLONG;
        break;
    case ERROR_INVALID_NAME:
    case ERROR_INVALID_PARAMETER:
        errno = EINVAL;
        break;
    default:
        errno = EIO;
        break;
    }
}
#endif

int platform_path_replace(const char *staged_path,
                          const char *destination_path)
{
    if (!staged_path || !staged_path[0] ||
        !destination_path || !destination_path[0]) {
        errno = EINVAL;
        return -1;
    }
#if defined(_WIN32)
    if (strlen(staged_path) >= 32764u ||
        strlen(destination_path) >= 32764u) {
        errno = ENAMETOOLONG;
        return -1;
    }

    wchar_t staged_wide[32768];
    wchar_t destination_wide[32768];
    if (!platform_windows_wide_path(staged_path, staged_wide) ||
        !platform_windows_wide_path(destination_path, destination_wide)) {
        errno = EINVAL;
        return -1;
    }
    if (!MoveFileExW(staged_wide, destination_wide,
                     MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
        path_replace_set_errno(GetLastError());
        return -1;
    }
    return 0;
#else
    return rename(staged_path, destination_path);
#endif
}
