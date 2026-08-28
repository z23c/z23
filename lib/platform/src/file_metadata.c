/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: POSIX (lstat) and Win32 (CreateFileW + GetFileInformationByHandle)
 * implementation of platform/file_metadata.h, distinguishing a missing path
 * from a refused one without ever following a final symlink/reparse point. */
#if !defined(_WIN32) && !defined(_POSIX_C_SOURCE)
#define _POSIX_C_SOURCE 200809L
#endif

#include "platform/file_metadata.h"

#include <stdbool.h>
#include <stddef.h>

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <wchar.h>

static bool metadata_wide(const char *utf8, wchar_t out[32768])
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

enum platform_file_metadata_result platform_file_metadata_read(
    const char *path, struct platform_file_metadata *out)
{
    wchar_t wide[32768];
    if (!out || !metadata_wide(path, wide))
        return PLATFORM_FILE_METADATA_REFUSED;
    HANDLE file = CreateFileW(
        wide, FILE_READ_ATTRIBUTES,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL,
        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT,
        NULL);
    if (file == INVALID_HANDLE_VALUE) {
        DWORD error = GetLastError();
        return error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND
            ? PLATFORM_FILE_METADATA_MISSING
            : PLATFORM_FILE_METADATA_REFUSED;
    }
    BY_HANDLE_FILE_INFORMATION info = {0};
    bool ok = GetFileInformationByHandle(file, &info) &&
              (info.dwFileAttributes &
               (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) == 0;
    CloseHandle(file);
    if (!ok) return PLATFORM_FILE_METADATA_REFUSED;
    out->size = ((uint64_t)info.nFileSizeHigh << 32) | info.nFileSizeLow;
    uint64_t ticks = ((uint64_t)info.ftLastWriteTime.dwHighDateTime << 32) |
                     info.ftLastWriteTime.dwLowDateTime;
    const uint64_t unix_epoch_ticks = UINT64_C(116444736000000000);
    out->modified_seconds = ticks >= unix_epoch_ticks
        ? (int64_t)((ticks - unix_epoch_ticks) / UINT64_C(10000000)) : 0;
    return PLATFORM_FILE_METADATA_OK;
}

enum platform_file_shape platform_file_shape_read(const char *path)
{
    wchar_t wide[32768];
    if (!metadata_wide(path, wide))
        return PLATFORM_FILE_SHAPE_UNREADABLE;
    /* FILE_FLAG_OPEN_REPARSE_POINT so a symlink/junction is described rather
     * than traversed — the whole point is to name what sits AT the path. */
    HANDLE file = CreateFileW(
        wide, FILE_READ_ATTRIBUTES,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL,
        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT,
        NULL);
    if (file == INVALID_HANDLE_VALUE) {
        DWORD error = GetLastError();
        return error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND
            ? PLATFORM_FILE_SHAPE_MISSING
            : PLATFORM_FILE_SHAPE_UNREADABLE;
    }
    BY_HANDLE_FILE_INFORMATION info = {0};
    bool described = GetFileInformationByHandle(file, &info) != 0;
    CloseHandle(file);
    if (!described) return PLATFORM_FILE_SHAPE_UNREADABLE;
    if (info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT)
        return PLATFORM_FILE_SHAPE_SYMLINK;
    if (info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
        return PLATFORM_FILE_SHAPE_OTHER;
    return PLATFORM_FILE_SHAPE_REGULAR;
}

#else
#include <errno.h>
#include <sys/stat.h>

enum platform_file_metadata_result platform_file_metadata_read(
    const char *path, struct platform_file_metadata *out)
{
    if (!path || !path[0] || !out)
        return PLATFORM_FILE_METADATA_REFUSED;
    struct stat st;
    if (lstat(path, &st) != 0)
        return errno == ENOENT || errno == ENOTDIR
            ? PLATFORM_FILE_METADATA_MISSING
            : PLATFORM_FILE_METADATA_REFUSED;
    if (!S_ISREG(st.st_mode) || st.st_size < 0)
        return PLATFORM_FILE_METADATA_REFUSED;
    out->size = (uint64_t)st.st_size;
    out->modified_seconds = (int64_t)st.st_mtime;
    return PLATFORM_FILE_METADATA_OK;
}

enum platform_file_shape platform_file_shape_read(const char *path)
{
    if (!path || !path[0]) return PLATFORM_FILE_SHAPE_UNREADABLE;
    struct stat st;
    /* lstat, not stat: a symlink must be described, not followed. */
    if (lstat(path, &st) != 0)
        return errno == ENOENT || errno == ENOTDIR
            ? PLATFORM_FILE_SHAPE_MISSING
            : PLATFORM_FILE_SHAPE_UNREADABLE;
    if (S_ISLNK(st.st_mode)) return PLATFORM_FILE_SHAPE_SYMLINK;
    if (S_ISREG(st.st_mode)) return PLATFORM_FILE_SHAPE_REGULAR;
    return PLATFORM_FILE_SHAPE_OTHER;
}
#endif
