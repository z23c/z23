/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: implementation of platform/private_directory.h. Windows route
 * creates the directory with an owner+SYSTEM-only security descriptor
 * (private_acl_internal.h) then re-opens and validates the live handle's
 * actual ACL/owner/no-reparse; POSIX route mkdir(0700)s then lstat-verifies
 * owner, exact 0700 mode, and no symlink. Both routes distrust their own
 * create call and refuse if the resulting directory does not actually match
 * what was requested. */
#if !defined(_WIN32) && !defined(_GNU_SOURCE)
#define _GNU_SOURCE
#endif
#include "platform/private_directory.h"
#include "private_acl_internal.h"

#include <errno.h>

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

static bool private_directory_wide(const char *path, wchar_t out[32768])
{
    return path && path[0] && MultiByteToWideChar(
        CP_UTF8, MB_ERR_INVALID_CHARS, path, -1, out, 32768) > 0;
}

bool platform_private_directory_ensure(const char *path)
{
    wchar_t wide[32768];
    struct platform_private_acl acl;
    platform_private_acl_init_empty(&acl);
    if (!private_directory_wide(path, wide) ||
        !platform_private_acl_create(&acl)) {
        errno = EINVAL;
        return false;
    }
    bool ok = true;
    SECURITY_ATTRIBUTES attributes = {
        .nLength = sizeof(attributes),
        .lpSecurityDescriptor = platform_private_acl_descriptor(&acl),
        .bInheritHandle = FALSE};
    if (ok && !CreateDirectoryW(wide, &attributes)) {
        DWORD error = GetLastError();
        ok = error == ERROR_ALREADY_EXISTS;
        if (!ok) errno = error == ERROR_ACCESS_DENIED ? EACCES : EIO;
    }
    HANDLE directory = INVALID_HANDLE_VALUE;
    if (ok)
        directory = CreateFileW(
            wide, READ_CONTROL | FILE_READ_ATTRIBUTES,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL,
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, NULL);
    ok = ok && directory != INVALID_HANDLE_VALUE &&
         platform_private_acl_validate_handle(directory, true);
    if (!ok && errno == 0) errno = EACCES;
    if (directory != INVALID_HANDLE_VALUE) CloseHandle(directory);
    platform_private_acl_destroy(&acl);
    return ok;
}

bool platform_private_directory_create(const char *path)
{
    wchar_t wide[32768];
    struct platform_private_acl acl;
    platform_private_acl_init_empty(&acl);
    if (!private_directory_wide(path, wide) ||
        !platform_private_acl_create(&acl)) {
        errno = EINVAL;
        return false;
    }
    bool ok = true;
    SECURITY_ATTRIBUTES attributes = {
        .nLength = sizeof(attributes),
        .lpSecurityDescriptor = platform_private_acl_descriptor(&acl),
        .bInheritHandle = FALSE};
    if (ok && !CreateDirectoryW(wide, &attributes)) {
        DWORD error = GetLastError();
        errno = error == ERROR_ALREADY_EXISTS || error == ERROR_FILE_EXISTS
                    ? EEXIST : error == ERROR_ACCESS_DENIED ? EACCES : EIO;
        ok = false;
    }
    HANDLE directory = INVALID_HANDLE_VALUE;
    if (ok)
        directory = CreateFileW(wide, READ_CONTROL | FILE_READ_ATTRIBUTES,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL,
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, NULL);
    ok = ok && directory != INVALID_HANDLE_VALUE &&
         platform_private_acl_validate_handle(directory, true);
    if (!ok && directory != INVALID_HANDLE_VALUE) RemoveDirectoryW(wide);
    if (directory != INVALID_HANDLE_VALUE) CloseHandle(directory);
    platform_private_acl_destroy(&acl);
    return ok;
}

bool platform_private_directory_publish_no_clobber(
    const char *staging, const char *destination)
{
    uintptr_t retained = 0;
    wchar_t from[32768], to[32768];
    if (!platform_private_directory_open_validated(staging, &retained) ||
        !private_directory_wide(staging, from) ||
        !private_directory_wide(destination, to)) {
        if (retained) platform_private_directory_close(retained);
        return false;
    }
    bool ok = MoveFileExW(from, to, MOVEFILE_WRITE_THROUGH) != 0;
    if (!ok) {
        DWORD error = GetLastError();
        errno = error == ERROR_ALREADY_EXISTS || error == ERROR_FILE_EXISTS
                    ? EEXIST : error == ERROR_ACCESS_DENIED ? EACCES : EIO;
    }
    platform_private_directory_close(retained);
    return ok;
}

bool platform_private_directory_remove_empty(const char *path)
{
    wchar_t wide[32768];
    return private_directory_wide(path, wide) && RemoveDirectoryW(wide) != 0;
}

bool platform_private_directory_open_validated(const char *path,
                                               uintptr_t *native_handle)
{
    wchar_t wide[32768];
    if (!native_handle || !private_directory_wide(path, wide))
        return false;
    HANDLE directory = CreateFileW(
        wide, FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES | READ_CONTROL,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL,
        OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, NULL);
    bool ok = directory != INVALID_HANDLE_VALUE &&
              platform_private_acl_validate_handle(directory, true);
    if (!ok) {
        if (directory != INVALID_HANDLE_VALUE) CloseHandle(directory);
        return false;
    }
    *native_handle = (uintptr_t)directory;
    return true;
}

void platform_private_directory_close(uintptr_t native_handle)
{
    if ((HANDLE)native_handle != INVALID_HANDLE_VALUE)
        CloseHandle((HANDLE)native_handle);
}

#else
#include <fcntl.h>
#include <stdio.h>
#include <sys/stat.h>
#include <unistd.h>

bool platform_private_directory_ensure(const char *path)
{
    if (!path || !path[0]) { errno = EINVAL; return false; }
    if (mkdir(path, 0700) != 0 && errno != EEXIST) return false;
    struct stat st;
    if (lstat(path, &st) != 0) return false;
    if (!S_ISDIR(st.st_mode) || S_ISLNK(st.st_mode) ||
        st.st_uid != geteuid() || (st.st_mode & 0777) != 0700) {
        errno = EACCES;
        return false;
    }
    return true;
}

bool platform_private_directory_create(const char *path)
{
    if (!path || !path[0]) { errno = EINVAL; return false; }
    if (mkdir(path, 0700) != 0) return false;
    uintptr_t handle;
    if (platform_private_directory_open_validated(path, &handle)) {
        platform_private_directory_close(handle);
        return true;
    }
    (void)rmdir(path);
    return false;
}

bool platform_private_directory_publish_no_clobber(
    const char *staging, const char *destination)
{
    uintptr_t handle;
    if (!platform_private_directory_open_validated(staging, &handle))
        return false;
    platform_private_directory_close(handle);
#if defined(__linux__)
    return renameat2(AT_FDCWD, staging, AT_FDCWD, destination,
                     RENAME_NOREPLACE) == 0;
#else
    struct stat st;
    if (lstat(destination, &st) == 0 || errno != ENOENT) {
        errno = EEXIST;
        return false;
    }
    return rename(staging, destination) == 0;
#endif
}

bool platform_private_directory_remove_empty(const char *path)
{
    return path && rmdir(path) == 0;
}

bool platform_private_directory_open_validated(const char *path,
                                               uintptr_t *native_handle)
{
    if (!path || !path[0] || !native_handle) return false;
    int fd = open(path, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    struct stat st;
    if (fd < 0 || fstat(fd, &st) != 0 || !S_ISDIR(st.st_mode) ||
        st.st_uid != geteuid() || (st.st_mode & 0777) != 0700) {
        if (fd >= 0) close(fd);
        return false;
    }
    *native_handle = (uintptr_t)fd;
    return true;
}

void platform_private_directory_close(uintptr_t native_handle)
{
    if ((int)native_handle >= 0) close((int)native_handle);
}
#endif
