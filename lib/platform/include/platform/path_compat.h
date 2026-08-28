/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: one canonical identity string per path, even for a path that does
 * not exist yet, so process-local database-ownership registries
 * (database.c, database_owner_lease.c) key on the resource realpath() would
 * resolve to rather than the caller's original spelling. See below for the
 * Darwin /tmp-vs-/private/tmp case this exists to collapse. */
#ifndef ZCL_PLATFORM_PATH_COMPAT_H
#define ZCL_PLATFORM_PATH_COMPAT_H

#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(_WIN32)
#include <windows.h>
#ifndef PATH_MAX
#define PATH_MAX 32768
#endif

static inline bool platform_path_resolve(char *resolved, size_t resolved_size,
                                         const char *path)
{
    if (!path || !resolved || resolved_size == 0) {
        errno = EINVAL;
        return false;
    }
    wchar_t input[PATH_MAX];
    wchar_t final_path[PATH_MAX];
    if (!MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, path, -1, input,
                             PATH_MAX)) {
        errno = EINVAL;
        return false;
    }
    HANDLE handle = CreateFileW(input, 0,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL,
        OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, NULL);
    if (handle == INVALID_HANDLE_VALUE) {
        errno = GetLastError() == ERROR_FILE_NOT_FOUND ? ENOENT : EACCES;
        return false;
    }
    DWORD length = GetFinalPathNameByHandleW(handle, final_path, PATH_MAX,
                                             FILE_NAME_NORMALIZED);
    CloseHandle(handle);
    if (length == 0 || length >= PATH_MAX) {
        errno = ENAMETOOLONG;
        return false;
    }
    const wchar_t *start = final_path;
    if (wcsncmp(start, L"\\\\?\\UNC\\", 8) == 0) {
        final_path[6] = L'\\';
        start = final_path + 6;
    } else if (wcsncmp(start, L"\\\\?\\", 4) == 0) {
        start += 4;
    }
    int required = WideCharToMultiByte(CP_UTF8, 0, start, -1, NULL, 0,
                                       NULL, NULL);
    if (required <= 0 || (size_t)required > resolved_size) {
        errno = ENAMETOOLONG;
        return false;
    }
    int written = WideCharToMultiByte(CP_UTF8, 0, start, -1, resolved,
                                      (int)resolved_size, NULL, NULL);
    if (written <= 0) return false;
    for (char *cursor = resolved; *cursor; cursor++)
        if (*cursor == '\\') *cursor = '/';
    return true;
}
#endif

/* Darwin exposes /tmp through /private/tmp. Normalize an existing path, or
 * the parent of a not-yet-created path, so process-local ownership registries
 * do not treat those spellings as different resources. */
static inline bool platform_path_identity(char *out, size_t out_size,
                                          const char *path)
{
    if (!out || out_size == 0 || !path || !path[0]) return false;
#if defined(__APPLE__)
    if (strcmp(path, ":memory:") != 0) {
        char resolved[4096];
        if (realpath(path, resolved)) {
            int written = snprintf(out, out_size, "%s", resolved);
            return written >= 0 && (size_t)written < out_size;
        }
        if (errno == ENOENT) {
            char directory[4096];
            const char *leaf = path;
            const char *slash = strrchr(path, '/');
            if (slash) {
                size_t directory_len = (size_t)(slash - path);
                if (directory_len == 0) directory_len = 1;
                if (directory_len >= sizeof(directory)) return false;
                memcpy(directory, path, directory_len);
                directory[directory_len] = '\0';
                leaf = slash + 1;
            } else {
                memcpy(directory, ".", 2);
            }
            if (leaf[0] && realpath(directory, resolved)) {
                int written = snprintf(out, out_size, "%s/%s", resolved,
                                       leaf);
                return written >= 0 && (size_t)written < out_size;
            }
        }
    }
#endif
    int written = snprintf(out, out_size, "%s", path);
    return written >= 0 && (size_t)written < out_size;
}

#endif
