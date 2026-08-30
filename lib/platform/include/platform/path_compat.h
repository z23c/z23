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

/* True only for a fully qualified filesystem path.  A single leading slash
 * or backslash is drive-relative on Win32 and therefore is not an authority
 * boundary.  Device namespaces are refused; callers use ordinary drive or
 * UNC paths and let the Windows platform layer add any long-path prefix. */
static inline bool platform_path_is_absolute(const char *path)
{
    if (!path || !path[0]) return false;
#if defined(_WIN32)
    bool drive = ((path[0] >= 'A' && path[0] <= 'Z') ||
                  (path[0] >= 'a' && path[0] <= 'z')) &&
                 path[1] == ':' &&
                 (path[2] == '\\' || path[2] == '/');
    if (drive) return true;
    if (!((path[0] == '\\' || path[0] == '/') &&
          (path[1] == '\\' || path[1] == '/')))
        return false;
    const char *server = path + 2;
    if (!server[0] || server[0] == '?' || server[0] == '.') return false;
    const char *separator = server;
    while (*separator && *separator != '\\' && *separator != '/')
        ++separator;
    if (separator == server || !separator[0]) return false;
    const char *share = separator + 1;
    if (!share[0] || share[0] == '\\' || share[0] == '/') return false;
    return true;
#else
    return path[0] == '/';
#endif
}

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
