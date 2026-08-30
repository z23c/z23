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
#if defined(_WIN32)
    /* Windows likewise admits several spellings of one file: /tmp/x,
     * C:\tmp\x, C:/tmp/x, relative forms.  SQLite reports db filenames in
     * its own resolved form, so a re-open through sqlite3_db_filename()
     * must key to the same identity as the caller's original spelling.
     * _fullpath() is lexical (works for not-yet-created paths) and always
     * returns an absolute backslash form; GetFullPathName is what SQLite's
     * win32 VFS applies to every path it opens. */
    if (strcmp(path, ":memory:") != 0) {
        char resolved[4096];
        if (_fullpath(resolved, path, sizeof(resolved))) {
            int written = snprintf(out, out_size, "%s", resolved);
            return written >= 0 && (size_t)written < out_size;
        }
    }
#endif
    int written = snprintf(out, out_size, "%s", path);
    return written >= 0 && (size_t)written < out_size;
}

#endif
