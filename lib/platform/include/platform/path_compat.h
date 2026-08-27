/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. */
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
    int written = snprintf(out, out_size, "%s", path);
    return written >= 0 && (size_t)written < out_size;
}

#endif
