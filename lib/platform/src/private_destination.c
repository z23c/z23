/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: Canonicalize relative-parent destinations before private writes. */

#include "platform/private_file.h"
#include "platform/directory_compat.h"
#include "base/safe_alloc.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

bool platform_private_destination_resolve(
    const char *path, char *resolved, size_t resolved_size, char *parent,
    size_t parent_size)
{
    if (!path || !path[0] || !resolved || !resolved_size || !parent ||
        !parent_size)
        return false;
    if (platform_private_path_resolve(path, resolved, resolved_size, parent,
                                      parent_size))
        return true;
    if (path[0] == '/' || path[0] == '\\')
        return false;
    const char *separator = strrchr(path, '/');
#if defined(_WIN32)
    const char *backslash = strrchr(path, '\\');
    if (!separator || (backslash && backslash > separator))
        separator = backslash;
#endif
    const char *leaf = separator ? separator + 1 : path;
    if (!leaf[0])
        return false;
    char relative_parent[32768];
    if (separator) {
        size_t length = (size_t)(separator - path);
        if (!length || length >= sizeof(relative_parent))
            return false;
        memcpy(relative_parent, path, length);
        relative_parent[length] = '\0';
    } else {
        memcpy(relative_parent, ".", 2);
    }
    if (!platform_directory_canonical_real(relative_parent, parent,
                                           parent_size))
        return false;
    size_t parent_length = strlen(parent), leaf_length = strlen(leaf);
    if (parent_length > SIZE_MAX - leaf_length - 2u)
        return false;
    size_t absolute_size = parent_length + leaf_length + 2u;
    char *absolute = zcl_malloc(absolute_size,
                                "platform-private-destination-path");
    if (!absolute)
        return false;
#if defined(_WIN32)
    const char join = '\\';
#else
    const char join = '/';
#endif
    int written = snprintf(absolute, absolute_size, "%s%c%s", parent, join,
                           leaf);
    bool ok = written > 0 && (size_t)written < absolute_size &&
              platform_private_path_resolve(
                  absolute, resolved, resolved_size, parent, parent_size);
    free(absolute);
    return ok;
}
