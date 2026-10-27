/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: Canonicalize relative-parent destinations before private writes. */

#include "platform/private_file.h"
#include "platform/directory_compat.h"
#include "base/safe_alloc.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* True when path, resolved and parent are non-NULL, path is non-empty, and
 * both sizes are non-zero. */
static bool platform_private_destination_arguments_valid(
    const char *path, const char *resolved, size_t resolved_size,
    const char *parent, size_t parent_size)
{
    return path && path[0] && resolved && resolved_size && parent &&
           parent_size;
}

/* Return the last separator in path ('\\' also counts on Windows). */
static const char *platform_private_destination_last_separator(
    const char *path)
{
    const char *separator = strrchr(path, '/');
#if defined(_WIN32)
    const char *backslash = strrchr(path, '\\');
    if (!separator || (backslash && backslash > separator))
        separator = backslash;
#endif
    return separator;
}

/* Copy the text before separator into relative_parent, or "." when separator
 * is NULL; false when that text is empty or too long. */
static bool platform_private_destination_copy_relative_parent(
    char *relative_parent, size_t relative_parent_size, const char *path,
    const char *separator)
{
    if (!separator) {
        memcpy(relative_parent, ".", 2);
        return true;
    }
    size_t length = (size_t)(separator - path);
    if (!length || length >= relative_parent_size)
        return false;
    memcpy(relative_parent, path, length);
    relative_parent[length] = '\0';
    return true;
}

/* Return a newly allocated "parent<join>leaf" path, or NULL when the size
 * overflows, allocation fails, or the write fails or truncates. */
static char *platform_private_destination_join_parent_leaf(
    const char *parent, const char *leaf)
{
    size_t parent_length = strlen(parent), leaf_length = strlen(leaf);
    if (parent_length > SIZE_MAX - leaf_length - 2u)
        return NULL;
    size_t absolute_size = parent_length + leaf_length + 2u;
    char *absolute = zcl_malloc(absolute_size,
                                "platform-private-destination-path");
    if (!absolute)
        return NULL;
#if defined(_WIN32)
    const char join = '\\';
#else
    const char join = '/';
#endif
    int written = snprintf(absolute, absolute_size, "%s%c%s", parent, join,
                           leaf);
    if (written <= 0 || (size_t)written >= absolute_size) {
        free(absolute);
        return NULL;
    }
    return absolute;
}

bool platform_private_destination_resolve(
    const char *path, char *resolved, size_t resolved_size, char *parent,
    size_t parent_size)
{
    if (!platform_private_destination_arguments_valid(
            path, resolved, resolved_size, parent, parent_size))
        return false;
    if (platform_private_path_resolve(path, resolved, resolved_size, parent,
                                      parent_size))
        return true;
    if (path[0] == '/' || path[0] == '\\')
        return false;
    const char *separator = platform_private_destination_last_separator(path);
    const char *leaf = separator ? separator + 1 : path;
    if (!leaf[0])
        return false;
    char relative_parent[32768];
    if (!platform_private_destination_copy_relative_parent(
            relative_parent, sizeof(relative_parent), path, separator))
        return false;
    if (!platform_directory_canonical_real(relative_parent, parent,
                                           parent_size))
        return false;
    char *absolute =
        platform_private_destination_join_parent_leaf(parent, leaf);
    if (!absolute)
        return false;
    bool ok = platform_private_path_resolve(
        absolute, resolved, resolved_size, parent, parent_size);
    free(absolute);
    return ok;
}
