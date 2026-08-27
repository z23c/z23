/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0.
 * Purpose: Render stable platform paths for open descriptors and their children. */
#ifndef ZCL_PLATFORM_FD_PATH_H
#define ZCL_PLATFORM_FD_PATH_H

#include <stdbool.h>
#include <stddef.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/stat.h>

static inline bool platform_fd_path(char *out, size_t out_size, int fd,
                                    const char *leaf)
{
#if defined(__APPLE__)
    const char *root = "/dev/fd";
#else
    const char *root = "/proc/self/fd";
#endif
    int written = leaf && leaf[0]
        ? snprintf(out, out_size, "%s/%d/%s", root, fd, leaf)
        : snprintf(out, out_size, "%s/%d", root, fd);
    return written >= 0 && (size_t)written < out_size;
}

static inline bool platform_dirfd_child_path(char *out, size_t out_size,
                                             int directory_fd,
                                             const char *leaf)
{
    if (!leaf || !leaf[0]) return false;
#if defined(__APPLE__)
    char directory[4096];
    struct stat opened;
    struct stat resolved;
    if (fcntl(directory_fd, F_GETPATH, directory) != 0 ||
        fstat(directory_fd, &opened) != 0 || stat(directory, &resolved) != 0 ||
        opened.st_dev != resolved.st_dev || opened.st_ino != resolved.st_ino)
        return false;
    int written = snprintf(out, out_size, "%s/%s", directory, leaf);
    return written >= 0 && (size_t)written < out_size;
#else
    return platform_fd_path(out, out_size, directory_fd, leaf);
#endif
}

#endif
