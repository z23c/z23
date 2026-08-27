/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: turn an open fd back into a walkable path (/proc/self/fd on Linux,
 * /dev/fd on Darwin) for callers like progress_store/projection_store that
 * need an *at()-relative path string, not just a descriptor. On Darwin, which
 * lacks Linux's kernel-resolved /proc/self/fd/<dirfd>/<leaf> shortcut, the
 * dirfd-child variant re-derives the directory via F_GETPATH and rejects it
 * if fstat/stat dev+ino no longer match — refusing a path built across a
 * rename/replace race instead of returning a silently wrong one. */
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

/* The path a SQLite WRITER can open for creation through an already-pinned
 * descriptor (VACUUM INTO target, journal rebuild). Linux: /proc/self/fd/<fd>,
 * the kernel-resolved descriptor path, immune to every rename. Darwin:
 * /dev/fd/<fd> is a dup of the descriptor and cannot be created through, so
 * the descriptor's own F_GETPATH is used — a path lookup the caller must fence
 * by re-verifying the pinned dev/ino after the write. */
static inline bool platform_fd_writable_path(char *out, size_t out_size, int fd)
{
#if defined(__APPLE__)
    char resolved[4096];
    if (fcntl(fd, F_GETPATH, resolved) != 0)
        return false;
    int written = snprintf(out, out_size, "%s", resolved);
    return written >= 0 && (size_t)written < out_size;
#else
    return platform_fd_path(out, out_size, fd, NULL);
#endif
}

#endif
