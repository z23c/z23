/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: Linux FICLONE implementation of platform/file_clone.h without
 * pathname reopening, subprocesses, shared inodes, or seek-position changes. */
#if defined(__linux__) && !defined(_GNU_SOURCE)
#define _GNU_SOURCE
#endif
#include "platform/file_clone.h"

#if defined(__linux__)
#include <errno.h>
#include <fcntl.h>
#include <linux/fs.h>
#include <stdbool.h>
#include <stdio.h>
#include <sys/ioctl.h>
#include <sys/stat.h>

static enum platform_file_clone_result clone_refused(const char *reason,
                                                      int error)
{
    fprintf(stderr, /* obs-ok:platform-primitive */
            "[platform] file_clone_fd: %s errno=%d\n", reason, error);
    return PLATFORM_FILE_CLONE_REFUSED;
}

static bool clone_unavailable(int error)
{
    return error == EOPNOTSUPP || error == ENOTTY || error == EXDEV ||
           error == EINVAL || error == EPERM || error == EACCES ||
           error == ENOSYS || error == EBADF;
}

static bool same_file(const struct stat *a, const struct stat *b)
{
    return a->st_dev == b->st_dev && a->st_ino == b->st_ino;
}
#endif

enum platform_file_clone_result platform_file_clone_fd(int source_fd,
                                                        int destination_fd)
{
#if defined(__linux__)
    struct stat source_before, destination_before;
    if (source_fd < 0 || destination_fd < 0)
        return clone_refused("invalid descriptor", 0);
    if (fstat(source_fd, &source_before) != 0 ||
        fstat(destination_fd, &destination_before) != 0)
        return clone_refused("descriptor inspection failed", errno);
    int source_flags = fcntl(source_fd, F_GETFL);
    if (source_flags < 0)
        return clone_refused("source descriptor flags unavailable", errno);
    int destination_flags = fcntl(destination_fd, F_GETFL);
    if (destination_flags < 0)
        return clone_refused("destination descriptor flags unavailable",
                             errno);
#if defined(O_PATH)
    if ((source_flags & O_PATH) != 0 || (destination_flags & O_PATH) != 0)
        return clone_refused("O_PATH descriptor refused", 0);
#endif
    if ((source_flags & O_ACCMODE) == O_WRONLY ||
        (destination_flags & O_ACCMODE) == O_RDONLY ||
        (destination_flags & O_APPEND) != 0)
        return clone_refused("descriptor access mode refused", 0);
    if (!S_ISREG(source_before.st_mode) ||
        !S_ISREG(destination_before.st_mode) ||
        destination_before.st_size != 0 ||
        destination_before.st_nlink > 1 ||
        same_file(&source_before, &destination_before))
        return clone_refused("descriptor shape refused", 0);

    if (ioctl(destination_fd, FICLONE, source_fd) != 0) {
        int error = errno;
        struct stat destination_after;
        if (fstat(destination_fd, &destination_after) != 0)
            return clone_refused("destination reinspection failed", errno);
        if (destination_after.st_size != 0)
            return clone_refused("failed clone changed destination", error);
        if (clone_unavailable(error))
            return PLATFORM_FILE_CLONE_UNAVAILABLE;
        return clone_refused("clone I/O failed", error);
    }

    struct stat source_after, destination_after;
    if (fstat(source_fd, &source_after) != 0 ||
        fstat(destination_fd, &destination_after) != 0)
        return clone_refused("cloned file inspection failed", errno);
    if (!S_ISREG(source_after.st_mode) ||
        !S_ISREG(destination_after.st_mode) ||
        destination_after.st_nlink > 1 ||
        same_file(&source_after, &destination_after) ||
        source_after.st_size != destination_after.st_size)
        return clone_refused("cloned file shape refused", 0);
    return PLATFORM_FILE_CLONE_CLONED;
#else
    (void)source_fd;
    (void)destination_fd;
    return PLATFORM_FILE_CLONE_UNAVAILABLE;
#endif
}
