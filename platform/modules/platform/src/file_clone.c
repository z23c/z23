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

/* Returns the inspection refusal reason and its error code, or NULL. */
static const char *descriptor_inspection_refusal(int source_fd,
                                                 int destination_fd,
                                                 struct stat *source,
                                                 struct stat *destination,
                                                 int *error)
{
    if (source_fd < 0 || destination_fd < 0) {
        *error = 0;
        return "invalid descriptor";
    }
    if (fstat(source_fd, source) != 0 ||
        fstat(destination_fd, destination) != 0) {
        *error = errno;
        return "descriptor inspection failed";
    }
    return NULL;
}

/* Returns which pre-clone rule refuses the request, or NULL if none. */
static const char *clone_request_refusal(int source_flags,
                                         int destination_flags,
                                         const struct stat *source,
                                         const struct stat *destination)
{
#if defined(O_PATH)
    if ((source_flags & O_PATH) != 0 || (destination_flags & O_PATH) != 0)
        return "O_PATH descriptor refused";
#endif
    if ((source_flags & O_ACCMODE) == O_WRONLY ||
        (destination_flags & O_ACCMODE) == O_RDONLY ||
        (destination_flags & O_APPEND) != 0)
        return "descriptor access mode refused";
    if (!S_ISREG(source->st_mode) ||
        !S_ISREG(destination->st_mode) ||
        destination->st_size != 0 ||
        destination->st_nlink > 1 ||
        same_file(source, destination))
        return "descriptor shape refused";
    return NULL;
}

/* Re-stats both descriptors after the clone; true when both calls succeed. */
static bool restat_cloned_descriptors(int source_fd, int destination_fd,
                                      struct stat *source,
                                      struct stat *destination)
{
    return fstat(source_fd, source) == 0 &&
           fstat(destination_fd, destination) == 0;
}

/* True when the cloned files fail the post-clone shape rules. */
static bool cloned_shape_refused(const struct stat *source,
                                 const struct stat *destination)
{
    return !S_ISREG(source->st_mode) ||
           !S_ISREG(destination->st_mode) ||
           destination->st_nlink > 1 ||
           same_file(source, destination) ||
           source->st_size != destination->st_size;
}
#endif

enum platform_file_clone_result platform_file_clone_fd(int source_fd,
                                                        int destination_fd)
{
#if defined(__linux__)
    struct stat source_before, destination_before;
    int inspection_error = 0;
    const char *inspection_refusal = descriptor_inspection_refusal(
        source_fd, destination_fd, &source_before, &destination_before,
        &inspection_error);
    if (inspection_refusal != NULL)
        return clone_refused(inspection_refusal, inspection_error);
    int source_flags = fcntl(source_fd, F_GETFL);
    if (source_flags < 0)
        return clone_refused("source descriptor flags unavailable", errno);
    int destination_flags = fcntl(destination_fd, F_GETFL);
    if (destination_flags < 0)
        return clone_refused("destination descriptor flags unavailable",
                             errno);
    const char *request_refusal = clone_request_refusal(
        source_flags, destination_flags, &source_before, &destination_before);
    if (request_refusal != NULL)
        return clone_refused(request_refusal, 0);

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
    if (!restat_cloned_descriptors(source_fd, destination_fd, &source_after,
                                   &destination_after))
        return clone_refused("cloned file inspection failed", errno);
    if (cloned_shape_refused(&source_after, &destination_after))
        return clone_refused("cloned file shape refused", 0);
    return PLATFORM_FILE_CLONE_CLONED;
#else
    (void)source_fd;
    (void)destination_fd;
    return PLATFORM_FILE_CLONE_UNAVAILABLE;
#endif
}
