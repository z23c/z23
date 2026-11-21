/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0
 *
 * LD_PRELOAD faults for post-publication cleanup and parent-directory sync.
 * Only paths named by ZCL_TEST_PEER_RECOVERY_UNLINK or
 * ZCL_TEST_PEER_RECOVERY_FSYNC_DIR are refused. */

#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int recovery_linked;

int unlink(const char *path)
{
    typedef int (*unlink_fn)(const char *);
    unlink_fn real_unlink = NULL;
    void *symbol = dlsym(RTLD_NEXT, "unlink");
    memcpy(&real_unlink, &symbol, sizeof real_unlink);
    if (!real_unlink) {
        errno = ENOSYS;
        return -1;
    }
    const char *fault = getenv("ZCL_TEST_PEER_RECOVERY_UNLINK");
    if (fault && strcmp(fault, path) == 0) {
        errno = EACCES;
        return -1;
    }
    return real_unlink(path);
}

int link(const char *oldpath, const char *newpath)
{
    typedef int (*link_fn)(const char *, const char *);
    link_fn real_link = NULL;
    void *symbol = dlsym(RTLD_NEXT, "link");
    memcpy(&real_link, &symbol, sizeof real_link);
    if (!real_link) {
        errno = ENOSYS;
        return -1;
    }
    int result = real_link(oldpath, newpath);
    if (result == 0) recovery_linked = 1;
    return result;
}

int fsync(int fd)
{
    typedef int (*fsync_fn)(int);
    fsync_fn real_fsync = NULL;
    void *symbol = dlsym(RTLD_NEXT, "fsync");
    memcpy(&real_fsync, &symbol, sizeof real_fsync);
    if (!real_fsync) {
        errno = ENOSYS;
        return -1;
    }
    const char *fault = getenv("ZCL_TEST_PEER_RECOVERY_FSYNC_DIR");
    if (fault) {
        char descriptor[64], path[4096];
        int length = snprintf(descriptor, sizeof descriptor, "/proc/self/fd/%d", fd);
        ssize_t resolved = length > 0 && (size_t)length < sizeof descriptor
            ? readlink(descriptor, path, sizeof path) : -1;
        int flags = fcntl(fd, F_GETFL);
        if (resolved == (ssize_t)strlen(fault) &&
            memcmp(path, fault, (size_t)resolved) == 0 &&
            (recovery_linked || (flags >= 0 && (flags & O_ACCMODE) == O_RDONLY))) {
            errno = getenv("ZCL_TEST_PEER_RECOVERY_FSYNC_EINVAL") ? EINVAL : EIO;
            return -1;
        }
    }
    return real_fsync(fd);
}
