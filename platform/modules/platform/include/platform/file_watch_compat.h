/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: shared mutation event vocabulary with fail-closed inotify seams. */

#ifndef ZCLASSIC_PLATFORM_FILE_WATCH_COMPAT_H
#define ZCLASSIC_PLATFORM_FILE_WATCH_COMPAT_H

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#if defined(__linux__)
#include <sys/inotify.h>
#else

struct inotify_event {
    int wd;
    uint32_t mask;
    uint32_t cookie;
    uint32_t len;
    char name[];
};

#define IN_ATTRIB       0x00000004u
#define IN_CLOSE_WRITE  0x00000008u
#define IN_MOVED_FROM   0x00000040u
#define IN_MOVED_TO     0x00000080u
#define IN_CREATE       0x00000100u
#define IN_DELETE       0x00000200u
#define IN_DELETE_SELF  0x00000400u
#define IN_MOVE_SELF    0x00000800u
#define IN_Q_OVERFLOW   0x00004000u
#define IN_IGNORED      0x00008000u
#define IN_ISDIR        0x40000000u
#define IN_CLOEXEC      0x00080000u
#define IN_NONBLOCK     0x00000004u

static inline int inotify_init1(int flags)
{
    (void)flags;
    errno = ENOTSUP;
    return -1;
}

static inline int inotify_add_watch(int fd, const char *path, uint32_t mask)
{
    (void)fd;
    (void)path;
    (void)mask;
    errno = ENOTSUP;
    return -1;
}
#endif

/* The caller must keep target_fd open through this call.  The watch is
 * attached to that held inode even if its original name changes. */
static inline int platform_file_watch_fd(int watch_fd, int target_fd, uint32_t mask)
{
#if defined(__linux__)
    if (watch_fd < 0 || target_fd < 0) { errno = EBADF; return -1; }
    char path[64];
    int n = snprintf(path, sizeof(path), "/proc/self/fd/%d", target_fd);
    if (n <= 0 || (size_t)n >= sizeof(path)) { errno = EOVERFLOW; return -1; }
    return inotify_add_watch(watch_fd, path, mask);
#else
    (void)watch_fd; (void)target_fd; (void)mask;
    errno = ENOTSUP;
    return -1;
#endif
}

#endif
