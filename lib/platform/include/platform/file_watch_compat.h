/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: shared mutation event vocabulary with fail-closed inotify seams. */

#ifndef ZCLASSIC_PLATFORM_FILE_WATCH_COMPAT_H
#define ZCLASSIC_PLATFORM_FILE_WATCH_COMPAT_H

#if defined(__linux__)
#include <sys/inotify.h>
#else
#include <errno.h>
#include <stdint.h>

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

#endif
