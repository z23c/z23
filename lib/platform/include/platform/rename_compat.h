/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

#ifndef ZCL_PLATFORM_RENAME_COMPAT_H
#define ZCL_PLATFORM_RENAME_COMPAT_H

#include <errno.h>
#include <stdio.h>
#include <unistd.h>

static inline int platform_renameat_noreplace(int old_dirfd,
                                               const char *old_name,
                                               int new_dirfd,
                                               const char *new_name)
{
#if defined(__APPLE__)
    return renameatx_np(old_dirfd, old_name, new_dirfd, new_name, RENAME_EXCL);
#elif defined(__linux__)
    return renameat2(old_dirfd, old_name, new_dirfd, new_name,
                     RENAME_NOREPLACE);
#else
    (void)old_dirfd;
    (void)old_name;
    (void)new_dirfd;
    (void)new_name;
    errno = ENOTSUP;
    return -1;
#endif
}

#endif
