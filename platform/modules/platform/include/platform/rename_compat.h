/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: atomic no-clobber rename for installers that must never overwrite
 * a concurrent writer's file (package_checkout, dev_failure_store) —
 * renameat2(RENAME_NOREPLACE) on Linux, renameatx_np(RENAME_EXCL) on Darwin,
 * and a hard ENOTSUP (not a silent plain rename) on any other host, since a
 * plain rename() there would reintroduce the clobber this seam exists to
 * rule out. */

#ifndef ZCL_PLATFORM_RENAME_COMPAT_H
#define ZCL_PLATFORM_RENAME_COMPAT_H

#include <errno.h>
#include <stdio.h>
#include <unistd.h>

#if defined(__linux__)
#include <sys/syscall.h>

/* renameat2() and RENAME_NOREPLACE are Linux extensions that glibc publishes
 * only under _GNU_SOURCE, while this tree compiles to strict ISO C with
 * _POSIX_C_SOURCE. A header may not set a feature macro -- it is included
 * after libc headers have already been read, so the definition would arrive
 * too late and silently do nothing. Going straight to the kernel keeps this
 * seam self-contained: it compiles the same under either setting, so no
 * caller has to be built with special flags to get the guarantee. */
#ifndef RENAME_NOREPLACE
#define RENAME_NOREPLACE (1u << 0)
#endif
long syscall(long number, ...);
#endif

static inline int platform_renameat_noreplace(int old_dirfd,
                                               const char *old_name,
                                               int new_dirfd,
                                               const char *new_name)
{
#if defined(__APPLE__)
    return renameatx_np(old_dirfd, old_name, new_dirfd, new_name, RENAME_EXCL);
#elif defined(__linux__)
    return (int)syscall(SYS_renameat2, old_dirfd, old_name, new_dirfd,
                        new_name, (unsigned int)RENAME_NOREPLACE);
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
