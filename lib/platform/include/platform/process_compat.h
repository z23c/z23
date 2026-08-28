/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: pinned-file execution and environment clearing across hosts. */

#ifndef ZCLASSIC_PLATFORM_PROCESS_COMPAT_H
#define ZCLASSIC_PLATFORM_PROCESS_COMPAT_H

#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <sys/stat.h>
#include <unistd.h>

#if defined(__APPLE__)
#include <crt_externs.h>
#elif !defined(_WIN32)
extern int clearenv(void);
#endif

static inline int platform_execve_fd(int fd, char *const argv[],
                                     char *const envp[])
{
#if defined(__APPLE__) || defined(_WIN32)
    /* macOS and Windows have no fexecve(2). Path reconstruction followed by
     * exec is not equivalent: another process can replace the pathname after
     * the identity check and before exec opens it. Refuse until the platform
     * supplies an atomic descriptor-bound execution primitive. */
    (void)fd;
    (void)argv;
    (void)envp;
    errno = ENOTSUP;
    return -1;
#else
    return fexecve(fd, argv, envp);
#endif
}

static inline int platform_clear_environment(void)
{
#if defined(_WIN32)
    /* The package adapter remains unavailable until Windows has restricted
     * token and Job Object confinement. Do not claim a clean environment
     * while the CRT and Win32 environment blocks can diverge. */
    errno = ENOTSUP;
    return -1;
#elif defined(__APPLE__)
    char ***environment = _NSGetEnviron();
    if (!environment || !*environment) {
        errno = EINVAL;
        return -1;
    }
    (*environment)[0] = NULL;
    return 0;
#else
    return clearenv();
#endif
}

#endif
