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
#else
extern int clearenv(void);
#endif

static inline int platform_execve_fd(int fd, char *const argv[],
                                     char *const envp[])
{
#if defined(__APPLE__)
    /* macOS has no fexecve(2). F_GETPATH followed by execve(path) is not an
     * equivalent: another process can replace the pathname after the inode
     * check and before execve opens it. Refuse until this platform supplies
     * an atomic descriptor-bound execution primitive. */
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
#if defined(__APPLE__)
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
