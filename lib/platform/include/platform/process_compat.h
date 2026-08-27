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
    char path[1024];
    struct stat pinned;
    struct stat current;
    if (fcntl(fd, F_GETPATH, path) != 0 || fstat(fd, &pinned) != 0 ||
        stat(path, &current) != 0)
        return -1;
    if (pinned.st_dev != current.st_dev || pinned.st_ino != current.st_ino) {
        errno = ESTALE;
        return -1;
    }
    return execve(path, argv, envp);
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
