/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: atomic-or-rolled-back close-on-exec nonblocking pipes. */

#ifndef ZCLASSIC_PLATFORM_PIPE_COMPAT_H
#define ZCLASSIC_PLATFORM_PIPE_COMPAT_H

#include <errno.h>
#if defined(_WIN32)

/* An int cannot carry a 64-bit Windows HANDLE without truncation.  Callers
 * which require a native pipe must use a retained HANDLE capability; this
 * legacy fd interface therefore fails closed instead of manufacturing CRT
 * descriptors with ambiguous inheritance. */
static inline int platform_pipe_cloexec_nonblock(int pipefd[2])
{
    if (pipefd) {
        pipefd[0] = -1;
        pipefd[1] = -1;
    }
    errno = ENOTSUP;
    return -1;
}

#else
#include <fcntl.h>
#include <unistd.h>

static inline int platform_pipe_cloexec_nonblock(int pipefd[2])
{
#if defined(__linux__)
    return pipe2(pipefd, O_CLOEXEC | O_NONBLOCK);
#else
    if (pipe(pipefd) != 0)
        return -1;
    int read_fd_flags = fcntl(pipefd[0], F_GETFD);
    int write_fd_flags = fcntl(pipefd[1], F_GETFD);
    int read_status = fcntl(pipefd[0], F_GETFL);
    int write_status = fcntl(pipefd[1], F_GETFL);
    if (read_fd_flags >= 0 && write_fd_flags >= 0 &&
        read_status >= 0 && write_status >= 0 &&
        fcntl(pipefd[0], F_SETFD, read_fd_flags | FD_CLOEXEC) == 0 &&
        fcntl(pipefd[1], F_SETFD, write_fd_flags | FD_CLOEXEC) == 0 &&
        fcntl(pipefd[0], F_SETFL, read_status | O_NONBLOCK) == 0 &&
        fcntl(pipefd[1], F_SETFL, write_status | O_NONBLOCK) == 0)
        return 0;
    int saved_errno = errno;
    close(pipefd[0]);
    close(pipefd[1]);
    pipefd[0] = -1;
    pipefd[1] = -1;
    errno = saved_errno;
    return -1;
#endif
}
#endif

#endif
