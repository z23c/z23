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
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <time.h>

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
static inline ssize_t platform_pipe_write_error(int error)
{
    errno = error;
    return -1;
}

#if defined(__linux__)
static inline bool platform_pipe_drain_sigpipe(const sigset_t *blocked)
{
    struct timespec zero = {0};
    int drained;
    do { drained = sigtimedwait(blocked, NULL, &zero); }
    while (drained < 0 && errno == EINTR);
    return drained == SIGPIPE || (drained < 0 && errno == EAGAIN);
}
#endif

/* Caller exclusively owns the descriptor and its flag changes for this call;
 * concurrent close, duplication, or writes through aliases are unsupported.
 * Writes once, preserving partial writes and errno. Never changes process-wide
 * signal disposition. Restoration failure returns -1 even after bytes were
 * written: restoration or drain failures use terminal EIO. Callers must stop
 * using the stream rather than retry those bytes, then log with context. This
 * primitive performs no diagnostic writes, including on failure.
 * On Linux, failed generated-signal drainage leaves SIGPIPE blocked in the
 * calling thread, because restoring an unblocked mask would be unsafe. */
static inline ssize_t platform_pipe_write_nosigpipe(int fd, const void *bytes,
                                                   size_t size)
{
#if defined(__APPLE__)
    int entry_errno = errno;
    int previous = fcntl(fd, F_GETNOSIGPIPE);
    if (previous < 0)
        return platform_pipe_write_error(errno);
    if (fcntl(fd, F_SETNOSIGPIPE, 1) < 0)
        return platform_pipe_write_error(errno);
    errno = entry_errno;
    ssize_t written = write(fd, bytes, size);
    int saved = errno;
    if (fcntl(fd, F_SETNOSIGPIPE, previous) < 0)
        return platform_pipe_write_error(EIO);
    errno = saved;
    return written;
#elif defined(__linux__)
    sigset_t blocked, previous, pending;
    sigemptyset(&blocked);
    sigaddset(&blocked, SIGPIPE);
    int entry_errno = errno;
    int error = pthread_sigmask(SIG_BLOCK, &blocked, &previous);
    if (error)
        return platform_pipe_write_error(error);
    bool known = sigpending(&pending) == 0;
    bool already = known && sigismember(&pending, SIGPIPE) == 1;
    int saved = errno;
    ssize_t written = -1;
    if (known) {
        errno = entry_errno;
        written = write(fd, bytes, size);
        saved = errno;
    }
    if (known && written < 0 && saved == EPIPE && !already) {
        if (!platform_pipe_drain_sigpipe(&blocked))
            return platform_pipe_write_error(EIO);
    }
    error = pthread_sigmask(SIG_SETMASK, &previous, NULL);
    if (error)
        return platform_pipe_write_error(EIO);
    if (!known)
        return platform_pipe_write_error(saved);
    errno = saved;
    return written;
#else
    (void)fd;
    (void)bytes;
    (void)size;
    return platform_pipe_write_error(ENOTSUP);
#endif
}

#endif

#endif
