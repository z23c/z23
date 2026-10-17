/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: the few places where the terminal hub's descriptor handling differs
 * between Linux and the other POSIX hosts (Darwin), in one header. Linux keeps
 * the single atomic syscalls it always used (accept4, pipe2, SOCK_CLOEXEC,
 * MSG_NOSIGNAL, pwritev2); elsewhere the same effect is reached with fcntl and
 * SO_NOSIGPIPE.
 *
 * Fork race on the non-Linux path: close-on-exec is set by fcntl right after
 * the descriptor exists, not atomically. That is safe here because every hub
 * descriptor is created on a thread that is the only one in its process able
 * to fork: the hub supervisor (accept, then fork) and the connect edge
 * (socketpair, then fork) start no threads, so nothing can fork between the
 * creating call and the fcntl. Shared by the hub sources and the connect edge. */

#ifndef ZCL_SESSION_MESH_TERMINAL_HUB_PORTABLE_H
#define ZCL_SESSION_MESH_TERMINAL_HUB_PORTABLE_H
#if !defined(_WIN32)

#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#if defined(__linux__)
#include <sys/syscall.h>
#endif

#include "platform/pipe_compat.h"

/* send() flags that keep a dead peer from raising SIGPIPE. Linux says it per
 * call; elsewhere hub_socket_nosigpipe() says it once per socket. */
#if defined(__linux__)
#define HUB_SEND_NOSIGNAL MSG_NOSIGNAL
#else
#define HUB_SEND_NOSIGNAL 0
#endif

/* Once per socket, at creation or accept: Darwin has no MSG_NOSIGNAL, so the
 * socket itself must refuse to raise SIGPIPE. A no-op on Linux (zero extra
 * syscalls on the Linux path). */
static inline void hub_socket_nosigpipe(int fd)
{
#if defined(__APPLE__)
    int one = 1;
    (void)setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof one);
#else
    (void)fd;
#endif
}

/* A close-on-exec pipe pair with both ends non-blocking. */
static inline int hub_pipe_cloexec_nonblock(int fds[2])
{
    return platform_pipe_cloexec_nonblock(fds);
}

/* Sets FD_CLOEXEC on an existing descriptor; false (errno kept) on failure. */
static inline bool hub_fd_set_cloexec(int fd)
{
    int flags = fcntl(fd, F_GETFD);
    return flags >= 0 && fcntl(fd, F_SETFD, flags | FD_CLOEXEC) == 0;
}

/* Sets O_NONBLOCK on an existing descriptor. */
static inline bool hub_fd_set_nonblock(int fd)
{
    int flags = fcntl(fd, F_GETFL);
    return flags >= 0 && fcntl(fd, F_SETFL, flags | O_NONBLOCK) == 0;
}

/* accept() whose result is close-on-exec. The accepted socket's blocking mode
 * is whatever the platform gives it, as it always was on Linux. */
static inline int hub_accept_cloexec(int listener)
{
#if defined(__linux__)
    return accept4(listener, NULL, NULL, SOCK_CLOEXEC);
#else
    int fd = accept(listener, NULL, NULL);
    if (fd >= 0 && !hub_fd_set_cloexec(fd)) {
        int saved = errno;
        close(fd);
        errno = saved;
        return -1;
    }
    return fd;
#endif
}

/* A close-on-exec stream socket pair. */
static inline int hub_socketpair_cloexec(int sv[2])
{
#if defined(__linux__)
    return socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sv);
#else
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0)
        return -1;
    if (hub_fd_set_cloexec(sv[0]) && hub_fd_set_cloexec(sv[1]))
        return 0;
    int saved = errno;
    close(sv[0]);
    close(sv[1]);
    errno = saved;
    return -1;
#endif
}

/* A close-on-exec TCP/IPv4 stream socket. */
static inline int hub_tcp_socket_cloexec(void)
{
#if defined(__linux__)
    return socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
#else
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd >= 0 && !hub_fd_set_cloexec(fd)) {
        int saved = errno;
        close(fd);
        errno = saved;
        return -1;
    }
    return fd;
#endif
}

/* The shell's pidfd, or -1 where the host has none (every non-Linux host);
 * callers already fall back to bounded polling on -1. */
static inline int hub_pidfd_open(pid_t pid)
{
#if defined(__linux__)
    return (int)syscall(SYS_pidfd_open, pid, 0);
#else
    (void)pid;
    return -1;
#endif
}

/* Whether this host can confine a session's shell. Only the Linux Landlock +
 * seccomp stack exists; Darwin Seatbelt confinement is a later unit, so until
 * then a non-Linux hub refuses every session with the typed confinement
 * refusal instead of running a shell unconfined. */
static inline bool hub_confinement_supported(void)
{
#if defined(__linux__)
    return true;
#else
    return false;
#endif
}

#endif /* !_WIN32 */
#endif
