/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: sockets with portable close-on-exec and nonblocking setup. */

#ifndef ZCLASSIC_PLATFORM_SOCKET_COMPAT_H
#define ZCLASSIC_PLATFORM_SOCKET_COMPAT_H

#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <sys/socket.h>
#include <unistd.h>

static inline int platform_socket_open(int domain, int type, int protocol,
                                       bool close_on_exec, bool nonblocking)
{
#if defined(__linux__)
    int flags = type;
    if (close_on_exec) flags |= SOCK_CLOEXEC;
    if (nonblocking) flags |= SOCK_NONBLOCK;
    return socket(domain, flags, protocol);
#else
    int fd = socket(domain, type, protocol);
    if (fd < 0)
        return -1;
    int descriptor_flags = fcntl(fd, F_GETFD);
    int status_flags = fcntl(fd, F_GETFL);
    if (descriptor_flags >= 0 && status_flags >= 0 &&
        (!close_on_exec ||
         fcntl(fd, F_SETFD, descriptor_flags | FD_CLOEXEC) == 0) &&
        (!nonblocking ||
         fcntl(fd, F_SETFL, status_flags | O_NONBLOCK) == 0))
        return fd;
    int saved_errno = errno;
    close(fd);
    errno = saved_errno;
    return -1;
#endif
}

#endif
