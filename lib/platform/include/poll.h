/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: POSIX poll surface backed by WSAPoll for native Windows sockets. */
#ifndef ZCL_PLATFORM_POLL_H
#define ZCL_PLATFORM_POLL_H
#if defined(_WIN32)
#include <errno.h>
#include <winsock2.h>
typedef ULONG nfds_t;
static inline int platform_poll(struct pollfd *fds, nfds_t count,
                                int timeout_ms)
{
    int result = WSAPoll((LPWSAPOLLFD)fds, count, timeout_ms);
    if (result == SOCKET_ERROR) {
        int error = WSAGetLastError();
        errno = error == WSAEINTR ? EINTR : EIO;
        return -1;
    }
    return result;
}
#define poll(fds, count, timeout_ms) \
    platform_poll((fds), (count), (timeout_ms))
#else
#if defined(__GNUC__)
#pragma GCC system_header
#endif
#include_next <poll.h>
#endif
#endif
