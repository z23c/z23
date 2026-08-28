/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: socket lifecycle, error, nonblocking, and timeout portability. */

#ifndef ZCLASSIC_PLATFORM_SOCKET_COMPAT_H
#define ZCLASSIC_PLATFORM_SOCKET_COMPAT_H

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

#if defined(_WIN32)
#include <winsock2.h>
#include <ws2tcpip.h>
typedef SOCKET platform_socket_t;
#define PLATFORM_SOCKET_INVALID INVALID_SOCKET

static INIT_ONCE platform_winsock_once = INIT_ONCE_STATIC_INIT;
static BOOL CALLBACK platform_winsock_start(PINIT_ONCE once, PVOID parameter,
                                             PVOID *context)
{
    (void)once;
    (void)parameter;
    (void)context;
    WSADATA data;
    return WSAStartup(MAKEWORD(2, 2), &data) == 0;
}

static inline bool platform_socket_runtime_init(void)
{
    return InitOnceExecuteOnce(&platform_winsock_once, platform_winsock_start,
                               NULL, NULL) != 0;
}
#else
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h> /* struct sockaddr_in, htons/htonl, INADDR_LOOPBACK —
                         * winsock2.h supplies these to the _WIN32 branch */
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>
typedef int platform_socket_t;
#define PLATFORM_SOCKET_INVALID (-1)

static inline bool platform_socket_runtime_init(void)
{
    return true;
}
#endif

/* Includes space for the terminating NUL.  Keep address text sizing in the
 * platform boundary so application code does not depend on which socket
 * headers expose the POSIX INET_* constants. */
#define PLATFORM_IPV4_ADDRESS_TEXT_SIZE 16U
#define PLATFORM_IPV6_ADDRESS_TEXT_SIZE 46U

static inline platform_socket_t platform_socket_open(int domain, int type,
                                                      int protocol,
                                                      bool close_on_exec,
                                                      bool nonblocking)
{
#if defined(_WIN32)
    if (!platform_socket_runtime_init())
        return PLATFORM_SOCKET_INVALID;
    DWORD flags = close_on_exec ? WSA_FLAG_NO_HANDLE_INHERIT : 0;
    SOCKET sock = WSASocketW(domain, type, protocol, NULL, 0, flags);
    if (sock == INVALID_SOCKET)
        return PLATFORM_SOCKET_INVALID;
    if (nonblocking) {
        u_long enabled = 1;
        if (ioctlsocket(sock, FIONBIO, &enabled) != 0) {
            closesocket(sock);
            return PLATFORM_SOCKET_INVALID;
        }
    }
    return sock;
#elif defined(__linux__)
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

static inline int platform_socket_close(platform_socket_t sock)
{
#if defined(_WIN32)
    return closesocket(sock);
#else
    return close(sock);
#endif
}

static inline int platform_socket_last_error(void)
{
#if defined(_WIN32)
    return WSAGetLastError();
#else
    return errno;
#endif
}

static inline bool platform_socket_error_in_progress(int error)
{
#if defined(_WIN32)
    return error == WSAEWOULDBLOCK || error == WSAEINPROGRESS;
#else
    return error == EINPROGRESS;
#endif
}

static inline bool platform_socket_error_refused(int error)
{
#if defined(_WIN32)
    return error == WSAECONNREFUSED;
#else
    return error == ECONNREFUSED;
#endif
}

static inline bool platform_socket_error_timed_out(int error)
{
#if defined(_WIN32)
    return error == WSAETIMEDOUT;
#else
    return error == ETIMEDOUT;
#endif
}

static inline bool platform_socket_error_would_block(int error)
{
#if defined(_WIN32)
    return error == WSAEWOULDBLOCK;
#else
    return error == EAGAIN || error == EWOULDBLOCK;
#endif
}

static inline bool platform_socket_error_interrupted(int error)
{
#if defined(_WIN32)
    return error == WSAEINTR;
#else
    return error == EINTR;
#endif
}

static inline int platform_socket_connect(platform_socket_t sock,
                                           const struct sockaddr *address,
                                           size_t address_size)
{
#if defined(_WIN32)
    if (address_size > INT32_MAX) return SOCKET_ERROR;
    return connect(sock, address, (int)address_size);
#else
    return connect(sock, address, (socklen_t)address_size);
#endif
}

static inline const char *platform_socket_error_string(int error, char *out,
                                                       size_t out_size)
{
#if defined(_WIN32)
    if (!out || out_size == 0)
        return "Winsock error";
    int written = snprintf(out, out_size, "Winsock error %d", error);
    return written >= 0 && (size_t)written < out_size ? out : "Winsock error";
#else
    (void)out;
    (void)out_size;
    return strerror(error);
#endif
}

static inline int platform_socket_pending_error(platform_socket_t sock,
                                                 int *error)
{
#if defined(_WIN32)
    int length = (int)sizeof(*error);
    return getsockopt(sock, SOL_SOCKET, SO_ERROR, (char *)error, &length);
#else
    socklen_t length = sizeof(*error);
    return getsockopt(sock, SOL_SOCKET, SO_ERROR, error, &length);
#endif
}

static inline int platform_socket_wait_writable(platform_socket_t sock,
                                                 int timeout_ms)
{
    fd_set writable;
    FD_ZERO(&writable);
    FD_SET(sock, &writable);
    struct timeval timeout = {
        .tv_sec = timeout_ms / 1000,
        .tv_usec = (timeout_ms % 1000) * 1000,
    };
#if defined(_WIN32)
    return select(0, NULL, &writable, NULL, &timeout);
#else
    return select(sock + 1, NULL, &writable, NULL, &timeout);
#endif
}

static inline int platform_socket_wait_readable(platform_socket_t sock,
                                                 int timeout_ms)
{
    fd_set readable;
    FD_ZERO(&readable);
    FD_SET(sock, &readable);
    struct timeval timeout = {
        .tv_sec = timeout_ms / 1000,
        .tv_usec = (timeout_ms % 1000) * 1000,
    };
#if defined(_WIN32)
    return select(0, &readable, NULL, NULL, &timeout);
#else
    return select(sock + 1, &readable, NULL, NULL, &timeout);
#endif
}

static inline int platform_socket_set_receive_timeout(platform_socket_t sock,
                                                       int timeout_ms)
{
#if defined(_WIN32)
    DWORD timeout = (DWORD)timeout_ms;
    return setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char *)&timeout,
                      (int)sizeof(timeout));
#else
    struct timeval timeout = {
        .tv_sec = timeout_ms / 1000,
        .tv_usec = (timeout_ms % 1000) * 1000,
    };
    return setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout,
                      sizeof(timeout));
#endif
}

static inline int platform_socket_set_send_timeout(platform_socket_t sock,
                                                    int timeout_ms)
{
#if defined(_WIN32)
    DWORD timeout = (DWORD)timeout_ms;
    return setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (const char *)&timeout,
                      (int)sizeof(timeout));
#else
    struct timeval timeout = {
        .tv_sec = timeout_ms / 1000,
        .tv_usec = (timeout_ms % 1000) * 1000,
    };
    return setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &timeout,
                      sizeof(timeout));
#endif
}

static inline bool platform_socket_send_all(platform_socket_t sock,
                                             const void *data, size_t size)
{
    const unsigned char *bytes = data;
    size_t sent = 0;
    while (sent < size) {
        size_t remaining = size - sent;
        int part = remaining > INT32_MAX ? INT32_MAX : (int)remaining;
#if defined(_WIN32)
        int result = send(sock, (const char *)bytes + sent, part, 0);
#else
        int flags = 0;
#ifdef MSG_NOSIGNAL
        flags = MSG_NOSIGNAL;
#endif
        int result = (int)send(sock, bytes + sent, (size_t)part, flags);
#endif
        if (result < 0) {
#if defined(_WIN32)
            if (WSAGetLastError() == WSAEINTR) continue;
#else
            if (errno == EINTR) continue;
#endif
            return false;
        }
        if (result == 0) return false;
        sent += (size_t)result;
    }
    return true;
}

static inline int platform_socket_receive(platform_socket_t sock, void *data,
                                           size_t size)
{
    int part = size > INT32_MAX ? INT32_MAX : (int)size;
#if defined(_WIN32)
    int result;
    do {
        result = recv(sock, (char *)data, part, 0);
    } while (result < 0 && WSAGetLastError() == WSAEINTR);
    return result;
#else
    int result;
    do {
        result = (int)recv(sock, data, (size_t)part, 0);
    } while (result < 0 && errno == EINTR);
    return result;
#endif
}

/* Parse one numeric network address without exposing the platform-specific
 * inet_pton declaration or its Windows startup requirement to callers. */
static inline int platform_socket_parse_address(int family, const char *text,
                                                 void *address)
{
    if (!text || !address || !platform_socket_runtime_init())
        return 0;
#if defined(_WIN32)
    return InetPtonA(family, text, address);
#else
    return inet_pton(family, text, address);
#endif
}

#endif
