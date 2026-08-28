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
typedef WSAPOLLFD platform_socket_pollfd;
#define PLATFORM_SOCKET_INVALID INVALID_SOCKET
#define PLATFORM_SOCKET_POLL_READ POLLRDNORM
#define PLATFORM_SOCKET_POLL_WRITE POLLWRNORM
#define PLATFORM_SOCKET_POLL_HANGUP POLLHUP
#define PLATFORM_SOCKET_POLL_ERROR POLLERR

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
#include <netdb.h>
#include <netinet/in.h> /* struct sockaddr_in, htons/htonl, INADDR_LOOPBACK —
                         * winsock2.h supplies these to the _WIN32 branch */
#include <netinet/tcp.h>
#include <poll.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>
typedef int platform_socket_t;
typedef struct pollfd platform_socket_pollfd;
#define PLATFORM_SOCKET_INVALID (-1)
#define PLATFORM_SOCKET_POLL_READ POLLIN
#define PLATFORM_SOCKET_POLL_WRITE POLLOUT
#define PLATFORM_SOCKET_POLL_HANGUP POLLHUP
#define PLATFORM_SOCKET_POLL_ERROR POLLERR

static inline bool platform_socket_runtime_init(void)
{
    return true;
}
#endif

struct platform_socket_poll_entry {
    platform_socket_t socket;
    bool writable;
    bool error;
};

static inline int platform_socket_wait_writable_many(
    struct platform_socket_poll_entry *entries, size_t count, int timeout_ms)
{
    if ((!entries && count != 0) || count > INT32_MAX)
        return -1;
#if defined(_WIN32)
    WSAPOLLFD descriptors[64];
#else
    struct pollfd descriptors[64];
#endif
    if (count > sizeof(descriptors) / sizeof(descriptors[0]))
        return -1;
    for (size_t i = 0; i < count; i++) {
        descriptors[i].fd = entries[i].socket;
        descriptors[i].events = POLLOUT;
        descriptors[i].revents = 0;
        entries[i].writable = false;
        entries[i].error = false;
    }
#if defined(_WIN32)
    int result = WSAPoll(descriptors, (ULONG)count, timeout_ms);
#else
    int result = poll(descriptors, count, timeout_ms);
#endif
    if (result <= 0) return result;
    for (size_t i = 0; i < count; i++) {
        short revents = descriptors[i].revents;
        entries[i].writable = (revents & POLLOUT) != 0;
        entries[i].error = (revents & (POLLERR | POLLHUP | POLLNVAL)) != 0;
    }
    return result;
}

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

static inline int platform_socket_set_reuse_address(platform_socket_t sock,
                                                     bool enabled)
{
    int value = enabled ? 1 : 0;
#if defined(_WIN32)
    return setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (const char *)&value,
                      (int)sizeof(value));
#else
    return setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &value, sizeof(value));
#endif
}

static inline int platform_socket_bind(platform_socket_t sock,
                                       const struct sockaddr *address,
                                       size_t address_size)
{
#if defined(_WIN32)
    if (address_size > INT32_MAX) return SOCKET_ERROR;
    return bind(sock, address, (int)address_size);
#else
    return bind(sock, address, (socklen_t)address_size);
#endif
}

static inline int platform_socket_listen(platform_socket_t sock, int backlog)
{ return listen(sock, backlog); }

static inline int platform_socket_local_address(platform_socket_t sock,
                                                 struct sockaddr *address,
                                                 size_t *address_size)
{
    if (!address_size) return -1;
#if defined(_WIN32)
    if (*address_size > INT32_MAX) return SOCKET_ERROR;
    int size = (int)*address_size;
    int result = getsockname(sock, address, &size);
    if (result == 0) *address_size = (size_t)size;
    return result;
#else
    socklen_t size = (socklen_t)*address_size;
    int result = getsockname(sock, address, &size);
    if (result == 0) *address_size = (size_t)size;
    return result;
#endif
}

static inline platform_socket_t platform_socket_accept(
    platform_socket_t sock, struct sockaddr *address, size_t *address_size)
{
    if (!address_size) return PLATFORM_SOCKET_INVALID;
#if defined(_WIN32)
    if (*address_size > INT32_MAX) return PLATFORM_SOCKET_INVALID;
    int size = (int)*address_size;
    SOCKET accepted = accept(sock, address, &size);
    if (accepted != INVALID_SOCKET) *address_size = (size_t)size;
    return accepted;
#else
    socklen_t size = (socklen_t)*address_size;
    int accepted = accept(sock, address, &size);
    if (accepted >= 0) *address_size = (size_t)size;
    return accepted;
#endif
}

/* Connected, process-local stream pair. Windows has no socketpair(); build
 * the equivalent over the IPv4 loopback and verify that accept returned the
 * exact client endpoint we created, so another local process cannot splice
 * itself into the pair. */
static inline bool platform_socket_pair(platform_socket_t pair[2])
{
    if (!pair) return false;
    pair[0] = PLATFORM_SOCKET_INVALID;
    pair[1] = PLATFORM_SOCKET_INVALID;
#if defined(_WIN32)
    platform_socket_t listener = platform_socket_open(AF_INET, SOCK_STREAM, 0,
                                                       true, false);
    platform_socket_t client = PLATFORM_SOCKET_INVALID;
    platform_socket_t accepted = PLATFORM_SOCKET_INVALID;
    struct sockaddr_in address = {0};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    int address_size = (int)sizeof(address);
    if (listener == PLATFORM_SOCKET_INVALID ||
        platform_socket_bind(listener, (const struct sockaddr *)&address,
                             sizeof(address)) != 0 ||
        getsockname(listener, (struct sockaddr *)&address, &address_size) != 0 ||
        platform_socket_listen(listener, 1) != 0)
        goto fail;
    client = platform_socket_open(AF_INET, SOCK_STREAM, 0, true, false);
    if (client == PLATFORM_SOCKET_INVALID ||
        connect(client, (const struct sockaddr *)&address,
                (int)sizeof(address)) != 0)
        goto fail;
    size_t accepted_size = sizeof(address);
    accepted = platform_socket_accept(listener, (struct sockaddr *)&address,
                                      &accepted_size);
    if (accepted == PLATFORM_SOCKET_INVALID) goto fail;
    struct sockaddr_in client_local = {0};
    struct sockaddr_in accepted_peer = {0};
    int client_size = (int)sizeof(client_local);
    int peer_size = (int)sizeof(accepted_peer);
    if (getsockname(client, (struct sockaddr *)&client_local, &client_size) != 0 ||
        getpeername(accepted, (struct sockaddr *)&accepted_peer, &peer_size) != 0 ||
        client_local.sin_family != accepted_peer.sin_family ||
        client_local.sin_port != accepted_peer.sin_port ||
        client_local.sin_addr.s_addr != accepted_peer.sin_addr.s_addr)
        goto fail;
    platform_socket_close(listener);
    pair[0] = client;
    pair[1] = accepted;
    return true;
fail:
    if (listener != PLATFORM_SOCKET_INVALID) platform_socket_close(listener);
    if (client != PLATFORM_SOCKET_INVALID) platform_socket_close(client);
    if (accepted != PLATFORM_SOCKET_INVALID) platform_socket_close(accepted);
    return false;
#else
    return socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == 0;
#endif
}

static inline int platform_socket_shutdown_both(platform_socket_t sock)
{
#if defined(_WIN32)
    return shutdown(sock, SD_BOTH);
#else
    return shutdown(sock, SHUT_RDWR);
#endif
}

static inline bool platform_socket_set_nonblocking(platform_socket_t sock,
                                                    bool enabled)
{
#if defined(_WIN32)
    u_long value = enabled ? 1UL : 0UL;
    return ioctlsocket(sock, FIONBIO, &value) == 0;
#else
    int flags = fcntl(sock, F_GETFL);
    if (flags < 0) return false;
    int updated = enabled ? (flags | O_NONBLOCK) : (flags & ~O_NONBLOCK);
    return fcntl(sock, F_SETFL, updated) == 0;
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
#if defined(_WIN32)
    if (timeout_ms < 0) return SOCKET_ERROR;
    fd_set writable;
    FD_ZERO(&writable);
    FD_SET(sock, &writable);
    struct timeval timeout = {
        .tv_sec = timeout_ms / 1000,
        .tv_usec = (timeout_ms % 1000) * 1000,
    };
    return select(0, NULL, &writable, NULL, &timeout);
#else
    if (sock < 0 || timeout_ms < 0) {
        errno = EINVAL;
        return -1;
    }
    struct pollfd descriptor = {.fd = sock, .events = POLLOUT};
    return poll(&descriptor, 1, timeout_ms);
#endif
}

static inline int platform_socket_wait_readable(platform_socket_t sock,
                                                 int timeout_ms)
{
#if defined(_WIN32)
    if (timeout_ms < 0) return SOCKET_ERROR;
    fd_set readable;
    FD_ZERO(&readable);
    FD_SET(sock, &readable);
    struct timeval timeout = {
        .tv_sec = timeout_ms / 1000,
        .tv_usec = (timeout_ms % 1000) * 1000,
    };
    return select(0, &readable, NULL, NULL, &timeout);
#else
    if (sock < 0 || timeout_ms < 0) {
        errno = EINVAL;
        return -1;
    }
    struct pollfd descriptor = {.fd = sock, .events = POLLIN};
    return poll(&descriptor, 1, timeout_ms);
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

static inline int platform_socket_set_no_delay(platform_socket_t sock,
                                                bool enabled)
{
    int value = enabled ? 1 : 0;
#if defined(_WIN32)
    return setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, (const char *)&value,
                      (int)sizeof(value));
#else
    return setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, &value, sizeof(value));
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

static inline int platform_socket_send(platform_socket_t sock,
                                       const void *data, size_t size)
{
    int part = size > INT32_MAX ? INT32_MAX : (int)size;
#if defined(_WIN32)
    return send(sock, (const char *)data, part, 0);
#else
    int flags = 0;
#ifdef MSG_NOSIGNAL
    flags = MSG_NOSIGNAL;
#endif
    return (int)send(sock, data, (size_t)part, flags);
#endif
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

static inline int platform_socket_peek(platform_socket_t sock, void *data,
                                       size_t size)
{
    int part = size > INT32_MAX ? INT32_MAX : (int)size;
#if defined(_WIN32)
    return recv(sock, (char *)data, part, MSG_PEEK);
#else
    return (int)recv(sock, data, (size_t)part, MSG_PEEK);
#endif
}

/* One nonblocking operation without leaking a socket-mode change to callers.
 * Windows has no MSG_DONTWAIT, so temporarily toggle FIONBIO and restore the
 * blocking mode expected by the framing layer. */
static inline int platform_socket_send_nonblocking(platform_socket_t sock,
                                                    const void *data,
                                                    size_t size)
{
    int part = size > INT32_MAX ? INT32_MAX : (int)size;
#if defined(_WIN32)
    if (!platform_socket_set_nonblocking(sock, true)) return SOCKET_ERROR;
    int result = send(sock, (const char *)data, part, 0);
    int error = result == SOCKET_ERROR ? WSAGetLastError() : 0;
    if (!platform_socket_set_nonblocking(sock, false) &&
        result != SOCKET_ERROR)
        return SOCKET_ERROR;
    if (result == SOCKET_ERROR) WSASetLastError(error);
    return result;
#else
    int flags = MSG_DONTWAIT;
#ifdef MSG_NOSIGNAL
    flags |= MSG_NOSIGNAL;
#endif
    return (int)send(sock, data, (size_t)part, flags);
#endif
}

static inline int platform_socket_receive_nonblocking(platform_socket_t sock,
                                                       void *data, size_t size)
{
    int part = size > INT32_MAX ? INT32_MAX : (int)size;
#if defined(_WIN32)
    if (!platform_socket_set_nonblocking(sock, true)) return SOCKET_ERROR;
    int result = recv(sock, (char *)data, part, 0);
    int error = result == SOCKET_ERROR ? WSAGetLastError() : 0;
    if (!platform_socket_set_nonblocking(sock, false) &&
        result != SOCKET_ERROR)
        return SOCKET_ERROR;
    if (result == SOCKET_ERROR) WSASetLastError(error);
    return result;
#else
    return (int)recv(sock, data, (size_t)part, MSG_DONTWAIT);
#endif
}

static inline int platform_socket_poll(platform_socket_pollfd *sockets,
                                       size_t count, int timeout_ms)
{
#if defined(_WIN32)
    if (count > ULONG_MAX || !platform_socket_runtime_init())
        return SOCKET_ERROR;
    return WSAPoll(sockets, (ULONG)count, timeout_ms);
#else
    return poll(sockets, (nfds_t)count, timeout_ms);
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

static inline bool platform_socket_format_address(int family,
                                                   const void *address,
                                                   char *text,
                                                   size_t text_size)
{
    if (!address || !text || text_size == 0 || text_size > INT32_MAX ||
        !platform_socket_runtime_init())
        return false;
#if defined(_WIN32)
    return InetNtopA(family, (void *)address, text, (DWORD)text_size) != NULL;
#else
    return inet_ntop(family, address, text, (socklen_t)text_size) != NULL;
#endif
}

static inline bool platform_socket_resolve_addresses(
    const char *host, bool allow_lookup, uint8_t (*addresses)[16],
    size_t capacity, size_t *count)
{
    if (count) *count = 0;
    if (!host || !host[0] || !addresses || capacity == 0 || !count ||
        !platform_socket_runtime_init())
        return false;
#if defined(_WIN32)
    wchar_t wide[256];
    if (MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, host, -1, wide,
                            (int)(sizeof(wide) / sizeof(*wide))) <= 0)
        return false;
    ADDRINFOW hints = {0};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    hints.ai_flags = allow_lookup ? 0 : AI_NUMERICHOST;
    PADDRINFOW results = NULL;
    if (GetAddrInfoW(wide, NULL, &hints, &results) != 0)
        return false;
    for (PADDRINFOW it = results; it && *count < capacity; it = it->ai_next) {
#else
    struct addrinfo hints = {0};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    hints.ai_flags = allow_lookup ? AI_ADDRCONFIG : AI_NUMERICHOST;
    struct addrinfo *results = NULL;
    if (getaddrinfo(host, NULL, &hints, &results) != 0)
        return false;
    for (struct addrinfo *it = results; it && *count < capacity;
         it = it->ai_next) {
#endif
        uint8_t *out = addresses[*count];
        if (it->ai_family == AF_INET &&
            it->ai_addrlen >= sizeof(struct sockaddr_in)) {
            const struct sockaddr_in *v4 =
                (const struct sockaddr_in *)it->ai_addr;
            memset(out, 0, 10);
            out[10] = 0xff;
            out[11] = 0xff;
            memcpy(out + 12, &v4->sin_addr, 4);
            (*count)++;
        } else if (it->ai_family == AF_INET6 &&
                   it->ai_addrlen >= sizeof(struct sockaddr_in6)) {
            const struct sockaddr_in6 *v6 =
                (const struct sockaddr_in6 *)it->ai_addr;
            memcpy(out, &v6->sin6_addr, 16);
            (*count)++;
        }
    }
#if defined(_WIN32)
    FreeAddrInfoW(results);
#else
    freeaddrinfo(results);
#endif
    return *count > 0;
}

/* Resolve one UTF-8 host name to the node's canonical 16-byte address form.
 * IPv4 is returned as an IPv4-mapped IPv6 address. Windows uses the wide
 * resolver so non-ASCII UTF-8 host names are never interpreted in the active
 * ANSI code page. */
static inline bool platform_socket_resolve_ip(const char *host,
                                               uint8_t address[16])
{
    if (!host || !host[0] || !address || !platform_socket_runtime_init())
        return false;
    memset(address, 0, 16);
#if defined(_WIN32)
    wchar_t wide[256];
    int count = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, host, -1,
                                    wide, (int)(sizeof(wide) / sizeof(*wide)));
    if (count <= 0)
        return false;
    ADDRINFOW hints = {0};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    PADDRINFOW results = NULL;
    if (GetAddrInfoW(wide, NULL, &hints, &results) != 0)
        return false;
    bool found = false;
    for (PADDRINFOW it = results; it && !found; it = it->ai_next) {
        if (it->ai_family == AF_INET &&
            it->ai_addrlen >= sizeof(struct sockaddr_in)) {
            const struct sockaddr_in *v4 =
                (const struct sockaddr_in *)it->ai_addr;
            address[10] = 0xff;
            address[11] = 0xff;
            memcpy(address + 12, &v4->sin_addr, 4);
            found = true;
        } else if (it->ai_family == AF_INET6 &&
                   it->ai_addrlen >= sizeof(struct sockaddr_in6)) {
            const struct sockaddr_in6 *v6 =
                (const struct sockaddr_in6 *)it->ai_addr;
            memcpy(address, &v6->sin6_addr, 16);
            found = true;
        }
    }
    FreeAddrInfoW(results);
#else
    struct addrinfo hints = {0};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    struct addrinfo *results = NULL;
    if (getaddrinfo(host, NULL, &hints, &results) != 0)
        return false;
    bool found = false;
    for (struct addrinfo *it = results; it && !found; it = it->ai_next) {
        if (it->ai_family == AF_INET &&
            it->ai_addrlen >= sizeof(struct sockaddr_in)) {
            const struct sockaddr_in *v4 =
                (const struct sockaddr_in *)it->ai_addr;
            address[10] = 0xff;
            address[11] = 0xff;
            memcpy(address + 12, &v4->sin_addr, 4);
            found = true;
        } else if (it->ai_family == AF_INET6 &&
                   it->ai_addrlen >= sizeof(struct sockaddr_in6)) {
            const struct sockaddr_in6 *v6 =
                (const struct sockaddr_in6 *)it->ai_addr;
            memcpy(address, &v6->sin6_addr, 16);
            found = true;
        }
    }
    freeaddrinfo(results);
#endif
    return found;
}

#endif
