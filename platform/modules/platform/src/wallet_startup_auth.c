/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: validate and receive startup wallet authentication over a local stream. */
#if defined(__linux__) && !defined(_GNU_SOURCE)
#define _GNU_SOURCE
#endif
#include "platform/wallet_startup_auth.h"
#include "platform/time_compat.h"
#include "base/cleanse.h"
#include "platform/wallet_startup_auth_protocol.h"
#include <string.h>
#if defined(__linux__)
#include <errno.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

static bool auth_peer_valid(int fd)
{
    struct sockaddr_storage local, peer;
    socklen_t n = sizeof(local), pn = sizeof(peer), tn = sizeof(int);
    int type = 0;
    if (fd < 3 || getsockname(fd, (struct sockaddr *)&local, &n) != 0 ||
        getpeername(fd, (struct sockaddr *)&peer, &pn) != 0 ||
        local.ss_family != AF_UNIX || peer.ss_family != AF_UNIX ||
        getsockopt(fd, SOL_SOCKET, SO_TYPE, &type, &tn) != 0 || type != SOCK_STREAM)
        return false;
    struct { pid_t pid; uid_t uid; gid_t gid; } cred;
    socklen_t cn = sizeof(cred);
    return getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &cred, &cn) == 0 &&
           cn == sizeof(cred) && cred.uid == geteuid();
}

static bool auth_wait(int fd, bool sending, int64_t deadline)
{
    for (;;) {
        int64_t now = platform_time_monotonic_ms();
        if (now <= 0 || now >= deadline) return false;
        int64_t left = deadline - now;
        struct pollfd pollfd = {.fd = fd, .events = sending ? POLLOUT : POLLIN};
        int rc = poll(&pollfd, 1, left > 1000 ? 1000 : (int)left);
        if (rc < 0 && errno == EINTR) continue;
        if (rc < 0 || (rc > 0 && (pollfd.revents & (POLLERR | POLLNVAL)))) return false;
        if (rc > 0) return true;
    }
}

static bool auth_io(int fd, void *buf, size_t len, bool sending, int64_t deadline)
{
    unsigned char *p = buf;
    while (len) {
        if (!auth_wait(fd, sending, deadline)) return false;
        int flags = MSG_DONTWAIT;
#ifdef MSG_NOSIGNAL
        if (sending) flags |= MSG_NOSIGNAL;
#endif
        ssize_t n = sending ? send(fd, p, len, flags) : recv(fd, p, len, flags);
        if (n < 0 && (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)) continue;
        if (n <= 0) return false;
        p += n; len -= (size_t)n;
    }
    return true;
}

static bool auth_secret_length(const unsigned char hdr[8], size_t cap, size_t *len)
{
    *len = (size_t)hdr[6] | (size_t)hdr[7] << 8;
    return !memcmp(hdr, "ZWA1", 4) && hdr[4] == Z23_WALLET_AUTH_SECRET && !hdr[5] &&
           *len > 0 && *len <= Z23_WALLET_AUTH_SECRET_MAX && *len < cap;
}

static bool auth_receive_linux(int fd, int64_t timeout_ms, char *out, size_t cap)
{
    if (!out || cap == 0) { platform_wallet_startup_auth_close(fd); return false; }
    memory_cleanse(out, cap);
    bool ok = false;
    int64_t now = platform_time_monotonic_ms();
    if (timeout_ms <= 0 || now <= 0 || now > INT64_MAX - timeout_ms || !auth_peer_valid(fd)) goto done;
    int64_t deadline = now + timeout_ms;
    unsigned char req[8] = {'Z','W','A','1', Z23_WALLET_AUTH_REQUEST, 0, 0, 0};
    unsigned char hdr[8];
    if (!auth_io(fd, req, sizeof(req), true, deadline) || !auth_io(fd, hdr, sizeof(hdr), false, deadline)) goto done;
    size_t len = 0;
    if (!auth_secret_length(hdr, cap, &len)) goto done;
    if (!auth_io(fd, out, len, false, deadline) || memchr(out, 0, len)) goto done;
    out[len] = '\0';
    ok = true;
done:
    platform_wallet_startup_auth_close(fd);
    if (!ok) memory_cleanse(out, cap);
    return ok;
}
#endif
#if !defined(__linux__) && !defined(_WIN32)
#include <unistd.h>
#endif
void platform_wallet_startup_auth_close(int fd)
{
#if !defined(_WIN32)
    if (fd >= 3) close(fd);
#else
    (void)fd;
#endif
}
bool platform_wallet_startup_auth_receive(int fd, int64_t timeout_ms, char *out, size_t cap)
{
#if defined(__linux__)
    return auth_receive_linux(fd, timeout_ms, out, cap);
#else
    (void)timeout_ms;
    platform_wallet_startup_auth_close(fd);
    if (out && cap) memory_cleanse(out, cap);
    return false;
#endif
}
