/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * sd_notify: direct AF_UNIX socket talk to systemd's notification
 * socket. See util/sd_notify.h for the rationale (no libsystemd
 * dependency, ~5 lines of protocol).
 */

#include "util/sd_notify.h"
#include "util/log_macros.h"

#include <errno.h>
#include <stddef.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

static _Atomic int      g_active;
static _Atomic uint64_t g_watchdog_usec;
static char             g_socket_path[108]; /* sun_path max */
static int              g_socket_path_len;
static sd_notify_health_check_fn _Atomic g_health_check;

bool sd_notify_init(void)
{
    if (atomic_load(&g_active))
        return true;

    const char *path = getenv("NOTIFY_SOCKET");
    if (!path || !path[0])
        return false;

    /* Linux abstract sockets are signaled by a leading '@' that we
     * translate to a NUL byte for the wire form. Path-mode sockets
     * just use the literal string. */
    size_t n = strlen(path);
    if (n >= sizeof(g_socket_path))
        return false;
    memcpy(g_socket_path, path, n + 1);
    if (g_socket_path[0] == '@')
        g_socket_path[0] = '\0';
    g_socket_path_len = (int)n;

    const char *wd = getenv("WATCHDOG_USEC");
    uint64_t wd_us = 0;
    if (wd && wd[0]) {
        long long v = strtoll(wd, NULL, 10);
        if (v > 0)
            wd_us = (uint64_t)v;
    }
    atomic_store(&g_watchdog_usec, wd_us);
    atomic_store(&g_active, 1);
    return true;
}

bool sd_notify_is_active(void)
{
    return atomic_load(&g_active) != 0;
}

uint64_t sd_notify_watchdog_usec(void)
{
    return atomic_load(&g_watchdog_usec);
}

/* Send a single notification line. Failures are logged but never
 * propagated as exit codes — the node must keep running even if the
 * notify socket has gone away. */
static bool sd_send(const char *msg)
{
    if (!atomic_load(&g_active) || !msg || !msg[0])
        return false;

    int fd = socket(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (fd < 0) {
        LOG_WARN("sd_notify", "socket failed: %s", strerror(errno));
        return false;
    }

    struct sockaddr_un sa;
    memset(&sa, 0, sizeof(sa));
    sa.sun_family = AF_UNIX;
    /* sun_path holds either a path-mode string (NUL-terminated) or a
     * Linux abstract path (leading NUL, then bytes). We stored the
     * caller's representation already in g_socket_path with the '@'
     * translation done in init. */
    memcpy(sa.sun_path, g_socket_path, (size_t)g_socket_path_len);
    socklen_t sa_len = (socklen_t)(offsetof(struct sockaddr_un, sun_path) +
                                    g_socket_path_len);

    ssize_t rc = sendto(fd, msg, strlen(msg), MSG_NOSIGNAL,
                        (struct sockaddr *)&sa, sa_len);
    close(fd);
    if (rc < 0) {
        LOG_WARN("sd_notify", "sendto failed: %s", strerror(errno));
        return false;
    }
    return true;
}

bool sd_notify_ready(void)
{
    return sd_send("READY=1\n");
}

bool sd_notify_watchdog_ping(void)
{
    sd_notify_health_check_fn health =
        atomic_load_explicit(&g_health_check, memory_order_acquire);
    if (health && !health())
        return false;
    return sd_send("WATCHDOG=1\n");
}

void sd_notify_set_health_check(sd_notify_health_check_fn fn)
{
    atomic_store_explicit(&g_health_check, fn, memory_order_release);
}

bool sd_notify_status(const char *msg)
{
    if (!msg) return false;
    char buf[512];
    int n = snprintf(buf, sizeof(buf), "STATUS=%s\n", msg);
    if (n <= 0) return false;
    return sd_send(buf);
}

bool sd_notify_extend_timeout_usec(uint64_t usec)
{
    if (usec == 0)
        return false;
    char buf[64];
    int n = snprintf(buf, sizeof(buf), "EXTEND_TIMEOUT_USEC=%llu\n",
                     (unsigned long long)usec);
    if (n <= 0) return false;
    return sd_send(buf);
}

bool sd_notify_stopping(const char *reason)
{
    char buf[512];
    int n = snprintf(buf, sizeof(buf), "STOPPING=1\nSTATUS=%s\n",
                     reason && reason[0] ? reason : "shutting down");
    if (n <= 0) return false;
    return sd_send(buf);
}

#ifdef ZCL_TESTING
void sd_notify_reset_for_testing(void)
{
    atomic_store(&g_active, 0);
    atomic_store(&g_watchdog_usec, 0);
    g_socket_path[0] = '\0';
    g_socket_path_len = 0;
    atomic_store_explicit(&g_health_check, NULL, memory_order_release);
}
#endif
