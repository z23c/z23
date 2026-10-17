/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: see mesh_terminal_hub_io.h. */

#if !defined(_WIN32)
#define _GNU_SOURCE
#include "mesh_terminal_hub_io.h"
#include "session/mesh_terminal_hub_portable.h"

#include "platform/time_compat.h"
#include "util/log_macros.h"

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdatomic.h>
#include <string.h>
#include <limits.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <sys/socket.h>
#include <unistd.h>

bool hub_io_send(int fd, const uint8_t *frame, size_t total)
{
    size_t sent = 0;
    while (sent < total) {
        ssize_t n = send(fd, frame + sent, total - sent, HUB_SEND_NOSIGNAL);
        if (n > 0)
            sent += (size_t)n;
        else if (n < 0 && errno != EINTR)
            return false;
    }
    return true;
}

bool hub_io_send_frame(int fd, uint8_t type, const uint8_t *payload, size_t len)
{
    uint8_t frame[MESH_TERMINAL_HUB_FRAME_MAX];
    if (len && payload)
        memcpy(frame + MESH_TERMINAL_HUB_HEADER_BYTES, payload, len);
    size_t total = mesh_terminal_hub_frame_seal(frame, type, len);
    return total != 0 && hub_io_send(fd, frame, total);
}

#if defined(ZCL_TESTING)
static void (*g_before_write)(int fd);

void mesh_terminal_hub_testing_before_write(void (*hook)(int fd))
{
    g_before_write = hook;
}

void hub_io_before_write(int fd)
{
    if (g_before_write)
        g_before_write(fd);
}
#endif

/* Off Linux there is no RWF_NOWAIT, so a pipe is only bounded if the descriptor
 * itself is non-blocking: then a write is all-or-EAGAIN (a record of at most
 * PIPE_BUF bytes stays atomic) and hub_wfd_write polls the REMAINING deadline
 * on EAGAIN. A pipe that is still blocking falls back to poll + PIPE_BUF,
 * which a second writer can beat; hub_wfd_sink_bounded refuses to
 * start a server on such a shared sink (the flags are never changed). ZCL_TESTING lets Linux take the same branch. */
#if defined(ZCL_TESTING)
static bool g_force_polled_fifo;

void mesh_terminal_hub_testing_force_polled_fifo(bool on)
{
    g_force_polled_fifo = on;
}
#endif

#if defined(__linux__)
#if defined(ZCL_TESTING)
#define HUB_POLLED_FIFO() g_force_polled_fifo
#else
#define HUB_POLLED_FIFO() false
#endif
#else
#define HUB_POLLED_FIFO() true
#endif

static bool hub_fd_nonblocking(int fd)
{
    int fl = fcntl(fd, F_GETFL);
    return fl >= 0 && (fl & O_NONBLOCK);
}

static void hub_wfd_open_fifo(struct hub_wfd *w)
{
    w->fifo = true;
    if (HUB_POLLED_FIFO())
        w->mode = hub_fd_nonblocking(w->fd) ? HUB_WFD_PLAIN : HUB_WFD_POLLED;
}

bool hub_wfd_sink_bounded(int fd)
{
    struct stat st;
    if (!HUB_POLLED_FIFO() || fstat(fd, &st) != 0 || !S_ISFIFO(st.st_mode) || hub_fd_nonblocking(fd))
        return true;
    LOG_FAIL("hub_io", "fd %d is a blocking pipe shared with other holders: a bounded write needs O_NONBLOCK, which the hub will not set on a descriptor it does not own", fd);
}

void hub_wfd_open(struct hub_wfd *w, int fd)
{
    struct stat st;
    *w = (struct hub_wfd){ .fd = fd, .mode = HUB_WFD_NOWAIT };
    if (fstat(fd, &st) != 0) {
#if !defined(__linux__)
        w->mode = HUB_WFD_POLLED;
#endif
        return;
    }
    if (S_ISSOCK(st.st_mode)) {
        w->mode = HUB_WFD_SOCKET;
        hub_socket_nosigpipe(fd); /* once per socket; no-op on Linux (MSG_NOSIGNAL) */
    }
    else if (S_ISREG(st.st_mode))
        w->mode = HUB_WFD_PLAIN;
    else if (S_ISFIFO(st.st_mode))
        hub_wfd_open_fifo(w);
    else
        w->mode = HUB_WFD_POLLED; /* tty/pty/char device: RWF_NOWAIT is not worth probing */
}

/* poll(POLLOUT, 0) then a chunk the ready descriptor is guaranteed to take:
 * PIPE_BUF for a pipe, ONE byte for anything else (POLLOUT on a tty can mean
 * a single free byte, and a bigger write would block past the caller's
 * deadline). A second writer can still win the readiness on a file that has
 * no RWF_NOWAIT; the audit sink and the screen pipes do have it. */
#if defined(ZCL_TESTING)
static void (*g_after_ready)(int fd);

void mesh_terminal_hub_testing_after_ready(void (*hook)(int fd))
{
    g_after_ready = hook;
}
#define HUB_AFTER_READY(fd) do { if (g_after_ready) g_after_ready(fd); } while (0)
#else
#define HUB_AFTER_READY(fd) ((void)0)
#endif

static ssize_t hub_wfd_try_polled(const struct hub_wfd *w, const void *buf, size_t n)
{
    struct pollfd pfd = { .fd = w->fd, .events = POLLOUT };
    if (poll(&pfd, 1, 0) <= 0 || !pfd.revents) { /* an error revent falls through: write reports it */
        errno = EAGAIN;
        return -1;
    }
    HUB_AFTER_READY(w->fd); /* a second writer can still win the room here */
    size_t cap = w->fifo ? PIPE_BUF : 1;
    return write(w->fd, buf, n < cap ? n : cap);
}

ssize_t hub_wfd_try(struct hub_wfd *w, const void *buf, size_t n)
{
    hub_io_before_write(w->fd);
    if (w->mode == HUB_WFD_SOCKET)
        return send(w->fd, buf, n, MSG_DONTWAIT | HUB_SEND_NOSIGNAL);
    if (w->mode == HUB_WFD_PLAIN) {
        HUB_AFTER_READY(w->fd); /* test seam: the instant before the syscall */
        return write(w->fd, buf, n);
    }
#if defined(__linux__)
    if (w->mode == HUB_WFD_NOWAIT) {
        struct iovec iov = { .iov_base = (void *)buf, .iov_len = n };
        ssize_t k = pwritev2(w->fd, &iov, 1, -1, RWF_NOWAIT);
        if (k >= 0 || (errno != EOPNOTSUPP && errno != EINVAL && errno != ENOSYS))
            return k;
        static atomic_flag warned = ATOMIC_FLAG_INIT;
        if (!atomic_flag_test_and_set(&warned))
            LOG_WARN("hub_io", "fd %d takes no RWF_NOWAIT (errno=%d): writes degrade to poll+%s chunks",
                     w->fd, errno, w->fifo ? "PIPE_BUF" : "1-byte");
        w->mode = HUB_WFD_POLLED; /* this file takes no RWF_NOWAIT */
    }
#endif
    return hub_wfd_try_polled(w, buf, n);
}

bool hub_wfd_write(struct hub_wfd *w, const void *buf, size_t n, int64_t deadline_ms)
{
    const uint8_t *p = buf;
    while (n) {
        ssize_t k = hub_wfd_try(w, p, n);
        if (k > 0) {
            p += k;
            n -= (size_t)k;
            continue;
        }
        if (k < 0 && errno == EINTR)
            continue;
        if (k < 0 && errno != EAGAIN)
            return false;
        int64_t left = deadline_ms - platform_time_monotonic_ms();
        struct pollfd pfd = { .fd = w->fd, .events = POLLOUT };
        if (left <= 0 || (poll(&pfd, 1, (int)left) < 0 && errno != EINTR))
            return false;
    }
    return true;
}

enum hub_rx_status hub_rx_next(const struct hub_rx *rx, uint8_t *type,
                               const uint8_t **payload, size_t *len)
{
    if (rx->fill < MESH_TERMINAL_HUB_HEADER_BYTES)
        return HUB_RX_NEED_MORE;
    if (!mesh_terminal_hub_frame_header(rx->buf, rx->fill, type, len))
        return HUB_RX_BAD;
    if (rx->fill < MESH_TERMINAL_HUB_HEADER_BYTES + *len)
        return HUB_RX_NEED_MORE;
    *payload = rx->buf + MESH_TERMINAL_HUB_HEADER_BYTES;
    return HUB_RX_FRAME;
}

void hub_rx_consume(struct hub_rx *rx, size_t payload_len)
{
    size_t total = MESH_TERMINAL_HUB_HEADER_BYTES + payload_len;
    if (total >= rx->fill) {
        rx->fill = 0;
        return;
    }
    rx->fill -= total;
    memmove(rx->buf, rx->buf + total, rx->fill);
}

long hub_rx_read(struct hub_rx *rx, int fd)
{
    ssize_t n = read(fd, rx->buf + rx->fill, sizeof(rx->buf) - rx->fill);
    if (n > 0) {
        rx->fill += (size_t)n;
        return (long)n;
    }
    if (n == 0)
        return 0;
    return (errno == EINTR || errno == EAGAIN) ? -2 : -1;
}

enum hub_wait hub_rx_wait(struct hub_rx *rx, int fd, int timeout_ms,
                          uint8_t *type, const uint8_t **payload, size_t *len)
{
    int64_t deadline = platform_time_monotonic_ms() + timeout_ms;
    for (;;) {
        enum hub_rx_status s = hub_rx_next(rx, type, payload, len);
        if (s == HUB_RX_FRAME)
            return HUB_WAIT_FRAME;
        if (s == HUB_RX_BAD)
            return HUB_WAIT_BAD;
        int64_t left = deadline - platform_time_monotonic_ms();
        if (left <= 0)
            return HUB_WAIT_TIMEOUT;
        struct pollfd pfd = { .fd = fd, .events = POLLIN };
        int ready = poll(&pfd, 1, (int)left);
        if (ready < 0 && errno != EINTR)
            return HUB_WAIT_CLOSED;
        if (ready <= 0)
            continue;
        long got = hub_rx_read(rx, fd);
        if (got == 0 || got == -1)
            return HUB_WAIT_CLOSED;
    }
}

#else
/* Linux-only unit: provide a declaration so the non-Linux translation unit
 * is not empty (ISO C forbids an empty translation unit). */
typedef int zcl_mesh_terminal_hub_io_unused;

#endif /* !_WIN32 */
