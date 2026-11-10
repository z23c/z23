/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0.
 * Disposable PUBLIC byte fixture; neither a relay nor an SSH launcher. */
/* FreeBSD's native termios extensions are required by the raw-FD contract. */
#if !defined(__FreeBSD__)
#define _POSIX_C_SOURCE 200809L
#endif
#include <errno.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <sys/ioctl.h>
#include "guest_port.h" /* Exact independently owned raw-FD implementation. */
#if defined(__FreeBSD__) && (!defined(IMAXBEL) || !defined(PENDIN))
#error "FreeBSD binary transport requires visible native termios flags"
#endif

#define PB_BYTES 4097u
#define PB_DEADLINE_MS 25000

static int pb_refuse(const char *why)
{
    fprintf(stderr, "PUBLIC_PORT_REFUSED:%s\n", why);
    return 1;
}

static int64_t pb_now(void)
{
    struct timespec t;
    if (clock_gettime(CLOCK_MONOTONIC, &t) != 0) return -1;
    return (int64_t)t.tv_sec * 1000 + t.tv_nsec / 1000000;
}

static bool pb_wait(int fd, short events, int64_t end)
{
    for (;;) {
        int64_t now = pb_now();
        if (now < 0 || now >= end) return false;
        struct pollfd p = {fd, events, 0};
        int rc = poll(&p, 1, (int)(end - now));
        if (rc < 0 && errno == EINTR) continue;
        return rc > 0 && (p.revents & events) &&
            !(p.revents & (POLLERR | POLLHUP | POLLNVAL));
    }
}

static bool pb_read(int fd, uint8_t bytes[PB_BYTES], int64_t end)
{
    size_t used = 0;
    while (used < PB_BYTES) {
        if (!pb_wait(fd, POLLIN, end)) return false;
        ssize_t n = read(fd, bytes + used, PB_BYTES - used);
        if (n > 0) used += (size_t)n;
        else if (n == 0 || (errno != EINTR && errno != EAGAIN && errno != EWOULDBLOCK)) return false;
    }
    uint8_t extra;
    ssize_t n = read(fd, &extra, 1);
    return n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK);
}

static bool pb_write(int fd, const uint8_t bytes[PB_BYTES], int64_t end)
{
    size_t sent = 0;
    while (sent < PB_BYTES) {
        if (!pb_wait(fd, POLLOUT, end)) return false;
        ssize_t n = write(fd, bytes + sent, PB_BYTES - sent);
        if (n > 0) sent += (size_t)n;
        else if (n == 0 || (errno != EINTR && errno != EAGAIN && errno != EWOULDBLOCK)) return false;
    }
    return true;
}

static bool pb_gate(uint8_t want, int64_t end)
{
    uint8_t line[2];
    size_t got = 0;
    while (got < sizeof line) {
        if (!pb_wait(STDIN_FILENO, POLLIN, end)) return false;
        ssize_t n = read(STDIN_FILENO, line + got, sizeof line - got);
        if (n > 0) got += (size_t)n;
        else if (n == 0 || errno != EINTR) return false;
    }
    return line[0] == want && line[1] == '\n';
}

static bool pb_close_cycle(int *fd, const char *path, int64_t end)
{
    uint8_t first;
    int unread = 0;
    if (!pb_wait(*fd, POLLIN, end) || read(*fd, &first, 1) != 1 || first != 19u ||
        ioctl(*fd, FIONREAD, &unread) != 0 || unread <= 0) return false;
    if (fprintf(stderr, "PUBLIC_PORT_CLOSE_SETUP read=1 unread=%d\n", unread) < 0 ||
        fflush(stderr) != 0 || !pb_gate('g', end)) return false;
    int old = *fd;
    *fd = -1;
    if (close(old) != 0) return false;
    if (fprintf(stderr, "PUBLIC_PORT_CLOSED_T\n") < 0 || fflush(stderr) != 0 ||
        !pb_gate('r', end)) return false;
    *fd = open_raw(path);
    return *fd >= 0;
}

static bool pb_exchange(int fd, uint8_t bytes[PB_BYTES], unsigned bias, const char *role, int64_t now)
{
    if (!pb_read(fd, bytes, now + PB_DEADLINE_MS)) { pb_refuse("READ"); return false; }
    for (size_t i = 0; i < PB_BYTES; i++) {
        if (bytes[i] != (uint8_t)(i * 73u + 19u + bias)) { pb_refuse("BYTES"); return false; }
        bytes[i] ^= 0xa5u;
    }
    if (fprintf(stderr, "PUBLIC_PORT_RX_EXACT_%s:4097\n", role) < 0 || fflush(stderr) != 0) return false;
    if (!pb_write(fd, bytes, now + PB_DEADLINE_MS)) { pb_refuse("WRITE"); return false; }
    if (fprintf(stderr, "PUBLIC_PORT_EXACT_%s:4097\n", role) < 0 || fflush(stderr) != 0) return false;
    return true;
}

static int pb_validate(int argc, char **argv)
{
    if (argc != 2 || (strcmp(argv[1], "T") && strcmp(argv[1], "P") && strcmp(argv[1], "CLOSE"))) return pb_refuse("ROLE");
    int console_flags = fcntl(STDERR_FILENO, F_GETFL);
    if (console_flags < 0 || (console_flags & O_ACCMODE) == O_RDONLY)
        return pb_refuse("CONSOLE");
    return 0;
}

static bool pb_close_phase(int *fd, const char *path, int64_t now, unsigned *bias)
{
    if (!pb_close_cycle(fd, path, now + PB_DEADLINE_MS)) { pb_refuse("CLOSE_CYCLE"); return false; }
    *bias = 53u;
    if (fprintf(stderr, "PUBLIC_PORT_RAW_READY_T\n") < 0 || fflush(stderr) != 0) return false;
    return true;
}

int main(int argc, char **argv)
{
    int valid = pb_validate(argc, argv);
    if (valid) return valid;
    bool closing = !strcmp(argv[1], "CLOSE");
    const char *role = !strcmp(argv[1], "P") ? "P" : "T";
    const char *path = !strcmp(role, "T") ? "/dev/vtcon/z23.l0.t" : "/dev/vtcon/z23.l0.p";
    int64_t now = pb_now();
    if (now < 0) return pb_refuse("CLOCK");
    int fd = open_raw(path);
    if (fd < 0) return pb_refuse("RAW");
    int rc = 1;
    unsigned bias = !strcmp(argv[1], "P") ? 31u : 0u;
    uint8_t bytes[PB_BYTES];
    if (fprintf(stderr, "PUBLIC_PORT_RAW_READY_%s\n", role) < 0 || fflush(stderr) != 0) goto done;
    if (closing && !pb_close_phase(&fd, path, now, &bias)) goto done;
    if (!pb_exchange(fd, bytes, bias, role, now)) goto done;
    rc = 0;
done:
    if (fd >= 0 && close(fd) != 0) return pb_refuse("CLOSE");
    return rc;
}
