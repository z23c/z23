/* Copyright 2026 Rhett Creighton - Apache License 2.0 */
#define _GNU_SOURCE
#include "test/test_core.h"
int test_portfwd(void);
#if defined(__linux__)
[[maybe_unused]] static int portfwd_fixture_main(int argc, char **argv);
#define main portfwd_fixture_main
#include "../../../tools/zcl_portfwd.c"
#undef main

/* Drive the real epoll dispatcher without a child, listener, or network. */
static int portfwd_pump(int timeout)
{
    struct epoll_event events[16];
    int n = epoll_wait(g_epfd, events, 16, timeout);
    if (n < 0) return -1;
    for (int i = 0; i < n; i++)
        dispatch_epoll_event(events[i].data.ptr, events[i].events);
    return n;
}

#ifdef PORTFWD_MANAGED_INTEREST
/* Hold upstream completion until after the client request and EOF are read. */
static bool portfwd_connect_order(void)
{
    int l[2] = {-1, -1}, r[2] = {-1, -1};
    struct endpoint *a = NULL, *b = NULL;
    bool ok = false;
    char reply[4];
    if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0, l) < 0 ||
        socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0, r) < 0) goto done;
    a = calloc(1, sizeof(*a)); b = calloc(1, sizeof(*b));
    if (!a || !b) goto done;
    a->fd = l[1]; b->fd = r[0]; l[1] = r[0] = -1;
    a->peer = b; b->peer = a; b->connecting = true;
    if (write(l[0], "abc", 3) != 3 || shutdown(l[0], SHUT_WR) < 0) goto done;
    dispatch_epoll_event(a, EPOLLIN | EPOLLRDHUP);
    if (a->dead || !a->read_eof || b->buf_len != 3 || b->write_shutdown || !b->connecting)
        goto done;
    dispatch_epoll_event(b, EPOLLOUT);
    if (a->dead || b->connecting || !b->write_shutdown ||
        read(r[1], reply, sizeof(reply)) != 3 || memcmp(reply, "abc", 3) ||
        read(r[1], reply, sizeof(reply)) != 0) goto done;
    ok = true;
done:
    if (a && b && a->peer && !a->dead) close_pair(a);
    else if (!a || !b) { free(a); free(b); }
    drain_free_list();
    for (int i = 0; i < 2; i++) { if (l[i] >= 0) close(l[i]); if (r[i] >= 0) close(r[i]); }
    return ok;
}

/* A bound but non-listening local port deterministically refuses the connect. */
static bool portfwd_connect_failure(void)
{
    int reservation = -1, client[2] = {-1, -1}, upstream = -1;
    struct endpoint *a = NULL, *b = NULL;
    struct sockaddr_in sa = {.sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    socklen_t len = sizeof(sa);
    bool ok = false;
    reservation = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (reservation < 0 || bind(reservation, (struct sockaddr *)&sa, sizeof(sa)) < 0 ||
        getsockname(reservation, (struct sockaddr *)&sa, &len) < 0 ||
        socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0, client) < 0) goto done;
    upstream = connect_target(ntohs(sa.sin_port));
    if (upstream < 0) { ok = true; goto done; } /* synchronous refusal */
    a = calloc(1, sizeof(*a)); b = calloc(1, sizeof(*b));
    if (!a || !b) goto done;
    a->fd = client[1]; client[1] = -1; b->fd = upstream; upstream = -1;
    a->peer = b; b->peer = a; b->connecting = true;
    if (!ep_update(a) || !ep_update(b)) goto done;
    for (int i = 0; i < 10 && !a->dead; i++)
        if (portfwd_pump(100) < 0) goto done;
    ok = a->dead && b->dead;
done:
    if (a && b && a->peer && !a->dead) close_pair(a);
    else if (!a || !b) { free(a); free(b); }
    drain_free_list();
    if (reservation >= 0) close(reservation);
    if (upstream >= 0) close(upstream);
    for (int i = 0; i < 2; i++) if (client[i] >= 0) close(client[i]);
    return ok;
}
#endif

int test_portfwd(void)
{
    enum { SIZE = 2 * BUF_SZ };
    int left[2] = {-1, -1}, right[2] = {-1, -1};
    struct endpoint *a = NULL, *b = NULL;
    unsigned char *data = NULL, *received = NULL;
    int failures = 1;
    size_t sent = 0, got = 0;
    bool eof = false;
    int large = 1024 * 1024, small = 4096;
    struct sigaction old_pipe, ignore_pipe = {0};
    ignore_pipe.sa_handler = SIG_IGN;
    if (sigaction(SIGPIPE, &ignore_pipe, &old_pipe) < 0) return 1;
    g_epfd = epoll_create1(EPOLL_CLOEXEC);
    if (g_epfd < 0) goto done;
#ifdef PORTFWD_MANAGED_INTEREST
    if (!portfwd_connect_order() || !portfwd_connect_failure()) goto done;
#endif
    if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0, left) < 0 ||
        socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0, right) < 0) goto done;
    if (setsockopt(left[0], SOL_SOCKET, SO_SNDBUF, &large, sizeof(large)) < 0 ||
        setsockopt(right[0], SOL_SOCKET, SO_SNDBUF, &small, sizeof(small)) < 0) goto done;
    a = calloc(1, sizeof(*a)); b = calloc(1, sizeof(*b));
    data = malloc(SIZE); received = malloc(SIZE);
    if (!a || !b || !data || !received) goto done;
    a->fd = left[1]; b->fd = right[0]; a->peer = b; b->peer = a;
    left[1] = right[0] = -1;
    for (size_t i = 0; i < SIZE; i++) data[i] = (unsigned char)(i * 37u + i / 251u);
    while (sent < SIZE) {
        ssize_t n = write(left[0], data + sent, SIZE - sent);
        if (n <= 0) goto done;
        sent += (size_t)n;
    }
    if (shutdown(left[0], SHUT_WR) < 0) goto done;
    struct epoll_event event = {.events = EPOLLIN | EPOLLRDHUP, .data.ptr = a};
    if (epoll_ctl(g_epfd, EPOLL_CTL_ADD, a->fd, &event) < 0) goto done;
    event.data.ptr = b;
    if (epoll_ctl(g_epfd, EPOLL_CTL_ADD, b->fd, &event) < 0) goto done;
#ifdef PORTFWD_MANAGED_INTEREST
    a->registered = b->registered = true;
#endif
    /* The sender has queued >64 KiB and FIN; do not drain the recipient yet. */
    for (int i = 0; i < 100 && b->buf_len < BUF_SZ; i++)
        if (portfwd_pump(0) < 0 || a->dead) goto done;
    if (b->buf_len != BUF_SZ || a->read_eof) goto done;
    /* Full backpressure must not turn the persistent hangup into a busy loop. */
    if (portfwd_pump(0) != 0) goto done;
    for (int i = 0; i < 10000 && !eof; i++) {
        unsigned char extra;
        ssize_t n = read(right[1], got < SIZE ? received + got : &extra,
                         got < SIZE ? SIZE - got : 1);
        if (n > 0) { if (got == SIZE) goto done; got += (size_t)n; }
        else if (n == 0) eof = true;
        else if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) goto done;
        if (portfwd_pump(0) < 0) goto done;
    }
    if (!eof || got != SIZE || memcmp(data, received, SIZE) || a->dead) goto done;
    /* A response after seeing request EOF must still cross the reverse path. */
    if (write(right[1], "response", 8) != 8 || shutdown(right[1], SHUT_WR) < 0) goto done;
    got = 0; eof = false;
    for (int i = 0; i < 10000 && !eof; i++) {
        ssize_t n = read(left[0], received + got, SIZE - got);
        if (n > 0) got += (size_t)n;
        else if (n == 0) eof = true;
        else if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) goto done;
        if (portfwd_pump(0) < 0) goto done;
    }
    if (!eof || got != 8 || memcmp(received, "response", 8) || !a->dead || !b->dead)
        goto done;
    failures = 0;
done:
    if (a && b && a->peer && !a->dead) close_pair(a);
    else if (a && !a->peer && !a->dead) { free(a); free(b); }
    else if (!a || !b) { free(a); free(b); }
    drain_free_list();
    for (int i = 0; i < 2; i++) {
        if (left[i] >= 0) close(left[i]);
        if (right[i] >= 0) close(right[i]);
    }
    if (g_epfd >= 0) close(g_epfd);
    g_epfd = -1;
    free(data); free(received);
    if (sigaction(SIGPIPE, &old_pipe, NULL) < 0) failures = 1;
    printf("portfwd: backpressure and half-close: %s\n", failures ? "FAIL" : "OK");
    return failures;
}
#else
int test_portfwd(void)
{
    printf("UNOBSERVED (portfwd: Linux epoll required)\n");
    return 0;
}
#endif
