/* Copyright 2026 Rhett Creighton - Apache License 2.0 */
#define _GNU_SOURCE
#include "test/test_core.h"
int test_portfwd(void);
#if defined(__linux__)
[[maybe_unused]] static int portfwd_fixture_main(int argc, char **argv);
#define main portfwd_fixture_main
#include "../../../tools/zcl_portfwd.c"
#undef main

enum { PORTFWD_SIZE = 2 * BUF_SZ };
struct portfwd_fixture {
    int left[2], right[2];
    struct endpoint *a, *b;
    unsigned char *data, *received;
};

static void portfwd_init(struct portfwd_fixture *f)
{
    *f = (struct portfwd_fixture){.left = {-1, -1}, .right = {-1, -1}};
}

static void portfwd_cleanup(struct portfwd_fixture *f)
{
    if (f->a && f->b && f->a->peer && !f->a->dead) close_pair(f->a);
    else if (f->a && !f->a->peer && !f->a->dead) { free(f->a); free(f->b); }
    else if (!f->a || !f->b) { free(f->a); free(f->b); }
    drain_free_list();
    for (int i = 0; i < 2; i++) {
        if (f->left[i] >= 0) close(f->left[i]);
        if (f->right[i] >= 0) close(f->right[i]);
    }
    free(f->data); free(f->received);
}

static bool portfwd_endpoints(struct portfwd_fixture *f, int *left, int *right)
{
    f->a = calloc(1, sizeof(*f->a)); f->b = calloc(1, sizeof(*f->b));
    if (!f->a || !f->b) return false;
    f->a->fd = *left; f->b->fd = *right; *left = *right = -1;
    f->a->peer = f->b; f->b->peer = f->a;
    return true;
}

static bool portfwd_socketpairs(struct portfwd_fixture *f)
{
    return socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0, f->left) == 0 &&
           socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0, f->right) == 0;
}

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
static bool portfwd_order_exchange(struct portfwd_fixture *f)
{
    struct endpoint *a = f->a, *b = f->b;
    char reply[4];
    b->connecting = true;
    if (write(f->left[0], "abc", 3) != 3 || shutdown(f->left[0], SHUT_WR) < 0)
        return false;
    dispatch_epoll_event(a, EPOLLIN | EPOLLRDHUP);
    if (a->dead || !a->read_eof || b->buf_len != 3 || b->write_shutdown || !b->connecting)
        return false;
    dispatch_epoll_event(b, EPOLLOUT);
    if (a->dead || b->connecting || !b->write_shutdown) return false;
    return read(f->right[1], reply, sizeof(reply)) == 3 && !memcmp(reply, "abc", 3) &&
           read(f->right[1], reply, sizeof(reply)) == 0;
}

static bool portfwd_connect_order(void)
{
    struct portfwd_fixture f;
    portfwd_init(&f);
    bool ok = portfwd_socketpairs(&f) && portfwd_endpoints(&f, &f.left[1], &f.right[0]) &&
              portfwd_order_exchange(&f);
    portfwd_cleanup(&f);
    return ok;
}

/* A bound but non-listening local port deterministically refuses the connect. */
static int portfwd_reserve_port(uint16_t *port)
{
    struct sockaddr_in sa = {.sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    socklen_t len = sizeof(sa);
    int fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0) return -1;
    if (bind(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0 ||
        getsockname(fd, (struct sockaddr *)&sa, &len) < 0) { close(fd); return -1; }
    *port = ntohs(sa.sin_port);
    return fd;
}

static bool portfwd_refusal_dispatch(struct portfwd_fixture *f)
{
    f->b->connecting = true;
    if (!ep_update(f->a) || !ep_update(f->b)) return false;
    for (int i = 0; i < 10 && !f->a->dead; i++)
        if (portfwd_pump(100) < 0) return false;
    return f->a->dead && f->b->dead;
}

static bool portfwd_connect_failure(void)
{
    struct portfwd_fixture f;
    uint16_t port = 0;
    int reservation = -1, upstream = -1;
    bool ok = false;
    portfwd_init(&f);
    reservation = portfwd_reserve_port(&port);
    if (reservation < 0 || socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0, f.left) < 0)
        goto done;
    upstream = connect_target(port);
    if (upstream < 0) { ok = true; goto done; } /* synchronous refusal */
    if (!portfwd_endpoints(&f, &f.left[1], &upstream)) goto done;
    ok = portfwd_refusal_dispatch(&f);
done:
    portfwd_cleanup(&f);
    if (reservation >= 0) close(reservation);
    if (upstream >= 0) close(upstream);
    return ok;
}
#endif

static bool portfwd_prepare(struct portfwd_fixture *f)
{
    int large = 1024 * 1024, small = 4096;
    if (!portfwd_socketpairs(f)) return false;
    if (setsockopt(f->left[0], SOL_SOCKET, SO_SNDBUF, &large, sizeof(large)) < 0 ||
        setsockopt(f->right[0], SOL_SOCKET, SO_SNDBUF, &small, sizeof(small)) < 0) return false;
    f->data = malloc(PORTFWD_SIZE); f->received = malloc(PORTFWD_SIZE);
    if (!f->data || !f->received || !portfwd_endpoints(f, &f->left[1], &f->right[0]))
        return false;
    for (size_t i = 0; i < PORTFWD_SIZE; i++)
        f->data[i] = (unsigned char)(i * 37u + i / 251u);
    size_t sent = 0;
    while (sent < PORTFWD_SIZE) {
        ssize_t n = write(f->left[0], f->data + sent, PORTFWD_SIZE - sent);
        if (n <= 0) return false;
        sent += (size_t)n;
    }
    if (shutdown(f->left[0], SHUT_WR) < 0) return false;
    struct epoll_event event = {.events = EPOLLIN | EPOLLRDHUP, .data.ptr = f->a};
    if (epoll_ctl(g_epfd, EPOLL_CTL_ADD, f->a->fd, &event) < 0) return false;
    event.data.ptr = f->b;
    if (epoll_ctl(g_epfd, EPOLL_CTL_ADD, f->b->fd, &event) < 0) return false;
#ifdef PORTFWD_MANAGED_INTEREST
    f->a->registered = f->b->registered = true;
#endif
    return true;
}

/* The sender queued >64 KiB and FIN; do not drain the recipient yet. */
static bool portfwd_backpressure(struct portfwd_fixture *f)
{
    for (int i = 0; i < 100 && f->b->buf_len < BUF_SZ; i++)
        if (portfwd_pump(0) < 0 || f->a->dead) return false;
    if (f->b->buf_len != BUF_SZ || f->a->read_eof) return false;
    /* Full backpressure must not turn the persistent hangup into a busy loop. */
    return portfwd_pump(0) == 0;
}

static bool portfwd_receive_request(struct portfwd_fixture *f)
{
    size_t got = 0;
    bool eof = false;
    for (int i = 0; i < 10000 && !eof; i++) {
        unsigned char extra;
        ssize_t n = read(f->right[1], got < PORTFWD_SIZE ? f->received + got : &extra,
                         got < PORTFWD_SIZE ? PORTFWD_SIZE - got : 1);
        if (n > 0) { if (got == PORTFWD_SIZE) return false; got += (size_t)n; }
        else if (n == 0) eof = true;
        else if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) return false;
        if (portfwd_pump(0) < 0) return false;
    }
    return eof && got == PORTFWD_SIZE && !memcmp(f->data, f->received, PORTFWD_SIZE) && !f->a->dead;
}

/* A response after seeing request EOF must still cross the reverse path. */
static bool portfwd_receive_response(struct portfwd_fixture *f)
{
    size_t got = 0;
    bool eof = false;
    if (write(f->right[1], "response", 8) != 8 || shutdown(f->right[1], SHUT_WR) < 0)
        return false;
    for (int i = 0; i < 10000 && !eof; i++) {
        ssize_t n = read(f->left[0], f->received + got, PORTFWD_SIZE - got);
        if (n > 0) got += (size_t)n;
        else if (n == 0) eof = true;
        else if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) return false;
        if (portfwd_pump(0) < 0) return false;
    }
    return eof && got == 8 && !memcmp(f->received, "response", 8) && f->a->dead && f->b->dead;
}

int test_portfwd(void)
{
    struct portfwd_fixture f;
    int failures = 1;
    struct sigaction old_pipe, ignore_pipe = {0};
    portfwd_init(&f);
    ignore_pipe.sa_handler = SIG_IGN;
    if (sigaction(SIGPIPE, &ignore_pipe, &old_pipe) < 0) return 1;
    g_epfd = epoll_create1(EPOLL_CLOEXEC);
    if (g_epfd < 0) goto done;
#ifdef PORTFWD_MANAGED_INTEREST
    if (!portfwd_connect_order() || !portfwd_connect_failure()) goto done;
#endif
    if (portfwd_prepare(&f) && portfwd_backpressure(&f) &&
        portfwd_receive_request(&f) && portfwd_receive_response(&f)) failures = 0;
done:
    portfwd_cleanup(&f);
    if (g_epfd >= 0) close(g_epfd);
    g_epfd = -1;
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
