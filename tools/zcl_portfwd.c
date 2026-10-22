/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * zcl_portfwd — a tiny, self-contained userspace TCP forwarder.
 *
 * WHY THIS EXISTS
 * ---------------
 * z23 IS its own web server: it serves the block explorer over its
 * built-in HTTPS server on a HIGH port (8443) with an HTTP redirect on 8080,
 * bound as the UNPRIVILEGED operator user. There is no nginx / reverse proxy
 * and we never add one. But public clients hit 443/80, and binding ports <1024
 * needs CAP_NET_BIND_SERVICE. We do NOT want that capability on the node binary
 * (it would be lost on every redeploy) nor on system-wide socat (too broad).
 *
 * So THIS binary is the one file that gets the capability:
 *     sudo setcap 'cap_net_bind_service=+ep' <this binary>
 * That single setcap is the operator's ONE privileged step, ever. Afterwards a
 * user-linger systemd service (zcl-portfwd.service) runs this forwarder with no
 * sudo at runtime. The cap lives on a project-owned forwarder, scoped to this
 * one file, and survives node redeploys (we never rebuild this for a node bump).
 *
 * WHAT IT DOES
 * ------------
 * Forwards two TCP listen ports to two loopback targets:
 *     443 -> 127.0.0.1:8443   (node HTTPS)
 *      80 -> 127.0.0.1:8080   (node HTTP redirect)
 * It is a dumb byte pipe: TLS terminates at the node, not here. It listens on
 * both IPv4 and IPv6 (dual ::  with IPV6_V6ONLY off where possible, plus a
 * separate v4 socket as a fallback). It starts even if the node isn't up yet:
 * a listen socket just accepts and, if the upstream connect fails, closes the
 * client — the service keeps running and the next client retries. Restart=always
 * in the unit handles the rest.
 *
 * DESIGN
 * ------
 * Single-threaded epoll event loop, non-blocking sockets, O(1) per fd via a
 * small heap-allocated per-connection struct that holds a bidirectional pair
 * with two 64 KiB ring-ish buffers. No external deps, no malloc storms, no
 * threads. ~self-contained in one file.
 *
 * USAGE
 * -----
 *   zcl_portfwd                       # default pairs: 443->8443, 80->8080
 *   zcl_portfwd L1:T1 [L2:T2 ...]     # explicit pairs, e.g. 18443:8443
 *                                     #   L = public listen port (this host)
 *                                     #   T = loopback target port (127.0.0.1)
 *
 * The explicit form lets you prove the forwarding logic on HIGH ports without
 * the capability, e.g.  `zcl_portfwd 18443:8443`  (no root needed).
 */

#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#define MAX_PAIRS    8
#define BUF_SZ       (64 * 1024)
#define TARGET_ADDR  "127.0.0.1"
#define EPOLL_EVENTS 256

/* One forward pair: a public listen port -> a 127.0.0.1 target port. */
struct fwd_pair {
    uint16_t listen_port;
    uint16_t target_port;
};

/* The two endpoints of a proxied connection share this struct: `self` is the
 * fd this end reads from / writes to; `peer` points at the partner endpoint. */
struct endpoint {
    int             fd;
    struct endpoint *peer;
    /* bytes pending to be WRITTEN to this->fd (read from peer->fd). */
    unsigned char   buf[BUF_SZ];
    size_t          buf_len;     /* total bytes buffered */
    size_t          buf_off;     /* bytes already written out of buf */
    bool            read_eof;    /* OUR fd hit EOF/error; once peer's buf drains, close */
    bool            is_listener; /* true => fd is a listening socket */
    bool            dead;        /* torn down this batch; skip + free after loop */
    struct endpoint *free_next;  /* deferred-free list link */
    uint16_t        target_port; /* (listener only) where to connect upstream */
};

static volatile sig_atomic_t g_stop = 0;
static int g_epfd = -1;
/* Endpoints torn down within an epoll batch are not freed inline (both members
 * of a pair can appear in the SAME batch — freeing inline would UAF the second
 * event). We unhook their fds, mark them dead, and free after the batch. */
static struct endpoint *g_free_list = NULL;

static void on_signal(int sig) { (void)sig; g_stop = 1; }

/* Update this endpoint's epoll interest: always EPOLLIN unless its peer is
 * fully gone; EPOLLOUT only while we have buffered bytes to flush. */
static void ep_update(struct endpoint *e)
{
    struct epoll_event ev = {0};
    ev.data.ptr = e;
    ev.events = EPOLLRDHUP;
    /* Read more from us only if WE haven't hit EOF and the partner's outbound
     * buffer (which our reads fill) still has room — backpressure. */
    if (!e->read_eof && e->peer && e->peer->buf_len < BUF_SZ)
        ev.events |= EPOLLIN;
    /* Flush our outbound buffer when it has anything. */
    if (e->buf_len > e->buf_off)
        ev.events |= EPOLLOUT;
    epoll_ctl(g_epfd, EPOLL_CTL_MOD, e->fd, &ev);
}

/* Tear down a proxied pair. Unhooks both fds from epoll and closes them NOW (so
 * no further events fire for them), marks both endpoints dead so a later event
 * in the same batch is skipped, and queues them for free after the batch. */
static void close_pair(struct endpoint *a)
{
    if (a->dead) return;
    struct endpoint *b = a->peer;
    if (a->fd >= 0) { epoll_ctl(g_epfd, EPOLL_CTL_DEL, a->fd, NULL); close(a->fd); a->fd = -1; }
    if (b && b->fd >= 0) { epoll_ctl(g_epfd, EPOLL_CTL_DEL, b->fd, NULL); close(b->fd); b->fd = -1; }
    a->dead = true;
    a->free_next = g_free_list;
    g_free_list = a;
    if (b) {
        b->dead = true;
        b->free_next = g_free_list;
        g_free_list = b;
        b->peer = NULL;   /* sever so neither side dereferences the other again */
    }
    a->peer = NULL;
}

/* Free everything queued by close_pair() during the just-finished batch. */
static void drain_free_list(void)
{
    while (g_free_list) {
        struct endpoint *e = g_free_list;
        g_free_list = e->free_next;
        free(e);
    }
}

/* Connect a brand-new non-blocking socket to 127.0.0.1:port. Returns fd or -1.
 * A pending (EINPROGRESS) connect is fine — we treat the fd as ready and let
 * the first write surface any real failure. */
static int connect_target(uint16_t port)
{
    int fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (fd < 0) return -1;
    int one = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
    struct sockaddr_in sa = {0};
    sa.sin_family = AF_INET;
    sa.sin_port = htons(port);
    inet_pton(AF_INET, TARGET_ADDR, &sa.sin_addr);
    if (connect(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0 && errno != EINPROGRESS) {
        close(fd);
        return -1;
    }
    return fd;
}

/* A listener fired: accept everything pending, and for each, open an upstream
 * connection and wire the two endpoints together. If upstream fails (node down)
 * we just drop the client — the listener stays alive for the next attempt. */
static void handle_accept(struct endpoint *ln)
{
    for (;;) {
        int cfd = accept4(ln->fd, NULL, NULL, SOCK_NONBLOCK | SOCK_CLOEXEC);
        if (cfd < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) break;
            if (errno == EINTR) continue;
            break;
        }
        int one = 1;
        setsockopt(cfd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));

        int ufd = connect_target(ln->target_port);
        if (ufd < 0) { close(cfd); continue; }   /* node not up yet — retry next client */

        struct endpoint *c = calloc(1, sizeof(*c)); // raw-alloc-ok: standalone tool, no node/safe_alloc dep
        struct endpoint *u = calloc(1, sizeof(*u)); // raw-alloc-ok: standalone tool, no node/safe_alloc dep
        if (!c || !u) { free(c); free(u); close(cfd); close(ufd); continue; }
        c->fd = cfd; u->fd = ufd;
        c->peer = u; u->peer = c;

        struct epoll_event ev = {0};
        ev.events = EPOLLIN | EPOLLRDHUP;
        ev.data.ptr = c;
        if (epoll_ctl(g_epfd, EPOLL_CTL_ADD, cfd, &ev) < 0) { close(cfd); close(ufd); free(c); free(u); continue; }
        ev.data.ptr = u;
        if (epoll_ctl(g_epfd, EPOLL_CTL_ADD, ufd, &ev) < 0) { close_pair(c); continue; }
    }
}

/* Drain readable bytes from `e->fd` into the PEER's outbound buffer. */
static void handle_read(struct endpoint *e)
{
    struct endpoint *p = e->peer;
    for (;;) {
        if (!p || p->buf_len >= BUF_SZ) break;          /* peer buffer full — backpressure */
        ssize_t n = read(e->fd, p->buf + p->buf_len, BUF_SZ - p->buf_len);
        if (n > 0) { p->buf_len += (size_t)n; continue; }
        if (n == 0) { e->read_eof = true; break; }   /* EOF from us */
        if (errno == EAGAIN || errno == EWOULDBLOCK) break;
        if (errno == EINTR) continue;
        e->read_eof = true;                          /* hard error */
        break;
    }
}

/* Flush this endpoint's outbound buffer to its fd. Returns false if the
 * connection should be torn down. */
static bool handle_write(struct endpoint *e)
{
    while (e->buf_len > e->buf_off) {
        ssize_t n = write(e->fd, e->buf + e->buf_off, e->buf_len - e->buf_off);
        if (n > 0) { e->buf_off += (size_t)n; continue; }
        if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) break;
        if (n < 0 && errno == EINTR) continue;
        return false;                                   /* peer gone / error */
    }
    /* Buffer fully drained: reset to the front. */
    if (e->buf_off == e->buf_len) { e->buf_off = e->buf_len = 0; }
    return true;
}

static int make_listener(uint16_t port, int family, bool quiet)
{
    int fd = socket(family, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (fd < 0) return -1;
    int one = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    if (family == AF_INET6) {
        /* v6 socket carries ONLY v6; we open a separate v4 socket so behaviour
         * is identical on hosts where bindv6only defaults either way. */
        setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &one, sizeof(one));
    }
    if (family == AF_INET6) {
        struct sockaddr_in6 sa = {0};
        sa.sin6_family = AF_INET6;
        sa.sin6_addr = in6addr_any;
        sa.sin6_port = htons(port);
        if (bind(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) goto fail;
    } else {
        struct sockaddr_in sa = {0};
        sa.sin_family = AF_INET;
        sa.sin_addr.s_addr = htonl(INADDR_ANY);
        sa.sin_port = htons(port);
        if (bind(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) goto fail;
    }
    if (listen(fd, SOMAXCONN) < 0) goto fail;
    return fd;
fail:
    if (!quiet)
        fprintf(stderr, "zcl_portfwd: bind/listen :%u (%s) failed: %s\n",
                port, family == AF_INET6 ? "v6" : "v4", strerror(errno));
    close(fd);
    return -1;
}

/* Register a listening endpoint with epoll. Returns 0 on success. */
static int add_listener(int fd, uint16_t target_port)
{
    struct endpoint *ln = calloc(1, sizeof(*ln)); // raw-alloc-ok: standalone tool, no node/safe_alloc dep
    if (!ln) { close(fd); return -1; }
    ln->fd = fd;
    ln->is_listener = true;
    ln->target_port = target_port;
    struct epoll_event ev = {0};
    ev.events = EPOLLIN;
    ev.data.ptr = ln;
    if (epoll_ctl(g_epfd, EPOLL_CTL_ADD, fd, &ev) < 0) { close(fd); free(ln); return -1; }
    return 0;
}

static bool parse_pair(const char *s, struct fwd_pair *out)
{
    long l = 0, t = 0;
    char *end = NULL;
    l = strtol(s, &end, 10);
    if (end == s || *end != ':' || l <= 0 || l > 65535) return false;
    const char *ts = end + 1;
    t = strtol(ts, &end, 10);
    if (end == ts || *end != '\0' || t <= 0 || t > 65535) return false;
    out->listen_port = (uint16_t)l;
    out->target_port = (uint16_t)t;
    return true;
}

int main(int argc, char **argv)
{
    struct fwd_pair pairs[MAX_PAIRS];
    int npairs = 0;

    if (argc > 1) {
        for (int i = 1; i < argc && npairs < MAX_PAIRS; i++) {
            if (!parse_pair(argv[i], &pairs[npairs])) {
                fprintf(stderr,
                        "zcl_portfwd: bad pair '%s' (want LISTEN:TARGET, e.g. 443:8443)\n",
                        argv[i]);
                return 2;
            }
            npairs++;
        }
    } else {
        pairs[npairs++] = (struct fwd_pair){443, 8443};
        pairs[npairs++] = (struct fwd_pair){80, 8080};
    }

    signal(SIGPIPE, SIG_IGN);
    struct sigaction sa = {0};
    sa.sa_handler = on_signal;
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);

    g_epfd = epoll_create1(EPOLL_CLOEXEC);
    if (g_epfd < 0) { perror("zcl_portfwd: epoll_create1"); return 1; }

    int bound = 0;
    for (int i = 0; i < npairs; i++) {
        bool any = false;
        /* IPv6 first (so a single ::  socket isn't accidentally dual-stack),
         * then IPv4. Either binding succeeding counts the pair as live. */
        int f6 = make_listener(pairs[i].listen_port, AF_INET6, true);
        if (f6 >= 0 && add_listener(f6, pairs[i].target_port) == 0) any = true;
        int f4 = make_listener(pairs[i].listen_port, AF_INET, f6 >= 0);
        if (f4 >= 0 && add_listener(f4, pairs[i].target_port) == 0) any = true;
        if (any) {
            bound++;
            fprintf(stderr, "zcl_portfwd: listening :%u -> %s:%u%s%s\n",
                    pairs[i].listen_port, TARGET_ADDR, pairs[i].target_port,
                    f6 >= 0 ? " [v6]" : "", f4 >= 0 ? " [v4]" : "");
        } else {
            fprintf(stderr,
                    "zcl_portfwd: could NOT bind :%u (need cap_net_bind_service for <1024? "
                    "run: sudo setcap 'cap_net_bind_service=+ep' <this binary>)\n",
                    pairs[i].listen_port);
        }
    }
    if (bound == 0) {
        fprintf(stderr, "zcl_portfwd: no listeners bound — exiting\n");
        return 1;
    }

    struct epoll_event events[EPOLL_EVENTS];
    while (!g_stop) {
        int n = epoll_wait(g_epfd, events, EPOLL_EVENTS, -1);
        if (n < 0) { if (errno == EINTR) continue; perror("zcl_portfwd: epoll_wait"); break; }
        for (int i = 0; i < n; i++) {
            struct endpoint *e = events[i].data.ptr;
            uint32_t ev = events[i].events;

            /* This endpoint (or its pair) was torn down earlier in THIS batch;
             * its memory is queued for free, skip the stale event. */
            if (e->dead) continue;

            if (e->is_listener) { handle_accept(e); continue; }

            struct endpoint *peer = e->peer;
            bool tear = false;

            if (ev & EPOLLIN)  handle_read(e);
            /* moving our peer's buffer? data read from e went into peer->buf. */
            if (peer && peer->buf_len > peer->buf_off)
                if (!handle_write(peer)) tear = true;
            if ((ev & EPOLLOUT) && !tear)
                if (!handle_write(e)) tear = true;
            if (ev & (EPOLLHUP | EPOLLERR)) tear = true;
            if (ev & EPOLLRDHUP) e->read_eof = true;

            /* Tear down once both directions are drained and one side is gone. */
            if (!tear && e->read_eof && (!peer || peer->buf_len == peer->buf_off))
                tear = true;
            if (!tear && peer && peer->read_eof && e->buf_len == e->buf_off)
                tear = true;

            if (tear) { close_pair(e); continue; }

            ep_update(e);
            if (peer) ep_update(peer);
        }
        /* Safe now: no further events in this batch reference these. */
        drain_free_list();
    }

    if (g_epfd >= 0) close(g_epfd);
    return 0;
}
