/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * The RPC front door must never be permanently brickable.
 *
 * A long-running node was observed answering every single RPC with an
 * instant 503 {"code":-32603,"message":"RPC server busy"} while its
 * listener thread sat healthily in accept() and 54 client sockets sat
 * in CLOSE-WAIT, each still holding its unread request, all still owned
 * by the process. The admission queue in engine/modules/rpc/src/httpserver.c had
 * become a ONE-WAY RATCHET: its only decrementer was a worker returning
 * from handle_client(), so once the worker pool stopped returning, the
 * count stuck at RPC_HTTP_QUEUE_CAP for the life of the process and
 * every queued fd leaked with it — nothing else would ever close them.
 *
 * These tests drive the real admission path (enqueue_client() and its
 * reclaim rule, through the rpc_http_test_queue_* surface) over
 * socketpairs, and assert the invariant the server now enforces:
 *
 *   the queue is a waiting room, not a resource pool — it surrenders
 *   every entry it is no longer entitled to own before it reports
 *   itself full, so no sequence of client hang-ups or timeouts can
 *   leave the front door permanently refusing, and no queued fd
 *   outlives the queue.
 *
 * Every case below except the honest-backpressure one FAILS against the
 * pre-fix code, which had no hang-up probe, no residency deadline, and
 * no way at all to give a slot back.
 *
 * Ownership discipline in this file mirrors the server's: the moment a
 * server-side fd is handed to the queue the test drops its own handle
 * (server = -1) and keeps the raw number only in held[] for the
 * "was it really closed" assertions. That is why no case can
 * double-close a recycled fd number.
 */

#include "test/test_core.h"
#include "rpc/httpserver.h"
#include "rpc/server.h"
#include "platform/socket_compat.h"

#include <errno.h>
#include <fcntl.h>
#include <time.h>
#if !defined(_WIN32)
#include <arpa/inet.h>
#include <netinet/in.h>
#include <poll.h>
#endif
#include <stdio.h>
#include <string.h>
#if !defined(_WIN32)
#include <sys/socket.h>
#endif
#include <unistd.h>

#if defined(_WIN32)
#include "platform/socket_compat.h"

#include <stdint.h>

/* Simulated clients hold peer sockets as int fds; socketpair becomes the
 * verified loopback-TCP pair, write()/close() SOCKET verbs, and the
 * poll(NULL, 0, 25) pause becomes Sleep. Every write()/close() in this TU
 * targets one of those sockets. */
static int rfs_socketpair(int sv[2])
{
    platform_socket_t pair[2];
    if (!platform_socket_pair(pair))
        return -1;
    sv[0] = (int)(intptr_t)pair[0];
    sv[1] = (int)(intptr_t)pair[1];
    return 0;
}

#define socketpair(domain, type, protocol, sv) rfs_socketpair(sv)
#define write(fd, buf, len) \
    ((ssize_t)platform_socket_send((platform_socket_t)(intptr_t)(fd), \
                                   buf, len))
#define close(fd) \
    (platform_socket_close((platform_socket_t)(intptr_t)(fd)) == 0 ? 0 : -1)
#define poll(fds, count, ms) (Sleep(ms), 0)
#endif

/* One simulated client: [0] is the client end, [1] is the end the
 * server accepted and hands to the admission queue. */
struct sim_client {
    int client;
    int server;
};

/* Bounded by the queue capacity discovered at runtime, plus slack for
 * the extra admissions each case attempts. */
#define SIM_MAX 256

static bool sim_open(struct sim_client *c)
{
    int sv[2];
    c->client = -1;
    c->server = -1;
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0)
        return false;
    c->client = sv[0];
    c->server = sv[1];
    return true;
}

/* Send a request the server has not read yet, so the server end is
 * readable with real bytes. This is what the live CLOSE-WAIT sockets
 * looked like: ~250 bytes of an unread POST. */
static void sim_send_request(const struct sim_client *c)
{
    static const char req[] =
        "POST / HTTP/1.1\r\nHost: 127.0.0.1\r\n"
        "Authorization: Basic X\r\nContent-Length: 2\r\n\r\n{}";
    if (c->client >= 0)
        (void)!write(c->client, req, sizeof(req) - 1);
}

static void sim_hangup(struct sim_client *c)
{
    if (c->client >= 0) {
        close(c->client);
        c->client = -1;
    }
}

static void sim_close(struct sim_client *c)
{
    sim_hangup(c);
    if (c->server >= 0) {
        close(c->server);
        c->server = -1;
    }
}

#if !defined(_WIN32)
/* One real TCP loopback pair: [client] sends and closes, [server] is the end
 * the listener accepted. Unlike socketpair(2), a TCP close with unread bytes
 * pending reports POLLIN alone — no POLLHUP until the data is drained — so
 * only this helper reproduces the CLOSE-WAIT-with-unread-bytes sockets from
 * the live incident. (On Windows these cases SKIP: WSAPoll's RDHUP
 * signaling is unverified there.) */
static bool tcp_pair_open(int *client_fd, int *server_fd)
{
    int ls = socket(AF_INET, SOCK_STREAM, 0);
    if (ls < 0)
        return false;
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = 0;
    bool ok = bind(ls, (struct sockaddr *)&addr, sizeof(addr)) == 0 &&
              listen(ls, 1) == 0;
    socklen_t addr_len = sizeof(addr);
    if (ok && getsockname(ls, (struct sockaddr *)&addr, &addr_len) != 0)
        ok = false;
    int client = -1;
    if (ok) {
        client = socket(AF_INET, SOCK_STREAM, 0);
        if (client < 0)
            ok = false;
        else if (connect(client, (struct sockaddr *)&addr,
                         sizeof(addr)) != 0) {
            close(client);
            client = -1;
            ok = false;
        }
    }
    int server = -1;
    if (ok) {
        server = accept(ls, NULL, NULL);
        if (server < 0)
            ok = false;
    }
    close(ls);
    if (!ok) {
        if (client >= 0)
            close(client);
        if (server >= 0)
            close(server);
        return false;
    }
    *client_fd = client;
    *server_fd = server;
    return true;
}
#endif

/* An fd the queue has closed is gone from this process. Only meaningful
 * while nothing else is opening fds, which each case guarantees by
 * doing all of its opens before the reclaim it is testing. */
static bool fd_is_closed(int fd)
{
#if defined(_WIN32)
    int type = 0;
    int len = sizeof(type);
    return getsockopt((platform_socket_t)(intptr_t)fd, SOL_SOCKET, SO_TYPE,
                      (char *)&type, &len) == SOCKET_ERROR &&
           WSAGetLastError() == WSAENOTSOCK;
#else
    return fcntl(fd, F_GETFD) == -1 && errno == EBADF;
#endif
}

/* Half-close: FIN without closing our own end. The server end sits in
 * CLOSE-WAIT until the server closes it — exactly the leaked state from
 * the incident. Full close() would also reclaim the fd number and hide a
 * leak; shutdown(SHUT_WR) keeps our end open so a leaked server fd stays
 * visible as a non-zero queue depth. */
static void rfs_half_close(platform_socket_t fd)
{
    if (fd == PLATFORM_SOCKET_INVALID)
        return;
#if defined(_WIN32)
    (void)shutdown(fd, SD_SEND);
#else
    (void)shutdown(fd, SHUT_WR);
#endif
}

static void rfs_sleep_ms(int ms)
{
#if defined(_WIN32)
    Sleep(ms);
#else
    struct timespec ts;
    ts.tv_sec = ms / 1000;
    ts.tv_nsec = (long)(ms % 1000) * 1000000L;
    (void)nanosleep(&ts, NULL);
#endif
}

/* Ask the kernel for a free loopback port, then release it. Same
 * find-then-bind race every loopback test in this tree takes (see
 * test_rpc.c); a collision just fails this case, never another run. */
static uint16_t rfs_free_port(void)
{
    platform_socket_t fd = platform_socket_open(AF_INET, SOCK_STREAM, 0,
                                                true, false);
    if (fd == PLATFORM_SOCKET_INVALID)
        return 0;
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons(0);
    uint16_t port = 0;
    if (platform_socket_bind(fd, (struct sockaddr *)&addr,
                             sizeof(addr)) == 0) {
        size_t len = sizeof(addr);
        if (platform_socket_local_address(fd, (struct sockaddr *)&addr,
                                          &len) == 0)
            port = ntohs(addr.sin_port);
    }
    platform_socket_close(fd);
    return port;
}

/* Reset every slot in sim[0..cap] (and held[0..cap] when given) to "no fd
 * yet". Shared init step for every case below, so each case's own
 * complexity is just its distinctive admit/reclaim sequence. */
static void rfs_reset_slots(size_t cap, struct sim_client *sim, int *held)
{
    for (size_t i = 0; i <= cap; i++) {
        sim[i].client = sim[i].server = -1;
        if (held)
            held[i] = -1;
    }
}

/* Open and admit `count` live clients into sim[0..count), recording each
 * server fd in held[] when given and sending a request first when
 * send_request is set. Stops and returns false on the first failure. */
static bool rfs_fill_admit(size_t count, struct sim_client *sim, int *held,
                           bool send_request)
{
    bool ok = true;
    for (size_t i = 0; i < count && ok; i++) {
        if (!sim_open(&sim[i])) { ok = false; break; }
        if (send_request)
            sim_send_request(&sim[i]);
        if (held)
            held[i] = sim[i].server;
        ok = rpc_http_test_queue_admit(sim[i].server);
        sim[i].server = -1;   /* the queue owns it now */
    }
    return ok;
}

/* Close every simulated client in sim[0..cap]. */
static void rfs_close_slots(size_t cap, struct sim_client *sim)
{
    for (size_t i = 0; i <= cap; i++)
        sim_close(&sim[i]);
}

/* ── A full queue of LIVE clients is honest backpressure ──── */
static bool rfs_case_full_queue_refuses(size_t cap, struct rpc_http_queue_stats *st)
{
    struct sim_client sim[SIM_MAX];
    bool ok = true;

    printf("frontdoor full queue of live clients refuses... ");

    rpc_http_test_queue_reset(-1);
    rfs_reset_slots(cap, sim, NULL);
    ok = rfs_fill_admit(cap, sim, NULL, true);
    rpc_http_test_queue_stats(st);
    ok = ok && st->depth == cap && st->peak_depth == cap;

    /* Nothing is reclaimable: every peer is connected and inside
     * the residency deadline. Refusing here is correct, and the
     * refused fd stays the caller's to close. */
    ok = ok && sim_open(&sim[cap]);
    ok = ok && rpc_http_test_queue_admit(sim[cap].server) == false;
    rpc_http_test_queue_stats(st);
    ok = ok && st->rejected_busy == 1;
    ok = ok && st->reclaimed_hangup == 0 && st->reclaimed_stale == 0;
    ok = ok && st->depth == cap;          /* never overfills */

    rpc_http_test_queue_reset(-1);
    rfs_close_slots(cap, sim);
    printf(ok ? "OK\n" : "FAIL\n");
    return ok;
}

/* ── A hung-up client must not hold a slot ─────────────────── */
/* Assert the reclaim shape shared by rfs_case_reclaims_hangup: the first
 * `gone` held fds are CLOSED (not merely unlinked), and the queue's next
 * arrival-order entry is the oldest client still connected. */
static bool rfs_check_hangup_reclaim(const int *held, size_t gone)
{
    bool ok = true;
    for (size_t i = 0; i < gone; i++)
        ok = ok && fd_is_closed(held[i]);

    int taken = rpc_http_test_queue_take();
    ok = ok && taken == held[gone];
    if (taken >= 0)
        close(taken);
    return ok;
}

static bool rfs_case_reclaims_hangup(size_t cap, struct rpc_http_queue_stats *st)
{
    struct sim_client sim[SIM_MAX];
    int held[SIM_MAX];
    size_t gone = cap / 2;
    bool ok;

    printf("frontdoor reclaims slots from clients that hung up... ");

    rpc_http_test_queue_reset(-1);
    rfs_reset_slots(cap, sim, held);
    ok = rfs_fill_admit(cap, sim, held, false);

    /* The first `gone` clients give up and close, sending nothing.
     * Their server ends are now readable-at-EOF: unservable. Before
     * the fix they kept their slots forever. */
    for (size_t i = 0; i < gone; i++)
        sim_hangup(&sim[i]);

    ok = ok && sim_open(&sim[cap]);
    sim_send_request(&sim[cap]);
    held[cap] = sim[cap].server;
    ok = ok && rpc_http_test_queue_admit(sim[cap].server);
    sim[cap].server = -1;

    rpc_http_test_queue_stats(st);
    ok = ok && st->reclaimed_hangup == gone;
    ok = ok && st->reclaimed_stale == 0;
    ok = ok && st->depth == cap - gone + 1;
    ok = ok && rfs_check_hangup_reclaim(held, gone);

    rpc_http_test_queue_reset(-1);
    rfs_close_slots(cap, sim);
    printf(ok ? "OK\n" : "FAIL\n");
    return ok;
}

/* ── A connected client that waited past the deadline ──────── */
/* Every held fd closed: the age-based reclaim actually closed them, not
 * merely unlinked them from the queue. */
static bool rfs_all_closed(const int *held, size_t count)
{
    bool ok = true;
    for (size_t i = 0; i < count; i++)
        ok = ok && fd_is_closed(held[i]);
    return ok;
}

static bool rfs_case_reclaims_stale(size_t cap, struct rpc_http_queue_stats *st)
{
    struct sim_client sim[SIM_MAX];
    int held[SIM_MAX];
    bool ok;

    printf("frontdoor reclaims slots past the residency deadline... ");

    /* Deadline 2 ms, then wait past it. Each client stays
     * CONNECTED with an unread request pending, so the hang-up
     * probe deliberately cannot fire — this proves the age rule
     * alone is what reopens the door. (0 is not "instantly stale":
     * it is the documented way to DISABLE age-based reclaim, same
     * as ZCL_RPC_TIMEOUT_MS=0 disables the request watchdog.) */
    rpc_http_test_queue_reset(2);
    rfs_reset_slots(cap, sim, held);
    ok = rfs_fill_admit(cap, sim, held, true);
    rpc_http_test_queue_stats(st);
    /* An expired deadline must not evict on the way IN — the queue
     * reclaims only when it would otherwise report itself full. */
    ok = ok && st->depth == cap && st->reclaimed_stale == 0;

    /* Put every queued entry safely past the 2 ms deadline. */
    (void)poll(NULL, 0, 25);

    ok = ok && sim_open(&sim[cap]);
    sim_send_request(&sim[cap]);
    ok = ok && rpc_http_test_queue_admit(sim[cap].server);
    sim[cap].server = -1;

    rpc_http_test_queue_stats(st);
    ok = ok && st->reclaimed_stale == cap;
    ok = ok && st->reclaimed_hangup == 0;
    ok = ok && st->depth == 1;
    ok = ok && rfs_all_closed(held, cap);

    rpc_http_test_queue_reset(-1);
    rfs_close_slots(cap, sim);
    printf(ok ? "OK\n" : "FAIL\n");
    return ok;
}

/* ── THE INVARIANT: no run of hang-ups bricks the door ─────── */
static bool rfs_case_survives_hangup_run(size_t cap, struct rpc_http_queue_stats *st)
{
    size_t rounds = cap * 4;
    bool ok = true;

    printf("frontdoor survives a long run of clients that hang up... ");

    rpc_http_test_queue_reset(-1);
    for (size_t i = 0; i < rounds; i++) {
        struct sim_client c;
        if (!sim_open(&c)) { ok = false; break; }

        if (!rpc_http_test_queue_admit(c.server)) {
            /* Refused. Every queued peer is a client that already
             * hung up, so the queue owns nothing servable and MUST
             * be able to take this one. Against the pre-fix ratchet
             * this failed on round cap and every round after it,
             * for the life of the process. */
            if (!rpc_http_test_queue_admit(c.server)) {
                ok = false;
                sim_close(&c);
                break;
            }
        }
        c.server = -1;        /* the queue owns it now */
        sim_hangup(&c);       /* the client gives up immediately */
    }

    rpc_http_test_queue_stats(st);
    ok = ok && st->admitted == (uint64_t)rounds;
    ok = ok && st->depth <= cap;
    /* The run could only get this far by reclaiming. */
    ok = ok && st->reclaimed_hangup > 0;

    rpc_http_test_queue_reset(-1);
    rpc_http_test_queue_stats(st);
    ok = ok && st->depth == 0;
    printf(ok ? "OK\n" : "FAIL\n");
    return ok;
}

/* ── The queue owns nothing after it is emptied ────────────── */
static bool rfs_case_no_fd_leak_on_empty(size_t cap, struct rpc_http_queue_stats *st)
{
    struct sim_client sim[SIM_MAX];
    int held[SIM_MAX];
    bool ok = true;

    printf("frontdoor queue leaves no fd behind when emptied... ");

    rpc_http_test_queue_reset(-1);
    for (size_t i = 0; i < cap; i++) {
        sim[i].client = sim[i].server = -1;
        held[i] = -1;
    }

    for (size_t i = 0; i < cap && ok; i++) {
        if (!sim_open(&sim[i])) { ok = false; break; }
        sim_send_request(&sim[i]);
        held[i] = sim[i].server;
        ok = rpc_http_test_queue_admit(sim[i].server);
        sim[i].server = -1;
    }

    rpc_http_test_queue_reset(-1);
    rpc_http_test_queue_stats(st);
    ok = ok && st->depth == 0 && st->admitted == 0;
    for (size_t i = 0; i < cap; i++)
        ok = ok && fd_is_closed(held[i]);

    for (size_t i = 0; i < cap; i++)
        sim_close(&sim[i]);
    printf(ok ? "OK\n" : "FAIL\n");
    return ok;
}

#if !defined(_WIN32)
/* ── A partial request followed by close must not hold a slot ──
 *
 * The live brick: dozens of TCP sockets in CLOSE-WAIT each holding
 * ~250 unread bytes. A close() with unread data pending reports
 * POLLIN alone (no POLLHUP until the bytes are drained), and the old
 * hang-up probe treated "peek returns data" as "peer is alive" — so a
 * queue full of such entries never shed one and every later client got
 * an instant 503 while workers idled. socketpair(2) cannot reproduce
 * this (it reports POLLHUP); only real TCP can. */
/* One TCP client sends a partial request and half-closes: the server end
 * holds unread bytes plus FIN, the CLOSE-WAIT shape from the incident.
 * Waits out loopback delivery so the reclaim below sees the steady state. */
static bool rfs_open_dead_partial(struct sim_client *dead, int *held_dead)
{
    bool ok = tcp_pair_open(&dead->client, &dead->server);
    sim_send_request(dead);
    *held_dead = dead->server;
    ok = ok && rpc_http_test_queue_admit(dead->server);
    dead->server = -1;   /* the queue owns it now */
    sim_hangup(dead);    /* FIN joins the unread bytes */
    (void)poll(NULL, 0, 100);
    return ok;
}

/* Take the next queue entry and assert it matches `expect` (arrival order
 * survives compaction/reclaim); closes whatever fd was actually taken. */
static bool rfs_take_matches(int expect)
{
    int taken = rpc_http_test_queue_take();
    bool ok = taken == expect;
    if (taken >= 0)
        close(taken);
    return ok;
}

static bool rfs_case_reclaims_partial_close(size_t cap, struct rpc_http_queue_stats *st)
{
    struct sim_client dead = { .client = -1, .server = -1 };
    struct sim_client sim[SIM_MAX];
    int held[SIM_MAX];
    int held_dead = -1;
    bool ok;

    printf("frontdoor reclaims a partial request followed by close... ");

    rpc_http_test_queue_reset(-1);
    rfs_reset_slots(cap - 1, sim, held);
    ok = rfs_open_dead_partial(&dead, &held_dead);

    /* Fill the rest of the queue with live clients, then one more: the
     * dead partial is reclaimable, so the door is not full. Before the
     * fix this refused with rejected_busy (the count never
     * self-corrected). */
    ok = ok && rfs_fill_admit(cap - 1, sim, held, true);
    ok = ok && sim_open(&sim[cap - 1]);
    sim_send_request(&sim[cap - 1]);
    held[cap - 1] = sim[cap - 1].server;
    bool admitted = rpc_http_test_queue_admit(sim[cap - 1].server);
    if (admitted)
        sim[cap - 1].server = -1;
    ok = ok && admitted;

    rpc_http_test_queue_stats(st);
    ok = ok && st->reclaimed_hangup == 1;
    ok = ok && st->depth == cap;
    ok = ok && st->rejected_busy == 0;
    ok = ok && fd_is_closed(held_dead); /* reclaimed means CLOSED */
    ok = ok && rfs_take_matches(held[0]);

    rpc_http_test_queue_reset(-1);
    sim_close(&dead);
    rfs_close_slots(cap - 1, sim);
    printf(ok ? "OK\n" : "FAIL\n");
    return ok;
}

/* ── N partial-then-close clients never trip busy ──────────── */
static bool rfs_case_survives_partial_close_run(size_t cap, struct rpc_http_queue_stats *st)
{
    size_t rounds = cap * 2;
    bool ok = true;

    printf("frontdoor survives a run of partial-then-close TCP clients... ");

    rpc_http_test_queue_reset(-1);
    for (size_t i = 0; i < rounds; i++) {
        struct sim_client c = { .client = -1, .server = -1 };
        if (!tcp_pair_open(&c.client, &c.server)) { ok = false; break; }
        sim_send_request(&c);
        sim_hangup(&c);   /* unread bytes plus FIN on the server end */
        if (i + 1 == cap)
            (void)poll(NULL, 0, 100); /* FINs arrive before first reclaim */
        if (!rpc_http_test_queue_admit(c.server)) {
            /* Every queued peer already hung up: refusing here is the
             * one-way ratchet the incident bricked on. */
            ok = false;
            sim_close(&c);
            break;
        }
        c.server = -1;  /* the queue owns it now */
    }

    rpc_http_test_queue_stats(st);
    ok = ok && st->admitted == (uint64_t)rounds;
    ok = ok && st->rejected_busy == 0;
    ok = ok && st->depth <= cap;
    ok = ok && st->reclaimed_hangup > 0;

    rpc_http_test_queue_reset(-1);
    rpc_http_test_queue_stats(st);
    ok = ok && st->depth == 0;
    printf(ok ? "OK\n" : "FAIL\n");
    return ok;
}
#endif /* !_WIN32 */

/* ── THE WIRE TRUTH: half-closed loopback clients drain ────
 *
 * The cases above drive the admission queue over socketpairs with
 * full close(). This one runs the REAL server on 127.0.0.1, opens N
 * TCP connections, and half-closes every one of them — FIN sent,
 * our end still open — which is the exact CLOSE-WAIT shape from the
 * incident. Half the clients die mid-request (partial bytes, then
 * FIN); half go silent after connect (then FIN). The server's
 * connection count must return to zero inside the idle budget with
 * no further admission to trigger it, and the door must still
 * answer a fresh client afterwards. Scratch datadir only (repo
 * test-tmp convention, like test_rpc.c); no live node, no live
 * datadir, no /tmp. */
#define RFS_HALFCLOSE_N 16

static bool rfs_halfclose_probe_ok(const struct sockaddr_in *srv)
{
    platform_socket_t probe = platform_socket_open(AF_INET, SOCK_STREAM, 0,
                                                    true, false);
    bool ok = probe != PLATFORM_SOCKET_INVALID;
    if (ok && platform_socket_connect(probe, (const struct sockaddr *)srv,
                                      sizeof(*srv)) == 0) {
        static const char req[] =
            "POST / HTTP/1.1\r\nHost: 127.0.0.1\r\n"
            "Content-Length: 2\r\n\r\n{}";
        ok = ok && platform_socket_send(probe, req, sizeof(req) - 1) > 0;
        char rbuf[4096];
        int n = platform_socket_receive(probe, rbuf, sizeof(rbuf) - 1);
        ok = ok && n > 0;
        if (ok) {
            rbuf[n] = '\0';
            ok = ok && strstr(rbuf, "401") != NULL;
        }
    } else {
        ok = false;
    }
    if (probe != PLATFORM_SOCKET_INVALID)
        platform_socket_close(probe);
    return ok;
}

static bool rfs_halfclose_open_clients(platform_socket_t *cli,
                                       const struct sockaddr_in *srv)
{
    static const char partial[] =
        "POST / HTTP/1.1\r\nHost: 127.0.0.1\r\n";
    bool ok = true;

    for (size_t i = 0; i < RFS_HALFCLOSE_N; i++)
        cli[i] = PLATFORM_SOCKET_INVALID;

    for (size_t i = 0; i < RFS_HALFCLOSE_N && ok; i++) {
        cli[i] = platform_socket_open(AF_INET, SOCK_STREAM, 0, true, false);
        ok = ok && cli[i] != PLATFORM_SOCKET_INVALID;
        if (!ok)
            break;
        ok = ok && platform_socket_connect(
            cli[i], (const struct sockaddr *)srv, sizeof(*srv)) == 0;
        if (!ok)
            break;
        if (i < RFS_HALFCLOSE_N / 2) {
            /* Mid-request half-close: partial bytes, then FIN. */
            ok = ok && platform_socket_send(cli[i], partial,
                sizeof(partial) - 1) > 0;
        }
        /* else: silent after connect, then FIN. */
        rfs_half_close(cli[i]);
    }
    return ok;
}

/* The listener must actually ADMIT all N first: without this wait a slow
 * accept loop could leave every connection in the listen backlog, depth
 * would read 0 without proving anything, and the case would be vacuous. */
static bool rfs_wait_admitted_all(struct rpc_http_queue_stats *hst, size_t n)
{
    int waited_ms = 0;
    while (waited_ms < 5000) {
        rpc_http_test_queue_stats(hst);
        if (hst->admitted >= n)
            return true;
        rfs_sleep_ms(25);
        waited_ms += 25;
    }
    rpc_http_test_queue_stats(hst);
    return hst->admitted >= n;
}

/* Workers must pick up and close every one: the 5 s socket deadlines plus
 * the peer-gone pre-check bound each connection, and the 10 s queue
 * residency budget bounds the stragglers. Poll a little past that budget. */
static bool rfs_wait_depth_zero(struct rpc_http_queue_stats *hst)
{
    int waited_ms = 0;
    while (waited_ms < 12000) {
        rpc_http_test_queue_stats(hst);
        if (hst->depth == 0)
            return true;
        rfs_sleep_ms(25);
        waited_ms += 25;
    }
    rpc_http_test_queue_stats(hst);
    return hst->depth == 0;
}

static bool rfs_halfclose_run(const struct sockaddr_in *srv)
{
    platform_socket_t cli[RFS_HALFCLOSE_N];
    struct rpc_http_queue_stats hst;
    memset(&hst, 0, sizeof(hst));

    bool ok = rfs_halfclose_open_clients(cli, srv);
    ok = ok && rfs_wait_admitted_all(&hst, RFS_HALFCLOSE_N);
    ok = ok && rfs_wait_depth_zero(&hst);
    /* The door is still alive: a fresh client gets an answer (401 without
     * credentials), not a hang-up or a 503. */
    ok = ok && rfs_halfclose_probe_ok(srv);

    for (size_t i = 0; i < RFS_HALFCLOSE_N; i++) {
        if (cli[i] != PLATFORM_SOCKET_INVALID)
            platform_socket_close(cli[i]);
    }
    return ok;
}

static bool rfs_case_drains_halfclosed_loopback(void)
{
    bool ok;
    char rpcdir[512];

    printf("frontdoor drains half-closed loopback connections... ");

    test_make_tmpdir(rpcdir, sizeof(rpcdir), "rpc_frontdoor", "halfclose");
    uint16_t port = rfs_free_port();
    struct rpc_table tbl;
    rpc_table_init(&tbl);
    bool started = port != 0 &&
        rpc_http_start(&tbl, port, NULL, NULL, rpcdir);
    ok = started;
    if (started) {
        struct sockaddr_in srv;
        memset(&srv, 0, sizeof(srv));
        srv.sin_family = AF_INET;
        srv.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        srv.sin_port = htons(port);
        ok = rfs_halfclose_run(&srv);
        rpc_http_stop();
    }
    test_rm_rf(rpcdir);
    printf(ok ? "OK\n" : "FAIL\n");
    return ok;
}
#undef RFS_HALFCLOSE_N

int test_rpc_frontdoor_slots(void)
{
    int failures = 0;
    struct rpc_http_queue_stats st;
    size_t cap;

    /* Discover the capacity through the same surface the tests use, so
     * this file never carries a hand-typed copy of RPC_HTTP_QUEUE_CAP
     * that can drift away from the server's. */
    rpc_http_test_queue_reset(-1);
    rpc_http_test_queue_stats(&st);
    cap = st.capacity;
    if (cap == 0 || cap + 8 > SIM_MAX) {
        printf("rpc frontdoor: implausible queue capacity %zu\n", cap);
        return 1;
    }

    if (!rfs_case_full_queue_refuses(cap, &st)) failures++;
    if (!rfs_case_reclaims_hangup(cap, &st)) failures++;
    if (!rfs_case_reclaims_stale(cap, &st)) failures++;
    if (!rfs_case_survives_hangup_run(cap, &st)) failures++;
    if (!rfs_case_no_fd_leak_on_empty(cap, &st)) failures++;
#if defined(_WIN32)
    printf("frontdoor reclaims a partial request followed by close... "
           "SKIP (Windows: WSAPoll RDHUP signaling unverified)\n");
    printf("frontdoor survives a run of partial-then-close TCP clients... "
           "SKIP (Windows: WSAPoll RDHUP signaling unverified)\n");
#else
    if (!rfs_case_reclaims_partial_close(cap, &st)) failures++;
    if (!rfs_case_survives_partial_close_run(cap, &st)) failures++;
#endif
    if (!rfs_case_drains_halfclosed_loopback()) failures++;

    rpc_http_test_queue_reset(-1);

    printf("\n%d rpc front-door slot tests, %d failed\n", 8, failures);
    return failures;
}
