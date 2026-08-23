/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * The RPC front door must never be permanently brickable.
 *
 * A long-running node was observed answering every single RPC with an
 * instant 503 {"code":-32603,"message":"RPC server busy"} while its
 * listener thread sat healthily in accept() and 54 client sockets sat
 * in CLOSE-WAIT, each still holding its unread request, all still owned
 * by the process. The admission queue in lib/rpc/src/httpserver.c had
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

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

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

/* An fd the queue has closed is gone from this process. Only meaningful
 * while nothing else is opening fds, which each case guarantees by
 * doing all of its opens before the reclaim it is testing. */
static bool fd_is_closed(int fd)
{
    return fcntl(fd, F_GETFD) == -1 && errno == EBADF;
}

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

    /* ── A full queue of LIVE clients is honest backpressure ──── */

    printf("frontdoor full queue of live clients refuses... ");
    {
        struct sim_client sim[SIM_MAX];
        bool ok = true;

        rpc_http_test_queue_reset(-1);
        for (size_t i = 0; i <= cap; i++)
            sim[i].client = sim[i].server = -1;

        for (size_t i = 0; i < cap && ok; i++) {
            if (!sim_open(&sim[i])) { ok = false; break; }
            sim_send_request(&sim[i]);
            ok = rpc_http_test_queue_admit(sim[i].server);
            sim[i].server = -1;   /* the queue owns it now */
        }
        rpc_http_test_queue_stats(&st);
        ok = ok && st.depth == cap && st.peak_depth == cap;

        /* Nothing is reclaimable: every peer is connected and inside
         * the residency deadline. Refusing here is correct, and the
         * refused fd stays the caller's to close. */
        ok = ok && sim_open(&sim[cap]);
        ok = ok && rpc_http_test_queue_admit(sim[cap].server) == false;
        rpc_http_test_queue_stats(&st);
        ok = ok && st.rejected_busy == 1;
        ok = ok && st.reclaimed_hangup == 0 && st.reclaimed_stale == 0;
        ok = ok && st.depth == cap;          /* never overfills */

        rpc_http_test_queue_reset(-1);
        for (size_t i = 0; i <= cap; i++)
            sim_close(&sim[i]);
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    /* ── A hung-up client must not hold a slot ─────────────────── */

    printf("frontdoor reclaims slots from clients that hung up... ");
    {
        struct sim_client sim[SIM_MAX];
        int held[SIM_MAX];
        size_t gone = cap / 2;
        bool ok = true;

        rpc_http_test_queue_reset(-1);
        for (size_t i = 0; i <= cap; i++) {
            sim[i].client = sim[i].server = -1;
            held[i] = -1;
        }

        for (size_t i = 0; i < cap && ok; i++) {
            if (!sim_open(&sim[i])) { ok = false; break; }
            held[i] = sim[i].server;
            ok = rpc_http_test_queue_admit(sim[i].server);
            sim[i].server = -1;
        }

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

        rpc_http_test_queue_stats(&st);
        ok = ok && st.reclaimed_hangup == gone;
        ok = ok && st.reclaimed_stale == 0;
        ok = ok && st.depth == cap - gone + 1;

        /* Reclaimed means CLOSED, not merely unlinked — the whole point
         * is that the fd stops being leaked. */
        for (size_t i = 0; i < gone; i++)
            ok = ok && fd_is_closed(held[i]);

        /* Arrival order survives compaction: the next entry out is the
         * oldest client that is still connected. */
        int taken = rpc_http_test_queue_take();
        ok = ok && taken == held[gone];
        if (taken >= 0)
            close(taken);

        rpc_http_test_queue_reset(-1);
        for (size_t i = 0; i <= cap; i++)
            sim_close(&sim[i]);
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    /* ── A connected client that waited past the deadline ──────── */

    printf("frontdoor reclaims slots past the residency deadline... ");
    {
        struct sim_client sim[SIM_MAX];
        int held[SIM_MAX];
        bool ok = true;

        /* Deadline 2 ms, then wait past it. Each client stays
         * CONNECTED with an unread request pending, so the hang-up
         * probe deliberately cannot fire — this proves the age rule
         * alone is what reopens the door. (0 is not "instantly stale":
         * it is the documented way to DISABLE age-based reclaim, same
         * as ZCL_RPC_TIMEOUT_MS=0 disables the request watchdog.) */
        rpc_http_test_queue_reset(2);
        for (size_t i = 0; i <= cap; i++) {
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
        rpc_http_test_queue_stats(&st);
        /* An expired deadline must not evict on the way IN — the queue
         * reclaims only when it would otherwise report itself full. */
        ok = ok && st.depth == cap && st.reclaimed_stale == 0;

        /* Put every queued entry safely past the 2 ms deadline. */
        (void)poll(NULL, 0, 25);

        ok = ok && sim_open(&sim[cap]);
        sim_send_request(&sim[cap]);
        ok = ok && rpc_http_test_queue_admit(sim[cap].server);
        sim[cap].server = -1;

        rpc_http_test_queue_stats(&st);
        ok = ok && st.reclaimed_stale == cap;
        ok = ok && st.reclaimed_hangup == 0;
        ok = ok && st.depth == 1;

        for (size_t i = 0; i < cap; i++)
            ok = ok && fd_is_closed(held[i]);

        rpc_http_test_queue_reset(-1);
        for (size_t i = 0; i <= cap; i++)
            sim_close(&sim[i]);
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    /* ── THE INVARIANT: no run of hang-ups bricks the door ─────── */

    printf("frontdoor survives a long run of clients that hang up... ");
    {
        size_t rounds = cap * 4;
        bool ok = true;

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

        rpc_http_test_queue_stats(&st);
        ok = ok && st.admitted == (uint64_t)rounds;
        ok = ok && st.depth <= cap;
        /* The run could only get this far by reclaiming. */
        ok = ok && st.reclaimed_hangup > 0;

        rpc_http_test_queue_reset(-1);
        rpc_http_test_queue_stats(&st);
        ok = ok && st.depth == 0;
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    /* ── The queue owns nothing after it is emptied ────────────── */

    printf("frontdoor queue leaves no fd behind when emptied... ");
    {
        struct sim_client sim[SIM_MAX];
        int held[SIM_MAX];
        bool ok = true;

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
        rpc_http_test_queue_stats(&st);
        ok = ok && st.depth == 0 && st.admitted == 0;
        for (size_t i = 0; i < cap; i++)
            ok = ok && fd_is_closed(held[i]);

        for (size_t i = 0; i < cap; i++)
            sim_close(&sim[i]);
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    rpc_http_test_queue_reset(-1);

    printf("\n%d rpc front-door slot tests, %d failed\n", 5, failures);
    return failures;
}
