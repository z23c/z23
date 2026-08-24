/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * The onion socketpair bridge, exercised end to end WITHOUT a live Tor
 * network. lib/test/src/test_onion_stream.c covers the fail-closed gates
 * (no Tor runtime, no clearnet fallback); this file covers what those gates
 * skip and what the fleet actually depends on:
 *
 *   1. Bytes cross the bridge in BOTH directions, byte-for-byte, at a full
 *      VERSION/VERACK-sized exchange plus a burst larger than one pump read.
 *   2. The fd handed to connman carries the same socket properties
 *      connect_socket_start() gives a clearnet peer: connected SOCK_STREAM,
 *      non-blocking, no pending error.
 *   3. A circuit that reaches CONNECTED and then goes terminal inside the
 *      same connect wait is scored a FAILED dial. Accepting it handed the
 *      P2P layer a socket whose pump exits immediately: the node logged
 *      "onion circuit established" and peer_connected, then the peer died
 *      before its version frame could be written, with no line naming why.
 *   4. A backend that refuses writes while its queue drains (the fork's
 *      1 s flush tick) must NOT cost the connection or drop the refused
 *      bytes — that silently truncated the P2P stream mid-frame.
 *   5. The stage ledger names every stage this layer owns, so the
 *      docs/work/ONION_DIAL_GAP.md acceptance contract can assert on a
 *      counter instead of grepping a rotated log.
 *
 * The loopback double stands in for dynhost: its "Tor thread" is a real
 * thread, so the read/event callbacks fire off the caller's thread exactly
 * as the fork's contract says they do. */

#define _DEFAULT_SOURCE   /* usleep */
#include "platform/time_compat.h"
#include "test/test_core.h"
#include "controllers/network_controller.h"
#include "net/onion_stream.h"
#include "net/onion_v3_address.h"
#include "net/peer_lifecycle.h"

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>

/* ── Loopback stand-in for the embedded Tor fork ───────────────────────── */

#define STUB_ECHO_CAP (1u * 1024u * 1024u)

struct stub_stream {
    onion_stream_read_fn  read_cb;
    onion_stream_event_fn event_cb;
    void                 *ctx;

    pthread_t        tid;
    bool             tid_valid;
    _Atomic bool     stop;          /* close() asked the thread to wind up */
    _Atomic bool     terminal;      /* terminal already fired */
    _Atomic bool     closed;        /* close() returned; state is quiescent */

    /* Behaviour knobs, set before open(). */
    bool     die_after_connect;     /* fire CONNECTED then CLOSED at once */
    int      refuse_writes_ticks;   /* writes fail this many times first */

    /* Bytes the app pushed at us, echoed straight back to the read_cb —
     * a peer that mirrors every frame it is sent. */
    uint8_t *echo;
    size_t   echo_len;
};

/* Kept out of the struct so a reset can memset the state without ever
 * destroying a mutex the pump thread might still hold. */
static pthread_mutex_t g_stub_mu = PTHREAD_MUTEX_INITIALIZER;
static struct stub_stream g_stub;
static bool g_stub_opened;

/* The stub's "Tor event loop": fires CONNECTED once, then delivers echoed
 * bytes to the read callback until close() winds it up. */
static void *stub_tor_thread(void *arg)
{
    struct stub_stream *s = (struct stub_stream *)arg;

    usleep(20 * 1000);              /* circuit build */
    s->event_cb((struct onion_stream_raw *)s, ONION_STREAM_EVENT_CONNECTED,
                s->ctx);

    if (s->die_after_connect) {
        atomic_store(&s->terminal, true);
        s->event_cb((struct onion_stream_raw *)s, ONION_STREAM_EVENT_CLOSED,
                    s->ctx);
        return NULL;
    }

    while (!atomic_load(&s->stop)) {
        uint8_t *out = NULL;
        size_t   out_len = 0;
        pthread_mutex_lock(&g_stub_mu);
        if (s->echo_len > 0) {
            out = malloc(s->echo_len);
            if (out) {
                memcpy(out, s->echo, s->echo_len);
                out_len = s->echo_len;
                s->echo_len = 0;
            }
        }
        pthread_mutex_unlock(&g_stub_mu);
        if (out_len > 0)
            s->read_cb((struct onion_stream_raw *)s, out, out_len, s->ctx);
        free(out);
        usleep(5 * 1000);
    }

    atomic_store(&s->terminal, true);
    s->event_cb((struct onion_stream_raw *)s, ONION_STREAM_EVENT_CLOSED,
                s->ctx);
    return NULL;
}

static struct onion_stream_raw *stub_open(const char *onion, uint16_t port,
                                          onion_stream_read_fn read_cb,
                                          onion_stream_event_fn event_cb,
                                          void *ctx, int lifetime_secs)
{
    (void)onion; (void)port; (void)lifetime_secs;
    struct stub_stream *s = &g_stub;
    s->read_cb = read_cb;
    s->event_cb = event_cb;
    s->ctx = ctx;
    if (pthread_create(&s->tid, NULL, stub_tor_thread, s) != 0)
        return NULL;
    s->tid_valid = true;
    g_stub_opened = true;
    return (struct onion_stream_raw *)s;
}

static int stub_write(struct onion_stream_raw *raw, const uint8_t *data,
                      size_t len)
{
    struct stub_stream *s = (struct stub_stream *)raw;
    if (atomic_load(&s->terminal))
        return -1;
    pthread_mutex_lock(&g_stub_mu);
    if (s->refuse_writes_ticks > 0) {
        s->refuse_writes_ticks--;
        pthread_mutex_unlock(&g_stub_mu);
        return -1;                  /* fork's "queue full", not "gone" */
    }
    if (s->echo_len + len > STUB_ECHO_CAP) {
        pthread_mutex_unlock(&g_stub_mu);
        return -1;
    }
    memcpy(s->echo + s->echo_len, data, len);
    s->echo_len += len;
    pthread_mutex_unlock(&g_stub_mu);
    return 0;
}

static void stub_close(struct onion_stream_raw *raw)
{
    struct stub_stream *s = (struct stub_stream *)raw;
    atomic_store(&s->stop, true);
    if (s->tid_valid) {
        pthread_join(s->tid, NULL);
        s->tid_valid = false;
    }
    atomic_store(&s->closed, true);
}

static const struct onion_stream_backend g_stub_backend = {
    .open = stub_open, .write = stub_write, .close = stub_close,
};

/* Wind the double down and hand back a clean slate. The bridge's pump owns
 * the close, so wait for it rather than racing it. */
static void stub_reset(void)
{
    if (g_stub_opened) {
        for (int i = 0; i < 1200 && !atomic_load(&g_stub.closed); i++)
            usleep(5 * 1000);
        if (!atomic_load(&g_stub.closed) && g_stub.tid_valid) {
            atomic_store(&g_stub.stop, true);
            pthread_join(g_stub.tid, NULL);
            g_stub.tid_valid = false;
        }
    }
    free(g_stub.echo);
    memset(&g_stub, 0, sizeof(g_stub));
    g_stub.echo = malloc(STUB_ECHO_CAP);
    g_stub_opened = false;
    onion_stream_reset_stages_for_test();
}

/* Spin until a stage counter reaches want, or the budget runs out. */
static bool wait_bridge_closed(uint64_t want, int budget_ms)
{
    for (int waited = 0; waited < budget_ms; waited += 5) {
        struct onion_stream_stages st;
        onion_stream_get_stages(&st);
        if (st.bridge_closed >= want)
            return st.bridge_closed == want;
        usleep(5 * 1000);
    }
    return false;
}

/* ── Helpers ───────────────────────────────────────────────────────────── */

static bool make_onion_service(struct net_service *svc, uint16_t port)
{
    uint8_t pub[32];
    for (int i = 0; i < 32; i++)
        pub[i] = (uint8_t)(0x11 + i);
    char host[ONION_V3_ADDRESS_LEN + 1];
    if (!onion_v3_address_from_pubkey(pub, host))
        return false;
    net_service_init(svc);
    if (!net_addr_from_onion(host, &svc->addr))
        return false;
    svc->port = port;
    return true;
}

/* Read exactly want bytes off a non-blocking fd, or give up. */
static bool read_exact(zcl_socket_t fd, uint8_t *out, size_t want,
                       int budget_ms)
{
    size_t got = 0;
    int waited = 0;
    while (got < want && waited < budget_ms) {
        ssize_t n = recv(fd, out + got, want - got, 0);
        if (n > 0) { got += (size_t)n; continue; }
        if (n == 0)
            return false;           /* EOF: the bridge tore down */
        if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR)
            return false;
        usleep(5 * 1000);
        waited += 5;
    }
    return got == want;
}

static bool write_all(zcl_socket_t fd, const uint8_t *buf, size_t len,
                      int budget_ms)
{
    size_t sent = 0;
    int waited = 0;
    while (sent < len && waited < budget_ms) {
        ssize_t n = send(fd, buf + sent, len - sent, 0);
        if (n > 0) { sent += (size_t)n; continue; }
        if (n == 0)
            return false;
        if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR)
            return false;
        usleep(5 * 1000);
        waited += 5;
    }
    return sent == len;
}

int test_onion_bridge(void);
int test_onion_bridge(void)
{
    int failures = 0;

    printf("onion_bridge: bytes cross the bridge in both directions... ");
    {
        stub_reset();
        struct net_service svc;
        bool ok = make_onion_service(&svc, 39150);

        /* Seed one OLD successful session for the same endpoint.  The fresh
         * dial below must classify from its own generation delta, never let
         * this historical success make a new unadopted bridge look complete. */
        peer_lifecycle_reset_for_test();
        struct p2p_node old_peer = {0};
        old_peer.addr.svc = svc;
        old_peer.id = 9001;
        old_peer.state = PEER_HANDSHAKE_COMPLETE;
        net_service_to_string(&svc, old_peer.addr_name,
                              sizeof(old_peer.addr_name));
        peer_lifecycle_note_connected(&old_peer,
                                      PEER_LIFECYCLE_SOURCE_ADDNODE);
        peer_lifecycle_note_version_sent(&old_peer, NODE_NETWORK, 1, "old");
        peer_lifecycle_note_version_received(&old_peer, NODE_NETWORK, 1,
                                             "old");
        peer_lifecycle_note_verack_received(&old_peer);
        peer_lifecycle_note_handshake_complete(&old_peer);
        peer_lifecycle_note_disconnected(&old_peer, "test_old_session");

        zcl_socket_t app = ZCL_INVALID_SOCKET;
        ok = ok && onion_stream_connect_backend_for_test(&svc, &app, 4000,
                                                         &g_stub_backend) &&
             app != ZCL_INVALID_SOCKET;

        /* A version-frame-sized round trip, then a burst larger than one
         * 16 KiB pump read so the staging path is exercised too. */
        static const size_t sizes[] = { 126, 24, 70000 };
        for (size_t si = 0; ok && si < sizeof(sizes) / sizeof(sizes[0]); si++) {
            size_t n = sizes[si];
            uint8_t *tx = malloc(n), *rx = malloc(n);
            if (!tx || !rx) { ok = false; free(tx); free(rx); break; }
            for (size_t i = 0; i < n; i++)
                tx[i] = (uint8_t)((i * 31u + si * 7u) & 0xff);
            ok = write_all(app, tx, n, 5000) &&
                 read_exact(app, rx, n, 5000) &&
                 memcmp(tx, rx, n) == 0;
            free(tx);
            free(rx);
        }

        /* The ledger must have named every stage of a successful dial. */
        struct onion_stream_stages st;
        onion_stream_get_stages(&st);
        ok = ok && st.dial_started == 1 && st.stream_queued == 1 &&
             st.circuit_ready == 1 && st.bridge_up == 1 &&
             st.peers_answered == 1 &&
             st.bytes_to_peer == 126 + 24 + 70000 &&
             st.bytes_from_peer == 126 + 24 + 70000 &&
             st.circuit_torn_down == 0 && st.circuit_timeout == 0;

        struct onion_stream_dial_snapshot recent[2];
        size_t recent_count = onion_stream_get_recent_dials(recent, 2);
        ok = ok && recent_count == 1 && recent[0].active &&
             strstr(recent[0].target, ".onion:39150") != NULL &&
             recent[0].stages.dial_started == 1 &&
             recent[0].stages.bridge_up == 1 &&
             recent[0].stages.peers_answered == 1 &&
             recent[0].stages.bytes_to_peer == 126 + 24 + 70000 &&
             recent[0].stages.bytes_from_peer == 126 + 24 + 70000 &&
             recent[0].p2p_baseline.handshake_complete == 1;

        struct json_value params = {0};
        struct json_value status = {0};
        json_set_array(&params);
        ok = ok && network_onion_status_rpc(&params, false, &status);
        const struct json_value *dial = json_at(
            json_get(&status, "recent_dials"), 0);
        const struct json_value *delta = dial
            ? json_get(dial, "p2p_handshake_delta") : NULL;
        ok = ok && dial &&
             strcmp(json_get_str(json_get(dial, "first_incomplete_stage")),
                    "p2p_not_connected") == 0 &&
             delta && json_get_int(json_get(delta, "connected")) == 0 &&
             json_get_int(json_get(delta, "handshake_complete")) == 0;
        json_free(&status);
        json_free(&params);

        if (app != ZCL_INVALID_SOCKET)
            close_socket(&app);
        /* The pump must notice the app-side EOF and name its own teardown. */
        ok = ok && wait_bridge_closed(1, 5000);
        recent_count = onion_stream_get_recent_dials(recent, 2);
        ok = ok && recent_count == 1 && !recent[0].active &&
             recent[0].stages.bridge_closed == 1 &&
             recent[0].ended_ms >= recent[0].started_ms;
        stub_reset();
        peer_lifecycle_reset_for_test();

        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("onion_bridge: bridged fd matches the clearnet socket contract... ");
    {
        stub_reset();
        struct net_service svc;
        bool ok = make_onion_service(&svc, 39150);
        zcl_socket_t app = ZCL_INVALID_SOCKET;
        ok = ok && onion_stream_connect_backend_for_test(&svc, &app, 4000,
                                                         &g_stub_backend);

        if (ok) {
            /* Non-blocking, exactly as connect_socket_start() leaves a
             * clearnet fd — the reactor polls and must never stall a send. */
            int fl = fcntl(app, F_GETFL, 0);
            ok = ok && fl >= 0 && (fl & O_NONBLOCK) != 0;

            /* A connected SOCK_STREAM with no pending error: what
             * connect_socket_check() asserts before connman adopts an fd. */
            int type = 0, so_err = -1;
            socklen_t tlen = sizeof(type), elen = sizeof(so_err);
            ok = ok && getsockopt(app, SOL_SOCKET, SO_TYPE, &type, &tlen) == 0 &&
                 type == SOCK_STREAM;
            ok = ok &&
                 getsockopt(app, SOL_SOCKET, SO_ERROR, &so_err, &elen) == 0 &&
                 so_err == 0;

            /* Immediately writable and not hung up — the reactor's first
             * POLLOUT edge is where the version frame goes out. */
            struct pollfd p = { .fd = app, .events = POLLOUT, .revents = 0 };
            ok = ok && poll(&p, 1, 250) == 1 && (p.revents & POLLOUT) != 0 &&
                 (p.revents & (POLLERR | POLLHUP | POLLNVAL)) == 0;
        }

        if (app != ZCL_INVALID_SOCKET)
            close_socket(&app);
        (void)wait_bridge_closed(1, 5000);
        stub_reset();

        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("onion_bridge: a circuit that dies at CONNECTED is a failed dial... ");
    {
        stub_reset();
        g_stub.die_after_connect = true;
        struct net_service svc;
        bool ok = make_onion_service(&svc, 39150);

        zcl_socket_t app = ZCL_INVALID_SOCKET;
        /* Under the retry ceiling, so exactly one attempt is made. */
        ok = ok && !onion_stream_connect_backend_for_test(&svc, &app, 2000,
                                                          &g_stub_backend) &&
             app == ZCL_INVALID_SOCKET;

        struct onion_stream_stages st;
        onion_stream_get_stages(&st);
        ok = ok && st.circuit_torn_down == 1 && st.bridge_up == 0 &&
             st.circuit_ready == 0;
        struct onion_stream_dial_snapshot recent[2];
        size_t recent_count = onion_stream_get_recent_dials(recent, 2);
        ok = ok && recent_count == 1 && !recent[0].active &&
             recent[0].stages.circuit_torn_down == 1 &&
             recent[0].stages.bridge_up == 0;
        stub_reset();

        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("onion_bridge: circuit backpressure does not drop bytes or the "
           "peer... ");
    {
        stub_reset();
        /* ~1 s of refusals at the pump's 25 ms retry cadence: well inside
         * ONION_TX_BACKPRESSURE_MS, and exactly the shape of the fork's
         * "queue full until the next flush tick". */
        g_stub.refuse_writes_ticks = 40;
        struct net_service svc;
        bool ok = make_onion_service(&svc, 39150);

        zcl_socket_t app = ZCL_INVALID_SOCKET;
        ok = ok && onion_stream_connect_backend_for_test(&svc, &app, 4000,
                                                         &g_stub_backend);

        uint8_t tx[126], rx[126];
        for (size_t i = 0; i < sizeof(tx); i++)
            tx[i] = (uint8_t)(0xa0 + (i & 0x1f));
        ok = ok && write_all(app, tx, sizeof(tx), 5000) &&
             read_exact(app, rx, sizeof(rx), 8000) &&
             memcmp(tx, rx, sizeof(tx)) == 0;

        struct onion_stream_stages st;
        onion_stream_get_stages(&st);
        ok = ok && st.bridge_closed == 0 && st.bytes_to_peer == sizeof(tx);

        if (app != ZCL_INVALID_SOCKET)
            close_socket(&app);
        (void)wait_bridge_closed(1, 5000);
        stub_reset();

        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    return failures;
}
