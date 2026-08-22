/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: see net/onion_stream.h — the dynhost raw-stream ↔ socketpair
 * bridge that lets connman dial .onion peers without a SOCKS proxy and
 * without any change above the socket layer.
 *
 * supervisor-ok:per-connection-pump — the pump thread's lifetime IS the
 * connection's: it exits on fd EOF or stream terminal and frees the bridge
 * in the same frame, so there is no long-running loop to supervise, and at
 * most MAX_OUTBOUND_ONION such threads exist at once. */

#define _DEFAULT_SOURCE   /* usleep, MSG_NOSIGNAL */
#include "net/onion_stream.h"
#include "net/onion_v3_address.h"
#include "net/tor_integration.h"
#include "util/safe_alloc.h"
#include "util/log_macros.h"

#include <errno.h>
#include <pthread.h>
#include <poll.h>
#include <stdatomic.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>

#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif

/* ── Weak dynhost raw-stream symbols ─────────────────────────────────────
 * Present when linked against the real vendored libtor.a; NULL against
 * libtor_stub.a (same posture as dynhost_client_fetch in
 * tor_integration.c). Every call site is NULL-guarded, and the stub build
 * fails CLOSED with a named error before any dial is attempted. */
typedef struct dynhost_stream dynhost_stream_t;
#define DYNHOST_STREAM_EVENT_OPEN      0
#define DYNHOST_STREAM_EVENT_CONNECTED 1
#define DYNHOST_STREAM_EVENT_CLOSED    2
#define DYNHOST_STREAM_EVENT_TIMEOUT   3
typedef void (*dynhost_stream_read_fn)(dynhost_stream_t *, const uint8_t *,
                                       size_t, void *);
typedef void (*dynhost_stream_event_fn)(dynhost_stream_t *, int, void *);
extern dynhost_stream_t *dynhost_stream_open(const char *onion,
    uint16_t port, dynhost_stream_read_fn, dynhost_stream_event_fn,
    void *ctx, int timeout_secs) __attribute__((weak));
extern int dynhost_stream_write(dynhost_stream_t *, const uint8_t *, size_t)
    __attribute__((weak));
extern void dynhost_stream_close(dynhost_stream_t *) __attribute__((weak));

/* Inbound (Tor → app) staging cap, mirroring the fork's own 4 MiB write
 * queue bound. A peer that outruns our reactor by more than this is torn
 * down rather than buffered without limit. */
#define ONION_RXQ_CAP (4u * 1024u * 1024u)

/* Connect-phase / teardown poll cadences. */
#define ONION_CONNECT_POLL_MS 25
#define ONION_PUMP_TICK_MS   250
/* After the remote stream ends, this long is spent draining bytes already
 * staged for the app before the fd is closed. */
#define ONION_DRAIN_BUDGET_MS 2000
/* dynhost guarantees exactly one terminal event; this is the defensive
 * bound on waiting for it before leaking (never freeing) the context. */
#define ONION_TERMINAL_WAIT_MS 5000

enum onion_bridge_phase {
    BRIDGE_CONNECTING = 0,
    BRIDGE_CONNECTED  = 1,
};

struct onion_bridge {
    dynhost_stream_t *stream;     /* closed EXACTLY once, by the pump */
    zcl_socket_t      pump_fd;    /* bridge end of the socketpair */
    _Atomic int       phase;      /* enum onion_bridge_phase */
    _Atomic bool      terminal_seen; /* CLOSED/TIMEOUT fired: no callbacks after */
    pthread_mutex_t   mu;         /* serializes ALL writes to pump_fd */
    uint8_t          *rxq;        /* staged Tor → app bytes */
    size_t            rxq_head;
    size_t            rxq_len;
    bool              rx_overflow;/* cap exceeded: tear down, never drop */
    bool              dead;       /* set under mu before pump_fd closes */
    char              desc[NET_SERVICE_STR_MAX + 1];
};

/* Queue bytes for the app side. The fast path is a non-blocking send
 * straight into the socketpair (immediate delivery, no pump involvement);
 * whatever the socket buffer cannot take is staged for the pump to flush
 * when the fd turns writable. Runs on Tor's event-loop thread — MUST NOT
 * block. */
static void onion_bridge_read(dynhost_stream_t *stream, const uint8_t *data,
                              size_t len, void *ctx)
{
    (void)stream;
    struct onion_bridge *b = (struct onion_bridge *)ctx;
    if (!b || !data || len == 0)
        return;

    pthread_mutex_lock(&b->mu);
    if (b->dead) {
        pthread_mutex_unlock(&b->mu);
        return;
    }
    size_t off = 0;
    if (b->rxq_len == 0) {
        ssize_t w = send(b->pump_fd, data, len, MSG_NOSIGNAL);
        if (w > 0)
            off = (size_t)w;
        else if (w < 0 && errno != EAGAIN && errno != EWOULDBLOCK &&
                 errno != EINTR)
            off = len;  /* fd is dying; the pump's poll sees it and tears
                         * down — do not stage bytes nobody will read */
    }
    if (off < len && !b->rx_overflow) {
        size_t need = len - off;
        if (b->rxq_head > 0) {
            memmove(b->rxq, b->rxq + b->rxq_head, b->rxq_len);
            b->rxq_head = 0;
        }
        if (b->rxq_len + need > ONION_RXQ_CAP) {
            b->rx_overflow = true;
            LOG_WARN("onion", "onion peer %s outran the %u-byte inbound "
                              "staging cap — tearing down",
                     b->desc, (unsigned)ONION_RXQ_CAP);
        } else {
            memcpy(b->rxq + b->rxq_head + b->rxq_len, data + off, need);
            b->rxq_len += need;
        }
    }
    pthread_mutex_unlock(&b->mu);
}

static void onion_bridge_event(dynhost_stream_t *stream, int event, void *ctx)
{
    (void)stream;
    struct onion_bridge *b = (struct onion_bridge *)ctx;
    if (!b)
        return;
    if (event == DYNHOST_STREAM_EVENT_CONNECTED)
        atomic_store(&b->phase, BRIDGE_CONNECTED);
    else if (event == DYNHOST_STREAM_EVENT_CLOSED ||
             event == DYNHOST_STREAM_EVENT_TIMEOUT)
        atomic_store(&b->terminal_seen, true);
}

/* Flush staged Tor → app bytes while the fd stays writable. Returns false
 * when the fd is dead (peer side gone) or the queue hit its cap. */
static bool onion_bridge_drain(struct onion_bridge *b)
{
    pthread_mutex_lock(&b->mu);
    while (b->rxq_len > 0 && !b->dead) {
        ssize_t w = send(b->pump_fd, b->rxq + b->rxq_head, b->rxq_len,
                         MSG_NOSIGNAL);
        if (w > 0) {
            b->rxq_head += (size_t)w;
            b->rxq_len -= (size_t)w;
            if (b->rxq_len == 0)
                b->rxq_head = 0;
            continue;
        }
        if (w < 0 && (errno == EAGAIN || errno == EWOULDBLOCK ||
                      errno == EINTR))
            break;
        b->dead = true;   /* hard fd error */
    }
    bool ok = !b->dead && !b->rx_overflow;
    pthread_mutex_unlock(&b->mu);
    return ok;
}

/* Shared teardown: close the dynhost stream (exactly once, here), stop all
 * further fd writes, give the fork's guaranteed terminal event a bounded
 * moment to land, then EOF the app side. The context is freed ONLY when
 * the terminal event was observed — the point after which the fork
 * guarantees no callback can be running or pending. If it never lands
 * (contract violation), the context is LEAKED, never freed: a late callback
 * then touches valid-but-dead memory instead of freed memory. */
static void onion_bridge_teardown(struct onion_bridge *b,
                                  zcl_socket_t *app_fd_or_null)
{
    dynhost_stream_close(b->stream);

    pthread_mutex_lock(&b->mu);
    b->dead = true;
    pthread_mutex_unlock(&b->mu);

    int waited = 0;
    while (!atomic_load(&b->terminal_seen) && waited < ONION_TERMINAL_WAIT_MS) {
        usleep(ONION_CONNECT_POLL_MS * 1000);
        waited += ONION_CONNECT_POLL_MS;
    }
    if (!atomic_load(&b->terminal_seen))
        LOG_WARN("onion", "dynhost terminal event never arrived for %s "
                          "(fork contract violation) — leaking the bridge "
                          "context rather than risking a late callback",
                 b->desc);

    close_socket(&b->pump_fd);
    if (app_fd_or_null)
        close_socket(app_fd_or_null);

    if (!atomic_load(&b->terminal_seen))
        return;   /* deliberate leak, named above */

    pthread_mutex_destroy(&b->mu);
    free(b->rxq);
    free(b);
}

/* Snapshot of the queue state for the pump loop; rxq_len and rx_overflow
 * are written under mu by the Tor-thread read callback, so the pump reads
 * them under the same lock. */
static void onion_bridge_queue_state(struct onion_bridge *b, size_t *qlen,
                                     bool *overflow)
{
    pthread_mutex_lock(&b->mu);
    *qlen = b->rxq_len;
    *overflow = b->rx_overflow;
    pthread_mutex_unlock(&b->mu);
}

/* Pump thread: shuttles app → Tor bytes (Tor → app is written by the read
 * callback directly). Exits on app EOF/error, stream terminal, or staging
 * overflow, then owns the full teardown. */
static void *onion_bridge_pump(void *arg)
{
    struct onion_bridge *b = (struct onion_bridge *)arg;
    uint8_t buf[16384];
    int drain_left_ms = ONION_DRAIN_BUDGET_MS;

    for (;;) {
        size_t qlen;
        bool overflow;
        onion_bridge_queue_state(b, &qlen, &overflow);
        bool terminal = atomic_load(&b->terminal_seen);
        if (overflow)
            break;
        if (terminal && qlen == 0)
            break;
        if (terminal) {
            drain_left_ms -= ONION_PUMP_TICK_MS;
            if (drain_left_ms <= 0)
                break;
        }

        short events = POLLIN;
        if (qlen > 0)
            events |= POLLOUT;
        struct pollfd pfd = { .fd = b->pump_fd, .events = events,
                              .revents = 0 };
        int r = poll(&pfd, 1, ONION_PUMP_TICK_MS);
        if (r < 0) {
            if (errno == EINTR)
                continue;
            break;
        }
        if (r == 0)
            continue;

        if (pfd.revents & POLLOUT) {
            if (!onion_bridge_drain(b))
                break;
        }

        /* App → Tor. POLLHUP can arrive with data still readable, so read
         * until EAGAIN before giving the revents their meaning. */
        bool app_gone = false;
        for (;;) {
            ssize_t n = recv(b->pump_fd, buf, sizeof(buf), 0);
            if (n > 0) {
                if (dynhost_stream_write(b->stream, buf, (size_t)n) != 0) {
                    /* Stream is closing/closed or over its queue cap — the
                     * terminal event will (or did) follow; stop pumping. */
                    app_gone = true;
                    break;
                }
                continue;
            }
            if (n == 0)
                app_gone = true;   /* app closed its end */
            else if (errno != EAGAIN && errno != EWOULDBLOCK &&
                     errno != EINTR)
                app_gone = true;
            break;
        }
        if (app_gone)
            break;
        if (pfd.revents & (POLLERR | POLLNVAL))
            break;
        if ((pfd.revents & POLLHUP) && !terminal)
            break;
    }

    onion_bridge_teardown(b, NULL);
    return NULL;
}

static bool onion_bridge_spawn_pump(struct onion_bridge *b)
{
    pthread_t tid;
    /* raw-pthread-ok: per-connection pump, detached and bounded by
     * MAX_OUTBOUND_ONION concurrent onion peers; the thread registry's
     * NULL-tid ownership retains every entry until join_all, which a
     * long-lived node dialing onion peers over months would eventually
     * fill. The bridge teardown (fd EOF or stream terminal) is the
     * liveness contract — there is nothing for a supervisor to restart. */
    /* raw-pthread-ok: see the block above */
    int rc = pthread_create(&tid, NULL, onion_bridge_pump, b);
    if (rc != 0) {
        LOG_FAIL("onion", "pthread_create failed for onion pump to %s: rc=%d",
                 b->desc, rc);
    }
    pthread_detach(tid);
    return true;
}

bool onion_stream_connect(const struct net_service *svc,
                          zcl_socket_t *sock_out,
                          int connect_timeout_ms)
{
    if (!sock_out)
        LOG_FAIL("onion", "onion_stream_connect: NULL sock_out");
    *sock_out = ZCL_INVALID_SOCKET;

    if (!svc || !net_addr_is_tor(&svc->addr))
        LOG_FAIL("onion", "onion_stream_connect: not a torv3 address");
    if (!dynhost_stream_open || !dynhost_stream_write || !dynhost_stream_close)
        LOG_FAIL("onion", "onion dialing unavailable: tor stub build");
    if (!tor_integration_is_enabled())
        LOG_FAIL("onion", "onion dialing unavailable: tor not running");
    if (!tor_integration_is_ready())
        LOG_FAIL("onion", "onion dialing unavailable: tor not ready "
                          "(still bootstrapping)");

    char host[ONION_V3_ADDRESS_LEN + 1];
    if (!onion_v3_address_from_pubkey(svc->addr.torv3, host))
        LOG_FAIL("onion", "onion_stream_connect: torv3 key does not render");

    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0)
        LOG_FAIL("onion", "socketpair failed for %s: errno=%d", host, errno);
    zcl_socket_t app_fd = sv[0];
    zcl_socket_t pump_fd = sv[1];
    /* Match connect_socket_start() semantics: the node above expects a
     * non-blocking fd (the reactor polls; sends must not stall the message
     * thread on a full buffer). */
    if (!set_socket_nonblocking(app_fd, true) ||
        !set_socket_nonblocking(pump_fd, true)) {
        close_socket(&app_fd);
        close_socket(&pump_fd);
        LOG_FAIL("onion", "set_socket_nonblocking failed for %s", host);
    }

    struct onion_bridge *b = zcl_calloc(1, sizeof(*b), "onion_bridge");
    if (!b) {
        close_socket(&app_fd);
        close_socket(&pump_fd);
        LOG_FAIL("onion", "onion bridge allocation failed for %s", host);
    }
    b->rxq = zcl_malloc(ONION_RXQ_CAP, "onion_bridge_rxq");
    if (!b->rxq) {
        free(b);
        close_socket(&app_fd);
        close_socket(&pump_fd);
        LOG_FAIL("onion", "onion bridge rxq allocation failed for %s", host);
    }
    pthread_mutex_init(&b->mu, NULL);
    b->pump_fd = pump_fd;
    snprintf(b->desc, sizeof(b->desc), "%s:%u", host, svc->port);

    b->stream = dynhost_stream_open(host, svc->port, onion_bridge_read,
                                    onion_bridge_event, b,
                                    ONION_STREAM_LIFETIME_SECS);
    if (!b->stream) {
        LOG_WARN("onion", "dynhost_stream_open refused %s", b->desc);
        pthread_mutex_destroy(&b->mu);
        free(b->rxq);
        free(b);
        close_socket(&app_fd);
        close_socket(&pump_fd);
        return false;
    }

    /* Wait for the circuit: CONNECTED wins, a terminal event or the
     * connect budget ends the attempt. */
    int waited_ms = 0;
    while (atomic_load(&b->phase) != BRIDGE_CONNECTED &&
           !atomic_load(&b->terminal_seen) &&
           waited_ms < connect_timeout_ms) {
        usleep(ONION_CONNECT_POLL_MS * 1000);
        waited_ms += ONION_CONNECT_POLL_MS;
    }

    if (atomic_load(&b->phase) != BRIDGE_CONNECTED) {
        bool was_terminal = atomic_load(&b->terminal_seen);
        LOG_WARN("onion", "onion dial to %s %s", b->desc,
                 was_terminal ? "was refused/torn down by Tor"
                              : "timed out waiting for a circuit");
        onion_bridge_teardown(b, &app_fd);
        return false;
    }

    if (!onion_bridge_spawn_pump(b)) {
        LOG_WARN("onion", "onion pump spawn failed for %s", b->desc);
        onion_bridge_teardown(b, &app_fd);
        return false;
    }

    *sock_out = app_fd;
    LOG_INFO("onion", "onion circuit established to %s", b->desc);
    return true;
}
