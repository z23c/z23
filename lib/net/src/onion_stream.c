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
#include "net/onion_stream_telemetry.h"
#include "net/onion_v3_address.h"
#include "net/tor_integration.h"
#include "platform/time_compat.h"
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
/* The fork flushes queued writes on Tor's ~1 s event-loop tick and refuses
 * a write that would push its queue past 4 MiB. On a healthy peer that
 * refusal is ordinary backpressure, NOT a dead stream, so the pump waits it
 * out for this long before giving up on the connection. */
#define ONION_TX_BACKPRESSURE_MS 5000

enum onion_bridge_phase {
    BRIDGE_CONNECTING = 0,
    BRIDGE_CONNECTED  = 1,
};

struct onion_bridge {
    const struct onion_stream_backend *be;  /* raw-stream calls; never NULL */
    struct onion_stream_raw *stream; /* closed EXACTLY once, by the pump */
    zcl_socket_t      pump_fd;    /* bridge end of the socketpair */
    _Atomic int       phase;      /* enum onion_bridge_phase */
    _Atomic bool      terminal_seen; /* CLOSED/TIMEOUT fired: no callbacks after */
    pthread_mutex_t   mu;         /* serializes ALL writes to pump_fd */
    uint8_t          *rxq;        /* staged Tor → app bytes */
    size_t            rxq_head;
    size_t            rxq_len;
    bool              rx_overflow;/* cap exceeded: tear down, never drop */
    bool              dead;       /* set under mu before pump_fd closes */
    uint64_t          tx_bytes;   /* app → Tor; pump thread only */
    _Atomic uint64_t  rx_bytes;   /* Tor → app; written on Tor's thread */
    int64_t           up_since_ms;/* monotonic ms at bridge_up */
    const char       *close_reason; /* names the pump's exit path */
    char              desc[NET_SERVICE_STR_MAX + 1];
    struct onion_stream_dial_record *dial_record;
};

static void onion_bridge_read(struct onion_stream_raw *stream,
                              const uint8_t *data, size_t len, void *ctx);
static void onion_bridge_event(struct onion_stream_raw *stream, int event,
                               void *ctx);

/* ── Production backend: the embedded Tor fork's weak symbols ────────────
 * Trampolines, not function-pointer casts: the fork types its callbacks on
 * dynhost_stream_t and this layer types them on the opaque
 * onion_stream_raw, so the two pointer types meet exactly once, here, on a
 * data pointer. */
static void dynhost_read_trampoline(dynhost_stream_t *s, const uint8_t *data,
                                    size_t len, void *ctx)
{
    onion_bridge_read((struct onion_stream_raw *)s, data, len, ctx);
}

static void dynhost_event_trampoline(dynhost_stream_t *s, int event, void *ctx)
{
    onion_bridge_event((struct onion_stream_raw *)s, event, ctx);
}

static struct onion_stream_raw *dynhost_open_adapter(
    const char *onion, uint16_t port, onion_stream_read_fn read_cb,
    onion_stream_event_fn event_cb, void *ctx, int lifetime_secs)
{
    (void)read_cb;   /* the trampolines above ARE the bridge's callbacks */
    (void)event_cb;
    return (struct onion_stream_raw *)dynhost_stream_open(
        onion, port, dynhost_read_trampoline, dynhost_event_trampoline, ctx,
        lifetime_secs);
}

static int dynhost_write_adapter(struct onion_stream_raw *s,
                                 const uint8_t *data, size_t len)
{
    return dynhost_stream_write((dynhost_stream_t *)s, data, len);
}

static void dynhost_close_adapter(struct onion_stream_raw *s)
{
    dynhost_stream_close((dynhost_stream_t *)s);
}

static const struct onion_stream_backend g_dynhost_backend = {
    .open  = dynhost_open_adapter,
    .write = dynhost_write_adapter,
    .close = dynhost_close_adapter,
};

/* Queue bytes for the app side. The fast path is a non-blocking send
 * straight into the socketpair (immediate delivery, no pump involvement);
 * whatever the socket buffer cannot take is staged for the pump to flush
 * when the fd turns writable. Runs on Tor's event-loop thread — MUST NOT
 * block. */
static void onion_bridge_read(struct onion_stream_raw *stream,
                              const uint8_t *data, size_t len, void *ctx)
{
    (void)stream;
    struct onion_bridge *b = (struct onion_bridge *)ctx;
    if (!b || !data || len == 0)
        return;

    /* Stage: the peer answered on this circuit. Exactly one line per
     * bridge, so "the circuit built but the remote never spoke" is
     * distinguishable from "the remote spoke and we mishandled it". */
    if (atomic_fetch_add_explicit(&b->rx_bytes, (uint64_t)len,
                                  memory_order_relaxed) == 0) {
        onion_stream_dial_bump(b->dial_record, ONION_DIAL_PEERS_ANSWERED, 1);
        LOG_INFO("onion", "onion stage=peer_answered target=%s first_rx=%zu",
                 b->desc, len);
    }
    onion_stream_dial_bump(b->dial_record, ONION_DIAL_BYTES_FROM_PEER,
                           (uint64_t)len);

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

static void onion_bridge_event(struct onion_stream_raw *stream, int event,
                               void *ctx)
{
    (void)stream;
    struct onion_bridge *b = (struct onion_bridge *)ctx;
    if (!b)
        return;
    if (event == ONION_STREAM_EVENT_CONNECTED)
        atomic_store(&b->phase, BRIDGE_CONNECTED);
    else if (event == ONION_STREAM_EVENT_CLOSED ||
             event == ONION_STREAM_EVENT_TIMEOUT)
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

/* Hand one app-side chunk to the circuit. The fork's write refuses for two
 * very different reasons (vendor/tor dynhost_stream.c): the stream is
 * closing/closed, or its 4 MiB queue is full because Tor's ~1 s flush tick
 * has not run yet. Treating both as "the peer is gone" tore down healthy
 * peers AND dropped the bytes just read off the socketpair, so the P2P
 * stream the node believed it had sent was silently truncated mid-frame.
 * Terminal is checked explicitly; anything else is backpressure and the
 * SAME chunk is retried until the budget runs out. Returns false only when
 * the connection is genuinely over, with close_reason already named. */
static bool onion_bridge_push(struct onion_bridge *b, const uint8_t *data,
                              size_t len)
{
    int waited_ms = 0;
    for (;;) {
        if (b->be->write(b->stream, data, len) == 0) {
            b->tx_bytes += (uint64_t)len;
            onion_stream_dial_bump(b->dial_record, ONION_DIAL_BYTES_TO_PEER,
                                   (uint64_t)len);
            return true;
        }
        if (atomic_load(&b->terminal_seen)) {
            b->close_reason = "tor_stream_terminal";
            return false;
        }
        if (waited_ms >= ONION_TX_BACKPRESSURE_MS) {
            b->close_reason = "tor_write_backpressure";
            LOG_WARN("onion", "onion peer %s: circuit refused %zu bytes for "
                              "%d ms (fork write queue full) — tearing down",
                     b->desc, len, waited_ms);
            return false;
        }
        usleep(ONION_CONNECT_POLL_MS * 1000);
        waited_ms += ONION_CONNECT_POLL_MS;
    }
}

/* Shared teardown: close the raw stream (exactly once, here), stop all
 * further fd writes, give the fork's guaranteed terminal event a bounded
 * moment to land, then EOF the app side. The context is freed ONLY when
 * the terminal event was observed — the point after which the fork
 * guarantees no callback can be running or pending. If it never lands
 * (contract violation), the context is LEAKED, never freed: a late callback
 * then touches valid-but-dead memory instead of freed memory. */
static void onion_bridge_teardown(struct onion_bridge *b,
                                  zcl_socket_t *app_fd_or_null)
{
    b->be->close(b->stream);

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

    if (!atomic_load(&b->terminal_seen))
        onion_stream_dial_poison(b->dial_record);

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
 * overflow, then owns the full teardown.
 *
 * Every exit names itself. An onion peer that vanished used to leave NO
 * line anywhere: the pump closed the socketpair, connman scored the
 * app-side EOF as an ordinary io_error on a DIFFERENT sink, and the redial
 * loop was indistinguishable from a handshake that never completed. */
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
        if (overflow) {
            b->close_reason = "inbound_staging_overflow";
            break;
        }
        if (terminal && qlen == 0) {
            b->close_reason = "tor_stream_terminal";
            break;
        }
        if (terminal) {
            drain_left_ms -= ONION_PUMP_TICK_MS;
            if (drain_left_ms <= 0) {
                b->close_reason = "tor_stream_terminal_drain_expired";
                break;
            }
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
            b->close_reason = "pump_poll_error";
            break;
        }
        if (r == 0)
            continue;

        if (pfd.revents & POLLOUT) {
            if (!onion_bridge_drain(b)) {
                b->close_reason = "app_fd_write_error";
                break;
            }
        }

        /* App → Tor. POLLHUP can arrive with data still readable, so read
         * until EAGAIN before giving the revents their meaning. */
        bool app_gone = false;
        for (;;) {
            ssize_t n = recv(b->pump_fd, buf, sizeof(buf), 0);
            if (n > 0) {
                if (!onion_bridge_push(b, buf, (size_t)n)) {
                    app_gone = true;   /* close_reason named by the push */
                    break;
                }
                continue;
            }
            if (n == 0) {
                b->close_reason = "app_closed";   /* app closed its end */
                app_gone = true;
            } else if (errno != EAGAIN && errno != EWOULDBLOCK &&
                       errno != EINTR) {
                b->close_reason = "app_fd_read_error";
                app_gone = true;
            }
            break;
        }
        if (app_gone)
            break;
        if (pfd.revents & (POLLERR | POLLNVAL)) {
            b->close_reason = "app_fd_error";
            break;
        }
        if ((pfd.revents & POLLHUP) && !terminal) {
            b->close_reason = "app_hangup";
            break;
        }
    }

    onion_stream_dial_bump(b->dial_record, ONION_DIAL_BRIDGE_CLOSED, 1);
    LOG_INFO("onion", "onion stage=bridge_closed target=%s reason=%s "
                      "up_ms=%lld to_peer=%llu from_peer=%llu",
             b->desc, b->close_reason ? b->close_reason : "unknown",
             (long long)(platform_time_monotonic_ms() - b->up_since_ms),
             (unsigned long long)b->tx_bytes,
             (unsigned long long)atomic_load_explicit(&b->rx_bytes,
                                                      memory_order_relaxed));

    struct onion_stream_dial_record *dial_record = b->dial_record;
    onion_bridge_teardown(b, NULL);
    onion_stream_dial_end(dial_record);
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

static size_t onion_stream_connect_plan(int connect_timeout_ms,
                                        int budgets[2])
{
    budgets[0] = connect_timeout_ms;
    budgets[1] = 0;
    if (connect_timeout_ms < ONION_STREAM_RETRY_MIN_TOTAL_MS)
        return 1;

    budgets[0] = connect_timeout_ms / 2;
    budgets[1] = connect_timeout_ms - budgets[0];
    return 2;
}

#ifdef ZCL_TESTING
size_t onion_stream_connect_plan_for_test(int connect_timeout_ms,
                                          int budgets[2])
{
    return onion_stream_connect_plan(connect_timeout_ms, budgets);
}
#endif

static bool onion_stream_connect_once(const struct net_service *svc,
                                      zcl_socket_t *sock_out,
                                      int connect_timeout_ms,
                                      const struct onion_stream_backend *be,
                                      struct onion_stream_dial_record *record)
{
    *sock_out = ZCL_INVALID_SOCKET;

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
    b->be = be;
    b->pump_fd = pump_fd;
    b->dial_record = record;
    snprintf(b->desc, sizeof(b->desc), "%s:%u", host, svc->port);

    int64_t started_ms = platform_time_monotonic_ms();
    b->stream = be->open(host, svc->port, onion_bridge_read,
                         onion_bridge_event, b, ONION_STREAM_LIFETIME_SECS);
    if (!b->stream) {
        onion_stream_dial_bump(record, ONION_DIAL_OPEN_REFUSED, 1);
        LOG_WARN("onion", "onion stage=open_refused target=%s", b->desc);
        pthread_mutex_destroy(&b->mu);
        free(b->rxq);
        free(b);
        close_socket(&app_fd);
        close_socket(&pump_fd);
        return false;
    }
    onion_stream_dial_bump(record, ONION_DIAL_STREAM_QUEUED, 1);
    LOG_INFO("onion", "onion stage=stream_queued target=%s budget_ms=%d",
             b->desc, connect_timeout_ms);

    /* Wait for the circuit: CONNECTED wins, a terminal event or the
     * connect budget ends the attempt. */
    int waited_ms = 0;
    while (atomic_load(&b->phase) != BRIDGE_CONNECTED &&
           !atomic_load(&b->terminal_seen) &&
           waited_ms < connect_timeout_ms) {
        usleep(ONION_CONNECT_POLL_MS * 1000);
        waited_ms += ONION_CONNECT_POLL_MS;
    }

    /* A stream that reached CONNECTED and then went terminal inside the
     * same wait is NOT a usable circuit. Accepting it handed connman a
     * socketpair whose pump exits on its very first iteration: the dial
     * logged "onion circuit established", net.c logged peer_connected, and
     * the peer died before its version frame could be written — with no
     * line naming why. Score it as the torn-down circuit it is and spend
     * the retry budget on a fresh one. */
    if (atomic_load(&b->phase) != BRIDGE_CONNECTED ||
        atomic_load(&b->terminal_seen)) {
        bool was_terminal = atomic_load(&b->terminal_seen);
        if (was_terminal)
            onion_stream_dial_bump(record, ONION_DIAL_CIRCUIT_TORN_DOWN, 1);
        else
            onion_stream_dial_bump(record, ONION_DIAL_CIRCUIT_TIMEOUT, 1);
        LOG_WARN("onion", "onion dial to %s %s (stage=%s waited_ms=%d)",
                 b->desc,
                 was_terminal ? "was refused/torn down by Tor"
                              : "timed out waiting for a circuit",
                 was_terminal ? "circuit_torn_down" : "circuit_timeout",
                 waited_ms);
        onion_bridge_teardown(b, &app_fd);
        return false;
    }

    onion_stream_dial_bump(record, ONION_DIAL_CIRCUIT_READY, 1);
    LOG_INFO("onion", "onion stage=circuit_ready target=%s build_ms=%lld",
             b->desc, (long long)(platform_time_monotonic_ms() - started_ms));

    b->up_since_ms = platform_time_monotonic_ms();
    if (!onion_bridge_spawn_pump(b)) {
        LOG_WARN("onion", "onion pump spawn failed for %s", b->desc);
        onion_bridge_teardown(b, &app_fd);
        return false;
    }

    *sock_out = app_fd;
    onion_stream_dial_bump(record, ONION_DIAL_BRIDGE_UP, 1);
    LOG_INFO("onion", "onion circuit established to %s (stage=bridge_up)",
             b->desc);
    return true;
}

static bool onion_stream_connect_backend(const struct net_service *svc,
                                         zcl_socket_t *sock_out,
                                         int connect_timeout_ms,
                                         const struct onion_stream_backend *be)
{
    struct onion_stream_dial_record *record = onion_stream_dial_begin(svc);
    int budgets[2];
    size_t attempts = onion_stream_connect_plan(connect_timeout_ms, budgets);
    for (size_t i = 0; i < attempts; i++) {
        if (onion_stream_connect_once(svc, sock_out, budgets[i], be, record))
            return true;
        if (i + 1 < attempts)
            LOG_WARN("onion", "first onion circuit attempt failed; "
                              "retrying once with a fresh stream "
                              "(remaining_budget_ms=%d)", budgets[i + 1]);
    }
    onion_stream_dial_end(record);
    return false;
}

#ifdef ZCL_TESTING
bool onion_stream_connect_backend_for_test(
    const struct net_service *svc, zcl_socket_t *sock_out,
    int connect_timeout_ms, const struct onion_stream_backend *backend)
{
    if (!sock_out)
        LOG_FAIL("onion", "onion_stream_connect: NULL sock_out");
    *sock_out = ZCL_INVALID_SOCKET;
    if (!svc || !backend || !backend->open || !backend->write ||
        !backend->close)
        LOG_FAIL("onion", "onion_stream_connect: incomplete test backend");

    return onion_stream_connect_backend(svc, sock_out, connect_timeout_ms,
                                        backend);
}
#endif

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
    if (!tor_integration_is_dial_ready())
        LOG_FAIL("onion", "onion dialing unavailable: dynhost not ready "
                          "to queue outbound streams");

    return onion_stream_connect_backend(svc, sock_out, connect_timeout_ms,
                                        &g_dynhost_backend);
}
