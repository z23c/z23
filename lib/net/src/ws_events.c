/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * WebSocket event stream — see ws_events.h for the contract. */

#define _DEFAULT_SOURCE  /* usleep */
#include "net/ws_events.h"
#include "event/event.h"
#include "crypto/sha1.h"
#include "encoding/utilstrencodings.h"
#include "core/utiltime.h"

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <sys/socket.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "util/log_macros.h"
#include "util/thread_liveness.h"
#include "util/thread_registry.h"

/* ── WebSocket frame helpers (RFC 6455 minimal) ──────────────── */

/* Opcodes */
#define WS_TEXT   0x1
#define WS_CLOSE  0x8
#define WS_PING   0x9
#define WS_PONG   0xA

/* Write a server→client frame (no masking per RFC 6455 §5.1).
 * Returns bytes written, or -1 on error. */
static ssize_t ws_write_frame(int fd, uint8_t opcode,
                               const void *data, size_t len)
{
    uint8_t hdr[10];
    size_t hdr_len;
    hdr[0] = (uint8_t)(0x80 | (opcode & 0x0F));  /* FIN + opcode */

    if (len < 126) {
        hdr[1] = (uint8_t)len;
        hdr_len = 2;
    } else if (len < 65536) {
        hdr[1] = 126;
        hdr[2] = (uint8_t)(len >> 8);
        hdr[3] = (uint8_t)(len & 0xFF);
        hdr_len = 4;
    } else {
        hdr[1] = 127;
        for (int i = 0; i < 8; i++)
            hdr[2 + i] = (uint8_t)((len >> (56 - 8 * i)) & 0xFF);
        hdr_len = 10;
    }

    /* Non-blocking write with MSG_NOSIGNAL to avoid SIGPIPE when the
     * client has disconnected.  If the buffer is full, we'll catch
     * the error and mark the client dead on the next pump iteration. */
    ssize_t w1 = send(fd, hdr, hdr_len, MSG_NOSIGNAL);
    if (w1 < 0) return -1;
    if (len > 0) {
        ssize_t w2 = send(fd, data, len, MSG_NOSIGNAL);
        if (w2 < 0) return -1;
        return w1 + w2;
    }
    return w1;
}

/* ── Domain filter matching ──────────────────────────────────── */

#define WS_FILTER_LEN 256

/* Check if an event type name matches a comma-separated prefix
 * filter.  Empty filter matches everything. */
static bool domain_matches(const char *filter, const char *type_name)
{
    if (!filter || !filter[0]) return true;
    if (!type_name) return false;

    /* Iterate comma-separated prefixes */
    const char *p = filter;
    while (*p) {
        while (*p == ' ' || *p == ',') p++;
        if (!*p) break;
        const char *end = p;
        while (*end && *end != ',') end++;
        size_t plen = (size_t)(end - p);
        /* Trim trailing spaces */
        while (plen > 0 && p[plen - 1] == ' ') plen--;
        if (plen > 0 && strncmp(type_name, p, plen) == 0)
            return true;
        p = end;
    }
    return false;
}

/* ── Client table ────────────────────────────────────────────── */

struct ws_client {
    int       fd;
    bool      active;
    uint64_t  cursor;        /* position in global event ring */
    char      filter[WS_FILTER_LEN];
    int64_t   last_active_us;
    int64_t   last_ping_us;
    uint64_t  delivered;     /* events sent to this client */
    uint64_t  overflows;     /* events dropped (ring too far behind) */
};

static struct ws_client g_clients[WS_MAX_CLIENTS];
static _Atomic int      g_client_count;
static _Atomic uint64_t g_total_delivered;
static pthread_mutex_t  g_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_t        g_pump_thread;
static _Atomic bool     g_running;
static _Atomic bool     g_started;

/* Supervisor liveness (root child — lib/net cannot include the app-side
 * supervisors/domains.h, see util/thread_liveness.h). Liveness-only: the
 * pump sleeps WS_PUMP_INTERVAL_MS between iterations, present on the tree
 * and heartbeats every iteration. */
static struct thread_liveness_child g_ws_pump_liveness = { .id = SUPERVISOR_INVALID_ID };
static _Atomic uint64_t g_ws_pump_beat_count = 0;

/* ── Event ring access (from event.h internals) ──────────────── */

/* The global event log is declared in event.c.  We access it via
 * the public dump API, but for streaming we need direct ring access.
 * Rather than expose the struct, we use the public event_dump_json
 * for now.  However, for efficiency, we read directly from the ring
 * buffer — this is safe because the ring uses atomic writes and
 * readers only lag behind the writer. */

/* We need the global event_log pointer.  Since it's not exposed,
 * we use a simpler approach: maintain a cursor of the last sequence
 * number we've seen, and use event_dump_json_filtered to get new
 * events.  This is less efficient but doesn't require exposing
 * event_log internals. */

/* Actually, the simplest approach: subscribe as an async observer
 * and push events to a small per-module queue, then the pump thread
 * drains the queue to clients.  But observers must be fast...
 *
 * Compromise: use the sequence-based ring.  We extern the global
 * event_log from event.c. */

/* The event_log is actually initialized at file scope in event.c
 * as `static struct event_log g_event_log`.  We can't access it
 * directly.  Instead, we'll use a synchronous observer that queues
 * events into our own internal ring, and the pump thread drains
 * that ring to connected clients. */

#define WS_EVENT_QUEUE_SIZE 4096
#define WS_EVENT_QUEUE_MASK (WS_EVENT_QUEUE_SIZE - 1)

struct ws_event_entry {
    _Atomic uint64_t sequence;
    int64_t          timestamp_us;
    enum event_type  type;
    uint32_t         peer_id;
    char             payload[EVENT_PAYLOAD_SIZE + 1];
    uint32_t         payload_len;
};

static struct ws_event_entry g_event_queue[WS_EVENT_QUEUE_SIZE];
static _Atomic uint64_t      g_eq_write;
static _Atomic uint64_t      g_eq_read;

static void ws_event_observer(enum event_type type, uint32_t peer_id,
                               const void *payload, uint32_t payload_len,
                               void *ctx)
{
    (void)ctx;
    uint64_t pos = atomic_fetch_add(&g_eq_write, 1);
    struct ws_event_entry *e = &g_event_queue[pos & WS_EVENT_QUEUE_MASK];

    e->timestamp_us = GetTimeMicros();
    e->type = type;
    e->peer_id = peer_id;
    e->payload_len = payload_len < EVENT_PAYLOAD_SIZE
                       ? payload_len : EVENT_PAYLOAD_SIZE;
    if (payload && e->payload_len > 0)
        memcpy(e->payload, payload, e->payload_len);
    e->payload[e->payload_len] = '\0';
    atomic_store(&e->sequence, pos + 1);  /* publish */
}

/* ── Pump thread ─────────────────────────────────────────────── */

/* Format one event as JSON into buf.  Returns bytes written. */
static size_t format_event_json(const struct ws_event_entry *e,
                                 char *buf, size_t cap)
{
    const char *name = event_type_name(e->type);
    /* Escape payload for JSON (simple: replace " and \ with space,
     * control chars with space — the payload is diagnostic text,
     * not structured data, so lossy escaping is acceptable). */
    char escaped[EVENT_PAYLOAD_SIZE * 2 + 1];
    size_t ep = 0;
    for (size_t i = 0; i < e->payload_len && ep + 2 < sizeof(escaped); i++) {
        char c = e->payload[i];
        if (c == '"' || c == '\\') {
            escaped[ep++] = '\\';
            escaped[ep++] = c;
        } else if ((unsigned char)c < 0x20) {
            escaped[ep++] = ' ';
        } else {
            escaped[ep++] = c;
        }
    }
    escaped[ep] = '\0';

    int n = snprintf(buf, cap,
        "{\"ts\":%lld,\"type\":\"%s\",\"peer_id\":%u,\"payload\":\"%s\"}",
        (long long)e->timestamp_us, name, e->peer_id, escaped);
    if (n < 0 || (size_t)n >= cap) return 0;
    return (size_t)n;
}

static void pump_events_to_clients(void)
{
    uint64_t eq_head = atomic_load(&g_eq_write);
    uint64_t eq_tail = atomic_load(&g_eq_read);

    /* Nothing new? */
    if (eq_tail >= eq_head) return;

    /* Cap reads per iteration to avoid starving heartbeats */
    if (eq_head - eq_tail > WS_EVENT_QUEUE_SIZE)
        eq_tail = eq_head - WS_EVENT_QUEUE_SIZE;

    pthread_mutex_lock(&g_lock);

    for (uint64_t seq = eq_tail; seq < eq_head; seq++) {
        struct ws_event_entry *e =
            &g_event_queue[seq & WS_EVENT_QUEUE_MASK];

        /* Wait for publish (the observer sets sequence after writing
         * all fields).  If it hasn't published yet, skip — we'll
         * catch it next iteration. */
        if (atomic_load(&e->sequence) != seq + 1) continue;

        const char *type_name = event_type_name(e->type);

        char json[1024];
        size_t jlen = format_event_json(e, json, sizeof(json));
        if (jlen == 0) continue;

        for (int i = 0; i < WS_MAX_CLIENTS; i++) {
            struct ws_client *c = &g_clients[i];
            if (!c->active) continue;

            if (!domain_matches(c->filter, type_name)) continue;

            ssize_t w = ws_write_frame(c->fd, WS_TEXT, json, jlen);
            if (w < 0) {
                /* Write failed — mark client dead */
                close(c->fd);
                c->active = false;
                atomic_fetch_sub(&g_client_count, 1);
            } else {
                c->delivered++;
                c->last_active_us = GetTimeMicros();
                atomic_fetch_add(&g_total_delivered, 1);
            }
        }
    }

    atomic_store(&g_eq_read, eq_head);
    pthread_mutex_unlock(&g_lock);
}

static void send_heartbeats(void)
{
    int64_t now = GetTimeMicros();
    int64_t ping_interval = WS_HEARTBEAT_SEC * 1000000LL;
    int64_t idle_timeout = WS_IDLE_TIMEOUT_SEC * 1000000LL;

    pthread_mutex_lock(&g_lock);
    for (int i = 0; i < WS_MAX_CLIENTS; i++) {
        struct ws_client *c = &g_clients[i];
        if (!c->active) continue;

        /* Idle timeout: disconnect if no activity for too long */
        if (now - c->last_active_us > idle_timeout) {
            ws_write_frame(c->fd, WS_CLOSE, NULL, 0);
            close(c->fd);
            c->active = false;
            atomic_fetch_sub(&g_client_count, 1);
            continue;
        }

        /* Heartbeat ping */
        if (now - c->last_ping_us > ping_interval) {
            ws_write_frame(c->fd, WS_PING, "ping", 4);
            c->last_ping_us = now;
        }
    }
    pthread_mutex_unlock(&g_lock);
}

/* Drain any incoming client frames (pong, close).  We don't
 * parse the frame body — just detect close or error. */
static void drain_client_input(void)
{
    pthread_mutex_lock(&g_lock);
    for (int i = 0; i < WS_MAX_CLIENTS; i++) {
        struct ws_client *c = &g_clients[i];
        if (!c->active) continue;

        struct pollfd pfd = { .fd = c->fd, .events = POLLIN };
        if (poll(&pfd, 1, 0) > 0) {
            if (pfd.revents & (POLLHUP | POLLERR)) {
                close(c->fd);
                c->active = false;
                atomic_fetch_sub(&g_client_count, 1);
                continue;
            }
            if (pfd.revents & POLLIN) {
                /* Read and discard (we don't process client frames
                 * beyond detecting disconnect).  A proper impl would
                 * parse masked frames, but for an event stream the
                 * client only sends pong or close. */
                uint8_t discard[256];
                ssize_t r = read(c->fd, discard, sizeof(discard));
                if (r <= 0) {
                    close(c->fd);
                    c->active = false;
                    atomic_fetch_sub(&g_client_count, 1);
                } else {
                    c->last_active_us = GetTimeMicros();
                }
            }
        }
    }
    pthread_mutex_unlock(&g_lock);
}

static void *pump_thread_fn(void *arg)
{
    (void)arg;
    while (atomic_load(&g_running)) {
        pump_events_to_clients();
        drain_client_input();
        send_heartbeats();
        thread_liveness_beat(&g_ws_pump_liveness,
                             (int64_t)atomic_fetch_add(&g_ws_pump_beat_count, 1) + 1);
        usleep(WS_PUMP_INTERVAL_MS * 1000);
    }
    return NULL;
}

/* ── Public API ──────────────────────────────────────────────── */

bool ws_events_start(void)
{
    bool expected = false;
    if (!atomic_compare_exchange_strong(&g_started, &expected, true))
        return true;  /* already started */

    atomic_store(&g_running, true);
    atomic_store(&g_eq_write, 0);
    atomic_store(&g_eq_read, 0);
    memset(g_clients, 0, sizeof(g_clients));
    atomic_store(&g_client_count, 0);
    atomic_store(&g_total_delivered, 0);

    /* Register observers for ALL event types so clients get everything
     * (domain filter is per-client, not per-observer). */
    for (int t = 0; t < EV_NUM_TYPES; t++)
        event_observe((enum event_type)t, ws_event_observer, NULL);

    if (thread_registry_spawn("zcl_ws_pump", pump_thread_fn, NULL,
                                  &g_pump_thread) != 0) {
        atomic_store(&g_started, false);
        LOG_FAIL("ws", "thread_registry_spawn failed for event pump thread");
    }
    thread_liveness_register(&g_ws_pump_liveness, "zcl_ws_pump", 0, 0);
    return true;
}

void ws_events_stop(void)
{
    if (!atomic_load(&g_started)) return;
    atomic_store(&g_running, false);
    pthread_join(g_pump_thread, NULL);
    thread_liveness_retire(&g_ws_pump_liveness);

    /* Close all client fds.  We don't clear_observers here because
     * that would destructively remove observers registered by other
     * modules (metrics, alerts, etc.).  The per-type observers we
     * installed will simply write to the now-drained queue and the
     * entries will be harmlessly overwritten on next start(). */
    pthread_mutex_lock(&g_lock);
    for (int i = 0; i < WS_MAX_CLIENTS; i++) {
        if (g_clients[i].active) {
            ws_write_frame(g_clients[i].fd, WS_CLOSE, NULL, 0);
            close(g_clients[i].fd);
            g_clients[i].active = false;
        }
    }
    atomic_store(&g_client_count, 0);
    pthread_mutex_unlock(&g_lock);

    atomic_store(&g_started, false);
}

bool ws_events_accept(int fd, const char *domain_filter)
{
    if (atomic_load(&g_client_count) >= WS_MAX_CLIENTS)
        return false;

    /* Set non-blocking so write() in pump thread doesn't stall */
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags >= 0)
        fcntl(fd, F_SETFL, flags | O_NONBLOCK);

    pthread_mutex_lock(&g_lock);
    int slot = -1;
    for (int i = 0; i < WS_MAX_CLIENTS; i++) {
        if (!g_clients[i].active) { slot = i; break; }
    }
    if (slot < 0) {
        pthread_mutex_unlock(&g_lock);
        return false;
    }

    struct ws_client *c = &g_clients[slot];
    memset(c, 0, sizeof(*c));
    c->fd = fd;
    c->active = true;
    c->last_active_us = GetTimeMicros();
    c->last_ping_us = GetTimeMicros();
    if (domain_filter && domain_filter[0])
        snprintf(c->filter, sizeof(c->filter), "%s", domain_filter);

    atomic_fetch_add(&g_client_count, 1);
    pthread_mutex_unlock(&g_lock);
    return true;
}

int ws_events_client_count(void)
{
    return atomic_load(&g_client_count);
}

__attribute__((format(printf, 4, 5)))
static size_t ws_append(char *buf, size_t cap, size_t pos, const char *fmt, ...)
{
    if (pos >= cap) return pos;
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(buf + pos, cap - pos, fmt, ap);
    va_end(ap);
    if (n < 0) return pos;
    if ((size_t)n >= cap - pos) return cap - 1;
    return pos + (size_t)n;
}

size_t ws_events_status_json(char *buf, size_t cap)
{
    if (!buf || cap == 0) return 0;
    int clients = atomic_load(&g_client_count);
    uint64_t delivered = atomic_load(&g_total_delivered);
    bool running = atomic_load(&g_started);

    size_t pos = 0;
    pos = ws_append(buf, cap, pos,
        "{\"running\":%s,\"clients\":%d,\"max_clients\":%d,"
        "\"total_delivered\":%llu}",
        running ? "true" : "false",
        clients, WS_MAX_CLIENTS,
        (unsigned long long)delivered);
    if (pos < cap) buf[pos] = '\0';
    return pos;
}

/* ── WebSocket handshake ─────────────────────────────────────── */

/* RFC 6455 §4.2.2: Sec-WebSocket-Accept = Base64(SHA1(key + GUID)) */

bool ws_events_upgrade(int fd, const char *path,
                        const char *ws_key, const char *query)
{
    if (!ws_key || !*ws_key) LOG_FAIL("ws", "upgrade request missing Sec-WebSocket-Key");

    /* Ensure the pump thread is running */
    if (!ws_events_start()) LOG_FAIL("ws", "failed to start event pump for upgrade");

    /* Check client capacity before doing the handshake */
    if (atomic_load(&g_client_count) >= WS_MAX_CLIENTS)
        LOG_FAIL("ws", "upgrade rejected: max clients (%d) reached", WS_MAX_CLIENTS);

    /* Compute Sec-WebSocket-Accept */
    char concat[256];
    int clen = snprintf(concat, sizeof(concat), "%s%s", ws_key,
                        "258EAFA5-E914-47DA-95CA-C5AB0DC85B11");
    if (clen < 0 || (size_t)clen >= sizeof(concat))
        LOG_FAIL("ws", "Sec-WebSocket-Key too long for accept computation");

    struct sha1_ctx sha;
    sha1_init(&sha);
    sha1_write(&sha, (const unsigned char *)concat, (size_t)clen);
    unsigned char hash[20];
    sha1_finalize(&sha, hash);

    char accept_b64[64];
    EncodeBase64(hash, 20, accept_b64, sizeof(accept_b64));

    /* Parse domain filter from query string: ?domain=chain,peer */
    char domain[WS_FILTER_LEN] = {0};
    if (query) {
        const char *d = strstr(query, "domain=");
        if (d) {
            d += 7;
            size_t i = 0;
            while (*d && *d != '&' && i + 1 < sizeof(domain))
                domain[i++] = *d++;
            domain[i] = '\0';
        }
    }

    /* Send 101 Switching Protocols */
    char resp[512];
    int rlen = snprintf(resp, sizeof(resp),
        "HTTP/1.1 101 Switching Protocols\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        "Sec-WebSocket-Accept: %s\r\n"
        "\r\n",
        accept_b64);
    if (rlen < 0) LOG_FAIL("ws", "snprintf failed building 101 response");
    ssize_t w = write(fd, resp, (size_t)rlen);
    if (w < 0) LOG_FAIL("ws", "write failed sending 101 response: fd=%d", fd);

    /* Hand the fd to the event pump */
    (void)path;  /* reserved for future path-based dispatch */
    return ws_events_accept(fd, domain);
}
