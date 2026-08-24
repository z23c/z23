/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Outbound P2P connections to .onion peers over the embedded Tor fork's raw
 * bidirectional stream API (dynhost_stream_*, vendor/tor
 * src/feature/dynhost/dynhost_stream.h). No SOCKS anywhere: the stream is
 * opened by direct C call into the in-process Tor, and a socketpair bridge
 * presents it to connman as an ordinary connected fd, so the reactor, the
 * version handshake, and every message path above the socket are unchanged.
 *
 * Scope discipline: onion endpoints are operator-directed (addnode) only.
 * They are NEVER gossiped, so no addr wire format changes exist or belong
 * here. See docs/work/NAT_AND_ONION_TRANSPORT.md.
 *
 * Threading contract (from the fork header):
 *  - dynhost_stream_open/write/close are callable from any thread;
 *  - read/event callbacks fire ONLY on Tor's event-loop thread;
 *  - exactly one terminal event (CLOSED or TIMEOUT) fires per stream, and
 *    no callbacks fire after it;
 *  - the handle is freed ONLY by dynhost_stream_close, called exactly once.
 *
 * The bridge context is therefore freed ONLY by the pump thread, and only
 * AFTER the terminal event has been observed — that is the point at which
 * the fork guarantees no callback can still be executing or pending, so no
 * Tor-thread access to the context can race the free. */

#ifndef ZCL_NET_ONION_STREAM_H
#define ZCL_NET_ONION_STREAM_H

#include "net/netbase.h"

/* Whole-lifetime deadline handed to dynhost_stream_open for a P2P stream.
 * The fork's timeout covers the stream's ENTIRE life, not just connect, so
 * it must be generous for long-lived peers (30 days). The CONNECT-phase
 * budget is the separate timeout_ms argument to onion_stream_connect. */
#define ONION_STREAM_LIFETIME_SECS (30 * 24 * 3600)

/* Connect-phase budget: circuit builds take 10-60s on a cold Tor, far
 * beyond the clearnet dialer's shared 5s window. Onion candidates get their
 * own budget instead of losing the batch race and churning addrman
 * backoff. */
#define ONION_STREAM_CONNECT_TIMEOUT_MS 120000

/* A cold circuit can occasionally consume its whole connect budget without
 * reaching CONNECTED.  At the normal 120 s ceiling, spend the same total
 * budget across two fresh streams so one poisoned circuit cannot monopolize
 * the only dial scheduler for the entire attempt.  Short diagnostic budgets
 * remain a single attempt instead of being split into unusably small slices. */
#define ONION_STREAM_RETRY_MIN_TOTAL_MS 120000

/* Open a raw onion stream to svc (must satisfy net_addr_is_tor) and bridge
 * it to a freshly-connected socket fd, returned in *sock_out. The circuit
 * connect-phase waits share connect_timeout_ms; at the normal ceiling the
 * dial may replace one failed circuit once without extending that wait
 * budget. Bounded terminal-callback teardown remains outside that budget,
 * as it was for the former single attempt. The fd is an ordinary socket:
 * poll/recv/send/shutdown/close all work; the peer closing the stream reads
 * as EOF on the fd, and closing the fd tears the stream down.
 *
 * Fails CLOSED with a named log line — never a clearnet fallback:
 *   - stub build (dynhost_stream_* not linked);
 *   - Tor not running / not bootstrapped;
 *   - invalid arguments, timeout, or stream error. */
bool onion_stream_connect(const struct net_service *svc,
                          zcl_socket_t *sock_out,
                          int connect_timeout_ms);

/* ── Raw-stream backend ──────────────────────────────────────────────────
 * The bridge talks to the circuit through this three-call interface, not
 * to dynhost_stream_* directly. Production binds the embedded Tor fork's
 * weak symbols (onion_stream.c); a test binds a loopback double, so the
 * socketpair bridge itself is exercised without a live Tor network. The
 * handle is opaque here — only the backend that minted it may touch it. */
struct onion_stream_raw;

/* Mirrors the fork's event codes (dynhost_stream.h) one-for-one. */
#define ONION_STREAM_EVENT_OPEN      0
#define ONION_STREAM_EVENT_CONNECTED 1
#define ONION_STREAM_EVENT_CLOSED    2
#define ONION_STREAM_EVENT_TIMEOUT   3

typedef void (*onion_stream_read_fn)(struct onion_stream_raw *stream,
                                     const uint8_t *data, size_t len,
                                     void *ctx);
typedef void (*onion_stream_event_fn)(struct onion_stream_raw *stream,
                                      int event, void *ctx);

struct onion_stream_backend {
    struct onion_stream_raw *(*open)(const char *onion, uint16_t port,
                                     onion_stream_read_fn read_cb,
                                     onion_stream_event_fn event_cb,
                                     void *ctx, int lifetime_secs);
    int  (*write)(struct onion_stream_raw *stream, const uint8_t *data,
                  size_t len);
    void (*close)(struct onion_stream_raw *stream);
};

/* ── Stage ledger ────────────────────────────────────────────────────────
 * docs/work/ONION_DIAL_GAP.md requires every stage of the loop to be named
 * by a log line OR a counter. These are the stages this file owns — from
 * "a dial was issued" through "the peer answered on the bridge" — counted
 * monotonically since process start so an acceptance check can assert on a
 * number instead of grepping a log that may have rotated. */
struct onion_stream_stages {
    uint64_t dial_started;       /* onion_stream_connect entered */
    uint64_t stream_queued;      /* backend accepted the open (INTRODUCE1 next) */
    uint64_t circuit_ready;      /* CONNECTED: rendezvous done, bytes may flow */
    uint64_t bridge_up;          /* fd handed to the P2P layer */
    uint64_t open_refused;       /* backend refused to queue the open */
    uint64_t circuit_timeout;    /* connect budget spent, no circuit */
    uint64_t circuit_torn_down;  /* terminal event before the bridge went up */
    uint64_t bridge_closed;      /* pump teardown (any reason) */
    uint64_t bytes_to_peer;      /* app → Tor, accepted by the backend */
    uint64_t bytes_from_peer;    /* Tor → app, handed to the socketpair */
    uint64_t peers_answered;     /* bridges that saw a first inbound byte */
};
void onion_stream_get_stages(struct onion_stream_stages *out);

/* Bounded per-dial attribution.  The process-wide counters above are cheap
 * health totals; these records answer which exact onion endpoint advanced or
 * stalled.  A fixed ring is sufficient because connman permits at most three
 * simultaneous outbound onion peers.  New completed dials replace the oldest
 * completed record, while active records are never reused. */
#define ONION_STREAM_RECENT_DIALS_MAX 16
struct onion_stream_dial_snapshot {
    char target[NET_SERVICE_STR_MAX + 1];
    uint64_t generation;
    bool active;
    int64_t started_ms;
    int64_t ended_ms;
    struct onion_stream_stages stages;
    struct {
        int64_t connected;
        int64_t version_sent;
        int64_t version_received;
        int64_t verack_received;
        int64_t handshake_complete;
        int64_t pre_handshake_disconnects;
    } p2p_baseline;
};

/* Returns newest first, up to cap records. */
size_t onion_stream_get_recent_dials(struct onion_stream_dial_snapshot *out,
                                     size_t cap);

/* Last operator/dialer onion attempt. Isolated probes and onionstatus
 * read this instead of grepping node.log for "Connecting to onion addnode".
 * result is one of: none, queued, tor_not_running, dynhost_not_ready,
 * stub_build, not_tor, dial_deferred, dial_started, stream_queued,
 * open_refused, circuit_timeout, circuit_torn_down, circuit_ready,
 * bridge_up. */
struct onion_last_dial {
    char target[96];
    int64_t attempted_unix;
    char result[32];
};
void onion_stream_note_last_dial(const char *target, const char *result);
void onion_stream_get_last_dial(struct onion_last_dial *out);

#ifdef ZCL_TESTING
size_t onion_stream_connect_plan_for_test(int connect_timeout_ms,
                                          int budgets[2]);

/* Build the bridge over an injected backend, skipping the Tor-runtime
 * gates onion_stream_connect() enforces. Same socket contract as the
 * production path: *sock_out is a connected, non-blocking stream fd the
 * caller owns. */
bool onion_stream_connect_backend_for_test(
    const struct net_service *svc, zcl_socket_t *sock_out,
    int connect_timeout_ms, const struct onion_stream_backend *backend);

void onion_stream_reset_stages_for_test(void);
#endif

#endif /* ZCL_NET_ONION_STREAM_H */
