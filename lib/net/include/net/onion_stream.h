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

/* Open a raw onion stream to svc (must satisfy net_addr_is_tor) and bridge
 * it to a freshly-connected socket fd, returned in *sock_out. Blocks up to
 * connect_timeout_ms waiting for the circuit to reach CONNECTED. The fd is
 * an ordinary socket: poll/recv/send/shutdown/close all work; the peer
 * closing the stream reads as EOF on the fd, and closing the fd tears the
 * stream down.
 *
 * Fails CLOSED with a named log line — never a clearnet fallback:
 *   - stub build (dynhost_stream_* not linked);
 *   - Tor not running / not bootstrapped;
 *   - invalid arguments, timeout, or stream error. */
bool onion_stream_connect(const struct net_service *svc,
                          zcl_socket_t *sock_out,
                          int connect_timeout_ms);

#endif /* ZCL_NET_ONION_STREAM_H */
