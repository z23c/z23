/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * WebSocket event stream — push EV_* events to connected clients
 * as JSON text frames over a persistent WebSocket connection at
 * GET /events.
 *
 * Architecture:
 *   - Client connects to /events with standard WebSocket upgrade
 *   - Optional query param ?domain=chain,peer to filter events
 *   - Server pumps matching events as JSON text frames:
 *     {"ts":1234567890,"type":"chain.tip_updated","peer_id":0,"payload":"..."}
 *   - Per-client ring tracks position in global event_log
 *   - Background thread polls event_log + writes frames at ~100ms
 *   - Heartbeat ping every 30s, disconnect after 90s idle
 *   - Max 100 concurrent subscribers (101st gets 503)
 *
 * Threading model:
 *   The httpserver worker performs the WebSocket handshake, then
 *   hands the fd to ws_events_accept(). A single background pump
 *   thread iterates all clients, reads new events from the global
 *   ring buffer, and writes text frames. No per-client thread.
 */

#ifndef ZCL_WS_EVENTS_H
#define ZCL_WS_EVENTS_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "platform/socket_compat.h"

#ifdef __cplusplus
extern "C" {
#endif

#define WS_MAX_CLIENTS       100
#define WS_RING_PER_CLIENT   1000  /* max queued events before overflow */
#define WS_HEARTBEAT_SEC     30
#define WS_IDLE_TIMEOUT_SEC  90
#define WS_PUMP_INTERVAL_MS  100

/* Start the background pump thread.  Idempotent. */
bool ws_events_start(void);

/* Stop the pump thread and close all client connections. */
void ws_events_stop(void);

/* Accept a new WebSocket client.  The httpserver has already
 * completed the RFC 6455 handshake; this function takes ownership
 * of the fd (caller must NOT close it).
 *
 * `domain_filter` is a comma-separated list of event type prefixes
 * (e.g. "chain,peer") or NULL/"" for all events.  Copied internally.
 *
 * Returns true if accepted, false if the client table is full
 * (caller should send 503 and close fd). */
bool ws_events_accept(platform_socket_t fd, const char *domain_filter);

/* Current number of connected clients. */
int ws_events_client_count(void);

/* Render a JSON status snapshot.
 * Returns bytes written (excluding NUL). */
size_t ws_events_status_json(char *buf, size_t cap);

/* ── WebSocket handshake helper ──────────────────────────────
 * Called by httpserver.c when it detects a GET /events request
 * with Upgrade: websocket headers.  Performs the RFC 6455
 * handshake on the raw fd, sends 101 Switching Protocols, and
 * then calls ws_events_accept() with the parsed domain filter.
 *
 * Returns true if the upgrade succeeded (fd is now owned by
 * ws_events — caller must NOT close it).  Returns false on
 * handshake failure (caller closes fd normally). */
bool ws_events_upgrade(platform_socket_t fd, const char *path,
                        const char *ws_key, const char *query);

#ifdef __cplusplus
}
#endif

#endif /* ZCL_WS_EVENTS_H */
