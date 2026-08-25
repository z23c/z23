/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Thin loopback RPC client used by the native command handlers and the
 * tools/command CLI.  Talks to the local zclassic23 node over HTTP on
 * 127.0.0.1 using the cookie file in the data directory for auth. This is
 * the only public interface that knows how to speak to the node this way. */

#ifndef ZCL_CONTROLLERS_RPC_CLIENT_H
#define ZCL_CONTROLLERS_RPC_CLIENT_H

#include <stdbool.h>

/* Call once at startup (from the node/CLI entry point). */
void node_rpc_client_init(const char *datadir, int rpc_port);

/* Return the datadir passed to node_rpc_client_init (empty string if
 * not yet initialized). The pointer is to a static buffer owned by
 * the client; callers must not free or modify it. */
const char *node_rpc_client_datadir(void);

/* Invoke a JSON-RPC method on the local node.
 * params_json may be NULL (sends []) or a JSON array string.
 * Returns a malloc'd JSON string (either the "result" field or an
 * error stub).  Never returns NULL in practice — on connection
 * failure, returns a minimal error object instead.  Caller frees.
 *
 * The client uses the out-of-process HTTP path and returns the bare JSON-RPC
 * result value, or the error object on failure. */
char *node_rpc_call(const char *method, const char *params_json);

/* Same as node_rpc_call, but with an explicit connect/total deadline (in
 * milliseconds) instead of the generic env-configurable defaults
 * (ZCL_RPC_CONNECT_MS / ZCL_RPC_DEADLINE_MS, 2s/10s). For front doors that
 * must always answer fast (e.g. core.status.brief's ~250ms budget) rather
 * than tolerate a wedged/busy node for up to 10s. Both values are clamped
 * to the same sane floor/ceiling as the env defaults. Honors the
 * ZCL_TESTING hook exactly like node_rpc_call. */
char *node_rpc_call_deadline(const char *method, const char *params_json,
                             long connect_ms, long total_ms);

/* Endpoint-explicit variant for concurrent multi-wallet readers. Unlike the
 * legacy init+call pair, this does not read or mutate process-global endpoint
 * state, so independent dev/prod calls cannot cross-wire cookies or ports. */
char *node_rpc_call_at_deadline(const char *datadir, int rpc_port,
                                const char *method, const char *params_json,
                                long connect_ms, long total_ms);

/* Pure socket-level liveness oracle: true iff something accepts TCP
 * connections on 127.0.0.1:rpc_port within connect_ms. No cookie, no
 * JSON-RPC, no error bodies. Needed because every node_rpc_call* variant
 * returns a NON-NULL self-describing error body when the connect is refused
 * or times out — a caller that treats any non-NULL reply as "the node
 * answered" inverts the client's own convention and reads a stopped node as
 * running. When the question is "is a node listening at all", ask this,
 * not the call path. rpc_port outside 1..65535 returns false. */
bool node_rpc_port_listening(int rpc_port, long connect_ms);

/* The default out-of-process HTTP backend (socket + JSON-RPC POST), using
 * the env-configurable defaults. */
char *node_rpc_call_http(const char *method, const char *params_json);

/* Same HTTP backend as node_rpc_call_http, with an explicit connect/total
 * deadline. See node_rpc_call_deadline. */
char *node_rpc_call_http_deadline(const char *method, const char *params_json,
                                  long connect_ms, long total_ms);

#ifdef ZCL_TESTING
typedef char *(*node_rpc_test_fn)(const char *method,
                                  const char *params_json);
void node_rpc_client_set_test_hook(node_rpc_test_fn fn);
#endif

#endif
