/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Thin loopback RPC client used by the native command handlers and the
 * tools/command CLI.  Talks to the local z23 node over HTTP on
 * 127.0.0.1 using the cookie file in the data directory for auth. This is
 * the only public interface that knows how to speak to the node this way. */

#ifndef ZCL_CONTROLLERS_RPC_CLIENT_H
#define ZCL_CONTROLLERS_RPC_CLIENT_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Call once at startup (from the node/CLI entry point). */
void node_rpc_client_init(const char *datadir, int rpc_port);

/* Binary read of one filesystem path through the same CRT open the cookie
 * loader uses (plain path, then one Windows `\\?\` retry). `*n_out` is the
 * byte count actually read, which may include 0x00 and 0x0A. Returns false
 * when the path cannot be opened. Does not append a NUL. */
bool node_rpc_client_read_file(const char *path, void *buf, size_t cap,
                               size_t *n_out);

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

/* JSON-RPC error code of the transport body returned when an absolute
 * deadline expired before any request byte was sent. Distinct from the
 * generic -32603 so an optional observer can tell "never asked" from
 * "asked, no answer". */
#define NODE_RPC_DEADLINE_EXPIRED (-32098)

/* Absolute-deadline variants. `deadline_ms` is an absolute reading of
 * platform_time_monotonic_ms(); ONE deadline bounds the cookie read, setup,
 * connect, send and receive. A deadline at or before "now" (including zero,
 * negative and INT64_MIN) issues no request and returns a NODE_RPC_DEADLINE_
 * EXPIRED body. It is re-checked after the cookie read, before connect and
 * before the first byte is sent. The connect wait is min(deadline, now +
 * connect_ms), recomputed after every interrupted or early wake. The blocking
 * cookie read itself cannot be preempted: a slow cookie costs its own time but
 * is never followed by a request once the deadline has passed. The
 * environment defaults are not consulted. Honors the ZCL_TESTING hook. */
char *node_rpc_call_until(const char *method, const char *params_json,
                          long connect_ms, int64_t deadline_ms);
char *node_rpc_call_at_until(const char *datadir, int rpc_port,
                             const char *method, const char *params_json,
                             long connect_ms, int64_t deadline_ms);

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

/* Test-only views of the private deadline arithmetic (saturating add; wait
 * left clamped to 0..INT32_MAX with 0 = expired; min(deadline, now + phase))
 * and of the endpoint port, so tests can drive a fake clock and restore the
 * process endpoint. */
int64_t node_rpc_test_deadline_after(int64_t now_ms, int64_t delta_ms);
int node_rpc_test_deadline_remaining_ms(int64_t now_ms, int64_t deadline_ms);
int64_t node_rpc_test_phase_deadline_ms(int64_t now_ms, int64_t deadline_ms,
                                        int64_t phase_ms);
int node_rpc_test_client_port(void);

/* Test-only script for the deadline loops: a fake clock plus scripted poll
 * results driving the production connect, send and receive code. A step is
 * 'i' (EINTR), 'z' (zero-timeout wake), 'r' (ready) or 'q' (ready once bytes are
 * really queued) and advances the clock by adv_ms; the first three writable and
 * readable waits use their steps, later ones are real, and every socket call is
 * real. `alloc_adv_ms` advances the clock when the receive buffer grows (a slow
 * allocation); `grown_at` records the readable waits made by then. `seq` values (0-terminated) are
 * returned by the first now() reads before `now` is used. `pending` makes
 * connect() report EINPROGRESS (the connect itself still ran); otherwise it
 * reports completion. Outputs: wait-call counts and the first eight wait
 * arguments the loops computed. NULL restores the real clock and polls. */
struct node_rpc_test_step { char kind; int adv_ms; };
struct node_rpc_test_script {
    int64_t now, seq[6];
    bool pending;
    struct node_rpc_test_step w[3], r[3];
    int alloc_adv_ms, grown_at, iseq, nw, nr, ww[8], wr[8];
};
void node_rpc_test_set_script(struct node_rpc_test_script *script);
/* Force the connect report to pending and replace only its writable wait.
 * The clock and deadline loop remain real; NULL restores ordinary transport. */
typedef int (*node_rpc_test_connect_wait_fn)(int wait_ms, void *ctx);
void node_rpc_test_set_connect_wait(node_rpc_test_connect_wait_fn wait, void *ctx);
#endif

#endif
