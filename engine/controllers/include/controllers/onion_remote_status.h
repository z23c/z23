/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * core.network.onion.remote-status: the running node fetches one other node's
 * public GET /status over its embedded Tor and returns a typed, allowlisted
 * summary beside its own tip. Read-only; the path is a constant, the body is
 * capped, and the raw body is never echoed. See
 * controllers/native_handler_body.h for the body contract. */

#ifndef ZCL_CONTROLLERS_ONION_REMOTE_STATUS_H
#define ZCL_CONTROLLERS_ONION_REMOTE_STATUS_H

#include "controllers/native_handler_body.h"
#include "net/tor_integration.h"

#ifdef __cplusplus
extern "C" {
#endif

#define ONION_REMOTE_STATUS_BODY_MAX 4096
#define ONION_REMOTE_STATUS_TIMEOUT_MIN 5
#define ONION_REMOTE_STATUS_TIMEOUT_MAX 60
#define ONION_REMOTE_STATUS_TIMEOUT_DEFAULT 30

/* Bridge body (runs in the CLI process): validates args {"onion":
 * "<56 base32>.onion", "timeout_secs": 5..60}, then asks the node, which owns
 * the embedded Tor and the chain, to run the fetch through the onionremotestatus
 * RPC (params [onion, timeout_secs]) and maps its refusal back to a typed one.
 * On failure err->message begins with a typed code (BAD_ONION, BAD_TIMEOUT,
 * BUSY, TOR_UNAVAILABLE, UNREACHABLE, RATE_LIMITED, PUZZLE_REQUIRED, HTTP_STATUS,
 * BODY_TOO_LARGE, BAD_JSON, BAD_HEIGHT) followed by the next action. */
char *zcl_native_onion_remote_status_body(const struct json_value *args,
                                          struct zcl_native_body_err *err);

/* Shared argument check for the CLI body and the node RPC: onion must be a
 * valid v3 host string, timeout (may be NULL or null) an integer 5..60.
 * On success *timeout_out holds the seconds to use; on failure err carries
 * BAD_ONION or BAD_TIMEOUT. */
bool onion_remote_status_check_args(const struct json_value *onion,
                                    const struct json_value *timeout,
                                    int *timeout_out,
                                    struct zcl_native_body_err *err);

/* The fetch-and-summarize core, run inside the node. local_height < 0 means
 * this node's own tip was unavailable (reported as null). timeout_secs is not
 * range-checked here; the callers own the 5..60 refusal. Returns a heap JSON
 * document or NULL. */
char *onion_remote_status_run(const char *onion, int timeout_secs,
                              int64_t local_height,
                              struct zcl_native_body_err *err);

#ifdef ZCL_TESTING
/* Test seam: route the fetch through an injected dispatcher and fix the Tor
 * readiness answer. Clear with (NULL, false) semantics via _clear. */
void onion_remote_status_set_test_hooks(tor_fetch_dispatch_fn dispatch,
                                        bool tor_ready);
void onion_remote_status_clear_test_hooks(void);
#endif

#ifdef __cplusplus
}
#endif

#endif /* ZCL_CONTROLLERS_ONION_REMOTE_STATUS_H */
