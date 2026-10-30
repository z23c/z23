/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#ifndef ZAPP_RPC_H
#define ZAPP_RPC_H
#include <stdbool.h>
#include <stddef.h>

enum zapp_rpc_result {
    ZAPP_RPC_OK,
    /* No port or cookie file, or nothing accepts the connection: the node is not serving RPC. */
    ZAPP_RPC_UNREACHABLE,
    /* The node was reached but the exchange failed or the reply is not usable. */
    ZAPP_RPC_FAILED
};

/* One JSON-RPC call to the node serving <datadir>, over loopback with the datadir's cookie. The
 * port is read from <datadir>/.rpcport on every call, so a restarted node is found. On success
 * out holds the NUL-terminated JSON-RPC reply body. On failure why holds a one-line reason. */
enum zapp_rpc_result zapp_rpc_call(const char *datadir, const char *method, const char *params,
                                   int timeout_ms, char *out, size_t cap, char *why, size_t why_cap);
#endif
