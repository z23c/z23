/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: private classifier for the RPC reserved fast lane, which serves
 * only an allowlist of lock-free status calls. */
#ifndef ZCL_RPC_HTTPSERVER_FASTLANE_H
#define ZCL_RPC_HTTPSERVER_FASTLANE_H

#include "httpserver_transport.h"
#include "json/json.h"
#include <stdbool.h>

/* True when (method, params) is on the lock-free allowlist. */
bool rpc_http_fastlane_allows(const char *method,
                              const struct json_value *params);

/* True when the connection's already-received bytes hold one complete
 * plain-text POST whose method is allowlisted. Never blocks and never
 * consumes bytes; TLS and incomplete requests report false. */
bool rpc_http_fastlane_conn_matches(const struct rpc_conn *conn);

#endif
