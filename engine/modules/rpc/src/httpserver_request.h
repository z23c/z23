/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Private request-dispatch boundary for the RPC HTTP server. */
#ifndef ZCL_RPC_HTTPSERVER_REQUEST_H
#define ZCL_RPC_HTTPSERVER_REQUEST_H

#include "httpserver_transport.h"
#include "rpc/http_middleware.h"
#include "rpc/rpc_timeout.h"
#include "rpc/server.h"
#include <stdbool.h>

struct rpc_http_request_context {
    const struct rpc_table *table;
    struct rpc_http_middleware *middleware;
    struct rpc_timeout_mgr *timeout;
    bool metrics_http_enable;
};

void rpc_http_request_handle(
    struct rpc_conn conn,
    const struct rpc_http_request_context *context);

#endif
