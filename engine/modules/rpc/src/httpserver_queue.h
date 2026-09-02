/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Private accepted-connection queue for the RPC HTTP server. */
#ifndef ZCL_RPC_HTTPSERVER_QUEUE_H
#define ZCL_RPC_HTTPSERVER_QUEUE_H

#include "httpserver_transport.h"
#include <stdatomic.h>

void rpc_http_queue_start(int wait_ms);
bool rpc_http_queue_admit(struct rpc_conn conn);
struct rpc_conn rpc_http_queue_take_wait(const _Atomic bool *running);
void rpc_http_queue_wake(void);
void rpc_http_queue_drain(void);

#endif
