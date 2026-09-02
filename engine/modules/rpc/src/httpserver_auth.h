/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Private credential owner for the RPC HTTP server. */
#ifndef ZCL_RPC_HTTPSERVER_AUTH_H
#define ZCL_RPC_HTTPSERVER_AUTH_H

#include <stdbool.h>
#include <stdint.h>

void rpc_http_auth_configure(const char *rpc_user, const char *rpc_password,
                             const char *datadir, uint16_t port);
bool rpc_http_auth_check(const char *auth_header);
void rpc_http_auth_start_rotation(void);
void rpc_http_auth_stop_rotation(void);
void rpc_http_auth_stop(void);

#endif
