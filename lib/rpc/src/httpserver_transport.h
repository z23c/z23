/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Private plain-text and TLS transport boundary for the RPC server. */
#ifndef ZCL_RPC_HTTPSERVER_TRANSPORT_H
#define ZCL_RPC_HTTPSERVER_TRANSPORT_H

#include "platform/socket_compat.h"
#include <openssl/ssl.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct rpc_conn {
    platform_socket_t fd;
    SSL *ssl;
    int64_t admitted_us;
};

bool conn_write_all(const struct rpc_conn *conn, const void *data, size_t size);
bool read_line(const struct rpc_conn *conn, char *line, size_t capacity);
bool read_exact(const struct rpc_conn *conn, char *data, size_t size);

#endif
