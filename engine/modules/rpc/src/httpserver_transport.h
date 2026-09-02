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
void rpc_conn_close(struct rpc_conn *conn);
void rpc_conn_discard(struct rpc_conn *conn);
void rpc_conn_set_deadlines(platform_socket_t fd);
bool rpc_conn_peer_gone(const struct rpc_conn *conn);
void rpc_conn_send_response_with_type(const struct rpc_conn *conn,
                                      int status_code,
                                      const char *status_text,
                                      const char *content_type,
                                      const char *body, size_t body_len);
void rpc_conn_send_response(const struct rpc_conn *conn, int status_code,
                            const char *status_text, const char *body,
                            size_t body_len);

#endif
