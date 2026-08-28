/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Deadline-aware plain-text and TLS I/O for the RPC HTTP server. */
#include "httpserver_transport.h"
#include <limits.h>

static int conn_read(const struct rpc_conn *conn, void *data, size_t size)
{
    if (conn->ssl)
        return SSL_read(conn->ssl, data,
                        size > INT32_MAX ? INT32_MAX : (int)size);
    return platform_socket_receive(conn->fd, data, size);
}

static int conn_write(const struct rpc_conn *conn, const void *data,
                      size_t size)
{
    if (conn->ssl)
        return SSL_write(conn->ssl, data,
                         size > INT32_MAX ? INT32_MAX : (int)size);
    return platform_socket_send(conn->fd, data, size);
}

bool conn_write_all(const struct rpc_conn *conn, const void *data, size_t size)
{
    const char *cursor = data;
    size_t sent = 0;
    while (sent < size) {
        int result = conn_write(conn, cursor + sent, size - sent);
        if (result > 0) {
            sent += (size_t)result;
            continue;
        }
        if (result < 0 && platform_socket_error_interrupted(
                              platform_socket_last_error()))
            continue;
        return false;
    }
    return true;
}

bool read_line(const struct rpc_conn *conn, char *line, size_t capacity)
{
    size_t length = 0;
    while (length < capacity - 1) {
        char byte;
        int result = conn_read(conn, &byte, 1);
        if (result <= 0)
            return false;
        if (byte == '\n') {
            if (length > 0 && line[length - 1] == '\r')
                length--;
            line[length] = '\0';
            return true;
        }
        line[length++] = byte;
    }
    line[length] = '\0';
    return true;
}

bool read_exact(const struct rpc_conn *conn, char *data, size_t size)
{
    size_t received = 0;
    while (received < size) {
        int result = conn_read(conn, data + received, size - received);
        if (result <= 0)
            return false;
        received += (size_t)result;
    }
    return true;
}
