/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Deadline-aware plain-text and TLS I/O for the RPC HTTP server. */
#include "httpserver_transport.h"
#include <limits.h>
#include <stdio.h>

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

void rpc_conn_close(struct rpc_conn *conn)
{
    if (conn->ssl) {
        SSL_shutdown(conn->ssl);
        SSL_free(conn->ssl);
        conn->ssl = NULL;
    }
    if (conn->fd != PLATFORM_SOCKET_INVALID) {
        platform_socket_close(conn->fd);
        conn->fd = PLATFORM_SOCKET_INVALID;
    }
}

void rpc_conn_discard(struct rpc_conn *conn)
{
    if (conn->ssl) {
        SSL_free(conn->ssl);
        conn->ssl = NULL;
    }
    if (conn->fd != PLATFORM_SOCKET_INVALID) {
        platform_socket_close(conn->fd);
        conn->fd = PLATFORM_SOCKET_INVALID;
    }
}

void rpc_conn_set_deadlines(platform_socket_t fd)
{
    (void)platform_socket_set_receive_timeout(fd, 5000);
    (void)platform_socket_set_send_timeout(fd, 5000);
}

bool rpc_conn_peer_gone(const struct rpc_conn *conn)
{
    if (conn->fd == PLATFORM_SOCKET_INVALID)
        return true;

    platform_socket_pollfd pfd = { .fd = conn->fd, .events = POLLIN,
                                   .revents = 0 };
    int result = platform_socket_poll(&pfd, 1, 0);
    if (result < 0)
        return !platform_socket_error_interrupted(
            platform_socket_last_error());
    if (result == 0)
        return false;
    if (pfd.revents & (POLLHUP | POLLERR | POLLNVAL))
        return true;
    if (pfd.revents & POLLIN) {
        char probe;
#if defined(_WIN32)
        int read_result = recv(conn->fd, &probe, 1, MSG_PEEK);
#else
        int read_result = (int)recv(conn->fd, &probe, 1, MSG_PEEK);
#endif
        if (read_result == 0)
            return true;
    }
    return false;
}

void rpc_conn_send_response_with_type(const struct rpc_conn *conn,
                                      int status_code,
                                      const char *status_text,
                                      const char *content_type,
                                      const char *body, size_t body_len)
{
    char header[512];
    int header_len = snprintf(header, sizeof(header),
        "HTTP/1.1 %d %s\r\n"
        "Content-Type: %s\r\n"
        "Content-Length: %zu\r\n"
        "Connection: close\r\n"
        "\r\n",
        status_code, status_text, content_type, body_len);
    if (!conn_write_all(conn, header, (size_t)header_len))
        return;
    if (body_len > 0)
        (void)conn_write_all(conn, body, body_len);
}

void rpc_conn_send_response(const struct rpc_conn *conn, int status_code,
                            const char *status_text, const char *body,
                            size_t body_len)
{
    rpc_conn_send_response_with_type(conn, status_code, status_text,
                                     "engine/application/json", body,
                                     body_len);
}
