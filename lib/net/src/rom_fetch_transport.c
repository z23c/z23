/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Bounded socket transport for the ROM artifact fetch client. */
#include "rom_fetch_transport.h"
#include "util/log_macros.h"
#include <errno.h>
#include <stdio.h>
#include <string.h>

#define RF_SUBSYS "rom_fetch"
#define RF_CONNECT_TIMEOUT_MS 10000
#define RF_IO_TIMEOUT_MS 120000

void rf_session_close(struct fs_session *session, platform_socket_t fd)
{
    fs_session_cleanup(session);
    platform_socket_close(fd);
}

bool rf_recv_exact(platform_socket_t fd, uint8_t *buf, size_t size)
{
    size_t received = 0;
    while (received < size) {
        int result = platform_socket_receive(fd, buf + received,
                                             size - received);
        if (result < 0) {
            if (platform_socket_error_interrupted(
                    platform_socket_last_error()))
                continue;
            return false;
        }
        if (result == 0)
            return false;
        received += (size_t)result;
    }
    return true;
}

platform_socket_t rf_connect(const char *peer_addr, uint16_t port)
{
    char port_text[8];
    snprintf(port_text, sizeof(port_text), "%u", (unsigned)port);

    struct addrinfo hints = {0};
    struct addrinfo *addresses = NULL;
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(peer_addr, port_text, &hints, &addresses) != 0 ||
        !addresses)
        LOG_ERR(RF_SUBSYS, "chunk: resolve failed for %s", peer_addr);

    platform_socket_t fd = platform_socket_open(
        addresses->ai_family, addresses->ai_socktype, addresses->ai_protocol,
        true, true);
    if (fd == PLATFORM_SOCKET_INVALID) {
        freeaddrinfo(addresses);
        LOG_ERR(RF_SUBSYS, "chunk: socket() failed: %s", strerror(errno));
    }

    int result = platform_socket_connect(fd, addresses->ai_addr,
                                         addresses->ai_addrlen);
    int connect_error = result == 0 ? 0 : platform_socket_last_error();
    if (result != 0 && platform_socket_error_in_progress(connect_error)) {
        result = platform_socket_wait_writable(fd, RF_CONNECT_TIMEOUT_MS);
        int pending_error = 0;
        if (result > 0)
            (void)platform_socket_pending_error(fd, &pending_error);
        if (result <= 0 || pending_error != 0) {
            platform_socket_close(fd);
            freeaddrinfo(addresses);
            LOG_ERR(RF_SUBSYS, "chunk: connect to %s:%u failed/timed out",
                    peer_addr, (unsigned)port);
        }
    } else if (result != 0) {
        platform_socket_close(fd);
        freeaddrinfo(addresses);
        LOG_ERR(RF_SUBSYS, "chunk: connect to %s:%u failed: %s",
                peer_addr, (unsigned)port, strerror(errno));
    }
    freeaddrinfo(addresses);

    if (!platform_socket_set_nonblocking(fd, false)) {
        platform_socket_close(fd);
        LOG_ERR(RF_SUBSYS, "chunk: restore blocking socket failed");
    }
    (void)platform_socket_set_receive_timeout(fd, RF_IO_TIMEOUT_MS);
    (void)platform_socket_set_send_timeout(fd, RF_IO_TIMEOUT_MS);
    return fd;
}
