/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Private bounded transport operations for the ROM fetch client. */
#ifndef ZCL_NET_ROM_FETCH_TRANSPORT_H
#define ZCL_NET_ROM_FETCH_TRANSPORT_H

#include "net/file_service.h"
#include "platform/socket_compat.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

platform_socket_t rf_connect(const char *peer_addr, uint16_t port);
bool rf_recv_exact(platform_socket_t fd, uint8_t *buf, size_t size);
void rf_session_close(struct fs_session *session, platform_socket_t fd);

#endif
