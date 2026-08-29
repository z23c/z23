/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Private bounded transport operations for the ROM fetch client. */
#ifndef ZCL_NET_ROM_FETCH_TRANSPORT_H
#define ZCL_NET_ROM_FETCH_TRANSPORT_H

#include "net/file_service.h"
#include "platform/socket_compat.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Connect to a seeding peer. Routes by address family: a ".onion" name goes
 * over a Tor circuit (net/onion_stream.h), anything else over getaddrinfo +
 * connect(2). Either way the returned fd is blocking with recv/send silence
 * windows armed, so every caller above is transport-blind. */
platform_socket_t rf_connect(const char *peer_addr, uint16_t port);
bool rf_recv_exact(platform_socket_t fd, uint8_t *buf, size_t size);
void rf_session_close(struct fs_session *session, platform_socket_t fd);

/* Short pre-flight recv window for the manifest/directory probes, scaled for
 * the transport peer_addr implies. Never collapse this with rf_connect's
 * budget: this one exists to detect a LEGACY seeder quickly, which is a
 * different question from whether the link is slow. */
int rf_probe_io_timeout_ms(const char *peer_addr);

#endif
