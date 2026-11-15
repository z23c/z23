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
platform_socket_t rf_connect_onion_cancelable(const char *peer_addr, uint16_t port,
                                               bool (*cancelled)(void *), void *context);
bool rf_recv_exact(platform_socket_t fd, uint8_t *buf, size_t size);
bool rf_recv_exact_until(platform_socket_t fd, uint8_t *buf, size_t size,
                         int64_t deadline_ms);
/* rf_recv_exact_until that ALSO keeps the per-recv silence window: each
 * recv waits at most min(silence_ms, time left), so a silent link still
 * fails at the silence window while a dripping one fails at the deadline. */
bool rf_recv_exact_bounded(platform_socket_t fd, uint8_t *buf, size_t size,
                           int64_t deadline_ms, int silence_ms);
void rf_session_close(struct fs_session *session, platform_socket_t fd);

/* The per-recv silence window rf_connect armed for peer_addr's transport. */
int rf_io_timeout_ms(const char *peer_addr);

/* Absolute monotonic deadline by which the first wire_bytes of a chunk reply
 * requested at start_ms must have arrived (floor rate plus slack, scaled for
 * an onion peer; see rom_fetch_transport.c). 0 (already expired) when no
 * deadline can be formed, so the exchange fails closed. */
int64_t rf_chunk_deadline_ms(const char *peer_addr, int64_t start_ms,
                             uint64_t wire_bytes);

#ifdef ZCL_TESTING
/* Replace the floor rate and slack (0 restores each production value). */
void rom_fetch_set_chunk_deadline_for_test(uint64_t floor_bytes_per_sec,
                                           int64_t slack_ms);
#endif

/* Short pre-flight recv window for the manifest/directory probes, scaled for
 * the transport peer_addr implies. Never collapse this with rf_connect's
 * budget: this one exists to detect a LEGACY seeder quickly, which is a
 * different question from whether the link is slow. */
int rf_probe_io_timeout_ms(const char *peer_addr);

#endif
