/* Copyright (c) 2009-2010 Satoshi Nakamoto
 * Copyright (c) 2009-2014 The Bitcoin Core developers
 * Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. */

#ifndef ZCL_NETBASE_H
#define ZCL_NETBASE_H

#include "net/netaddr.h"
#include <stdbool.h>
#include <stdint.h>

#ifndef _WIN32
#include <sys/socket.h>
#include <netinet/in.h>
typedef int zcl_socket_t;
#define ZCL_INVALID_SOCKET (-1)
#define ZCL_SOCKET_ERROR (-1)
#else
#include <winsock2.h>
typedef SOCKET zcl_socket_t;
#define ZCL_INVALID_SOCKET INVALID_SOCKET
#define ZCL_SOCKET_ERROR SOCKET_ERROR
#endif

#define DEFAULT_CONNECT_TIMEOUT 5000

bool lookup_host(const char *name, struct net_addr *results,
                 size_t max_results, size_t *num_results,
                 bool allow_lookup);

bool lookup_numeric(const char *name, struct net_service *result,
                    uint16_t default_port);

/* True when the host part of "host[:port]" carries the ".onion" suffix.
 * Detection only — no parsing, no resolution. */
bool net_name_is_onion(const char *name);

/* Parse "<56 base32>.onion[:port]" into a torv3 net_service. Fails CLOSED:
 * false on any malformed onion name, and NEVER attempts DNS or clearnet
 * resolution — a .onion name must never leak to getaddrinfo. */
bool lookup_onion(const char *name, struct net_service *result,
                  uint16_t default_port);

bool connect_socket_directly(const struct net_service *addr,
                             zcl_socket_t *sock_out,
                             int timeout_ms);

/* ── Non-blocking connect primitives (parallel dialer) ───────────────────
 *
 * connect_socket_directly() blocks in select() for up to timeout_ms on ONE
 * address. To dial many peers concurrently from a single thread, split the
 * connect into "start" (create socket, set non-blocking, issue connect()) and
 * "check" (has the in-flight connect completed successfully?). The caller
 * poll()s the returned fds against ONE shared deadline and completes whichever
 * win, closing the losers — no extra threads, no per-address blocking wait. */
enum zcl_connect_start {
    ZCL_CONNECT_START_ERROR = 0,   /* socket()/connect() failed; sock closed */
    ZCL_CONNECT_START_CONNECTED,   /* connected synchronously (e.g. localhost) */
    ZCL_CONNECT_START_IN_PROGRESS, /* EINPROGRESS — poll POLLOUT then _check */
};

/* Create a non-blocking TCP socket (TCP_NODELAY, SO_NOSIGPIPE where available)
 * and issue a non-blocking connect() to `addr`. On ERROR the socket is closed
 * and *sock_out is ZCL_INVALID_SOCKET. On CONNECTED/IN_PROGRESS *sock_out holds
 * the (still non-blocking) socket the caller now owns. */
enum zcl_connect_start connect_socket_start(const struct net_service *addr,
                                            zcl_socket_t *sock_out);

/* After poll() reports the socket writable (POLLOUT), returns true iff the
 * async connect() succeeded (SO_ERROR == 0). Does not close the socket. */
bool connect_socket_check(zcl_socket_t sock);

bool close_socket(zcl_socket_t *sock);

/* Prefixed to avoid conflict with Tor's socket.c */
bool zcl_set_socket_nonblocking(zcl_socket_t sock, bool nonblocking);
#define set_socket_nonblocking zcl_set_socket_nonblocking

void split_host_port(const char *in, char *host_out, size_t host_size,
                     int *port_out);

struct timeval millis_to_timeval(int64_t ms);

#endif
