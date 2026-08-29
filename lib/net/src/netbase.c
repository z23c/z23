/* Copyright (c) 2009-2010 Satoshi Nakamoto
 * Copyright (c) 2009-2014 The Bitcoin Core developers
 * Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. */

#include "net/netbase.h"
#include "encoding/utilstrencodings.h"
#include "platform/socket_compat.h"
#include "util/safe_alloc.h"
#include "util/log_macros.h"
#include "base/safe_alloc.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

void split_host_port(const char *in, char *host_out, size_t host_size,
                     int *port_out)
{
    size_t len = strlen(in);
    const char *colon = NULL;
    for (size_t i = len; i > 0; i--) {
        if (in[i - 1] == ':') {
            colon = &in[i - 1];
            break;
        }
    }

    if (colon) {
        bool bracketed = (in[0] == '[' && colon > in && colon[-1] == ']');
        bool multi_colon = false;
        for (const char *p = in; p < colon; p++) {
            if (*p == ':') { multi_colon = true; break; }
        }
        if (colon != in && (bracketed || !multi_colon)) {
            int n = 0;
            if (ParseInt32(colon + 1, &n) && n > 0 && n < 0x10000) {
                *port_out = n;
                len = (size_t)(colon - in);
            }
        }
    }

    if (len >= 2 && in[0] == '[' && in[len - 1] == ']') {
        if (len - 2 < host_size) {
            memcpy(host_out, in + 1, len - 2);
            host_out[len - 2] = '\0';
        }
    } else {
        size_t copy = len < host_size - 1 ? len : host_size - 1;
        memcpy(host_out, in, copy);
        host_out[copy] = '\0';
    }
}

bool lookup_host(const char *name, struct net_addr *results,
                 size_t max_results, size_t *num_results,
                 bool allow_lookup)
{
    if (!name || !results || !num_results || max_results == 0)
        LOG_FAIL("net", "lookup_host: invalid arguments");

    *num_results = 0;

    if (max_results > SIZE_MAX / 16)
        return false;
    uint8_t (*resolved)[16] =
        zcl_malloc(max_results * sizeof(*resolved), "netbase.resolve_addresses");
    if (!resolved)
        LOG_FAIL("net", "lookup_host: address allocation failed for '%s'",
                 name);
    size_t count = 0;
    bool ok = platform_socket_resolve_addresses(
        name, allow_lookup, resolved, max_results, &count);
    if (ok)
        for (size_t i = 0; i < count; i++) {
            net_addr_init(&results[i]);
            memcpy(results[i].ip, resolved[i], 16);
        }
    free(resolved);
    *num_results = count;
    return ok;
}

bool lookup_numeric(const char *name, struct net_service *result,
                    uint16_t default_port)
{
    char host[256];
    int port = (int)default_port;
    strncpy(host, name, sizeof(host) - 1);
    host[sizeof(host) - 1] = '\0';
    split_host_port(name, host, sizeof(host), &port);

    struct net_addr addrs[1];
    size_t n = 0;
    if (!lookup_host(host, addrs, 1, &n, false))
        LOG_FAIL("net", "lookup_numeric: host '%s' not resolvable", host);
    result->addr = addrs[0];
    result->port = (uint16_t)port;
    return true;
}

bool net_name_is_onion(const char *name)
{
    if (!name)
        return false;
    char host[256];
    int port = 0;
    split_host_port(name, host, sizeof(host), &port);
    size_t len = strlen(host);
    if (len > 0 && host[len - 1] == '.')
        len--;
    static const char suffix[] = ".onion";
    if (len <= sizeof(suffix) - 1u)
        return false;
    const char *tail = host + len - (sizeof(suffix) - 1u);
    for (size_t i = 0; i < sizeof(suffix) - 1u; i++) {
        char c = tail[i];
        if (c >= 'A' && c <= 'Z')
            c = (char)(c + ('a' - 'A'));
        if (c != suffix[i])
            return false;
    }
    return true;
}

bool lookup_onion(const char *name, struct net_service *result,
                  uint16_t default_port)
{
    if (!name || !result)
        LOG_FAIL("net", "lookup_onion: invalid arguments");

    char host[256];
    int port = (int)default_port;
    split_host_port(name, host, sizeof(host), &port);

    if (!net_addr_from_onion(host, &result->addr))
        LOG_FAIL("net", "lookup_onion: '%s' is not a valid v3 onion address",
                 host);
    result->port = (uint16_t)port;
    return true;
}

struct timeval millis_to_timeval(int64_t ms)
{
    struct timeval tv;
    tv.tv_sec = (long)(ms / 1000);
    tv.tv_usec = (long)((ms % 1000) * 1000);
    return tv;
}

static bool net_service_get_sockaddr(const struct net_service *svc,
                                     struct sockaddr_storage *ss,
                                     size_t *len)
{
    if (net_addr_is_ipv4(&svc->addr)) {
        struct sockaddr_in *s4 = (struct sockaddr_in *)ss;
        memset(s4, 0, sizeof(*s4));
        s4->sin_family = AF_INET;
        memcpy(&s4->sin_addr, svc->addr.ip + 12, 4);
        s4->sin_port = htons(svc->port);
        *len = sizeof(*s4);
        return true;
    }
    struct sockaddr_in6 *s6 = (struct sockaddr_in6 *)ss;
    memset(s6, 0, sizeof(*s6));
    s6->sin6_family = AF_INET6;
    memcpy(&s6->sin6_addr, svc->addr.ip, 16);
    s6->sin6_port = htons(svc->port);
    *len = sizeof(*s6);
    return true;
}

enum zcl_connect_start connect_socket_start(const struct net_service *addr,
                                            zcl_socket_t *sock_out)
{
    *sock_out = ZCL_INVALID_SOCKET;

    /* Fail closed: a torv3 service has no sockaddr. Onion dials route
     * through onion_stream_connect (raw dynhost stream over the embedded
     * Tor circuit); letting one reach connect(2) would dial the all-zero
     * IPv6 address on the clearnet. */
    if (net_addr_is_tor(&addr->addr)) {
        LOG_RETURN(ZCL_CONNECT_START_ERROR, "net",
                   "connect_socket_start: torv3 address refused — onion "
                   "dials use onion_stream_connect, never connect(2)");
    }

    struct sockaddr_storage ss;
    size_t len = sizeof(ss);
    if (!net_service_get_sockaddr(addr, &ss, &len)) {
        LOG_RETURN(ZCL_CONNECT_START_ERROR, "net",
                   "connect_socket_start: failed to get sockaddr");
    }

    zcl_socket_t sock = platform_socket_open(
        ((struct sockaddr *)&ss)->sa_family, SOCK_STREAM, IPPROTO_TCP,
        true, true);
    if (sock == ZCL_INVALID_SOCKET) {
        LOG_RETURN(ZCL_CONNECT_START_ERROR, "net",
                   "connect_socket_start: socket failed, error=%d",
                   platform_socket_last_error());
    }

    (void)platform_socket_set_no_delay(sock, true);

    if (platform_socket_connect(sock, (struct sockaddr *)&ss, len) ==
        ZCL_SOCKET_ERROR) {
        int err = platform_socket_last_error();
        if (platform_socket_error_in_progress(err) ||
            platform_socket_error_would_block(err)) {
            *sock_out = sock;
            return ZCL_CONNECT_START_IN_PROGRESS;
        }
        close_socket(&sock);
        return ZCL_CONNECT_START_ERROR;
    }

    /* Connected synchronously (rare on non-blocking sockets, e.g. loopback). */
    *sock_out = sock;
    return ZCL_CONNECT_START_CONNECTED;
}

bool connect_socket_check(zcl_socket_t sock)
{
    if (sock == ZCL_INVALID_SOCKET)
        return false;
    int so_err = 0;
    if (platform_socket_pending_error(sock, &so_err) < 0)
        return false;
    return so_err == 0;
}

bool connect_socket_directly(const struct net_service *addr,
                             zcl_socket_t *sock_out,
                             int timeout_ms)
{
    zcl_socket_t sock = ZCL_INVALID_SOCKET;
    enum zcl_connect_start st = connect_socket_start(addr, &sock);
    if (st == ZCL_CONNECT_START_ERROR)
        return false;
    if (st == ZCL_CONNECT_START_CONNECTED) {
        *sock_out = sock;
        return true;
    }

    /* IN_PROGRESS: wait for writability up to timeout_ms, then confirm. */
    platform_socket_pollfd pfd = {
        .fd = sock, .events = PLATFORM_SOCKET_POLL_WRITE, .revents = 0};
    int nRet = platform_socket_poll(&pfd, 1, timeout_ms);
    if (nRet <= 0 || !connect_socket_check(sock)) {
        close_socket(&sock);
        *sock_out = ZCL_INVALID_SOCKET;
        return false;
    }
    *sock_out = sock;
    return true;
}

bool close_socket(zcl_socket_t *sock)
{
    if (*sock == ZCL_INVALID_SOCKET)
        return false;
    int ret = platform_socket_close(*sock);
    *sock = ZCL_INVALID_SOCKET;
    return ret != ZCL_SOCKET_ERROR;
}

bool zcl_set_socket_nonblocking(zcl_socket_t sock, bool nonblocking)
{
    return platform_socket_set_nonblocking(sock, nonblocking);
}
