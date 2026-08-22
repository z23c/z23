/* Copyright (c) 2009-2010 Satoshi Nakamoto
 * Copyright (c) 2009-2014 The Bitcoin Core developers
 * Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. */

#include "net/netbase.h"
#include "encoding/utilstrencodings.h"
#include "util/log_macros.h"
#include <string.h>
#include <stdio.h>

#ifndef _WIN32
#include <netdb.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <unistd.h>
#include <netinet/tcp.h>
#include <errno.h>
#include <poll.h>
#include <sys/select.h>

#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif
#endif

static const unsigned char pchIPv4Map[12] = {
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff
};

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

    struct in_addr ipv4;
    if (inet_pton(AF_INET, name, &ipv4) > 0) {
        net_addr_init(&results[0]);
        memcpy(results[0].ip, pchIPv4Map, 12);
        memcpy(results[0].ip + 12, &ipv4, 4);
        *num_results = 1;
        return true;
    }

    struct in6_addr ipv6;
    if (inet_pton(AF_INET6, name, &ipv6) > 0) {
        net_addr_init(&results[0]);
        memcpy(results[0].ip, &ipv6, 16);
        *num_results = 1;
        return true;
    }

    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    hints.ai_family = AF_UNSPEC;
#ifndef _WIN32
    hints.ai_flags = allow_lookup ? AI_ADDRCONFIG : AI_NUMERICHOST;
#else
    hints.ai_flags = allow_lookup ? 0 : AI_NUMERICHOST;
#endif

    struct addrinfo *res = NULL;
    int err = getaddrinfo(name, NULL, &hints, &res);
    if (err != 0)
        LOG_FAIL("net", "getaddrinfo failed for '%s': error %d", name, err);

    for (struct addrinfo *ai = res;
         ai && *num_results < max_results;
         ai = ai->ai_next) {
        if (ai->ai_family == AF_INET) {
            struct sockaddr_in *s4 = (struct sockaddr_in *)ai->ai_addr;
            net_addr_init(&results[*num_results]);
            memcpy(results[*num_results].ip, pchIPv4Map, 12);
            memcpy(results[*num_results].ip + 12, &s4->sin_addr, 4);
            (*num_results)++;
        } else if (ai->ai_family == AF_INET6) {
            struct sockaddr_in6 *s6 = (struct sockaddr_in6 *)ai->ai_addr;
            net_addr_init(&results[*num_results]);
            memcpy(results[*num_results].ip, &s6->sin6_addr, 16);
            (*num_results)++;
        }
    }

    freeaddrinfo(res);
    return *num_results > 0;
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
    return len > 6 && strcmp(host + len - 6, ".onion") == 0;
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
                                     socklen_t *len)
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
    socklen_t len = sizeof(ss);
    if (!net_service_get_sockaddr(addr, &ss, &len)) {
        LOG_RETURN(ZCL_CONNECT_START_ERROR, "net",
                   "connect_socket_start: failed to get sockaddr");
    }

    zcl_socket_t sock = socket(((struct sockaddr *)&ss)->sa_family,
                               SOCK_STREAM, IPPROTO_TCP);
    if (sock == ZCL_INVALID_SOCKET) {
        LOG_RETURN(ZCL_CONNECT_START_ERROR, "net",
                   "connect_socket_start: socket() failed, errno=%d", errno);
    }

    int set = 1;
#ifdef SO_NOSIGPIPE
    setsockopt(sock, SOL_SOCKET, SO_NOSIGPIPE, &set, sizeof(int));
#endif
    setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, &set, sizeof(int));

    if (!set_socket_nonblocking(sock, true)) {
        close_socket(&sock);
        LOG_RETURN(ZCL_CONNECT_START_ERROR, "net",
                   "connect_socket_start: set_socket_nonblocking failed");
    }

    if (connect(sock, (struct sockaddr *)&ss, len) == ZCL_SOCKET_ERROR) {
        int err = errno;
        if (err == EINPROGRESS || err == EWOULDBLOCK) {
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
    socklen_t so_len = sizeof(so_err);
    if (getsockopt(sock, SOL_SOCKET, SO_ERROR, &so_err, &so_len) < 0)
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
    struct pollfd pfd = { .fd = sock, .events = POLLOUT, .revents = 0 };
    int nRet = poll(&pfd, 1, timeout_ms);
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
#ifdef _WIN32
    int ret = closesocket(*sock);
#else
    int ret = close(*sock);
#endif
    *sock = ZCL_INVALID_SOCKET;
    return ret != ZCL_SOCKET_ERROR;
}

bool zcl_set_socket_nonblocking(zcl_socket_t sock, bool nonblocking)
{
#ifdef _WIN32
    u_long mode = nonblocking ? 1 : 0;
    return ioctlsocket(sock, FIONBIO, &mode) != ZCL_SOCKET_ERROR;
#else
    int flags = fcntl(sock, F_GETFL, 0);
    if (flags < 0) LOG_FAIL("net", "fcntl F_GETFL failed for socket %d", sock);
    if (nonblocking)
        flags |= O_NONBLOCK;
    else
        flags &= ~O_NONBLOCK;
    return fcntl(sock, F_SETFL, flags) != -1;
#endif
}
