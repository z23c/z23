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
#include <errno.h>
#include <stdatomic.h>

static _Atomic int g_p2p_socket_requested_receive = 0;
static _Atomic int g_p2p_socket_requested_send = 0;
static _Atomic int g_p2p_socket_minimum_actual_receive = -1;
static _Atomic int g_p2p_socket_minimum_actual_send = -1;
static _Atomic uint64_t g_p2p_socket_attempts = 0;
static _Atomic uint64_t g_p2p_socket_fully_observed = 0;
static _Atomic uint64_t g_p2p_socket_degraded = 0;

static void net_record_minimum_socket_grant(_Atomic int *slot, int value)
{
    int current = atomic_load_explicit(slot, memory_order_relaxed);
    while ((current < 0 || value < current) &&
           !atomic_compare_exchange_weak_explicit(
               slot, &current, value, memory_order_relaxed,
               memory_order_relaxed)) {
        /* current is refreshed by the failed compare-exchange. */
    }
}

bool net_configure_p2p_socket_buffers(zcl_socket_t sock)
{
    struct platform_socket_buffer_observation observation;
    bool ok = platform_socket_configure_p2p_buffers(sock, &observation);

    atomic_store_explicit(&g_p2p_socket_requested_receive,
                          observation.requested_receive_bytes,
                          memory_order_relaxed);
    atomic_store_explicit(&g_p2p_socket_requested_send,
                          observation.requested_send_bytes,
                          memory_order_relaxed);
    if (observation.receive_observed)
        net_record_minimum_socket_grant(
            &g_p2p_socket_minimum_actual_receive,
            observation.actual_receive_bytes);
    if (observation.send_observed)
        net_record_minimum_socket_grant(
            &g_p2p_socket_minimum_actual_send,
            observation.actual_send_bytes);
    atomic_fetch_add_explicit(&g_p2p_socket_attempts, 1,
                              memory_order_relaxed);
    if (observation.receive_observed && observation.send_observed)
        atomic_fetch_add_explicit(&g_p2p_socket_fully_observed, 1,
                                  memory_order_relaxed);
    if (!ok)
        atomic_fetch_add_explicit(&g_p2p_socket_degraded, 1,
                                  memory_order_relaxed);
    return ok;
}

void net_get_p2p_socket_buffer_stats(struct net_p2p_socket_buffer_stats *out)
{
    if (!out) return;
    out->requested_receive_bytes = atomic_load_explicit(
        &g_p2p_socket_requested_receive, memory_order_relaxed);
    out->requested_send_bytes = atomic_load_explicit(
        &g_p2p_socket_requested_send, memory_order_relaxed);
    out->minimum_actual_receive_bytes = atomic_load_explicit(
        &g_p2p_socket_minimum_actual_receive, memory_order_relaxed);
    out->minimum_actual_send_bytes = atomic_load_explicit(
        &g_p2p_socket_minimum_actual_send, memory_order_relaxed);
    out->attempts_total = atomic_load_explicit(
        &g_p2p_socket_attempts, memory_order_relaxed);
    out->fully_observed_total = atomic_load_explicit(
        &g_p2p_socket_fully_observed, memory_order_relaxed);
    out->degraded_total = atomic_load_explicit(
        &g_p2p_socket_degraded, memory_order_relaxed);
}

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
    if (allow_lookup && !netbase_host_dial_allowed(name))
        LOG_FAIL("net", "lookup_host: DNS refused by -onlynet=onion");

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

static _Atomic bool g_onlynet_onion;

void netbase_set_onlynet_onion(bool on)
{
    atomic_store_explicit(&g_onlynet_onion, on, memory_order_relaxed);
}

bool netbase_onlynet_onion(void)
{
    return atomic_load_explicit(&g_onlynet_onion, memory_order_relaxed);
}

/* -onlynet=onion outbound census (re-derive with
 *   git grep -n 'getaddrinfo\|connect(' -- core engine contexts platform).
 * Goal: with the flag on the node issues ZERO clearnet DNS lookups and ZERO
 * clearnet TCP connects of its own. Loopback and the LAN gateway are the only
 * exceptions. Each path is one of: gated, refused, loopback-only, LAN-only,
 * not reachable. Rows name functions, not line numbers, so they do not rot.
 *   GATED      netbase.c connect_socket_start       P2P dialer/connect_node/probe
 *   GATED      netbase.c lookup_host                every DNS lookup (allow_lookup)
 *   GATED      connman.c dns_seed_resolve           DNS seeds skipped
 *   GATED      connman.c connman_add_seed_node      host check before getaddrinfo
 *   GATED      boot_node_utilities.c app_open_node  host check before resolve
 *   GATED      rom_fetch_transport.c rf_connect_route  host check before
 *              getaddrinfo (+ boot_bundle_fetch_seeds.c: no clearnet seed list,
 *              and no peer-discovered seed at all under the flag, onion ones
 *              included: over-conservative, never a leak)
 *   GATED      file_service.c fs_client_sync        host check before getaddrinfo;
 *              fs_connect_resolved_until and the range worker re-check the
 *              resolved sockaddr (defence in depth)
 *   REFUSED    -fileservice=HOST, -filesync=HOST, -allow-clearnet-snapshot-fetch
 *              (app_context.c app_onlynet_onion_refusal)
 *   GATED      file_market_delivery_client.c        delivery dial (peer IP)
 *   GATED      legacy_rpc_client.c legacy_rpc_call  the legacy zclassicd RPC
 *              (mirror sync, UTXO parity): numeric host, no DNS; a non-loopback
 *              host is refused before connect
 *   GATED      nat.c (UPnP/NAT-PMP, LAN gateway only): nat_add_port_mapping
 *              and nat_discover_public_ip return before any probe
 *   LOOPBACK   mesh_tunnel.c                        tunnel_loopback_v4 only
 *   LOOPBACK   device_host_bridge.c                 INADDR_LOOPBACK only
 *   LOOPBACK   main_cli_modes.c                     CLI probes of 127.0.0.1
 *   LOOPBACK   socket_compat.h socketpair fallback  loopback self-pair
 *   NOT REACHABLE device_host_runtime.c runtime_dial: operator CLI command
 *              (`ops mesh device-host ...`) in its own process, never started by
 *              the node; the route address is an operator-typed literal
 *   LOOPBACK   explorer_controller.c, wallet_view_helpers.c, api_controller.c,
 *              rpc client.c, entry/cli.c: node RPC on INADDR_LOOPBACK
 *   LOCAL-ONLY ui_present_host_transport.c          AF_UNIX socket, no network
 *              (no IP at all)
 *   TOR        onion_stream_connect rides Tor, not DNS. The embedded Tor
 *              itself connects to Tor relays over clearnet: that is the
 *              transport, and the only clearnet egress the flag leaves. */
bool netbase_clearnet_dial_allowed(const struct net_service *addr)
{
    if (!addr)
        return false;
    if (!netbase_onlynet_onion())
        return true;
    return net_addr_is_tor(&addr->addr) ||
           net_addr_is_operator_local(&addr->addr);
}

/* ::1 or a v4-mapped 127/8 address. */
static bool netbase_in6_is_loopback(const struct in6_addr *a)
{
    return IN6_IS_ADDR_LOOPBACK(a) ||
           (IN6_IS_ADDR_V4MAPPED(a) && a->s6_addr[12] == 127);
}

/* Host-string form of the same policy, for code that resolves a NAME before it
 * has an address: allowed when the flag is off, or the host is a .onion name,
 * "localhost" or a numeric loopback literal. Nothing is resolved here. */
bool netbase_host_dial_allowed(const char *host)
{
    if (!netbase_onlynet_onion())
        return true;
    if (!host || host[0] == '\0')
        return false;
    if (net_name_is_onion(host))
        return true;
    char bare[256];
    int port = 0;
    split_host_port(host, bare, sizeof(bare), &port);
    if (strcmp(bare, "localhost") == 0)
        return true;
    struct in_addr v4;
    struct in6_addr v6;
    if (inet_pton(AF_INET, bare, &v4) == 1)
        return (ntohl(v4.s_addr) >> 24) == 127;
    if (inet_pton(AF_INET6, bare, &v6) == 1)
        return netbase_in6_is_loopback(&v6);
    return false;
}

/* Already-resolved form (range workers, resolved-peer connects). */
bool netbase_sockaddr_dial_allowed(const struct sockaddr *sa, size_t len)
{
    if (!netbase_onlynet_onion())
        return true;
    if (!sa)
        return false;
    if (sa->sa_family == AF_INET && len >= sizeof(struct sockaddr_in))
        return (ntohl(((const struct sockaddr_in *)sa)->sin_addr.s_addr) >>
                24) == 127;
    if (sa->sa_family == AF_INET6 && len >= sizeof(struct sockaddr_in6))
        return netbase_in6_is_loopback(
            &((const struct sockaddr_in6 *)sa)->sin6_addr);
    return false;
}

/* Guarded syscall wrappers: drop-in for getaddrinfo()/connect() where the
 * target is operator- or peer-supplied. With -onlynet=onion a non-onion,
 * non-loopback target is refused BEFORE any resolve or connect (EAI_FAIL /
 * EACCES); with the flag off they are the plain calls. */
int netbase_getaddrinfo_guarded(const char *host, const char *service,
                                const struct addrinfo *hints,
                                struct addrinfo **res)
{
    if (!netbase_host_dial_allowed(host))
        return EAI_FAIL;
    return getaddrinfo(host, service, hints, res);
}

int netbase_connect_guarded(zcl_socket_t fd, const struct sockaddr *sa,
                           size_t len)
{
    if (!netbase_sockaddr_dial_allowed(sa, len)) {
        errno = EACCES;
        return -1;
    }
    return platform_socket_connect(fd, sa, len);
}

enum zcl_connect_start connect_socket_start(const struct net_service *addr,
                                            zcl_socket_t *sock_out)
{
    *sock_out = ZCL_INVALID_SOCKET;

    if (!netbase_clearnet_dial_allowed(addr)) {
        LOG_RETURN(ZCL_CONNECT_START_ERROR, "net",
                   "connect_socket_start: clearnet dial refused by "
                   "-onlynet=onion");
    }

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
    if (!net_configure_p2p_socket_buffers(sock)) {
        LOG_WARN("net",
                 "connect_socket_start: P2P socket buffer configuration or "
                 "readback degraded");
    }

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
