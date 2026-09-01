/* Copyright (c) 2009-2010 Satoshi Nakamoto
 * Copyright (c) 2009-2014 The Bitcoin Core developers
 * Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. */

#ifndef ZCL_NETADDR_H
#define ZCL_NETADDR_H

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

enum zcl_network {
    NET_UNROUTABLE = 0,
    NET_IPV4,
    NET_IPV6,
    NET_ONION,
    NET_MAX
};

#define TORV3_ADDR_SIZE 32

struct net_addr {
    unsigned char ip[16];
    unsigned char torv3[TORV3_ADDR_SIZE];
    bool has_torv3;
};

struct net_service {
    struct net_addr addr;
    uint16_t port;
};

struct net_address {
    struct net_service svc;
    uint64_t nServices;
    uint32_t nTime;
};

static const unsigned char pchIPv4Prefix[12] = {
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff
};

static inline void net_addr_init(struct net_addr *a)
{
    memset(a, 0, sizeof(*a));
}

static inline void net_service_init(struct net_service *s)
{
    net_addr_init(&s->addr);
    s->port = 0;
}

static inline void net_address_init(struct net_address *a)
{
    net_service_init(&a->svc);
    a->nServices = 1; /* NODE_NETWORK */
    a->nTime = 100000000;
}

static inline bool net_addr_is_ipv4(const struct net_addr *a)
{
    return memcmp(a->ip, pchIPv4Prefix, 12) == 0;
}

static inline bool net_addr_is_ipv6(const struct net_addr *a)
{
    return !a->has_torv3 && !net_addr_is_ipv4(a);
}

static inline bool net_addr_is_tor(const struct net_addr *a)
{
    return a->has_torv3;
}

static inline enum zcl_network net_addr_get_network(const struct net_addr *a)
{
    if (a->has_torv3) return NET_ONION;
    if (net_addr_is_ipv4(a)) return NET_IPV4;
    return NET_IPV6;
}

static inline bool net_addr_is_valid(const struct net_addr *a)
{
    if (a->has_torv3) return true;
    unsigned char none[16] = {0};
    if (memcmp(a->ip, none, 16) == 0) return false;
    /* RFC 3849 documentation IPv6 */
    if (a->ip[0] == 0x20 && a->ip[1] == 0x01 &&
        a->ip[2] == 0x0d && a->ip[3] == 0xb8)
        return false;
    return true;
}

static inline bool net_addr_eq(const struct net_addr *a, const struct net_addr *b)
{
    return memcmp(a->ip, b->ip, 16) == 0 &&
           a->has_torv3 == b->has_torv3 &&
           (!a->has_torv3 || memcmp(a->torv3, b->torv3, TORV3_ADDR_SIZE) == 0);
}

static inline bool net_service_eq(const struct net_service *a, const struct net_service *b)
{
    return net_addr_eq(&a->addr, &b->addr) && a->port == b->port;
}

static inline void net_addr_set_ipv4(struct net_addr *a, const unsigned char ip4[4])
{
    memcpy(a->ip, pchIPv4Prefix, 12);
    memcpy(a->ip + 12, ip4, 4);
    a->has_torv3 = false;
}

static inline unsigned char net_addr_get_byte(const struct net_addr *a, int n)
{
    return a->ip[15 - n];
}

bool net_addr_is_rfc1918(const struct net_addr *a);
bool net_addr_is_rfc2544(const struct net_addr *a);
bool net_addr_is_rfc3927(const struct net_addr *a);
bool net_addr_is_rfc6598(const struct net_addr *a);
bool net_addr_is_rfc5737(const struct net_addr *a);
bool net_addr_is_rfc3964(const struct net_addr *a);
bool net_addr_is_rfc6052(const struct net_addr *a);
bool net_addr_is_rfc4380(const struct net_addr *a);
bool net_addr_is_rfc4862(const struct net_addr *a);
bool net_addr_is_rfc4193(const struct net_addr *a);
bool net_addr_is_rfc6145(const struct net_addr *a);
bool net_addr_is_rfc4843(const struct net_addr *a);
bool net_addr_is_local(const struct net_addr *a);
bool net_addr_is_routable(const struct net_addr *a);

/* True ONLY for a same-host peer: IPv4 127.0.0.0/8 or IPv6 ::1. Never true
 * for a Tor address, never true for RFC1918 or any other private range, and
 * NULL reads as false (deny).
 *
 * Sole use is the per-source-IP INBOUND ADMISSION cap in
 * accept_connection(). Several nodes on one machine all arrive as
 * 127.0.0.1 and share one 16-byte key, so the default cap of 3 refuses the
 * fourth of them by construction — which is exactly the local multi-node
 * topology a cold-start sync proof is made of. Loopback answers that
 * completely; RFC1918 does not appear here on purpose, because on a hosted
 * machine with provider private networking the neighbouring tenants are
 * RFC1918 sources.
 *
 * This is NOT a trust decision and it is NOT an exemption from any bound.
 * Loopback gets a RAISED per-source cap and, on top of that, an AGGREGATE
 * ceiling on how many inbound slots all loopback sources together may hold
 * (peer_scoring_max_inbound_loopback()) — 127.0.0.0/8 is 16M distinct
 * source keys, so a per-IP number alone would bound nothing. The global
 * inbound cap and the reserved outbound slots still apply as they do to
 * every other peer. */
bool net_addr_is_operator_local(const struct net_addr *a);

#define NET_ADDR_GROUP_MAX 5

size_t net_addr_get_group(const struct net_addr *a, unsigned char *out,
                          size_t out_size);

/* Worst-case rendered lengths, excluding the NUL: a torv3 hostname is
 * "<56 base32>.onion" (62); a service adds ":<port>" (6). Callers that may
 * carry an onion address must size buffers with these, not INET6_ADDRSTRLEN
 * habits. */
#define NET_ADDR_STR_MAX 62
#define NET_SERVICE_STR_MAX 69

/* Fixed-size identity key for a service. Layout:
 *   out[0]      = 1 when the address is a torv3 onion, else 0
 *   out[1..32]  = torv3 pubkey for onion addresses, else ip[16] followed
 *                 by 16 zero bytes
 *   out[33..34] = port, big-endian
 * The torv3 pubkey MUST be part of the key: before it was, every onion
 * service (ip[16] zeroed) collided onto the single all-zero key. */
#define NET_SERVICE_KEY_SIZE 35

void net_service_get_key(const struct net_service *s,
                         unsigned char out[NET_SERVICE_KEY_SIZE]);

int net_addr_to_string(const struct net_addr *a, char *out, size_t out_size);
int net_service_to_string(const struct net_service *s, char *out, size_t out_size);

/* Parse a v3 onion hostname ("<56 base32>.onion", suffix optional per the
 * codec) into a torv3 net_addr. False — with *out zeroed — on any malformed
 * input. NEVER resolves anything; pure decode. */
bool net_addr_from_onion(const char *hostname, struct net_addr *out);

#endif
