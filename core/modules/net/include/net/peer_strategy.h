/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Peer connectivity strategy — decides how to reach every peer.
 * Probes NAT-PMP, UPnP, and Tor at startup; selects the best
 * transport per peer address; advertises all reachable addresses. */

#ifndef ZCL_NET_PEER_STRATEGY_H
#define ZCL_NET_PEER_STRATEGY_H

#include <stdbool.h>
#include <stdint.h>

enum peer_transport {
    TRANSPORT_CLEARNET = 0,
    TRANSPORT_TOR      = 1,
    TRANSPORT_NAT_PMP  = 2,
    TRANSPORT_UPNP     = 3,
};

struct node_profile {
    bool     has_public_ip;
    bool     nat_pmp_available;
    bool     upnp_available;
    bool     tor_available;
    uint8_t  public_ip[4];
    uint16_t public_port;
    char     onion_address[68];
};

/* Probe NAT-PMP, UPnP, and Tor to build our reachability profile. */
bool peer_strategy_discover_self(struct node_profile *profile,
                                 uint16_t listen_port);

/* Choose the best transport for a given peer address. */
enum peer_transport peer_strategy_select(const struct node_profile *self,
                                         const char *peer_addr);

/* Fill addrs_out with our reachable addresses (IP:port and/or .onion).
 * Returns the number of addresses written (up to max_addrs). */
int peer_strategy_get_addresses(const struct node_profile *self,
                                char (*addrs_out)[68], int max_addrs);

/* Return a human-readable label for a transport enum value. */
const char *peer_transport_name(enum peer_transport t);

#endif
