/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. */

#ifndef ZCL_PEER_IDENTITY_H
#define ZCL_PEER_IDENTITY_H

#include <stdbool.h>
#include <stddef.h>

struct p2p_node;

#define ZCL_PEER_HOST_KEY_MAX 128
#define ZCL_PEER_HOST_SET_MAX 256

struct zcl_peer_host_set {
    char hosts[ZCL_PEER_HOST_SET_MAX][ZCL_PEER_HOST_KEY_MAX];
    size_t count;
    bool overflow;
};

bool zcl_peer_host_key(const struct p2p_node *node,
                       char *out,
                       size_t out_len);
void zcl_peer_host_set_init(struct zcl_peer_host_set *set);
int zcl_peer_host_set_find_host(const struct zcl_peer_host_set *set,
                                const char *host);
bool zcl_peer_host_set_add_host(struct zcl_peer_host_set *set,
                                const char *host);
bool zcl_peer_host_set_add_peer(struct zcl_peer_host_set *set,
                                const struct p2p_node *node);

#endif
