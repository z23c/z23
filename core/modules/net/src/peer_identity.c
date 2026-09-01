/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. */

#include "net/peer_identity.h"

#include "net/net.h"
#include "net/netaddr.h"
#include <stdio.h>
#include <string.h>

bool zcl_peer_host_key(const struct p2p_node *node,
                       char *out,
                       size_t out_len)
{
    int n;

    if (!out || out_len == 0)
        return false;
    out[0] = '\0';
    if (!node)
        return false;

    n = net_addr_to_string(&node->addr.svc.addr, out, out_len);
    if (n > 0 && (size_t)n < out_len && out[0] != '\0')
        return true;

    if (node->addr_name[0] == '[') {
        const char *end = strchr(node->addr_name, ']');
        size_t len;

        if (!end || end == node->addr_name + 1)
            return false;
        len = (size_t)(end - node->addr_name - 1);
        if (len >= out_len)
            return false;
        memcpy(out, node->addr_name + 1, len);
        out[len] = '\0';
        return true;
    }

    {
        size_t len = strcspn(node->addr_name, ":");
        if (len == 0 || len >= out_len)
            return false;
        memcpy(out, node->addr_name, len);
        out[len] = '\0';
    }
    return true;
}

void zcl_peer_host_set_init(struct zcl_peer_host_set *set)
{
    if (!set)
        return;
    memset(set, 0, sizeof(*set));
}

int zcl_peer_host_set_find_host(const struct zcl_peer_host_set *set,
                                const char *host)
{
    if (!set || !host || host[0] == '\0')
        return -1;
    for (size_t i = 0; i < set->count; i++) {
        if (strcmp(set->hosts[i], host) == 0)
            return (int)i;
    }
    return -1;
}

bool zcl_peer_host_set_add_host(struct zcl_peer_host_set *set,
                                const char *host)
{
    if (!set || !host || host[0] == '\0')
        return false;
    if (zcl_peer_host_set_find_host(set, host) >= 0)
        return false;
    if (set->count >= ZCL_PEER_HOST_SET_MAX) {
        set->overflow = true;
        return true;
    }
    snprintf(set->hosts[set->count], sizeof(set->hosts[set->count]),
             "%s", host);
    set->count++;
    return true;
}

bool zcl_peer_host_set_add_peer(struct zcl_peer_host_set *set,
                                const struct p2p_node *node)
{
    char host[ZCL_PEER_HOST_KEY_MAX];

    if (!zcl_peer_host_key(node, host, sizeof(host)))
        return false;
    return zcl_peer_host_set_add_host(set, host);
}
