/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. */

/* Narrow internal seam between net.c and the inbound server path split out
 * into net_listen.c. Nothing here is part of the public net API — it exists
 * only so the two translation units can share one node-table helper instead
 * of each keeping its own copy. */

#ifndef ZCL_NET_INTERNAL_H
#define ZCL_NET_INTERNAL_H

#include "net/net.h"

/* Append an already-constructed node to nm->nodes[], growing the array if
 * needed. CALLER MUST HOLD nm->cs_nodes. Defined in net.c; also used by the
 * accept path in net_listen.c. */
bool nm_add_node(struct net_manager *nm, struct p2p_node *node);

#endif /* ZCL_NET_INTERNAL_H */
