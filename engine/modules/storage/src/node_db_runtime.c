/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 *
 * node_db_runtime — see storage/node_db_runtime.h for the contract.
 *
 * The port pointer is published once by the composition root before the
 * reducer and P2P threads exist and is read-only afterwards, so an acquire
 * load is enough: the pointee is immutable static storage. */

#include "storage/node_db_runtime.h"

#include <stdatomic.h>

static const struct node_db_runtime_port *_Atomic g_node_db_runtime_port = NULL;

void node_db_runtime_port_set(const struct node_db_runtime_port *port)
{
    atomic_store_explicit(&g_node_db_runtime_port, port, memory_order_release);
}

static const struct node_db_runtime_port *port_get(void)
{
    return atomic_load_explicit(&g_node_db_runtime_port, memory_order_acquire);
}

struct node_db *node_db_runtime(void)
{
    const struct node_db_runtime_port *p = port_get();
    if (!p || !p->handle)
        return NULL;
    return p->handle();
}

bool node_db_runtime_handle_open(const struct node_db *ndb)
{
    const struct node_db_runtime_port *p = port_get();
    if (!p || !p->handle_open)
        return false;
    return p->handle_open(ndb);
}

bool node_db_runtime_state_set(struct node_db *ndb, const char *key,
                               const void *value, size_t len)
{
    const struct node_db_runtime_port *p = port_get();
    if (!p || !p->state_set)
        return false;
    return p->state_set(ndb, key, value, len);
}

int node_db_runtime_utxo_max_height(struct node_db *ndb)
{
    const struct node_db_runtime_port *p = port_get();
    if (!p || !p->utxo_max_height)
        return 0;
    return p->utxo_max_height(ndb);
}

bool node_db_runtime_load_header_by_hash_height(
    int height, const uint8_t hash[32], struct block_header *out)
{
    const struct node_db_runtime_port *p = port_get();
    if (!p || !p->load_header_by_hash_height)
        return false;
    return p->load_header_by_hash_height(height, hash, out);
}
