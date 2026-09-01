/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 *
 * net_runtime_port — see net/net_runtime_port.h for the contract.
 *
 * The port pointer is published once by the composition root before any
 * P2P thread is spawned and read from those threads afterwards, so a
 * relaxed atomic load is enough: there is no data race on the pointer and
 * the pointee is immutable static storage. */

#include "net/net_runtime_port.h"

#include <stdatomic.h>
#include <string.h>

static const struct net_runtime_port *_Atomic g_net_runtime_port = NULL;

void net_runtime_port_set(const struct net_runtime_port *port)
{
    atomic_store_explicit(&g_net_runtime_port, port, memory_order_release);
}

static const struct net_runtime_port *port_get(void)
{
    return atomic_load_explicit(&g_net_runtime_port, memory_order_acquire);
}

/* Fail-closed reason text, so a caller that asked for one never reads an
 * uninitialised buffer when the composition root is absent. */
static void port_absent_reason(char *reason, size_t reason_size)
{
    if (!reason || reason_size == 0)
        return;
    const char *msg = "net runtime port not registered";
    size_t n = strlen(msg);
    if (n >= reason_size)
        n = reason_size - 1;
    memcpy(reason, msg, n);
    reason[n] = '\0';
}

struct node_db *net_runtime_node_db(const struct app_runtime_context *runtime)
{
    const struct net_runtime_port *p = port_get();
    if (!p || !p->node_db)
        return NULL;
    return p->node_db(runtime);
}

struct snapshot_sync_service *net_runtime_snapshot_sync(
    const struct app_runtime_context *runtime)
{
    const struct net_runtime_port *p = port_get();
    if (!p || !p->snapshot_sync)
        return NULL;
    return p->snapshot_sync(runtime);
}

bool net_runtime_snapshot_state_is_sovereign(char *reason, size_t reason_size)
{
    const struct net_runtime_port *p = port_get();
    if (!p || !p->snapshot_state_is_sovereign) {
        port_absent_reason(reason, reason_size);
        return false;
    }
    return p->snapshot_state_is_sovereign(reason, reason_size);
}

bool net_runtime_snapshot_artifact_is_eligible(const char *datadir,
                                                char *reason,
                                                size_t reason_size)
{
    const struct net_runtime_port *p = port_get();
    if (!p || !p->snapshot_artifact_is_eligible) {
        port_absent_reason(reason, reason_size);
        return false;
    }
    return p->snapshot_artifact_is_eligible(datadir, reason, reason_size);
}
