/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 *
 * boot_net_runtime_port — the composition root's side of net/net_runtime_port.h.
 *
 * config/ wires the process together and therefore sits ABOVE lib/. core/modules/net
 * used to call straight back down into config/ by name (db_service_node_db,
 * boot_snapshot_offer_state_is_sovereign,
 * boot_snapshot_offer_artifact_is_eligible), which made the two layers
 * mutually dependent. core/modules/net now declares what it needs; this file supplies
 * it. Serving callbacks defer optional work while the host requests cooling.
 *
 * Registration runs from a constructor rather than app_init_services so
 * that every binary linking the composition root — node, test runner —
 * gets identical wiring with no start-order question. A binary that links
 * core/modules/net WITHOUT config/ leaves the port unset, and it fails closed.
 */

#include "config/runtime.h"
#include "config/boot.h"
#include "config/db_service.h"
#include "config/boot_snapshot_offer.h"
#include "net/net_runtime_port.h"
#include "jobs/node_pace.h"
#include <stdio.h>

static struct node_db *net_port_node_db(
    const struct app_runtime_context *runtime)
{
    if (!runtime || !runtime->db_service)
        return NULL;
    return db_service_node_db(runtime->db_service);
}

static struct snapshot_sync_service *net_port_snapshot_sync(
    const struct app_runtime_context *runtime)
{
    return runtime ? runtime->snapshot_sync : NULL;
}

static bool net_port_cooling(char *reason, size_t size)
{
    node_pace_poll();
    if (node_pace_get() != NODE_PACE_PAUSE)
        return false;
    if (reason && size)
        (void)snprintf(reason, size, "node_cooling");
    return true;
}

static bool net_port_deferred(char *reason, size_t size)
{
    if (!app_is_running()) {
        if (reason && size)
            (void)snprintf(reason, size, "node_not_running");
        return true;
    }
    return net_port_cooling(reason, size);
}

static bool net_port_block_can_serve(char *reason, size_t size)
{
    return !net_port_deferred(reason, size) &&
           boot_block_swarm_state_can_serve(reason, size);
}

static bool net_port_snapshot_sovereign(char *reason, size_t size)
{
    return !net_port_deferred(reason, size) &&
           boot_snapshot_offer_state_is_sovereign(reason, size);
}

static bool net_port_snapshot_eligible(const char *datadir, char *reason, size_t size)
{
    return !net_port_deferred(reason, size) &&
           boot_snapshot_offer_artifact_is_eligible(datadir, reason, size);
}

static const struct net_runtime_port g_net_runtime_port = {
    .node_db = net_port_node_db,
    .snapshot_sync = net_port_snapshot_sync,
    .block_state_can_serve = net_port_block_can_serve,
    .snapshot_state_is_sovereign = net_port_snapshot_sovereign,
    .snapshot_artifact_is_eligible = net_port_snapshot_eligible,
};

__attribute__((constructor))
static void boot_register_net_runtime_port(void)
{
    net_runtime_port_set(&g_net_runtime_port);
}
