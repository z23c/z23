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
 * it. Nothing here is new policy — each adapter forwards to the function
 * core/modules/net previously called directly.
 *
 * Registration runs from a constructor rather than app_init_services so
 * that every binary linking the composition root — node, test runner —
 * gets identical wiring with no start-order question. A binary that links
 * core/modules/net WITHOUT config/ leaves the port unset, and it fails closed.
 */

#include "config/runtime.h"
#include "config/db_service.h"
#include "config/boot_snapshot_offer.h"
#include "net/net_runtime_port.h"

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

static const struct net_runtime_port g_net_runtime_port = {
    .node_db = net_port_node_db,
    .snapshot_sync = net_port_snapshot_sync,
    .snapshot_state_is_sovereign = boot_snapshot_offer_state_is_sovereign,
    .snapshot_artifact_is_eligible = boot_snapshot_offer_artifact_is_eligible,
};

__attribute__((constructor))
static void boot_register_net_runtime_port(void)
{
    net_runtime_port_set(&g_net_runtime_port);
}
