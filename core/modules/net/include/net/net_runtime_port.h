/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 *
 * net_runtime_port — the one seam through which core/modules/net reaches the
 * composition root.
 *
 * config/ wires the process together and therefore sits ABOVE lib/. Before
 * this port existed, three core/modules/net translation units called straight into
 * config/ (db_service_node_db, boot_snapshot_offer_state_is_sovereign,
 * boot_snapshot_offer_artifact_is_eligible), which made core/modules/net and config/
 * mutually dependent: config/ composes the message processor, and the
 * message processor called back into config/ by name.
 *
 * The direction is now one-way. core/modules/net declares what it needs; config/
 * registers the implementations at process start. Nothing in core/modules/net names
 * a config/ symbol.
 *
 * FAIL-CLOSED: with no port registered every accessor returns NULL/false.
 * A binary that links core/modules/net without the composition root (a fuzz target,
 * a tool) therefore serves nothing rather than serving unverified state.
 */

#ifndef ZCL_NET_RUNTIME_PORT_H
#define ZCL_NET_RUNTIME_PORT_H

#include <stdbool.h>
#include <stddef.h>

struct app_runtime_context;
struct node_db;
struct snapshot_sync_service;

/* Implementations supplied by the composition root. Every member may be
 * NULL; each accessor below degrades to its fail-closed answer. */
struct net_runtime_port {
    /* Node database handle owned by the runtime's db_service, or NULL. */
    struct node_db *(*node_db)(const struct app_runtime_context *runtime);
    /* Snapshot-sync service owned by the runtime, or NULL. */
    struct snapshot_sync_service *(*snapshot_sync)(
        const struct app_runtime_context *runtime);
    /* Trust policy for serving locally validated block bodies. This is
     * deliberately separate from snapshot export authority: a block remains
     * independently bound to the requester's admitted header chain. */
    bool (*block_state_can_serve)(char *reason, size_t reason_size);
    /* Trust policy behind snapshot re-serving; see
     * config/boot_snapshot_offer.h for the fail-closed contract. */
    bool (*snapshot_state_is_sovereign)(char *reason, size_t reason_size);
    bool (*snapshot_artifact_is_eligible)(const char *datadir,
                                          char *reason,
                                          size_t reason_size);
};

/* Install the port. `port` is borrowed and must have static storage
 * duration; pass NULL to unregister (fail-closed). Called once from the
 * composition root before any P2P thread starts. */
void net_runtime_port_set(const struct net_runtime_port *port);

struct node_db *net_runtime_node_db(
    const struct app_runtime_context *runtime);
struct snapshot_sync_service *net_runtime_snapshot_sync(
    const struct app_runtime_context *runtime);
bool net_runtime_block_state_can_serve(char *reason, size_t reason_size);
bool net_runtime_snapshot_state_is_sovereign(char *reason,
                                             size_t reason_size);
bool net_runtime_snapshot_artifact_is_eligible(const char *datadir,
                                                char *reason,
                                                size_t reason_size);

#endif
