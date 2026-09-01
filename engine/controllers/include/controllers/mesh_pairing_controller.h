/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: Owner-only local RPC surface for machine pairing inspection and
 * revocation. */

#ifndef ZCL_CONTROLLERS_MESH_PAIRING_CONTROLLER_H
#define ZCL_CONTROLLERS_MESH_PAIRING_CONTROLLER_H

#include "models/database.h"
#include "rpc/server.h"

/* Registers only redacted list and revoke plan/commit. Pairing acceptance
 * remains exclusively bound to an authenticated live Noise/ZID session. */
void register_mesh_pairing_rpc_commands(struct rpc_table *table,
                                        struct node_db *ndb);

#endif /* ZCL_CONTROLLERS_MESH_PAIRING_CONTROLLER_H */
