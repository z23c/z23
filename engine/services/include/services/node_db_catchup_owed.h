/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. */

/* The turbo-mode restore a yielded catchup pass still owes, and the
 * sync-controller turbo scope it is kept in. A pass that yields inside
 * another writer's transaction cannot restore normal mode there, so the
 * scope is handed to this module and restored by the next idle pass. */

#ifndef ZCL_SERVICES_NODE_DB_CATCHUP_OWED_H
#define ZCL_SERVICES_NODE_DB_CATCHUP_OWED_H

#include <stdbool.h>

struct node_db;

/* Sync-controller turbo scope, declared in the controller-private
 * sync_controller_internal.h (not on the services include path); mirrored
 * here verbatim, defined in sync_controller.c. */
struct sync_db_turbo_scope {
    struct node_db *ndb;
    bool entered;
};

bool sync_db_turbo_scope_begin(struct sync_db_turbo_scope *scope,
                               struct node_db *ndb,
                               bool enabled);
bool sync_db_turbo_scope_end(struct sync_db_turbo_scope *scope);

/* Take over an entered scope whose restore cannot run now; the caller's
 * scope is left not entered. */
void node_db_catchup_owed_defer(struct sync_db_turbo_scope *scope);

#endif /* ZCL_SERVICES_NODE_DB_CATCHUP_OWED_H */
