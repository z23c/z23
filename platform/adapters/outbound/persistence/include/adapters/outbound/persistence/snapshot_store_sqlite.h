/* SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Rhett Creighton
 *
 * snapshot_store_sqlite — sqlite-backed implementation of
 * snapshot_store_port.
 *
 * This adapter is the ONLY place that names sqlite for the fast-sync
 * snapshot subsystem. Its methods hold the raw sqlite reads/writes for
 * the snapshot path: the SQL text, bind order, open connection, and step
 * macros are fixed so the staging rows written and the counts read stay
 * byte-for-byte identical to the inline service code they replace.
 *
 * The subsystem is CONSENSUS-ADJACENT (the snapshot is pinned to a
 * SHA3-256 commitment), so this adapter touches ONLY the storage access
 * around the commitment — never the commitment computation itself, which
 * stays in the service.
 *
 * It wraps one already-open connection: the node_db that owns the utxos /
 * snapshot_staging_utxos / blocks tables and the cached
 * stmt_snapshot_staging_insert statement. The bind stores that node_db in
 * a small caller-owned context so the port's `self` carries it without
 * leaking a sqlite type through the port header. The adapter NEVER takes
 * ownership of the connection — there is no close for it.
 */

#ifndef ZCL_ADAPTERS_OUTBOUND_PERSISTENCE_SNAPSHOT_STORE_SQLITE_H
#define ZCL_ADAPTERS_OUTBOUND_PERSISTENCE_SNAPSHOT_STORE_SQLITE_H

#include "ports/snapshot_store_port.h"

struct node_db;   /* models/database.h — holds sqlite3 *db + cached stmts */

/* Caller-owned binding context. Holds the non-owned node_db the reads and
 * the cached staging insert operate on. Aliased by the port's `self`; must
 * outlive every call through the returned port. */
struct snapshot_store_sqlite_ctx {
    struct node_db *ndb;   /* node_db that owns utxos / staging / blocks (non-owned) */
};

/* Bind a snapshot_store_port to an already-open node_db. `ctx` is
 * caller-owned storage the port's `self` will alias; it must outlive every
 * call through the returned port. Returns false (and leaves *out_port / *ctx
 * untouched) only if ctx or out_port is NULL; a NULL ndb is permitted (the
 * methods then return false/-1, db-not-open). */
bool snapshot_store_sqlite_bind(struct snapshot_store_sqlite_ctx *ctx,
                                struct node_db *ndb,
                                struct snapshot_store_port *out_port);

#endif /* ZCL_ADAPTERS_OUTBOUND_PERSISTENCE_SNAPSHOT_STORE_SQLITE_H */
