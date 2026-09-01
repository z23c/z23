/* SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Rhett Creighton
 *
 * db_maintenance_sqlite — sqlite-backed implementation of
 * db_maintenance_port.
 *
 * This adapter is the ONLY place that names sqlite for the
 * db_maintenance subsystem. The three methods run the exact maintenance
 * statements the scheduler used inline before the seam
 * (PRAGMA wal_checkpoint(TRUNCATE) / ANALYZE / VACUUM), so the
 * EV_DB_MAINTENANCE_* timing/observability surface is unchanged. The
 * checkpoint runs through sqlite3_wal_checkpoint_v2 rather than exec,
 * because exec with a NULL callback discards the result row carrying the
 * frame counts and the busy flag — the only fields that say whether the
 * checkpoint reclaimed anything.
 *
 * It wraps a single already-open sqlite3* (the primary node DB
 * connection) opened elsewhere and NEVER takes ownership: there is no
 * close — the handle must outlive every call made through the port.
 *
 * The bind stores the handle in a small caller-owned context so the
 * port's `self` carries it without leaking a sqlite type through the
 * port header. The context must outlive every call through the port.
 */

#ifndef ZCL_ADAPTERS_OUTBOUND_PERSISTENCE_DB_MAINTENANCE_SQLITE_H
#define ZCL_ADAPTERS_OUTBOUND_PERSISTENCE_DB_MAINTENANCE_SQLITE_H

#include "ports/db_maintenance_port.h"

#include <sqlite3.h>

/* Caller-owned binding context. Holds the non-owned connection the three
 * maintenance ops execute against. Aliased by the port's `self`. */
struct db_maintenance_sqlite_ctx {
    sqlite3 *db;   /* maintenance ops exec against this one (may be NULL) */
};

/* Bind a db_maintenance_port to an already-open sqlite3 connection.
 * `ctx` is caller-owned storage the port's `self` will alias; it must
 * outlive every call through the returned port. `db` may be NULL (the
 * methods then return false with a "no db" message, mirroring the
 * original null guard). Returns false (and leaves *out_port / *ctx
 * untouched) only if ctx or out_port is NULL. */
bool db_maintenance_sqlite_bind(struct db_maintenance_sqlite_ctx *ctx,
                                sqlite3 *db,
                                struct db_maintenance_port *out_port);

#endif /* ZCL_ADAPTERS_OUTBOUND_PERSISTENCE_DB_MAINTENANCE_SQLITE_H */
