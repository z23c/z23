/* SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Rhett Creighton
 *
 * wallet_backup_store_sqlite — sqlite-backed implementation of
 * wallet_backup_store_port.
 *
 * This adapter is the ONLY place that names sqlite for the wallet-backup
 * subsystem. The four methods hold the raw reads/writes that used to live
 * inline in contexts/wallet/services/src/wallet_backup_service.c, moved here with
 * byte-for-byte identical SQL text, the same ATTACH/CREATE-TABLE-AS-SELECT
 * strategy, the same per-table existence probe, and the same open flags,
 * so the produced backup file is identical to before the seam.
 *
 * It wraps one already-open connection: the node_db that owns the wallet
 * tables. The bind stores that handle in a small caller-owned context so
 * the port's `self` carries it without leaking a sqlite type through the
 * port header. The adapter NEVER takes ownership of the source handle —
 * there is no close for it. The write/verify methods open and close their
 * OWN destination connections internally, exactly as the inline code did.
 *
 * Key-material safety: rows are copied through sqlite's own
 * "CREATE TABLE AS SELECT"; no wallet key, privkey, or seed bytes are ever
 * decoded or returned through the port — only paths, counts, and a stage
 * code cross the boundary.
 */

#ifndef ZCL_ADAPTERS_OUTBOUND_PERSISTENCE_WALLET_BACKUP_STORE_SQLITE_H
#define ZCL_ADAPTERS_OUTBOUND_PERSISTENCE_WALLET_BACKUP_STORE_SQLITE_H

#include "ports/wallet_backup_store_port.h"

#include <sqlite3.h>

/* Caller-owned binding context. Holds the non-owned source connection the
 * reads operate on. Aliased by the port's `self`; must outlive every call
 * through the returned port. */
struct wallet_backup_store_sqlite_ctx {
    sqlite3 *src_db;   /* node_db that owns the wallet_* tables (non-owned) */
};

/* Bind a wallet_backup_store_port to an already-open source sqlite3
 * connection. `ctx` is caller-owned storage the port's `self` will alias;
 * it must outlive every call through the returned port. Returns false (and
 * leaves *out_port / *ctx untouched) only if ctx or out_port is NULL; a
 * NULL src_db is permitted (the source-reading methods then return
 * false/-1, mirroring the original "db not open" behaviour). */
bool wallet_backup_store_sqlite_bind(struct wallet_backup_store_sqlite_ctx *ctx,
                                     sqlite3 *src_db,
                                     struct wallet_backup_store_port *out_port);

#endif /* ZCL_ADAPTERS_OUTBOUND_PERSISTENCE_WALLET_BACKUP_STORE_SQLITE_H */
