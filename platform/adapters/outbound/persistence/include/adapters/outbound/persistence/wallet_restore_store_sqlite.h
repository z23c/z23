/* SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Rhett Creighton
 *
 * wallet_restore_store_sqlite — sqlite-backed implementation of
 * wallet_restore_store_port.
 *
 * The only place that names sqlite for the wallet-RESTORE subsystem, the
 * mirror of wallet_backup_store_sqlite. It wraps one already-open TARGET
 * connection — the node.db the caller opened through the normal schema
 * path, so every wallet table already carries its real primary keys,
 * CHECK constraints and indexes — and ATTACHes the backup file onto it
 * read-only to merge rows in.
 *
 * The adapter never takes ownership of the target handle and never opens
 * the target itself; the service owns that lifecycle so the "is a node
 * holding this datadir" refusal happens before a single byte is written.
 *
 * Key-material safety: rows move through "INSERT OR IGNORE ... SELECT",
 * so key/seed bytes are never decoded, decrypted, or returned across the
 * port — only table names and counts cross the boundary.
 */

#ifndef ZCL_ADAPTERS_OUTBOUND_PERSISTENCE_WALLET_RESTORE_STORE_SQLITE_H
#define ZCL_ADAPTERS_OUTBOUND_PERSISTENCE_WALLET_RESTORE_STORE_SQLITE_H

#include "ports/wallet_restore_store_port.h"

#include <sqlite3.h>

/* Caller-owned binding context. Holds the non-owned target connection the
 * merge writes into. Aliased by the port's `self`; must outlive every call
 * through the returned port. */
struct wallet_restore_store_sqlite_ctx {
    sqlite3 *target_db;   /* schema-correct node.db (non-owned) */
};

/* Bind a wallet_restore_store_port to an already-open target connection.
 * Returns false (leaving *out_port untouched) only if ctx or out_port is
 * NULL; a NULL target_db is permitted — merge_into_target then reports
 * WR_STORE_NO_TARGET, and inspect_backup (which needs no target) still
 * works, so a caller can inspect a backup file without a datadir. */
bool wallet_restore_store_sqlite_bind(struct wallet_restore_store_sqlite_ctx *ctx,
                                      sqlite3 *target_db,
                                      struct wallet_restore_store_port *out_port);

#endif /* ZCL_ADAPTERS_OUTBOUND_PERSISTENCE_WALLET_RESTORE_STORE_SQLITE_H */
