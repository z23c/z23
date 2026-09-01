/* SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Rhett Creighton
 *
 * node_health_store_sqlite — sqlite-backed implementation of
 * node_health_store_port.
 *
 * This adapter is the ONLY place that names sqlite for the node-health
 * subsystem. node_health_collect() performs exactly three storage reads;
 * this adapter holds them behind the port with byte-for-byte identical
 * SQL and the same WAL stat() so `z23 status` and metrics
 * surface is unchanged.
 *
 * It wraps two already-open connections opened elsewhere:
 *   query_db — the shared read connection used for the two SELECTs
 *              (tip-height fallback, utxo-count fallback).
 *   node_db  — the primary write connection whose filename we resolve to
 *              stat the "-wal" file.
 * Either may be NULL (the matching methods then return false, mirroring
 * the original "no row / no path" behaviour). The adapter NEVER takes
 * ownership: there is no close — both handles must outlive the port.
 *
 * The bind stores the two handles in a small caller-owned context so the
 * port's `self` carries both without leaking a sqlite type through the
 * port header. The context must outlive every call through the port.
 */

#ifndef ZCL_ADAPTERS_OUTBOUND_PERSISTENCE_NODE_HEALTH_STORE_SQLITE_H
#define ZCL_ADAPTERS_OUTBOUND_PERSISTENCE_NODE_HEALTH_STORE_SQLITE_H

#include "ports/node_health_store_port.h"

#include <sqlite3.h>

/* Caller-owned binding context. Holds the two non-owned connections the
 * three reads operate on. Aliased by the port's `self`. */
struct node_health_store_sqlite_ctx {
    sqlite3 *query_db;   /* the two SELECTs read this one (may be NULL) */
    sqlite3 *node_db;    /* WAL stat resolves this one's filename (NULL ok) */
};

/* Bind a node_health_store_port to two already-open sqlite3 connections.
 * `ctx` is caller-owned storage the port's `self` will alias; it must
 * outlive every call through the returned port. Returns false (and leaves
 * *out_port / *ctx untouched) only if ctx or out_port is NULL — either
 * connection may legitimately be NULL. */
bool node_health_store_sqlite_bind(struct node_health_store_sqlite_ctx *ctx,
                                   sqlite3 *query_db,
                                   sqlite3 *node_db,
                                   struct node_health_store_port *out_port);

#endif /* ZCL_ADAPTERS_OUTBOUND_PERSISTENCE_NODE_HEALTH_STORE_SQLITE_H */
