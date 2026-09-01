/* SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Rhett Creighton
 *
 * block_index_sidecar_sqlite — sqlite-backed implementation of
 * block_index_sidecar_port.
 *
 * This adapter is the ONLY place that names sqlite for the block-index
 * sidecar integrity cross-check. Its single method runs the exact
 * SELECT the verifier used inline before the seam
 * ("SELECT height FROM blocks WHERE hash=?", blob-bound, readonly
 * single-shot step), so bii_verify()'s verdict surface is bit-for-bit
 * identical.
 *
 * It wraps a single already-open sqlite3* (the primary node DB
 * connection) opened elsewhere and NEVER takes ownership: there is no
 * close — the handle must outlive every call made through the port.
 *
 * The bind stores the handle in a small caller-owned context so the
 * port's `self` carries it without leaking a sqlite type through the
 * port header. The context must outlive every call through the port.
 */

#ifndef ZCL_ADAPTERS_OUTBOUND_PERSISTENCE_BLOCK_INDEX_SIDECAR_SQLITE_H
#define ZCL_ADAPTERS_OUTBOUND_PERSISTENCE_BLOCK_INDEX_SIDECAR_SQLITE_H

#include "ports/block_index_sidecar_port.h"

#include <sqlite3.h>

/* Caller-owned binding context. Holds the non-owned connection the
 * cross-check reads against. Aliased by the port's `self`. */
struct block_index_sidecar_sqlite_ctx {
    sqlite3 *db;   /* cross-check reads against this one (may be NULL) */
};

/* Bind a block_index_sidecar_port to an already-open sqlite3
 * connection. `ctx` is caller-owned storage the port's `self` will
 * alias; it must outlive every call through the returned port. `db`
 * may be NULL (lookup then returns BII_HEIGHT_UNAVAILABLE, mirroring
 * the inline "no db -> skip cross-check" guard). Returns false (and
 * leaves *out_port / *ctx untouched) only if ctx or out_port is NULL. */
bool block_index_sidecar_sqlite_bind(struct block_index_sidecar_sqlite_ctx *ctx,
                                     sqlite3 *db,
                                     struct block_index_sidecar_port *out_port);

#endif /* ZCL_ADAPTERS_OUTBOUND_PERSISTENCE_BLOCK_INDEX_SIDECAR_SQLITE_H */
