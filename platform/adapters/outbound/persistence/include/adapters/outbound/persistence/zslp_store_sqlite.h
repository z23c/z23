/* SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Rhett Creighton
 *
 * zslp_store_sqlite — sqlite-backed implementation of zslp_store_port.
 *
 * This adapter is the ONLY place that names sqlite for the ZSLP token
 * subsystem. It performs the single connection-open path the service used
 * inline before the seam: sqlite3_open("<datadir>/node.db"),
 * sqlite3_busy_timeout(..., 5000), and the CREATE TABLE IF NOT EXISTS
 * zslp_balances(...) DDL — byte-for-byte the same calls, in the same order,
 * so the on-disk store the model layer then reads/writes is identical.
 *
 * The adapter is stateless: open() returns a fresh caller-OWNED handle and
 * close() releases it. There is no held connection, so the bind takes no
 * connection and the port's `self` is unused (NULL). The opaque void* the
 * port traffics in is a sqlite3* under the hood; only this file knows that.
 */

#ifndef ZCL_ADAPTERS_OUTBOUND_PERSISTENCE_ZSLP_STORE_SQLITE_H
#define ZCL_ADAPTERS_OUTBOUND_PERSISTENCE_ZSLP_STORE_SQLITE_H

#include "ports/zslp_store_port.h"

/* Bind a zslp_store_port to the stateless sqlite open/close adapter.
 * Returns false (and leaves *out_port untouched) only if out_port is NULL.
 * The adapter holds no state, so there is nothing for the caller to keep
 * alive beyond the port struct itself. */
bool zslp_store_sqlite_bind(struct zslp_store_port *out_port);

#endif /* ZCL_ADAPTERS_OUTBOUND_PERSISTENCE_ZSLP_STORE_SQLITE_H */
