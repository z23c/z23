/* SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Rhett Creighton
 *
 * hodl_history_sqlite — sqlite-backed implementation of
 * hodl_history_port.
 *
 * This adapter is the ONLY place that names sqlite for the HODL-history
 * subsystem. It wraps a sqlite3* opened elsewhere (the shared node DB)
 * and never takes ownership of the connection — close() just drops the
 * port binding, it does NOT close the handle.
 *
 * Query semantics are byte-for-byte the ones hodl_history_service.c used
 * before the seam: the alive-at-H aggregate, the block-time lookup, the
 * INSERT OR REPLACE upsert, the MAX(height) cursor, and the ordered
 * load. See the port header for the contract each method honours.
 */

#ifndef ZCL_ADAPTERS_OUTBOUND_PERSISTENCE_HODL_HISTORY_SQLITE_H
#define ZCL_ADAPTERS_OUTBOUND_PERSISTENCE_HODL_HISTORY_SQLITE_H

#include "ports/hodl_history_port.h"

#include <sqlite3.h>

/* Bind a hodl_history_port to an already-open sqlite3 connection. The
 * port's `self` aliases `db`; the adapter holds no other state, so there
 * is no separate handle to free. The connection MUST outlive every call
 * made through the returned port. Returns false (and leaves *out_port
 * untouched) only if either argument is NULL. */
bool hodl_history_sqlite_bind(sqlite3 *db, struct hodl_history_port *out_port);

#endif /* ZCL_ADAPTERS_OUTBOUND_PERSISTENCE_HODL_HISTORY_SQLITE_H */
