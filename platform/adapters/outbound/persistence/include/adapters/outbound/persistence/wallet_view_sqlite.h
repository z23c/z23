/* SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Rhett Creighton
 *
 * wallet_view_sqlite — sqlite-backed implementation of wallet_view_port.
 *
 * This adapter is the ONLY place that names sqlite for the wallet-view
 * subsystem. It wraps a sqlite3* opened elsewhere (the shared node DB)
 * and never takes ownership of the connection — there is no close(); the
 * port binding just aliases the handle.
 *
 * Query semantics are byte-for-byte the ones wallet_view_projection.c
 * used before the seam: the ordered sapling receive-address list and the
 * top-10 held-token aggregate. See the port header for the contract each
 * method honours.
 */

#ifndef ZCL_ADAPTERS_OUTBOUND_PERSISTENCE_WALLET_VIEW_SQLITE_H
#define ZCL_ADAPTERS_OUTBOUND_PERSISTENCE_WALLET_VIEW_SQLITE_H

#include "ports/wallet_view_port.h"

#include <sqlite3.h>
#include <stdbool.h>

/* Bind a wallet_view_port to an already-open sqlite3 connection. The
 * port's `self` aliases `db`; the adapter holds no other state, so there
 * is no separate handle to free. The connection MUST outlive every call
 * made through the returned port. Returns false (and leaves *out_port
 * untouched) only if either argument is NULL. */
bool wallet_view_sqlite_bind(sqlite3 *db, struct wallet_view_port *out_port);

#endif /* ZCL_ADAPTERS_OUTBOUND_PERSISTENCE_WALLET_VIEW_SQLITE_H */
