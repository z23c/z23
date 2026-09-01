/* SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Rhett Creighton
 *
 * bg_hash_verify_store_sqlite — sqlite-backed implementation of
 * bg_hash_verify_store_port.
 *
 * This adapter is the ONLY place that names the sqlite-backed node DB for
 * the bg-hash-verification subsystem. It wraps an already-open
 * `struct node_db *` (the shared node DB opened by boot) and resolves the
 * two cursor operations to the node-DB state-kv path
 * (node_db_state_get_int / node_db_state_set_int) under the fixed key
 * "bg_hash_verification_height" — byte-for-byte the key and semantics the
 * inline load_progress/save_progress used before the seam.
 *
 * It NEVER takes ownership: there is no close; the wrapped connection
 * must outlive every call through the port. `self` aliases the node_db*
 * directly — there is no separate context struct to free.
 */

#ifndef ZCL_ADAPTERS_OUTBOUND_PERSISTENCE_BG_HASH_VERIFY_STORE_SQLITE_H
#define ZCL_ADAPTERS_OUTBOUND_PERSISTENCE_BG_HASH_VERIFY_STORE_SQLITE_H

#include "ports/bg_hash_verify_store_port.h"

#include <stdbool.h>

struct node_db;

/* Bind a bg_hash_verify_store_port to an already-open node DB. The port's
 * `self` aliases `ndb`; the adapter holds no other state, so there is no
 * separate handle to free. The connection MUST outlive every call made
 * through the returned port. Returns false (and leaves *out_port
 * untouched) only if out_port is NULL — a NULL `ndb` is permitted and the
 * port methods then degrade to the "no stored cursor" / "save no-ops"
 * behaviour the inline code had against a closed DB. */
bool bg_hash_verify_store_sqlite_bind(struct node_db *ndb,
                                      struct bg_hash_verify_store_port *out_port);

#endif /* ZCL_ADAPTERS_OUTBOUND_PERSISTENCE_BG_HASH_VERIFY_STORE_SQLITE_H */
