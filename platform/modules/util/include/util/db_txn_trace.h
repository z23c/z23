/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 *
 * Opt-in node.db transaction diagnostics.
 *
 * Active only when the environment variable ZCL_DB_TXN_TRACE=1 is set at
 * process start (checked once, cached). When active:
 *
 *   - Every registered node.db connection gets a SQLITE_TRACE_STMT callback
 *     that logs BEGIN / COMMIT / ROLLBACK / SAVEPOINT / RELEASE / END
 *     statements with the owner label, connection pointer, and thread id.
 *     This produces a per-connection transaction timeline.
 *
 *   - A background thread dumps sqlite3_txn_state() for every registered
 *     connection every few seconds, naming any connection sitting in a
 *     non-NONE (WRITE/READ) transaction while otherwise idle — i.e. the
 *     never-committed lock holder that starves every other node.db writer.
 *
 * Zero cost and a no-op when the env flag is unset. Intended to be safe to
 * ship: the register/unregister calls stay compiled in, but do nothing
 * unless the operator opts in. */

#ifndef ZCL_UTIL_DB_TXN_TRACE_H
#define ZCL_UTIL_DB_TXN_TRACE_H

#include <sqlite3.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* True iff ZCL_DB_TXN_TRACE=1 was set at process start. */
bool zcl_db_txn_trace_enabled(void);

/* Register a node.db connection under a human owner label (e.g. "node_db:main",
 * "node_db:private", "coins_view"). Installs the statement trace and starts the
 * background txn-state dumper on first use. No-op when tracing is disabled or
 * db is NULL. Safe to call multiple times for the same handle (re-labels). */
void zcl_db_txn_trace_register(sqlite3 *db, const char *label);

/* Drop a connection from the registry (call before sqlite3_close). No-op when
 * tracing is disabled or the handle was never registered. */
void zcl_db_txn_trace_unregister(sqlite3 *db);

/* See CLAUDE.md "Adding state introspection". Reentrant-safe; NEVER touches a
 * live sqlite handle from the caller's (RPC) thread — the per-connection
 * txn_state / busy-statement scan runs only on the background dumper thread and
 * is read here from a seqlock-published snapshot block. Emits {enabled:false}
 * when ZCL_DB_TXN_TRACE was not set at process start. */
struct json_value;
bool db_txn_trace_dump_state_json(struct json_value *out, const char *key);

#ifdef __cplusplus
}
#endif

#endif /* ZCL_UTIL_DB_TXN_TRACE_H */
