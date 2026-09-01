/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Diagnostics controller — hosts read-only introspection RPC methods
 * for AI agents and power-dev users:
 *
 *   dumpstate <subsystem> [key]   — generic in-process state dump,
 *                                   dispatches to <subsystem>_dump_state_json
 *   statecatalog                  — machine-readable dumpstate catalog
 *   getnodelog <pattern> ...      — reverse-scan node.log with regex/level
 *   dbquery <sql> [limit]         — SELECT-only SQLite passthrough
 *
 * These primitives let native clients inspect runtime state without one
 * dedicated command per question. */

#ifndef ZCL_DIAGNOSTICS_CONTROLLER_H
#define ZCL_DIAGNOSTICS_CONTROLLER_H

#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>
#include <sqlite3.h>

struct rpc_table;
struct main_state;
struct json_value;

/* diagnostics_machine_identity.c — one redacted, read-only projection of the
 * running machine's build, transport, authenticated-DHT and platform facts
 * (schema zcl.machine_mesh_identity.v1). Declared publicly so the mesh
 * status responder (config/boot_mesh_status.c) can serve the exact capsule
 * the operator sees locally; it creates no identity and grants no pairing or
 * remote-control authority. */
bool machine_identity_dump_state_json(struct json_value *out,
                                      const char *key);

/* Wire main_state for subsystems that look up chain state (block_index
 * dumps, lastboot, etc). Call once after main_state is initialized. */
void diagnostics_controller_set_state(struct main_state *ms,
                                      const char *datadir);

/* Quiesce and join diagnostics workers before releasing state they inspect.
 * False means ownership could not be proven and teardown must stop. */
bool diagnostics_controller_shutdown(void);

void register_diagnostics_rpc_commands(struct rpc_table *t);

/* Return the machine-readable catalog of `dumpstate` subsystems. Exposed so
 * the native CLI can serve `z23 statecatalog`
 * directly without depending on a running RPC node. */
bool diag_rpc_statecatalog(const struct json_value *params, bool help,
                           struct json_value *result);

/* Fill `out` with a comma-separated list of every subsystem name accepted
 * by `dumpstate`. The list is
 * derived from the live g_dumpers registry, so adding a descriptor to
 * diagnostics_dumpers.def automatically propagates here. Truncates on
 * overflow; returns the unclamped length (snprintf-style). */
int diagnostics_subsystems_csv(char *out, size_t out_sz);

/* Shared SELECT-only executor behind `dbquery` / core.storage.query
 * (engine/controllers/src/dbquery_controller.c). Validates SELECT-only, no
 * semicolons, no DDL/DML keywords, no wallet secret-material reference,
 * auto-appends LIMIT if missing, enforces the 2 s wall-clock budget and the
 * 100-row hard cap, then fills `result` with
 * {columns,rows,row_count,truncated,interrupted,elapsed_ms,sql_executed} on
 * success. On any validation or execution failure, sets `result` to a plain
 * error string (not an object) and returns false — mirrors the `dbquery` RPC
 * method's own error-body contract.
 *
 * `db` is any already-open SQLite handle: the live node's node.db (via
 * app_runtime_node_db(), as diag_rpc_dbquery uses it), or an ad hoc
 * SQLITE_OPEN_READONLY handle opened against a copied/stopped datadir's
 * node.db — exactly what core.storage.query.offline
 * (tools/command/native_offline_query.c) does so a fixture datadir can be
 * inspected without booting a node or reaching a running node's RPC. */
bool dbquery_execute(sqlite3 *db, const char *sql_in, int64_t limit,
                     struct json_value *result);

#endif /* ZCL_DIAGNOSTICS_CONTROLLER_H */
