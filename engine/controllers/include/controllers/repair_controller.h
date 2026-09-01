/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

#ifndef ZCL_RPC_REPAIR_H
#define ZCL_RPC_REPAIR_H

#include "rpc/server.h"

struct main_state;
struct coins_view_cache;
struct node_db;
struct chain_params;

void rpc_repair_set_state(struct main_state *ms,
                           struct coins_view_cache *coins_tip,
                           struct node_db *ndb,
                           const char *datadir,
                           const struct chain_params *params);
void register_repair_rpc_commands(struct rpc_table *t);

/* rebuild_recent recovery RPC — fetch the recent block range from the
 * legacy advisory source and connect it through local consensus
 * validation, reorging off any stale local fork.
 * Implemented in repair_controller_rebuild.c. Shares g_repair_ctx, so
 * rpc_repair_set_state() must be called before registration. */
void register_rebuild_recent_rpc_commands(struct rpc_table *t);

/* backfill_header_solutions ( from_height ) — bulk-fill the
 * header_solution_repair side-table for [from..header_tip] from zclassicd via
 * getblock verbose=0. Additive, idempotent, hash-bound; no consensus write,
 * never moves the tip. Implemented in repair_controller_rebuild.c. */
void register_backfill_header_solutions_rpc_commands(struct rpc_table *t);

/* Programmatic entry to the same rebuild_recent recovery logic the RPC
 * runs — for self-heal Conditions that must call the validated repair
 * directly (no RPC text round-trip). Fetches the recent range from the
 * legacy advisory source starting at from_height and connects each block
 * through local consensus validation, reorging off any stale local fork.
 *
 * Returns true if the run completed (all in-range blocks fetched +
 * accepted, or an idempotent no-op because the local tip is already at/
 * above the remote). Returns false if the node is not initialized, the
 * range is invalid, zclassicd is unreachable, or a block was rejected
 * before the range completed. Bounded + idempotent (re-running once at
 * tip is a no-op). Implemented in repair_controller_rebuild.c. */
bool rebuild_recent_repair(int from_height);

#endif
