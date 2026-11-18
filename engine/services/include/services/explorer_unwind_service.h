/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. */

#ifndef ZCL_SERVICES_EXPLORER_UNWIND_SERVICE_H
#define ZCL_SERVICES_EXPLORER_UNWIND_SERVICE_H

/* Reorg unwind of the explorer projection and its on-chain overlays.
 *
 * Make the projection and every overlay exactly what they would be had only
 * the blocks at heights <= fork_height ever been indexed. Called when the
 * catchup cursor is rewound below a block a reorg removed, so the ascending
 * re-walk applies the winners onto the right state.
 *
 *   - rows stamped above fork_height are deleted (tx_outputs, tx_inputs,
 *     op_returns, sapling/joinsplit rows, view_integrity, op_return_index,
 *     zslp_transfers / zslp_validity / zslp_ledger / zslp_tokens, zanc);
 *   - ZNAM / ZID / ZDIR rows are mutated in place, so when the stale range
 *     held any such operation (or such a row was last touched above the
 *     fork) those tables are cleared and re-folded from the operations at
 *     heights <= fork_height, in block order, through `read`;
 *   - the zslp_ledger and op_return_index catalogs rewind EXACTLY (cursor =
 *     fork, digest from their bounded digest history) when the fork is
 *     within CATALOG_HISTORY_DEPTH of their cursor, else they are truncated
 *     for their own services to re-derive;
 *   - `transactions` rows above the fork whose block hash is not the active
 *     chain's hash at that height are deleted, when `active_hash` is given.
 *
 * `read` fills one block of the ACTIVE chain at `height` (the caller owns it
 * and block_free()s it afterwards). It is only called when a replay is
 * needed and may be NULL, in which case such a replay fails. One
 * transaction: on any failure nothing changes and the result carries the
 * reason. node.db only; never consulted by consensus.
 *
 * CONCURRENCY. The unwind takes the zslp_ledger and op_return_index fold
 * guards (zslp_ledger first) around its transaction and waits for them for a
 * bounded time. If a fold still holds one it returns
 * EXPLORER_UNWIND_ERR_BUSY having changed NOTHING: the caller must then not
 * rewind its cursor and retries on its next tick. The same answer comes back
 * when the shared node.db connection is inside another writer's transaction
 * (the unwind cannot open its own). */

#include "models/catalog_digest_history.h"
#include "util/result.h"

#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>

struct node_db;
struct block;

#define EXPLORER_UNWIND_ERR_BUSY (-5)
#define EXPLORER_UNWIND_ERR_HOOK (-6)

/* The persistent "projection needs repair" signal: raised (BLOCKER_DEPENDENCY,
 * owner-bound, listed by `dumpstate blocker`) when an
 * unwind fails after the catchup cursor has moved on, so the losing branch may
 * still sit in the projection. Cleared by the next successful unwind or by a
 * completed -reindex-explorer. */
/* blocker-id: explorer.unwind_failed */
#define EXPLORER_UNWIND_BLOCKER_ID "explorer.unwind_failed"

typedef bool (*explorer_block_reader_fn)(void *ctx, int height,
                                         struct block *out);

/* Fills out[32] with the hash of the ACTIVE chain's block at `height` and
 * returns true, or returns false when the active chain has no such height. */
typedef bool (*explorer_active_hash_fn)(void *ctx, int height, uint8_t out[32]);

struct explorer_unwind_chain {
    explorer_block_reader_fn read;      /* may be NULL */
    explorer_active_hash_fn active_hash; /* may be NULL: transactions kept */
    /* Runs AFTER the unwind commits and BEFORE the fold guards are released,
     * on success only. The catchup cursor (projection tip) must move to the
     * fork inside this window: the zslp backfill is gated by that tip, and
     * with the tip still at the losing height a tick between the commit and
     * the cursor move would fold the now-empty heights above the fork and
     * advance its digest past rows the winner has not written yet. Returning
     * false makes the call fail with EXPLORER_UNWIND_ERR_HOOK (the unwind
     * itself stays committed). */
    bool (*after_commit)(void *ctx, int fork_height);
    void *ctx;                          /* passed to all callbacks */
};

/* What the unwind did, for tests and logs. Zeroed on entry. */
struct explorer_unwind_report {
    enum catalog_rewind zslp_ledger;
    enum catalog_rewind op_return_index;
    size_t stale_blocks_in_transactions; /* blocks whose tx rows were dropped */
};

struct zcl_result explorer_index_unwind_above_chain(
    struct node_db *ndb, int fork_height,
    const struct explorer_unwind_chain *chain,
    struct explorer_unwind_report *report);

/* The same with a block reader only (no active-hash source). */
struct zcl_result explorer_index_unwind_above(struct node_db *ndb,
                                              int fork_height,
                                              explorer_block_reader_fn read,
                                              void *ctx);

#ifdef ZCL_TESTING
/* How long the unwind polls for the fold guards; < 0 restores the default. */
void explorer_unwind_test_set_guard_wait_ms(int ms);
#endif

#endif /* ZCL_SERVICES_EXPLORER_UNWIND_SERVICE_H */
