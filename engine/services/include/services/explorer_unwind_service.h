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
 *   - the zslp_ledger and op_return_index catalogs, whose digest cannot be
 *     rewound, are truncated for their own services to re-derive when their
 *     cursor is above the fork.
 *
 * `read` fills one block of the ACTIVE chain at `height` (the caller owns it
 * and block_free()s it afterwards). It is only called when a replay is
 * needed and may be NULL, in which case such a replay fails. One
 * transaction: on any failure nothing changes and the result carries the
 * reason. node.db only; never consulted by consensus. */

#include "util/result.h"

#include <stdbool.h>

struct node_db;
struct block;

typedef bool (*explorer_block_reader_fn)(void *ctx, int height,
                                         struct block *out);

struct zcl_result explorer_index_unwind_above(struct node_db *ndb,
                                              int fork_height,
                                              explorer_block_reader_fn read,
                                              void *ctx);

#endif /* ZCL_SERVICES_EXPLORER_UNWIND_SERVICE_H */
