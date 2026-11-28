/* purpose: Prepare an authenticated Ironwood checkpoint without publishing it. */
/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#ifndef ZCL_JOBS_UTXO_APPLY_IRONWOOD_H
#define ZCL_JOBS_UTXO_APPLY_IRONWOOD_H
#include "storage/ironwood_frontier_store.h"
struct block;
struct block_index;
/* The parent expectation must be carried from a previously committed fold,
 * or independently rebuilt by replay from the authenticated private genesis.
 * Neither a checkpoint row nor its audit alone authenticates root or count. */
struct utxo_ironwood_parent {
    uint8_t root[32];
    uint64_t count;
};
struct utxo_ironwood_pending {
    struct ironwood_checkpoint checkpoint;
    uint8_t parent_hash[32];
    bool changed;
};
enum utxo_ironwood_result {
    UTXO_IRONWOOD_OK,
    UTXO_IRONWOOD_MALFORMED,
    UTXO_IRONWOOD_ANCHOR_MISSING,
    UTXO_IRONWOOD_HISTORY_INCOMPLETE,
    UTXO_IRONWOOD_LOCAL_ERROR,
};
/* Caller authenticates the candidate body against bi, binds every v6 wire
 * to its parsed transaction model, and supplies a live,
 * audited, branch-replayed session in its transaction. No writes are made.
 * Genesis initialization is separate. On refusal, out is unchanged. */
enum utxo_ironwood_result utxo_apply_ironwood_prepare(
    struct ironwood_checkpoint_session *session, const struct block_index *bi,
    const struct block *block, const struct utxo_ironwood_parent *parent,
    const uint8_t *parameters, size_t parameters_size,
    struct utxo_ironwood_pending *out);
#endif
