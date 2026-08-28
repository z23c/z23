/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * yardsale_prevout_service — the confirmed-prevout fetch behind the buyer's
 * chain-content port (yardsale_ceremony_set_prevout_fetch). Before a buyer
 * signs a swap he re-reads the seller's claimed token input from confirmed
 * chain state: the ad's token leg is a claim, and this service accepts it
 * only when strict ZSLP ancestry is current at the unchanged active tip and
 * the exact promised ledger outpoint remains an unspent TOKEN row.
 *
 * Shape: one pure read over the canonical confirmed lookup path — the
 * node.db locator row is only a HINT; the row's height must name the
 * active chain's block and the on-disk body must hash back to both that
 * block and the requested txid, so a stale or hostile locator row can
 * never substitute a different body. Never serves mempool transactions. */

#ifndef ZCL_SERVICES_YARDSALE_PREVOUT_SERVICE_H
#define ZCL_SERVICES_YARDSALE_PREVOUT_SERVICE_H

#include "base/result.h"

#include <stdbool.h>
#include <stdint.h>

struct main_state;
struct node_db;
struct transaction;
struct block;
struct block_index;

typedef bool (*yardsale_prevout_read_block_fn)(
    struct block *out, const struct block_index *index, const char *datadir,
    void *ctx);

/* The confirmed-chain view a fetch reads: the active chain for tip
 * verification, the canonical node database for the finalized
 * (txid -> height / tx_index / block_hash) locator row, and the datadir
 * for the verified block body. The boot composition root fills one for
 * the node's lifetime; direct service tests build an isolated view. */
struct yardsale_prevout_view {
    struct main_state *state;
    struct node_db *node_db;
    const char *datadir;
    /* NULL selects read_block_from_disk_index. The callback exists so the
     * complete production decision can be tested without manufacturing a
     * blk*.dat file; it receives the already-snapshotted index. */
    yardsale_prevout_read_block_fn read_block;
    void *read_block_ctx;
};

/* Fetch a strictly-valid, confirmed, unspent TOKEN transaction body by txid
 * (internal little-endian byte order — the same order as transaction.hash).
 * Signature matches yardsale_prevout_fetch_fn, so it wires straight into the
 * ceremony port. ctx is a struct yardsale_prevout_view *. On ZCL_OK *tx_out
 * receives a
 * private copy the caller owns (transaction_free); on failure *tx_out is
 * untouched and the result names why the body is not confirmed here. */
struct zcl_result yardsale_prevout_fetch_confirmed(void *ctx,
                                                   const uint8_t txid[32],
                                                   uint32_t vout,
                                                   const uint8_t token_id[32],
                                                   uint64_t token_amount,
                                                   struct transaction *tx_out);

#endif /* ZCL_SERVICES_YARDSALE_PREVOUT_SERVICE_H */
