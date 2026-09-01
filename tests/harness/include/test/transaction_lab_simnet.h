/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Reusable isolated-chain proof fixture for production OP_RETURN builders. */

#ifndef ZCL_TEST_TRANSACTION_LAB_SIMNET_H
#define ZCL_TEST_TRANSACTION_LAB_SIMNET_H

#include "primitives/transaction.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct node_db;

/* Exact transaction retained after the simnet block consumes its original
 * allocation. The receipt is public test evidence only: it contains no key,
 * address, endpoint, datadir, memo, or live-network material. */
struct transaction_lab_simnet_receipt {
    struct transaction transaction;
    struct uint256 txid;
    struct uint256 funding_txid;
    uint8_t owner_hash160[20];
    int32_t funding_height;
    int32_t mined_height;
    int64_t change_zat;
};

/* Fund one transparent coin in a fresh RAM-only simnet, build a transaction
 * whose vout[0] is the supplied production OP_RETURN and vout[1] is ordinary
 * ZCL change, and admit the exact bytes through connect_block(). Success also
 * proves the funding input was consumed and the change output entered the
 * in-memory UTXO view. */
bool transaction_lab_simnet_mine_op_return(
    const uint8_t *op_return, size_t op_return_len,
    struct transaction_lab_simnet_receipt *out);

/* Owned variant for overlays whose authorization is the first input's
 * previous P2PKH output (for example ZID and ZDIR). The funding coin and
 * change both use owner_hash160, and target_height is the exact height at
 * which the supplied bytes must be admitted. It must be high enough for the
 * fresh coinbase funding output to mature. */
bool transaction_lab_simnet_mine_owned_op_return_at(
    const uint8_t *op_return, size_t op_return_len,
    const uint8_t owner_hash160[20], int32_t target_height,
    struct transaction_lab_simnet_receipt *out);

/* Fold the already-mined exact transaction through the production explorer
 * projection. Consensus acceptance is proved by the mint helper; this second
 * axis proves the overlay parser and rebuildable projection consume the same
 * bytes. The receipt's funding previous output is seeded first, so overlays
 * derive the same P2PKH owner that connect_block consumed. */
bool transaction_lab_simnet_project(
    struct node_db *ndb,
    const struct transaction_lab_simnet_receipt *receipt);

void transaction_lab_simnet_receipt_free(
    struct transaction_lab_simnet_receipt *receipt);

#endif /* ZCL_TEST_TRANSACTION_LAB_SIMNET_H */
