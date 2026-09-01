/* Copyright (c) 2009-2010 Satoshi Nakamoto
 * Copyright (c) 2009-2014 The Bitcoin Core developers
 * Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 *
 * update_coins — applies a transaction's effects to the UTXO set.
 * Spends inputs (removes UTXOs), creates outputs (adds UTXOs).
 * Maintains undo data for chain reorgs.
 *
 * PEDANTIC: every error path logs loudly and returns false.
 * Silent failures here cause UTXO set corruption. */

#include "validation/update_coins.h"
#include "coins/utxo_commitment.h"
#include "domain/consensus/coins_math.h"
#include "util/log_macros.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "util/safe_alloc.h"

bool update_coins_with_undo(const struct transaction *tx,
                            struct coins_view_cache *inputs,
                            struct tx_undo *txundo,
                            int nHeight)
{
    if (!transaction_is_coinbase(tx)) {
        if (!tx_undo_alloc(txundo, tx->num_vin))
            LOG_FAIL("update_coins", "tx_undo_alloc failed num_vin=%zu h=%d",
                     tx->num_vin, nHeight);
        for (size_t i = 0; i < tx->num_vin; i++) {
            struct coins_cache_entry *entry =
                coins_view_cache_modify(inputs, &tx->vin[i].prevout.hash);
            if (!entry) {
                char hex[65];
                uint256_get_hex(&tx->vin[i].prevout.hash, hex);
                LOG_FAIL("update_coins", "coins_modify failed input[%zu]=%s h=%d",
                         i, hex, nHeight);
            }
            unsigned int nPos = tx->vin[i].prevout.n;

            /* Grow vout array if needed */
            if (nPos >= entry->coins.num_vout) {
                size_t old_size = entry->coins.num_vout;
                size_t new_size = nPos + 1;
                struct tx_out *nv = zcl_realloc(entry->coins.vout,
                    new_size * sizeof(struct tx_out), "coins_vout_grow");
                if (!nv)
                    LOG_FAIL("update_coins", "realloc failed new_size=%zu h=%d",
                             new_size, nHeight);
                for (size_t k = entry->coins.num_vout; k < new_size; k++)
                    tx_out_set_null(&nv[k]);
                entry->coins.vout = nv;
                entry->coins.num_vout = new_size;
                coins_view_cache_account_vout_resize(
                    inputs, old_size, new_size);
            }
            if (tx_out_is_null(&entry->coins.vout[nPos])) {
                char hex[65];
                uint256_get_hex(&tx->vin[i].prevout.hash, hex);
                LOG_FAIL("update_coins",
                         "spending NULL output %s:%u at h=%d (double-spend or missing UTXO)",
                         hex, nPos, nHeight);
            }

            /* Validate output value before spending */
            if (!MoneyRange(entry->coins.vout[nPos].value))
                LOG_FAIL("update_coins", "corrupt output value %lld at h=%d",
                         (long long)entry->coins.vout[nPos].value, nHeight);

            /* Remove spent UTXO from commitment */
            utxo_commitment_remove(&inputs->commitment,
                                    tx->vin[i].prevout.hash.data, nPos,
                                    entry->coins.vout[nPos].value,
                                    entry->coins.height);

            /* Pure domain mutation: snapshot the txout into the undo
             * record, null the vout, and (if the coin is now fully
             * pruned) populate the parent metadata so a reorg can
             * rebuild it. This is the slice of update_coins that does
             * not touch the cache. Range / liveness preconditions
             * were already established above (we grew the array and
             * logged NULL-out / corrupt-value with LOG_FAIL); the
             * domain call cannot fail in this code path. */
            struct zcl_result _cu = coins_math_capture_undo(
                    &entry->coins, nPos, &txundo->vprevout[i]);
            if (!_cu.ok)
                LOG_FAIL("update_coins",
                         "coins_math_capture_undo failed code=%d msg=%s h=%d",
                         _cu.code, _cu.message, nHeight);
        }
    }

    /* Create new outputs */
    struct coins_cache_entry *new_entry =
        coins_view_cache_modify_new(inputs, &tx->hash);
    if (!new_entry)
        LOG_FAIL("update_coins", "modify_new failed at h=%d", nHeight);
    /* Treat a false return (OOM / over-cap) as a hard failure: an empty
     * record would otherwise drop this tx's outputs from the UTXO set and
     * the commitment while the block is accepted — a silent consensus
     * divergence. Fail the connect instead. */
    size_t old_size = new_entry->coins.num_vout;
    if (!coins_from_transaction(&new_entry->coins, tx, nHeight))
        LOG_FAIL("update_coins",
                 "coins_from_transaction failed (OOM/over-cap) at h=%d", nHeight);
    coins_view_cache_account_vout_resize(
        inputs, old_size, new_entry->coins.num_vout);

    /* Validate new output values before adding to commitment */
    for (size_t vi = 0; vi < new_entry->coins.num_vout; vi++) {
        if (!tx_out_is_null(&new_entry->coins.vout[vi])) {
            if (!MoneyRange(new_entry->coins.vout[vi].value))
                LOG_FAIL("update_coins",
                         "new output[%zu] value %lld out of range at h=%d",
                         vi, (long long)new_entry->coins.vout[vi].value, nHeight);
            utxo_commitment_add(&inputs->commitment,
                                 tx->hash.data, (uint32_t)vi,
                                 new_entry->coins.vout[vi].value,
                                 nHeight);
        }
    }

    return true;
}

void update_coins(const struct transaction *tx,
                  struct coins_view_cache *inputs,
                  int nHeight)
{
    struct tx_undo txundo;
    tx_undo_init(&txundo);
    update_coins_with_undo(tx, inputs, &txundo, nHeight);
    tx_undo_free(&txundo);
}
