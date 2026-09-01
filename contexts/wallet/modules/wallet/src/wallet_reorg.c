/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: reconcile wallet transaction state across restart and reorg. */

#include "wallet_internal.h"
#include "coins/coins.h"
#include "coins/coins_view.h"
#include "support/cleanse.h"
#include "util/log_macros.h"
#include <string.h>

void wallet_verify_utxos(struct wallet *w, struct coins_view_cache *coins_tip)
{
    if (!coins_tip)
        return;
    size_t verified = 0, pruned = 0;
    for (size_t i = 0; i < MAX_WALLET_TX; i++) {
        if (!w->map_wallet[i].used)
            continue;
        const struct wallet_tx *wtx = &w->map_wallet[i];
        /* Unconfirmed change is necessarily absent from confirmed chainstate.
         * Mempool/reaccept state reconciles those transactions. */
        if (wtx->confirms < 1)
            continue;
        for (size_t j = 0; j < wtx->tx.num_vout; j++) {
            if (!wallet_is_mine(w, &wtx->tx.vout[j]) ||
                wallet_is_outpoint_spent(w, &wtx->tx.hash, (uint32_t)j))
                continue;
            struct coins c;
            coins_init(&c);
            bool found = coins_view_cache_get_coins(coins_tip,
                                                    &wtx->tx.hash, &c);
            if (!found || !coins_is_available(&c, (unsigned int)j)) {
                wallet_mark_outpoint_spent(w, &wtx->tx.hash, (uint32_t)j);
                pruned++;
            }
            coins_free(&c);
            verified++;
        }
    }
    LOG_INFO("wallet", "Wallet UTXO verification: %zu checked, %zu pruned",
             verified, pruned);
}

bool wallet_get_tx_copy(const struct wallet *w, const struct uint256 *hash,
                        struct wallet_tx *out)
{
    if (!w || !hash || !out)
        return false; /* raw-return-ok:invalid read request */
    memset(out, 0, sizeof(*out));
    zcl_mutex_lock((zcl_mutex_t *)&w->cs);
    size_t idx = wallet_find_slot_internal(w, hash);
    if (idx >= MAX_WALLET_TX) {
        zcl_mutex_unlock((zcl_mutex_t *)&w->cs);
        return false; /* raw-return-ok:normal lookup miss */
    }
    struct wallet_tx snapshot = w->map_wallet[idx];
    transaction_init(&snapshot.tx);
    bool copied = transaction_copy(&snapshot.tx, &w->map_wallet[idx].tx);
    zcl_mutex_unlock((zcl_mutex_t *)&w->cs);
    if (!copied) {
        transaction_free(&snapshot.tx);
        LOG_ERROR("wallet", "wallet transaction snapshot allocation failed");
        return false; /* raw-return-ok:failure logged with context */
    }
    *out = snapshot;
    return true;
}

bool wallet_disconnect_transaction(struct wallet *w,
                                   const struct transaction *tx,
                                   bool keep_pending)
{
    if (!w || !tx)
        LOG_RETURN(false, "wallet",
                   "disconnect_transaction: NULL wallet or tx");
    zcl_mutex_lock(&w->cs);

    size_t ni = 0;
    while (ni < w->num_sapling_notes) {
        struct sapling_received_note *note = &w->sapling_notes[ni];
        if (!note->used || !uint256_eq(&note->txid, &tx->hash)) {
            ni++;
            continue;
        }
        size_t last = w->num_sapling_notes - 1;
        if (ni != last)
            w->sapling_notes[ni] = w->sapling_notes[last];
        memory_cleanse(&w->sapling_notes[last], sizeof(w->sapling_notes[last]));
        w->num_sapling_notes--;
    }

    size_t idx = wallet_find_slot_internal(w, &tx->hash);
    if (idx >= MAX_WALLET_TX) {
        zcl_mutex_unlock(&w->cs);
        return true;
    }
    struct wallet_tx *wtx = &w->map_wallet[idx];
    if (keep_pending && !transaction_is_coinbase(tx)) {
        uint256_set_null(&wtx->hash_block);
        wtx->confirms = 0;
        wallet_mark_dirty(wtx);
        zcl_mutex_unlock(&w->cs);
        return true;
    }

    for (size_t i = 0; i < wtx->tx.num_vin; i++)
        wallet_unmark_outpoint_spent(w, &wtx->tx.vin[i].prevout.hash,
                                     wtx->tx.vin[i].prevout.n);
    for (size_t si = 0; si < wtx->tx.num_shielded_spend; si++) {
        const uint8_t *nf = wtx->tx.v_shielded_spend[si].nullifier.data;
        for (size_t j = 0; j < w->num_sapling_notes; j++) {
            if (w->sapling_notes[j].used &&
                memcmp(w->sapling_notes[j].nf, nf, 32) == 0)
                w->sapling_notes[j].spent = false;
        }
    }
    transaction_free(&wtx->tx);
    memset(wtx, 0, sizeof(*wtx));
    if (w->num_wallet_tx > 0)
        w->num_wallet_tx--;
    zcl_mutex_unlock(&w->cs);
    return true;
}

int wallet_rewind_confirmations(struct wallet *w, int new_best_height)
{
    if (!w)
        LOG_ERR("wallet", "rewind_confirmations: NULL wallet");
    zcl_mutex_lock(&w->cs);
    int delta = w->best_block_height - new_best_height;
    if (delta <= 0) {
        zcl_mutex_unlock(&w->cs);
        return 0;
    }
    int lowered = 0;
    for (size_t i = 0; i < MAX_WALLET_TX; i++) {
        struct wallet_tx *wtx = &w->map_wallet[i];
        if (!wtx->used || wtx->confirms < 1)
            continue;
        wtx->confirms = wtx->confirms > delta ? wtx->confirms - delta : 1;
        wallet_mark_dirty(wtx);
        lowered++;
    }
    w->best_block_height = new_best_height;
    zcl_mutex_unlock(&w->cs);
    return lowered;
}
