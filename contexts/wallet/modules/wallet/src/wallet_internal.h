/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: shared private declarations for wallet C modules. */
#ifndef ZCL_WALLET_INTERNAL_H
#define ZCL_WALLET_INTERNAL_H

#include "wallet/wallet.h"

size_t wallet_find_slot_internal(const struct wallet *w,
                                 const struct uint256 *hash);

/* Index maintenance; every call holds w->cs. insert: slot is used with its final
 * txid. remove: call before the slot is cleared. clear: all slots gone. */
void wallet_tx_index_insert_locked(struct wallet *w, size_t slot);
void wallet_tx_index_remove_locked(struct wallet *w, size_t slot);
void wallet_tx_index_clear(struct wallet *w);
void wallet_key_pool_consume_transaction_outputs_locked(
    struct wallet *w, const struct transaction *tx);

bool wallet_add_sapling_note(struct wallet *w,
                                const struct sapling_received_note *note);

void wallet_release_note_buffer(struct sapling_received_note *buf,
                                size_t cap);

#endif /* ZCL_WALLET_INTERNAL_H */
