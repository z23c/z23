/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: shared private declarations for wallet C modules. */
#ifndef ZCL_WALLET_INTERNAL_H
#define ZCL_WALLET_INTERNAL_H

#include "wallet/wallet.h"

size_t wallet_find_slot_internal(const struct wallet *w,
                                 const struct uint256 *hash);
void wallet_key_pool_consume_transaction_outputs_locked(
    struct wallet *w, const struct transaction *tx);

#endif /* ZCL_WALLET_INTERNAL_H */
