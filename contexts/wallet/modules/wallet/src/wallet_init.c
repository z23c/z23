/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: wallet struct initialisation, heap and pre-zeroed-storage variants. */

#include "wallet/wallet.h"
#include "wallet/keystore.h"
#include "wallet/sapling_keys.h"

#include "util/sync.h"

#include <string.h>

void wallet_init(struct wallet *w)
{
    memset(w->map_wallet, 0, sizeof(w->map_wallet));
    memset(w->key_pool, 0, sizeof(w->key_pool));
    memset(w->keystore.keys, 0, sizeof(w->keystore.keys));
    memset(w->keystore.scripts, 0, sizeof(w->keystore.scripts));
    memset(w->keystore.watching, 0, sizeof(w->keystore.watching));
    wallet_init_zeroed(w);
}

void wallet_init_zeroed(struct wallet *w)
{
    zcl_mutex_init(&w->cs);
    keystore_init_zeroed(&w->keystore);
    w->num_wallet_tx = 0;
    w->key_pool_size = 0;
    w->next_key_pool_index = 0;
    w->oldest_key_pool_time = 0;
    w->time_first_key = 0;
    w->has_master_key = false;
    w->hd_external_counter = 0;
    w->hd_internal_counter = 0;
    w->hd_account = 0;
    w->default_fee = WALLET_DEFAULT_FEE_ZAT;
    w->min_fee = WALLET_MIN_FEE_ZAT;
    w->spend_zero_conf_change = true;
    w->best_block = NULL;
    sapling_keystore_init(&w->sapling_keys);
    w->best_block_height = 0;
    memset(&w->scan_retry, 0, sizeof(w->scan_retry));
    w->sapling_notes = NULL;
    w->num_sapling_notes = 0;
    w->sapling_notes_cap = 0;
    memset(w->spent_set, 0, sizeof(w->spent_set));
    w->num_spent = 0;
}

