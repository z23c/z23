/* Copyright (c) 2009-2010 Satoshi Nakamoto
 * Copyright (c) 2009-2014 The Bitcoin Core developers
 * Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. */

#include "wallet/wallet.h"
#include "wallet_internal.h"
#include "wallet/bip44.h"
#include "wallet/mnemonic.h"
#include "chain/chainparams.h"
#include "consensus/consensus.h"
#include "consensus/upgrades.h"
#include "util/file_io.h"
#include "util/log_macros.h"
#include "core/random.h"
#include "core/utiltime.h"
#include "keys/key_io.h"
#include "script/standard.h"
#include "storage/disk_block_io.h"
#include "core/serialize.h"
#include "support/cleanse.h"
#include "validation/chainstate.h"
#include "validation/accept_to_mempool.h"
#include "validation/txmempool.h"
#include "validation/check_transaction.h"
#include "validation/sighash.h"
#include "sapling/note_encryption.h"
#include "sapling/sapling.h"
#include "coins/coins.h"
#include "coins/coins_view.h"
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "util/safe_alloc.h"

static uint32_t spent_hash(const struct uint256 *txid, uint32_t vout)
{
    uint32_t h = 0;
    for (int i = 0; i < 8; i++) {
        /* memcpy, not `((const uint32_t *)txid->data)[i]`. Alignment is fine
         * (uint256::data is alignas(4)), but reading a uint8_t[32] object
         * through a uint32_t lvalue violates strict aliasing, which -O3
         * -flto=auto is entitled to act on. gcc lowers this memcpy to the
         * same single 4-byte load — same bytes, same value, no UB. */
        uint32_t w;
        memcpy(&w, txid->data + (size_t)i * sizeof w, sizeof w);
        h ^= w;
    }
    h ^= vout * 2654435761u;
    return h % SPENT_SET_BUCKETS;
}

void wallet_mark_outpoint_spent(struct wallet *w,
                                 const struct uint256 *txid, uint32_t vout)
{
    uint32_t idx = spent_hash(txid, vout);
    for (uint32_t i = 0; i < SPENT_SET_BUCKETS; i++) {
        uint32_t slot = (idx + i) % SPENT_SET_BUCKETS;
        if (!w->spent_set[slot].occupied) {
            w->spent_set[slot].txid = *txid;
            w->spent_set[slot].vout = vout;
            w->spent_set[slot].occupied = true;
            w->num_spent++;
            return;
        }
        if (uint256_eq(&w->spent_set[slot].txid, txid) &&
            w->spent_set[slot].vout == vout)
            return;
    }
}

void wallet_unmark_outpoint_spent(struct wallet *w,
                                   const struct uint256 *txid, uint32_t vout)
{
    uint32_t idx = spent_hash(txid, vout);
    for (uint32_t i = 0; i < SPENT_SET_BUCKETS; i++) {
        uint32_t slot = (idx + i) % SPENT_SET_BUCKETS;
        if (!w->spent_set[slot].occupied)
            return;
        if (uint256_eq(&w->spent_set[slot].txid, txid) &&
            w->spent_set[slot].vout == vout) {
            w->spent_set[slot].occupied = false;
            w->num_spent--;
            /* Rehash displaced entries in the linear-probe chain */
            uint32_t hole = slot;
            for (uint32_t j = 1; j < SPENT_SET_BUCKETS; j++) {
                uint32_t next = (slot + j) % SPENT_SET_BUCKETS;
                if (!w->spent_set[next].occupied)
                    break;
                uint32_t natural = spent_hash(&w->spent_set[next].txid,
                                               w->spent_set[next].vout);
                /* If the entry at 'next' would hash to or before 'hole'
                 * (wrapping around), move it to fill the hole. */
                bool needs_move;
                if (hole <= next)
                    needs_move = (natural <= hole || natural > next);
                else
                    needs_move = (natural <= hole && natural > next);
                if (needs_move) {
                    w->spent_set[hole] = w->spent_set[next];
                    w->spent_set[next].occupied = false;
                    hole = next;
                }
            }
            return;
        }
    }
}

bool wallet_is_outpoint_spent(const struct wallet *w,
                               const struct uint256 *txid, uint32_t vout)
{
    uint32_t idx = spent_hash(txid, vout);
    for (uint32_t i = 0; i < SPENT_SET_BUCKETS; i++) {
        uint32_t slot = (idx + i) % SPENT_SET_BUCKETS;
        if (!w->spent_set[slot].occupied)
            return false;
        if (uint256_eq(&w->spent_set[slot].txid, txid) &&
            w->spent_set[slot].vout == vout)
            return true;
    }
    return false;
}

void wallet_init(struct wallet *w)
{
    zcl_mutex_init(&w->cs);
    keystore_init(&w->keystore);
    memset(w->map_wallet, 0, sizeof(w->map_wallet));
    w->num_wallet_tx = 0;
    memset(w->key_pool, 0, sizeof(w->key_pool));
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
    w->sapling_notes = NULL;
    w->num_sapling_notes = 0;
    w->sapling_notes_cap = 0;
    memset(w->spent_set, 0, sizeof(w->spent_set));
    w->num_spent = 0;
}

void wallet_rebuild_spent_set(struct wallet *w)
{
    memset(w->spent_set, 0, sizeof(w->spent_set));
    w->num_spent = 0;

    for (size_t i = 0; i < MAX_WALLET_TX; i++) {
        if (!w->map_wallet[i].used)
            continue;
        const struct transaction *tx = &w->map_wallet[i].tx;
        for (size_t j = 0; j < tx->num_vin; j++) {
            const struct uint256 *prev_hash = &tx->vin[j].prevout.hash;
            uint32_t n = tx->vin[j].prevout.n;
            size_t idx = wallet_find_slot_internal(w, prev_hash);
            if (idx < MAX_WALLET_TX) {
                const struct wallet_tx *prev = &w->map_wallet[idx];
                if (n < prev->tx.num_vout &&
                    wallet_is_mine(w, &prev->tx.vout[n]))
                    wallet_mark_outpoint_spent(w, prev_hash, n);
            }
        }
    }
    LOG_INFO("wallet", "Wallet spent set rebuilt: %zu spent outpoints", w->num_spent);
}

void wallet_free(struct wallet *w)
{
    for (size_t i = 0; i < MAX_WALLET_TX; i++) {
        if (w->map_wallet[i].used) {
            transaction_free(&w->map_wallet[i].tx);
            w->map_wallet[i].used = false;
        }
    }
    w->num_wallet_tx = 0;
    free(w->sapling_notes);
    w->sapling_notes = NULL;
    w->num_sapling_notes = 0;
    w->sapling_notes_cap = 0;
    keystore_free(&w->keystore);
    zcl_mutex_destroy(&w->cs);
}

bool wallet_mint_next_hd_key(struct wallet *w, uint32_t change,
                             struct pubkey *pk_out)
{
    uint32_t *counter = (change == BIP44_INTERNAL)
                        ? &w->hd_internal_counter
                        : &w->hd_external_counter;

    struct privkey priv;
    struct pubkey pub;
    privkey_init(&priv);

    /* Read counter, derive, add, and increment as one atomic step under
     * w->cs. Two concurrent callers would otherwise read the same index,
     * derive an identical key/address, and bump the counter twice. The
     * derivation runs no wallet code and keystore_add_key takes only its
     * own keystore.cs, so holding w->cs across them cannot self-deadlock. */
    zcl_mutex_lock(&w->cs);
    uint32_t index = *counter;
    bool ok = bip44_derive_keypair(&w->master_key, &priv, &pub,
                                   w->hd_account, change, index)
              && keystore_add_key(&w->keystore, &priv);
    if (ok)
        (*counter)++;
    zcl_mutex_unlock(&w->cs);

    memory_cleanse(priv.vch, 32);

    if (ok && pk_out)
        *pk_out = pub;
    return ok;
}

bool wallet_generate_new_key(struct wallet *w, struct pubkey *pk_out)
{
    /* If HD wallet is initialized, derive from BIP44 external chain */
    if (w->has_master_key)
        return wallet_mint_next_hd_key(w, BIP44_EXTERNAL, pk_out);

    /* Fallback: random key generation (legacy wallet) */
    struct privkey key;
    privkey_init(&key);
    privkey_make_new(&key, true);

    if (!privkey_is_valid(&key))
        return false;

    struct pubkey pk;
    if (!privkey_get_pubkey(&key, &pk)) {
        memory_cleanse(key.vch, 32);
        return false;
    }

    zcl_mutex_lock(&w->cs);
    bool ok = keystore_add_key(&w->keystore, &key);
    zcl_mutex_unlock(&w->cs);

    memory_cleanse(key.vch, 32);

    if (ok && pk_out)
        *pk_out = pk;
    return ok;
}

bool wallet_init_hd(struct wallet *w, const unsigned char *seed, size_t seed_len)
{
    if (!seed || seed_len < HD_SEED_MIN_BYTES || seed_len > HD_SEED_MAX_BYTES)
        return false;

    struct ext_key master;
    if (!hd_master_from_seed(&master, seed, seed_len)) {
        memory_cleanse(&master, sizeof(master));
        return false;
    }

    zcl_mutex_lock(&w->cs);
    w->master_key = master;
    w->has_master_key = true;
    w->hd_external_counter = 0;
    w->hd_internal_counter = 0;
    w->hd_account = 0;
    zcl_mutex_unlock(&w->cs);

    memory_cleanse(&master, sizeof(master));
    return true;
}

bool wallet_init_hd_from_mnemonic(struct wallet *w, const char *mnemonic,
                                   const char *passphrase)
{
    if (!mnemonic)
        return false;
    if (!mnemonic_validate(mnemonic))
        return false;

    uint8_t seed[MNEMONIC_SEED_SIZE];
    if (!mnemonic_to_seed(mnemonic, passphrase, seed)) {
        memory_cleanse(seed, sizeof(seed));
        return false;
    }

    bool ok = wallet_init_hd(w, seed, sizeof(seed));
    memory_cleanse(seed, sizeof(seed));
    return ok;
}

bool wallet_has_hd(const struct wallet *w)
{
    return w && w->has_master_key;
}

bool wallet_pubkey_to_addr(const struct pubkey *pk, char *addr_out,
                           size_t addr_size)
{
    struct key_id kid = pubkey_get_id(pk);
    struct tx_destination dest;
    dest.type = DEST_KEY_ID;
    dest.id.key = kid;

    const struct chain_params *cp = chain_params_get();
    size_t pk_pfx_len, sc_pfx_len;
    const unsigned char *pk_pfx = chain_params_base58_prefix(
        cp, B58_PUBKEY_ADDRESS, &pk_pfx_len);
    const unsigned char *sc_pfx = chain_params_base58_prefix(
        cp, B58_SCRIPT_ADDRESS, &sc_pfx_len);

    return encode_destination(&dest, pk_pfx, pk_pfx_len,
                              sc_pfx, sc_pfx_len, addr_out, addr_size);
}

bool wallet_get_new_change_address(struct wallet *w, char *addr_out,
                                    size_t addr_size)
{
    struct pubkey pk;

    if (w->has_master_key) {
        if (!wallet_mint_next_hd_key(w, BIP44_INTERNAL, &pk))
            return false;
    } else {
        /* Legacy: change addresses are just regular addresses */
        if (!wallet_generate_new_key(w, &pk))
            return false;
    }

    return wallet_pubkey_to_addr(&pk, addr_out, addr_size);
}

bool wallet_get_new_address_with_key_id(struct wallet *w, char *addr_out,
                               size_t addr_size, struct key_id *key_id_out)
{
    struct pubkey pk;

    if (w->has_master_key) {
        /* HD wallet: derive directly from BIP44 external chain */
        if (!wallet_mint_next_hd_key(w, BIP44_EXTERNAL, &pk))
            return false;
    } else {
        /* Legacy wallet: use key pool */
        if (!wallet_get_key_from_pool(w, &pk))
            return false;
    }

    if (key_id_out)
        *key_id_out = pubkey_get_id(&pk);
    return wallet_pubkey_to_addr(&pk, addr_out, addr_size);
}

bool wallet_get_new_address(struct wallet *w, char *addr_out, size_t addr_size)
{
    return wallet_get_new_address_with_key_id(w, addr_out, addr_size, NULL);
}

bool wallet_top_up_key_pool(struct wallet *w, unsigned int target_size)
{
    if (target_size == 0)
        target_size = DEFAULT_KEYPOOL_SIZE;
    if (target_size > MAX_KEY_POOL)
        target_size = MAX_KEY_POOL;

    /* wallet_generate_new_key locks w->cs itself, so the key must be
     * generated with w->cs released; only the key_pool bookkeeping is
     * guarded by a brief lock. w->cs is non-recursive, so holding it
     * across the generate call would self-deadlock.
     *
     * The bound is re-checked under the SAME lock that performs the write
     * (not just at the top of the loop): w->cs is dropped across the
     * generate call, so a concurrent top-up could raise key_pool_size in
     * the window. Re-checking under the write lock keeps the index in
     * [0, MAX_KEY_POOL) and prevents overshoot past target_size. A surplus
     * generated key simply stays in the keystore (harmless), as in the
     * original (which also discarded pk). */
    for (;;) {
        zcl_mutex_lock(&w->cs);
        bool need = w->key_pool_size < target_size;
        zcl_mutex_unlock(&w->cs);
        if (!need)
            break;

        struct pubkey pk;
        if (!wallet_generate_new_key(w, &pk))
            return false;
        struct key_id kid = pubkey_get_id(&pk);

        zcl_mutex_lock(&w->cs);
        if (w->key_pool_size < target_size) {
            struct wallet_key_pool_entry *entry =
                &w->key_pool[w->key_pool_size];
            entry->keyid = kid;
            entry->generation = w->next_key_pool_index;
            entry->persisted = false;
            w->next_key_pool_index++;
            w->key_pool_size++;
        }
        zcl_mutex_unlock(&w->cs);
    }
    return true;
}

int64_t wallet_key_pool_generation_ceiling(const struct wallet *w)
{
    if (!w)
        return -1;
    zcl_mutex_lock((zcl_mutex_t *)&w->cs);
    int64_t ceiling = w->next_key_pool_index - 1;
    zcl_mutex_unlock((zcl_mutex_t *)&w->cs);
    return ceiling;
}

void wallet_key_pool_mark_persisted_through(struct wallet *w,
                                            int64_t generation)
{
    if (!w || generation < 0)
        return;
    zcl_mutex_lock(&w->cs);
    for (size_t i = 0; i < w->key_pool_size; i++)
        if (w->key_pool[i].generation <= generation)
            w->key_pool[i].persisted = true;
    zcl_mutex_unlock(&w->cs);
}

size_t wallet_key_pool_persisted_size(const struct wallet *w)
{
    if (!w)
        return 0;
    size_t count = 0;
    zcl_mutex_lock((zcl_mutex_t *)&w->cs);
    for (size_t i = 0; i < w->key_pool_size; i++)
        if (w->key_pool[i].persisted)
            count++;
    zcl_mutex_unlock((zcl_mutex_t *)&w->cs);
    return count;
}

bool wallet_get_key_from_pool(struct wallet *w, struct pubkey *pk_out)
{
    if (!w || !pk_out)
        LOG_FAIL("wallet", "get_key_from_pool: NULL wallet or output");

    zcl_mutex_lock(&w->cs);
    size_t selected = SIZE_MAX;
    for (size_t i = w->key_pool_size; i > 0; i--) {
        if (w->key_pool[i - 1].persisted) {
            selected = i - 1;
            break;
        }
    }
    if (selected == SIZE_MAX) {
        zcl_mutex_unlock(&w->cs);
        LOG_FAIL("wallet",
                 "get_key_from_pool: no persisted keypool entry available");
    }

    struct key_id kid = w->key_pool[selected].keyid;
    if (selected + 1 < w->key_pool_size)
        w->key_pool[selected] = w->key_pool[w->key_pool_size - 1];
    memset(&w->key_pool[w->key_pool_size - 1], 0,
           sizeof(w->key_pool[w->key_pool_size - 1]));
    w->key_pool_size--;
    zcl_mutex_unlock(&w->cs);

    /* Top-up already generated and persisted this private key. Return that
     * exact public key instead of generating an unrelated extra key (the old
     * implementation's 100-then-101st-key bug). */
    if (!keystore_get_pubkey(&w->keystore, &kid, pk_out))
        LOG_FAIL("wallet", "get_key_from_pool: persisted pool key missing");
    return true;
}

size_t wallet_find_slot_internal(const struct wallet *w,
                                 const struct uint256 *hash)
{
    for (size_t i = 0; i < MAX_WALLET_TX; i++) {
        if (w->map_wallet[i].used &&
            uint256_eq(&w->map_wallet[i].tx.hash, hash))
            return i;
    }
    return MAX_WALLET_TX;
}

static size_t wallet_find_free_slot(const struct wallet *w)
{
    for (size_t i = 0; i < MAX_WALLET_TX; i++) {
        if (!w->map_wallet[i].used)
            return i;
    }
    return MAX_WALLET_TX;
}

bool wallet_add_to_wallet(struct wallet *w, const struct wallet_tx *wtx)
{
    if (!w || !wtx)
        LOG_FAIL("wallet", "add_to_wallet: NULL wallet or transaction");

    zcl_mutex_lock(&w->cs);

    size_t idx = wallet_find_slot_internal(w, &wtx->tx.hash);
    if (idx < MAX_WALLET_TX) {
        w->map_wallet[idx].hash_block = wtx->hash_block;
        w->map_wallet[idx].confirms = wtx->confirms;
        w->map_wallet[idx].debit_cached_valid = false;
        w->map_wallet[idx].credit_cached_valid = false;
        w->map_wallet[idx].available_credit_cached_valid = false;
        zcl_mutex_unlock(&w->cs);
        return true;
    }

    idx = wallet_find_free_slot(w);
    if (idx >= MAX_WALLET_TX) {
        zcl_mutex_unlock(&w->cs);
        return false;
    }

    /* Build a complete independent record before publishing the slot.  The
     * former field-by-field copy installed the shallow source pointers first
     * and silently zeroed a shielded vector when one allocation failed.  That
     * reported success with a partial wallet transaction (and left durability
     * or rollback reasoning about different bytes than the admitted tx).
     * transaction_copy is all-or-nothing and frees its partial allocations on
     * failure, so an unused map slot remains byte-clean. */
    struct wallet_tx copy = *wtx;
    transaction_init(&copy.tx);
    if (!transaction_copy(&copy.tx, &wtx->tx)) {
        zcl_mutex_unlock(&w->cs);
        LOG_FAIL("wallet", "add_to_wallet: deep transaction copy failed");
    }
    copy.used = true;
    w->map_wallet[idx] = copy;

    w->num_wallet_tx++;
    zcl_mutex_unlock(&w->cs);
    return true;
}

const struct wallet_tx *wallet_get_tx(const struct wallet *w,
                                       const struct uint256 *hash)
{
    size_t idx = wallet_find_slot_internal(w, hash);
    if (idx < MAX_WALLET_TX)
        return &w->map_wallet[idx];
    return NULL;
}

void wallet_mark_dirty(struct wallet_tx *wtx)
{
    wtx->debit_cached_valid = false;
    wtx->credit_cached_valid = false;
    wtx->immature_credit_cached_valid = false;
    wtx->available_credit_cached_valid = false;
}

bool wallet_is_mine(const struct wallet *w, const struct tx_out *txout)
{
    struct tx_destination dest;
    if (!script_extract_destination(&txout->script_pub_key, &dest))
        return false;

    if (dest.type == DEST_KEY_ID)
        return keystore_have_key(&w->keystore, &dest.id.key) ||
               keystore_have_watch_only(&w->keystore, &dest.id.key);
    if (dest.type == DEST_SCRIPT_ID)
        return keystore_have_cscript(&w->keystore, &dest.id.script.hash);
    return false;
}

bool wallet_is_watch_only(const struct wallet *w, const struct tx_out *txout)
{
    struct tx_destination dest;
    if (!script_extract_destination(&txout->script_pub_key, &dest))
        return false;

    if (dest.type == DEST_KEY_ID)
        return !keystore_have_key(&w->keystore, &dest.id.key) &&
                keystore_have_watch_only(&w->keystore, &dest.id.key);
    return false;
}

bool wallet_is_change(const struct wallet *w, const struct tx_out *txout)
{
    struct tx_destination dest;
    if (!script_extract_destination(&txout->script_pub_key, &dest))
        return false;
    if (dest.type != DEST_KEY_ID)
        return false;
    return keystore_have_key(&w->keystore, &dest.id.key);
}

int64_t wallet_get_debit(const struct wallet *w, const struct transaction *tx)
{
    int64_t debit = 0;
    for (size_t i = 0; i < tx->num_vin; i++) {
        const struct outpoint *prevout = &tx->vin[i].prevout;
        size_t idx = wallet_find_slot_internal(w, &prevout->hash);
        if (idx < MAX_WALLET_TX) {
            const struct wallet_tx *prev = &w->map_wallet[idx];
            if (prevout->n < prev->tx.num_vout) {
                if (wallet_is_mine(w, &prev->tx.vout[prevout->n]))
                    debit += prev->tx.vout[prevout->n].value;
            }
        }
    }
    return debit;
}

int64_t wallet_get_balance(const struct wallet *w)
{
    int64_t balance = 0;
    zcl_mutex_lock((zcl_mutex_t *)&w->cs);
    for (size_t i = 0; i < MAX_WALLET_TX; i++) {
        if (!w->map_wallet[i].used)
            continue;
        const struct wallet_tx *wtx = &w->map_wallet[i];
        if (wtx->confirms < 1)
            continue;
        if (transaction_is_coinbase(&wtx->tx) &&
            wallet_tx_get_blocks_to_maturity(wtx) > 0)
            continue;

        for (size_t j = 0; j < wtx->tx.num_vout; j++) {
            if (wallet_is_mine(w, &wtx->tx.vout[j]) &&
                !wallet_is_outpoint_spent(w, &wtx->tx.hash, (uint32_t)j))
                balance += wtx->tx.vout[j].value;
        }
    }
    zcl_mutex_unlock((zcl_mutex_t *)&w->cs);
    return balance;
}

int64_t wallet_get_unconfirmed_balance(const struct wallet *w)
{
    int64_t balance = 0;
    zcl_mutex_lock((zcl_mutex_t *)&w->cs);
    for (size_t i = 0; i < MAX_WALLET_TX; i++) {
        if (!w->map_wallet[i].used)
            continue;
        const struct wallet_tx *wtx = &w->map_wallet[i];
        if (wtx->confirms != 0)
            continue;
        for (size_t j = 0; j < wtx->tx.num_vout; j++) {
            if (wallet_is_mine(w, &wtx->tx.vout[j]) &&
                !wallet_is_outpoint_spent(w, &wtx->tx.hash, (uint32_t)j))
                balance += wtx->tx.vout[j].value;
        }
    }
    zcl_mutex_unlock((zcl_mutex_t *)&w->cs);
    return balance;
}

int64_t wallet_get_immature_balance(const struct wallet *w)
{
    int64_t balance = 0;
    zcl_mutex_lock((zcl_mutex_t *)&w->cs);
    for (size_t i = 0; i < MAX_WALLET_TX; i++) {
        if (!w->map_wallet[i].used)
            continue;
        const struct wallet_tx *wtx = &w->map_wallet[i];
        if (transaction_is_coinbase(&wtx->tx) &&
            wallet_tx_get_blocks_to_maturity(wtx) > 0) {
            for (size_t j = 0; j < wtx->tx.num_vout; j++) {
                if (wallet_is_mine(w, &wtx->tx.vout[j]))
                    balance += wtx->tx.vout[j].value;
            }
        }
    }
    zcl_mutex_unlock((zcl_mutex_t *)&w->cs);
    return balance;
}

/* Sign every input of wtx_out from the selected coins. On any failure this
 * unlocks w->cs, frees wtx_out->tx, sets *error and returns false; on success
 * it returns true with w->cs released. The caller computes the tx hash. */
bool wallet_sign_selected_inputs(struct wallet *w, struct wallet_tx *wtx_out,
                                 const struct coin_entry *selected,
                                 size_t num_selected, int height,
                                 const char **error)
{
    const struct chain_params *cp = chain_params_get();

    zcl_mutex_lock(&w->cs);
    for (size_t i = 0; i < num_selected; i++) {
        struct privkey skey;
        const struct tx_out *prev_out =
            &selected[i].wtx->tx.vout[selected[i].i];
        struct tx_destination prev_dest;
        if (!script_extract_destination(&prev_out->script_pub_key, &prev_dest)) {
            zcl_mutex_unlock(&w->cs);
            transaction_free(&wtx_out->tx);
            *error = "Cannot determine input destination";
            return false;
        }

        if (!keystore_get_key(&w->keystore, &prev_dest.id.key, &skey)) {
            zcl_mutex_unlock(&w->cs);
            transaction_free(&wtx_out->tx);
            *error = "Private key not available";
            return false;
        }

        struct pubkey spk;
        privkey_get_pubkey(&skey, &spk);

        uint32_t branch_id = consensus_current_epoch_branch_id(
            height + 1, &cp->consensus);
        struct sighash_type ht;
        ht.raw = SIGHASH_ALL;
        struct precomputed_tx_data txdata;
        precompute_tx_data(&wtx_out->tx, &txdata);

        struct uint256 sighash;
        if (!signature_hash(&prev_out->script_pub_key, &wtx_out->tx,
                            (unsigned int)i, ht, prev_out->value,
                            branch_id, &txdata, &sighash)) {
            memory_cleanse(skey.vch, 32);
            zcl_mutex_unlock(&w->cs);
            transaction_free(&wtx_out->tx);
            *error = "Sighash computation failed";
            return false;
        }

        unsigned char sig[SIGNATURE_SIZE + 1];
        size_t siglen = 0;
        if (!privkey_sign(&skey, &sighash, sig, &siglen)) {
            memory_cleanse(skey.vch, 32);
            zcl_mutex_unlock(&w->cs);
            transaction_free(&wtx_out->tx);
            *error = "Signing failed";
            return false;
        }
        sig[siglen++] = 0x01;

        struct script *ss = &wtx_out->tx.vin[i].script_sig;
        ss->size = 0;
        ss->data[ss->size++] = (unsigned char)siglen;
        memcpy(&ss->data[ss->size], sig, siglen);
        ss->size += siglen;
        ss->data[ss->size++] = (unsigned char)spk.size;
        memcpy(&ss->data[ss->size], spk.vch, spk.size);
        ss->size += spk.size;

        memory_cleanse(skey.vch, 32);
    }
    zcl_mutex_unlock(&w->cs);
    return true;
}

bool wallet_create_transaction(struct wallet *w,
                                const struct tx_destination *dest,
                                int64_t value,
                                struct wallet_tx *wtx_out,
                                int64_t *fee_out,
                                const char **error)
{
    if (value <= 0) {
        *error = "Invalid amount";
        return false;
    }

    const struct chain_params *cp = chain_params_get();
    /* Snapshot default_fee under a brief w->cs hold so the read is atomic
     * w.r.t. concurrent wallet mutation; do not hold w->cs across coin
     * selection below, which locks w->cs itself (would self-deadlock as
     * w->cs is non-recursive). */
    zcl_mutex_lock(&w->cs);
    int64_t fee = w->default_fee;
    zcl_mutex_unlock(&w->cs);

    struct coin_entry available[4096];
    size_t num_available = 0;
    wallet_available_coins(w, available, &num_available, 4096, true, false);

    struct coin_entry selected[4096];
    size_t num_selected = 0;
    int64_t selected_value = 0;

    if (!wallet_select_coins(w, available, num_available, value + fee,
                             selected, &num_selected, 4096, &selected_value)) {
        *error = "Insufficient funds";
        return false;
    }

    memset(wtx_out, 0, sizeof(*wtx_out));
    transaction_init(&wtx_out->tx);

    /* Snapshot best_block_height (mutated by wallet_rescan) under a brief
     * w->cs hold for an atomic read; never held across coin selection. */
    zcl_mutex_lock(&w->cs);
    int height = w->best_block_height;
    zcl_mutex_unlock(&w->cs);
    int epoch = consensus_current_epoch(height, &cp->consensus);

    if (epoch >= UPGRADE_SAPLING) {
        wtx_out->tx.overwintered = true;
        wtx_out->tx.version = SAPLING_TX_VERSION;
        wtx_out->tx.version_group_id = SAPLING_VERSION_GROUP_ID;
        wtx_out->tx.expiry_height = (uint32_t)(height + 20);
    } else if (epoch >= UPGRADE_OVERWINTER) {
        wtx_out->tx.overwintered = true;
        wtx_out->tx.version = OVERWINTER_TX_VERSION;
        wtx_out->tx.version_group_id = OVERWINTER_VERSION_GROUP_ID;
        wtx_out->tx.expiry_height = (uint32_t)(height + 20);
    }

    size_t num_out = (selected_value > value + fee) ? 2 : 1;
    if (!transaction_alloc(&wtx_out->tx, num_selected, num_out)) {
        *error = "Transaction allocation failed";
        return false;
    }

    struct script dest_script;
    script_for_destination(&dest_script, dest);
    wtx_out->tx.vout[0].value = value;
    wtx_out->tx.vout[0].script_pub_key = dest_script;

    if (num_out == 2) {
        int64_t change = selected_value - value - fee;
        struct pubkey change_pk;
        if (!wallet_get_key_from_pool(w, &change_pk)) {
            transaction_free(&wtx_out->tx);
            *error = "Cannot get change address";
            return false;
        }
        struct key_id change_kid = pubkey_get_id(&change_pk);
        struct tx_destination change_dest;
        change_dest.type = DEST_KEY_ID;
        change_dest.id.key = change_kid;
        struct script change_script;
        script_for_destination(&change_script, &change_dest);
        wtx_out->tx.vout[1].value = change;
        wtx_out->tx.vout[1].script_pub_key = change_script;
    }

    for (size_t i = 0; i < num_selected; i++) {
        wtx_out->tx.vin[i].prevout.hash = selected[i].wtx->tx.hash;
        wtx_out->tx.vin[i].prevout.n = selected[i].i;
        wtx_out->tx.vin[i].sequence = UINT32_MAX - 1;
    }

    if (!wallet_sign_selected_inputs(w, wtx_out, selected, num_selected,
                                     height, error))
        return false;

    transaction_compute_hash(&wtx_out->tx);
    wtx_out->time_received = GetTime();
    wtx_out->from_me = true;
    wtx_out->used = true;

    if (fee_out)
        *fee_out = fee;

    return true;
}

bool wallet_create_transaction_multi(struct wallet *w,
                                      const struct tx_destination *dests,
                                      const int64_t *values,
                                      size_t num_outputs,
                                      struct wallet_tx *wtx_out,
                                      int64_t *fee_out,
                                      const char **error)
{
    if (num_outputs == 0 || num_outputs > 256) {
        *error = "Invalid number of outputs";
        return false;
    }

    int64_t total_value = 0;
    for (size_t i = 0; i < num_outputs; i++) {
        if (values[i] <= 0) {
            *error = "Invalid amount";
            return false;
        }
        total_value += values[i];
    }

    const struct chain_params *cp = chain_params_get();
    /* Snapshot default_fee under a brief w->cs hold so the read is atomic
     * w.r.t. concurrent wallet mutation; do not hold w->cs across coin
     * selection below, which locks w->cs itself (would self-deadlock as
     * w->cs is non-recursive). */
    zcl_mutex_lock(&w->cs);
    int64_t fee = w->default_fee;
    zcl_mutex_unlock(&w->cs);

    struct coin_entry available[4096];
    size_t num_available = 0;
    wallet_available_coins(w, available, &num_available, 4096, true, false);

    struct coin_entry selected[4096];
    size_t num_selected = 0;
    int64_t selected_value = 0;

    if (!wallet_select_coins(w, available, num_available, total_value + fee,
                             selected, &num_selected, 4096, &selected_value)) {
        *error = "Insufficient funds";
        return false;
    }

    memset(wtx_out, 0, sizeof(*wtx_out));
    transaction_init(&wtx_out->tx);

    /* Snapshot best_block_height (mutated by wallet_rescan) under a brief
     * w->cs hold for an atomic read; never held across coin selection. */
    zcl_mutex_lock(&w->cs);
    int height = w->best_block_height;
    zcl_mutex_unlock(&w->cs);
    int epoch = consensus_current_epoch(height, &cp->consensus);

    if (epoch >= UPGRADE_SAPLING) {
        wtx_out->tx.overwintered = true;
        wtx_out->tx.version = SAPLING_TX_VERSION;
        wtx_out->tx.version_group_id = SAPLING_VERSION_GROUP_ID;
        wtx_out->tx.expiry_height = (uint32_t)(height + 20);
    } else if (epoch >= UPGRADE_OVERWINTER) {
        wtx_out->tx.overwintered = true;
        wtx_out->tx.version = OVERWINTER_TX_VERSION;
        wtx_out->tx.version_group_id = OVERWINTER_VERSION_GROUP_ID;
        wtx_out->tx.expiry_height = (uint32_t)(height + 20);
    }

    bool need_change = selected_value > total_value + fee;
    size_t total_outputs = num_outputs + (need_change ? 1 : 0);

    if (!transaction_alloc(&wtx_out->tx, num_selected, total_outputs)) {
        *error = "Transaction allocation failed";
        return false;
    }

    for (size_t i = 0; i < num_outputs; i++) {
        struct script dest_script;
        script_for_destination(&dest_script, &dests[i]);
        wtx_out->tx.vout[i].value = values[i];
        wtx_out->tx.vout[i].script_pub_key = dest_script;
    }

    if (need_change) {
        int64_t change = selected_value - total_value - fee;
        struct pubkey change_pk;
        if (!wallet_get_key_from_pool(w, &change_pk)) {
            transaction_free(&wtx_out->tx);
            *error = "Cannot get change address";
            return false;
        }
        struct key_id change_kid = pubkey_get_id(&change_pk);
        struct tx_destination change_dest;
        change_dest.type = DEST_KEY_ID;
        change_dest.id.key = change_kid;
        struct script change_script;
        script_for_destination(&change_script, &change_dest);
        wtx_out->tx.vout[num_outputs].value = change;
        wtx_out->tx.vout[num_outputs].script_pub_key = change_script;
    }

    for (size_t i = 0; i < num_selected; i++) {
        wtx_out->tx.vin[i].prevout.hash = selected[i].wtx->tx.hash;
        wtx_out->tx.vin[i].prevout.n = selected[i].i;
        wtx_out->tx.vin[i].sequence = UINT32_MAX - 1;
    }

    if (!wallet_sign_selected_inputs(w, wtx_out, selected, num_selected,
                                     height, error))
        return false;

    transaction_compute_hash(&wtx_out->tx);
    wtx_out->time_received = GetTime();
    wtx_out->from_me = true;
    wtx_out->used = true;

    if (fee_out)
        *fee_out = fee;

    return true;
}

static const char *wallet_mempool_result_name(enum mempool_accept_result r)
{
    switch (r) {
    case MEMPOOL_ACCEPT_OK:             return "ok";
    case MEMPOOL_ACCEPT_INVALID:        return "invalid";
    case MEMPOOL_ACCEPT_DUPLICATE:      return "duplicate";
    case MEMPOOL_ACCEPT_CONFLICT:       return "conflict";
    case MEMPOOL_ACCEPT_BELOW_FEE:      return "below_fee";
    case MEMPOOL_ACCEPT_MISSING_INPUTS: return "missing_inputs";
    case MEMPOOL_ACCEPT_NONFINAL:       return "nonfinal";
    case MEMPOOL_ACCEPT_EXPIRING_SOON:  return "expiring_soon";
    case MEMPOOL_ACCEPT_INTERNAL_ERROR: return "internal_error";
    case MEMPOOL_ACCEPT_UNVERIFIABLE:   return "unverifiable";
    }
    return "unknown";
}

struct zcl_result wallet_commit_transaction(
    struct wallet *w, struct wallet_tx *wtx,
    const struct wallet_tx_admission *admission)
{
    if (!w || !wtx || !admission)
        return ZCL_ERR(-1, "wallet commit: NULL wallet, tx, or admission context");
    if (!admission->mempool || !admission->coins_tip ||
        !admission->main_state || !admission->params) {
        return ZCL_ERR(-2,
            "wallet commit: incomplete validation context "
            "(mempool=%p coins_tip=%p main_state=%p params=%p)",
            (void *)admission->mempool, (void *)admission->coins_tip,
            (void *)admission->main_state, (const void *)admission->params);
    }

    /* Validate BEFORE wallet mutation: structural, shielded proof/signature,
     * input, fee, and transparent script checks all precede insertion. */
    char reject_detail[128];
    enum mempool_accept_result ar = accept_to_mempool_detailed(
        admission->mempool, admission->coins_tip, admission->main_state,
        admission->params, &wtx->tx, reject_detail, sizeof(reject_detail));
    if (ar != MEMPOOL_ACCEPT_OK) {
        return ZCL_ERR(-100 - (int)ar,
            "wallet commit: mempool admission rejected transaction (%s%s%s)",
            wallet_mempool_result_name(ar), reject_detail[0] ? ": " : "",
            reject_detail);
    }
    if (!wallet_add_to_wallet(w, wtx)) {
        /* Admission succeeded but the wallet record failed (e.g. OOM/cap).
         * Roll back the pool so callers never relay a transaction whose
         * ownership/change record could not be installed. */
        tx_mempool_remove(admission->mempool, &wtx->tx.hash);
        return ZCL_ERR(-3,
            "wallet commit: wallet record failed after admission; mempool rolled back");
    }

    /* Mutate the spent set under a brief w->cs hold so concurrent readers
     * (under w->cs) never race the writes. w->cs is non-recursive, so it is
     * never held across wallet_add_to_wallet (above) or the mempool add. */
    zcl_mutex_lock(&w->cs);
    for (size_t i = 0; i < wtx->tx.num_vin; i++)
        wallet_mark_outpoint_spent(w, &wtx->tx.vin[i].prevout.hash,
                                    wtx->tx.vin[i].prevout.n);
    wallet_key_pool_consume_transaction_outputs_locked(w, &wtx->tx);
    zcl_mutex_unlock(&w->cs);

    return ZCL_OK;
}

struct zcl_result wallet_rollback_transaction(
    struct wallet *w, const struct wallet_tx *wtx,
    struct tx_mempool *mempool)
{
    if (!w || !wtx || !mempool)
        return ZCL_ERR(-1, "wallet rollback: NULL wallet, tx, or mempool");

    /* The transaction has not been relayed yet, so removing the local pool
     * entry first prevents any later inventory scan from discovering it while
     * the wallet record is being unwound. */
    tx_mempool_remove(mempool, &wtx->tx.hash);

    zcl_mutex_lock(&w->cs);
    size_t idx = wallet_find_slot_internal(w, &wtx->tx.hash);
    if (idx >= MAX_WALLET_TX) {
        zcl_mutex_unlock(&w->cs);
        return ZCL_ERR(-2,
            "wallet rollback: committed transaction not found in wallet map");
    }

    for (size_t i = 0; i < wtx->tx.num_vin; i++)
        wallet_unmark_outpoint_spent(w, &wtx->tx.vin[i].prevout.hash,
                                     wtx->tx.vin[i].prevout.n);
    for (size_t si = 0; si < wtx->tx.num_shielded_spend; si++) {
        const uint8_t *nf = wtx->tx.v_shielded_spend[si].nullifier.data;
        for (size_t ni = 0; ni < w->num_sapling_notes; ni++) {
            if (w->sapling_notes[ni].used &&
                memcmp(w->sapling_notes[ni].nf, nf, 32) == 0)
                w->sapling_notes[ni].spent = false;
        }
    }

    transaction_free(&w->map_wallet[idx].tx);
    memset(&w->map_wallet[idx], 0, sizeof(w->map_wallet[idx]));
    if (w->num_wallet_tx > 0)
        w->num_wallet_tx--;
    zcl_mutex_unlock(&w->cs);
    return ZCL_OK;
}

int wallet_advance_confirmations(struct wallet *w, int new_best_height)
{
    if (!w)
        LOG_ERR("wallet", "advance_confirmations: NULL wallet");

    zcl_mutex_lock(&w->cs);

    int delta = new_best_height - w->best_block_height;
    if (delta <= 0) {
        /* Not a forward move (reorg, replay, or first block before the height
         * is known). Never lower a depth and never inflate one — leave every
         * stored depth exactly as it is. */
        zcl_mutex_unlock(&w->cs);
        return 0;
    }

    int raised = 0;
    for (size_t i = 0; i < MAX_WALLET_TX; i++) {
        struct wallet_tx *wtx = &w->map_wallet[i];
        if (!wtx->used || wtx->confirms < 1)
            continue;   /* unconfirmed (mempool) entries have no depth yet */
        wtx->confirms += delta;
        wallet_mark_dirty(wtx);
        raised++;
    }

    w->best_block_height = new_best_height;
    zcl_mutex_unlock(&w->cs);
    return raised;
}

bool wallet_sync_transaction(struct wallet *w, const struct transaction *tx,
                             const struct block_index *pindex)
{
    zcl_mutex_lock(&w->cs);

    /* Durable wallet membership is itself ownership evidence. After restart,
     * a locally committed outgoing transaction can survive even when its
     * parent is absent from the bounded in-memory map or none of its outputs
     * are ours (for example, exact-value shielding with no transparent
     * change). It must still be upgraded from mempool to confirmed state. */
    size_t existing = wallet_find_slot_internal(w, &tx->hash);
    bool dominated = existing < MAX_WALLET_TX;
    for (size_t i = 0; i < tx->num_vout; i++) {
        if (wallet_is_mine(w, &tx->vout[i])) {
            dominated = true;
            break;
        }
    }
    if (!dominated) {
        for (size_t i = 0; i < tx->num_vin; i++) {
            size_t idx = wallet_find_slot_internal(w,
                                                   &tx->vin[i].prevout.hash);
            if (idx < MAX_WALLET_TX) {
                dominated = true;
                break;
            }
        }
    }

    if (!dominated) {
        zcl_mutex_unlock(&w->cs);
        return false;
    }

    struct wallet_tx wtx;
    memset(&wtx, 0, sizeof(wtx));
    wtx.tx = *tx;
    wtx.tx.vin = NULL;
    wtx.tx.vout = NULL;
    wtx.time_received = GetTime();
    wtx.from_me = false;
    wtx.used = true;

    if (pindex) {
        if (pindex->phashBlock)
            wtx.hash_block = *pindex->phashBlock;
        int depth = w->best_block_height - pindex->nHeight + 1;
        wtx.confirms = depth > 0 ? depth : 1;
        if (dominated && depth <= 0)
            LOG_WARN("wallet", "tx at height %d, best=%d, depth=%d, confirms=%d",
                     pindex->nHeight, w->best_block_height, depth, wtx.confirms);
    }

    for (size_t i = 0; i < tx->num_vin; i++) {
        size_t idx = wallet_find_slot_internal(w, &tx->vin[i].prevout.hash);
        if (idx < MAX_WALLET_TX) {
            wtx.from_me = true;
            uint32_t n = tx->vin[i].prevout.n;
            const struct wallet_tx *prev = &w->map_wallet[idx];
            if (n < prev->tx.num_vout &&
                wallet_is_mine(w, &prev->tx.vout[n]))
                wallet_mark_outpoint_spent(w, &tx->vin[i].prevout.hash, n);
        }
    }

    if (existing < MAX_WALLET_TX) {
        w->map_wallet[existing].hash_block = wtx.hash_block;
        w->map_wallet[existing].confirms = wtx.confirms;
        wallet_mark_dirty(&w->map_wallet[existing]);
    } else {
        wtx.tx.vin = (struct tx_in *)tx->vin;
        wtx.tx.vout = (struct tx_out *)tx->vout;
        zcl_mutex_unlock(&w->cs);
        return wallet_add_to_wallet(w, &wtx);
    }

    zcl_mutex_unlock(&w->cs);
    return true;
}

bool wallet_import_key(struct wallet *w, const struct privkey *key)
{
    zcl_mutex_lock(&w->cs);
    bool ok = keystore_add_key(&w->keystore, key);
    zcl_mutex_unlock(&w->cs);
    return ok;
}

bool wallet_remove_key(struct wallet *w, const struct key_id *keyid)
{
    if (!w || !keyid) return false;
    zcl_mutex_lock(&w->cs);
    bool ok = keystore_remove_key(&w->keystore, keyid);
    zcl_mutex_unlock(&w->cs);
    return ok;
}

bool wallet_dump_key(const struct wallet *w, const struct key_id *keyid,
                      struct privkey *key_out)
{
    return keystore_get_key(&w->keystore, keyid, key_out);
}

int wallet_tx_get_blocks_to_maturity(const struct wallet_tx *wtx)
{
    if (!transaction_is_coinbase(&wtx->tx))
        return 0;
    int maturity = COINBASE_MATURITY - wtx->confirms;
    return maturity > 0 ? maturity : 0;
}

/* Scan raw block files for wallet transactions — no index needed */
static void wallet_process_block_for_spent(struct wallet *w,
                                             const struct block *b)
{
    for (size_t i = 0; i < b->num_vtx; i++) {
        const struct transaction *tx = &b->vtx[i];

        /* Check if any input spends a wallet output we own */
        for (size_t j = 0; j < tx->num_vin; j++) {
            size_t idx = wallet_find_slot_internal(w,
                                                   &tx->vin[j].prevout.hash);
            if (idx < MAX_WALLET_TX) {
                const struct wallet_tx *prev = &w->map_wallet[idx];
                uint32_t n = tx->vin[j].prevout.n;
                if (n < prev->tx.num_vout &&
                    wallet_is_mine(w, &prev->tx.vout[n]))
                    wallet_mark_outpoint_spent(w, &tx->vin[j].prevout.hash, n);
            }
        }

        /* Check if any output pays to our wallet */
        bool dominated = false;
        for (size_t j = 0; j < tx->num_vout; j++) {
            if (wallet_is_mine(w, &tx->vout[j])) {
                dominated = true;
                break;
            }
        }

        if (dominated) {
            /* Add to wallet with at least 1 confirm since it's in a block */
            struct uint256 txhash;
            transaction_compute_hash((struct transaction *)tx);
            txhash = tx->hash;
            size_t existing = wallet_find_slot_internal(w, &txhash);
            if (existing < MAX_WALLET_TX) {
                if (w->map_wallet[existing].confirms < 1)
                    w->map_wallet[existing].confirms = 1;
            } else {
                wallet_sync_transaction(w, tx, NULL);
                existing = wallet_find_slot_internal(w, &txhash);
                if (existing < MAX_WALLET_TX)
                    w->map_wallet[existing].confirms = 1;
            }
        }
    }
}

int wallet_scan_blockfiles(struct wallet *w, const char *datadir)
{
    LOG_INFO("wallet", "Scanning block files for wallet transactions...");
    int64_t t_start = GetTime();
    int total_found = 0;
    int blocks_scanned = 0;

    const struct chain_params *cp = chain_params_get();
    const unsigned char *magic = cp->pchMessageStart;

    for (int file_num = 0; file_num < 9999; file_num++) {
        char path[512];
        snprintf(path, sizeof(path), "%s/blocks/blk%05d.dat",
                 datadir, file_num);

        unsigned char *buf = NULL;
        size_t nread = 0;
        if (!zcl_read_whole_file(path, 0, &buf, &nread, "wallet"))
            break;

        /* Parse blocks from the file */
        size_t pos = 0;
        while (pos + 8 < nread) {
            /* Find magic bytes */
            if (memcmp(buf + pos, magic, 4) != 0) {
                pos++;
                continue;
            }
            pos += 4;

            uint32_t block_size;
            memcpy(&block_size, buf + pos, 4);
            pos += 4;

            if (block_size == 0 || pos + block_size > nread)
                break;

            struct byte_stream bs;
            stream_init_from_data(&bs, buf + pos, block_size);
            struct block b;
            block_init(&b);
            if (block_deserialize(&b, &bs)) {
                blocks_scanned++;
                wallet_process_block_for_spent(w, &b);
                for (size_t i = 0; i < b.num_vtx; i++) {
                    for (size_t j = 0; j < b.vtx[i].num_vout; j++) {
                        if (wallet_is_mine(w, &b.vtx[i].vout[j]))
                            total_found++;
                    }
                }
            }
            block_free(&b);
            pos += block_size;
        }

        free(buf);

        if (file_num % 10 == 0)
            LOG_INFO("wallet", "scanned blk%05d.dat (%d blocks so far)",
                     file_num, blocks_scanned);
    }

    int64_t elapsed = GetTime() - t_start;
    LOG_INFO("wallet", "Block file scan: %d blocks in %"PRId64"s, %d wallet outputs, %zu spent outpoints.",
             blocks_scanned, elapsed, total_found, w->num_spent);

    return total_found;
}

/* --- Sapling trial decryption --- */

static bool wallet_add_sapling_note(struct wallet *w,
                                     const struct sapling_received_note *note)
{
    /* w->cs guards the sapling_notes array, its count and capacity. The
     * append below reallocs (freeing the old buffer), so it must be
     * serialized against every reader; see wallet_copy_sapling_notes(). */
    zcl_mutex_lock(&w->cs);
    /* Check for duplicate */
    for (size_t i = 0; i < w->num_sapling_notes; i++) {
        if (uint256_eq(&w->sapling_notes[i].txid, &note->txid) &&
            w->sapling_notes[i].output_index == note->output_index) {
            zcl_mutex_unlock(&w->cs);
            return false;
        }
    }

    if (w->num_sapling_notes >= w->sapling_notes_cap) {
        size_t new_cap = w->sapling_notes_cap == 0 ? 64 : w->sapling_notes_cap * 2;
        struct sapling_received_note *new_buf = zcl_realloc(
            w->sapling_notes, new_cap * sizeof(*new_buf), "sapling_notes");
        if (!new_buf) {
            zcl_mutex_unlock(&w->cs);
            return false;
        }
        w->sapling_notes = new_buf;
        w->sapling_notes_cap = new_cap;
    }
    w->sapling_notes[w->num_sapling_notes] = *note;
    w->sapling_notes[w->num_sapling_notes].used = true;
    w->num_sapling_notes++;
    zcl_mutex_unlock(&w->cs);
    return true;
}

int wallet_try_sapling_decrypt(struct wallet *w,
                                const struct transaction *tx,
                                const struct uint256 *txid)
{
    int found = 0;

    for (size_t oi = 0; oi < tx->num_shielded_output; oi++) {
        const struct output_description *od = &tx->v_shielded_output[oi];

        for (size_t ki = 0; ki < w->sapling_keys.num_keys; ki++) {
            const struct sapling_key_entry *ke = &w->sapling_keys.keys[ki];
            if (!ke->used)
                continue;

            /* Key agreement: dhsecret = [ivk] * epk */
            uint8_t dhsecret[32];
            if (!sapling_ka_agree(od->ephemeral_key.data, ke->ivk, dhsecret))
                continue;

            /* KDF */
            uint8_t dec_key[32];
            if (!sapling_kdf(dec_key, dhsecret, od->ephemeral_key.data)) {
                memory_cleanse(dhsecret, 32);
                continue;
            }
            memory_cleanse(dhsecret, 32);

            /* Try decrypt */
            uint8_t plaintext[ZC_SAPLING_ENCPLAINTEXT_SIZE];
            if (!sapling_note_decrypt(dec_key, od->enc_ciphertext,
                                       ZC_SAPLING_ENCCIPHERTEXT_SIZE,
                                       plaintext)) {
                memory_cleanse(dec_key, 32);
                continue;
            }
            memory_cleanse(dec_key, 32);

            /* Parse plaintext: leadbyte(1) || d(11) || v(8) || rcm(32) || memo(512) */
            if (plaintext[0] != 0x01)
                continue;

            uint8_t d[11];
            memcpy(d, plaintext + 1, 11);
            uint64_t value = 0;
            for (int b = 0; b < 8; b++)
                value |= ((uint64_t)plaintext[12 + b]) << (8 * b);
            uint8_t rcm[32];
            memcpy(rcm, plaintext + 20, 32);

            /* Derive pk_d from ivk and decrypted diversifier to verify */
            uint8_t pk_d[32];
            if (!sapling_ivk_to_pkd(ke->ivk, d, pk_d))
                continue;

            /* Recompute cm and verify against output_description.cm */
            uint8_t cm[32];
            if (!sapling_compute_cm(d, pk_d, value, rcm, cm))
                continue;

            if (memcmp(cm, od->cm.data, 32) != 0)
                continue;

            /* Compute nullifier for spend detection */
            uint8_t ak[32], nk[32];
            sapling_ask_to_ak(ke->xsk.expsk.ask, ak);
            sapling_nsk_to_nk(ke->xsk.expsk.nsk, nk);

            struct sapling_received_note note = {0};
            note.txid = *txid;
            note.output_index = (uint32_t)oi;
            memcpy(note.diversifier, d, 11);
            memcpy(note.pk_d, pk_d, 32);
            note.value = value;
            memcpy(note.rcm, rcm, 32);
            memcpy(note.memo, plaintext + 52, 512);
            memcpy(note.ivk, ke->ivk, 32);
            memcpy(note.cm, cm, 32);

            /* The Sapling nullifier needs the note's ABSOLUTE leaf position
             * in the global commitment tree (rho = MixingPedersenHash(cm,
             * position)). That position is NOT knowable here: trial-decrypt
             * runs over a transaction during a block scan, before this note's
             * commitment has been appended to the tree, and a later reorg can
             * still change it. Computing nf with a guessed position would
             * produce a WRONG nullifier that never matches the on-chain spend
             * — strictly worse than this honest placeholder (which simply
             * never matches, so spend detection on this in-memory path is a
             * no-op rather than a false positive). The correct nf must be
             * (re)computed at witness-creation time in advance_wallet_witnesses()
             * (sync_controller_blocks.c) where position =
             * incremental_tree_size(tree) - 1 is exact. See BUG #7 and the
             * regression test in test_sapling.c ("BUG#7 nullifier position").
             * Position 0 placeholder is kept (not all-zero) so the derived
             * nullifier is non-blank and the note still persists past the
             * ActiveRecord presence validation. */
            sapling_compute_nf(d, pk_d, value, rcm, ak, nk, 0, note.nf);

            note.spent = false;

            if (wallet_add_sapling_note(w, &note))
                found++;

            memory_cleanse(plaintext, sizeof(plaintext));
            break; /* This ivk matched, move to next output */
        }
    }
    return found;
}

bool wallet_sapling_nullifier_is_spent(const struct wallet *w,
                                        const uint8_t nf[32])
{
    zcl_mutex_lock((zcl_mutex_t *)&w->cs);
    for (size_t i = 0; i < w->num_sapling_notes; i++) {
        if (w->sapling_notes[i].used && w->sapling_notes[i].spent &&
            memcmp(w->sapling_notes[i].nf, nf, 32) == 0) {
            zcl_mutex_unlock((zcl_mutex_t *)&w->cs);
            return true;
        }
    }
    zcl_mutex_unlock((zcl_mutex_t *)&w->cs);
    return false;
}

void wallet_mark_sapling_nullifiers_spent(struct wallet *w,
                                           const struct transaction *tx)
{
    zcl_mutex_lock(&w->cs);
    for (size_t si = 0; si < tx->num_shielded_spend; si++) {
        const uint8_t *nf = tx->v_shielded_spend[si].nullifier.data;
        for (size_t ni = 0; ni < w->num_sapling_notes; ni++) {
            if (w->sapling_notes[ni].used && !w->sapling_notes[ni].spent &&
                memcmp(w->sapling_notes[ni].nf, nf, 32) == 0) {
                w->sapling_notes[ni].spent = true;
            }
        }
    }
    zcl_mutex_unlock(&w->cs);
}

int64_t wallet_get_sapling_balance(const struct wallet *w)
{
    int64_t balance = 0;
    zcl_mutex_lock((zcl_mutex_t *)&w->cs);
    for (size_t i = 0; i < w->num_sapling_notes; i++) {
        if (w->sapling_notes[i].used && !w->sapling_notes[i].spent)
            balance += (int64_t)w->sapling_notes[i].value;
    }
    zcl_mutex_unlock((zcl_mutex_t *)&w->cs);
    return balance;
}

struct sapling_received_note *wallet_copy_sapling_notes(const struct wallet *w,
                                                         size_t *count)
{
    /* Point-in-time snapshot taken under w->cs so callers can iterate the
     * notes without holding the wallet lock and without racing a concurrent
     * wallet_add_sapling_note() realloc that frees the live array. */
    zcl_mutex_lock((zcl_mutex_t *)&w->cs);
    size_t n = w->num_sapling_notes;
    struct sapling_received_note *snap = NULL;
    if (n > 0) {
        snap = zcl_malloc(n * sizeof(*snap), "sapling_notes_snapshot");
        if (snap)
            memcpy(snap, w->sapling_notes, n * sizeof(*snap));
        else
            n = 0; /* OOM: report an empty snapshot, never a torn one */
    }
    zcl_mutex_unlock((zcl_mutex_t *)&w->cs);
    if (count)
        *count = n;
    return snap;
}
