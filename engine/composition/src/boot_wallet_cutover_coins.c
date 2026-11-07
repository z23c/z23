/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: pinned coin state for wallet checkpoint publication. */
#include "config/boot_wallet_cutover_coins.h"
#include "core/amount.h"
#include "primitives/transaction.h"
#include "sha3/sha3.h"
#include "util/safe_alloc.h"
#include "wallet/wallet.h"
#include <limits.h>
#include <stdlib.h>
#include <string.h>

#define BOOT_COINS_MAX_OUTPUTS 65536u

struct boot_coins_entry {
    uint8_t txid[32], script_digest[32];
    uint32_t vout;
    int64_t value;
    size_t script_len;
    int height;
    bool coinbase;
    enum db_cutover_coin_verdict verdict;
};
struct boot_cutover_coins {
    struct boot_coins_entry *entries;
    size_t count, capacity;
    int reference_height;
    uint64_t generation;
    uint8_t reference_hash[32], identity[32];
};

static bool boot_coins_script(const struct tx_out *out, uint8_t digest[32])
{
    if (!out || out->value < 0 || out->value > MAX_MONEY ||
        out->script_pub_key.size > sizeof(out->script_pub_key.data)) return false;
    sha3_256(out->script_pub_key.data, out->script_pub_key.size, digest);
    return true;
}

static enum boot_cutover_coins_status boot_coins_append(struct boot_cutover_coins *cache,
    const struct wallet_tx *tx, uint32_t vout, int height)
{
    if (cache->count == BOOT_COINS_MAX_OUTPUTS) return BOOT_CUTOVER_COINS_LIMIT;
    if (cache->count == cache->capacity) {
        size_t next = cache->capacity ? cache->capacity * 2 : 32;
        if (next > BOOT_COINS_MAX_OUTPUTS) next = BOOT_COINS_MAX_OUTPUTS;
        void *grown = zcl_realloc(cache->entries, next * sizeof(*cache->entries), "cutover coin cache");
        if (!grown) return BOOT_CUTOVER_COINS_ERROR;
        cache->entries = grown; cache->capacity = next;
    }
    const struct tx_out *out = &tx->tx.vout[vout];
    struct boot_coins_entry entry = {.vout = vout, .value = out->value,
        .script_len = out->script_pub_key.size, .height = height,
        .coinbase = transaction_is_coinbase(&tx->tx), .verdict = DB_CUTOVER_COIN_UNKNOWN};
    if (!boot_coins_script(out, entry.script_digest)) return BOOT_CUTOVER_COINS_INVALID;
    memcpy(entry.txid, tx->tx.hash.data, 32);
    cache->entries[cache->count++] = entry;
    return BOOT_CUTOVER_COINS_OK;
}

static enum boot_cutover_coins_status boot_coins_capture_tx(struct boot_cutover_coins *cache,
    struct wallet *wallet, const struct wallet_tx *tx, wallet_height_resolver resolve, void *chain_ctx)
{
    const uint8_t zero[32] = {0};
    if (!memcmp(tx->hash_block.data, zero, 32)) return BOOT_CUTOVER_COINS_OK;
    int height = -1;
    if (!memcmp(tx->tx.hash.data, zero, 32) || !resolve(chain_ctx, tx->hash_block.data, &height) ||
        height < 0 || height > cache->reference_height || tx->tx.num_vout > MAX_TX_OUTPUTS ||
        (tx->tx.num_vout && !tx->tx.vout)) return BOOT_CUTOVER_COINS_INVALID;
    for (size_t i = 0; i < tx->tx.num_vout; i++) {
        const struct tx_out *out = &tx->tx.vout[i];
        if (out->script_pub_key.size > sizeof(out->script_pub_key.data)) return BOOT_CUTOVER_COINS_INVALID;
        if (!wallet_is_mine(wallet, out)) continue;
        enum boot_cutover_coins_status status = boot_coins_append(cache, tx, (uint32_t)i, height);
        if (status != BOOT_CUTOVER_COINS_OK) return status;
    }
    return BOOT_CUTOVER_COINS_OK;
}

static enum boot_cutover_coins_status boot_coins_capture(struct boot_cutover_coins *cache,
    struct wallet *wallet, wallet_height_resolver resolve, void *chain_ctx)
{
    if (!zcl_mutex_trylock(&wallet->cs)) return BOOT_CUTOVER_COINS_BUSY;
    bool key = zcl_mutex_trylock(&wallet->keystore.cs);
    bool sapling = key && zcl_mutex_trylock(&wallet->sapling_keys.cs);
    enum boot_cutover_coins_status status = BOOT_CUTOVER_COINS_BUSY;
    if (sapling) {
        uint8_t identity[32];
        status = wallet_scan_identity_locked(wallet, identity) && !memcmp(identity, cache->identity, 32)
            ? BOOT_CUTOVER_COINS_OK : BOOT_CUTOVER_COINS_INVALID;
        for (size_t i = 0; status == BOOT_CUTOVER_COINS_OK && i < MAX_WALLET_TX; i++)
            if (wallet->map_wallet[i].used)
                status = boot_coins_capture_tx(cache, wallet, &wallet->map_wallet[i], resolve, chain_ctx);
    }
    if (sapling) zcl_mutex_unlock(&wallet->sapling_keys.cs);
    if (key) zcl_mutex_unlock(&wallet->keystore.cs);
    zcl_mutex_unlock(&wallet->cs);
    return status;
}

static int boot_coins_key_compare(const void *left, const void *right)
{
    const struct boot_coins_entry *a = left, *b = right;
    int cmp = memcmp(a->txid, b->txid, 32);
    return cmp ? cmp : (a->vout > b->vout) - (a->vout < b->vout);
}

static bool boot_coins_row_matches(const struct boot_coins_entry *entry,
                                   const struct coins_kv_read_snapshot_row *row)
{
    if (memcmp(entry->txid, row->txid, 32) || entry->vout != row->vout ||
        entry->value != row->value || entry->height != row->height || entry->coinbase != row->is_coinbase ||
        entry->script_len != row->script_len || (row->script_len && !row->script)) return false;
    uint8_t digest[32]; sha3_256(row->script, row->script_len, digest);
    return !memcmp(digest, entry->script_digest, 32);
}

static enum boot_cutover_coins_status boot_coins_lookup(struct boot_cutover_coins *cache,
                                                         struct coins_kv_read_snapshot *snapshot)
{
    if (cache->count) qsort(cache->entries, cache->count, sizeof(*cache->entries), boot_coins_key_compare);
    for (size_t i = 0; i < cache->count; i++) {
        if (i && boot_coins_key_compare(&cache->entries[i - 1], &cache->entries[i]) == 0)
            return BOOT_CUTOVER_COINS_INVALID;
        struct boot_coins_entry *entry = &cache->entries[i];
        struct coins_kv_read_snapshot_row row;
        enum coins_kv_read_snapshot_lookup_result found = coins_kv_read_snapshot_lookup(snapshot, entry->txid, entry->vout, &row);
        if (found == COINS_KV_LOOKUP_ERROR) return BOOT_CUTOVER_COINS_ERROR;
        if (found == COINS_KV_LOOKUP_ABSENT) entry->verdict = DB_CUTOVER_COIN_SPENT;
        else if (found == COINS_KV_LOOKUP_FOUND && boot_coins_row_matches(entry, &row)) entry->verdict = DB_CUTOVER_COIN_UNSPENT;
        else return BOOT_CUTOVER_COINS_INVALID;
    }
    return BOOT_CUTOVER_COINS_OK;
}

static bool boot_coins_request_valid(struct wallet *wallet, struct coins_kv_read_snapshot *snapshot,
    const struct coins_kv_read_snapshot_info *info, int reference_height,
    const uint8_t reference_hash[32], uint64_t generation, const uint8_t scan_identity[32],
    wallet_height_resolver resolver, struct boot_cutover_coins **out)
{
    return out && wallet && snapshot && info && reference_hash && scan_identity && resolver &&
        reference_height >= 0 && reference_height < INT_MAX && info->applied_height == reference_height + 1 && info->authority_generation == generation;
}

enum boot_cutover_coins_status boot_cutover_coins_prepare(
    struct wallet *wallet, struct coins_kv_read_snapshot *snapshot,
    const struct coins_kv_read_snapshot_info *info, int reference_height,
    const uint8_t reference_hash[32], uint64_t generation, const uint8_t scan_identity[32],
    wallet_height_resolver resolver, void *chain_ctx, struct boot_cutover_coins **out)
{
    if (out) *out = NULL;
    if (!boot_coins_request_valid(wallet, snapshot, info, reference_height, reference_hash,
                                  generation, scan_identity, resolver, out))
        return BOOT_CUTOVER_COINS_INVALID;
    int resolved = -1;
    if (!resolver(chain_ctx, reference_hash, &resolved) || resolved != reference_height) return BOOT_CUTOVER_COINS_INVALID;
    struct boot_cutover_coins *cache = zcl_calloc(1, sizeof(*cache), "cutover coins cache");
    if (!cache) return BOOT_CUTOVER_COINS_ERROR;
    cache->reference_height = reference_height; cache->generation = generation;
    memcpy(cache->reference_hash, reference_hash, 32); memcpy(cache->identity, scan_identity, 32);
    enum boot_cutover_coins_status status = boot_coins_capture(cache, wallet, resolver, chain_ctx);
    if (status == BOOT_CUTOVER_COINS_OK) status = boot_coins_lookup(cache, snapshot);
    if (status != BOOT_CUTOVER_COINS_OK) { boot_cutover_coins_free(cache); return status; }
    *out = cache;
    return BOOT_CUTOVER_COINS_OK;
}

bool boot_cutover_coins_matches(const struct boot_cutover_coins *cache,
    int reference_height, const uint8_t reference_hash[32], uint64_t generation,
    const uint8_t scan_identity[32])
{
    return cache && reference_hash && scan_identity && cache->reference_height == reference_height &&
        cache->generation == generation && !memcmp(cache->reference_hash, reference_hash, 32) &&
        !memcmp(cache->identity, scan_identity, 32);
}

enum db_cutover_coin_verdict boot_cutover_coins_verdict(void *opaque,
    const uint8_t txid[32], uint32_t vout, const struct tx_out *expected, int height, bool coinbase)
{
    const struct boot_cutover_coins *cache = opaque;
    uint8_t digest[32];
    if (!cache || !cache->count || !txid || !boot_coins_script(expected, digest)) return DB_CUTOVER_COIN_UNKNOWN;
    struct boot_coins_entry key = {.vout = vout}; memcpy(key.txid, txid, 32);
    const struct boot_coins_entry *entry = bsearch(&key, cache->entries, cache->count, sizeof(*cache->entries), boot_coins_key_compare);
    if (!entry || entry->value != expected->value || entry->height != height || entry->coinbase != coinbase ||
        entry->script_len != expected->script_pub_key.size || memcmp(entry->script_digest, digest, 32))
        return DB_CUTOVER_COIN_UNKNOWN;
    return entry->verdict;
}

void boot_cutover_coins_free(struct boot_cutover_coins *cache)
{
    if (!cache) return;
    free(cache->entries); free(cache);
}
