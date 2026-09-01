/* Copyright (c) 2009-2010 Satoshi Nakamoto
 * Copyright (c) 2009-2014 The Bitcoin Core developers
 * Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. */

#include "coins/coins_view.h"
#include "sapling/incremental_merkle_tree.h"
#include <stdio.h>
#include <string.h>
#include "util/log_macros.h"
#include "util/safe_alloc.h"

#define COINS_MAP_INITIAL_BUCKETS 4096
#define COINS_MAP_LOAD_FACTOR_NUM 3
#define COINS_MAP_LOAD_FACTOR_DEN 4

static void coins_map_rehash(struct coins_map *m, size_t new_num_buckets);

/* The bucket index for every map operation in this file.
 *
 * Normally this is coins_map_hash() (the txid's first 8 bytes). When the
 * test-only regression hook is armed (coins/coins_fault.h) it collapses to a
 * single constant bucket: every find/insert/erase still returns the CORRECT
 * entry — linear probing over a consistent hash always does — but the probe
 * walk degrades from O(1) to O(n), which is what makes the whole UTXO fold
 * O(n^2). That is the regression tools/sim/simperf.c must be able to catch.
 *
 * Unarmed cost is one load of a struct field the caller has already touched
 * (`m` is in cache on every path below), so the hot path pays no global read,
 * no atomic, and no call. */
static inline uint64_t coins_map_bucket_of(const struct coins_map *m,
                                           const struct uint256 *txid)
{
    if (m->degraded_hash)
        return 0;
    return coins_map_hash(txid);
}

struct coins_cache_entry *coins_map_find(struct coins_map *m,
                                          const struct uint256 *txid)
{
    if (m->num_buckets == 0)
        return NULL;
    uint64_t h = coins_map_bucket_of(m, txid);
    size_t idx = (size_t)(h % m->num_buckets);
    for (size_t i = 0; i < m->num_buckets; i++) {
        size_t slot = (idx + i) % m->num_buckets;
        if (!m->buckets[slot].occupied)
            return NULL;
        if (uint256_cmp(&m->buckets[slot].txid, txid) == 0)
            return &m->buckets[slot].entry;
    }
    return NULL;
}

struct coins_cache_entry *coins_map_insert(struct coins_map *m,
                                            const struct uint256 *txid)
{
    if (m->num_buckets > 0) {
        struct coins_cache_entry *existing = coins_map_find(m, txid);
        if (existing)
            return existing;
    }

    if (m->num_buckets == 0 ||
        m->size * COINS_MAP_LOAD_FACTOR_DEN >=
            m->num_buckets * COINS_MAP_LOAD_FACTOR_NUM) {
        size_t new_cap = m->num_buckets == 0
            ? COINS_MAP_INITIAL_BUCKETS : m->num_buckets * 2;
        coins_map_rehash(m, new_cap);
    }

    uint64_t h = coins_map_bucket_of(m, txid);
    size_t idx = (size_t)(h % m->num_buckets);
    for (size_t i = 0; i < m->num_buckets; i++) {
        size_t slot = (idx + i) % m->num_buckets;
        if (!m->buckets[slot].occupied) {
            m->buckets[slot].txid = *txid;
            coins_init(&m->buckets[slot].entry.coins);
            m->buckets[slot].entry.flags = 0;
            m->buckets[slot].occupied = true;
            m->size++;
            return &m->buckets[slot].entry;
        }
    }
    return NULL;
}

bool coins_map_erase(struct coins_map *m, const struct uint256 *txid)
{
    if (m->num_buckets == 0)
        return false;
    uint64_t h = coins_map_bucket_of(m, txid);
    size_t idx = (size_t)(h % m->num_buckets);
    for (size_t i = 0; i < m->num_buckets; i++) {
        size_t slot = (idx + i) % m->num_buckets;
        if (!m->buckets[slot].occupied)
            return false;
        if (uint256_cmp(&m->buckets[slot].txid, txid) == 0) {
            coins_free(&m->buckets[slot].entry.coins);
            m->buckets[slot].occupied = false;
            m->size--;
            /* Rehash subsequent entries to fill the gap */
            size_t next = (slot + 1) % m->num_buckets;
            while (m->buckets[next].occupied) {
                struct coins_map_entry tmp = m->buckets[next];
                m->buckets[next].occupied = false;
                m->size--;
                /* Re-insert */
                uint64_t rh = coins_map_bucket_of(m, &tmp.txid);
                size_t ri = (size_t)(rh % m->num_buckets);
                for (size_t j = 0; j < m->num_buckets; j++) {
                    size_t rs = (ri + j) % m->num_buckets;
                    if (!m->buckets[rs].occupied) {
                        m->buckets[rs] = tmp;
                        m->size++;
                        break;
                    }
                }
                next = (next + 1) % m->num_buckets;
            }
            return true;
        }
    }
    return false;
}

size_t coins_map_count(const struct coins_map *m)
{
    return m->size;
}

static void coins_map_rehash(struct coins_map *m, size_t new_num_buckets)
{
    struct coins_map_entry *old = m->buckets;
    size_t old_num = m->num_buckets;

    m->buckets = zcl_calloc(new_num_buckets, sizeof(struct coins_map_entry), "coins_map_buckets");
    if (!m->buckets) {
        m->buckets = old;
        return;
    }
    m->num_buckets = new_num_buckets;
    m->size = 0;

    if (old) {
        for (size_t i = 0; i < old_num; i++) {
            if (old[i].occupied) {
                uint64_t h = coins_map_bucket_of(m, &old[i].txid);
                size_t idx = (size_t)(h % new_num_buckets);
                for (size_t j = 0; j < new_num_buckets; j++) {
                    size_t slot = (idx + j) % new_num_buckets;
                    if (!m->buckets[slot].occupied) {
                        m->buckets[slot] = old[i];
                        m->size++;
                        break;
                    }
                }
            }
        }
        free(old);
    }
}

void coins_view_cache_init(struct coins_view_cache *c, struct coins_view *backing)
{
    c->base = *backing;
    coins_map_init(&c->cache_coins);
    uint256_set_null(&c->hash_block);
    c->cached_coins_usage = 0;
    utxo_commitment_init(&c->commitment);
}

void coins_view_cache_free(struct coins_view_cache *c)
{
    coins_map_free(&c->cache_coins);
    c->cached_coins_usage = 0;
}

void coins_view_cache_account_vout_resize(struct coins_view_cache *c,
                                           size_t old_count,
                                           size_t new_count)
{
    if (!c || new_count <= old_count)
        return;
    size_t count = new_count - old_count;
    if (count > SIZE_MAX / sizeof(struct tx_out) ||
        c->cached_coins_usage > SIZE_MAX - count * sizeof(struct tx_out))
        c->cached_coins_usage = SIZE_MAX;
    else
        c->cached_coins_usage += count * sizeof(struct tx_out);
}

size_t coins_view_cache_memory_usage(const struct coins_view_cache *c)
{
    if (!c)
        return 0;
    if (c->cache_coins.num_buckets >
            SIZE_MAX / sizeof(struct coins_map_entry))
        return SIZE_MAX;
    size_t buckets = c->cache_coins.num_buckets *
                     sizeof(struct coins_map_entry);
    return c->cached_coins_usage > SIZE_MAX - buckets
        ? SIZE_MAX : c->cached_coins_usage + buckets;
}

bool coins_view_cache_get_coins(struct coins_view_cache *c,
                                const struct uint256 *txid,
                                struct coins *out)
{
    struct coins_cache_entry *entry = coins_map_find(&c->cache_coins, txid);
    if (entry) {
        if (coins_is_pruned(&entry->coins))
            return false;
        coins_copy(out, &entry->coins);
        return true;
    }

    struct coins fetched;
    coins_init(&fetched);
    if (coins_view_get_coins(&c->base, txid, &fetched)) {
        struct coins_cache_entry *new_entry =
            coins_map_insert(&c->cache_coins, txid);
        if (!new_entry) { coins_free(&fetched); return false; }
        new_entry->coins = fetched;
        coins_view_cache_account_vout_resize(
            c, 0, new_entry->coins.num_vout);
        if (coins_is_pruned(&new_entry->coins))
            return false;
        coins_copy(out, &new_entry->coins);
        return true;
    }
    return false;
}

bool coins_view_cache_have_coins(struct coins_view_cache *c,
                                 const struct uint256 *txid)
{
    struct coins_cache_entry *entry = coins_map_find(&c->cache_coins, txid);
    if (entry)
        return !coins_is_pruned(&entry->coins);
    struct coins tmp;
    coins_init(&tmp);
    bool has = coins_view_get_coins(&c->base, txid, &tmp);
    coins_free(&tmp);
    return has;
}

bool coins_view_cache_invalidate(struct coins_view_cache *c,
                                 const struct uint256 *txid)
{
    if (!c || !txid)
        return false;
    return coins_map_erase(&c->cache_coins, txid);
}

void coins_view_cache_get_best_block(struct coins_view_cache *c,
                                     struct uint256 *out)
{
    if (uint256_is_null(&c->hash_block))
        coins_view_get_best_block(&c->base, &c->hash_block);
    *out = c->hash_block;
}

void coins_view_cache_set_best_block(struct coins_view_cache *c,
                                     const struct uint256 *hash)
{
    c->hash_block = *hash;
}

struct coins_cache_entry *coins_view_cache_modify(struct coins_view_cache *c,
                                                   const struct uint256 *txid)
{
    struct coins_cache_entry *entry = coins_map_find(&c->cache_coins, txid);
    if (entry) {
        entry->flags |= COINS_CACHE_DIRTY;
        return entry;
    }

    struct coins_cache_entry *new_entry = coins_map_insert(&c->cache_coins, txid);
    if (!new_entry) return NULL;
    coins_view_get_coins(&c->base, txid, &new_entry->coins);
    coins_view_cache_account_vout_resize(c, 0, new_entry->coins.num_vout);
    new_entry->flags |= COINS_CACHE_DIRTY;
    return new_entry;
}

struct coins_cache_entry *coins_view_cache_modify_new(struct coins_view_cache *c,
                                                       const struct uint256 *txid)
{
    struct coins_cache_entry *entry = coins_map_insert(&c->cache_coins, txid);
    if (!entry) return NULL;
    entry->flags |= COINS_CACHE_DIRTY | COINS_CACHE_FRESH;
    return entry;
}

static bool cvc_get_coins(void *self, const struct uint256 *txid,
                           struct coins *coins)
{
    return coins_view_cache_get_coins((struct coins_view_cache *)self,
                                      txid, coins);
}

static bool cvc_have_coins(void *self, const struct uint256 *txid)
{
    return coins_view_cache_have_coins((struct coins_view_cache *)self, txid);
}

static bool cvc_get_best_block(void *self, struct uint256 *hash)
{
    coins_view_cache_get_best_block((struct coins_view_cache *)self, hash);
    return true;
}

static enum coins_anchor_lookup_result cvc_get_anchor(
    void *self, enum coins_anchor_pool pool, const struct uint256 *root,
    struct incremental_merkle_tree *tree_out)
{
    struct coins_view_cache *cache = (struct coins_view_cache *)self;
    return coins_view_get_anchor(&cache->base, pool, root, tree_out);
}

static bool cvc_batch_write(void *self, struct coins_map *map_coins,
                             const struct uint256 *hash_block)
{
    struct coins_view_cache *parent = (struct coins_view_cache *)self;
    size_t written = 0, pruned = 0, skipped = 0;

    for (size_t i = 0; i < map_coins->num_buckets; i++) {
        struct coins_map_entry *e = &map_coins->buckets[i];
        if (!e->occupied)
            continue;
        if (e->entry.flags & COINS_CACHE_DIRTY) {
            if (coins_is_pruned(&e->entry.coins)) {
                struct coins_cache_entry *dest =
                    coins_map_insert(&parent->cache_coins, &e->txid);
                if (!dest)
                    LOG_FAIL("coins_view", "cvc_batch_write: FATAL hash table full (pruned entry)");
                size_t old_count = dest->coins.num_vout;
                coins_free(&dest->coins);
                dest->coins = e->entry.coins;
                coins_init(&e->entry.coins);
                coins_view_cache_account_vout_resize(
                    parent, old_count, dest->coins.num_vout);
                dest->flags |= COINS_CACHE_DIRTY;
                pruned++;
            } else {
                struct coins_cache_entry *dest =
                    coins_map_insert(&parent->cache_coins, &e->txid);
                if (!dest)
                    LOG_FAIL("coins_view", "cvc_batch_write: FATAL hash table full (write entry)");
                size_t old_count = dest->coins.num_vout;
                coins_free(&dest->coins);
                dest->coins = e->entry.coins;
                coins_init(&e->entry.coins);
                coins_view_cache_account_vout_resize(
                    parent, old_count, dest->coins.num_vout);
                dest->flags |= COINS_CACHE_DIRTY;
                written++;
            }
        } else {
            skipped++;
        }
    }

    if (!uint256_is_null(hash_block))
        parent->hash_block = *hash_block;

    /* Diagnostic: log if no entries were written (indicates a bug) */
    if (written == 0 && map_coins->size > 0) {
        fprintf(stderr,  // obs-ok:cvc-wrote-zero-bug-sentinel
                "cvc_batch_write: WARNING wrote 0 entries "
                "(map_size=%zu pruned=%zu skipped=%zu)\n",
                map_coins->size, pruned, skipped);
    }

    return true;
}

static struct coins_view_vtable g_cache_vtable = {
    .get_coins = cvc_get_coins,
    .have_coins = cvc_have_coins,
    .get_best_block = cvc_get_best_block,
    .batch_write = cvc_batch_write,
    .get_stats = NULL,
    .get_anchor = cvc_get_anchor,
};

void coins_view_cache_as_view(struct coins_view *out,
                               struct coins_view_cache *cache)
{
    out->vtable = &g_cache_vtable;
    out->impl = cache;
}

#ifdef ZCL_TESTING
bool coins_view_cache_flush_for_testing(struct coins_view_cache *c)
{
    if (!c->base.vtable || !c->base.vtable->batch_write)
        return false;
    bool ok = c->base.vtable->batch_write(c->base.impl, &c->cache_coins,
                                          &c->hash_block);

    /* Merge this cache's commitment delta into the parent cache.
     * If the parent is a coins_view_cache (child→parent flush), the
     * commitment accumulates upward. If it's LevelDB (top-level flush),
     * cvc_batch_write is not used and the commitment is persisted
     * separately by flush_coins_if_needed in process_block.c. */
    if (ok && c->base.vtable == &g_cache_vtable) {
        struct coins_view_cache *parent = (struct coins_view_cache *)c->base.impl;
        utxo_commitment_merge(&parent->commitment, &c->commitment);
    }

    if (ok) {
        /* Only clear cache after successful flush. If batch_write failed
         * (e.g. SQLite COMMIT error due to active statements), we MUST
         * retain the dirty entries so the next flush attempt can persist
         * them. Clearing on failure causes UTXO loss — the data disappears
         * from both RAM and disk, causing "bad-txns-inputs-missingorspent"
         * when later blocks try to spend those UTXOs. */
        coins_map_free(&c->cache_coins);
        coins_map_init(&c->cache_coins);
        c->cached_coins_usage = 0;
        /* Reset child commitment after flush (deltas merged into parent) */
        utxo_commitment_init(&c->commitment);
    } else {
        fprintf(stderr,  // obs-ok:coins-flush-failed-propagated-via-return
                "WARNING: coins cache flush FAILED — retaining %zu "
                "dirty entries for retry\n", c->cache_coins.size);
    }
    return ok;
}
#endif

void coins_view_cache_recompute_commitment(const struct coins_view_cache *c,
                                           struct utxo_commitment *out)
{
    /* Path-independent: derive the commitment purely from the live coin
     * SET. We XOR in every still-available output of every non-pruned
     * entry. This is the in-memory analogue of utxo_commitment_compute_db()
     * (which iterates the SQLite `utxos` table) and uses the IDENTICAL
     * per-UTXO hash inputs the forward path fed to utxo_commitment_add:
     * txid, vout, the output's value, and the coin's creation height. XOR
     * is commutative, so bucket-iteration order does not affect the result.
     * For a forward-only coin set the output is therefore byte-identical to
     * the incremental c->commitment accumulator. */
    utxo_commitment_init(out);
    const struct coins_map *m = &c->cache_coins;
    for (size_t b = 0; b < m->num_buckets; b++) {
        const struct coins_map_entry *e = &m->buckets[b];
        if (!e->occupied)
            continue;
        const struct coins *coins = &e->entry.coins;
        if (coins_is_pruned(coins))
            continue;
        for (size_t i = 0; i < coins->num_vout; i++) {
            if (!coins_is_available(coins, (unsigned)i))
                continue;
            utxo_commitment_add(out, e->txid.data, (uint32_t)i,
                                coins->vout[i].value, (int32_t)coins->height);
        }
    }
}

const struct tx_out *coins_view_cache_get_output_for(
    struct coins_view_cache *c, const struct tx_in *in)
{
    struct coins_cache_entry *entry =
        coins_map_find(&c->cache_coins, &in->prevout.hash);
    if (!entry) {
        struct coins coins;
        coins_init(&coins);
        if (!coins_view_get_coins(&c->base, &in->prevout.hash, &coins)) {
            coins_free(&coins);
            return NULL;
        }
        struct coins_cache_entry *new_entry =
            coins_map_insert(&c->cache_coins, &in->prevout.hash);
        if (!new_entry) { coins_free(&coins); return NULL; }
        new_entry->coins = coins;
        coins_view_cache_account_vout_resize(
            c, 0, new_entry->coins.num_vout);
        new_entry->flags = 0;
        entry = new_entry;
    }
    if (in->prevout.n >= entry->coins.num_vout)
        return NULL;
    if (tx_out_is_null(&entry->coins.vout[in->prevout.n]))
        return NULL;
    return &entry->coins.vout[in->prevout.n];
}

bool coins_view_cache_have_inputs(struct coins_view_cache *c,
                                   const struct transaction *tx)
{
    if (transaction_is_coinbase(tx))
        return true;
    for (size_t i = 0; i < tx->num_vin; i++) {
        const struct tx_out *out = coins_view_cache_get_output_for(c, &tx->vin[i]);
        if (!out)
            return false;
    }
    return true;
}

int64_t coins_view_cache_get_value_in(struct coins_view_cache *c,
                                       const struct transaction *tx)
{
    if (transaction_is_coinbase(tx))
        return 0;
    int64_t value = 0;
    for (size_t i = 0; i < tx->num_vin; i++) {
        const struct tx_out *out = coins_view_cache_get_output_for(c, &tx->vin[i]);
        if (!out) {
            /* Missing input — caller should have checked have_inputs first.
             * Return -1 to signal error rather than silently undercounting. */
            return -1;
        }
        /* Per-input MoneyRange: each input must be in [0, MAX_MONEY].
         * Catches corrupted coins with invalid values before summing. */
        if (!MoneyRange(out->value))
            LOG_RETURN((int64_t)-1, "coins_view",
                       "get_value_in: input[%zu] value %lld out of range",
                       i, (long long)out->value);
        value += out->value;
        /* Overflow check: cumulative transparent inputs can't exceed MAX_MONEY */
        if (!MoneyRange(value))
            return -1;
    }
    /* Sapling value balance: positive = value FROM shielded pool */
    if (tx->value_balance >= 0) {
        value += tx->value_balance;
        if (!MoneyRange(value))
            return -1;
    }
    /* JoinSplit vpub_new: value FROM Sprout pool */
    for (size_t i = 0; i < tx->num_joinsplit; i++) {
        value += tx->v_joinsplit[i].vpub_new;
        if (!MoneyRange(value))
            return -1;
    }
    return value;
}

struct sprout_intermediate {
    struct uint256 root;
    struct incremental_merkle_tree tree;
};

static bool anchor_is_empty(enum coins_anchor_pool pool,
                            const struct uint256 *root,
                            struct incremental_merkle_tree *tree_out)
{
    struct incremental_merkle_tree tree;
    if (pool == COINS_ANCHOR_SPROUT)
        sprout_tree_init(&tree);
    else
        sapling_tree_init(&tree);
    struct uint256 empty;
    /* The empty-tree root is a per-pool CONSTANT — use the cached form. A
     * full incremental_tree_root here is a ~8ms Pedersen fold and this
     * helper runs per shielded spend/JoinSplit. Bit-identical. */
    incremental_tree_empty_root(&tree, &empty);
    if (!uint256_eq(root, &empty))
        return false;
    if (tree_out)
        *tree_out = tree;
    return true;
}

static enum coins_shielded_requirements_result anchor_result_map(
    enum coins_anchor_lookup_result r)
{
    switch (r) {
    case COINS_ANCHOR_FOUND:
        return COINS_SHIELDED_REQUIREMENTS_OK;
    case COINS_ANCHOR_MISSING:
        return COINS_SHIELDED_REQUIREMENTS_MISSING_ANCHOR;
    case COINS_ANCHOR_HISTORY_INCOMPLETE:
        return COINS_SHIELDED_REQUIREMENTS_HISTORY_INCOMPLETE;
    case COINS_ANCHOR_ERROR:
    default:
        return COINS_SHIELDED_REQUIREMENTS_STORE_ERROR;
    }
}

enum coins_shielded_requirements_result
coins_view_cache_check_shielded_requirements(
    struct coins_view_cache *c, const struct transaction *tx)
{
    if (!c || !tx)
        return COINS_SHIELDED_REQUIREMENTS_STORE_ERROR;
    if (tx->num_joinsplit == 0 && tx->num_shielded_spend == 0)
        return COINS_SHIELDED_REQUIREMENTS_OK;

    struct sprout_intermediate *intermediates = NULL;
    if (tx->num_joinsplit > 0) {
        if (tx->num_joinsplit > SIZE_MAX / sizeof(*intermediates))
            return COINS_SHIELDED_REQUIREMENTS_STORE_ERROR;
        intermediates = zcl_calloc(tx->num_joinsplit,
                                   sizeof(*intermediates),
                                   "shielded_requirements_intermediates");
        if (!intermediates)
            return COINS_SHIELDED_REQUIREMENTS_STORE_ERROR;
    }

    size_t num_intermediates = 0;
    enum coins_shielded_requirements_result result =
        COINS_SHIELDED_REQUIREMENTS_OK;
    for (size_t i = 0; i < tx->num_joinsplit; i++) {
        const struct js_description *js = &tx->v_joinsplit[i];
        struct incremental_merkle_tree tree;
        bool found_intermediate = false;

        /* zclassicd's per-transaction `intermediates` map: an anchor made by
         * an earlier JoinSplit of THIS transaction is valid, while a root made
         * by an earlier transaction of the same block is not yet pushed. */
        for (size_t j = 0; j < num_intermediates; j++) {
            if (uint256_eq(&intermediates[j].root, &js->anchor)) {
                tree = intermediates[j].tree;
                found_intermediate = true;
                break;
            }
        }
        if (!found_intermediate) {
            enum coins_anchor_lookup_result ar;
            if (anchor_is_empty(COINS_ANCHOR_SPROUT, &js->anchor, &tree))
                ar = COINS_ANCHOR_FOUND;
            else
                ar = coins_view_get_anchor(&c->base, COINS_ANCHOR_SPROUT,
                                           &js->anchor, &tree);
            result = anchor_result_map(ar);
            if (result != COINS_SHIELDED_REQUIREMENTS_OK)
                goto out;
        }

        for (size_t j = 0; j < ZC_NUM_JS_OUTPUTS; j++)
            incremental_tree_append(&tree, &js->commitments[j]);
        incremental_tree_root(&tree,
                              &intermediates[num_intermediates].root);
        intermediates[num_intermediates].tree = tree;
        num_intermediates++;
    }

    for (size_t i = 0; i < tx->num_shielded_spend; i++) {
        const struct uint256 *root = &tx->v_shielded_spend[i].anchor;
        enum coins_anchor_lookup_result ar;
        if (anchor_is_empty(COINS_ANCHOR_SAPLING, root, NULL))
            ar = COINS_ANCHOR_FOUND;
        else
            ar = coins_view_get_anchor(&c->base, COINS_ANCHOR_SAPLING,
                                       root, NULL);
        result = anchor_result_map(ar);
        if (result != COINS_SHIELDED_REQUIREMENTS_OK)
            goto out;
    }

out:
    free(intermediates);
    return result;
}

bool coins_view_cache_have_joinsplit_requirements(
    struct coins_view_cache *c, const struct transaction *tx)
{
    return coins_view_cache_check_shielded_requirements(c, tx) ==
           COINS_SHIELDED_REQUIREMENTS_OK;
}
