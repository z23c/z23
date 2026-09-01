/* Copyright (c) 2009-2010 Satoshi Nakamoto
 * Copyright (c) 2009-2014 The Bitcoin Core developers
 * Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. */

#ifndef ZCL_COINS_VIEW_H
#define ZCL_COINS_VIEW_H

#include "coins/coins.h"
#include "coins/utxo_commitment.h"
#include "core/uint256.h"
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

struct coins_cache_entry {
    struct coins coins;
    unsigned char flags;
};

struct coins_map_entry {
    struct uint256 txid;
    struct coins_cache_entry entry;
    bool occupied;
};

struct coins_map {
    struct coins_map_entry *buckets;
    size_t num_buckets;
    size_t size;
    /* Test-only algorithmic-regression hook — see coins/coins_fault.h for the
     * bug class it models and the empty-map arming contract. When true every
     * key hashes to bucket 0, so lookups stay CORRECT but degrade from O(1)
     * to O(n). Never written by the node; only
     * coins_fault_arm_map_hash_collapse() flips it, and only on an empty map.
     * Cleared by coins_map_init(), so every map defaults to the real hash. */
    bool degraded_hash;
};

struct incremental_merkle_tree;

/* Shielded anchor namespaces and lookup verdicts.  Numeric pool values are
 * durable and intentionally match storage/anchor_kv.h without making the
 * foundational coins interface depend on a storage implementation. */
enum coins_anchor_pool {
    COINS_ANCHOR_SPROUT = 0,
    COINS_ANCHOR_SAPLING = 1,
};

enum coins_anchor_lookup_result {
    COINS_ANCHOR_ERROR = -1,
    COINS_ANCHOR_MISSING = 0,
    COINS_ANCHOR_FOUND = 1,
    COINS_ANCHOR_HISTORY_INCOMPLETE = 2,
};

enum coins_shielded_requirements_result {
    COINS_SHIELDED_REQUIREMENTS_OK = 0,
    COINS_SHIELDED_REQUIREMENTS_MISSING_ANCHOR,
    COINS_SHIELDED_REQUIREMENTS_HISTORY_INCOMPLETE,
    COINS_SHIELDED_REQUIREMENTS_STORE_ERROR,
};

static inline uint64_t coins_map_hash(const struct uint256 *txid)
{
    uint64_t h;
    memcpy(&h, txid->data, 8);
    return h;
}

static inline void coins_map_init(struct coins_map *m)
{
    m->buckets = NULL;
    m->num_buckets = 0;
    m->size = 0;
    m->degraded_hash = false;
}

static inline void coins_map_free(struct coins_map *m)
{
    for (size_t i = 0; i < m->num_buckets; i++) {
        if (m->buckets[i].occupied)
            coins_free(&m->buckets[i].entry.coins);
    }
    free(m->buckets);
    m->buckets = NULL;
    m->num_buckets = 0;
    m->size = 0;
}

/* Open-addressed (linear-probe) hash map from txid -> coins cache entry.
 * coins_map_hash uses the first 8 bytes of the txid as the bucket key. */

/* Find the entry for txid, or NULL if absent. */
struct coins_cache_entry *coins_map_find(struct coins_map *m,
                                          const struct uint256 *txid);

/* Return the existing entry for txid, or insert a fresh one (coins_init'd,
 * flags=0) and return it. Grows + rehashes when the load factor (3/4) is
 * reached. Returns NULL only if a rehash allocation fails and the table is
 * full. The returned pointer is invalidated by any later insert that triggers
 * a rehash — do not hold it across inserts. */
struct coins_cache_entry *coins_map_insert(struct coins_map *m,
                                            const struct uint256 *txid);

/* Erase txid's entry (freeing its coins) and back-shift the probe run so no
 * lookup is stranded. Returns false if txid was not present. */
bool coins_map_erase(struct coins_map *m, const struct uint256 *txid);

/* Number of occupied entries. */
size_t coins_map_count(const struct coins_map *m);

/* Backing-store interface for a UTXO view (a LevelDB/SQLite store, or
 * another cache). All hooks may be NULL on a given impl; the
 * coins_view_* inline wrappers below treat a NULL hook as "false". */
struct coins_view_vtable {
    /* Fill *coins for txid; return false (coins left as-is) if absent. */
    bool (*get_coins)(void *self, const struct uint256 *txid, struct coins *coins);
    /* True iff txid has at least one unspent output. */
    bool (*have_coins)(void *self, const struct uint256 *txid);
    /* Best-block hash this view is synced to. */
    bool (*get_best_block)(void *self, struct uint256 *hash);
    /* Flush a batch of cached entries downward. Only DIRTY entries are
     * applied; each is moved (ownership transferred), so map_coins is
     * consumed. hash_block updates the store's best block unless it is
     * null. Returning false means the flush did NOT persist — the caller
     * MUST retain the dirty entries and retry (clearing them on failure
     * loses UTXOs). */
    bool (*batch_write)(void *self, struct coins_map *map_coins,
                        const struct uint256 *hash_block);
    /* Aggregate UTXO-set stats; may be NULL when unsupported. */
    bool (*get_stats)(void *self, struct coins_stats *stats);
    /* Resolve an active-chain Sprout/Sapling note-commitment root.  Sprout
     * callers request the historical frontier so same-transaction
     * intermediate JoinSplit roots can be derived exactly as zclassicd does.
     * Sapling callers may pass tree_out=NULL when membership alone suffices. */
    enum coins_anchor_lookup_result (*get_anchor)(
        void *self, enum coins_anchor_pool pool, const struct uint256 *root,
        struct incremental_merkle_tree *tree_out);
};

struct coins_view {
    struct coins_view_vtable *vtable;
    void *impl;
};

static inline bool coins_view_get_coins(struct coins_view *cv,
                                        const struct uint256 *txid,
                                        struct coins *coins)
{
    if (cv->vtable && cv->vtable->get_coins)
        return cv->vtable->get_coins(cv->impl, txid, coins);
    return false;
}

static inline bool coins_view_have_coins(struct coins_view *cv,
                                         const struct uint256 *txid)
{
    if (cv->vtable && cv->vtable->have_coins)
        return cv->vtable->have_coins(cv->impl, txid);
    return false;
}

static inline bool coins_view_get_best_block(struct coins_view *cv,
                                             struct uint256 *hash)
{
    if (cv->vtable && cv->vtable->get_best_block)
        return cv->vtable->get_best_block(cv->impl, hash);
    return false;
}

static inline enum coins_anchor_lookup_result coins_view_get_anchor(
    struct coins_view *cv, enum coins_anchor_pool pool,
    const struct uint256 *root, struct incremental_merkle_tree *tree_out)
{
    if (cv && cv->vtable && cv->vtable->get_anchor)
        return cv->vtable->get_anchor(cv->impl, pool, root, tree_out);
    return COINS_ANCHOR_HISTORY_INCOMPLETE;
}

struct coins_view_cache {
    struct coins_view base;
    struct coins_map cache_coins;
    struct uint256 hash_block;
    size_t cached_coins_usage;
    struct utxo_commitment commitment;  /* incremental UTXO set hash */
};

/* Initialize a cache layered over `backing` (copied by value into c->base):
 * empty coin map, null hash_block, zeroed incremental commitment. */
void coins_view_cache_init(struct coins_view_cache *c, struct coins_view *backing);

/* Free the cached coin map. Does NOT free the backing view. */
void coins_view_cache_free(struct coins_view_cache *c);

/* Conservative O(1) heap footprint: map buckets plus tracked vout capacity.
 * Shrinks are retained until the next cache reset, so the value can trigger an
 * early flush but can never hide allocation growth. Saturates at SIZE_MAX. */
size_t coins_view_cache_memory_usage(const struct coins_view_cache *c);
void coins_view_cache_account_vout_resize(struct coins_view_cache *c,
                                           size_t old_count,
                                           size_t new_count);

/* Wrap this cache as a coins_view (vtable + impl=cache) so it can itself be
 * the backing store of another coins_view_cache (cache stacking). Its
 * batch_write only applies DIRTY entries and transfers ownership upward. */
void coins_view_cache_as_view(struct coins_view *out,
                               struct coins_view_cache *cache);

/* Authoritative, PATH-INDEPENDENT UTXO commitment for this cache.
 *
 * Recomputes the XOR-hash accumulator + count directly from the live coin
 * SET (every available output of every non-pruned entry currently held in
 * cache_coins), rather than reading the incremental `c->commitment` field.
 *
 * Why this exists: the incremental `c->commitment` accumulator is maintained
 * only on the FORWARD path (update_coins add/remove). disconnect_block does
 * NOT decrement it, so after a chain reorg `c->commitment` is path-DEPENDENT:
 * it reflects the history of connects/disconnects rather than the resulting
 * coin set. Any commitment query that must hold across a reorg MUST therefore
 * recompute from the coin set — this function — and may
 * NOT trust the stale incremental field.
 *
 * Equivalence guarantee: for a coin set produced by forward-only connects
 * (no disconnect), the recomputed value is BYTE-IDENTICAL to the incremental
 * `c->commitment` (same per-UTXO hash inputs: txid, vout, value, creation
 * height; XOR is commutative so iteration order is irrelevant). The persisted
 * forward-only commitment value is therefore unchanged — existing snapshots
 * stay valid.
 *
 * Cost: O(N) over the cache's live entries. Call it on-demand / for a proof
 * or checkpoint — NOT on the per-block hot path (the incremental field
 * already serves the forward path at O(1) per change).
 *
 * Only the in-memory cache is iterated; the backing view is not consulted
 * (the live tip cache holds the full set during validation). */
void coins_view_cache_recompute_commitment(const struct coins_view_cache *c,
                                            struct utxo_commitment *out);

/* Copy txid's coins into *out. Checks the cache first; on a miss it loads
 * from the backing view and caches the result. Returns false (out untouched)
 * if absent OR if the record is pruned (a pruned cache entry reads as
 * "not present"). *out receives a deep copy the caller owns. */
bool coins_view_cache_get_coins(struct coins_view_cache *c,
                                const struct uint256 *txid,
                                struct coins *out);

/* True iff txid has a live (non-pruned) record, consulting the cache then
 * the backing view. */
bool coins_view_cache_have_coins(struct coins_view_cache *c,
                                 const struct uint256 *txid);

/* Forget one clean or dirty cached generation so the next lookup resolves
 * against the backing authority. The caller owns publication ordering: call
 * only after the backing mutation commits. This is required when a cache is
 * layered over a store (such as live coins_kv) that is authored independently
 * rather than through this cache's batch_write path. Returns true iff an entry
 * was present. cached_coins_usage is intentionally conservative and retains
 * its high-water accounting until a full cache reset. */
bool coins_view_cache_invalidate(struct coins_view_cache *c,
                                 const struct uint256 *txid);

/* Best block this cache is synced to. Lazily pulls it from the backing view
 * the first time while hash_block is still null, then returns the cached
 * value. */
void coins_view_cache_get_best_block(struct coins_view_cache *c,
                                     struct uint256 *out);
void coins_view_cache_set_best_block(struct coins_view_cache *c,
                                     const struct uint256 *hash);

/* Get a MUTABLE, DIRTY-marked entry for txid for an existing coin: on a
 * cache miss it is loaded from the backing view first, so the returned entry
 * already holds the current coins. Returns NULL only if the map is full.
 * Use for SPENDING/modifying an existing UTXO. */
struct coins_cache_entry *coins_view_cache_modify(struct coins_view_cache *c,
                                                   const struct uint256 *txid);

/* Get a MUTABLE entry for a BRAND-NEW coin, marked DIRTY|FRESH (no backing
 * load — the caller is creating outputs that do not yet exist downstream).
 * Returns NULL only if the map is full. Use for ADDING a new tx's outputs. */
struct coins_cache_entry *coins_view_cache_modify_new(struct coins_view_cache *c,
                                                       const struct uint256 *txid);
#ifdef ZCL_TESTING
bool coins_view_cache_flush_for_testing(struct coins_view_cache *c);
#endif

/* Resolve the txout an input spends: looks up in->prevout.hash (loading from
 * the backing view and caching it on a miss), then indexes prevout.n.
 * Returns NULL if the parent coin is absent, the index is out of range, or
 * that output is already spent (null). The returned pointer aliases the
 * cache entry and is invalidated by any later insert that rehashes the map. */
const struct tx_out *coins_view_cache_get_output_for(
    struct coins_view_cache *c, const struct tx_in *in);

/* True iff every transparent input of tx resolves to an available output
 * (coinbase trivially true — it has no real inputs). Does not validate
 * amounts; see coins_view_cache_get_value_in. */
bool coins_view_cache_have_inputs(struct coins_view_cache *c,
                                   const struct transaction *tx);

/* Total value entering tx: transparent inputs + positive value_balance
 * (value from the Sapling pool) + every joinsplit vpub_new (value from the
 * Sprout pool). Returns -1 (consensus reject sentinel, NOT a valid amount)
 * if any input is missing, an input value or any running total leaves
 * MoneyRange. Coinbase returns 0. Caller should have confirmed have_inputs
 * first. */
int64_t coins_view_cache_get_value_in(struct coins_view_cache *c,
                                       const struct transaction *tx);

/* Exact zclassicd anchor-membership predicate.  Sprout permits a later
 * JoinSplit in the same transaction to reference an intermediate root made by
 * an earlier JoinSplit, so this check retrieves and advances historical
 * frontiers; Sapling spends require a durable active-chain root directly.
 * Empty roots are protocol-defined and need no store row.
 *
 * The detailed form distinguishes a positively absent forged root from an
 * incomplete snapshot/import history and a store error.  Consensus callers
 * fail closed for all three non-OK results; reducer diagnostics use the
 * distinction to name the owner/action. */
enum coins_shielded_requirements_result
coins_view_cache_check_shielded_requirements(
    struct coins_view_cache *c, const struct transaction *tx);

bool coins_view_cache_have_joinsplit_requirements(
    struct coins_view_cache *c, const struct transaction *tx);

#endif
