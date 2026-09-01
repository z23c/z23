/* Copyright (c) 2009-2010 Satoshi Nakamoto
 * Copyright (c) 2009-2014 The Bitcoin Core developers
 * Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. */

#include "validation/txmempool.h"
#include "validation/contextual_check_tx.h"
#include "core/serialize.h"
#include "util/log_macros.h"
#include <stdlib.h>
#include <string.h>
#include "util/safe_alloc.h"

/* Post-add hook (registered by engine/services/mempool_limits).
 * Simple scalar — no lock needed, adds race at most with
 * unregister which happens only at shutdown. */
static tx_mempool_post_add_hook_fn g_post_add_hook = NULL;

void tx_mempool_set_post_add_hook(tx_mempool_post_add_hook_fn fn)
{
    g_post_add_hook = fn;
}

/* --- mempool_entry --- */

void mempool_entry_init(struct mempool_entry *e, const struct transaction *tx,
                        int64_t fee, int64_t time, double priority,
                        unsigned int height, bool pool_has_no_inputs_of,
                        bool spends_coinbase, uint32_t branch_id)
{
    transaction_copy(&e->tx, tx);
    e->fee = fee;
    e->time = time;
    e->priority = priority;
    e->height = height;
    e->had_no_deps = pool_has_no_inputs_of;
    e->spends_coinbase = spends_coinbase;
    e->branch_id = branch_id;

    struct byte_stream s;
    stream_init(&s, 512);
    transaction_serialize(&e->tx, &s);
    e->tx_size = s.size;
    stream_free(&s);

    e->mod_size = e->tx_size;
    for (size_t i = 0; i < tx->num_vin; i++) {
        size_t offset = 41 + (tx->vin[i].script_sig.size < 110 ? 0 :
                               tx->vin[i].script_sig.size - 110);
        if (e->mod_size > offset)
            e->mod_size -= offset;
    }
}

void mempool_entry_free(struct mempool_entry *e)
{
    transaction_free(&e->tx);
}

double mempool_entry_get_priority(const struct mempool_entry *e,
                                   unsigned int current_height)
{
    int64_t value_in = transaction_get_value_out(&e->tx) + e->fee;
    double delta = ((double)(current_height - e->height) * (double)value_in) /
                   (double)e->mod_size;
    return e->priority + delta;
}

/* --- outpoint hash map --- */

static uint32_t outpoint_hash(const struct outpoint *op, size_t cap)
{
    uint32_t h;
    memcpy(&h, op->hash.data, 4);
    h ^= op->n * 2654435761u;
    return h % (uint32_t)cap;
}

static struct outpoint_map_entry *outpoint_find(struct outpoint_map_entry *map,
                                                 size_t cap,
                                                 const struct outpoint *key)
{
    uint32_t idx = outpoint_hash(key, cap);
    for (size_t i = 0; i < cap; i++) {
        size_t pos = (idx + i) % cap;
        if (!map[pos].used)
            return NULL;
        if (uint256_eq(&map[pos].key.hash, &key->hash) &&
            map[pos].key.n == key->n)
            return &map[pos];
    }
    return NULL;
}

/* Insert (or update) one outpoint→inpoint mapping. On a successful
 * insert into a previously-empty slot, *added (if non-NULL) is set to
 * true so the caller can maintain a live-occupancy counter; on an
 * update of an existing key it is set to false. Returns false only if
 * the table is genuinely full (no empty slot found on the probe
 * chain) — callers MUST check the return so saturation surfaces
 * loudly instead of silently dropping the double-spend tracking
 * entry. With grow-before-insert maintaining load < 0.7, the full
 * case is unreachable in normal operation. */
static bool outpoint_insert(struct outpoint_map_entry *map, size_t cap,
                              const struct outpoint *key,
                              const struct inpoint *value,
                              bool *added)
{
    uint32_t idx = outpoint_hash(key, cap);
    for (size_t i = 0; i < cap; i++) {
        size_t pos = (idx + i) % cap;
        if (!map[pos].used) {
            map[pos].key = *key;
            map[pos].value = *value;
            map[pos].used = true;
            if (added) *added = true;
            return true;
        }
        if (uint256_eq(&map[pos].key.hash, &key->hash) &&
            map[pos].key.n == key->n) {
            map[pos].value = *value;
            if (added) *added = false;
            return true;
        }
    }
    if (added) *added = false;
    LOG_FAIL("mempool", "outpoint_insert: hash table full (cap=%zu)", cap);
}

/* Grow the outpoint map to `newcap` slots and rehash every live entry.
 * Allocated empty (calloc) so the open-addressing probe chains are
 * rebuilt cleanly from scratch. Returns false (leaving the pool's map
 * untouched) on allocation failure — the caller treats that as a hard
 * insert failure rather than silently continuing with a saturated map. */
static bool outpoint_map_grow(struct tx_mempool *pool, size_t newcap)
{
    struct outpoint_map_entry *newmap =
        zcl_calloc(newcap, sizeof(*newmap), "mempool_next_tx_grow");
    if (!newmap)
        LOG_FAIL("mempool", "outpoint_map_grow: calloc failed for %zu slots", newcap);

    for (size_t i = 0; i < pool->next_tx_cap; i++) {
        if (!pool->next_tx[i].used)
            continue;
        if (!outpoint_insert(newmap, newcap, &pool->next_tx[i].key,
                             &pool->next_tx[i].value, NULL)) {
            /* Should be impossible: newcap > live count. Bail loudly
             * without corrupting the existing map. */
            free(newmap);
            LOG_FAIL("mempool", "outpoint_map_grow: rehash overflow (newcap=%zu)", newcap);
        }
    }

    free(pool->next_tx);
    pool->next_tx = newmap;
    pool->next_tx_cap = newcap;
    return true;
}

/* Remove one outpoint mapping (no-op if absent). Returns true iff a
 * live entry was actually removed, so the caller can decrement its
 * live-occupancy counter. The reinserts that repair the linear-probe
 * chain relocate already-live entries within the same map, so they do
 * not change occupancy and the map can never be full during this
 * fixup (we just freed a slot) — the insert return is therefore safe
 * to assert rather than propagate. */
static bool outpoint_remove(struct outpoint_map_entry *map, size_t cap,
                              const struct outpoint *key)
{
    uint32_t idx = outpoint_hash(key, cap);
    for (size_t i = 0; i < cap; i++) {
        size_t pos = (idx + i) % cap;
        if (!map[pos].used)
            return false;
        if (uint256_eq(&map[pos].key.hash, &key->hash) &&
            map[pos].key.n == key->n) {
            map[pos].used = false;
            /* rehash subsequent entries to fix linear probing chain */
            size_t next = (pos + 1) % cap;
            while (map[next].used) {
                struct outpoint_map_entry tmp = map[next];
                map[next].used = false;
                if (!outpoint_insert(map, cap, &tmp.key, &tmp.value, NULL))
                    LOG_RETURN(true, "mempool",
                               "outpoint_remove: probe-chain reinsert overflow (cap=%zu)", cap);
                next = (next + 1) % cap;
            }
            return true;
        }
    }
    return false;
}

/* --- tx_mempool --- */

void tx_mempool_init(struct tx_mempool *pool, int64_t min_relay_fee)
{
    memset(pool, 0, sizeof(*pool));
    zcl_mutex_init(&pool->cs);
    pool->min_relay_fee = min_relay_fee;

    pool->entries_cap = MEMPOOL_INITIAL_CAP;
    pool->entries = zcl_calloc(pool->entries_cap, sizeof(*pool->entries), "mempool_entries");

    pool->next_tx_cap = OUTPOINT_MAP_CAP;
    pool->next_tx_used = 0;
    pool->next_tx = zcl_calloc(pool->next_tx_cap, sizeof(*pool->next_tx), "mempool_next_tx");

    pool->deltas_cap = PRIORITY_MAP_CAP;
    pool->deltas = zcl_calloc(pool->deltas_cap, sizeof(*pool->deltas), "mempool_deltas");
}

void tx_mempool_free(struct tx_mempool *pool)
{
    for (size_t i = 0; i < pool->num_entries; i++)
        mempool_entry_free(&pool->entries[i]);
    free(pool->entries);
    free(pool->next_tx);
    free(pool->deltas);
    zcl_mutex_destroy(&pool->cs);
}

void tx_mempool_clear(struct tx_mempool *pool)
{
    zcl_mutex_lock(&pool->cs);
    pool->cleared_total += pool->num_entries;
    for (size_t i = 0; i < pool->num_entries; i++)
        mempool_entry_free(&pool->entries[i]);
    pool->num_entries = 0;
    memset(pool->next_tx, 0, pool->next_tx_cap * sizeof(*pool->next_tx));
    pool->next_tx_used = 0;
    pool->total_tx_size = 0;
    pool->txs_updated++;
    zcl_mutex_unlock(&pool->cs);
}

size_t tx_mempool_size(struct tx_mempool *pool)
{
    zcl_mutex_lock(&pool->cs);
    size_t n = pool->num_entries;
    zcl_mutex_unlock(&pool->cs);
    return n;
}

uint64_t tx_mempool_total_size(struct tx_mempool *pool)
{
    zcl_mutex_lock(&pool->cs);
    uint64_t s = pool->total_tx_size;
    zcl_mutex_unlock(&pool->cs);
    return s;
}

void tx_mempool_stats_snapshot(struct tx_mempool *pool,
                               struct tx_mempool_stats *out)
{
    if (!out)
        return;
    memset(out, 0, sizeof(*out));
    if (!pool)
        return;
    zcl_mutex_lock(&pool->cs);
    out->size = pool->num_entries;
    out->bytes = pool->total_tx_size;
    out->added_total = pool->added_total;
    out->removed_direct_total = pool->removed_direct_total;
    out->removed_for_block_total = pool->removed_for_block_total;
    out->removed_for_branch_total = pool->removed_for_branch_total;
    out->cleared_total = pool->cleared_total;
    zcl_mutex_unlock(&pool->cs);
}

unsigned int tx_mempool_txs_updated(struct tx_mempool *pool)
{
    zcl_mutex_lock(&pool->cs);
    unsigned int n = pool->txs_updated;
    zcl_mutex_unlock(&pool->cs);
    return n;
}

void tx_mempool_add_txs_updated(struct tx_mempool *pool, unsigned int n)
{
    zcl_mutex_lock(&pool->cs);
    pool->txs_updated += n;
    zcl_mutex_unlock(&pool->cs);
}

static int find_entry_by_hash(const struct tx_mempool *pool,
                               const struct uint256 *hash)
{
    for (size_t i = 0; i < pool->num_entries; i++)
        if (uint256_eq(&pool->entries[i].tx.hash, hash))
            return (int)i;
    return -1;
}

bool tx_mempool_add_unchecked(struct tx_mempool *pool,
                               const struct uint256 *hash,
                               const struct mempool_entry *entry)
{
    zcl_mutex_lock(&pool->cs);

    /* The caller's optimistic exists check is deliberately outside this
     * critical section because script/proof verification can be expensive.
     * It is therefore only an early-out, never the ownership boundary. Two
     * peer threads can validate the same exact transaction concurrently and
     * both reach this function. The locked insertion must arbitrate exact
     * txid ownership or both copies enter the array; remove_for_block then
     * removes only one and the survivor can be mined again at the next
     * height. Keep this check before input-conflict classification: an exact
     * duplicate is idempotent, not a malicious double spend. */
    if (find_entry_by_hash(pool, hash) >= 0) {
        zcl_mutex_unlock(&pool->cs);
        return false;
    }

    /* Mempool size limit: 300MB total, prevents OOM from tx flooding.
     * Matches Bitcoin Core's default -maxmempool=300. */
    if (pool->total_tx_size + entry->tx_size > 300 * 1024 * 1024) {
        zcl_mutex_unlock(&pool->cs);
        LOG_FAIL("mempool", "mempool full: total_size=%zu + tx_size=%zu exceeds 300MB limit",
                 (size_t)pool->total_tx_size, (size_t)entry->tx_size);
    }

    /* Double-spend detection: reject if any input is already spent
     * by another mempool transaction. */
    for (size_t i = 0; i < entry->tx.num_vin; i++) {
        struct outpoint op;
        op.hash = entry->tx.vin[i].prevout.hash;
        op.n = entry->tx.vin[i].prevout.n;
        uint32_t idx = outpoint_hash(&op, pool->next_tx_cap);
        for (size_t j = 0; j < pool->next_tx_cap; j++) {
            size_t pos = (idx + j) % pool->next_tx_cap;
            if (!pool->next_tx[pos].used) break;
            if (uint256_eq(&pool->next_tx[pos].key.hash, &op.hash) &&
                pool->next_tx[pos].key.n == op.n) {
                /* Input already spent by another mempool tx */
                zcl_mutex_unlock(&pool->cs);
                LOG_FAIL("mempool", "double-spend detected: input already spent by mempool tx");
            }
        }
    }

    /* Grow the outpoint map *before* inserting so live occupancy never
     * crosses 70% — an open-addressing table degrades sharply and (at
     * 100%) silently loses entries past full. After this tx's inputs
     * are added, live count is at most next_tx_used + num_vin; if that
     * would exceed 0.7*cap, rehash to ~4x the projected live count so
     * the map stays sparse across a sustained flood (mempool cap 50k).
     * Failure here is a hard add failure — never proceed with a
     * saturated map, which would let a double-spend slip through. */
    size_t projected = pool->next_tx_used + entry->tx.num_vin;
    if (projected * 10 > pool->next_tx_cap * 7) {
        size_t target = (projected * 4 < OUTPOINT_MAP_CAP)
                        ? (size_t)OUTPOINT_MAP_CAP : projected * 4;
        if (target <= pool->next_tx_cap)
            target = pool->next_tx_cap * 2;
        if (!outpoint_map_grow(pool, target)) {
            zcl_mutex_unlock(&pool->cs);
            LOG_FAIL("mempool", "outpoint map grow failed (cap=%zu, projected=%zu)",
                     pool->next_tx_cap, projected);
        }
    }

    if (pool->num_entries >= pool->entries_cap) {
        size_t newcap = pool->entries_cap * 2;
        struct mempool_entry *tmp = zcl_realloc(pool->entries,
                                             newcap * sizeof(*tmp), "mempool_entries_grow");
        if (!tmp) { zcl_mutex_unlock(&pool->cs); LOG_FAIL("mempool", "realloc failed expanding entries from %zu", pool->entries_cap); }
        pool->entries = tmp;
        pool->entries_cap = newcap;
    }

    struct mempool_entry *e = &pool->entries[pool->num_entries];
    mempool_entry_init(e, &entry->tx, entry->fee, entry->time,
                       entry->priority, entry->height, entry->had_no_deps,
                       entry->spends_coinbase, entry->branch_id);
    size_t idx = pool->num_entries;
    pool->num_entries++;
    pool->added_total++;

    for (size_t i = 0; i < e->tx.num_vin; i++) {
        struct outpoint op;
        op.hash = e->tx.vin[i].prevout.hash;
        op.n = e->tx.vin[i].prevout.n;
        struct inpoint ip = { idx, (uint32_t)i };
        bool added = false;
        /* The map was just grown to keep load < 0.7, so insert cannot
         * fail for lack of space. Check the return regardless so any
         * future regression surfaces loudly instead of silently
         * dropping a double-spend-tracking entry. */
        if (!outpoint_insert(pool->next_tx, pool->next_tx_cap, &op, &ip, &added)) {
            LOG_WARN("mempool",
                     "outpoint_insert unexpectedly failed (cap=%zu, used=%zu) — double-spend tracking may be incomplete",
                     pool->next_tx_cap, pool->next_tx_used);
        } else if (added) {
            pool->next_tx_used++;
        }
    }

    pool->txs_updated++;
    pool->total_tx_size += entry->tx_size;

    zcl_mutex_unlock(&pool->cs);

    /* Fire the policy hook *after* releasing the lock so the
     * hook is free to call `tx_mempool_remove`/`collect_views`
     * without deadlocking. Read the pointer once to avoid a
     * TOCTOU where unregister runs between check and call. */
    tx_mempool_post_add_hook_fn hook = g_post_add_hook;
    if (hook) hook(pool);

    return true;
}

bool tx_mempool_exists(const struct tx_mempool *pool,
                        const struct uint256 *hash)
{
    zcl_mutex_lock((zcl_mutex_t *)&pool->cs);
    int idx = find_entry_by_hash(pool, hash);
    zcl_mutex_unlock((zcl_mutex_t *)&pool->cs);
    return idx >= 0;
}

bool tx_mempool_lookup(const struct tx_mempool *pool,
                        const struct uint256 *hash,
                        struct transaction *result)
{
    zcl_mutex_lock((zcl_mutex_t *)&pool->cs);
    int idx = find_entry_by_hash(pool, hash);
    if (idx < 0) {
        zcl_mutex_unlock((zcl_mutex_t *)&pool->cs);
        return false;
    }
    transaction_copy(result, &pool->entries[idx].tx);
    zcl_mutex_unlock((zcl_mutex_t *)&pool->cs);
    return true;
}

static void remove_entry_at(struct tx_mempool *pool, size_t idx)
{
    struct mempool_entry *e = &pool->entries[idx];

    for (size_t i = 0; i < e->tx.num_vin; i++) {
        struct outpoint op;
        op.hash = e->tx.vin[i].prevout.hash;
        op.n = e->tx.vin[i].prevout.n;
        if (outpoint_remove(pool->next_tx, pool->next_tx_cap, &op) &&
            pool->next_tx_used > 0)
            pool->next_tx_used--;
    }

    pool->total_tx_size -= e->tx_size;
    mempool_entry_free(e);

    if (idx < pool->num_entries - 1)
        pool->entries[idx] = pool->entries[pool->num_entries - 1];
    pool->num_entries--;
    pool->txs_updated++;

    /* update outpoint map indices for the moved entry */
    if (idx < pool->num_entries) {
        struct mempool_entry *moved = &pool->entries[idx];
        for (size_t i = 0; i < moved->tx.num_vin; i++) {
            struct outpoint op;
            op.hash = moved->tx.vin[i].prevout.hash;
            op.n = moved->tx.vin[i].prevout.n;
            struct outpoint_map_entry *found =
                outpoint_find(pool->next_tx, pool->next_tx_cap, &op);
            if (found)
                found->value.tx_index = idx;
        }
    }
}

void tx_mempool_remove(struct tx_mempool *pool, const struct uint256 *hash)
{
    zcl_mutex_lock(&pool->cs);
    int idx = find_entry_by_hash(pool, hash);
    if (idx >= 0) {
        pool->removed_direct_total++;
        remove_entry_at(pool, (size_t)idx);
    }
    zcl_mutex_unlock(&pool->cs);
}

void tx_mempool_remove_for_block(struct tx_mempool *pool,
                                  const struct transaction *txs,
                                  size_t num_txs,
                                  unsigned int block_height)
{
    (void)block_height;
    zcl_mutex_lock(&pool->cs);
    for (size_t t = 0; t < num_txs; t++) {
        int idx = find_entry_by_hash(pool, &txs[t].hash);
        if (idx >= 0) {
            pool->removed_for_block_total++;
            remove_entry_at(pool, (size_t)idx);
        }
    }
    zcl_mutex_unlock(&pool->cs);
}

void tx_mempool_remove_without_branch_id(struct tx_mempool *pool,
                                          uint32_t branch_id)
{
    zcl_mutex_lock(&pool->cs);
    for (size_t i = 0; i < pool->num_entries; ) {
        if (pool->entries[i].branch_id != branch_id) {
            pool->removed_for_branch_total++;
            remove_entry_at(pool, i);
        } else
            i++;
    }
    zcl_mutex_unlock(&pool->cs);
}

bool tx_mempool_has_no_inputs_of(const struct tx_mempool *pool,
                                  const struct transaction *tx)
{
    zcl_mutex_lock((zcl_mutex_t *)&pool->cs);
    for (size_t i = 0; i < tx->num_vin; i++) {
        if (find_entry_by_hash(pool, &tx->vin[i].prevout.hash) >= 0) {
            zcl_mutex_unlock((zcl_mutex_t *)&pool->cs);
            return false;
        }
    }
    zcl_mutex_unlock((zcl_mutex_t *)&pool->cs);
    return true;
}

bool tx_mempool_has_conflict(const struct tx_mempool *pool,
                              const struct transaction *tx)
{
    if (!pool || !tx) return false;
    zcl_mutex_t *cs = (zcl_mutex_t *)&pool->cs;
    zcl_mutex_lock(cs);
    for (size_t i = 0; i < tx->num_vin; i++) {
        struct outpoint op;
        op.hash = tx->vin[i].prevout.hash;
        op.n = tx->vin[i].prevout.n;
        if (outpoint_find((struct outpoint_map_entry *)pool->next_tx,
                           pool->next_tx_cap, &op) != NULL) {
            zcl_mutex_unlock(cs);
            return true;
        }
    }
    zcl_mutex_unlock(cs);
    return false;
}

void tx_mempool_query_hashes(struct tx_mempool *pool,
                              struct uint256 *out, size_t max_out,
                              size_t *num_out)
{
    zcl_mutex_lock(&pool->cs);
    size_t n = pool->num_entries < max_out ? pool->num_entries : max_out;
    for (size_t i = 0; i < n; i++)
        out[i] = pool->entries[i].tx.hash;
    *num_out = n;
    zcl_mutex_unlock(&pool->cs);
}

size_t tx_mempool_collect_views(struct tx_mempool *pool,
                                 struct tx_mempool_entry_view *out,
                                 size_t max_out)
{
    if (!pool || !out || max_out == 0) return 0;
    zcl_mutex_lock(&pool->cs);
    size_t n = pool->num_entries < max_out ? pool->num_entries : max_out;
    for (size_t i = 0; i < n; i++) {
        out[i].hash    = pool->entries[i].tx.hash;
        out[i].fee     = pool->entries[i].fee;
        out[i].tx_size = pool->entries[i].tx_size;
        out[i].time    = pool->entries[i].time;
    }
    zcl_mutex_unlock(&pool->cs);
    return n;
}

/* --- priority deltas --- */

static int find_delta(const struct tx_mempool *pool, const struct uint256 *hash)
{
    for (size_t i = 0; i < pool->num_deltas; i++)
        if (pool->deltas[i].used && uint256_eq(&pool->deltas[i].hash, hash))
            return (int)i;
    return -1;
}

void tx_mempool_prioritise(struct tx_mempool *pool,
                            const struct uint256 *hash,
                            double priority_delta, int64_t fee_delta)
{
    zcl_mutex_lock(&pool->cs);
    int idx = find_delta(pool, hash);
    if (idx >= 0) {
        pool->deltas[idx].priority_delta += priority_delta;
        pool->deltas[idx].fee_delta += fee_delta;
    } else {
        if (pool->num_deltas >= pool->deltas_cap) {
            size_t newcap = pool->deltas_cap * 2;
            struct priority_delta *tmp = zcl_realloc(pool->deltas,
                                                   newcap * sizeof(*tmp), "mempool_deltas_grow");
            if (!tmp) { zcl_mutex_unlock(&pool->cs); return; }
            memset(tmp + pool->deltas_cap, 0,
                   (newcap - pool->deltas_cap) * sizeof(*tmp));
            pool->deltas = tmp;
            pool->deltas_cap = newcap;
        }
        pool->deltas[pool->num_deltas].hash = *hash;
        pool->deltas[pool->num_deltas].priority_delta = priority_delta;
        pool->deltas[pool->num_deltas].fee_delta = fee_delta;
        pool->deltas[pool->num_deltas].used = true;
        pool->num_deltas++;
    }
    zcl_mutex_unlock(&pool->cs);
}

void tx_mempool_apply_deltas(struct tx_mempool *pool,
                              const struct uint256 *hash,
                              double *priority_out, int64_t *fee_out)
{
    zcl_mutex_lock(&pool->cs);
    int idx = find_delta(pool, hash);
    if (idx >= 0) {
        *priority_out += pool->deltas[idx].priority_delta;
        *fee_out += pool->deltas[idx].fee_delta;
    }
    zcl_mutex_unlock(&pool->cs);
}

void tx_mempool_clear_prioritisation(struct tx_mempool *pool,
                                      const struct uint256 *hash)
{
    zcl_mutex_lock(&pool->cs);
    int idx = find_delta(pool, hash);
    if (idx >= 0)
        pool->deltas[idx].used = false;
    zcl_mutex_unlock(&pool->cs);
}
