/* Copyright (c) 2009-2010 Satoshi Nakamoto
 * Copyright (c) 2009-2014 The Bitcoin Core developers
 * Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. */

#ifndef ZCL_TXMEMPOOL_H
#define ZCL_TXMEMPOOL_H

#include "primitives/transaction.h"
#include "core/uint256.h"
#include "core/amount.h"
#include "util/sync.h"
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

#define MEMPOOL_HEIGHT 0x7FFFFFFF
#define COIN_VALUE 100000000LL

static inline double allow_free_threshold(void)
{
    return (double)COIN_VALUE * 144.0 / 250.0;
}

static inline bool allow_free(double priority)
{
    return priority > allow_free_threshold();
}

struct mempool_entry {
    struct transaction tx;
    int64_t fee;
    size_t tx_size;
    size_t mod_size;
    int64_t time;
    double priority;
    unsigned int height;
    bool had_no_deps;
    bool spends_coinbase;
    uint32_t branch_id;
};

void mempool_entry_init(struct mempool_entry *e, const struct transaction *tx,
                        int64_t fee, int64_t time, double priority,
                        unsigned int height, bool pool_has_no_inputs_of,
                        bool spends_coinbase, uint32_t branch_id);

void mempool_entry_free(struct mempool_entry *e);

double mempool_entry_get_priority(const struct mempool_entry *e,
                                   unsigned int current_height);

struct inpoint {
    size_t tx_index;
    uint32_t n;
};

struct outpoint_map_entry {
    struct outpoint key;
    struct inpoint value;
    bool used;
};

struct priority_delta {
    struct uint256 hash;
    double priority_delta;
    int64_t fee_delta;
    bool used;
};

#define MEMPOOL_INITIAL_CAP 256
/* Initial slot count for the open-addressing outpoint map. The map
 * grows (rehash) whenever live occupancy crosses 70% of capacity, so
 * this is a starting size, not a hard ceiling. */
#define OUTPOINT_MAP_CAP 4096
#define PRIORITY_MAP_CAP 256

struct tx_mempool {
    zcl_mutex_t cs;

    struct mempool_entry *entries;
    size_t num_entries;
    size_t entries_cap;

    struct outpoint_map_entry *next_tx;
    size_t next_tx_cap;
    size_t next_tx_used;   /* live (used) slots — drives grow trigger */

    struct priority_delta *deltas;
    size_t num_deltas;
    size_t deltas_cap;

    unsigned int txs_updated;
    uint64_t total_tx_size;
    uint64_t added_total;
    uint64_t removed_direct_total;
    uint64_t removed_for_block_total;
    uint64_t removed_for_branch_total;
    uint64_t cleared_total;

    int64_t min_relay_fee;
};

struct tx_mempool_stats {
    size_t size;
    uint64_t bytes;
    uint64_t added_total;
    uint64_t removed_direct_total;
    uint64_t removed_for_block_total;
    uint64_t removed_for_branch_total;
    uint64_t cleared_total;
};

void tx_mempool_init(struct tx_mempool *pool, int64_t min_relay_fee);
void tx_mempool_free(struct tx_mempool *pool);
void tx_mempool_clear(struct tx_mempool *pool);

size_t tx_mempool_size(struct tx_mempool *pool);
uint64_t tx_mempool_total_size(struct tx_mempool *pool);
void tx_mempool_stats_snapshot(struct tx_mempool *pool,
                               struct tx_mempool_stats *out);
unsigned int tx_mempool_txs_updated(struct tx_mempool *pool);
void tx_mempool_add_txs_updated(struct tx_mempool *pool, unsigned int n);

bool tx_mempool_add_unchecked(struct tx_mempool *pool,
                               const struct uint256 *hash,
                               const struct mempool_entry *entry);

bool tx_mempool_exists(const struct tx_mempool *pool,
                        const struct uint256 *hash);

bool tx_mempool_lookup(const struct tx_mempool *pool,
                        const struct uint256 *hash,
                        struct transaction *result);

void tx_mempool_remove(struct tx_mempool *pool,
                        const struct uint256 *hash);

void tx_mempool_remove_for_block(struct tx_mempool *pool,
                                  const struct transaction *txs,
                                  size_t num_txs,
                                  unsigned int block_height);

void tx_mempool_remove_without_branch_id(struct tx_mempool *pool,
                                          uint32_t branch_id);

bool tx_mempool_has_no_inputs_of(const struct tx_mempool *pool,
                                  const struct transaction *tx);

/* Returns true iff any input of `tx` is already spent by another
 * transaction in the mempool. Read-only probe — does not mutate the
 * pool. Used by the `tx` message handler to reject
 * double-spends with a typed peer offence before attempting the
 * add-unchecked path, where double-spends are also detected but fold
 * into a generic "add failed" return. */
bool tx_mempool_has_conflict(const struct tx_mempool *pool,
                              const struct transaction *tx);

void tx_mempool_query_hashes(struct tx_mempool *pool,
                              struct uint256 *out, size_t max_out,
                              size_t *num_out);

/* ── Lightweight view snapshot (hash + fee + size + time) ──
 *
 * Policy modules (mempool_limits, fee estimation) need a stable
 * read-only snapshot of the fields they care about without
 * copying whole transactions. This accessor copies at most
 * `max_out` tuples while holding `pool->cs` and returns how
 * many were actually copied. Callers sort/filter in userspace
 * and re-issue removals via `tx_mempool_remove(hash)` — which
 * re-acquires the lock, so the snapshot is a point-in-time view
 * and may be stale by the time a removal runs. That is safe:
 * `tx_mempool_remove` is a no-op if the hash is gone. */
struct tx_mempool_entry_view {
    struct uint256 hash;
    int64_t fee;
    size_t  tx_size;
    int64_t time;
};

size_t tx_mempool_collect_views(struct tx_mempool *pool,
                                 struct tx_mempool_entry_view *out,
                                 size_t max_out);

/* ── Post-add hook ───────────────────────────────────────────
 *
 * `tx_mempool_add_unchecked` calls the registered hook (if any)
 * after a successful add, with the pool lock released. This is
 * the seam `mempool_limits_start` uses to enforce size/count
 * caps on every acceptance without introducing a reverse
 * dependency from core/modules/validation into app/services. The hook
 * may re-enter mempool operations (remove, collect_views, etc.)
 * but must not itself call `tx_mempool_add_unchecked` — that
 * would recurse forever. A NULL hook disables the feature.
 */
typedef void (*tx_mempool_post_add_hook_fn)(struct tx_mempool *pool);
void tx_mempool_set_post_add_hook(tx_mempool_post_add_hook_fn fn);

void tx_mempool_prioritise(struct tx_mempool *pool,
                            const struct uint256 *hash,
                            double priority_delta, int64_t fee_delta);

void tx_mempool_apply_deltas(struct tx_mempool *pool,
                              const struct uint256 *hash,
                              double *priority_delta, int64_t *fee_delta);

void tx_mempool_clear_prioritisation(struct tx_mempool *pool,
                                      const struct uint256 *hash);

#endif
