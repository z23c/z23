/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Orphan transaction pool — holds txs whose parent outputs are
 * not yet in the mempool or UTXO set.
 *
 * Limits: max 50 entries, 10-minute TTL.
 * When a new transaction is accepted to the main mempool, call
 * orphan_pool_reconnect() to promote any orphans whose missing
 * parents just arrived. */

#ifndef ZCL_ORPHAN_POOL_H
#define ZCL_ORPHAN_POOL_H

#include "platform/time_compat.h"
#include "primitives/transaction.h"
#include "core/uint256.h"
#include "util/sync.h"
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

#define ORPHAN_MAX_ENTRIES 50
#define ORPHAN_TTL_SECONDS 600   /* 10 minutes */

struct orphan_entry {
    struct transaction tx;
    int64_t  arrival_time;       /* platform_time_wall_time_t() when added */
    bool     used;
};

struct orphan_pool {
    zcl_mutex_t cs;
    struct orphan_entry entries[ORPHAN_MAX_ENTRIES];
    size_t count;                /* number of used entries */
};

/* Init/free — call once at startup/shutdown. */
void orphan_pool_init(struct orphan_pool *pool);
void orphan_pool_free(struct orphan_pool *pool);

/* Add a transaction to the orphan pool.
 * Returns true if added, false if pool full, duplicate, or tx invalid. */
bool orphan_pool_add(struct orphan_pool *pool, const struct transaction *tx);

/* Check if a transaction hash is in the orphan pool. */
bool orphan_pool_exists(const struct orphan_pool *pool,
                         const struct uint256 *hash);

/* Remove expired entries (older than ORPHAN_TTL_SECONDS). */
size_t orphan_pool_expire(struct orphan_pool *pool, int64_t now);

/* Remove a specific orphan by hash. */
void orphan_pool_remove(struct orphan_pool *pool, const struct uint256 *hash);

/* Erase the entire orphan pool. */
void orphan_pool_clear(struct orphan_pool *pool);

/* Number of entries currently in the pool. */
size_t orphan_pool_size(const struct orphan_pool *pool);

/* Collect orphans that spend a given parent tx hash.
 * Copies up to max_out transactions into `out`.
 * Returns number copied. Caller owns the copies and must free them. */
size_t orphan_pool_find_children(const struct orphan_pool *pool,
                                  const struct uint256 *parent_hash,
                                  struct transaction *out,
                                  size_t max_out);

/* Remove orphans that spend a given parent tx hash and return them.
 * Similar to find_children but also removes from pool.
 * Returns number of orphans extracted. */
size_t orphan_pool_extract_children(struct orphan_pool *pool,
                                     const struct uint256 *parent_hash,
                                     struct transaction *out,
                                     size_t max_out);

#endif
