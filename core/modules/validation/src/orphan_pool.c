/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Orphan transaction pool implementation. */

#include "platform/time_compat.h"
#include "validation/orphan_pool.h"
#include "util/log_macros.h"
#include <stdlib.h>
#include <string.h>
#include <time.h>

void orphan_pool_init(struct orphan_pool *pool)
{
    memset(pool, 0, sizeof(*pool));
    zcl_mutex_init(&pool->cs);
}

void orphan_pool_free(struct orphan_pool *pool)
{
    for (size_t i = 0; i < ORPHAN_MAX_ENTRIES; i++) {
        if (pool->entries[i].used)
            transaction_free(&pool->entries[i].tx);
    }
    zcl_mutex_destroy(&pool->cs);
}

static int find_by_hash(const struct orphan_pool *pool,
                         const struct uint256 *hash)
{
    for (size_t i = 0; i < ORPHAN_MAX_ENTRIES; i++) {
        if (pool->entries[i].used &&
            uint256_eq(&pool->entries[i].tx.hash, hash))
            return (int)i;
    }
    return -1;
}

static int find_free_slot(const struct orphan_pool *pool)
{
    for (size_t i = 0; i < ORPHAN_MAX_ENTRIES; i++) {
        if (!pool->entries[i].used)
            return (int)i;
    }
    return -1;
}

static void remove_at(struct orphan_pool *pool, size_t idx)
{
    transaction_free(&pool->entries[idx].tx);
    pool->entries[idx].used = false;
    pool->count--;
}

bool orphan_pool_add(struct orphan_pool *pool, const struct transaction *tx)
{
    if (!pool || !tx || tx->num_vin == 0)
        LOG_FAIL("orphan", "invalid input: pool=%p tx=%p num_vin=%zu",
                 (void *)pool, (void *)tx, tx ? tx->num_vin : 0);

    zcl_mutex_lock(&pool->cs);

    /* Reject duplicate */
    if (find_by_hash(pool, &tx->hash) >= 0) {
        zcl_mutex_unlock(&pool->cs);
        return false;
    }

    /* Pool full */
    if (pool->count >= ORPHAN_MAX_ENTRIES) {
        zcl_mutex_unlock(&pool->cs);
        LOG_FAIL("orphan", "pool full: count=%zu max=%d", pool->count, ORPHAN_MAX_ENTRIES);
    }

    int slot = find_free_slot(pool);
    if (slot < 0) {
        zcl_mutex_unlock(&pool->cs);
        LOG_FAIL("orphan", "no free slot despite count=%zu < max=%d", pool->count, ORPHAN_MAX_ENTRIES);
    }

    transaction_copy(&pool->entries[slot].tx, tx);
    pool->entries[slot].arrival_time = (int64_t)platform_time_wall_time_t();
    pool->entries[slot].used = true;
    pool->count++;

    zcl_mutex_unlock(&pool->cs);
    return true;
}

bool orphan_pool_exists(const struct orphan_pool *pool,
                         const struct uint256 *hash)
{
    zcl_mutex_lock((zcl_mutex_t *)&pool->cs);
    bool found = find_by_hash(pool, hash) >= 0;
    zcl_mutex_unlock((zcl_mutex_t *)&pool->cs);
    return found;
}

size_t orphan_pool_expire(struct orphan_pool *pool, int64_t now)
{
    size_t removed = 0;
    zcl_mutex_lock(&pool->cs);
    for (size_t i = 0; i < ORPHAN_MAX_ENTRIES; i++) {
        if (pool->entries[i].used &&
            (now - pool->entries[i].arrival_time) >= ORPHAN_TTL_SECONDS) {
            remove_at(pool, i);
            removed++;
        }
    }
    zcl_mutex_unlock(&pool->cs);
    return removed;
}

void orphan_pool_remove(struct orphan_pool *pool, const struct uint256 *hash)
{
    zcl_mutex_lock(&pool->cs);
    int idx = find_by_hash(pool, hash);
    if (idx >= 0)
        remove_at(pool, (size_t)idx);
    zcl_mutex_unlock(&pool->cs);
}

void orphan_pool_clear(struct orphan_pool *pool)
{
    zcl_mutex_lock(&pool->cs);
    for (size_t i = 0; i < ORPHAN_MAX_ENTRIES; i++) {
        if (pool->entries[i].used)
            remove_at(pool, i);
    }
    zcl_mutex_unlock(&pool->cs);
}

size_t orphan_pool_size(const struct orphan_pool *pool)
{
    zcl_mutex_lock((zcl_mutex_t *)&pool->cs);
    size_t n = pool->count;
    zcl_mutex_unlock((zcl_mutex_t *)&pool->cs);
    return n;
}

size_t orphan_pool_find_children(const struct orphan_pool *pool,
                                  const struct uint256 *parent_hash,
                                  struct transaction *out,
                                  size_t max_out)
{
    size_t found = 0;
    zcl_mutex_lock((zcl_mutex_t *)&pool->cs);
    for (size_t i = 0; i < ORPHAN_MAX_ENTRIES && found < max_out; i++) {
        if (!pool->entries[i].used) continue;
        const struct transaction *tx = &pool->entries[i].tx;
        for (size_t j = 0; j < tx->num_vin; j++) {
            if (uint256_eq(&tx->vin[j].prevout.hash, parent_hash)) {
                transaction_copy(&out[found], tx);
                found++;
                break;
            }
        }
    }
    zcl_mutex_unlock((zcl_mutex_t *)&pool->cs);
    return found;
}

size_t orphan_pool_extract_children(struct orphan_pool *pool,
                                     const struct uint256 *parent_hash,
                                     struct transaction *out,
                                     size_t max_out)
{
    size_t found = 0;
    zcl_mutex_lock(&pool->cs);
    for (size_t i = 0; i < ORPHAN_MAX_ENTRIES && found < max_out; i++) {
        if (!pool->entries[i].used) continue;
        const struct transaction *tx = &pool->entries[i].tx;
        for (size_t j = 0; j < tx->num_vin; j++) {
            if (uint256_eq(&tx->vin[j].prevout.hash, parent_hash)) {
                transaction_copy(&out[found], tx);
                found++;
                remove_at(pool, i);
                break;
            }
        }
    }
    zcl_mutex_unlock(&pool->cs);
    return found;
}
