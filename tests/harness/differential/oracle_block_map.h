/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * FROZEN ORACLE (append-only): the block_map as it was before the buckets
 * dropped their duplicated 32-byte key (48-byte bucket {hash, index,
 * occupied}).  Copied verbatim from core/modules/validation/src/chainstate.c
 * and include/validation/chainstate.h at origin/main 23519699c, with every
 * block_map identifier prefixed oracle_ and every function made static.
 * Do not edit the algorithm; the differential test (test_block_map_keyless)
 * proves the production map is slot-for-slot equivalent to this one.
 */
#ifndef ORACLE_BLOCK_MAP_H
#define ORACLE_BLOCK_MAP_H

#include "chain/chain.h"
#include "core/uint256.h"
#include "util/log_macros.h"
#include "util/safe_alloc.h"
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

struct oracle_block_map_entry {
    struct uint256 hash;
    struct block_index *index;
    bool occupied;
};

struct oracle_block_map {
    struct oracle_block_map_entry *buckets;
    size_t size;
    size_t capacity;
    pthread_rwlock_t rwlock;
};

static uint64_t oracle_block_map_hash(const struct uint256 *h)
{
    uint64_t v;
    memcpy(&v, h->data, 8);
    return v;
}

static bool oracle_block_map_grow(struct oracle_block_map *m);

static void oracle_block_map_init(struct oracle_block_map *m)
{
    m->buckets = NULL;
    m->size = 0;
    m->capacity = 0;
    pthread_rwlock_init(&m->rwlock, NULL);
}

static void oracle_block_map_free(struct oracle_block_map *m)
{
    pthread_rwlock_wrlock(&m->rwlock);
    /* Only free individually-allocated entries. Arena-allocated entries
     * (from bulk flat-file load) are in a contiguous block — freeing
     * individual pointers from an arena causes double-free/invalid-free.
     * We detect arena entries by checking if adjacent entries in the
     * bucket array point to contiguous memory. For simplicity, skip
     * freeing entirely — block_index lives for process lifetime. */
    free(m->buckets);
    m->buckets = NULL;
    m->size = 0;
    m->capacity = 0;
    pthread_rwlock_unlock(&m->rwlock);
    pthread_rwlock_destroy(&m->rwlock);
}

static struct block_index *oracle_block_map_find(const struct oracle_block_map *m,
                                    const struct uint256 *hash)
{
    if (m->capacity == 0) return NULL;
    pthread_rwlock_rdlock((pthread_rwlock_t *)&m->rwlock);
    uint64_t h = oracle_block_map_hash(hash);
    size_t idx = h & (m->capacity - 1);
    struct block_index *result = NULL;
    for (size_t i = 0; i < m->capacity; i++) {
        size_t slot = (idx + i) & (m->capacity - 1);
        if (!m->buckets[slot].occupied)
            break;
        if (uint256_eq(&m->buckets[slot].hash, hash)) {
            result = m->buckets[slot].index;
            break;
        }
    }
    pthread_rwlock_unlock((pthread_rwlock_t *)&m->rwlock);
    return result;
}

static bool oracle_block_map_insert_internal(struct oracle_block_map *m,
                                       const struct uint256 *hash,
                                       struct block_index *index)
{
    uint64_t h = oracle_block_map_hash(hash);
    size_t idx = h & (m->capacity - 1);
    for (size_t i = 0; i < m->capacity; i++) {
        size_t slot = (idx + i) & (m->capacity - 1);
        if (!m->buckets[slot].occupied) {
            m->buckets[slot].hash = *hash;
            m->buckets[slot].index = index;
            m->buckets[slot].occupied = true;
            return true;
        }
        if (uint256_eq(&m->buckets[slot].hash, hash))
            LOG_FAIL("chainstate", "oracle_block_map_insert_internal: duplicate hash in slot %zu", slot);
    }
    LOG_FAIL("chainstate", "oracle_block_map_insert_internal: hash table full (capacity=%zu)", m->capacity);
}

/* Pre-allocate hash map to avoid repeated rehashing during bulk load.
 * next_power_of_2(n * 2) gives ~50% load factor for good probe performance. */
static bool oracle_block_map_reserve(struct oracle_block_map *m, size_t expected_count)
{
    size_t target = expected_count * 2;
    size_t cap = 4096;
    while (cap < target) cap *= 2;
    if (cap <= m->capacity) return true;

    pthread_rwlock_wrlock(&m->rwlock);
    struct oracle_block_map_entry *old = m->buckets;
    size_t old_cap = m->capacity;

    m->buckets = zcl_calloc(cap, sizeof(struct oracle_block_map_entry), "oracle_block_map_buckets");
    if (!m->buckets) {
        m->buckets = old;
        pthread_rwlock_unlock(&m->rwlock);
        LOG_FAIL("chainstate", "oracle_block_map_reserve: calloc failed for %zu entries", cap);
    }
    m->capacity = cap;

    for (size_t i = 0; i < old_cap; i++) {
        if (old[i].occupied)
            oracle_block_map_insert_internal(m, &old[i].hash, old[i].index);
    }
    free(old);
    /* Option A: phashBlock points at per-node block_index.hashBlock
     * (never-freed), so reallocating the bucket array does not
     * invalidate it. The bucket .hash keys are re-seeded by
     * oracle_block_map_insert_internal above; no phashBlock repoint needed. */
    pthread_rwlock_unlock(&m->rwlock);
    return true;
}

static bool oracle_block_map_grow(struct oracle_block_map *m)
{
    size_t new_cap = m->capacity ? m->capacity * 2 : 4096;
    struct oracle_block_map_entry *old = m->buckets;
    size_t old_cap = m->capacity;

    m->buckets = zcl_calloc(new_cap, sizeof(struct oracle_block_map_entry), "oracle_block_map_buckets_grow");
    if (!m->buckets) {
        m->buckets = old;
        LOG_FAIL("chainstate", "oracle_block_map_grow: calloc failed for %zu entries", new_cap);
    }
    m->capacity = new_cap;

    for (size_t i = 0; i < old_cap; i++) {
        if (old[i].occupied)
            oracle_block_map_insert_internal(m, &old[i].hash, old[i].index);
    }
    free(old);

    /* Option A: phashBlock references per-node block_index.hashBlock
     * (never freed), NOT the bucket array. Growing/reallocating the
     * bucket array therefore does not invalidate any phashBlock, so
     * no repoint loop is needed here. This removes the UAF: lock-free
     * readers (push_getheaders_from, syncsvc_build_locator_from_index,
     * block_index_get_ancestor) deref *walk->phashBlock against stable
     * per-node storage that this free() never touches. Bucket .hash
     * keys are re-seeded by oracle_block_map_insert_internal above. */

    return true;
}

static bool oracle_block_map_insert(struct oracle_block_map *m, const struct uint256 *hash,
                      struct block_index *index)
{
    pthread_rwlock_wrlock(&m->rwlock);
    if (m->size * 4 >= m->capacity * 3) {
        if (!oracle_block_map_grow(m)) {
            pthread_rwlock_unlock(&m->rwlock);
            LOG_FAIL("chainstate", "oracle_block_map_insert: grow failed (size=%zu)", m->size);
        }
    }
    if (!oracle_block_map_insert_internal(m, hash, index)) {
        pthread_rwlock_unlock(&m->rwlock);
        LOG_FAIL("chainstate", "oracle_block_map_insert: duplicate block hash (size=%zu)", m->size);
    }
    m->size++;
    pthread_rwlock_unlock(&m->rwlock);
    return true;
}

static size_t oracle_block_map_count(const struct oracle_block_map *m)
{
    return m->size;
}

static bool oracle_block_map_next(const struct oracle_block_map *m, size_t *iter,
                    const struct uint256 **hash_out,
                    struct block_index **index_out)
{
    pthread_rwlock_rdlock((pthread_rwlock_t *)&m->rwlock);
    while (*iter < m->capacity) {
        size_t i = (*iter)++;
        if (m->buckets[i].occupied) {
            if (hash_out) *hash_out = &m->buckets[i].hash;
            if (index_out) *index_out = m->buckets[i].index;
            pthread_rwlock_unlock((pthread_rwlock_t *)&m->rwlock);
            return true;
        }
    }
    pthread_rwlock_unlock((pthread_rwlock_t *)&m->rwlock);
    return false;
}

static bool oracle_block_map_snapshot_indices(const struct oracle_block_map *m,
                                struct block_index ***indices_out,
                                size_t *count_out)
{
    if (indices_out) *indices_out = NULL;
    if (count_out) *count_out = 0;
    if (!m || !indices_out || !count_out) {
        LOG_FAIL("chainstate",
                 "oracle_block_map_snapshot_indices: null map=%d indices_out=%d "
                 "count_out=%d",
                 !m, !indices_out, !count_out);
    }

    pthread_rwlock_rdlock((pthread_rwlock_t *)&m->rwlock);
    size_t expected = m->size;
    if (expected == 0) {
        pthread_rwlock_unlock((pthread_rwlock_t *)&m->rwlock);
        return true;
    }
    if (expected > SIZE_MAX / sizeof(struct block_index *)) {
        pthread_rwlock_unlock((pthread_rwlock_t *)&m->rwlock);
        LOG_FAIL("chainstate",
                 "oracle_block_map_snapshot_indices: size overflow for %zu entries",
                 expected);
    }

    struct block_index **indices = zcl_malloc(
        expected * sizeof(*indices), "oracle_block_map_snapshot_indices");
    if (!indices) {
        pthread_rwlock_unlock((pthread_rwlock_t *)&m->rwlock);
        LOG_FAIL("chainstate",
                 "oracle_block_map_snapshot_indices: malloc failed for %zu entries",
                 expected);
    }

    size_t count = 0;
    for (size_t i = 0; i < m->capacity; i++) {
        if (!m->buckets[i].occupied)
            continue;
        if (count >= expected) {
            free(indices);
            pthread_rwlock_unlock((pthread_rwlock_t *)&m->rwlock);
            LOG_FAIL("chainstate",
                     "oracle_block_map_snapshot_indices: map size drift under read "
                     "lock expected=%zu count=%zu",
                     expected, count + 1);
        }
        indices[count++] = m->buckets[i].index;
    }
    pthread_rwlock_unlock((pthread_rwlock_t *)&m->rwlock);

    if (count != expected) {
        free(indices);
        LOG_FAIL("chainstate",
                 "oracle_block_map_snapshot_indices: occupied count mismatch "
                 "expected=%zu actual=%zu",
                 expected, count);
    }

    *indices_out = indices;
    *count_out = count;
    return true;
}


#endif
