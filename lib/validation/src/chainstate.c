/* Copyright (c) 2009-2010 Satoshi Nakamoto
 * Copyright (c) 2009-2014 The Bitcoin Core developers
 * Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. */

#include "validation/chainstate.h"
#include "validation/chain_linkage_check.h"
#include "platform/time_compat.h"
#include "util/log_macros.h"
#include "util/log_throttle.h"
#include "storage/progress_store.h"
#include <limits.h>
#include <sqlite3.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>
#include "util/safe_alloc.h"

/* S5 observability counters — see chainstate.h
 * active_chain_extend_window_have_data_{fast,slow}_count(). */
static _Atomic uint64_t g_window_extend_fast_hits = 0;
static _Atomic uint64_t g_window_extend_slow_hits = 0;
/* Times the have-data merge recognized a body on a same-hash block_map twin of
 * a bodiless best-header ancestry object (the live H+1 duplicate wedge). A live
 * climb on this counter names the heights the duplicate-body merge rescued —
 * see active_chain_extend_window_have_data / have_data_by_hash. */
static _Atomic uint64_t g_window_dup_data_rescued = 0;
static struct log_throttle g_dup_data_throttle = LOG_THROTTLE_INIT;

uint64_t active_chain_extend_window_have_data_fast_count(void)
{
    return atomic_load_explicit(&g_window_extend_fast_hits,
                                memory_order_relaxed);
}

uint64_t active_chain_extend_window_have_data_slow_count(void)
{
    return atomic_load_explicit(&g_window_extend_slow_hits,
                                memory_order_relaxed);
}

uint64_t active_chain_extend_window_dup_data_rescued_count(void)
{
    return atomic_load_explicit(&g_window_dup_data_rescued,
                                memory_order_relaxed);
}

/* --- Block Map (open-addressing hash table) --- */

static uint64_t block_map_hash(const struct uint256 *h)
{
    uint64_t v;
    memcpy(&v, h->data, 8);
    return v;
}

static bool block_map_grow(struct block_map *m);

void block_map_init(struct block_map *m)
{
    m->buckets = NULL;
    m->size = 0;
    m->capacity = 0;
    pthread_rwlock_init(&m->rwlock, NULL);
}

void block_map_free(struct block_map *m)
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

struct block_index *block_map_find(const struct block_map *m,
                                    const struct uint256 *hash)
{
    if (m->capacity == 0) return NULL;
    pthread_rwlock_rdlock((pthread_rwlock_t *)&m->rwlock);
    uint64_t h = block_map_hash(hash);
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

static bool block_map_insert_internal(struct block_map *m,
                                       const struct uint256 *hash,
                                       struct block_index *index)
{
    uint64_t h = block_map_hash(hash);
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
            LOG_FAIL("chainstate", "block_map_insert_internal: duplicate hash in slot %zu", slot);
    }
    LOG_FAIL("chainstate", "block_map_insert_internal: hash table full (capacity=%zu)", m->capacity);
}

/* Pre-allocate hash map to avoid repeated rehashing during bulk load.
 * next_power_of_2(n * 2) gives ~50% load factor for good probe performance. */
bool block_map_reserve(struct block_map *m, size_t expected_count)
{
    size_t target = expected_count * 2;
    size_t cap = 4096;
    while (cap < target) cap *= 2;
    if (cap <= m->capacity) return true;

    pthread_rwlock_wrlock(&m->rwlock);
    struct block_map_entry *old = m->buckets;
    size_t old_cap = m->capacity;

    m->buckets = zcl_calloc(cap, sizeof(struct block_map_entry), "block_map_buckets");
    if (!m->buckets) {
        m->buckets = old;
        pthread_rwlock_unlock(&m->rwlock);
        LOG_FAIL("chainstate", "block_map_reserve: calloc failed for %zu entries", cap);
    }
    m->capacity = cap;

    for (size_t i = 0; i < old_cap; i++) {
        if (old[i].occupied)
            block_map_insert_internal(m, &old[i].hash, old[i].index);
    }
    free(old);
    /* Option A: phashBlock points at per-node block_index.hashBlock
     * (never-freed), so reallocating the bucket array does not
     * invalidate it. The bucket .hash keys are re-seeded by
     * block_map_insert_internal above; no phashBlock repoint needed. */
    pthread_rwlock_unlock(&m->rwlock);
    return true;
}

static bool block_map_grow(struct block_map *m)
{
    size_t new_cap = m->capacity ? m->capacity * 2 : 4096;
    struct block_map_entry *old = m->buckets;
    size_t old_cap = m->capacity;

    m->buckets = zcl_calloc(new_cap, sizeof(struct block_map_entry), "block_map_buckets_grow");
    if (!m->buckets) {
        m->buckets = old;
        LOG_FAIL("chainstate", "block_map_grow: calloc failed for %zu entries", new_cap);
    }
    m->capacity = new_cap;

    for (size_t i = 0; i < old_cap; i++) {
        if (old[i].occupied)
            block_map_insert_internal(m, &old[i].hash, old[i].index);
    }
    free(old);

    /* Option A: phashBlock references per-node block_index.hashBlock
     * (never freed), NOT the bucket array. Growing/reallocating the
     * bucket array therefore does not invalidate any phashBlock, so
     * no repoint loop is needed here. This removes the UAF: lock-free
     * readers (push_getheaders_from, syncsvc_build_locator_from_index,
     * block_index_get_ancestor) deref *walk->phashBlock against stable
     * per-node storage that this free() never touches. Bucket .hash
     * keys are re-seeded by block_map_insert_internal above. */

    return true;
}

bool block_map_insert(struct block_map *m, const struct uint256 *hash,
                      struct block_index *index)
{
    pthread_rwlock_wrlock(&m->rwlock);
    if (m->size * 4 >= m->capacity * 3) {
        if (!block_map_grow(m)) {
            pthread_rwlock_unlock(&m->rwlock);
            LOG_FAIL("chainstate", "block_map_insert: grow failed (size=%zu)", m->size);
        }
    }
    if (!block_map_insert_internal(m, hash, index)) {
        pthread_rwlock_unlock(&m->rwlock);
        LOG_FAIL("chainstate", "block_map_insert: duplicate block hash (size=%zu)", m->size);
    }
    m->size++;
    pthread_rwlock_unlock(&m->rwlock);
    return true;
}

size_t block_map_count(const struct block_map *m)
{
    return m->size;
}

bool block_map_next(const struct block_map *m, size_t *iter,
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

bool block_map_snapshot_indices(const struct block_map *m,
                                struct block_index ***indices_out,
                                size_t *count_out)
{
    if (indices_out) *indices_out = NULL;
    if (count_out) *count_out = 0;
    if (!m || !indices_out || !count_out) {
        LOG_FAIL("chainstate",
                 "block_map_snapshot_indices: null map=%d indices_out=%d "
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
                 "block_map_snapshot_indices: size overflow for %zu entries",
                 expected);
    }

    struct block_index **indices = zcl_malloc(
        expected * sizeof(*indices), "block_map_snapshot_indices");
    if (!indices) {
        pthread_rwlock_unlock((pthread_rwlock_t *)&m->rwlock);
        LOG_FAIL("chainstate",
                 "block_map_snapshot_indices: malloc failed for %zu entries",
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
                     "block_map_snapshot_indices: map size drift under read "
                     "lock expected=%zu count=%zu",
                     expected, count + 1);
        }
        indices[count++] = m->buckets[i].index;
    }
    pthread_rwlock_unlock((pthread_rwlock_t *)&m->rwlock);

    if (count != expected) {
        free(indices);
        LOG_FAIL("chainstate",
                 "block_map_snapshot_indices: occupied count mismatch "
                 "expected=%zu actual=%zu",
                 expected, count);
    }

    *indices_out = indices;
    *count_out = count;
    return true;
}

/* --- Active Chain --- */

static struct active_chain_authority g_chain_authority = {0};
static struct block_map *g_chain_block_map = NULL;

void active_chain_register_authority(const struct active_chain_authority *auth)
{
    if (auth) g_chain_authority = *auth;
}

void active_chain_register_block_map(struct block_map *m)
{
    g_chain_block_map = m;
}

void active_chain_init(struct active_chain *c)
{
    c->chain = NULL;
    c->height = -1;
    c->capacity = 0;
    c->retired = NULL;
    zcl_mutex_init(&c->write_lock);
}

void active_chain_free(struct active_chain *c)
{
    zcl_mutex_lock(&c->write_lock);
    free(c->chain);
    c->chain = NULL;
    c->height = -1;
    c->capacity = 0;
    while (c->retired) {
        struct active_chain_retired *r = c->retired;
        c->retired = r->next;
        free(r->arr);
        free(r);
    }
    zcl_mutex_unlock(&c->write_lock);
    zcl_mutex_destroy(&c->write_lock);
}

/* Lock-free reader discipline (all readers below): load the index bound
 * (height) BEFORE the array pointer. Writers publish height LAST, so an
 * array loaded after the bound always spans it; an older array seen with
 * an older bound is retired-not-freed, so the deref is always in-bounds
 * against live storage. */
struct block_index *active_chain_cached_tip(const struct active_chain *c)
{
    if (!c)
        return NULL;
    int h = c->height;
    if (h < 0 || h >= c->capacity)
        return NULL;
    struct block_index **arr = c->chain;
    if (!arr)
        return NULL;
    return arr[h];
}

int active_chain_cached_height(const struct active_chain *c)
{
    return c ? atomic_load_explicit(&c->height, memory_order_acquire) : -1;
}

struct block_index *active_chain_tip(const struct active_chain *c)
{
    if (!c || !c->chain) return NULL;
    if (g_chain_authority.is_authoritative &&
        g_chain_authority.is_authoritative()) {
        uint8_t h32[32];
        if (g_chain_authority.get_hash && g_chain_block_map &&
            g_chain_authority.get_hash(h32)) {
            struct uint256 hash;
            memcpy(hash.data, h32, 32);
            struct block_index *bi = block_map_find(g_chain_block_map, &hash);
            if (bi) return bi;
        }
    }
    int h = active_chain_height(c);
    if (h < 0 || h >= c->capacity) return NULL;
    struct block_index **arr = c->chain;
    if (!arr) return NULL;
    return arr[h];
}

struct block_index *active_chain_at(const struct active_chain *c, int height)
{
    if (!c || height < 0 || height > c->height) return NULL;
    struct block_index **arr = c->chain;
    if (!arr) return NULL;
    return arr[height];
}

bool active_chain_capture_window(struct active_chain *c,
                                 int requested_height,
                                 struct active_chain_window_snapshot *out)
{
    if (!c || !out)
        return false;
    struct active_chain_window_snapshot snapshot = {
        .height = -1,
        .requested_height = requested_height,
    };
    zcl_mutex_lock(&c->write_lock);
    int height = c->height;
    int capacity = c->capacity;
    struct block_index **arr = c->chain;
    snapshot.height = height;
    if (arr && height >= 0 && height < capacity)
        snapshot.tip = arr[height];
    if (arr && requested_height >= 0 && requested_height <= height &&
        requested_height < capacity)
        snapshot.requested = arr[requested_height];
    zcl_mutex_unlock(&c->write_lock);
    *out = snapshot;
    return true;
}

bool active_chain_contains(const struct active_chain *c,
                           const struct block_index *bi)
{
    if (bi->nHeight < 0 || bi->nHeight > c->height) return false;
    struct block_index **arr = c->chain;
    if (!arr) return false;
    return arr[bi->nHeight] == bi;
}

/* Grow chain[] to cover min_height. write_lock must be held. A grow never
 * frees the old array in place (lock-free readers — RPC, net locator builds,
 * bg verification — may hold it): the new array is fully populated, published,
 * then the wider capacity, and the old one retired until active_chain_free.
 * Growth is geometric so the retired set stays O(log height) arrays, bounded
 * by ~1x the live array. Returns false only on allocation failure (callers
 * log context). */
static bool active_chain_grow_locked(struct active_chain *c, int min_height)
{
    if (min_height < c->capacity)
        return true;
    int old_cap = c->capacity;
    int new_cap = min_height + 1024;
    if (old_cap > 0 && old_cap <= INT_MAX / 2 && old_cap * 2 > new_cap)
        new_cap = old_cap * 2;
    struct block_index **nc = zcl_malloc(
        (size_t)new_cap * sizeof(struct block_index *), "active_chain");
    if (!nc)
        return false;
    struct block_index **old = c->chain;
    if (old_cap > 0)
        memcpy(nc, old, (size_t)old_cap * sizeof(struct block_index *));
    memset(&nc[old_cap], 0,
           (size_t)(new_cap - old_cap) * sizeof(struct block_index *));
    c->chain = nc;       /* publish fully-populated array first... */
    c->capacity = new_cap; /* ...then the wider bound */
    if (old) {
        struct active_chain_retired *r =
            zcl_malloc(sizeof(*r), "active_chain_retired");
        if (r) {
            r->arr = old;
            r->next = c->retired;
            c->retired = r;
        }
        /* On node-alloc failure: leak `old` — still reader-safe. */
    }
    return true;
}

/* Physically assemble chain[] so chain[bi->nHeight] == bi and every lower
 * slot holds the ancestor on bi's path (walking pprev), then set c->height
 * = bi->nHeight. This is the structural half of the active-chain window move;
 * the part every reader (active_chain_at, the stages) depends on. It never
 * publishes the authoritative tip; reducer/repair callers must do that
 * through their explicit authority API after their durable write succeeds.
 * Returns false only on an array-grow allocation failure (which LOG_FAILs).
 * Slots ABOVE new_height are left untouched (a later wider window can still
 * re-expose them).
 *
 * Writers serialize on c->write_lock; the grow retires-not-frees the old
 * array (active_chain_grow_locked above). height is published LAST — see
 * the reader-discipline comment above. */
static bool active_chain_fill_window(struct active_chain *c,
                                     struct block_index *bi)
{
    int new_height = bi->nHeight;
    zcl_mutex_lock(&c->write_lock);
    if (!active_chain_grow_locked(c, new_height)) {
        zcl_mutex_unlock(&c->write_lock);
        LOG_FAIL("chainstate", "active_chain_fill_window: alloc failed for height %d", new_height);
    }

    struct block_index **arr = c->chain; /* stable under write_lock */
    int old_height = c->height;
    arr[new_height] = bi;
    struct block_index *p = bi->pprev;
    int h = new_height - 1;
    int walk_budget = new_height + 1;
    while (h >= 0) {
        while (p && p->nHeight > h) {
            if (--walk_budget < 0) {
                p = NULL;
                break;
            }
            p = p->pprev;
        }
        struct block_index *slot = (p && p->nHeight == h) ? p : NULL;
        if (!slot && h <= old_height)
            break; /* preserve the finalized lower window across pprev gaps */
        if (h <= old_height && arr[h] == slot)
            break;
        arr[h] = slot;
        if (p && p->nHeight == h) {
            if (--walk_budget < 0)
                p = NULL;
            else
                p = p->pprev;
        }
        h--;
    }
    c->height = new_height; /* publish last */
    zcl_mutex_unlock(&c->write_lock);
    return true;
}

bool active_chain_move_window_tip(struct active_chain *c, struct block_index *bi)
{
    if (!bi) {
        if (!c)
            return false;
        zcl_mutex_lock(&c->write_lock);
        c->height = -1;
        zcl_mutex_unlock(&c->write_lock);
        return true;
    }

    /* Fail-loud validation pack, check 1: O(1) parent-linkage check + the
     * HOLD latch (refuses moves at/past a detected divergence; rewinds and
     * repair installs below it always pass). Refusal is crash-only — the
     * callers all handle false without killing the process. NOT applied to
     * active_chain_install_tip_slot (the boot/restore repair primitive,
     * intentionally ungated). */
    if (!chain_linkage_check_advance(c, bi))
        return false;

    if (!active_chain_fill_window(c, bi))
        return false;

    return true;
}

/* Install `bi` as chain[bi->nHeight] and publish the height WITHOUT the
 * ancestor walk of active_chain_move_window_tip — the boot/restore repair
 * primitive (callers rebuild and disk-validate the ancestry afterwards, so
 * pre-filling lower slots from pprev here would change what they verify).
 * Same writer contract as active_chain_fill_window: the grow retires (never
 * frees in place) the old array and publishes array -> capacity -> slot ->
 * height LAST, all under write_lock. Returns false only on grow allocation
 * failure or bad args (callers log context). */
bool active_chain_install_tip_slot(struct active_chain *c,
                                   struct block_index *bi)
{
    if (!c || !bi || bi->nHeight < 0)
        return false;
    zcl_mutex_lock(&c->write_lock);
    if (!active_chain_grow_locked(c, bi->nHeight)) {
        zcl_mutex_unlock(&c->write_lock);
        LOG_FAIL("chainstate", "active_chain_install_tip_slot: alloc failed for height %d", bi->nHeight);
    }
    struct block_index **arr = c->chain; /* stable under write_lock */
    arr[bi->nHeight] = bi;
    c->height = bi->nHeight; /* publish last */
    zcl_mutex_unlock(&c->write_lock);
    return true;
}

/* Extend the VISIBLE chain[] window forward to a most-work CANDIDATE that
 * builds on the current tip, WITHOUT moving the authoritative (finalized)
 * tip. This is the reducer's structural analogue of assembling chain[] out to
 * find_most_work_chain's candidate before a block-by-block validation pass.
 *
 * It exists because the reducer's tip_finalize uses a one-block lookahead:
 * it finalizes height H by reading active_chain_at(H+1), then collapses
 * c->height back to H via active_chain_move_window_tip(new_tip). Without a
 * separate window-extender, the lookahead for H+1 would never find H+2 and the
 * reducer would wedge after one block. Re-extending to the candidate each
 * tick keeps the lookahead supplied while the finalized tip advances under
 * it.
 *
 * Contract:
 *   - `candidate` MUST descend from (or equal) the current tip — the caller
 *     (a most-work selector that refuses below-tip candidates) guarantees
 *     this; we only assemble the path it names.
 *   - NEVER shrinks the window: if candidate->nHeight <= c->height this is a
 *     no-op (the finalized tip is the authority on retreat; window growth is
 *     monotonic forward between finalizations).
 *   - Does NOT publish authority — the finalized tip is owned by
 *     tip_finalize's explicit authority publication. This only widens what
 *     active_chain_at can see.
 * Returns true on success (incl. the no-op case), false only on realloc
 * failure (which LOG_FAILs upstream). */
bool active_chain_extend_window(struct active_chain *c,
                                struct block_index *candidate)
{
    if (!c || !candidate)
        return true;
    if (candidate->nHeight <= c->height)
        return true; /* monotonic forward only — never retreat the window */
    return active_chain_fill_window(c, candidate);
}

/* Resolve the object that actually HOLDS the body for `anc`'s block, merging
 * BLOCK_HAVE_DATA across same-hash duplicates. best_header's ancestry can
 * reference a DUPLICATE block_index that stayed bodiless while body_persist
 * release-published BLOCK_HAVE_DATA onto the block_map's canonical object for
 * the SAME hash (the live H+1 window wedge: the ancestry twin never gets the
 * bit, so a raw `anc->nStatus & BLOCK_HAVE_DATA` read no data and the walk
 * stopped one block short of a body-present successor). Return the body-bearing
 * object — `anc` itself when it carries the body, else the block_map entry for
 * anc's hash when THAT does — or NULL when neither does.
 *
 * This admits NOTHING unverified: `anc` is already on best_header's proven-
 * continuous ancestry (the caller's hash guard), and the twin is the SAME
 * consensus block (identical hash => identical hashPrevBlock and height); we
 * only recognize which copy the body landed on. A genuinely bodiless height (no
 * same-hash twin carries the body) still returns NULL and stops the walk, so a
 * header-only / missing-body successor is never exposed. */
static struct block_index *have_data_by_hash(struct block_map *m,
                                             struct block_index *anc)
{
    if (!anc)
        return NULL;
    if (block_index_status_load(anc) & BLOCK_HAVE_DATA)
        return anc;
    struct block_index *twin = m ? block_map_find(m, &anc->hashBlock) : NULL;
    if (!twin || twin == anc || twin->nHeight != anc->nHeight ||
        block_has_any_failure(twin) ||
        !(block_index_status_load(twin) & BLOCK_HAVE_DATA))
        return NULL;
    atomic_fetch_add_explicit(&g_window_dup_data_rescued, 1,
                              memory_order_relaxed);
    uint64_t reps = 0;
    if (log_throttle_should_emit(&g_dup_data_throttle, (uint64_t)anc->nHeight,
                                 platform_time_wall_unix(), 60, &reps))
        LOG_WARN("chainstate",
                 "window extend: bodiless best-header ancestry at height %d "
                 "rescued via same-hash block_map body twin (suppressed=%llu)",
                 anc->nHeight, (unsigned long long)reps);
    return twin;
}

/* Upper bound on how far a single anchored extend reaches above the window —
 * keeps the bounded map scan and the contiguity walk cheap. ~a few days of
 * blocks; the lookahead lead is normally a handful. */
#define ACTIVE_CHAIN_EXTEND_HAVE_DATA_MAX_GAP 8192

/* Forward-extend the visible window ONLY along the CONTIGUOUS have-data
 * frontier above the finalized tip, bounded by max_height (the caller passes
 * the best-known header height so every upstream stage can see its next block,
 * while the have-data gate keeps the window from ever exposing a header-only /
 * bodiless successor).
 *
 * The gate is BLOCK_HAVE_DATA, NOT BLOCK_VALID_SCRIPTS: the body-dependent
 * stages (body_fetch, body_persist, script_validate) each read
 * active_chain_at(their_cursor + 1) and MUST see a block that has a body but is
 * NOT yet script-validated — script validation is exactly what script_validate
 * is about to do to that very block. Requiring BLOCK_VALID_SCRIPTS here is a
 * chicken-and-egg: the window can't expose a block until it's validated, but it
 * can't be validated until the body stages (which read it through the window)
 * run -> the whole body-dependent pipeline goes JOB_IDLE and the tip never
 * advances. The have-data gate alone is the correct anti-bodiless-orphan guard;
 * per-stage validity is enforced by each stage on its own cursor, not by what
 * the window happens to expose.
 *
 * Unlike active_chain_extend_window(best_header / most-work candidate), this
 * CANNOT trigger the false-reorg cascade that wedged the chain when a generic
 * candidate was used: it walks UP from the window tip and accepts a successor
 * only when that successor's pprev is pointer-equal to the previously accepted
 * block. The candidate it finally fills to is therefore provably continuous
 * with the finalized chain, so active_chain_fill_window walks the SAME pprev
 * path back down and breaks exactly at c->height (where c->chain[c->height]
 * already equals the tip) — never overwriting a finalized slot with a divergent
 * fork. With finalized slots intact, finalized_row_active_match cannot
 * false-fire and rewind_cursor_if_active_chain_reorged stays quiet.
 *
 * No-op (and NO map scan) when there is no gap (max_height <= c->height).
 * Returns true (incl. no-op / OOM-skip); false only on a fill realloc failure
 * (which LOG_FAILs upstream). */
bool active_chain_extend_window_have_data(struct active_chain *c,
                                          struct block_map *m,
                                          struct block_index *best_header,
                                          int max_height)
{
    if (!c || !m || c->height < 0)
        return true;
    if (max_height <= c->height)
        return true; /* nothing persisted above the window — cheap no-op */

    /* The window's tip slot (chain[c->height]) can be NULL while c->height is a
     * valid finalized height: a blocks-less snapshot boot RETRACTS the window to
     * the seed (active_chain_move_window_tip) and then the boot's later
     * window/grow churn leaves chain[seed] empty, even though the AUTHORITY
     * (tip_finalize) still names that height as the finalized tip. The plain
     * active_chain_cached_tip() reads the raw slot and returns NULL → the extend
     * bails and the body-dependent fold starves at seed+1 forever (the
     * blocks-less starter-pack climb stall: win_slot=(nil), ua_cursor=seed+1
     * ok=0, tf_blocked=lookahead_tip_missing). active_chain_tip() instead
     * re-resolves the tip from the authority's finalized hash via the block map,
     * so it returns the real tip even when the slot is empty. Re-install it into
     * the slot so the subsequent fill walk + every active_chain_at(c->height)
     * downstream is coherent. SELF-HEAL only — never lowers the height, never
     * publishes authority, and is a no-op when the slot is already correct. */
    struct block_index *tip = active_chain_cached_tip(c);
    if (!tip) {
        tip = active_chain_tip(c);  /* authority-resolved, slot-independent */
        if (!tip || tip->nHeight != c->height)
            return true;            /* no coherent finalized tip to anchor on */
        (void)active_chain_install_tip_slot(c, tip);  /* repair chain[height] */
    }

    int lo = c->height + 1;
    int hi = max_height;
    if ((int64_t)hi - (int64_t)lo + 1 > ACTIVE_CHAIN_EXTEND_HAVE_DATA_MAX_GAP)
        hi = lo + ACTIVE_CHAIN_EXTEND_HAVE_DATA_MAX_GAP - 1;

    /* ── FAST PATH: walk best-header ancestry, no whole-map scan ──────────
     * The two block_map_next sweeps below (count + fill) visit ALL ~3.1M map
     * buckets per call, lock-guarded — ~9s/block during above-checkpoint
     * catch-up because the cheap early-out (max_height<=c->height) never fires
     * (callers pass pindex_best_header height ≫ the climbing finalized tip),
     * and the MAX_GAP clamp bounds only the height FILTER, not the scan. Same
     * full-scan-per-call pathology already fixed in block_successor.c.
     *
     * When the finalized tip is provably ON best_header's chain
     * (block_index_get_ancestor(best_header, c->height) == tip — the liveness
     * guard), the canonical contiguous successors ARE best_header's ancestors at
     * each height. So
     * have-data contiguity reduces to: walk h up from lo, stop at the first
     * ancestor lacking BLOCK_HAVE_DATA or carrying a failure; fill to the last
     * good. This is verdict-IDENTICAL to the pprev-walk below (ancestors are
     * pprev-contiguous by construction; forks are excluded since only
     * best_header's own ancestor at each height is consulted) — only the
     * TRAVERSAL changes, restoring 2*O(map) → O(log n + gap). A reorg where
     * best_header left the finalized tip fails the guard and falls through to
     * the slow scan, which handles it via the pprev-walk. Never publishes
     * authority (active_chain_fill_window); under-extension is a safe stall. */
    struct block_index *guard_anc =
        best_header ? block_index_get_ancestor(best_header, c->height) : NULL;
    if (best_header && best_header->nHeight >= lo && guard_anc && tip &&
        memcmp(guard_anc->hashBlock.data, tip->hashBlock.data, 32) == 0) {
        /* Liveness guard by BLOCK HASH, not pointer: best_header's ancestry at
         * the finalized height must be the SAME BLOCK as the tip (hash), but a
         * duplicate same-hash object must not defeat the fast-path ancestry walk
         * — that pointer mismatch is exactly the live 3162167 wedge. */
        /* Probe the immediate successor before walking the whole bounded
         * header band. During catch-up every reducer stage calls this helper,
         * while block ingress normally makes only the next few bodies visible.
         * If H+1 is still body-missing, no later height can be contiguous, so
         * 8 stages x 8192 ancestor/map probes is provably wasted work. The
         * same-hash lookup preserves the duplicate-object rescue contract. */
        struct block_index *next = block_index_get_ancestor(best_header, lo);
        struct block_index *cand = have_data_by_hash(m, next);
        if (!cand || block_has_any_failure(cand))
            return true;

        atomic_fetch_add_explicit(&g_window_extend_fast_hits, 1,
                                  memory_order_relaxed);

        /* Seek to the top of the bounded band ONCE, then materialize its
         * ancestry by following pprev. The former loop performed one skip-list
         * seek per height (up to 8192 seeks per reducer batch), even though all
         * requested heights are consecutive on the same ancestry. Besides
         * being needlessly expensive, that cost sat inside the UTXO stage and
         * obscured its actual apply time. A fixed-size stack buffer is bounded
         * by ACTIVE_CHAIN_EXTEND_HAVE_DATA_MAX_GAP (64 KiB on 64-bit hosts),
         * cannot OOM, and keeps this helper reentrant/thread-safe.
         *
         * Clamp to best_header: callers normally pass its height, but the old
         * per-height loop simply stopped when asked above it. Preserving that
         * behavior avoids turning a harmless over-large bound into an
         * under-extension. Any malformed/non-consecutive pprev chain remains a
         * safe no-op, just as a failed ancestor seek was before. */
        struct block_index *path[ACTIVE_CHAIN_EXTEND_HAVE_DATA_MAX_GAP];
        int path_hi = hi;
        if (path_hi > best_header->nHeight)
            path_hi = best_header->nHeight;
        int path_len = path_hi - lo + 1;
        struct block_index *walk =
            block_index_get_ancestor(best_header, path_hi);
        for (int i = path_len - 1; i >= 0; i--) {
            if (!walk || walk->nHeight != lo + i)
                return true;
            path[i] = walk;
            walk = walk->pprev;
        }

        for (int i = 1; i < path_len; i++) {
            struct block_index *anc = path[i];
            if (!anc || block_has_any_failure(anc))
                break;
            /* Merge BLOCK_HAVE_DATA across same-hash duplicates: a bodiless
             * ancestry twin whose block_map body copy exists must not stop the
             * walk one block short. Fill with the body-bearing object so every
             * body-dependent stage reading active_chain_at(h) sees the body. */
            struct block_index *have = have_data_by_hash(m, anc);
            if (!have)
                break;
            cand = have;
        }
        return active_chain_fill_window(c, cand);
    }

    /* ── SLOW PATH (fallback): best_header absent / below the window / off the
     * finalized chain (reorg). Full-map scan + pprev-walk — the original, proven
     * logic, exercised by the test suite with best_header=NULL. ── */
    atomic_fetch_add_explicit(&g_window_extend_slow_hits, 1,
                              memory_order_relaxed);

    /* Collect eligible (have-data, failure-free) block_index entries in
     * (c->height, hi]. NOT gated on BLOCK_VALID_SCRIPTS — see the function
     * comment: the body stages must see a have-data block BEFORE it is
     * script-validated.
     *
     * The buffer is sized by a COUNT pass, not by `span = hi - lo + 1`: the map
     * can hold MORE than one block_index at a given height (competing branches /
     * forks within the gap window), so the count of in-range eligible entries
     * legitimately exceeds the number of distinct heights. Sizing by `span`
     * here was a heap overflow — `elig[n++]` ran past the allocation as soon as
     * any forked sibling fell inside [lo, hi] (the reorg the forward-progress
     * gate's PART 2 exercises). Count first, then fill exactly. */
    int n_eligible = 0;
    {
        size_t iter0 = 0;
        struct block_index *q = NULL;
        while (block_map_next(m, &iter0, NULL, &q)) {
            if (!q)
                continue;
            int h = q->nHeight;
            if (h < lo || h > hi)
                continue;
            if (block_has_any_failure(q))
                continue;
            if (!(q->nStatus & BLOCK_HAVE_DATA))
                continue;
            n_eligible++;
        }
    }
    if (n_eligible == 0)
        return true; /* no have-data successor in range — leave window as-is */

    struct block_index **elig =
        zcl_malloc((size_t)n_eligible * sizeof(*elig), "achd_elig");
    if (!elig)
        return true; /* OOM -> no extension (safe; never a partial window) */
    int n = 0;
    size_t iter = 0;
    struct block_index *p = NULL;
    while (block_map_next(m, &iter, NULL, &p)) {
        if (!p)
            continue;
        int h = p->nHeight;
        if (h < lo || h > hi)
            continue;
        if (block_has_any_failure(p))
            continue;
        if (!(p->nStatus & BLOCK_HAVE_DATA))
            continue;
        if (n >= n_eligible)
            break; /* defensive: map cannot grow between the two passes here */
        elig[n++] = p;
    }

    /* Walk UP from the finalized tip, accepting the eligible child whose parent
     * is the last accepted block BY BLOCK HASH (not by pointer). Contiguity is a
     * CONSENSUS property — child.hashPrevBlock == parent.GetBlockHash() — so the
     * test must be hash identity, not in-RAM object identity. A duplicate
     * block_index object for the same hash (e.g. a tip slot installed from a
     * snapshot seed vs the object header-ingest links pprev to) has a DIFFERENT
     * pointer but the SAME hash; a pointer compare wrongly rejected it and wedged
     * the forward fold at a body-present successor (live 3162167). Hash equality
     * is a strict superset of the old pointer test (same object => same hash) and
     * still skips real forks (different parent hash). */
    struct block_index *cand = tip;
    bool advanced = true;
    while (advanced) {
        advanced = false;
        for (int i = 0; i < n; i++) {
            struct block_index *ch = elig[i];
            if (ch && ch->pprev &&
                memcmp(ch->pprev->hashBlock.data, cand->hashBlock.data, 32) == 0 &&
                ch->nHeight == cand->nHeight + 1) {
                cand = ch;
                advanced = true;
                break;
            }
        }
    }
    free(elig);

    if (cand == tip || cand->nHeight <= c->height)
        return true; /* no contiguous have-data successor — leave window as-is */

    return active_chain_fill_window(c, cand);
}

/* LANE D / SELF-HEAL (S3 sibling-adopt) — does eligible candidate `cand` beat
 * the running `best` for chain selection, given the active chain `c`?
 *
 * Default rule (unchanged): strictly MORE nChainWork wins. Two VALID equal-work
 * siblings therefore never oscillate — the strict `>` keeps the incumbent.
 *
 * Self-heal extension: when the active-chain INCUMBENT at the candidate's own
 * height EXISTS and is FAILED (BLOCK_FAILED_VALID/FAILED_CHILD/TRANSIENT), an
 * EQUAL-work, non-failed candidate is allowed to win. This is exactly the
 * zeroed-Sapling-root wedge (live 3157647): the incumbent at height H folded
 * ok=0 and was marked FAILED_VALID; its canonical equal-work sibling carries the
 * SAME nChainWork, so the strict `>` rule would never select it and the chain
 * would wedge below H forever. cand itself is already known non-failed and
 * eligible (the caller filters block_has_any_failure / BLOCK_VALID_TREE / data
 * before calling this). This is a NODE-LOCAL selection policy over our own
 * block-index status — NOT a consensus rule (which block is valid is unchanged;
 * only WHICH of two equal-work valid candidates we activate when the incumbent
 * is locally failed). Parity-restoring: matches zclassicd invalidateblock +
 * FindMostWorkChain (a FAILED incumbent is not a valid tip).
 *
 * Scoped deliberately to a PRESENT, FAILED same-height incumbent — never an
 * absent one — so it cannot drift the normal forward path: a higher-height
 * candidate already carries strictly more cumulative work (cmp > 0) and wins
 * via the unchanged strict rule, and an absent slot is left to that strict
 * rule. So the only new selection this enables is the failed-sibling swap. */
bool active_chain_selection_candidate_beats_best(
        const struct active_chain *c,
        const struct block_index *cand,
        const struct block_index *best)
{
    if (!cand)
        return false;
    if (!best)
        return true;
    int cmp = arith_uint256_compare(&cand->nChainWork, &best->nChainWork);
    if (cmp > 0)
        return true;
    if (cmp < 0 || !c)
        return false;
    /* Equal work: adopt ONLY when a DIFFERENT, FAILED incumbent currently
     * occupies the active-chain slot at cand's height (otherwise keep the
     * incumbent — strict `>` semantics preserved). */
    struct block_index *incumbent =
        active_chain_at((struct active_chain *)c, cand->nHeight);
    if (!incumbent || incumbent == cand)
        return false;
    return block_has_any_failure(incumbent);
}

struct block_index *select_most_work_eligible(
        struct active_chain *c,
        struct block_map *m,
        struct most_work_selection_stats *stats)
{
    if (!c || !m)
        return NULL;
    if (stats) {
        memset(stats, 0, sizeof(*stats));
        stats->refused_below_tip_height = -1;
        stats->refused_below_tip_tip_height = -1;
    }

    struct block_index *tip = active_chain_tip(c);
    struct block_index *best = tip;

    size_t iter = 0;
    struct block_index *pindex = NULL;
    while (block_map_next(m, &iter, NULL, &pindex)) {
        if (!pindex)
            continue;
        if (block_has_any_failure(pindex)) {
            if (stats) stats->skipped_failed++;
            continue;
        }
        if (!block_index_is_valid(pindex, BLOCK_VALID_TREE)) {
            if (stats) stats->skipped_invalid++;
            continue;
        }
        if (pindex->nChainTx == 0 && !(pindex->nStatus & BLOCK_HAVE_DATA)) {
            if (stats) stats->skipped_no_chaintx++;
            continue;
        }

        if (active_chain_selection_candidate_beats_best(c, pindex, best)) {
            /* Ancestry must be failure-free up to the current best/tip. */
            bool chain_ok = true;
            struct block_index *check = pindex;
            int floor_h = best ? best->nHeight : -1;
            while (check && check->nHeight > floor_h) {
                if (block_has_any_failure(check)) {
                    chain_ok = false;
                    break;
                }
                if (!check->pprev && check->nHeight > 0)
                    break; /* pprev unlinked (post-import) — stop, accept */
                check = check->pprev;
            }
            if (chain_ok) {
                best = pindex;
            } else if (stats) {
                stats->skipped_bad_ancestry++;
            }
        }
    }

    /* Refuse a candidate strictly BELOW the current tip — the tip is
     * canonical (matches find_most_work_chain's stale-fork guard). The
     * window only ever grows forward; a lower-height higher-work fork is
     * never selected here. */
    if (tip && best && best != tip && best->nHeight < tip->nHeight) {
        if (stats) {
            stats->refused_below_tip = true;
            stats->refused_below_tip_height = best->nHeight;
            stats->refused_below_tip_tip_height = tip->nHeight;
        }
        return tip;
    }

    return best;
}

struct block_index *active_chain_most_work_candidate(struct active_chain *c,
                                                      struct block_map *m)
{
    return select_most_work_eligible(c, m, NULL);
}

int active_chain_height(const struct active_chain *c)
{
    if (!c) return -1;
    if (g_chain_authority.is_authoritative &&
        g_chain_authority.get_height &&
        g_chain_authority.is_authoritative()) {
        int64_t ah = g_chain_authority.get_height();
        if (ah >= 0) return (int)ah;
        return -1;
    }

    sqlite3 *db = progress_store_db();
    if (!db) return c->height;
    progress_store_tx_lock();
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db, "SELECT MAX(height) FROM tip_finalize_log WHERE ok = 1", -1, &st, NULL) != SQLITE_OK) {
        progress_store_tx_unlock();
        return c->height;
    }
    int h = -1;
    int rc = sqlite3_step(st);  // raw-sql-ok:kernel-primitive
    if (rc == SQLITE_ROW && sqlite3_column_type(st, 0) != SQLITE_NULL) {
        h = sqlite3_column_int(st, 0);
    }
    sqlite3_finalize(st);
    progress_store_tx_unlock();
    if (h > c->height) return h;
    return c->height;
}

/* --- Chainstate --- */

void chainstate_init(struct chainstate *cs)
{
    zcl_mutex_init(&cs->cs_main);
    block_map_init(&cs->map_block_index);
    active_chain_init(&cs->chain_active);
    cs->pindex_best_header = NULL;
    cs->f_tx_index = false;
    cs->f_reindex = false;
    cs->f_importing = false;
    cs->f_have_pruned = false;
    cs->f_prune_mode = false;
    cs->n_prune_target = 0;
}

void chainstate_free(struct chainstate *cs)
{
    active_chain_free(&cs->chain_active);
    block_map_free(&cs->map_block_index);
    zcl_mutex_destroy(&cs->cs_main);
}

struct block_index *chainstate_insert_block_index(struct chainstate *cs,
                                                   const struct uint256 *hash)
{
    if (!hash)
        return NULL; /* NULL-guard before uint256_is_null derefs it */
    if (uint256_is_null(hash))
        return NULL;

    struct block_index *existing = block_map_find(&cs->map_block_index, hash);
    if (existing) return existing;

    struct block_index *bi = zcl_calloc(1, sizeof(struct block_index), "block_index");
    if (!bi) return NULL;
    block_index_init(bi);
    /* Option A: stable per-node storage for the hash. Write hashBlock
     * BEFORE publishing the node into the map, then point phashBlock
     * at it. Lock-free readers that reach this node via pprev only ever
     * deref *phashBlock (the value), which is never-freed and written
     * exactly once here, so they can never observe a torn/dangling hash. */
    bi->hashBlock = *hash;
    bi->phashBlock = &bi->hashBlock;
    block_map_insert(&cs->map_block_index, hash, bi);
    return bi;
}
