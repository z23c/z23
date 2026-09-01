/* Copyright (c) 2009-2010 Satoshi Nakamoto
 * Copyright (c) 2009-2014 The Bitcoin Core developers
 * Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. */

#ifndef ZCL_VALIDATION_CHAINSTATE_H
#define ZCL_VALIDATION_CHAINSTATE_H

#include "chain/chain.h"
#include <pthread.h>
#include "core/uint256.h"
#include "util/sync.h"
#include <stdbool.h>
#include <stdint.h>

#define MAX_BLOCK_MAP_SIZE 2000000
#define MAX_CHAIN_HEIGHT 2000000

struct block_file_info {
    unsigned int nBlocks;
    unsigned int nSize;
    unsigned int nUndoSize;
    unsigned int nHeightFirst;
    unsigned int nHeightLast;
    uint64_t nTimeFirst;
    uint64_t nTimeLast;
};

static inline void block_file_info_init(struct block_file_info *fi)
{
    memset(fi, 0, sizeof(*fi));
}

static inline void block_file_info_add_block(struct block_file_info *fi,
                                              unsigned int height,
                                              uint64_t block_time)
{
    if (fi->nBlocks == 0 || fi->nHeightFirst > height)
        fi->nHeightFirst = height;
    if (fi->nBlocks == 0 || fi->nTimeFirst > block_time)
        fi->nTimeFirst = block_time;
    fi->nBlocks++;
    if (height > fi->nHeightLast)
        fi->nHeightLast = height;
    if (block_time > fi->nTimeLast)
        fi->nTimeLast = block_time;
}

struct disk_tx_pos {
    struct disk_block_pos block_pos;
    unsigned int nTxOffset;
};

static inline void disk_tx_pos_init(struct disk_tx_pos *p)
{
    disk_block_pos_init(&p->block_pos);
    p->nTxOffset = 0;
}

struct block_map_entry {
    struct uint256 hash;
    struct block_index *index;
    bool occupied;
};

struct block_map {
    struct block_map_entry *buckets;
    size_t size;
    size_t capacity;
    pthread_rwlock_t rwlock;
};

void block_map_init(struct block_map *m);
void block_map_free(struct block_map *m);
struct block_index *block_map_find(const struct block_map *m,
                                    const struct uint256 *hash);
bool block_map_insert(struct block_map *m, const struct uint256 *hash,
                      struct block_index *index);
bool block_map_reserve(struct block_map *m, size_t expected_count);
size_t block_map_count(const struct block_map *m);

/* Iteration: call with *iter=0, returns false when done */
bool block_map_next(const struct block_map *m, size_t *iter,
                    const struct uint256 **hash_out,
                    struct block_index **index_out);

/* Copy every currently published index pointer under one read-lock lease.
 *
 * block_map_next() is the right API for short or interruptible walks, but a
 * whole-map pass through a multi-million-entry index otherwise pays one
 * pthread rwlock transition per occupied bucket.  On Windows winpthreads
 * implements the contended release path with a kernel event, turning an O(N)
 * memory walk into minutes of SetEvent traffic.  This snapshot pays exactly
 * one lock/unlock pair and returns process-lifetime block_index pointers; the
 * caller owns only the pointer array and must free() it.
 *
 * Concurrent inserts after the snapshot are intentionally absent.  Callers
 * that require a stable structural view must retain their existing owner lock
 * (normally main_state.cs_main) while taking and consuming the snapshot. */
bool block_map_snapshot_indices(const struct block_map *m,
                                struct block_index ***indices_out,
                                size_t *count_out);

/* A chain[] array superseded by a window grow. Lock-free readers may still
 * hold the old pointer, so it is RETIRED (kept allocated, value-stable —
 * same discipline as block_index.hashBlock) and freed only by
 * active_chain_free. */
struct active_chain_retired {
    struct active_chain_retired *next;
    struct block_index **arr;
};

/* One writer-lock snapshot of the raw active-chain window.  This deliberately
 * does not consult the reducer's served-tip authority: `tip` is chain[height],
 * and `requested` is chain[requested_height].  Block-index objects and retired
 * arrays have process lifetime, so the returned pointers remain readable after
 * the short lock is released. */
struct active_chain_window_snapshot {
    int height;
    int requested_height;
    struct block_index *tip;
    struct block_index *requested;
};

/* Concurrency contract: readers are lock-free. `chain`, `height` and
 * `capacity` are _Atomic; writers publish a grow as fully-populated array,
 * then capacity, then height LAST, so a reader that bounds-checks against
 * height/capacity and loads `chain` afterwards always sees an array that
 * spans its index, and a reader holding an older array only ever indexes
 * within that array's (smaller) span. Slot stores stay plain aligned
 * pointer writes (a racing reader sees the old or new block_index, both
 * never-freed). Writers serialize on `write_lock` — a leaf lock; nothing
 * else is acquired while it is held. */
struct active_chain {
    struct block_index **_Atomic chain;
    _Atomic int height;
    _Atomic int capacity;
    struct active_chain_retired *retired; /* guarded by write_lock */
    zcl_mutex_t write_lock;
};

void active_chain_init(struct active_chain *c);
void active_chain_free(struct active_chain *c);
struct block_index *active_chain_cached_tip(const struct active_chain *c);
/* Raw derived cache/window bound; unlike active_chain_height(), never resolves
 * finalized authority. Used only to bound lookahead-cache work. */
int active_chain_cached_height(const struct active_chain *c);
struct block_index *active_chain_tip(const struct active_chain *c);
struct block_index *active_chain_at(const struct active_chain *c, int height);
bool active_chain_capture_window(struct active_chain *c,
                                 int requested_height,
                                 struct active_chain_window_snapshot *out);
bool active_chain_contains(const struct active_chain *c,
                           const struct block_index *bi);
/* Move the in-memory active-chain cache/window. This is not public tip
 * authority; reducer stages and explicit repair/bootstrap APIs publish
 * authority separately after their durable writes succeed. */
bool active_chain_move_window_tip(struct active_chain *c,
                                  struct block_index *bi);
/* Install `bi` as chain[bi->nHeight] and publish the height WITHOUT the
 * ancestor walk of active_chain_move_window_tip — the boot/restore repair
 * primitive (callers rebuild + disk-validate ancestry afterwards). The grow
 * follows the retire-not-free contract; height publishes LAST under
 * write_lock. Returns false only on grow allocation failure or bad args.
 * See chainstate.c. */
bool active_chain_install_tip_slot(struct active_chain *c,
                                   struct block_index *bi);
/* Forward-only widen of the visible chain[] window to a most-work candidate
 * that builds on the current tip, WITHOUT publishing an authoritative tip.
 * The reducer's structural analogue of assembling chain[] out to
 * find_most_work_chain's candidate. No-op when
 * candidate->nHeight <= c->height. See chainstate.c. */
bool active_chain_extend_window(struct active_chain *c,
                                struct block_index *candidate);
/* Forward-extend the window along the CONTIGUOUS have-data, script-validated
 * frontier above the finalized tip, bounded by max_height (caller passes the
 * utxo_apply cursor). Safe for tip_finalize's lookahead: it accepts a successor
 * only when its pprev is pointer-equal to the prior accepted block, so it never
 * exposes header-only/forked blocks and never overwrites a finalized slot (so
 * it cannot trigger the finalized-row false-reorg cascade a generic candidate
 * caused). No-op (no map scan) when max_height <= the window height.
 * See chainstate.c. */
bool active_chain_extend_window_have_data(struct active_chain *c,
                                          struct block_map *m,
                                          struct block_index *best_header,
                                          int max_height);
/* S5 observability: cumulative hit counts for the two traversal strategies
 * inside active_chain_extend_window_have_data — the O(log n + bounded gap)
 * best-header ancestry FAST path vs the O(map) full-scan+pprev-walk SLOW path
 * (fires only
 * when best_header is NULL/behind/off the finalized chain). A live node that
 * starts climbing on the slow path is a silent regression back to the fixed
 * ~9s/block full-map-scan pathology (commit b1c47d1d9) — these counters make
 * that regression visible via `zclassic23 dumpstate reducer_frontier`
 * (window_extend_fast / window_extend_slow) instead of only inferrable from a
 * throughput drop. Atomic: incremented from the reducer drive thread, read
 * from any diagnostics thread. See chainstate.c. */
uint64_t active_chain_extend_window_have_data_fast_count(void);
uint64_t active_chain_extend_window_have_data_slow_count(void);
/* Cumulative count of heights the fast path rescued by merging BLOCK_HAVE_DATA
 * across same-hash duplicates: best_header's ancestry object at a height was
 * bodiless but the block_map's canonical same-hash object carried the body, so
 * the walk fills with the body twin instead of stopping short (the live H+1
 * duplicate-object window wedge). Surfaced as `window_dup_data_rescued` via
 * `zclassic23 dumpstate reducer_frontier`. Same atomic contract as the counts
 * above. See chainstate.c have_data_by_hash. */
uint64_t active_chain_extend_window_dup_data_rescued_count(void);
struct most_work_selection_stats {
    int skipped_no_chaintx;
    int skipped_failed;
    int skipped_invalid;
    int skipped_bad_ancestry;
    bool refused_below_tip;
    int refused_below_tip_height;
    int refused_below_tip_tip_height;
};

/* Side-effect-free most-work candidate selector over the block map. This is the
 * shared eligibility/tie-break implementation used by
 * active_chain_most_work_candidate() and find_most_work_chain(): failure-free,
 * >= VALID_TREE, has data, clean ancestry, failed-incumbent equal-work
 * adoption, and below-tip refusal. Callers that need diagnostics pass `stats`;
 * callers with side effects keep them outside this pure selector. Returns the
 * current tip when no heavier eligible candidate exists, or NULL only on NULL
 * args. See chainstate.c. */
struct block_index *select_most_work_eligible(
        struct active_chain *c,
        struct block_map *m,
        struct most_work_selection_stats *stats);

/* Side-effect-free most-work candidate selector over the block map, using
 * select_most_work_eligible() without stats. Used by the reducer's
 * window-extender; carries none of find_most_work_chain's gap-fill/logging
 * side effects so it is safe to call every stage tick. See chainstate.c. */
struct block_index *active_chain_most_work_candidate(struct active_chain *c,
                                                      struct block_map *m);

/* LANE D / SELF-HEAL (S3 sibling-adopt) selection policy, shared by both
 * most-work selectors (active_chain_most_work_candidate + find_most_work_chain)
 * so the equal-work-when-incumbent-FAILED rule lives at exactly one site.
 * Returns true iff `cand` should replace the running `best`: strictly-more-work
 * always wins (unchanged); EQUAL work wins ONLY when the active-chain incumbent
 * at cand's height is PRESENT and FAILED (the zeroed-Sapling-root / corrupt-
 * incumbent self-heal, e.g. live 3157647). `cand` must already be a failure-
 * free, eligible candidate (callers filter that first). Pure / read-only over
 * our OWN block-index status — node-local policy, NOT a consensus rule (which
 * block is valid is unchanged; only WHICH of two equal-work valid candidates we
 * activate when the incumbent is locally FAILED). See chainstate.c. */
bool active_chain_selection_candidate_beats_best(
        const struct active_chain *c,
        const struct block_index *cand,
        const struct block_index *best);

int active_chain_height(const struct active_chain *c);

struct active_chain_authority {
    int64_t (*get_height)(void);
    bool    (*get_hash)(uint8_t hash[32]);
    bool    (*is_authoritative)(void);
};

void active_chain_register_authority(const struct active_chain_authority *auth);
void active_chain_register_block_map(struct block_map *m);

struct chainstate {
    zcl_mutex_t cs_main;
    struct block_map map_block_index;
    struct active_chain chain_active;
    struct block_index *pindex_best_header;
    bool f_tx_index;
    bool f_reindex;
    bool f_importing;
    bool f_have_pruned;
    bool f_prune_mode;
    uint64_t n_prune_target;
};

void chainstate_init(struct chainstate *cs);
void chainstate_free(struct chainstate *cs);

struct block_index *chainstate_insert_block_index(struct chainstate *cs,
                                                   const struct uint256 *hash);

#endif
