/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * block_parse_cache — a bounded direct-mapped ring of parsed immutable block
 * bodies, keyed by (height, block_hash).
 *
 * WHY: the five staged-sync stages (body_persist, script_validate,
 * proof_validate, utxo_apply, tip_finalize_post_step) each independently
 * pread + deserialize the SAME on-disk block body for the height they are
 * processing — five full disk reads + five full deserializations per block.
 * Deserialization (compact-size parse of every tx, every input/output script,
 * every JoinSplit, every Sapling spend/output bundle) dominates the fold's
 * CPU outside crypto. body_persist is the producer (it advances first), so by
 * the time the four downstream stages reach the same height the body is in
 * cache and converted stages borrow the same immutable parsed object instead
 * of re-reading, re-parsing, or deep-cloning it.
 *
 * KEY = (height, block_hash). The hash component is load-bearing: an in-memory
 * header relabel / reorg can put a DIFFERENT block at the same height, and a
 * height-only key would then serve a stale body. A (height,hash) miss falls
 * back to read_block_from_disk_pread off the supplied block_index.
 *
 * RESULT-PRESERVING: a borrowed pointer is valid only while its generation-
 * tagged handle is pinned. Eviction skips pinned entries and no cache lock is
 * held during downstream work. The legacy get API still returns an independent
 * deep clone for consumers that have not yet adopted the handle contract.
 */
#ifndef STORAGE_BLOCK_PARSE_CACHE_H
#define STORAGE_BLOCK_PARSE_CACHE_H

#include <stdbool.h>
#include <stdint.h>

struct block;
struct block_index;

struct block_parse_handle {
    const struct block *block;
    void *entry;
    uint64_t generation;
    bool detached;
    bool cache_hit;
    uint32_t lookup_probes;
    uint64_t lock_wait_us;
    uint64_t disk_read_us;
    uint64_t parse_us;
};

/* Cache capacity: the number of (height,hash) -> parsed-body slots. Must be
 * >= the refold batch size (currently 2000) so a full batch of bodies
 * survives across all five staged-sync consumers (body_persist,
 * script_validate, proof_validate, utxo_apply, tip_finalize_post_step)
 * without body_persist's own writes evicting entries the later stages in
 * the SAME batch still need to read — see block_parse_cache.c for the full
 * rationale. Exported here (rather than left as a private .c constant) so
 * every capacity-sensitive caller, including tests, derives it instead of
 * hardcoding a duplicate that can silently drift out of sync. */
#define BLOCK_PARSE_CACHE_CAPACITY 2048

/* Pin one immutable parsed body. A hit is a borrowed view of the resident
 * body, not a clone. The pointer returned by block_parse_handle_block is valid
 * only until the matching release. */
bool block_parse_cache_acquire(int32_t height, const uint8_t block_hash[32],
                               const struct block_index *bi,
                               const char *datadir,
                               struct block_parse_handle *out);
const struct block *block_parse_handle_block(
    const struct block_parse_handle *handle);
void block_parse_cache_release(struct block_parse_handle *handle);

/* Fetch the block body for (height, block_hash) into `out` (which the caller
 * MUST have block_init'd) as an independent deep copy the caller owns and frees
 * with block_free. On a cache miss the body is read from disk via
 * read_block_from_disk_pread off `bi` (HAVE_DATA guarded inside the reader),
 * the parsed body is retained in the cache, and a deep copy is returned. The
 * `bi`/`datadir` arguments are exactly the ones the default reader uses; `bi`
 * supplies both the disk position (on miss) and is the source of `block_hash`
 * the caller passes for the key.
 *
 * Returns true on success (out is a complete clone). Returns false on a read or
 * clone failure, leaving `out` safe to block_free (it may have been partially
 * built and is left in a free-able state). Matches the success/failure contract
 * of stage_default_block_reader so call sites swap with no logic change. */
bool block_parse_cache_get(int32_t height, const uint8_t block_hash[32],
                           const struct block_index *bi, const char *datadir,
                           struct block *out);

/* Drop all cached entries (e.g. on shutdown or a full reindex). Safe to call
 * with an empty cache. */
void block_parse_cache_clear(void);

/* Segment-vs-blk*.dat read source counters — proves the sealed-segment
 * substrate is actually being used by the fold. Counted once per MISS-path
 * body fetch (the LRU-hit path never touches either source, so it is
 * intentionally excluded): `*segment_hits` is incremented when the body was
 * served from a sealed, hash-verified segment; `*blkdat_reads` is
 * incremented when it fell through to the ordinary blk*.dat pread (no
 * covering segment, or the segment source declined). Either pointer may be
 * NULL to skip that output. Reentrant-safe (atomic loads). */
void block_parse_cache_segment_read_stats(uint64_t *segment_hits,
                                          uint64_t *blkdat_reads);

/* Remove exactly the (height, hash) entry if present; a no-op if it isn't
 * cached (or hash is NULL). Call this from a stage's OWN post-read
 * verification failure (hash mismatch, merkle mismatch, etc.) on a body that
 * came through this cache, so a poisoned or now-stale slot can never be
 * served again — the next block_parse_cache_get() for the same key is
 * forced back to a genuine disk/segment read. block_parse_cache_get() itself
 * already verifies a body's hash before ever installing it (see the MISS
 * path in block_parse_cache.c), so this is defense-in-depth / an explicit
 * self-healing hook for callers, not the only thing preventing poisoning. */
void block_parse_cache_evict(int32_t height, const uint8_t hash[32]);

#endif /* STORAGE_BLOCK_PARSE_CACHE_H */
