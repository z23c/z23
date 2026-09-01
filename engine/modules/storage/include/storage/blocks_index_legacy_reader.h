/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * blocks_index_legacy_reader: read a Bitcoin Core / zclassicd
 * `blocks/index/` LevelDB and produce a height-indexed array of
 * (hash, prev, file, datapos, ...) for the selected chain.
 *
 * Feeds the direct-import fast-sync mode in legacy_bootstrap_importer.c:
 * once we know each height's on-disk location in zclassicd's blk*.dat files,
 * we mmap and ingest with zero JSON-RPC overhead.
 *
 * Open is exclusive; if zclassicd holds the LevelDB LOCK, open fails.
 * Operator must briefly stop zclassicd, or pre-snapshot the directory.
 */

#ifndef ZCL_STORAGE_BLOCKS_INDEX_LEGACY_READER_H
#define ZCL_STORAGE_BLOCKS_INDEX_LEGACY_READER_H

#include "core/uint256.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

struct legacy_block_loc {
    struct uint256 hash;
    struct uint256 hashPrev;
    int32_t  height;       /* set; -1 means slot empty (no block at h) */
    int32_t  nFile;
    uint32_t nDataPos;
    uint32_t nUndoPos;
    uint32_t nStatus;
};

struct bilr;

/* Open zclassicd's blocks/index/ LevelDB. On success returns true and
 * stores an opaque handle in *out. On failure (most commonly: LOCK
 * held by a running zclassicd) returns false; caller logs.
 * `blocks_index_dir` is the .../blocks/index path. */
bool bilr_open(const char *blocks_index_dir, struct bilr **out);

void bilr_close(struct bilr *r);

/* Iterate every 'b'-prefixed record and resolve the selected chain by
 * walking hashPrev backward from tip_hash. On return: *out_array is a
 * height-indexed array of length *out_count (= max_height + 1). Slots
 * outside the selected chain have `height = -1`. Caller frees with
 * `bilr_free_height_map`. Returns false on iterator / deserialization
 * failure or when the tip chain cannot be resolved. */
bool bilr_load_height_map_for_tip(struct bilr *r,
                                  const struct uint256 *tip_hash,
                                  struct legacy_block_loc **out_array,
                                  size_t *out_count);

/* Backward-compatible helper that anchors at the highest usable block
 * when the caller has no chainstate best-block hash. Cold-import should
 * prefer bilr_load_height_map_for_tip(). */
bool bilr_load_height_map(struct bilr *r,
                          struct legacy_block_loc **out_array,
                          size_t *out_count);

void bilr_free_height_map(struct legacy_block_loc *array);

#ifdef __cplusplus
}
#endif

#endif /* ZCL_STORAGE_BLOCKS_INDEX_LEGACY_READER_H */
