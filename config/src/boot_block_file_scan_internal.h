/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Purpose: the block-file scan's private cross-TU contract — the parsed
 * per-block metadata record, the per-file parse result, the per-file apply
 * tally, and the apply entry point.
 *
 * boot_block_file_scan.c owns the blk*.dat PARSE half (magic walk, header
 * deserialize, the worker pool) and drives the scan;
 * boot_block_index_apply.c owns the APPLY half (create or repair the
 * block_index entry, mark BLOCK_HAVE_DATA, link pprev, accumulate chain
 * work). The split happened when the combined file passed the 800-line
 * shape ceiling. These three structs and one function are all that crosses
 * that seam, so they live here and nowhere else — nothing outside those two
 * translation units may include this header.
 */

#ifndef ZCL_CONFIG_BOOT_BLOCK_FILE_SCAN_INTERNAL_H
#define ZCL_CONFIG_BOOT_BLOCK_FILE_SCAN_INTERNAL_H

#include "core/uint256.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct main_state;
struct chain_params;

struct boot_scan_block_meta {
    struct uint256 hash;
    struct uint256 hashPrevBlock;
    struct uint256 hashMerkleRoot;
    struct uint256 hashFinalSaplingRoot;
    struct uint256 nNonce;
    int32_t nVersion;
    uint32_t nTime;
    uint32_t nBits;
    unsigned int nTx;
    unsigned int nDataPos;
};

struct boot_scan_file_result {
    char path[576];
    int file_idx;
    long file_size;
    struct boot_scan_block_meta *blocks;
    size_t count;
    size_t cap;
    int skipped;
    int corrupt;
    bool ok;
};

struct boot_scan_apply_counts {
    int marked;
    int created;
    int header_fixed;
};

/* Apply one file's parsed metadata to the in-memory block index: create
 * missing entries (only when `params` is present), repair zeroed headers,
 * link pprev, and mark BLOCK_HAVE_DATA with the earliest on-disk position.
 * Idempotent — the scan calls it again on its retry passes. Defined in
 * config/src/boot_block_index_apply.c. */
struct boot_scan_apply_counts scan_apply_one_file(
    struct main_state *ms,
    const struct boot_scan_file_result *r,
    const struct chain_params *params);

#endif /* ZCL_CONFIG_BOOT_BLOCK_FILE_SCAN_INTERNAL_H */
