/* Copyright (c) 2009-2010 Satoshi Nakamoto
 * Copyright (c) 2009-2014 The Bitcoin Core developers
 * Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. */

#ifndef ZCL_CHAIN_H
#define ZCL_CHAIN_H

#include "core/arith_uint256.h"
#include "primitives/block.h"
#include "core/uint256.h"
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define SPROUT_VALUE_VERSION 1001400
#define SAPLING_VALUE_VERSION 1010100

enum block_status {
    BLOCK_VALID_UNKNOWN      = 0,
    BLOCK_VALID_HEADER       = 1,
    BLOCK_VALID_TREE         = 2,
    BLOCK_VALID_TRANSACTIONS = 3,
    BLOCK_VALID_CHAIN        = 4,
    BLOCK_VALID_SCRIPTS      = 5,
    BLOCK_VALID_MASK         = 7,
    BLOCK_HAVE_DATA          = 8,
    BLOCK_HAVE_UNDO          = 16,
    BLOCK_HAVE_MASK          = 24,
    /* Three-class typed failure model.
     *
     *   VALID  = PERMANENT consensus reject. Bad PoW, bad signature,
     *            failed proof, malformed block. Only the consensus-scope
     *            retry path may legitimately clear this. See
     *            process_block_core.c:973 (rate-limited near-tip retry).
     *
     *   CHILD  = DEPENDENCY failure propagated from a failed ancestor.
     *            Self-clears once the ancestor is cleared (no separate
     *            evidence required).
     *
     *   TRANSIENT = recoverable resource/timing failure. Missing UTXO
     *            row a self-heal can repair, DB writer busy, I/O retry
     *            budget. Distinct from VALID so the eventual retry path
     *            never re-runs full consensus on a known-good block.
     *            Reserved here; no SET site yet.
     *
     * BLOCK_FAILED_MASK (= VALID | CHILD = 96) is preserved for
     * backward compatibility with persisted nStatus on disk; new code
     * should prefer block_has_any_failure() / the typed predicates
     * below so the eventual TRANSIENT introduction is automatic. */
    BLOCK_FAILED_VALID       = 32,
    BLOCK_FAILED_CHILD       = 64,
    BLOCK_FAILED_MASK        = 96,
    BLOCK_ACTIVATES_UPGRADE  = 128,
    BLOCK_PARKED_FLAG        = 256,
    BLOCK_PARKED_PARENT_FLAG = 512,
    BLOCK_PARKED_MASK        = 768,
    BLOCK_FAILED_TRANSIENT   = 1024,
    BLOCK_FAILED_ANY_MASK    = 1120, /* VALID | CHILD | TRANSIENT */
    /* NODE-LOCAL revalidation-candidate marker — NOT a failure and NOT part of
     * any FAILED/VALID mask, so it never excludes a block from chain selection,
     * validity checks, or failed-child propagation. The block-index loaders set
     * it when they DEMOTE a persisted BLOCK_FAILED_VALID/FAILED_CHILD verdict
     * recorded ABOVE the baked ROM checkpoint (see block_index_loader.c): the
     * persisted negative verdict is a revalidation CANDIDATE, never final, so
     * the real FAILED bits are cleared (a stale bit can no longer wedge the tip)
     * and this marker records "the stages must re-confirm this on demand." It is
     * a runtime-derived provenance flag, recomputed fresh on every load — never
     * consensus state, never trusted from disk. Pure observability + diagnostics;
     * no code branches on it for validity. */
    BLOCK_REVALIDATE_PENDING = 2048,
};

#define BLOCK_VALID_CONSENSUS BLOCK_VALID_SCRIPTS

struct disk_block_pos {
    int nFile;
    unsigned int nPos;
};

static inline void disk_block_pos_init(struct disk_block_pos *p)
{
    p->nFile = -1;
    p->nPos = 0;
}

#define OPTIONAL_NONE (-1)

struct block_index {
    /* --- 8-byte aligned pointers first --- */
    const struct uint256 *phashBlock;
    struct block_index *pprev;
    struct block_index *pskip;

    /* --- 32-byte fields --- */
    struct uint256 hashBlock;  /* Stable storage for phashBlock */
    struct arith_uint256 nChainWork;
    struct uint256 hashMerkleRoot;
    struct uint256 hashFinalSaplingRoot;
    struct uint256 nNonce;

    /* --- 8-byte fields --- */
    int64_t nCachedBranchId;
    int64_t nSproutValue;
    int64_t nChainSproutValue;
    int64_t nSaplingValue;
    int64_t nChainSaplingValue;
    uint64_t nTimeReceived;
    unsigned char *nSolution;      /* heap-allocated, NULL if not loaded */
    size_t nSolutionSize;

    /* --- 4-byte fields --- */
    int nHeight;
    int nFile;
    unsigned int nDataPos;
    unsigned int nUndoPos;
    unsigned int nTx;
    unsigned int nChainTx;
    unsigned int nStatus;
    int32_t nVersion;
    uint32_t nTime;
    uint32_t nBits;
    uint32_t nSequenceId;

    /* --- 1-byte fields (packed together to avoid padding) --- */
    bool has_sprout_value;
    bool has_chain_sprout_value;
    bool has_chain_sapling_value;
    /* 5 bytes padding to 8-byte boundary — struct ends here */
};

static inline void block_index_init(struct block_index *bi)
{
    memset(bi, 0, sizeof(*bi));
    bi->nCachedBranchId = OPTIONAL_NONE;
    arith_uint256_set_zero(&bi->nChainWork);
}

static inline int64_t block_index_get_time(const struct block_index *bi)
{
    return (int64_t)bi->nTime;
}

#define MEDIAN_TIME_SPAN 11

static inline int64_t block_index_get_median_time_past(const struct block_index *bi)
{
    int64_t pmedian[MEDIAN_TIME_SPAN];
    int count = 0;
    const struct block_index *p = bi;
    for (int i = 0; i < MEDIAN_TIME_SPAN && p; i++, p = p->pprev)
        pmedian[count++] = block_index_get_time(p);

    /* Simple insertion sort */
    for (int i = 1; i < count; i++) {
        int64_t key = pmedian[i];
        int j = i - 1;
        while (j >= 0 && pmedian[j] > key) {
            pmedian[j + 1] = pmedian[j];
            j--;
        }
        pmedian[j + 1] = key;
    }
    return pmedian[count / 2];
}

/* Cross-thread block-index fields.
 *
 * Reducer/body stages publish nStatus/nFile/nDataPos while background workers
 * may read or clear transient status bits. Keep those accesses behind these
 * helpers instead of adding cs_main to the reducer hot path. The disk position
 * is written before the HAVE_DATA bit is release-published; readers acquire
 * nStatus before copying the position. */
static inline unsigned int block_index_status_load(const struct block_index *bi)
{
    return bi ? __atomic_load_n(&bi->nStatus, __ATOMIC_ACQUIRE) : 0u;
}

static inline unsigned int block_index_status_fetch_or(struct block_index *bi,
                                                       unsigned int bits)
{
    return bi ? __atomic_fetch_or(&bi->nStatus, bits, __ATOMIC_ACQ_REL) : 0u;
}

static inline unsigned int block_index_status_fetch_and(struct block_index *bi,
                                                        unsigned int mask)
{
    return bi ? __atomic_fetch_and(&bi->nStatus, mask, __ATOMIC_ACQ_REL) : 0u;
}

static inline unsigned int block_index_status_clear_bits(struct block_index *bi,
                                                         unsigned int bits)
{
    return block_index_status_fetch_and(bi, ~bits);
}

static inline unsigned int
block_index_status_set_valid_level(struct block_index *bi,
                                   enum block_status level)
{
    if (!bi)
        return 0u;
    unsigned int old = block_index_status_load(bi);
    unsigned int desired;
    do {
        desired = (old & ~(unsigned int)BLOCK_VALID_MASK) | (unsigned int)level;
    } while (!__atomic_compare_exchange_n(&bi->nStatus, &old, desired,
                                          false, __ATOMIC_ACQ_REL,
                                          __ATOMIC_ACQUIRE));
    return desired;
}

static inline int block_index_file_load(const struct block_index *bi)
{
    return bi ? __atomic_load_n(&bi->nFile, __ATOMIC_RELAXED) : -1;
}

static inline unsigned int
block_index_data_pos_load(const struct block_index *bi)
{
    return bi ? __atomic_load_n(&bi->nDataPos, __ATOMIC_RELAXED) : 0u;
}

static inline unsigned int
block_index_undo_pos_load(const struct block_index *bi)
{
    return bi ? __atomic_load_n(&bi->nUndoPos, __ATOMIC_RELAXED) : 0u;
}

static inline void block_index_disk_pos_store(struct block_index *bi,
                                              int file,
                                              unsigned int data_pos)
{
    if (!bi)
        return;
    __atomic_store_n(&bi->nFile, file, __ATOMIC_RELAXED);
    __atomic_store_n(&bi->nDataPos, data_pos, __ATOMIC_RELAXED);
}

static inline bool block_index_disk_pos_snapshot(const struct block_index *bi,
                                                 struct disk_block_pos *out,
                                                 unsigned int *status_out)
{
    if (!bi || !out)
        return false;
    unsigned int status = block_index_status_load(bi);
    if (status_out)
        *status_out = status;
    if ((status & BLOCK_HAVE_DATA) == 0)
        return false;
    out->nFile = block_index_file_load(bi);
    out->nPos = block_index_data_pos_load(bi);
    /* A recorded payload offset is never 0: the 8-byte frame header occupies
     * offsets 0-7 of every blk file, so the first payload sits at 8 (the
     * write path records ftell AFTER the frame header). nPos==0 is the
     * zero-init signature of an index entry whose body was never written —
     * from-scratch genesis is inserted with BLOCK_HAVE_DATA but no body.
     * Report "no data" instead of aliasing whatever block actually sits at
     * offset 0 (previously read as h=0, producing pread hash mismatches).
     * Verified 2026-08-02: the live canonical block_index.bin has zero
     * HAVE_DATA rows with n_data_pos==0, so no healthy entry relies on it. */
    return out->nFile >= 0 && out->nPos != 0;
}

static inline bool block_index_undo_pos_snapshot(const struct block_index *bi,
                                                 struct disk_block_pos *out,
                                                 unsigned int *status_out)
{
    if (!bi || !out)
        return false;
    unsigned int status = block_index_status_load(bi);
    if (status_out)
        *status_out = status;
    if ((status & BLOCK_HAVE_UNDO) == 0)
        return false;
    out->nFile = block_index_file_load(bi);
    out->nPos = block_index_undo_pos_load(bi);
    return out->nFile >= 0;
}

/* Typed failure classification. Prefer these over raw
 * nStatus bit tests so the future TRANSIENT retry policy lands at one
 * site. */
static inline bool block_is_permanently_failed(const struct block_index *bi)
{
    return (block_index_status_load(bi) & BLOCK_FAILED_VALID) != 0;
}
static inline bool block_is_dependency_failed(const struct block_index *bi)
{
    return (block_index_status_load(bi) & BLOCK_FAILED_CHILD) != 0;
}
static inline bool block_is_transiently_failed(const struct block_index *bi)
{
    return (block_index_status_load(bi) & BLOCK_FAILED_TRANSIENT) != 0;
}
static inline bool block_has_any_failure(const struct block_index *bi)
{
    return (block_index_status_load(bi) & BLOCK_FAILED_ANY_MASK) != 0;
}
/* True when a loader demoted a persisted FAILED verdict above the ROM
 * checkpoint to a revalidation candidate (see BLOCK_REVALIDATE_PENDING). This
 * is NOT a failure — block_has_any_failure() is false — so the block stays
 * eligible for chain selection until the stages re-confirm it on demand. */
static inline bool block_is_revalidation_pending(const struct block_index *bi)
{
    return (block_index_status_load(bi) & BLOCK_REVALIDATE_PENDING) != 0;
}

static inline bool block_index_is_valid(const struct block_index *bi,
                                        enum block_status up_to)
{
    if (block_has_any_failure(bi))
        return false;
    return (block_index_status_load(bi) & BLOCK_VALID_MASK) >= (unsigned int)up_to;
}

struct block_index *block_index_get_ancestor(struct block_index *bi, int height);
void block_index_build_skip(struct block_index *bi);

/* qsort comparator: sort block_index pointers by height ascending */
static inline int block_index_cmp_height(const void *a, const void *b)
{
    const struct block_index *ba = *(const struct block_index *const *)a;
    const struct block_index *bb = *(const struct block_index *const *)b;
    return (ba->nHeight > bb->nHeight) - (ba->nHeight < bb->nHeight);
}

#endif
