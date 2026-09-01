/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Block-index disk placement and hydration helpers for process_block.
 *
 * The reducer and header-admit path still need a small validation-side bridge
 * for legacy block files: choose blk*.dat positions, refresh an in-memory
 * block_index from on-disk bytes, and recompute skip/work metadata after
 * hydration. Keep that disk/index machinery out of process_block_core.c. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include "chain/chain.h"
#include "chain/pow.h"
#include "core/uint256.h"
#include "primitives/block.h"
#include "storage/disk_block_io.h"
#include "storage/block_index_db.h"
#include "util/safe_alloc.h"
#include "validation/main_constants.h"

#include "process_block_internal.h"

static int g_last_block_file = -1;
unsigned int g_last_block_file_size = 0; /* extern in process_block_internal.h */

bool find_block_pos(struct disk_block_pos *pos, unsigned int block_size,
                    const char *datadir)
{
    if (g_last_block_file < 0) {
        /* Scan existing block files to find the last one */
        g_last_block_file = 0;
        for (int i = 0; i < 99999; i++) {
            char path[512];
            struct disk_block_pos probe = { .nFile = i, .nPos = 0 };
            get_block_pos_filename(path, sizeof(path), datadir, &probe, "blk");
            struct stat st;
            if (stat(path, &st) != 0)
                break;
            g_last_block_file = i;
            g_last_block_file_size = (unsigned int)st.st_size;
        }
    }

    /* Move to next file if current one is too large */
    if (g_last_block_file_size + block_size + 8 > MAX_BLOCKFILE_SIZE) {
        g_last_block_file++;
        g_last_block_file_size = 0;
    }

    /* Safety: cap file number to prevent runaway file creation.
     * 10000 files * 128MB each = 1.28TB which is more than enough. */
    if (g_last_block_file > 9999) {
        fprintf(stderr, "find_block_pos: file number %d exceeds max (9999)\n",
                g_last_block_file);
        return false;
    }

    pos->nFile = g_last_block_file;
    pos->nPos = g_last_block_file_size;
    return true;
}

void block_index_refresh_header(struct block_index *pindex,
                                const struct block_header *header)
{
    if (!pindex || !header)
        return;

    pindex->nVersion = header->nVersion;
    pindex->hashMerkleRoot = header->hashMerkleRoot;
    pindex->hashFinalSaplingRoot = header->hashFinalSaplingRoot;
    pindex->nTime = header->nTime;
    pindex->nBits = header->nBits;
    pindex->nNonce = header->nNonce;

    if (pindex->nSolution) {
        free(pindex->nSolution);
        pindex->nSolution = NULL;
        pindex->nSolutionSize = 0;
    }
    if (header->nSolutionSize == 0)
        return;

    pindex->nSolution = zcl_malloc(header->nSolutionSize,
                                   "block_solution_refresh");
    if (!pindex->nSolution)
        return;
    memcpy(pindex->nSolution, header->nSolution, header->nSolutionSize);
    pindex->nSolutionSize = header->nSolutionSize;
}

void block_index_snapshot_for_persist(struct disk_block_index *dbi,
                                      const struct block_index *pindex)
{
    if (!dbi)
        return;

    disk_block_index_init(dbi);
    if (!pindex)
        return;

    if (pindex->pprev && pindex->pprev->phashBlock)
        dbi->hashPrev = *pindex->pprev->phashBlock;
    dbi->nHeight = pindex->nHeight;
    dbi->nStatus = pindex->nStatus;
    dbi->nTx = pindex->nTx;
    dbi->nFile = pindex->nFile;
    dbi->nDataPos = pindex->nDataPos;
    dbi->nUndoPos = pindex->nUndoPos;
    dbi->nCachedBranchId = pindex->nCachedBranchId;
    dbi->nVersion = pindex->nVersion;
    dbi->hashMerkleRoot = pindex->hashMerkleRoot;
    dbi->hashFinalSaplingRoot = pindex->hashFinalSaplingRoot;
    dbi->nTime = pindex->nTime;
    dbi->nBits = pindex->nBits;
    dbi->nNonce = pindex->nNonce;
    if (pindex->nSolution && pindex->nSolutionSize > 0)
        memcpy(dbi->nSolution, pindex->nSolution, pindex->nSolutionSize);
    dbi->nSolutionSize = pindex->nSolutionSize;
}

bool block_index_hydrate_from_disk(struct block_index *pindex,
                                   const char *datadir)
{
    if (!pindex || !datadir || !pindex->phashBlock ||
        !(pindex->nStatus & BLOCK_HAVE_DATA) ||
        pindex->nFile < 0 || pindex->nDataPos == 0)
        return false;

    struct block disk_block;
    block_init(&disk_block);
    if (!read_block_from_disk_index(&disk_block, pindex, datadir)) {
        block_free(&disk_block);
        return false;
    }

    struct uint256 disk_hash;
    block_header_get_hash(&disk_block.header, &disk_hash);
    if (uint256_cmp(&disk_hash, pindex->phashBlock) != 0) {
        block_free(&disk_block);
        return false;
    }

    block_index_refresh_header(pindex, &disk_block.header);
    if (pindex->pprev) {
        pindex->nHeight = pindex->pprev->nHeight + 1;
        block_index_build_skip(pindex);
        struct arith_uint256 proof = GetBlockProof(pindex);
        arith_uint256_add(&pindex->nChainWork,
                          &pindex->pprev->nChainWork, &proof);
    }
    block_free(&disk_block);
    return pindex->nBits != 0;
}

#ifdef ZCL_TESTING
bool process_block_test_hydrate_index_from_disk(struct block_index *pindex,
                                                const char *datadir)
{
    return block_index_hydrate_from_disk(pindex, datadir);
}
#endif
