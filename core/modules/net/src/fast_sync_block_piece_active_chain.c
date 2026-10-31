/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Block piece manifest from the active chain: the in-memory builder that
 * hashes trusted block ranges into pieces. Split out of fast_sync.c so that
 * file stays under its shrink-only file-size pin; the functions below moved
 * verbatim. */

#include "net/fast_sync.h"
#include "core/hash.h"
#include "validation/chainstate.h"
#include <stdlib.h>
#include <string.h>
#include "util/safe_alloc.h"
#include "util/log_macros.h"

/* First height in start_height..end_height with trusted block data, or
 * end_height + 1 when there is none. */
static int32_t block_piece_manifest_first_trusted(const struct active_chain *chain,
                                                  int32_t start_height,
                                                  int32_t end_height)
{
    int32_t first_data_height = start_height;
    while (first_data_height <= end_height) {
        const struct block_index *bi = active_chain_at(chain, first_data_height);
        if (bi && bi->phashBlock && (bi->nStatus & BLOCK_HAVE_DATA))
            break;
        first_data_height++;
    }
    return first_data_height;
}

/* Hashes the trusted blocks first..end into piece hashes and the tip hash.
 * Returns 0, or the first height whose trusted block data is missing. */
static int32_t block_piece_manifest_chain_pieces(const struct active_chain *chain,
                                                 int32_t first_data_height,
                                                 int32_t end_height,
                                                 struct block_piece_manifest *out,
                                                 uint8_t (*piece_block_hashes)[32])
{
    uint32_t piece_idx = 0;
    uint32_t block_in_piece = 0;

    for (int32_t h = first_data_height; h <= end_height; h++) {
        const struct block_index *bi = active_chain_at(chain, h);
        if (!bi || !bi->phashBlock || !(bi->nStatus & BLOCK_HAVE_DATA))
            return h;

        memcpy(piece_block_hashes[block_in_piece], bi->phashBlock->data, 32);
        if (h == end_height)
            memcpy(out->tip_hash, bi->phashBlock->data, 32);
        block_in_piece++;

        if (block_in_piece == BLOCKS_PER_PIECE) {
            block_piece_hash((const uint8_t (*)[32])piece_block_hashes,
                             block_in_piece, piece_idx,
                             out->piece_hashes[piece_idx]);
            piece_idx++;
            block_in_piece = 0;
        }
    }

    if (block_in_piece > 0) {
        block_piece_hash((const uint8_t (*)[32])piece_block_hashes,
                         block_in_piece, piece_idx,
                         out->piece_hashes[piece_idx]);
    }
    return 0;
}

bool block_piece_manifest_build_active_chain(
                                 const struct active_chain *chain,
                                 int32_t start_height, int32_t end_height,
                                 struct block_piece_manifest *out)
{
    GUARD(out && chain && end_height >= start_height && start_height >= 1,
          "sync",
          "piece_manifest_build_chain: invalid args (out=%p chain=%p start=%d end=%d)",
          (void *)out, (const void *)chain, start_height, end_height);
    memset(out, 0, sizeof(*out));

    int chain_height = active_chain_height(chain);
    if (end_height > chain_height)
        LOG_FAIL("sync",
                 "piece_manifest_build_chain: end height beyond active chain (%d/%d)",
                 end_height, chain_height);

    int32_t first_data_height =
        block_piece_manifest_first_trusted(chain, start_height, end_height);
    if (first_data_height > end_height)
        LOG_FAIL("sync",
                 "piece_manifest_build_chain: no trusted block data in requested range h=%d..%d",
                 start_height, end_height);
    if (first_data_height != start_height)
        printf("Block manifest: skipping h=%d..%d without trusted block data\n",
               start_height, first_data_height - 1);

    out->start_height = first_data_height;
    out->end_height = end_height;
    int32_t total_blocks = end_height - first_data_height + 1;
    out->num_pieces = (uint32_t)((total_blocks + BLOCKS_PER_PIECE - 1)
                                  / BLOCKS_PER_PIECE);

    out->piece_hashes = zcl_calloc(out->num_pieces, 32, "piece_hashes");
    if (!out->piece_hashes)
        LOG_FAIL("sync",
                 "piece_manifest_build_chain: alloc piece_hashes failed for %u pieces",
                 out->num_pieces);

    uint8_t (*piece_block_hashes)[32] =
        zcl_calloc(BLOCKS_PER_PIECE, 32, "piece_block_hashes");
    if (!piece_block_hashes) {
        free(out->piece_hashes);
        out->piece_hashes = NULL;
        LOG_FAIL("sync",
                 "piece_manifest_build_chain: alloc piece_block_hashes failed");
    }

    int32_t h = block_piece_manifest_chain_pieces(chain, first_data_height,
                                                  end_height, out,
                                                  piece_block_hashes);
    if (h != 0) {
        free(piece_block_hashes);
        free(out->piece_hashes);
        out->piece_hashes = NULL;
        LOG_FAIL("sync",
                 "piece_manifest_build_chain: missing trusted block data at h=%d",
                 h);
    }

    free(piece_block_hashes);

    fast_sync_merkle_root((const uint8_t (*)[32])out->piece_hashes,
                           out->num_pieces, out->merkle_root);
    return true;
}
