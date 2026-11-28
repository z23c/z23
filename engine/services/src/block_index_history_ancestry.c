/* purpose: Verify the hash-linked header ancestry of a history archive. */
/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * The history archive opener in block_index_loader.c admits an archived
 * endpoint only after this walk has proved every row from the endpoint down
 * to genesis holds the header its index entry names. Nothing here reads an
 * index file, selects a chain or publishes state. */
#include "block_index_history_ancestry.h"
#include "services/island_anchor.h"
#include "storage/blocks_mmap_reader.h"
#include "core/serialize.h"
#include "chain/chain.h"
#include "primitives/block.h"
#include "core/uint256.h"
#include "validation/chainstate.h"
#include "validation/main_state.h"
#include "util/thread_registry.h"
#include "util/log_macros.h"
#include <string.h>

static bool bha_header(struct blocks_mmap *reader, const struct block_index *row,
                        struct block_header *header)
{
    size_t len = 0;
    if (!row || !row->phashBlock || row->nFile < 0) return false;
    const uint8_t *payload = bmr_get_payload(reader, row->nFile, row->nDataPos, &len);
    if (!payload) return false;
    struct byte_stream stream;
    stream_init_from_data(&stream, payload, len);
    block_header_init(header);
    if (!block_header_deserialize(header, &stream)) return false;
    struct uint256 hash;
    block_header_get_hash(header, &hash);
    return uint256_eq(&hash, row->phashBlock) && header->nVersion == row->nVersion &&
        header->nTime == row->nTime && header->nBits == row->nBits &&
        uint256_eq(&header->hashFinalSaplingRoot, &row->hashFinalSaplingRoot);
}

static bool bha_row_valid(struct main_state *state, struct blocks_mmap *reader,
                          struct block_index *row, int32_t height, struct block_header *header)
{
    return row && row->nHeight == height && row->phashBlock &&
        block_map_find(&state->map_block_index, row->phashBlock) == row && bha_header(reader, row, header);
}

static bool bha_link_valid(const struct block_index *row, const struct block_header *header,
                           int32_t height, const struct uint256 *genesis)
{
    if (height == 0)
        return !row->pprev && uint256_eq(row->phashBlock, genesis) && uint256_is_null(&header->hashPrevBlock);
    return row->pprev && row->pprev->phashBlock &&
        uint256_eq(&header->hashPrevBlock, row->pprev->phashBlock);
}

#ifdef ZCL_TESTING
static int32_t g_bha_cancel_height = -1;
void block_index_history_test_cancel_height(int32_t height);
void block_index_history_test_cancel_height(int32_t height)
{
    g_bha_cancel_height = height;
}
#endif

static bool bha_cancelled(int32_t height)
{
#ifdef ZCL_TESTING
    if (height == g_bha_cancel_height) return true;
#else
    (void)height;
#endif
    return thread_registry_shutdown_requested();
}

struct zcl_result block_index_history_cancel_refusal(int32_t height)
{
    return bha_cancelled(height) ? ZCL_ERR(-5, "history archive: cancelled") : ZCL_OK;
}

struct zcl_result block_index_history_ancestry_verify(struct main_state *state,
    struct blocks_mmap *reader, struct block_index *tip, int32_t height,
    const struct uint256 *genesis, struct block_header *top_window)
{
    struct block_index *row = tip;
    for (int32_t h = height; h >= 0; h--) {
        if (bha_cancelled(h)) return ZCL_ERR(-5, "history archive: cancelled");
        struct block_header header;
        if (!bha_row_valid(state, reader, row, h, &header) ||
            !bha_link_valid(row, &header, h, genesis)) {
            LOG_WARN("block_index_flat", "history archive header or ancestry invalid at height %d", (int)h);
            return ZCL_ERR(-3, "history archive: header ancestry invalid or unavailable");
        }
        if (height - h < ISLAND_ANCHOR_WINDOW) {
            if (!block_index_set_hdrext(row, &header.hashMerkleRoot, &header.nNonce,
                                        header.nSolution, header.nSolutionSize)) {
                LOG_WARN("block_index_flat", "history archive header extension failed at height %d", (int)h);
                return ZCL_ERR(-3, "history archive: header ancestry invalid or unavailable");
            }
            if (top_window) top_window[height - h] = header;
        }
        if (h == 0) return ZCL_OK;
        row = row->pprev;
    }
    return ZCL_ERR(-3, "history archive: header ancestry invalid or unavailable");
}
