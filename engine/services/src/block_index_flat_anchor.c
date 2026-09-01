/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * block_index_flat_anchor — preserve one complete hash-bound header in the
 * otherwise solution-free flat block-index artifact. */

#include "services/block_index_flat_anchor.h"

#include "base/serialize_le.h"
#include "chain/chain.h"
#include "chain/checkpoints.h"
#include "core/serialize.h"
#include "primitives/block.h"
#include "storage/node_db_runtime.h"
#include "util/log_macros.h"
#include "util/safe_alloc.h"
#include "validation/chainstate.h"
#include "validation/main_state.h"

#include <stdlib.h>
#include <string.h>

#define BIFA_SUBSYS "block_index_flat_anchor"
#define BIFA_MAGIC 0x3141485au /* "ZHA1" in little-endian */
#define BIFA_ENVELOPE_SIZE 12u

static struct block_header g_prepared_header;
static struct uint256 g_prepared_hash;
static int32_t g_prepared_height = -1;
static bool g_prepared = false;

static bool bifa_header_from_index(const struct block_index *bi,
                                   struct block_header *out)
{
    if (!bi || !bi->phashBlock || !bi->nSolution || bi->nSolutionSize == 0 ||
        bi->nSolutionSize > MAX_SOLUTION_SIZE)
        return false;
    block_header_init(out);
    out->nVersion = bi->nVersion;
    if (bi->pprev && bi->pprev->phashBlock)
        out->hashPrevBlock = *bi->pprev->phashBlock;
    out->hashMerkleRoot = bi->hashMerkleRoot;
    out->hashFinalSaplingRoot = bi->hashFinalSaplingRoot;
    out->nTime = bi->nTime;
    out->nBits = bi->nBits;
    out->nNonce = bi->nNonce;
    memcpy(out->nSolution, bi->nSolution, bi->nSolutionSize);
    out->nSolutionSize = bi->nSolutionSize;

    struct uint256 got;
    block_header_get_hash(out, &got);
    return uint256_eq(&got, bi->phashBlock);
}

static struct block_index *bifa_select(struct main_state *ms,
                                       struct block_index **sorted,
                                       size_t count)
{
    const struct sha3_utxo_checkpoint *cp = get_sha3_utxo_checkpoint();
    if (cp && cp->height >= 0) {
        struct uint256 hash;
        memcpy(hash.data, cp->block_hash, sizeof(hash.data));
        struct block_index *bi = block_map_find(&ms->map_block_index, &hash);
        if (bi && bi->nHeight == cp->height)
            return bi;
    }
    for (size_t i = count; i > 0; i--) {
        struct block_index *bi = sorted[i - 1];
        if (bi && bi->nSolution && bi->nSolutionSize > 0)
            return bi;
    }
    if (g_prepared) {
        struct block_index *bi =
            block_map_find(&ms->map_block_index, &g_prepared_hash);
        if (bi && bi->nHeight == g_prepared_height)
            return bi;
    }
    return NULL;
}

static struct block_index *bifa_select_for_prepare(struct main_state *ms)
{
    const struct sha3_utxo_checkpoint *cp = get_sha3_utxo_checkpoint();
    if (cp && cp->height >= 0) {
        struct uint256 hash;
        memcpy(hash.data, cp->block_hash, sizeof(hash.data));
        struct block_index *bi = block_map_find(&ms->map_block_index, &hash);
        if (bi && bi->nHeight == cp->height)
            return bi;
    }

    struct block_index *best = NULL;
    size_t iter = 0;
    struct block_index *bi = NULL;
    while (block_map_next(&ms->map_block_index, &iter, NULL, &bi)) {
        if (bi && bi->nSolution && bi->nSolutionSize > 0 &&
            (!best || bi->nHeight > best->nHeight))
            best = bi;
    }
    return best;
}

struct zcl_result block_index_flat_anchor_prepare(struct main_state *ms)
{
    g_prepared = false;
    g_prepared_height = -1;
    if (!ms) {
        LOG_WARN(BIFA_SUBSYS, "anchor prepare failed: null main state");
        return ZCL_ERR(-20, "flat anchor prepare: null main state");
    }

    struct block_index *bi = bifa_select_for_prepare(ms);
    if (!bi || !bi->phashBlock)
        return ZCL_OK;

    struct block_header hdr;
    bool have = bifa_header_from_index(bi, &hdr);
    if (!have)
        have = node_db_runtime_load_header_by_hash_height(
            bi->nHeight, bi->phashBlock->data, &hdr);
    if (!have)
        return ZCL_OK;

    struct uint256 got;
    block_header_get_hash(&hdr, &got);
    if (!uint256_eq(&got, bi->phashBlock)) {
        LOG_WARN(BIFA_SUBSYS,
                 "anchor prepare refused h=%d: complete header is not hash-bound",
                 bi->nHeight);
        return ZCL_ERR(-21, "flat anchor prepare: header not hash-bound h=%d",
                       bi->nHeight);
    }

    g_prepared_header = hdr;
    g_prepared_hash = got;
    g_prepared_height = bi->nHeight;
    g_prepared = true;
    LOG_INFO(BIFA_SUBSYS,
             "prepared complete hash-bound anchor header h=%d before DB close",
             bi->nHeight);
    return ZCL_OK;
}

struct zcl_result block_index_flat_anchor_encode(
    struct main_state *ms, struct block_index **sorted, size_t count,
    uint8_t *out, size_t out_cap, size_t *out_len)
{
    if (!out_len) {
        LOG_WARN(BIFA_SUBSYS, "anchor encode failed: null length output");
        return ZCL_ERR(-1, "flat anchor encode: null length output");
    }
    *out_len = 0;
    if (!ms || !sorted || count == 0 || !out ||
        out_cap < BIFA_ENVELOPE_SIZE) {
        LOG_WARN(BIFA_SUBSYS, "anchor encode failed: invalid arguments");
        return ZCL_ERR(-2, "flat anchor encode: invalid arguments");
    }

    struct block_index *bi = bifa_select(ms, sorted, count);
    if (!bi || !bi->phashBlock)
        return ZCL_OK;

    struct block_header hdr;
    bool have = bifa_header_from_index(bi, &hdr);
    if (!have && g_prepared && g_prepared_height == bi->nHeight &&
        uint256_eq(&g_prepared_hash, bi->phashBlock)) {
        hdr = g_prepared_header;
        have = true;
    }
    if (!have)
        have = node_db_runtime_load_header_by_hash_height(
            bi->nHeight, bi->phashBlock->data, &hdr);
    if (!have)
        return ZCL_OK;

    struct uint256 got;
    block_header_get_hash(&hdr, &got);
    if (!uint256_eq(&got, bi->phashBlock)) {
        LOG_WARN(BIFA_SUBSYS,
                 "anchor encode refused h=%d: complete header is not hash-bound",
                 bi->nHeight);
        return ZCL_ERR(-3, "flat anchor encode: header not hash-bound h=%d",
                       bi->nHeight);
    }

    struct byte_stream s;
    stream_init(&s, BLOCK_HEADER_SIZE + MAX_SOLUTION_SIZE + 9u);
    if (!block_header_serialize(&hdr, &s) || s.error ||
        s.size > out_cap - BIFA_ENVELOPE_SIZE) {
        LOG_WARN(BIFA_SUBSYS,
                 "anchor encode failed h=%d: serialized header exceeds bound",
                 bi->nHeight);
        stream_free(&s);
        return ZCL_ERR(-4, "flat anchor encode: serialization failed h=%d",
                       bi->nHeight);
    }

    zcl_write_u32_le(out, BIFA_MAGIC);
    zcl_write_i32_le(out + 4, bi->nHeight);
    zcl_write_u32_le(out + 8, (uint32_t)s.size);
    memcpy(out + BIFA_ENVELOPE_SIZE, s.data, s.size);
    *out_len = BIFA_ENVELOPE_SIZE + s.size;
    stream_free(&s);
    LOG_INFO(BIFA_SUBSYS,
             "preserved complete hash-bound anchor header h=%d bytes=%zu",
             bi->nHeight, *out_len);
    return ZCL_OK;
}

struct zcl_result block_index_flat_anchor_apply(
    struct main_state *ms, const uint8_t *trailer, size_t trailer_len)
{
    if (!trailer || trailer_len == 0)
        return ZCL_OK;
    if (!ms || trailer_len < BIFA_ENVELOPE_SIZE) {
        LOG_WARN(BIFA_SUBSYS, "anchor trailer refused: invalid arguments");
        return ZCL_ERR(-10, "flat anchor apply: invalid arguments");
    }
    if (zcl_read_u32_le(trailer) != BIFA_MAGIC)
        return ZCL_OK; /* forward/legacy-compatible unknown trailer */

    int32_t height = zcl_read_i32_le(trailer + 4);
    uint32_t header_len = zcl_read_u32_le(trailer + 8);
    if (height < 0 || header_len == 0 ||
        (size_t)header_len != trailer_len - BIFA_ENVELOPE_SIZE ||
        header_len > BIFA_TRAILER_MAX - BIFA_ENVELOPE_SIZE) {
        LOG_WARN(BIFA_SUBSYS,
                 "anchor trailer refused: malformed envelope h=%d bytes=%u/%zu",
                 height, header_len, trailer_len);
        return ZCL_ERR(-11, "flat anchor apply: malformed envelope h=%d",
                       height);
    }

    struct byte_stream s;
    stream_init_from_data(&s, trailer + BIFA_ENVELOPE_SIZE, header_len);
    struct block_header hdr;
    block_header_init(&hdr);
    if (!block_header_deserialize(&hdr, &s) || s.error ||
        stream_remaining(&s) != 0 || hdr.nSolutionSize == 0) {
        LOG_WARN(BIFA_SUBSYS,
                 "anchor trailer refused h=%d: malformed canonical header",
                 height);
        return ZCL_ERR(-12, "flat anchor apply: malformed header h=%d",
                       height);
    }

    struct uint256 hash;
    block_header_get_hash(&hdr, &hash);
    struct block_index *bi = block_map_find(&ms->map_block_index, &hash);
    if (!bi || bi->nHeight != height || !bi->phashBlock ||
        !uint256_eq(bi->phashBlock, &hash)) {
        LOG_WARN(BIFA_SUBSYS,
                 "anchor trailer refused h=%d: header does not bind an imported row",
                 height);
        return ZCL_ERR(-13, "flat anchor apply: unbound header h=%d", height);
    }
    if (bi->pprev && bi->pprev->phashBlock &&
        !uint256_eq(bi->pprev->phashBlock, &hdr.hashPrevBlock)) {
        LOG_WARN(BIFA_SUBSYS,
                 "anchor trailer refused h=%d: parent hash mismatch", height);
        return ZCL_ERR(-14, "flat anchor apply: parent mismatch h=%d", height);
    }

    uint8_t *solution = zcl_malloc(hdr.nSolutionSize, "flat anchor solution");
    if (!solution) {
        LOG_WARN(BIFA_SUBSYS,
                 "anchor trailer apply failed h=%d: solution allocation", height);
        return ZCL_ERR(-15, "flat anchor apply: allocation failed h=%d",
                       height);
    }
    memcpy(solution, hdr.nSolution, hdr.nSolutionSize);
    free(bi->nSolution);
    bi->nSolution = solution;
    bi->nSolutionSize = hdr.nSolutionSize;
    bi->nVersion = hdr.nVersion;
    bi->hashMerkleRoot = hdr.hashMerkleRoot;
    bi->hashFinalSaplingRoot = hdr.hashFinalSaplingRoot;
    bi->nTime = hdr.nTime;
    bi->nBits = hdr.nBits;
    bi->nNonce = hdr.nNonce;
    LOG_INFO(BIFA_SUBSYS,
             "restored complete hash-bound anchor header h=%d solution=%zu",
             height, hdr.nSolutionSize);
    return ZCL_OK;
}
