/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Atomic embedded-SHA3 block-index flat save and verified identity cache. */
// one-result-type-ok:flat-identity-cache-lookup

#include "services/block_index_loader.h"
#include "block_index_flat_internal.h"
#include "services/block_index_flat_anchor.h"
#include "services/block_index_integrity.h"
#include "validation/main_state.h"
#include "chain/chain.h"
#include "crypto/sha3.h"
#include "platform/time_compat.h"
#include "util/log_macros.h"
#include "util/safe_alloc.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static struct block_index_flat_identity g_identity;
static char g_identity_datadir[1024];
static bool g_identity_valid;

void block_index_flat_identity_forget(void)
{
    memset(&g_identity, 0, sizeof(g_identity));
    g_identity_datadir[0] = '\0';
    g_identity_valid = false;
}

void block_index_flat_identity_remember(
    const char *datadir, const struct block_index_flat_identity *identity)
{
    if (!datadir || !identity || snprintf(g_identity_datadir,
            sizeof(g_identity_datadir), "%s", datadir) >=
            (int)sizeof(g_identity_datadir)) {
        block_index_flat_identity_forget();
        return;
    }
    g_identity = *identity;
    g_identity_valid = true;
}

bool block_index_flat_verified_identity(
    const char *datadir, struct block_index_flat_identity *out)
{
    if (!datadir || !out || !g_identity_valid ||
        strcmp(datadir, g_identity_datadir) != 0)
        return false;
    *out = g_identity;
    return true;
}

struct emit_ctx {
    struct main_state *ms; struct block_index **sorted; size_t count;
    struct block_index_flat_identity identity;
};

static bool emit_payload(FILE *file, void *user, uint64_t *size_out,
                         uint8_t sha3_out[32])
{
    struct emit_ctx *ctx = user;
    struct sha3_256_ctx sha3;
    sha3_256_init(&sha3);
    uint32_t magic = 0x5A434C49, count = (uint32_t)ctx->count;
    if (fwrite(&magic, 4, 1, file) != 1 || // disk-io-lock: private-fd
        fwrite(&count, 4, 1, file) != 1)
        LOG_FAIL("block_index_flat", "flat payload header write failed");
    sha3_256_write(&sha3, (const uint8_t *)&magic, 4);
    sha3_256_write(&sha3, (const uint8_t *)&count, 4);
    uint64_t bytes = 8;
    for (size_t i = 0; i < ctx->count; i++) {
        struct block_index *src = ctx->sorted[i];
        struct block_index_flat row = {0};
        if (src->phashBlock) memcpy(row.hash, src->phashBlock->data, 32);
        if (src->pprev && src->pprev->phashBlock)
            memcpy(row.prev_hash, src->pprev->phashBlock->data, 32);
        row.height = src->nHeight; row.n_bits = src->nBits;
        row.n_time = src->nTime; row.n_version = src->nVersion;
        row.n_status = src->nStatus; row.n_file = src->nFile;
        row.n_data_pos = src->nDataPos; row.n_undo_pos = src->nUndoPos;
        row.n_tx = src->nTx; row.n_chain_tx = src->nChainTx;
        memcpy(row.chain_work, src->nChainWork.pn, 32);
        row.n_cached_branch_id = (uint32_t)src->nCachedBranchId;
        memcpy(row.sapling_root, src->hashFinalSaplingRoot.data, 32);
        if (fwrite(&row, sizeof(row), 1, file) != 1) // disk-io-lock: private-fd
            LOG_FAIL("block_index_flat", "flat row write failed at %zu: %s",
                     i, strerror(errno));
        sha3_256_write(&sha3, (const uint8_t *)&row, sizeof(row));
        bytes += sizeof(row);
    }
    uint8_t anchor[BIFA_TRAILER_MAX]; size_t anchor_len = 0;
    struct zcl_result ar = block_index_flat_anchor_encode(
        ctx->ms, ctx->sorted, ctx->count, anchor, sizeof(anchor), &anchor_len);
    if (!ar.ok) return false;
    if (anchor_len && fwrite(anchor, anchor_len, 1, file) != 1)
        LOG_FAIL("block_index_flat", "flat anchor write failed");
    if (anchor_len) sha3_256_write(&sha3, anchor, anchor_len);
    bytes += anchor_len;
    sha3_256_finalize(&sha3, sha3_out);
    *size_out = bytes;
    memcpy(ctx->identity.payload_sha3, sha3_out, 32);
    ctx->identity.payload_size = bytes; ctx->identity.row_count = ctx->count;
    return true;
}

static int save_height_cmp(const void *a, const void *b)
{
    const struct block_index *aa = *(const struct block_index *const *)a;
    const struct block_index *bb = *(const struct block_index *const *)b;
    return aa->nHeight < bb->nHeight ? -1 : aa->nHeight > bb->nHeight;
}

struct zcl_result block_index_flat_write_identity(
    const char *datadir, struct main_state *ms,
    struct block_index_flat_identity *out)
{
    if (!datadir || !datadir[0] || !ms)
        return ZCL_ERR(-1, "block index flat write: invalid datadir/state");
    size_t count = ms->map_block_index.size;
    struct block_index **sorted = zcl_malloc(
        count * sizeof(*sorted), "block_index sorted save");
    if (!sorted)
        return ZCL_ERR(-2, "block index flat write: allocation failed for "
                       "%zu entries", count);
    size_t n = 0, iter = 0; struct block_index *entry;
    while (block_map_next(&ms->map_block_index, &iter, NULL, &entry))
        if (entry && n < count) sorted[n++] = entry;
    qsort(sorted, n, sizeof(*sorted), save_height_cmp);
    int64_t started = (int64_t)platform_time_wall_time_t();
    struct emit_ctx ctx = { .ms = ms, .sorted = sorted, .count = n };
    struct zcl_result written = bii_write_embedded(datadir, emit_payload, &ctx);
    free(sorted);
    if (!written.ok)
        return written;
    block_index_flat_identity_remember(datadir, &ctx.identity);
    if (out) *out = ctx.identity;
    LOG_INFO("block_index_flat", "Block index flat file: %zu entries, "
             "%zuMB (%llds)", n, n * sizeof(struct block_index_flat) /
             (1024 * 1024), (long long)((int64_t)platform_time_wall_time_t() - started));
    return ZCL_OK;
}
