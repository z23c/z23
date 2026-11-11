/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0
 * purpose: Bind and validate the persisted block-index top-up prefix. */
// one-result-type-ok:resume-height-best-effort-mark — a failed check resumes at
// lo and folds the whole window; recording the mark is best effort and logged.
#include "block_index_topup_clean.h"
#include "validation/main_state.h"
#include "chain/chain.h"
#include "models/block.h"
#include "models/database.h"
#include "base/serialize_le.h"
#include "sha3/sha3.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
/* ── proven-clean prefix ─────────────────────────────────────────────────
 * A warm boot re-reads the whole [H_seed+1 .. coins_best] window (hundreds of
 * thousands of wide rows) only to find that the raise-only fold changes
 * nothing. After a fold that changed NOTHING, the top-up records the prefix
 * [lo .. coins_best - margin] as clean, bound to:
 *   - the seed anchor hash and the window floor (a new import or a moved
 *     floor invalidates it),
 *   - a fingerprint of every map entry in the prefix (count + an
 *     digest over complete hashes, heights, status, file, positions and nTx),
 *   - a digest of the ordered connected node.db rows and their same fields.
 * The next boot re-verifies all three and folds only the rows above the
 * prefix; any mismatch folds the whole window exactly as before. The margin
 * keeps the volatile tip region out of the prefix. */
#define NODE_DB_TOPUP_CLEAN_KEY "nodedb_topup_clean"
#define NODE_DB_TOPUP_CLEAN_MARGIN 1024

struct topup_clean_mark {
    uint8_t  anchor[32];
    int32_t  lo, clean_to;
    uint32_t map_count;
    uint32_t version;   /* NODE_DB_TOPUP_CLEAN_VERSION; an older mark is ignored */
    uint8_t  map_digest[32];
    uint8_t  row_digest[32];
    int64_t  row_count; /* status>=3 rows in lo..clean_to; span-row_count = holes */
};
/* v3 binds the complete map and database row contents in the prefix. */
#define NODE_DB_TOPUP_CLEAN_VERSION 3u

static void topup_hash_u32(struct sha3_256_ctx *ctx, uint32_t value)
{
    uint8_t bytes[4];
    zcl_write_u32_le(bytes, value);
    sha3_256_write(ctx, bytes, sizeof(bytes));
}

static void topup_hash_fields(struct sha3_256_ctx *ctx, int height,
                              const uint8_t hash[32], uint32_t status,
                              uint32_t file, uint32_t data, uint32_t undo,
                              uint32_t ntx)
{
    topup_hash_u32(ctx, (uint32_t)height);
    sha3_256_write(ctx, hash, 32);
    topup_hash_u32(ctx, status);
    topup_hash_u32(ctx, file);
    topup_hash_u32(ctx, data);
    topup_hash_u32(ctx, undo);
    topup_hash_u32(ctx, ntx);
}

static int topup_map_hash_cmp(const void *a, const void *b)
{
    const struct block_index *const *x = a, *const *y = b;
    if (!*x || !*y) return (*x != NULL) - (*y != NULL);
    return memcmp((*x)->hashBlock.data, (*y)->hashBlock.data, 32);
}

struct topup_row_hash { struct sha3_256_ctx ctx; int64_t count; };

static bool topup_hash_row(int height, const struct db_block *row, void *arg)
{
    struct topup_row_hash *h = arg;
    topup_hash_fields(&h->ctx, height, row->hash, (uint32_t)row->status,
                      (uint32_t)row->file_num, (uint32_t)row->data_pos,
                      (uint32_t)row->undo_pos, (uint32_t)row->num_tx);
    h->count++;
    return true;
}

static bool topup_clean_measure(struct main_state *ms, struct node_db *ndb,
                                int lo, int hi, struct topup_clean_mark *m)
{
    struct block_index **all = NULL;
    size_t n = 0;
    if (!block_map_snapshot_indices(&ms->map_block_index, &all, &n))
        return false; // raw-return-ok:caller treats a failed fingerprint as "no clean prefix" and folds the whole window
    size_t selected = 0;
    for (size_t i = 0; i < n; i++)
        if (all[i] && all[i]->nHeight >= lo && all[i]->nHeight <= hi)
            all[selected++] = all[i];
    if (selected > 1) qsort(all, selected, sizeof(*all), topup_map_hash_cmp);
    struct sha3_256_ctx map;
    sha3_256_init(&map);
    topup_hash_u32(&map, (uint32_t)lo);
    topup_hash_u32(&map, (uint32_t)hi);
    uint32_t count = 0;
    for (size_t i = 0; i < selected; i++) {
        const struct block_index *bi = all[i];
        if (!bi || bi->nHeight < lo || bi->nHeight > hi)
            continue;
        if (count == UINT32_MAX) { free(all); return false; }
        topup_hash_fields(&map, bi->nHeight, bi->hashBlock.data, bi->nStatus,
                          (uint32_t)bi->nFile, bi->nDataPos, bi->nUndoPos,
                          bi->nTx);
        count++;
    }
    free(all);
    m->lo = lo;
    m->clean_to = hi;
    m->map_count = count;
    topup_hash_u32(&map, count);
    sha3_256_finalize(&map, m->map_digest);
    struct topup_row_hash rows = {0};
    sha3_256_init(&rows.ctx);
    topup_hash_u32(&rows.ctx, (uint32_t)lo);
    topup_hash_u32(&rows.ctx, (uint32_t)hi);
    if (!db_block_scan_height_range_probe(ndb, lo, hi, topup_hash_row, &rows))
        return false; // raw-return-ok:caller refuses the clean mark and folds the full window
    m->row_count = rows.count;
    topup_hash_u32(&rows.ctx, (uint32_t)rows.count);
    sha3_256_finalize(&rows.ctx, m->row_digest);
    return true;
}

/* Why a stored mark does not fit this window before it is remeasured, or
 * NULL when it does. */
static const char *topup_clean_mark_unfit(const struct topup_clean_mark *got,
                                          const uint8_t anchor[32], int lo,
                                          int coins_best)
{
    if (got->version != NODE_DB_TOPUP_CLEAN_VERSION)
        return "older mark version";
    if (memcmp(got->anchor, anchor, 32) != 0)
        return "seed anchor changed";
    if (got->lo != lo)
        return "window start moved";
    if (got->clean_to < lo || got->clean_to >= coins_best)
        return "clean_to outside the window";
    return NULL;
}

/* Why the remeasured prefix differs from the stored mark, or NULL. */
static const char *topup_clean_mark_moved(const struct topup_clean_mark *got,
                                          const struct topup_clean_mark *now)
{
    if (now->map_count != got->map_count)
        return "map entry count changed";
    if (memcmp(now->map_digest, got->map_digest, sizeof(got->map_digest)))
        return "map entry fingerprint changed";
    if (now->row_count != got->row_count)
        return "node.db connected-row count changed";
    if (memcmp(now->row_digest, got->row_digest, sizeof(got->row_digest)))
        return "node.db row fingerprint changed";
    return NULL;
}

/* The first height still to fold: clean_to+1 when the stored prefix mark
 * re-verifies against the map and node.db, else `lo`. A refused mark prints
 * its reason, so a restart that folds the whole window says why. */
int topup_clean_resume(struct main_state *ms, struct node_db *ndb,
                              const uint8_t anchor[32], int lo, int coins_best,
                              bool *verified)
{
    struct topup_clean_mark got, now;
    size_t gn = 0;
    memset(&got, 0, sizeof(got));
    memset(&now, 0, sizeof(now));
    *verified = false;
    if (!node_db_state_get(ndb, NODE_DB_TOPUP_CLEAN_KEY, &got, sizeof(got),
                           &gn) || gn != sizeof(got)) {
        printf("[boot] block index top-up clean mark: none stored; folding %d..%d\n",
               lo, coins_best);
        return lo;
    }
    const char *why = topup_clean_mark_unfit(&got, anchor, lo, coins_best);
    if (!why)
        why = topup_clean_measure(ms, ndb, lo, got.clean_to, &now)
                  ? topup_clean_mark_moved(&got, &now)
                  : "prefix could not be remeasured";
    if (why) {
        printf("[boot] block index top-up clean mark: mark to %d refused (%s: "
               "map %u/%u rows %lld/%lld); folding %d..%d\n",
               got.clean_to, why, got.map_count, now.map_count,
               (long long)got.row_count, (long long)now.row_count, lo,
               coins_best);
        return lo;
    }
    *verified = true;
    printf("[boot] block index top-up clean mark: accepted through %d; resuming at %d\n",
           got.clean_to, got.clean_to + 1);
    return got.clean_to + 1;
}

void topup_clean_record(struct main_state *ms, struct node_db *ndb,
                               const uint8_t anchor[32], int lo,
                               int coins_best, bool fold_was_noop, bool verified,
                               int verified_to)
{
    if (!fold_was_noop && verified) return;
    const int clean_to = coins_best - NODE_DB_TOPUP_CLEAN_MARGIN;
    /* The same transaction and cs_main protect verification and the no-op
     * fold. The existing mark already binds exactly this unchanged prefix. */
    if (fold_was_noop && verified && verified_to == clean_to) return;
    struct topup_clean_mark m;
    memset(&m, 0, sizeof(m));
    if (!fold_was_noop || clean_to < lo ||
        !topup_clean_measure(ms, ndb, lo, clean_to, &m)) {
        (void)node_db_state_delete(ndb, NODE_DB_TOPUP_CLEAN_KEY);
        printf("[boot] block index top-up clean mark: none recorded (%s)\n",
               !fold_was_noop ? "the fold changed rows or missed a connected row"
               : clean_to < lo ? "window shorter than the margin"
                               : "prefix could not be measured");
        return;
    }
    memcpy(m.anchor, anchor, 32);
    m.version = NODE_DB_TOPUP_CLEAN_VERSION;
    if (!node_db_state_set(ndb, NODE_DB_TOPUP_CLEAN_KEY, &m, sizeof(m)))
        printf("[boot] block index top-up clean mark: mark to %d could not be stored\n",
               clean_to);
}

