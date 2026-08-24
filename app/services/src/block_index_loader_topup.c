/* Copyright 2026 Rhett Creighton - Apache License 2.0 */
// one-result-type-ok:loader-bool-contract — same bool surface as the
// sibling block_index_loader_rebuild.c loaders; every failure path logs
// its reason via LOG_FAIL before returning.
/*
 * Block Index Loader: projection top-up for the NORMAL boot path.
 *
 * The flat/LevelDB block-index loaders only know what was persisted at
 * the LAST boot-time save.
 * Every block connected after that save mutates its in-memory entry
 * only (reducer ingest / body_persist set HAVE_DATA + nFile/nDataPos
 * + nTx in RAM); the durable record of those mutations is the
 * EV_BLOCK_HEADER event log folded into block_index_projection (WAL,
 * crash-safe). Nothing read it back on a normal boot, so every restart
 * dropped the active chain to the stale flat-file extent and re-chased
 * a window of blocks whose bodies were already on disk.
 *
 * block_index_projection_topup() closes that loop: after the legacy
 * loaders run, fold the projection over the loaded map RAISE-ONLY —
 * apply HAVE_DATA + file positions an entry lacks, raise nTx and the
 * BLOCK_VALID level, insert entries the loaders never saw, and link
 * their pprev. Rows whose recorded height disagrees with the loaded
 * entry's height are refused loudly (label conflicts are surfaced,
 * never merged). FAILED bits are never copied (boot clears them).
 *
 * Legacy rows emitted before body persist learned to stamp nTx carry
 * n_tx=0; for those (HAVE_DATA + valid position + nTx==0) the tx count
 * is recovered from the block file itself, hash-bound to the entry.
 * The caller's existing nChainTx propagation pass (config/src/boot.c)
 * runs immediately after this top-up and turns the recovered nTx into
 * a connected nChainTx chain, which is what the single-pass boot scan
 * and the active-chain rebuild key on. */

#include "services/block_index_loader.h"
#include "chain/chain.h"
#include "chain/pow.h"
#include "core/arith_uint256.h"
#include "core/uint256.h"
#include "primitives/block.h"
#include "storage/block_index_db.h"
#include "storage/block_index_projection.h"
#include "storage/coins_kv.h"
#include "storage/disk_block_io.h"
#include "storage/progress_store.h"
#include "validation/chainstate.h"
#include "validation/main_state.h"
#include "jobs/block_header_emit.h"
#include "models/database.h"
#include "models/block.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "util/boot_phase.h"
#include "util/log_macros.h"
#include "util/safe_alloc.h"

/* Hard ceiling on per-boot disk reads for legacy-row nTx recovery. One
 * cold-import window is ~5.5-7k blocks; this is an order of magnitude
 * above that. Hitting it is logged loudly (no silent caps). */
#define TOPUP_NTX_RECOVERY_MAX 50000

struct topup_ctx {
    struct main_state *ms;
    size_t rows;
    size_t inserted;
    size_t data_applied;
    size_t ntx_applied;
    size_t valid_raised;
    size_t height_conflicts;
    size_t stubs_hydrated;
    /* Inserted entries, collected for the bounded chainwork pass. */
    struct block_index **new_entries;
    size_t new_count;
    size_t new_cap;
    bool failed;
};

static bool topup_track_inserted(struct topup_ctx *c,
                                 struct block_index *bi)
{
    if (c->new_count == c->new_cap) {
        size_t cap = c->new_cap ? c->new_cap * 2 : 256;
        struct block_index **grown = zcl_realloc(
            c->new_entries, cap * sizeof(*grown), "topup.new_entries");
        if (!grown)
            LOG_FAIL("block_index",
                     "topup: realloc failed at %zu inserted entries",
                     c->new_count);
        c->new_entries = grown;
        c->new_cap = cap;
    }
    c->new_entries[c->new_count++] = bi;
    return true;
}

/* Fold one projection row into the map, raise-only. */
static bool topup_row_cb(const uint8_t hash[32],
                         const struct disk_block_index *dbi,
                         void *user)
{
    struct topup_ctx *c = (struct topup_ctx *)user;
    c->rows++;
    if ((c->rows % 4096u) == 0)
        boot_progress_note("block_index.projection_topup", c->rows, 0);

    struct uint256 h;
    memcpy(h.data, hash, 32);

    struct block_index *bi = block_map_find(&c->ms->map_block_index, &h);
    if (!bi) {
        /* The loaders never saw this block (connected after the last
         * flat save). Insert it with the projection's full record —
         * the position is an exact payload offset written by this node. */
        bi = chainstate_insert_block_index((struct chainstate *)c->ms, &h);
        if (!bi) {
            c->failed = true;
            return false;
        }
        bi->nHeight              = dbi->nHeight;
        bi->nFile                = dbi->nFile;
        bi->nDataPos             = dbi->nDataPos;
        bi->nUndoPos             = dbi->nUndoPos;
        bi->nVersion             = dbi->nVersion;
        bi->hashMerkleRoot       = dbi->hashMerkleRoot;
        bi->hashFinalSaplingRoot = dbi->hashFinalSaplingRoot;
        bi->nTime                = dbi->nTime;
        bi->nBits                = dbi->nBits;
        bi->nNonce               = dbi->nNonce;
        bi->nSolution            = NULL;  /* not retained in RAM */
        bi->nSolutionSize        = 0;
        bi->nStatus              = dbi->nStatus & ~BLOCK_FAILED_MASK;
        bi->nCachedBranchId      = dbi->nCachedBranchId;
        bi->nTx                  = dbi->nTx;
        if (dbi->has_sprout_value) {
            bi->nSproutValue     = dbi->nSproutValue;
            bi->has_sprout_value = true;
        }
        bi->nSaplingValue        = dbi->nSaplingValue;
        c->inserted++;
        if (!topup_track_inserted(c, bi)) {
            c->failed = true;
            return false;
        }
        return true;
    }

    /* Same hash at a different recorded height: usually a label conflict
     * (the loaded entry wins; surface it, never merge) — EXCEPT when the
     * loaded entry is a contentless STUB: nBits==0 (no real header ever
     * has that), no HAVE_DATA, no nTx. Such an entry is a corrupt-load
     * artifact (flat-file reload placed the hash at height 0), not a
     * competing label; refusing the projection's full crash-safe record
     * here is what BIRTHS the boot placeholder tip — coins_best resolves
     * to the stub, the restore rewinds one height, and the node degrades
     * for a whole boot. Adopt
     * the projection row wholesale and track the entry like an insert so
     * the pprev-link + chainwork pass below covers it. */
    if (bi->nHeight != dbi->nHeight) {
        bool stub = bi->nBits == 0 &&
                    !(bi->nStatus & BLOCK_HAVE_DATA) &&
                    bi->nTx == 0;
        bool row_real = dbi->nHeight > 0 && dbi->nBits != 0;
        if (stub && row_real) {
            int stub_h = bi->nHeight;
            bi->nHeight              = dbi->nHeight;
            bi->nFile                = dbi->nFile;
            bi->nDataPos             = dbi->nDataPos;
            bi->nUndoPos             = dbi->nUndoPos;
            bi->nVersion             = dbi->nVersion;
            bi->hashMerkleRoot       = dbi->hashMerkleRoot;
            bi->hashFinalSaplingRoot = dbi->hashFinalSaplingRoot;
            bi->nTime                = dbi->nTime;
            bi->nBits                = dbi->nBits;
            bi->nNonce               = dbi->nNonce;
            bi->nStatus              = dbi->nStatus & ~BLOCK_FAILED_MASK;
            bi->nCachedBranchId      = dbi->nCachedBranchId;
            bi->nTx                  = dbi->nTx;
            if (dbi->has_sprout_value) {
                bi->nSproutValue     = dbi->nSproutValue;
                bi->has_sprout_value = true;
            }
            bi->nSaplingValue        = dbi->nSaplingValue;
            bi->pprev                = NULL;   /* re-linked below */
            bi->pskip                = NULL;
            c->stubs_hydrated++;
            if (c->stubs_hydrated <= 3)
                LOG_INFO("block_index",
                         "topup: hydrated contentless stub (loaded h=%d "
                         "nBits=0) from projection row h=%d",
                         stub_h, dbi->nHeight);
            if (!topup_track_inserted(c, bi)) {
                c->failed = true;
                return false;
            }
            return true;
        }
        if (c->height_conflicts < 3)
            LOG_WARN("block_index",
                     "topup: projection row height %d != loaded entry "
                     "height %d for the same hash — refusing merge",
                     dbi->nHeight, bi->nHeight);
        c->height_conflicts++;
        return true;
    }

    /* Data availability: apply HAVE_DATA + positions the entry lacks. */
    if ((dbi->nStatus & BLOCK_HAVE_DATA) &&
        !(bi->nStatus & BLOCK_HAVE_DATA) && dbi->nFile >= 0) {
        bi->nFile = dbi->nFile;
        bi->nDataPos = dbi->nDataPos;
        bi->nStatus |= BLOCK_HAVE_DATA;
        if (dbi->nStatus & BLOCK_HAVE_UNDO) {
            bi->nUndoPos = dbi->nUndoPos;
            bi->nStatus |= BLOCK_HAVE_UNDO;
        }
        c->data_applied++;
    }

    /* nTx: raise from zero only. */
    if (bi->nTx == 0 && dbi->nTx > 0) {
        bi->nTx = dbi->nTx;
        c->ntx_applied++;
    }

    /* Validity level: the projection may carry a HIGHER validated level
     * (script_validate re-emits after raising it). Raise-only; FAILED
     * bits are never copied. */
    {
        unsigned int cur_lvl = bi->nStatus & BLOCK_VALID_MASK;
        unsigned int row_lvl = dbi->nStatus & BLOCK_VALID_MASK;
        if (row_lvl > cur_lvl) {
            bi->nStatus = (bi->nStatus & ~BLOCK_VALID_MASK) | row_lvl;
            c->valid_raised++;
        }
    }

    return true;
}

/* Second pass: link pprev for entries this top-up inserted. Re-iterates
 * the projection (hashPrev is not retained on the in-memory entry);
 * pre-existing entries keep their loader-resolved pprev. */
static bool topup_link_pprev_cb(const uint8_t hash[32],
                                const struct disk_block_index *dbi,
                                void *user)
{
    struct main_state *ms = (struct main_state *)user;

    if (uint256_is_null(&dbi->hashPrev))
        return true;  /* genesis / no parent */

    struct uint256 h;
    memcpy(h.data, hash, 32);
    struct block_index *bi = block_map_find(&ms->map_block_index, &h);
    if (!bi || bi->pprev)
        return true;

    struct block_index *pprev = block_map_find(&ms->map_block_index,
                                               &dbi->hashPrev);
    if (pprev)
        bi->pprev = pprev;
    return true;
}

static int topup_cmp_height(const void *a, const void *b)
{
    const struct block_index *pa = *(const struct block_index *const *)a;
    const struct block_index *pb = *(const struct block_index *const *)b;
    if (pa->nHeight < pb->nHeight) return -1; // raw-return-ok:qsort-comparator
    if (pa->nHeight > pb->nHeight) return 1;
    return 0;
}

/* Bounded chainwork pass over JUST the inserted entries (height ASC, so
 * an inserted parent is computed before its inserted child). Pre-existing
 * entries already carry loader-computed work; the global boot passes are
 * not re-run here. */
static void topup_compute_inserted_chainwork(struct topup_ctx *c)
{
    if (c->new_count == 0)
        return;
    qsort(c->new_entries, c->new_count, sizeof(*c->new_entries),
          topup_cmp_height);
    for (size_t i = 0; i < c->new_count; i++) {
        struct block_index *bi = c->new_entries[i];
        struct arith_uint256 proof = GetBlockProof(bi);
        if (bi->pprev)
            arith_uint256_add(&bi->nChainWork, &bi->pprev->nChainWork,
                              &proof);
        else
            bi->nChainWork = proof;
        block_index_build_skip(bi);
    }
}

/* Legacy-row nTx recovery: entries with a verified body on disk but
 * nTx==0 (their EV_BLOCK_HEADER was emitted before body persist learned
 * to stamp nTx) break the caller's nChainTx propagation right at the
 * connected window. Read each such block back, hash-bind it to the
 * entry, and recover the tx count from the body itself. */
static void topup_recover_ntx_from_disk(struct main_state *ms,
                                        const char *datadir,
                                        size_t *recovered_out,
                                        size_t *unreadable_out,
                                        size_t *capped_out)
{
    size_t recovered = 0, unreadable = 0, capped = 0;
    size_t iter = 0;
    struct block_index *bi;
    while (block_map_next(&ms->map_block_index, &iter, NULL, &bi)) {
        if (!bi || bi->nTx != 0 || bi->nHeight <= 0)
            continue;
        if (!(bi->nStatus & BLOCK_HAVE_DATA) ||
            bi->nFile < 0 || bi->nDataPos == 0 || !bi->phashBlock)
            continue;
        if (recovered + unreadable >= TOPUP_NTX_RECOVERY_MAX) {
            capped++;
            continue;
        }
        boot_progress_note("block_index.topup_ntx_recovery",
                           recovered + unreadable + 1,
                           TOPUP_NTX_RECOVERY_MAX);
        struct block blk;
        block_init(&blk);
        if (read_block_from_disk_index_pread(&blk, bi, datadir)) {
            struct uint256 got;
            block_get_hash(&blk, &got);
            if (uint256_eq(&got, bi->phashBlock) && blk.num_vtx > 0) {
                bi->nTx = (unsigned int)blk.num_vtx;
                recovered++;
                /* Re-emit so the projection row self-corrects: the next
                 * boot's catch_up folds the real nTx and this disk read
                 * is never paid again for this block. */
                block_index_emit_header_event(bi, "topup_ntx_recovery",
                                              NULL, NULL);
            } else {
                unreadable++;  /* wrong block at the position — leave 0 */
            }
        } else {
            unreadable++;
        }
        block_free(&blk);
    }
    *recovered_out = recovered;
    *unreadable_out = unreadable;
    *capped_out = capped;
}

bool block_index_projection_topup_with(struct block_index_projection *bip,
                                       struct main_state *ms,
                                       const char *datadir)
{
    if (!ms)
        LOG_FAIL("block_index", "topup: null main_state");
    if (!bip)
        return true;  /* no projection on this datadir — nothing to fold */

    printf("[boot] block index projection top-up begin\n");
    fflush(stdout);
    boot_progress_note("block_index.projection_topup", 0, 0);

    /* Drain any events the prior process lifetime appended but never
     * consumed (live emits queue in the log; the projection only folds
     * at catch_up). Idempotent. */
    if (block_index_projection_catch_up(bip) == (uint64_t)-1)
        LOG_FAIL("block_index", "topup: projection catch_up failed");

    struct topup_ctx ctx = { .ms = ms };
    if (block_index_projection_iterate(bip, topup_row_cb, &ctx) != 0 ||
        ctx.failed) {
        free(ctx.new_entries);
        LOG_FAIL("block_index", "topup: projection iterate failed after "
                 "%zu rows", ctx.rows);
    }

    if (ctx.inserted > 0 || ctx.stubs_hydrated > 0) {
        if (block_index_projection_iterate(bip, topup_link_pprev_cb, ms)
                != 0) {
            free(ctx.new_entries);
            LOG_FAIL("block_index", "topup: pprev link iterate failed");
        }
        topup_compute_inserted_chainwork(&ctx);
    }
    free(ctx.new_entries);

    /* A hydrated stub carried nChainWork==0 while it was a detached
     * height-0 root, so any PRE-EXISTING entries loaded ABOVE it (flat
     * header-only children) have cumulative work collapsed through the
     * zero — and nothing downstream recomputes them (the inserted-entry
     * pass covers only new entries; block_index_repair_* work passes are
     * gated on height/pprev repairs, which hydration makes consistent).
     * Collapsed descendant work pins best_header at the hydrated block —
     * is_canonical_header_successor fails on work AND height and the fold
     * stalls until the next boot's flat-load forward pass (a two-boot
     * heal, the class P6/P7 exist to kill). Re-run the CANONICAL forward
     * pass over the whole map — the same helper every loader uses — so
     * descendants get true cumulative work in the same boot. Rare path
     * (stubs_hydrated > 0 only): one sort + walk, seconds at boot. */
    if (ctx.stubs_hydrated > 0) {
        size_t total = block_map_count(&ms->map_block_index);
        struct block_index **sorted = total
            ? zcl_malloc(total * sizeof(*sorted), "topup.forward_pass")
            : NULL;
        if (sorted) {
            size_t n = 0, it = 0;
            struct block_index *e;
            while (block_map_next(&ms->map_block_index, &it, NULL, &e)) {
                if (e && e->phashBlock && n < total)
                    sorted[n++] = e;
            }
            qsort(sorted, n, sizeof(*sorted), topup_cmp_height);
            block_index_forward_pass(sorted, n);
            free(sorted);
            printf("[boot] topup: global forward pass after %zu stub "
                   "hydration(s) — %zu entries recomputed\n",
                   ctx.stubs_hydrated, n);
        } else {
            LOG_WARN("block_index",
                     "topup: forward-pass alloc failed after %zu stub "
                     "hydration(s) (%zu entries) — descendant chainwork may "
                     "be collapsed until the next boot",
                     ctx.stubs_hydrated, total);
        }
    }

    size_t ntx_recovered = 0, ntx_unreadable = 0, ntx_capped = 0;
    if (datadir && datadir[0])
        topup_recover_ntx_from_disk(ms, datadir, &ntx_recovered,
                                    &ntx_unreadable, &ntx_capped);

    if (ctx.inserted || ctx.data_applied || ctx.ntx_applied ||
        ctx.valid_raised || ctx.height_conflicts || ctx.stubs_hydrated ||
        ntx_recovered || ntx_unreadable || ntx_capped) {
        printf("[boot] block index projection top-up: rows=%zu "
               "inserted=%zu data_applied=%zu ntx_applied=%zu "
               "valid_raised=%zu ntx_recovered_from_disk=%zu "
               "ntx_unreadable=%zu height_conflicts=%zu "
               "stubs_hydrated=%zu\n",
               ctx.rows, ctx.inserted, ctx.data_applied, ctx.ntx_applied,
               ctx.valid_raised, ntx_recovered, ntx_unreadable,
               ctx.height_conflicts, ctx.stubs_hydrated);
        if (ntx_capped > 0)
            LOG_WARN("block_index",
                     "topup: nTx disk recovery CAPPED at %d reads — "
                     "%zu entries left unrecovered this boot",
                     TOPUP_NTX_RECOVERY_MAX, ntx_capped);
    }
    return true;
}

bool block_index_projection_topup(struct main_state *ms, const char *datadir)
{
    return block_index_projection_topup_with(
        block_index_projection_singleton(), ms, datadir);
}

/* ── node.db forward-extent top-up (cold-import restart-fragility) ──────── */

/* Hard ceiling on the per-boot window the node.db top-up will fold. One
 * forward-sync window above a cold-import seed anchor is hundreds of blocks;
 * this is two orders of magnitude above that. The scan is ALWAYS bounded to
 * [H_seed+1 .. coins_best] — this only guards against an absurd
 * coins_best/seed pair (which is logged, not silently truncated). */
#define NODE_DB_TOPUP_WINDOW_MAX 200000

/* Copy the durable, body-backed db_block fields into a freshly-inserted
 * block_index entry, RAISE-ONLY. db_block_find_by_height already filtered to
 * status>=3 (connected / body-backed), so a returned row is a real, prev-linked
 * window block. FAILED bits are never copied (boot clears them anyway). pprev
 * is NOT set here — the caller links it after the whole window is in the map. */
static void node_db_topup_fill_new(struct block_index *bi,
                                   const struct db_block *blk,
                                   int height)
{
    bi->nHeight        = height;
    bi->nFile          = blk->file_num;
    bi->nDataPos       = (unsigned int)blk->data_pos;
    bi->nUndoPos       = (unsigned int)blk->undo_pos;
    bi->nVersion       = blk->version;
    memcpy(bi->hashMerkleRoot.data, blk->merkle_root, 32);
    memcpy(bi->hashFinalSaplingRoot.data, blk->sapling_root, 32);
    bi->nTime          = blk->time;
    bi->nBits          = blk->bits;
    memcpy(bi->nNonce.data, blk->nonce, 32);
    bi->nSolution      = NULL;  /* not retained in RAM */
    bi->nSolutionSize  = 0;
    /* status>=3 == connected; carry VALID bits + data availability, never a
     * FAILED bit. The block is body-backed on disk (file_num/data_pos), so
     * HAVE_DATA is asserted explicitly rather than trusted from the stored
     * status (which on some legacy rows omits the bit). */
    bi->nStatus        = (unsigned int)(blk->status & ~BLOCK_FAILED_MASK);
    if (blk->file_num >= 0)
        bi->nStatus |= BLOCK_HAVE_DATA;
    if (blk->num_tx > 0)
        bi->nTx = (unsigned int)blk->num_tx;
    bi->nSaplingValue  = blk->sapling_value;
    if (blk->sprout_value != 0) {
        bi->nSproutValue = blk->sprout_value;
        bi->has_sprout_value = true;
    }
}

bool block_index_node_db_topup_with(struct main_state *ms,
                                    struct node_db *ndb,
                                    struct sqlite3 *progress_db,
                                    const char *datadir)
{
    if (!ms)
        LOG_FAIL("block_index", "node.db topup: null main_state");
    if (!ndb || !ndb->open)
        return true;   /* no node.db this datadir — nothing to fold */
    if (!progress_db)
        return true;   /* no coins authority handle — cannot bound the window */

    /* (1) Durable cold-import seed anchor present? Absent on EVERY normal /
     *     P2P-origin datadir (the producer only writes it in the ldb_import
     *     accepted branch). Strict no-op when missing/empty. */
    int64_t anchor_h = 0;
    if (!node_db_state_get_int(ndb, "cold_import_seed_anchor_height",
                               &anchor_h))
        return true;                          /* never cold-imported here */
    if (anchor_h <= 0 || anchor_h > INT32_MAX)
        return true;
    uint8_t anchor_hash[32];
    size_t hn = 0;
    if (!node_db_state_get(ndb, "cold_import_seed_anchor_hash",
                           anchor_hash, sizeof(anchor_hash), &hn) ||
        hn != sizeof(anchor_hash))
        return true;
    const int H_seed = (int)anchor_h;

    /* INTEGRITY: the seed anchor block must be held in the map at exactly
     * H_seed — the same provenance binding block_index_loader_rebuild.c uses.
     * If we don't hold the anchor we don't trust the window above it. */
    struct uint256 ah;
    memcpy(ah.data, anchor_hash, 32);
    struct block_index *anchor = block_map_find(&ms->map_block_index, &ah);
    if (!anchor || anchor->nHeight != H_seed) {
        LOG_WARN("block_index",
                 "node.db topup: cold-import seed anchor not held at H=%d "
                 "(found=%d); skipping forward-extent fold",
                 H_seed, anchor ? anchor->nHeight : -1);
        return true;
    }

    /* (2) coins_best height == coins_applied_height - 1 (the utxo_apply
     *     cursor convention). This is the durable forward tip the window
     *     must reach. Absent on a fresh datadir → no-op. */
    int32_t applied = 0;
    bool applied_found = false;
    if (!coins_kv_get_applied_height(progress_db, &applied, &applied_found)) {
        LOG_WARN("block_index",
                 "node.db topup: coins applied-height read failed; "
                 "skipping forward-extent fold");
        return true;
    }
    if (!applied_found)
        return true;                          /* no coins frontier yet */
    const int coins_best = (int)applied - 1;
    if (coins_best <= H_seed)
        return true;                          /* nothing forward of the seed */

    int window = coins_best - H_seed;
    if (window > NODE_DB_TOPUP_WINDOW_MAX) {
        LOG_WARN("block_index",
                 "node.db topup: forward window %d..%d (=%d blocks) exceeds "
                 "the %d cap; folding only the top %d — a larger gap means "
                 "the active chain is not at the coins frontier",
                 H_seed + 1, coins_best, window, NODE_DB_TOPUP_WINDOW_MAX,
                 NODE_DB_TOPUP_WINDOW_MAX);
        window = NODE_DB_TOPUP_WINDOW_MAX;
    }
    const int lo = coins_best - window + 1;    /* == H_seed+1 (uncapped) */

    /* (3) Fold [lo .. coins_best] from node.db `blocks` raise-only. Insert
     *     missing entries (pprev linked in a second pass once the whole
     *     window is present), apply HAVE_DATA + positions an entry lacks,
     *     raise nTx + the BLOCK_VALID level. db_block_find_by_height filters
     *     status>=3 so a row is body-backed/connected; a missing/non-connected
     *     height is skipped (the window simply has a hole there). */
    size_t inserted = 0, data_applied = 0, ntx_applied = 0, valid_raised = 0;
    size_t height_conflicts = 0, missing_rows = 0;

    /* Inserted entries, height-ASC by construction (we iterate ascending),
     * collected for the bounded chainwork + skip pass. */
    struct block_index **new_entries = NULL;
    size_t new_count = 0, new_cap = 0;

    for (int h = lo; h <= coins_best; h++) {
        struct db_block blk;
        if (!db_block_find_by_height(ndb, h, &blk)) {
            missing_rows++;
            continue;
        }
        struct uint256 hh;
        memcpy(hh.data, blk.hash, 32);

        struct block_index *bi = block_map_find(&ms->map_block_index, &hh);
        if (!bi) {
            bi = chainstate_insert_block_index((struct chainstate *)ms, &hh);
            if (!bi) {
                free(new_entries);
                LOG_FAIL("block_index",
                         "node.db topup: insert failed at h=%d", h);
            }
            node_db_topup_fill_new(bi, &blk, h);
            inserted++;
            if (new_count == new_cap) {
                size_t cap = new_cap ? new_cap * 2 : 256;
                struct block_index **grown = zcl_realloc(
                    new_entries, cap * sizeof(*grown),
                    "node_db_topup.new_entries");
                if (!grown) {
                    free(new_entries);
                    LOG_FAIL("block_index",
                             "node.db topup: realloc failed at %zu entries",
                             new_count);
                }
                new_entries = grown;
                new_cap = cap;
            }
            new_entries[new_count++] = bi;
            continue;
        }

        /* Same hash at a different recorded height: a label conflict. The
         * loaded entry wins; surface it, never merge. */
        if (bi->nHeight != h) {
            if (height_conflicts < 3)
                LOG_WARN("block_index",
                         "node.db topup: blocks row height %d != loaded "
                         "entry height %d for the same hash — refusing merge",
                         h, bi->nHeight);
            height_conflicts++;
            continue;
        }

        /* Data availability: apply HAVE_DATA + positions the entry lacks. */
        if (blk.file_num >= 0 && !(bi->nStatus & BLOCK_HAVE_DATA)) {
            bi->nFile = blk.file_num;
            bi->nDataPos = (unsigned int)blk.data_pos;
            bi->nStatus |= BLOCK_HAVE_DATA;
            if (blk.undo_pos > 0) {
                bi->nUndoPos = (unsigned int)blk.undo_pos;
                bi->nStatus |= BLOCK_HAVE_UNDO;
            }
            data_applied++;
        }
        /* nTx: raise from zero only. */
        if (bi->nTx == 0 && blk.num_tx > 0) {
            bi->nTx = (unsigned int)blk.num_tx;
            ntx_applied++;
        }
        /* Validity level: raise-only, FAILED never copied. */
        {
            unsigned int cur_lvl = bi->nStatus & BLOCK_VALID_MASK;
            unsigned int row_lvl =
                (unsigned int)blk.status & BLOCK_VALID_MASK;
            if (row_lvl > cur_lvl) {
                bi->nStatus = (bi->nStatus & ~BLOCK_VALID_MASK) | row_lvl;
                valid_raised++;
            }
        }
    }

    /* (4) Second pass: link pprev for inserted entries (height ASC, so a
     *     parent inserted this run is already in the map), then compute
     *     chainwork + skip on top of the resolved parent. The seed anchor
     *     and the contiguous chain below it are already in the map, so the
     *     bottom of the window links onto the seed anchor — which is exactly
     *     what stops the seed anchor being an orphan tip. */
    size_t linked = 0;
    for (size_t i = 0; i < new_count; i++) {
        struct block_index *bi = new_entries[i];
        if (!bi->pprev) {
            /* prev_hash from the durable row — re-read once (cheap; bounded
             * to the inserted set). */
            struct db_block blk;
            if (db_block_find_by_height(ndb, bi->nHeight, &blk)) {
                struct uint256 ph;
                memcpy(ph.data, blk.prev_hash, 32);
                struct block_index *pprev =
                    block_map_find(&ms->map_block_index, &ph);
                if (pprev) {
                    bi->pprev = pprev;
                    linked++;
                }
            }
        }
        struct arith_uint256 proof = GetBlockProof(bi);
        if (bi->pprev)
            arith_uint256_add(&bi->nChainWork, &bi->pprev->nChainWork, &proof);
        else
            bi->nChainWork = proof;
        block_index_build_skip(bi);
    }
    free(new_entries);

    if (inserted || data_applied || ntx_applied || valid_raised ||
        height_conflicts) {
        printf("[boot] block index node.db top-up: window=%d..%d "
               "inserted=%zu linked=%zu data_applied=%zu ntx_applied=%zu "
               "valid_raised=%zu height_conflicts=%zu missing_rows=%zu\n",
               lo, coins_best, inserted, linked, data_applied, ntx_applied,
               valid_raised, height_conflicts, missing_rows);
    }
    (void)datadir;  /* reserved for a future on-disk re-verify pass */
    return true;
}

bool block_index_node_db_topup(struct main_state *ms,
                               struct node_db *ndb,
                               const char *datadir)
{
    return block_index_node_db_topup_with(ms, ndb, progress_store_db(),
                                          datadir);
}
