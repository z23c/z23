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
 * The caller's existing nChainTx propagation pass (engine/composition/src/boot.c)
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

/* ── Undo metadata top-up: one (nFile, nUndoPos) address, ONE source ──
 *
 * Both loader top-ups used to apply a row's undo position only from inside
 * their `!(nStatus & BLOCK_HAVE_DATA)` branch, so an entry that already had
 * HAVE_DATA but no HAVE_UNDO could never be repaired however good its row
 * was — exactly the shape a header-only snapshot import leaves behind (real
 * nFile/nDataPos restored, nUndoPos 0), which then costs the background
 * validator every transparent script in the block for want of recoverable
 * spent outputs.
 *
 * The read path pairs the ENTRY's nFile with the ENTRY's nUndoPos
 * (block_index_undo_pos_snapshot, core/modules/chain/include/chain/chain.h),
 * so those two fields must always come from one source:
 *
 *   - the entry keeps its own nFile → RAISE-ONLY. An entry that already
 *     claims HAVE_UNDO keeps its own position; an entry that lacks it adopts
 *     the row's, and only when the row itself claims HAVE_UNDO and names a
 *     nonzero undo offset in that same (non-negative) block file.
 *   - the data branch adopted the ROW's nFile → the entry's own nUndoPos was
 *     recorded against the file that was just replaced, so keeping it would
 *     manufacture a (row file, entry pos) address — the exact mismatch the
 *     raise-only rule exists to prevent. Adopt the row's undo position when
 *     the row carries a coherent one; otherwise DROP HAVE_UNDO and the stale
 *     position rather than publish the mismatch.
 *
 * Every outcome is counted, refusals split by reason, so a boot summary that
 * reports undo_applied=0 also reports why. */
enum topup_undo_outcome {
    TOPUP_UNDO_APPLIED,         /* entry now carries the row's undo address  */
    TOPUP_UNDO_CLEARED,         /* stale (new file, old pos) pair dropped    */
    TOPUP_UNDO_REFUSED_HAVE,    /* entry already claims HAVE_UNDO            */
    TOPUP_UNDO_REFUSED_POS,     /* row names no usable undo offset           */
    TOPUP_UNDO_REFUSED_STATUS,  /* row does not claim HAVE_UNDO              */
    TOPUP_UNDO_REFUSED_FILE     /* row's undo lives in another block file    */
};

struct topup_undo_tally {
    size_t applied;
    size_t cleared;
    size_t refused_have;
    size_t refused_pos;
    size_t refused_status;
    size_t refused_file;
};

struct topup_ctx {
    struct main_state *ms;
    size_t rows;
    size_t inserted;
    size_t data_applied;
    struct topup_undo_tally undo;
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

/* A durable row's undo column is a SIGNED int. Guard the sign BEFORE the
 * cast: (unsigned int)(-1) is 0xFFFFFFFF, which passes a `!= 0` test and
 * would be stored as a real undo offset. db_block_save() validates
 * non-negative, but the raw-SQL writer in utxo_recovery_backfill.c does not,
 * so a negative column value is reachable and must be refused, not wrapped. */
static unsigned int topup_row_undo_pos(int row_undo_pos)
{
    return row_undo_pos > 0 ? (unsigned int)row_undo_pos : 0u;
}

/* HAVE_UNDO only with a usable position. Every path that copies a stored
 * status onto an entry verbatim must end here: a row claiming the bit with
 * nUndoPos 0 would otherwise publish (nFile, 0) as a rev address, which the
 * undo reader takes for a real one. Fail closed. */
static void topup_seal_undo_bit(struct block_index *bi)
{
    if (bi->nUndoPos == 0)
        bi->nStatus &= ~(unsigned int)BLOCK_HAVE_UNDO;
}

/* Why the row cannot be applied to an entry that keeps its own nFile, or
 * TOPUP_UNDO_APPLIED when it can. See the contract above topup_undo_tally. */
static enum topup_undo_outcome topup_undo_refusal(const struct block_index *bi,
                                                  bool row_has_undo,
                                                  int row_file,
                                                  unsigned int row_undo_pos)
{
    if (bi->nStatus & BLOCK_HAVE_UNDO)
        return TOPUP_UNDO_REFUSED_HAVE;
    if (row_undo_pos == 0)
        return TOPUP_UNDO_REFUSED_POS;
    if (!row_has_undo)
        return TOPUP_UNDO_REFUSED_STATUS;
    if (row_file < 0 || bi->nFile != row_file)
        return TOPUP_UNDO_REFUSED_FILE;
    return TOPUP_UNDO_APPLIED;
}

/* Apply a durable row's undo metadata, shared by both top-ups.
 * `file_adopted` is true when the caller's data branch just replaced the
 * entry's nFile with the row's — which invalidates any undo position the
 * entry recorded against the old file. Returns what happened, for the
 * per-reason tally. */
static enum topup_undo_outcome
topup_apply_undo(struct block_index *bi, bool file_adopted, bool row_has_undo,
                 int row_file, unsigned int row_undo_pos)
{
    enum topup_undo_outcome refusal =
        topup_undo_refusal(bi, row_has_undo, row_file, row_undo_pos);
    bool row_pair_ok = row_has_undo && row_undo_pos != 0 && row_file >= 0 &&
                       bi->nFile == row_file;

    if ((bi->nStatus & BLOCK_HAVE_UNDO) && file_adopted) {
        /* The entry's position belongs to the file we just replaced. */
        if (row_pair_ok) {
            bi->nUndoPos = row_undo_pos;
            return TOPUP_UNDO_APPLIED;
        }
        bi->nUndoPos = 0;
        bi->nStatus &= ~(unsigned int)BLOCK_HAVE_UNDO;
        return TOPUP_UNDO_CLEARED;
    }
    if (refusal != TOPUP_UNDO_APPLIED)
        return refusal;
    bi->nUndoPos = row_undo_pos;
    bi->nStatus |= BLOCK_HAVE_UNDO;
    return TOPUP_UNDO_APPLIED;
}

/* Record one outcome. Every path through topup_apply_undo() lands in exactly
 * one bucket, so applied + cleared + all four refusals == the number of rows
 * that REACHED topup_apply_undo() — not the rows= field of the boot summary
 * line. A scanned row can be answered before ever getting here: rows that
 * insert a new entry and rows refused for a height conflict return earlier,
 * and neither is tallied. Read the identity as a partition of the update
 * path, and never as a reconciliation against rows=. */
static void topup_undo_count(struct topup_undo_tally *t,
                             enum topup_undo_outcome outcome)
{
    switch (outcome) {
    case TOPUP_UNDO_APPLIED:        t->applied++;        break;
    case TOPUP_UNDO_CLEARED:        t->cleared++;        break;
    case TOPUP_UNDO_REFUSED_HAVE:   t->refused_have++;   break;
    case TOPUP_UNDO_REFUSED_POS:    t->refused_pos++;    break;
    case TOPUP_UNDO_REFUSED_STATUS: t->refused_status++; break;
    case TOPUP_UNDO_REFUSED_FILE:   t->refused_file++;   break;
    }
}

/* Refusals that mean a row could NOT be used. refused_have is excluded: it
 * is the normal raise-only no-op on a healthy entry and would otherwise put
 * the summary line on every boot of every node. */
static size_t topup_undo_unusable(const struct topup_undo_tally *t)
{
    return t->refused_pos + t->refused_status + t->refused_file;
}

/* Anything about position metadata this run that is worth a summary line. */
static size_t topup_undo_events(const struct topup_undo_tally *t)
{
    return t->applied + t->cleared + topup_undo_unusable(t);
}

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
        topup_seal_undo_bit(bi);
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
            topup_seal_undo_bit(bi);
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
    bool file_adopted = false;
    if ((dbi->nStatus & BLOCK_HAVE_DATA) &&
        !(bi->nStatus & BLOCK_HAVE_DATA) && dbi->nFile >= 0) {
        file_adopted = bi->nFile != dbi->nFile;
        bi->nFile = dbi->nFile;
        bi->nDataPos = dbi->nDataPos;
        bi->nStatus |= BLOCK_HAVE_DATA;
        c->data_applied++;
    }

    /* Undo availability, INDEPENDENT of the HAVE_DATA branch above — see
     * topup_apply_undo() for why that independence is the whole fix, and
     * why an nFile the branch just replaced invalidates the entry's own
     * undo position. */
    topup_undo_count(&c->undo,
                     topup_apply_undo(bi, file_adopted,
                                      (dbi->nStatus & BLOCK_HAVE_UNDO) != 0,
                                      dbi->nFile, dbi->nUndoPos));

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
    struct block_index_flat_identity identity;
    bool have_identity = block_index_flat_verified_identity(datadir,
                                                             &identity);
    int iter_rc = 0;
    bool bounded = false;
    if (have_identity) {
        iter_rc = block_index_projection_iterate_dirty_if_bound(
            bip, identity.payload_sha3, identity.payload_size,
            identity.row_count, topup_row_cb, &ctx);
        bounded = iter_rc == 1;
    }
    if (!bounded && iter_rc >= 0)
        iter_rc = block_index_projection_iterate_storage_order(
            bip, topup_row_cb, &ctx);
    if (iter_rc < 0 || ctx.failed) {
        free(ctx.new_entries);
        LOG_FAIL("block_index", "topup: projection iterate failed after "
                 "%zu rows", ctx.rows);
    }
    printf("[boot] block index projection top-up source=%s rows=%zu\n",
           bounded ? "bound-delta" : "full", ctx.rows);

    if (ctx.inserted > 0 || ctx.stubs_hydrated > 0) {
        int link_rc = bounded
            ? block_index_projection_iterate_dirty_if_bound(
                bip, identity.payload_sha3, identity.payload_size,
                identity.row_count, topup_link_pprev_cb, ms)
            : block_index_projection_iterate_storage_order(
                bip, topup_link_pprev_cb, ms);
        if (link_rc < 0) {
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

    /* One "position metadata happened" term: an application, a cleared
     * stale pair, or a row that could not be used is each worth the line. */
    size_t pos_events = ctx.data_applied + topup_undo_events(&ctx.undo);
    if (ctx.inserted || pos_events || ctx.ntx_applied ||
        ctx.valid_raised || ctx.height_conflicts || ctx.stubs_hydrated ||
        ntx_recovered || ntx_unreadable || ntx_capped) {
        printf("[boot] block index projection top-up: rows=%zu "
               "inserted=%zu data_applied=%zu undo_applied=%zu "
               "undo_cleared=%zu "
               "undo_refused=%zu(have=%zu,pos=%zu,status=%zu,file=%zu) "
               "ntx_applied=%zu "
               "valid_raised=%zu ntx_recovered_from_disk=%zu "
               "ntx_unreadable=%zu height_conflicts=%zu "
               "stubs_hydrated=%zu\n",
               ctx.rows, ctx.inserted, ctx.data_applied, ctx.undo.applied,
               ctx.undo.cleared,
               ctx.undo.refused_have + topup_undo_unusable(&ctx.undo),
               ctx.undo.refused_have, ctx.undo.refused_pos,
               ctx.undo.refused_status, ctx.undo.refused_file,
               ctx.ntx_applied,
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

bool block_index_projection_bind_saved_flat(
    struct block_index_projection *bip,
    const struct block_index_flat_identity *identity)
{
    return bip && identity && block_index_projection_bind_flat(
        bip, identity->payload_sha3, identity->payload_size,
        identity->row_count);
}

struct bound_tip_ctx {
    const uint8_t *hash;
    int32_t height;
    bool found;
};

static bool bound_tip_cb(const uint8_t hash[32],
                         const struct disk_block_index *idx, void *user)
{
    struct bound_tip_ctx *ctx = user;
    if (memcmp(hash, ctx->hash, 32) == 0 && idx->nHeight == ctx->height)
        ctx->found = true;
    return true;
}

bool block_index_projection_bound_covers_tip(
    struct block_index_projection *bip, const char *datadir,
    const uint8_t hash[32], int32_t height)
{
    if (!bip || !datadir || !hash || height < 0)
        return false;
    struct block_index_flat_identity identity;
    if (!block_index_flat_verified_identity(datadir, &identity))
        return false; // raw-return-ok:unverified flat is an expected cache miss
    struct bound_tip_ctx ctx = { .hash = hash, .height = height };
    int rc = block_index_projection_iterate_dirty_if_bound(
        bip, identity.payload_sha3, identity.payload_size,
        identity.row_count, bound_tip_cb, &ctx);
    return rc == 1 && ctx.found;
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
    bi->nUndoPos       = topup_row_undo_pos(blk->undo_pos);
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
    /* The stored status is carried verbatim above; seal the undo bit
     * against a row that claims it with undo_pos <= 0. */
    topup_seal_undo_bit(bi);
    if (blk->num_tx > 0)
        bi->nTx = (unsigned int)blk->num_tx;
    bi->nSaplingValue  = blk->sapling_value;
    if (blk->sprout_value != 0) {
        bi->nSproutValue = blk->sprout_value;
        bi->has_sprout_value = true;
    }
}

/* Does this durable row grant block-body metadata to an entry that lacks it?
 * The row must CLAIM data through its STATUS bit, exactly like the
 * projection top-up above — a file number alone claims nothing. A
 * header-only snapshot import writes rows with HAVE_DATA and HAVE_UNDO
 * stripped and file_num pinned to 0 (snapshot_controller_import.c), and its
 * contract is that every block-file read is gated on those bits. Adopting
 * that 0 would publish (file 0, data_pos) as a body address the node does
 * not have, AND count as a file change — which sends topup_apply_undo()
 * down its TOPUP_UNDO_CLEARED path and destroys a legitimate pre-existing
 * nUndoPos on a row that carries no data at all. Fail closed.
 *
 * node_db_topup_fill_new() above deliberately keeps asserting HAVE_DATA
 * from file_num alone, and the asymmetry is the point: an INSERT builds an
 * entry that held no metadata to destroy, and that path's legacy-row
 * tolerance is what lets a pre-bit row still be inserted body-backed. Only
 * this path can overwrite state the entry already owns. A legacy row that
 * omits the bit therefore grants nothing here — the entry simply keeps
 * fetching the body over P2P, which is what the projection top-up's
 * identical gate has always done. */
static bool node_db_row_grants_data(const struct db_block *blk,
                                    const struct block_index *bi)
{
    return ((unsigned int)blk->status & BLOCK_HAVE_DATA) != 0 &&
           blk->file_num >= 0 &&
           !(bi->nStatus & BLOCK_HAVE_DATA);
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
    struct topup_undo_tally undo;
    memset(&undo, 0, sizeof(undo));
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

        /* Data availability: apply HAVE_DATA + positions the entry lacks,
         * gated on the row's own status bit — see node_db_row_grants_data. */
        bool file_adopted = false;
        if (node_db_row_grants_data(&blk, bi)) {
            file_adopted = bi->nFile != blk.file_num;
            bi->nFile = blk.file_num;
            bi->nDataPos = (unsigned int)blk.data_pos;
            bi->nStatus |= BLOCK_HAVE_DATA;
            data_applied++;
        }
        /* Undo availability, independent of HAVE_DATA — same defect and
         * same fail-closed rules as the projection top-up above. The row
         * claims undo through its STATUS bit, exactly like the projection
         * site; file_num >= 0 is a separate sanity term on the address
         * half, checked inside topup_apply_undo(). */
        topup_undo_count(&undo,
            topup_apply_undo(bi, file_adopted,
                             ((unsigned int)blk.status & BLOCK_HAVE_UNDO) != 0,
                             blk.file_num,
                             topup_row_undo_pos(blk.undo_pos)));
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

    /* One "position metadata happened" term — see the projection top-up's
     * summary above. */
    size_t pos_events = data_applied + topup_undo_events(&undo);
    if (inserted || pos_events || ntx_applied ||
        valid_raised || height_conflicts) {
        printf("[boot] block index node.db top-up: window=%d..%d "
               "inserted=%zu linked=%zu data_applied=%zu undo_applied=%zu "
               "undo_cleared=%zu "
               "undo_refused=%zu(have=%zu,pos=%zu,status=%zu,file=%zu) "
               "ntx_applied=%zu "
               "valid_raised=%zu height_conflicts=%zu missing_rows=%zu\n",
               lo, coins_best, inserted, linked, data_applied, undo.applied,
               undo.cleared,
               undo.refused_have + topup_undo_unusable(&undo),
               undo.refused_have, undo.refused_pos, undo.refused_status,
               undo.refused_file,
               ntx_applied,
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
