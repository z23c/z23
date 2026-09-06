/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * boot_steps.c — the heavy leaves of the node's boot sequence.
 *
 * Part of the boot composition root. app_init (boot.c) is a list of named
 * phases, each a list of named steps; three of those steps carry enough
 * code that keeping them inline would push boot.c past its size
 * budget, so they live here:
 *
 *   - boot_blkidx_pull_legacy_zclassicd — import ancestry, the chain tip and
 *     block files from a legacy zclassicd LevelDB block index;
 *   - boot_post_scan_anchor_ladder — the legacy ladder that resolves
 *     coins_best_block after an on-disk block-file scan;
 *   - boot_sapling_tree_boot_load — load the Sapling commitment tree from
 *     the flat checkpoint or node_state and verify its root.
 *
 * Owns no state: every entry point takes the chain state, node.db handle,
 * coins view and datadir it works on as parameters, so boot.c keeps sole
 * ownership of those file-statics. See boot_steps_internal.h. */

#include "boot_steps_internal.h"

#include "platform/time_compat.h"
#include "config/boot_internal.h"
#include "config/boot_legacy_blocks.h"
#include "chain/pow.h"
#include "controllers/sync_controller.h"
#include "event/event.h"
#include "jobs/reducer_frontier.h"
#include "services/block_index_loader.h"
#include "services/chain_restore_boot_snapshot.h"
#include "services/chain_restore_executor.h"
#include "services/chain_restore_integrity.h"
#include "services/chain_restore_repair.h"
#include "services/chain_tip.h"
#include "validation/process_block.h"
#include "storage/ldb_snapshot.h"
#include "util/ar_step_readonly.h"
#include "util/log_macros.h"
#include "util/safe_alloc.h"

#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sqlite3.h>
#include <sys/stat.h>
#include <unistd.h>

bool boot_derive_coins_best(struct boot_derived_coins_best *out)
{
    memset(out, 0, sizeof(*out));
    out->height = -1;
    return reducer_frontier_derive_coins_best_now(&out->height, out->hash,
                                                  &out->hash_found);
}

/* Comparator for sorting block_index pointers by height (for qsort). */
static int cmp_block_index_height(const void *a, const void *b)
{
    const struct block_index *pa = *(const struct block_index **)a;
    const struct block_index *pb = *(const struct block_index **)b;
    return (pa->nHeight > pb->nHeight) - (pa->nHeight < pb->nHeight);
}
/* Callback for block_tree_db_load_block_index_guts — inserts a block
 * into the block map, reusing existing entry if hash already present. */
static struct block_index *boot_insert_block_index_cb(void *ctx_ptr,
                                                       const struct uint256 *hash)
{
    struct main_state *ms = (struct main_state *)ctx_ptr;
    return chainstate_insert_block_index((struct chainstate *)ms, hash);
}

/* Re-seed per-node hash storage and point phashBlock at it. */
static void boot_zcd_reseed_hash_pointers(struct main_state *st)
{
    /* Option A: re-seed per-node hash storage and point
     * phashBlock at it (boot_insert_block_index_cb ->
     * chainstate_insert_block_index already does this at
     * insert; idempotent re-assert here). Never points
     * into the reallocatable bucket array. */
    size_t iter2 = 0;
    struct block_index *pi2;
    const struct uint256 *hash2;
    while (block_map_next(&st->map_block_index,
                          &iter2, &hash2, &pi2))
        if (pi2 && hash2) {
            pi2->hashBlock = *hash2;
            pi2->phashBlock = &pi2->hashBlock;
        }
}

/* Forward pass over the height-sorted index: accumulate nChainWork and
 * nChainTx, and return the most-work valid tip. */
static struct block_index *boot_zcd_accumulate_chain_work(
    struct block_index **sorted, size_t n)
{
    /* Forward pass: compute nChainWork + nChainTx */
    struct block_index *best = NULL;
    for (size_t i = 0; i < n; i++) {
        struct block_index *b = sorted[i];
        struct arith_uint256 proof = GetBlockProof(b);
        if (b->pprev)
            arith_uint256_add(&b->nChainWork,
                &b->pprev->nChainWork, &proof);
        else
            b->nChainWork = proof;
        if (b->nTx > 0) {
            if (b->pprev && b->pprev->nChainTx > 0)
                b->nChainTx = b->pprev->nChainTx + b->nTx;
            else if (!b->pprev)
                b->nChainTx = b->nTx;
        }
        /* Track best valid chain tip */
        if (b->nChainTx > 0 &&
            (b->nStatus & BLOCK_HAVE_DATA) &&
            !(b->nStatus & BLOCK_FAILED_MASK)) {
            if (!best || arith_uint256_compare(
                    &b->nChainWork,
                    &best->nChainWork) > 0)
                best = b;
        }
    }
    return best;
}

/* Commit the imported best tip, unless our own derived coins frontier is
 * strictly above it (never commit the public tip backward). */
static void boot_zcd_promote_import_best(struct block_index *best,
                                         bool have_ndcb,
                                         struct boot_derived_coins_best ndcb)
{
    if (best && best->nHeight > 0) {
        int32_t zcd_best_h = best->nHeight;
        if (have_ndcb &&
            ndcb.height > zcd_best_h) {
            /* Our derived frontier is ahead of
             * zclassicd's index — do NOT commit the
             * tip backward. Ancestry is already
             * imported; the downstream restore
             * utxo_recovery_restore_chain_tip
             * (reason coins_best_restore, later in
             * this boot) promotes our real derived
             * tip from the same coins authority. */
            fprintf(stderr,
                "[boot] suppressing "
                "zclassicd_import_best tip commit: "
                "derived coins-best h=%d > zclassicd "
                "index-best h=%d (would commit tip "
                "backward below our frontier)\n",
                ndcb.height, zcd_best_h);
            event_emitf(EV_RECOVERY_ACTION, 0,
                "action=zcd_import_tip_suppressed "
                "derived=%d zcd_best=%d",
                ndcb.height, zcd_best_h);
        } else if (boot_promote_tip_via_csr(
                       best, "zclassicd_import_best",
                       false)) {
            printf("Chain tip from zclassicd: "
                   "height=%d nChainTx=%u\n",
                   best->nHeight, best->nChainTx);
        }
    }
}

/* Compute chain work + set the chain tip directly. This avoids the O(n^2)
 * find_most_work_chain scan, which is catastrophically slow with 3M entries. */
static void boot_zcd_set_chain_tip_from_work(struct main_state *st,
                                             bool have_ndcb,
                                             struct boot_derived_coins_best ndcb)
{
    size_t n = st->map_block_index.size;
    struct block_index **sorted = zcl_malloc(
        n * sizeof(struct block_index *), "boot.chainwork_sorted");
    if (!sorted)
        return;
    size_t si = 0, idx2 = 0;
    struct block_index *sp;
    while (block_map_next(&st->map_block_index,
                          &si, NULL, &sp))
        if (sp && idx2 < n) sorted[idx2++] = sp;
    n = idx2;
    qsort(sorted, n, sizeof(*sorted),
          cmp_block_index_height);
    struct block_index *best = boot_zcd_accumulate_chain_work(sorted, n);
    free(sorted);
    boot_zcd_promote_import_best(best, have_ndcb, ndcb);
}

/* Build a snapshot dir so we can open the LevelDB even while a live
 * zclassicd holds the source LOCK. See engine/modules/storage/src/ldb_snapshot.c. */
static bool boot_zcd_make_index_snapshot(const char *zcd_idx_path,
                                         const char *snap_path)
{
    char snap_err[256] = {0};
    bool snap_ok = false;
    for (int snap_try = 0; snap_try < 3 && !snap_ok; snap_try++) {
        snap_ok = ldb_snapshot_make(zcd_idx_path, snap_path,
                                    snap_err, sizeof(snap_err));
        if (!snap_ok &&
            strcmp(snap_err, "manifest_changed") != 0)
            break;
    }
    if (!snap_ok) {
        fprintf(stderr,
                "[boot] ldb_snapshot_make(%s) failed: %s; "
                "falling back to direct open (may unlink "
                "stale LOCK)\n", zcd_idx_path, snap_err);
        /* Fallback path for a crashed zclassicd whose LOCK
         * is stale: unlink it and open directly. Only used
         * when the snapshot path itself fails. */
        char lock_path[1300];
        snprintf(lock_path, sizeof(lock_path),
                 "%s/LOCK", zcd_idx_path);
        unlink(lock_path);
    }
    return snap_ok;
}

/* Load zclassicd's block index into our map, then persist the enriched flat. */
static void boot_zcd_load_index(struct app_context *ctx, struct main_state *st,
                                const char *open_path, bool have_ndcb,
                                struct boot_derived_coins_best ndcb)
{
    struct block_tree_db zcd_btdb;
    int64_t t0 = (int64_t)platform_time_wall_time_t();
    if (!block_tree_db_open(&zcd_btdb, open_path, 450 << 20, false, false)) {
        fprintf(stderr, "Could not open zclassicd block index "
                "at %s\n", open_path);
        return;
    }
    if (block_tree_db_load_block_index_guts(
            &zcd_btdb, boot_insert_block_index_cb, st)) {
        int64_t elapsed = (int64_t)platform_time_wall_time_t() - t0;
        printf("Loaded %zu block index entries from zclassicd "
               "in %llds\n",
               st->map_block_index.size,
               (long long)elapsed);
        boot_zcd_reseed_hash_pointers(st);
        boot_zcd_set_chain_tip_from_work(st, have_ndcb, ndcb);
        /* Save flat file for instant future boots. The map is
         * now ENRICHED with zclassicd's 0..zcd-tip ancestry; the
         * flat persists the entry SET only (no tip), so saving it
         * is desirable even when the backward tip promotion above
         * was suppressed — OPTION 1's durable effect is the
         * skipped CSR promotion, not flat avoidance. */
        boot_persist_block_index(ctx->datadir, st);
    }
    block_tree_db_close(&zcd_btdb);
}

/* Copy block files from zclassicd if we don't have them. */
static void boot_zcd_copy_block_files(struct app_context *ctx, const char *home)
{
    char zcd_blk_dir[1024];
    if (!boot_legacy_default_blocks_dir(zcd_blk_dir,
                                        sizeof(zcd_blk_dir))) {
        if (home)
            snprintf(zcd_blk_dir, sizeof(zcd_blk_dir),
                     "%s/.zclassic/blocks", home);
        else
            snprintf(zcd_blk_dir, sizeof(zcd_blk_dir),
                     ".zclassic/blocks");
    }
    struct boot_legacy_block_file_import_result import_files =
        boot_legacy_import_block_files(zcd_blk_dir,
                                       ctx->datadir, 256);
    if (import_files.failures > 0)
        printf("Block files linked/copied from zclassicd "
               "with %d failure(s); see node.log\n",
               import_files.failures);
    else
        printf("Block files linked/copied from zclassicd\n");
    fflush(stdout);
}

/* Import zclassicd's LevelDB index (ancestry, tip, block files). */
static void boot_blkidx_import_from_zclassicd(struct app_context *ctx,
                                              struct main_state *st,
                                              const char *zcd_idx_path,
                                              const char *home,
                                              bool legacy_source_present)
{
    /* Derive our OWN coins frontier up front. The zclassicd LevelDB
     * index tops out at zclassicd's own tip; if our derived frontier
     * is STRICTLY above it, promoting/saving zclassicd's best would
     * commit the public tip BACKWARD below our frontier — a downshift
     * that detaches our coins-best block, forces a window re-chase,
     * and latches contradiction_frozen. We STILL import the index for
     * the 0..zcd-tip ANCESTRY (so the detached block gets a real pprev
     * root), but suppress the backward tip COMMIT. (We still save the
     * resulting flat — it is now ENRICHED with that ancestry and
     * carries no tip field, so persisting it is desirable.) Key
     * strictly on '>' so a legitimate fresh fast-cold-sync (at/below
     * zclassicd) and a legacy datadir (no derived frontier) promote
     * normally. */
    struct boot_derived_coins_best ndcb;
    bool have_ndcb = boot_derive_coins_best(&ndcb);
    if (!legacy_source_present)
        return;
    printf("Loading block index from zclassicd LevelDB: %s\n",
           zcd_idx_path);
    fflush(stdout);
    /* Build a snapshot dir so we can open the LevelDB even
     * while a live zclassicd holds the source LOCK.
     * Hardlinks the immutable .ldb SST files + copies the
     * small MANIFEST/CURRENT/LOG metadata + gives the
     * snapshot a fresh empty LOCK (distinct fcntl context).
     * See engine/modules/storage/src/ldb_snapshot.c for the rationale. */
    char snap_path[1200];
    snprintf(snap_path, sizeof(snap_path),
             "%s/.legacy_ldb_snap", ctx->datadir);
    bool snap_ok = boot_zcd_make_index_snapshot(zcd_idx_path, snap_path);
    const char *open_path = snap_ok ? snap_path : zcd_idx_path;
    boot_zcd_load_index(ctx, st, open_path, have_ndcb, ndcb);
    /* Tear down the snapshot (hardlinks free cheaply). */
    if (snap_ok)
        ldb_snapshot_destroy(snap_path);
    /* Copy block files from zclassicd if we don't have them */
    if (st->map_block_index.size > 1000)
        boot_zcd_copy_block_files(ctx, home);
}

void boot_blkidx_pull_legacy_zclassicd(struct app_context *ctx,
                                       struct main_state *st,
                                       struct node_db *ndb)
{
    int chain_h = active_chain_height(&st->chain_active);
    if (chain_h < 1000) {
        /* Estimate expected height from SQLite or coins */
        int64_t db_h = ndb->open ? db_block_max_height(ndb) : 0;
        if (db_h > chain_h) chain_h = (int)db_h;
    }
    /* Legacy source probe, hoisted: feeds need_zcd + the LevelDB open. */
    const char *home = getenv("HOME");
    char zcd_idx_path[1024];
    if (home)
        snprintf(zcd_idx_path, sizeof(zcd_idx_path),
                 "%s/.zclassic/blocks/index", home);
    else
        snprintf(zcd_idx_path, sizeof(zcd_idx_path),
                 ".zclassic/blocks/index");
    struct stat zcd_st;
    bool legacy_source_present = (stat(zcd_idx_path, &zcd_st) == 0);
    /* Ratio or empty-datadir trigger — see boot_need_legacy_header_pull. */
    bool need_zcd = boot_need_legacy_header_pull(
        (int64_t)st->map_block_index.size, (int64_t)chain_h, legacy_source_present);
    if (need_zcd)
        boot_blkidx_import_from_zclassicd(ctx, st, zcd_idx_path, home,
                                          legacy_source_present);
}

/* Highest UTXO height recorded in node.db. */
static int boot_post_scan_utxo_max_height(struct node_db *ndb)
{
    int utxo_max_h = 0;
    sqlite3_stmt *hst = NULL;
    if (sqlite3_prepare_v2(ndb->db,
        "SELECT MAX(height) FROM utxos",
        -1, &hst, NULL) == SQLITE_OK && hst) {
        if (AR_STEP_ROW_READONLY(hst) == SQLITE_ROW)
            utxo_max_h = sqlite3_column_int(hst, 0);
        sqlite3_finalize(hst);
    }
    return utxo_max_h;
}

/* Highest consensus-backed HAVE_DATA block at or below the UTXO height. */
static struct block_index *boot_post_scan_highest_backed_block(
    struct main_state *st, const char *datadir, int utxo_max_h)
{
    struct block_index *best_have = NULL;
    size_t bi = 0;
    struct block_index *bp;
    while (block_map_next(
        &st->map_block_index,
        &bi, NULL, &bp)) {
        if (!bp) continue;
        if (bp->nHeight <= utxo_max_h &&
            (bp->nStatus & BLOCK_HAVE_DATA) &&
            chain_restore_block_is_consensus_backed_on_disk(
                bp, datadir) &&
            (!best_have ||
             bp->nHeight > best_have->nHeight))
            best_have = bp;
    }
    return best_have;
}

/* Look up the coins-best block's height from the SQLite blocks table. */
static int boot_post_scan_lookup_target_height(struct node_db *ndb,
                                               struct uint256 post_scan_best)
{
    /* Look up correct height from SQLite */
    int target_h = -1;
    if (ndb->open && ndb->db) {
        /* Look up import height from SQLite blocks table.
         * blocks.hash stores display-order (big-endian),
         * coins_best_block is internal-order (little-endian). */
        uint8_t hash_rev[32];
        for (int bi = 0; bi < 32; bi++)
            hash_rev[bi] = post_scan_best.data[31 - bi];
        struct db_block sqlite_blk;
        if (db_block_find_by_hash(ndb, hash_rev,
                                   &sqlite_blk) &&
            sqlite_blk.height > 0) {
            target_h = sqlite_blk.height;
        }
        /* Fallback: try finding by height range near chain tip */
        if (target_h <= 0) {
            sqlite3_stmt *qs = NULL;
            sqlite3_prepare_v2(ndb->db,
                "SELECT height FROM blocks "
                "ORDER BY height DESC LIMIT 1",
                -1, &qs, NULL);
            if (qs) {
                if (AR_STEP_ROW_READONLY(qs) == SQLITE_ROW)
                    target_h = sqlite3_column_int(qs, 0);
                sqlite3_finalize(qs);
            }
            if (target_h > 0)
                printf("Post-scan: using max block height "
                       "%d as import target\n", target_h);
        }
        if (target_h > 0)
            printf("Post-scan: import height=%d\n", target_h);
    }
    return target_h;
}

/* Promote the coins-tip block, or a materially better scanned chain. */
static void boot_post_scan_promote_found(struct main_state *st,
                                         struct block_index *post_found,
                                         int target_h)
{
    struct block_index *best_scanned = NULL;
    size_t scan_iter = 0;
    struct block_index *scan_bi;
    while (block_map_next(&st->map_block_index,
                          &scan_iter, NULL, &scan_bi)) {
        if (!scan_bi) continue;
        if (!(scan_bi->nStatus & BLOCK_HAVE_DATA)) continue;
        if (scan_bi->nChainTx == 0) continue;
        if (!best_scanned ||
            arith_uint256_compare(&scan_bi->nChainWork,
                                  &best_scanned->nChainWork) > 0)
            best_scanned = scan_bi;
    }
    if (best_scanned &&
        best_scanned->nHeight > post_found->nHeight + 1000) {
        printf("Post-scan: promoting best scanned chain "
               "h=%d over stale coins anchor h=%d\n",
               best_scanned->nHeight, post_found->nHeight);
        post_found = best_scanned;
        target_h = best_scanned->nHeight;
    }
    /* SQLite block metadata is a cache and can lag or
     * carry stale labels after recovery.  The pprev chain
     * is the authority for block heights here; never
     * mutate a block_index height from SQLite metadata.
     * A one-block downlabel is enough to make the active
     * tip silently disagree with peers and can prune live
     * UTXOs above the false tip. */
    if (post_found->nHeight != target_h) {
        printf("Post-scan: ignoring SQLite height %d for "
               "pprev-derived h=%d\n",
               target_h, post_found->nHeight);
        target_h = post_found->nHeight;
    }
    if (boot_promote_tip_via_csr(
            post_found, "post_found_promote", true)) {
        printf("Post-scan: setting chain tip to h=%d\n",
               target_h);
    }
}

/* coins_best_block is not in the index: promote the highest disk-backed block
 * at or below the UTXO height, else record a metadata anchor, else reset. */
static void boot_post_scan_resolve_orphan(struct main_state *st,
                                          struct node_db *ndb,
                                          const char *datadir,
                                          const struct chain_params *params,
                                          struct uint256 post_scan_best)
{
    /* coins_best_block hash not found in block index.
     * Instead of wiping UTXOs, find the highest UTXO
     * height and set chain tip there.  The UTXO data
     * is valid — only the metadata label is wrong. */
    char hex[65];
    uint256_get_hex(&post_scan_best, hex);
    printf("[boot] coins_best_block %s not in "
           "block index — resolving from UTXO "
           "heights\n", hex);
    int utxo_max_h = boot_post_scan_utxo_max_height(ndb);
    if (utxo_max_h <= 0) {
        /* No UTXOs at all — safe to reset to genesis */
        printf("[boot] No UTXOs found — resetting to "
               "genesis\n");
        struct block_index *genesis = block_map_find(
            &st->map_block_index,
            &params->consensus.hashGenesisBlock);
        if (genesis) {
            (void)boot_promote_tip_preserving_header_via_csr(
                genesis, "no_utxos_reset_genesis", true);
        }
        return;
    }
    struct block_index *best_have =
        boot_post_scan_highest_backed_block(st, datadir, utxo_max_h);
    if (best_have && best_have->nHeight > 0 &&
        boot_promote_tip_via_csr(
            best_have, "coins_hash_orphan_promote",
            true)) {
        printf("[boot] coins_best_block hash not "
               "in index — setting tip to highest "
               "HAVE_DATA block at h=%d\n",
               best_have->nHeight);
        return;
    }
    /* No verified disk-backed blocks — record
     * metadata only at the UTXO height. */
    struct block_index *anchor =
        chain_restore_create_anchor(
            st, &post_scan_best,
            utxo_max_h);
    if (anchor) {
        snapsync_set_anchor(anchor);
        printf("[boot] coins_best_block hash "
               "not in index — metadata anchor "
               "at h=%d\n", utxo_max_h);
    }
}

void boot_post_scan_anchor_ladder(struct main_state *st, struct node_db *ndb,
                                  struct coins_view_sqlite *cs,
                                  const char *datadir,
                                  const struct chain_params *params)
{
    /* After block file scan, try to resolve coins_best_block.
     * The scan may have assigned wrong heights (blocks in random
     * file order) or picked a wrong "most work" chain due to
     * incomplete nChainTx propagation.  Use SQLite blocks table
     * to find the correct height, then set the active chain tip
     * to the coins-tip block.  This fires when:
     *   (a) active_chain is empty (no HAVE_DATA blocks), OR
     *   (b) active_chain tip is far below the coins tip
     *       (scan picked a wrong short fork). */
    struct uint256 post_scan_best;
    /* This LDB/damage-recovery branch needs the LEGACY coins.db
     * best-block, not the projection (the projection read view
     * tracks a consume offset, not a best-block hash). Read it
     * straight from g_coins_sqlite, which still exists for
     * legacy damage-recovery reads. */
    uint256_set_null(&post_scan_best);
    if (cs->db)
        coins_view_sqlite_get_best_block(cs,
                                         &post_scan_best);
    /* Restore chain tip to match UTXO snapshot height when
     * the active chain is far below the coins tip. This happens
     * after LDB import: the UTXO set is at 3M+ but block files
     * only cover up to ~2M, so reducer activation sets a low
     * tip. Without this fix, the node tries to re-connect
     * blocks that are already reflected in the UTXO set, causing
     * bad-txns-inputs-missingorspent failures. */
    if (uint256_is_null(&post_scan_best))
        return;
    int target_h = boot_post_scan_lookup_target_height(ndb, post_scan_best);
    struct block_index *post_found = block_map_find(
        &st->map_block_index, &post_scan_best);
    if (post_found && target_h > 0)
        boot_post_scan_promote_found(st, post_found, target_h);
    else if (!post_found)
        boot_post_scan_resolve_orphan(st, ndb, datadir, params,
                                      post_scan_best);
}

/* lane/sapling-tree-persist: decide whether a persisted Sapling tree that
 * mismatches the CURRENT tip may still be trusted as an older-but-consistent
 * frontier, rather than treated as corrupt.
 *
 * A node_state["sapling_tree"] / flat-checkpoint blob mismatching the
 * current tip's hashFinalSaplingRoot is EXPECTED whenever any block was
 * applied after the tree was last persisted — that alone does not mean the
 * tree is wrong. Reuses the same pure verify-then-trust predicate the
 * flat-file checkpoint load path already trusts (sapling_ckpt_verify_binding,
 * core/modules/sapling/src/incremental_merkle_tree.c) against the tree's OWN claimed
 * height instead of the tip: if the tree's root matches hashFinalSaplingRoot
 * at `saved_height`, the caller may fold forward from saved_height+1 to tip
 * via sapling_tree_rebuild()'s existing checkpoint-resume path (bounded work
 * proportional to tip - saved_height) instead of a full from-activation
 * replay.
 *
 * Returns 1 when verified (safe to fold forward), 0 when there is no
 * `saved_height` to check (legacy datadir predating this key, or the tree
 * is already at/above tip — not an error, caller's existing fallback runs
 * unchanged), or -1 (via LOG_ERR, every relevant number logged) when
 * `saved_height` itself fails to verify — the "genuine corruption" case the
 * full-rebuild fallback must still catch. */
static int sapling_tree_verify_at_saved_height(
    const struct active_chain *chain,
    const struct uint256 *tree_root, size_t tree_size,
    int64_t saved_height, int tip_height)
{
    if (saved_height <= 476969 || saved_height >= tip_height)
        return 0;
    const struct block_index *saved_bi =
        active_chain_at(chain, (int)saved_height);
    static const uint8_t zeros32[32] = {0};
    bool hash_known = saved_bi && saved_bi->phashBlock;
    bool root_known = saved_bi && memcmp(saved_bi->hashFinalSaplingRoot.data,
                                         zeros32, 32) != 0;
    enum sapling_ckpt_verdict v = sapling_ckpt_verify_binding(
        saved_height, tree_root, NULL, tip_height,
        hash_known ? saved_bi->phashBlock->data : NULL, hash_known,
        root_known ? &saved_bi->hashFinalSaplingRoot : NULL, root_known);
    if (v == SAPLING_CKPT_OK)
        return 1;
    char expected_hex[65] = "unknown";
    char got_hex[65];
    uint256_get_hex(tree_root, got_hex);
    if (root_known)
        uint256_get_hex(&saved_bi->hashFinalSaplingRoot, expected_hex);
    LOG_ERR("sapling_tree",
            "verify_at_saved_height: verdict=%s expected_root=%s "
            "got_root=%s tree_size=%zu saved_h=%lld tip_h=%d",
            sapling_ckpt_verdict_str(v), expected_hex, got_hex, tree_size,
            (long long)saved_height, tip_height);
}

/* lane/sapling-tree-persist: given a verified older-but-consistent tree
 * (sapling_tree_verify_at_saved_height already returned 1 for this
 * saved_height), fold forward to tip via sapling_tree_rebuild()'s existing
 * checkpoint-resume path instead of a full from-activation rebuild. Reloads
 * st->sapling_tree from the rebuilt node_state on success. Returns true
 * only when the fold-forward fully completed and reloaded; false leaves
 * st->sapling_tree untouched so the caller's existing full-rebuild
 * fallback still runs. */
static bool sapling_tree_attempt_fold_forward(struct app_context *ctx,
                                              struct main_state *st,
                                              struct node_db *ndb,
                                              const char *datadir,
                                              int tip_height, size_t old_size,
                                              int64_t saved_height)
{
    printf("Sapling tree verified at saved_h=%lld (size=%zu) — folding "
          "forward to tip_h=%d\n", (long long)saved_height, old_size,
          tip_height);
    fflush(stdout);
    atomic_store(&g_sapling_tree_rebuilding, true);
    bool folded = false;
    int fn = sapling_tree_rebuild(ndb, &st->chain_active,
                                  datadir);
    if (fn >= 0) {
        uint8_t fbuf[8192];
        size_t flen = 0;
        if (node_db_state_get(ndb, "sapling_tree", fbuf, sizeof(fbuf),
                              &flen) && flen > 0) {
            struct byte_stream fts;
            stream_init_from_data(&fts, fbuf, flen);
            sapling_tree_init(&st->sapling_tree);
            incremental_tree_deserialize(&st->sapling_tree, &fts);
            set_sapling_tree_for_flush(&st->sapling_tree);
            printf("Sapling tree folded forward: %d commitments (was %zu, "
                  "resumed from saved_h=%lld)\n", fn, old_size,
                  (long long)saved_height);
            folded = true;
        }
    }
    atomic_store(&g_sapling_tree_rebuilding, false);
    node_db_wal_checkpoint(ndb);
    boot_persist_block_index(ctx->datadir, st);
    return folded;
}

/* Load the Sapling commitment tree from the verified flat checkpoint. */
static void boot_step_load_sapling_checkpoint(struct main_state *st,
                                              struct node_db *ndb,
                                              const char *datadir,
                                              int64_t *saved_height)
{
    /* Load Sapling commitment tree from persistent storage.
     *
     * Three-tier fall-back, most-authoritative first:
     *   (1) Flat-file checkpoint at <datadir>/sapling_tree_ckpt.dat
     * SHA3-verified, atomic, ≤10K blocks stale.
     *   (2) node_state["sapling_tree"] — SQLite-backed, legacy path,
     *       kept as a secondary belt.
     *   (3) Fresh empty tree + replay during the mismatch-check pass.
     *
     * This tree is maintained by connect_block and verified against
     * hashFinalSaplingRoot in each block header. */
    /* The height this tree was verified/persisted at — -1 = unknown (a
     * legacy datadir predating "sapling_tree_rebuild_height", or no tree
     * loaded yet). Threaded into the mismatch-check pass below so a stale
     * (but internally-consistent) tree can fold forward instead of being
     * treated as corrupt. See sapling_tree_verify_at_saved_height(). */
    int64_t sapling_tree_saved_height = -1;
    if (ndb->open && !st->sapling_tree_loaded && datadir) {
        char ckpt_path[512];
        snprintf(ckpt_path, sizeof(ckpt_path),
                 "%s/sapling_tree_ckpt.dat", datadir);
        sapling_tree_init(&st->sapling_tree);
        int64_t ckpt_height = 0;
        uint8_t ckpt_block_hash[32] = {0};
        if (sapling_tree_load_checkpoint(&st->sapling_tree,
                                          &ckpt_height, ckpt_block_hash,
                                          ckpt_path)) {
            /* Verify-then-trust: bind the cached frontier to the
             * authoritative header chain at ckpt_height (height <= tip,
             * same block hash, root == hashFinalSaplingRoot). A stale
             * (above-tip / reorged / mismatched) checkpoint is DELETED and
             * we fall through to the node_state path + full replay — the
             * cache is never trusted unverified. */
            struct uint256 ckpt_root;
            incremental_tree_root(&st->sapling_tree, &ckpt_root);
            const struct block_index *ctip =
                active_chain_tip(&st->chain_active);
            const struct block_index *cbi =
                active_chain_at(&st->chain_active, (int)ckpt_height);
            static const uint8_t zeros32[32] = {0};
            bool exp_hash_known = cbi && cbi->phashBlock;
            bool exp_root_known = cbi && memcmp(cbi->hashFinalSaplingRoot.data,
                                                zeros32, 32) != 0;
            enum sapling_ckpt_verdict v = sapling_ckpt_verify_binding(
                ckpt_height, &ckpt_root, ckpt_block_hash,
                ctip ? ctip->nHeight : -1,
                exp_hash_known ? cbi->phashBlock->data : NULL, exp_hash_known,
                exp_root_known ? &cbi->hashFinalSaplingRoot : NULL,
                exp_root_known);
            if (v == SAPLING_CKPT_OK) {
                st->sapling_tree_loaded = true;
                set_sapling_tree_for_flush(&st->sapling_tree);
                sapling_tree_saved_height = ckpt_height;
                sapling_ckpt_record_load(SAPLING_CKPT_LOAD_VERIFIED,
                                         ckpt_height, "ok");
                printf("Sapling tree loaded from checkpoint: "
                       "%zu commitments, height=%lld (verified)\n",
                       incremental_tree_size(&st->sapling_tree),
                       (long long)ckpt_height);
            } else {
                fprintf(stderr,
                        "WARNING: Sapling checkpoint h=%lld REJECTED (%s) — "
                        "deleting %s and rebuilding\n",
                        (long long)ckpt_height, sapling_ckpt_verdict_str(v),
                        ckpt_path);
                unlink(ckpt_path);
                sapling_tree_init(&st->sapling_tree);
                sapling_ckpt_record_load(SAPLING_CKPT_LOAD_DISCARDED,
                                         ckpt_height,
                                         sapling_ckpt_verdict_str(v));
            }
        } else {
            sapling_ckpt_record_load(SAPLING_CKPT_LOAD_ABSENT, -1,
                                     "missing_or_corrupt");
        }
    }
    *saved_height = sapling_tree_saved_height;
}

/* Secondary belt: load the Sapling tree from node_state["sapling_tree"]. */
static void boot_step_load_sapling_from_node_state(struct main_state *st,
                                                   struct node_db *ndb,
                                                   int64_t *saved_height)
{
    int64_t sapling_tree_saved_height = *saved_height;
    if (ndb->open && !st->sapling_tree_loaded) {
        uint8_t tree_buf[8192];
        size_t tree_len = 0;
        if (node_db_state_get(ndb, "sapling_tree",
                               tree_buf, sizeof(tree_buf), &tree_len)
            && tree_len > 0) {
            struct byte_stream ts;
            stream_init_from_data(&ts, tree_buf, tree_len);
            sapling_tree_init(&st->sapling_tree);
            if (incremental_tree_deserialize(&st->sapling_tree, &ts)) {
                st->sapling_tree_loaded = true;
                set_sapling_tree_for_flush(&st->sapling_tree);
                /* The height this blob was persisted at — co-written
                 * alongside "sapling_tree" by every production writer
                 * (sync_controller_sapling_tree.c, boot_refold_staged.c,
                 * sync_controller_blocks.c). Absent (-1) only on a legacy
                 * datadir written before this key existed. */
                if (!node_db_state_get_int(ndb,
                        "sapling_tree_rebuild_height",
                        &sapling_tree_saved_height))
                    sapling_tree_saved_height = -1;
                if (sapling_tree_saved_height >= 0) {
                    printf("Sapling tree loaded: %zu commitments "
                           "(saved_h=%lld)\n",
                           incremental_tree_size(&st->sapling_tree),
                           (long long)sapling_tree_saved_height);
                } else {
                    printf("Sapling tree loaded: %zu commitments\n",
                           incremental_tree_size(&st->sapling_tree));
                }
            } else {
                fprintf(stderr, "WARNING: Sapling tree deserialization "
                        "failed — tree will rebuild during sync\n");
                sapling_tree_init(&st->sapling_tree);
            }
        } else {
            printf("No saved Sapling tree — will build during sync\n");
            st->sapling_tree_loaded = true; /* empty tree is valid pre-Sapling */
            set_sapling_tree_for_flush(&st->sapling_tree);
        }
    }
    *saved_height = sapling_tree_saved_height;
}

/* The Sapling tree disagrees with the tip and cannot fold forward: defer the
 * rebuild at a live height, else rebuild from block files now. */
static void boot_sapling_rebuild_after_mismatch(struct app_context *ctx,
                                                struct main_state *st,
                                                struct node_db *ndb,
                                                const char *datadir,
                                                int tip_height, size_t old_size)
{
    if (tip_height > 1000000) {
        printf("Sapling tree root MISMATCH (size=%zu) - "
               "deferring live rebuild until after boot "
               "(tip_h=%d)\n", old_size, tip_height);
        sapling_tree_rebuild_start_deferred(ndb, &st->chain_active, datadir, st);
        return;
    }
    printf("Sapling tree root MISMATCH (size=%zu) — "
           "rebuilding from block files...\n", old_size);
    fflush(stdout);
    atomic_store(&g_sapling_tree_rebuilding, true);
    int n = sapling_tree_rebuild(ndb,
        &st->chain_active, datadir);
    if (n >= 0) {
        /* Reload the rebuilt tree from node_state */
        uint8_t tbuf[8192];
        size_t tlen = 0;
        if (node_db_state_get(ndb, "sapling_tree",
                tbuf, sizeof(tbuf), &tlen) && tlen > 0) {
            struct byte_stream ts2;
            stream_init_from_data(&ts2, tbuf, tlen);
            sapling_tree_init(&st->sapling_tree);
            incremental_tree_deserialize(
                &st->sapling_tree, &ts2);
            set_sapling_tree_for_flush(&st->sapling_tree);
            printf("Sapling tree rebuilt: %d commitments "
                   "(was %zu)\n", n, old_size);
        }
    }
    atomic_store(&g_sapling_tree_rebuilding, false);
    /* Checkpoint WAL after bulk tree writes */
    node_db_wal_checkpoint(ndb);
    /* Save block_index.bin after rebuild — the entries
     * now have correct hashFinalSaplingRoot fields from
     * the rebuild. This prevents needless 5-min rebuilds
     * on future boots AND ensures coins_best_block will
     * be resolvable after a crash. */
    boot_persist_block_index(ctx->datadir, st);
}

/* Verify the Sapling tree root against the coins-applied endpoint. */
static void boot_step_verify_sapling_root(struct app_context *ctx,
                                          struct main_state *st,
                                          struct node_db *ndb,
                                          const char *datadir,
                                          int64_t sapling_tree_saved_height)
{
    /* Verify Sapling tree root matches chain tip. If mismatched,
     * rebuild from block files before P2P starts (no concurrency risk).
     * Skip if hashFinalSaplingRoot is all-zeros (block_index.bin doesn't
     * store this field yet, so it will be zero after flat file load). */
    if (!st->sapling_tree_loaded || !datadir)
        return;
    /* Resolve the comparison endpoint from coins-applied state, NOT the
     * pre-fold header tip. On a wedged node (active/header tip >> the
     * durable coins frontier) the loaded sapling tree corresponds to the
     * APPLIED frontier, so comparing it against the HEADER tip's
     * hashFinalSaplingRoot would (a) spuriously mismatch even when the
     * tree is correct for the applied state, and (b) feed the rebuild a
     * header-tip endpoint whose root may be absent and FATAL on
     * `tip_missing_sapling_root` before the forward fold runs. Cap to
     * coins_applied_height - 1 (coins-best) when present and lower; the
     * rebuild itself independently re-derives the same coins-applied
     * endpoint if a mismatch here triggers it. */
    const struct block_index *tip = active_chain_tip(&st->chain_active);
    struct boot_derived_coins_best sap_dcb;
    if (boot_derive_coins_best(&sap_dcb) && sap_dcb.height >= 0
        && (!tip || sap_dcb.height < tip->nHeight)) {
        const struct block_index *coins_tip =
            active_chain_at(&st->chain_active, sap_dcb.height);
        if (coins_tip) {
            printf("Sapling tree check: using coins-applied height %d "
                   "(header tip %d)\n", sap_dcb.height,
                   tip ? tip->nHeight : -1);
            tip = coins_tip;
        }
    }
    static const uint8_t zeros[32] = {0};
    bool tip_has_sapling_root = tip && tip->nHeight > 476969 &&
        memcmp(tip->hashFinalSaplingRoot.data, zeros, 32) != 0;
    if (!tip_has_sapling_root)
        return;
    struct uint256 tree_root;
    incremental_tree_root(&st->sapling_tree, &tree_root);
    if (memcmp(tree_root.data, tip->hashFinalSaplingRoot.data, 32) == 0)
        return;
    size_t old_size = incremental_tree_size(&st->sapling_tree);
    /* lane/sapling-tree-persist: a mismatch against the CURRENT
     * tip does not by itself mean the tree is corrupt — it is
     * the expected state whenever blocks were applied after the
     * tree was last persisted. If the tree carries the height it
     * was saved/verified at, check it against THAT height's own
     * expected root first; a match proves an older-but-consistent
     * frontier, so fold forward via sapling_tree_rebuild()'s
     * existing checkpoint-resume path (bounded work proportional
     * to tip - saved_height) instead of a full from-activation
     * rebuild. Only a saved_height that itself fails to verify
     * (or is absent) falls through to the unchanged full-rebuild
     * fallback below — that path remains for genuine corruption. */
    bool folded_forward = false;
    if (sapling_tree_verify_at_saved_height(
            &st->chain_active, &tree_root, old_size,
            sapling_tree_saved_height, tip->nHeight) == 1) {
        folded_forward = sapling_tree_attempt_fold_forward(ctx, st, ndb,
            datadir, tip->nHeight, old_size, sapling_tree_saved_height);
    }
    if (!folded_forward)
        boot_sapling_rebuild_after_mismatch(ctx, st, ndb, datadir,
                                            tip->nHeight, old_size);
}

void boot_sapling_tree_boot_load(struct app_context *ctx, struct main_state *st,
                                 struct node_db *ndb, const char *datadir)
{
    int64_t sapling_tree_saved_height = -1;
    boot_step_load_sapling_checkpoint(st, ndb, datadir,
                                      &sapling_tree_saved_height);
    boot_step_load_sapling_from_node_state(st, ndb,
                                           &sapling_tree_saved_height);
    boot_step_verify_sapling_root(ctx, st, ndb, datadir,
                                  sapling_tree_saved_height);
}
