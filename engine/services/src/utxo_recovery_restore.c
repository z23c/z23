/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * UTXO Recovery - boot import and active-tip restore paths.
 *
 * Two heavy boot-time recovery routines live here:
 *
 *   utxo_recovery_import_ldb        — LevelDB chainstate → SQLite UTXO
 *                                     migration (LOCK-safe copy, SHA3
 *                                     verify, tip/anchor creation).
 *   utxo_recovery_restore_chain_tip — restore the active tip from the
 *                                     derived coins-best (legacy: coins DB
 *                                     best block / metadata anchor).
 * Both share the CSR-gated commit primitives in utxo_recovery_internal.h. */

#include "services/utxo_recovery_service.h"
#include "services/seed_integrity_gate.h"
#include "services/chain_restore_executor.h"
#include "services/chain_restore_repair.h"
#include "services/chain_tip.h"
#include "jobs/reducer_frontier.h"
#include "net/snapshot_sync_contract.h"
#include "config/boot_internal.h"
#include "validation/main_state.h"
#include "validation/process_block.h"
#include "chain/chainparams.h"
#include "storage/coins_view_sqlite.h"
#include "storage/coins_db.h"
#include "storage/progress_store.h"
#include "storage/coins_kv.h"
#include "coins/coins_view.h"
#include "coins/utxo_commitment.h"
#include "chain/checkpoints.h"
#include "models/database.h"
#include "models/block.h"
#include "event/event.h"
#include "util/file_tree_ops.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sqlite3.h>

#include "util/ar_step_readonly.h"
#include "util/log_macros.h"

#include "utxo_recovery_internal.h"

static struct zcl_result recovery_status_ok(void)
{
    return ZCL_OK;
}

/* Cold-import seed provenance (write/clear) lives in
 * utxo_recovery_seed_provenance.c — declarations in
 * utxo_recovery_internal.h. */

/* Mirror-walk helpers (utxo_recovery_max_utxo_height,
 * utxo_recovery_find_disk_backed_utxo_tip) live in
 * utxo_recovery_mirror_walk.c — declarations in utxo_recovery_internal.h. */

static bool utxo_recovery_scan_fallback_below_finalized_floor(
    const struct block_index *scan_fallback,
    int *floor_out,
    struct uint256 *floor_hash_out,
    bool *have_floor_hash_out)
{
    if (floor_out)
        *floor_out = -1;
    if (floor_hash_out)
        memset(floor_hash_out, 0, sizeof(*floor_hash_out));
    if (have_floor_hash_out)
        *have_floor_hash_out = false;
    if (!scan_fallback)
        return false;

    int floor = utxo_recovery_finalized_served_floor(floor_hash_out,
                                                     have_floor_hash_out);
    if (floor_out)
        *floor_out = floor;
    return floor > scan_fallback->nHeight;
}

/* ── LDB→SQLite UTXO import ─────────────────────────────────── */


struct utxo_import_result utxo_recovery_import_ldb(
    struct utxo_recovery_ctx *ctx)
{
    struct utxo_import_result res = { .status = recovery_status_ok() };

    if (!ctx || !ctx->ndb || !ctx->datadir) {
        res.status = ZCL_ERR(-1,
            "utxo_recovery_import_ldb: invalid ctx=%p ndb=%p datadir=%s",
            (void *)ctx, ctx ? (void *)ctx->ndb : NULL,
            ctx && ctx->datadir ? ctx->datadir : "(null)");
        LOG_WARN("utxo_recovery", "%s", res.status.message);
        return res;
    }

    /* Defensive: ctx->datadir is interpolated into shell commands below
     * (the "rm -rf '%s' && cp -a ..." copy at the zclassicd-LOCK branch
     * and the "rm -rf '%s'" cleanup). A single quote or other shell
     * metacharacter in the path would break the quoting and allow command
     * injection. datadir is operator-controlled (CLI -datadir= / $HOME),
     * never network/RPC, so a clean reject is the correct response.
     * Reject any path containing characters meaningful to the shell;
     * all filesystem-valid paths without these rarely-needed characters
     * are unaffected. */
    if (strcspn(ctx->datadir, "\"'$`|&;<>()") != strlen(ctx->datadir)) {
        res.status = ZCL_ERR(-5,
            "utxo_recovery_import_ldb: datadir contains shell "
            "metacharacters datadir=%s", ctx->datadir);
        LOG_WARN("utxo_recovery", "%s", res.status.message);
        return res;
    }

    uint8_t mig_buf[8];
    size_t mig_len = 0;
    bool migration_done = node_db_state_get(ctx->ndb,
        "leveldb_utxo_migrated", mig_buf, sizeof(mig_buf), &mig_len);

    if (migration_done)
        return res;

    if (!ctx->coins_sqlite || !ctx->coins_tip || !ctx->state) {
        res.status = ZCL_ERR(-4,
            "utxo_recovery_import_ldb: import requires coins_sqlite=%p "
            "coins_tip=%p state=%p",
            (void *)ctx->coins_sqlite, (void *)ctx->coins_tip,
            (void *)ctx->state);
        LOG_WARN("utxo_recovery", "%s", res.status.message);
        return res;
    }

    char cs_path[1024];
    char import_path_cleanup[1100] = "";
    snprintf(cs_path, sizeof(cs_path), "%s/chainstate", ctx->datadir);
    struct stat cs_st;

    /* Fall back to zclassicd's chainstate if local doesn't exist */
    if (stat(cs_path, &cs_st) != 0) {
        const char *home_cs = getenv("HOME");
        if (home_cs)
            snprintf(cs_path, sizeof(cs_path),
                     "%s/.zclassic/chainstate", home_cs);
    }
    if (stat(cs_path, &cs_st) != 0) {
        /* No chainstate dir — mark as done (fresh node) */
        uint8_t one = 1;
        if (!node_db_state_set(ctx->ndb, "leveldb_utxo_migrated", &one, 1)) {
            res.status = ZCL_ERR(-2,
                "utxo_recovery_import_ldb: failed to mark empty chainstate "
                "migration done datadir=%s", ctx->datadir);
            LOG_WARN("utxo_recovery", "%s", res.status.message);
        }
        return res;
    }

    printf("LevelDB→SQLite UTXO migration from %s\n", cs_path);
    fflush(stdout);

    /* If zclassicd's LOCK file exists, another process owns this
     * LevelDB. Copy the chainstate to a temp dir to avoid
     * corrupting zclassicd's data. NEVER delete another
     * process's LOCK file. */
    char cs_lock[1100];
    snprintf(cs_lock, sizeof(cs_lock), "%s/LOCK", cs_path);
    char import_path[1100];
    struct stat lock_st;
    if (stat(cs_lock, &lock_st) == 0) {
        snprintf(import_path, sizeof(import_path),
                 "%s/chainstate_import_tmp", ctx->datadir);
        /* The owner is LIVE — take a provably point-in-time copy
         * (utxo_recovery_ldb_copy.c); a torn copy imports a UTXO set
         * with silent holes whose first spend wedges the reducer. */
        printf("Copying chainstate (zclassicd LOCK present)...\n");
        fflush(stdout);
        {
            struct zcl_result cpres = utxo_recovery_copy_chainstate_stable(
                cs_path, import_path);
            if (!cpres.ok) {
                res.status = cpres;
                LOG_WARN("utxo_recovery", "%s", res.status.message);
                goto cleanup;
            }
        }
        /* Remove the copied LOCK so we can open it */
        char tmp_lock[1200];
        snprintf(tmp_lock, sizeof(tmp_lock), "%s/LOCK", import_path);
        unlink(tmp_lock);
        snprintf(import_path_cleanup, sizeof(import_path_cleanup),
                 "%s", import_path);
    } else {
        snprintf(import_path, sizeof(import_path), "%s", cs_path);
    }

    {
        struct zcl_result wipe =
            utxo_recovery_wipe(ctx->ndb, "boot.ldb_import_prepare");
        if (!wipe.ok)
            LOG_WARN("utxo_recovery", "%s", wipe.message);
    }
    coins_view_sqlite_close(ctx->coins_sqlite);

    struct coins_view_db migrate_db;
    if (coins_view_db_open(&migrate_db, import_path,
                           450 << 20, false, false)) {
        struct node_db import_db;
        if (node_db_sync_open_private_db_like(ctx->ndb, &import_db)) {
            node_db_sync_import_utxos(&import_db, &migrate_db);
            node_db_close(&import_db);
        } else {
            node_db_sync_import_utxos(ctx->ndb, &migrate_db);
        }

        /* Discover LDB height from imported UTXOs */
        int ldb_height = utxo_recovery_max_utxo_height(ctx);
        if (ldb_height > 0)
            printf("LDB import: height %d (from UTXO heights)\n",
                   ldb_height);
        res.height = ldb_height;

        /* Set coins_best_block from LDB */
        struct uint256 ldb_best;
        memset(&ldb_best, 0, sizeof(ldb_best));
        if (coins_view_db_get_best_block(&migrate_db, &ldb_best) &&
            !uint256_is_null(&ldb_best)) {
            struct block_index *found = block_map_find(
                &ctx->state->map_block_index, &ldb_best);

            char dbg_hex[65];
            uint256_get_hex(&ldb_best, dbg_hex);

            if (found && found->nHeight > 0) {
                /* Block found in index — set as chain tip.
                 * frontier_exempt: the import carries SHA3-verified snapshot
                 * evidence and must not be clamped by a stale pre-import
                 * log; the seed-anchor stamp re-raises the frontier to H. */
                struct block_index *commit_blk = found;
                if (utxo_recovery_commit_tip(
                        ctx, &commit_blk, "ldb_import_found",
                        true, true).ok) {
                    printf("LDB import: chain tip at h=%d hash=%s\n",
                           commit_blk->nHeight, dbg_hex);
                    res.skip_activate = true;
                    snprintf(res.anchor_reason, sizeof(res.anchor_reason),
                             "ldb_import_found");
                    /* Record the durable seed from the COMMITTED tip (the
                     * exempt path never clamps, but the seed must attest to
                     * what was actually installed, not what was proposed).
                     * Count = live utxos rows. */
                    utxo_recovery_write_cold_import_seed(ctx->ndb,
                        commit_blk->nHeight, commit_blk->phashBlock,
                        node_db_utxo_count(ctx->ndb));
                }
            } else if (ldb_height > 0) {
                /* LDB best block NOT in our index — record an activation
                 * anchor only. Do not publish coins_best_block until the
                 * block is present in the local index and CSR can commit it. */
                struct block_index *anchor = chain_restore_create_anchor(
                    ctx->state, &ldb_best, ldb_height);
                if (anchor) {
                    snapsync_set_anchor(anchor);

                    printf("LDB import: metadata anchor at h=%d hash=%s "
                           "— waiting for real block data.\n",
                           ldb_height, dbg_hex);
                    /* Record-only: a pprev-less anchor installed above
                     * the trust-rooted extent is the band-hole class.
                     * Ancestry-derived — abstains on a
                     * contiguous imported header chain. */
                    utxo_recovery_note_band_unrooted_tip(
                        anchor, "ldb_import_anchor");
                }
                res.skip_activate = true;
                snprintf(res.anchor_reason, sizeof(res.anchor_reason),
                         "ldb_import_anchor");
            } else {
                char dbg_hex2[65];
                uint256_get_hex(&ldb_best, dbg_hex2);
                printf("LDB import: coins_best_block=%s "
                       "(height unknown)\n", dbg_hex2);
                res.skip_activate = true;
                snprintf(res.anchor_reason, sizeof(res.anchor_reason),
                         "ldb_import_unknown");
            }
        }

        coins_view_db_close(&migrate_db);
        node_db_wal_checkpoint(ctx->ndb);

        /* Force a fresh read snapshot so ctx->ndb sees the UTXOs
         * written by import_db (the private connection).  Without
         * this, a stale SQLite snapshot can report 0 rows, causing
         * the SHA3 check to falsely fail and wipe valid data. */
        sqlite3_exec(ctx->ndb->db, "BEGIN; END;", NULL, NULL, NULL);

        /* SHA3 verification */
        uint8_t imported_root[32];
        uint64_t imported_count = 0;
        bool sha3_root_valid = true;
        utxo_commitment_sha3_compute(ctx->ndb->db,
            imported_root, &imported_count);
        printf("SHA3 UTXO verification: %llu UTXOs\n",
               (unsigned long long)imported_count);
        res.utxo_count = imported_count;

        const struct sha3_utxo_checkpoint *cp = get_sha3_utxo_checkpoint();
        /* The utxo_sha3 stamp is an HONEST
         * cryptographic certificate ONLY when the imported set matches the
         * COMPILED checkpoint. Stamping at a non-checkpoint height made
         * gate_commitment_check recompute the SHA3 over the SAME table and
         * pass vacuously — it certified whatever was imported, including a
         * torn set. Track the genuine match here and gate the stamp on it
         * below; at non-checkpoint heights leave the commitment check
         * honestly unarmed (Part A's forward-evidence gate is the sole trust
         * authority above the single checkpoint). */
        bool checkpoint_match = false;
        if (cp && imported_count == cp->utxo_count &&
            memcmp(imported_root, cp->sha3_hash, 32) == 0) {
            printf("=== SHA3 UTXO CHECKPOINT: PASSED ===\n");
            checkpoint_match = true;
        } else if (imported_count > 100000) {
            printf("SHA3: %llu UTXOs (different height from "
                   "checkpoint, will verify later)\n",
                   (unsigned long long)imported_count);
        } else {
            /* Double-check actual row count before wiping — the SHA3
             * function might have missed data due to a stale snapshot, but
             * the UTXOs are actually in the table. Consult the
             * CANONICAL coins_kv count too (0 pre-seed in cold-import, so
             * the mirror count stays the live signal; max keeps both honest). */
            int64_t actual = node_db_utxo_count(ctx->ndb);
            {
                int64_t ck = coins_kv_count(progress_store_db());
                if (ck > actual)
                    actual = ck;
            }
            if (actual > 100000) {
                printf("SHA3 saw %llu but utxo table has %lld rows "
                       "— keeping data (snapshot lag)\n",
                       (unsigned long long)imported_count,
                       (long long)actual);
                imported_count = (uint64_t)actual;
                res.utxo_count = imported_count;
                /* Digest came from the stale snapshot — never stamp it. */
                sha3_root_valid = false;
            } else {
                LOG_WARN("chain", "only %llu UTXOs imported " "— will retry on next boot", (unsigned long long)imported_count);
                struct zcl_result wipe = utxo_recovery_wipe(ctx->ndb,
                    "boot.ldb_import_failed_retry");
                if (!wipe.ok)
                    LOG_WARN("utxo_recovery", "%s", wipe.message);
            }
        }

        uint8_t one = 1;
        if (imported_count > 100000) {
            if (!node_db_state_set(ctx->ndb, "leveldb_utxo_migrated",
                                   &one, 1))
                LOG_WARN("utxo_recovery",
                         "failed to persist leveldb_utxo_migrated stamp; "
                         "re-import retried next boot");

            /* Seed coins_kv from the ACCEPTED import (prevout resolver needs
             * pre-anchor coins). MUST run only after the verification gate: the
             * seed stamps a one-way migration key on SQL success, so seeding a
             * gate-wiped partial import strands coins_kv vs the next reimport. */
            if (!coins_kv_seed_from_node_db(progress_store_db(),
                    sqlite3_db_filename(ctx->ndb->db, "main")))
                LOG_WARN("utxo_recovery", "coins_kv import seed failed");

            /* DURABLE cold-import seed anchor for the path the ldb_import_found
             * branch does NOT take (normal --importblockindex + boot
             * auto-import). This gate (`imported_count > 100000`) is a
             * ROW-COUNT heuristic, NOT a crypto token at non-checkpoint
             * heights — the consumer establishes trust at consume time
             * (hash-in-index at H, recorded count == live count, migrated-flag
             * set) and the key is cleared on every wipe/reimport-prepare.
             * ldb_height = MAX(utxo height); count = live rows. */
            if (ldb_height > 0 && !uint256_is_null(&ldb_best))
                utxo_recovery_write_cold_import_seed(ctx->ndb, ldb_height,
                                                     &ldb_best,
                                                     node_db_utxo_count(ctx->ndb));

            /* Check 5, cold-import half: arm the seed gate's commitment
             * check (trust model: seed_integrity_gate.h). Stamp
             * ONLY at a genuine compiled-checkpoint match — never at a
             * non-checkpoint height, where the stamp would be a vacuous
             * self-certificate of the imported (possibly torn) set. */
            if (ldb_height > 0 && sha3_root_valid && checkpoint_match)
                (void)seed_integrity_stamp_utxo_sha3(
                    ctx->ndb, ldb_height, imported_root, imported_count);
        }

        /* Marker for process_block.c's hot-loop exit debounce: if the
         * reimport ran but the set is STILL incomplete (memtable-stale
         * zclassicd LDB), the hot-loop exit must not restart-loop. The
         * marker says "just tried reimport, still stuck" — stop
         * requesting shutdown (10-min staleness window for operator). */
        if (ctx->datadir) {
            char marker_path[512];
            snprintf(marker_path, sizeof(marker_path),
                     "%s/last_reimport_attempted", ctx->datadir);
            FILE *mf = fopen(marker_path, "w");
            if (mf) {
                fputs("1\n", mf);
                fclose(mf);
            }
        }

        coins_view_sqlite_open(ctx->coins_sqlite, ctx->ndb->db);
        /* Re-init coins cache after import */
        coins_view_cache_init(ctx->coins_tip, &ctx->coins_sqlite->view);
        set_coins_sqlite_for_commitment(ctx->coins_sqlite);

        /* Diagnostic: log UTXO height vs chain tip after import */
        {
            int tip_h = active_chain_height(&ctx->state->chain_active);
            printf("[boot] UTXO import: coins_best_block at h=%d, "
                   "chain tip at h=%d%s\n",
                   ldb_height, tip_h,
                   ldb_height != tip_h
                       ? " (MISMATCH — adjusting tip)" : "");
        }

        printf("UTXO migration complete.\n");
        fflush(stdout);
        res.imported = true;
    }

cleanup:
    if (import_path_cleanup[0])
        (void)zcl_tree_remove(import_path_cleanup);  /* rm -rf temp, no shell */

    return res;
}

/* ── Chain tip restoration ──────────────────────────────────── */

static bool has_disk_backed_competing_sibling(
    struct main_state *ms,
    const struct block_index *candidate,
    const char *datadir)
{
    if (!ms || !candidate || !candidate->pprev || !candidate->phashBlock)
        return false;

    size_t iter = 0;
    struct block_index *alt;
    while (block_map_next(&ms->map_block_index, &iter, NULL, &alt)) {
        if (!alt || alt == candidate)
            continue;
        if (alt->nHeight != candidate->nHeight)
            continue;
        if (alt->pprev != candidate->pprev)
            continue;
        if (alt->phashBlock &&
            uint256_eq(alt->phashBlock, candidate->phashBlock))
            continue;
        if (chain_restore_block_is_consensus_backed_on_disk(alt, datadir))
            return true;
    }
    return false;
}

struct chain_restore_result utxo_recovery_restore_chain_tip(
    struct utxo_recovery_ctx *ctx,
    struct block_index *scan_fallback)
{
    struct chain_restore_result res = { .status = recovery_status_ok() };
    res.restored_height = -1;

    if (!ctx || !ctx->state || !ctx->coins_tip || !ctx->ndb ||
        !ctx->params) {
        res.status = ZCL_ERR(-20,
            "utxo_recovery_restore_chain_tip: invalid ctx=%p state=%p "
            "coins_tip=%p ndb=%p params=%p",
            (void *)ctx, ctx ? (void *)ctx->state : NULL,
            ctx ? (void *)ctx->coins_tip : NULL,
            ctx ? (void *)ctx->ndb : NULL,
            ctx ? (void *)ctx->params : NULL);
        LOG_WARN("utxo_recovery", "%s", res.status.message);
        return res;
    }

    struct uint256 best_hash;
    /* The restore anchor is the DERIVED coins-best when the durable
     * logs resolve a hash for it; the in-RAM coins cache (seeded from the
     * node_state projection key) is the legacy fallback. */
    uint256_set_null(&best_hash);
    {
        int32_t d_h = -1;
        uint8_t d_hash[32];
        bool d_hf = false;
        if (reducer_frontier_derive_coins_best_now(&d_h, d_hash, &d_hf) &&
            d_hf) {
            memcpy(best_hash.data, d_hash, 32);
            printf("[boot] restore anchor: derived coins-best h=%d "
                   "(coins_kv authority)\n", d_h);
        }
    }
    if (uint256_is_null(&best_hash))
        coins_view_cache_get_best_block(ctx->coins_tip, &best_hash);

    if (uint256_is_null(&best_hash)) {
        /* No best block — try fast rebuild if fallback available */
        if (scan_fallback) {
            int served_floor = -1;
            struct uint256 served_hash;
            bool have_served_hash = false;
            if (utxo_recovery_scan_fallback_below_finalized_floor(
                    scan_fallback, &served_floor, &served_hash,
                    &have_served_hash)) {
                /* The floor outranks scan_fallback — but only a floor BOTH
                 * Invariant A authorities can back is real authority. The
                 * settle loop (utxo_recovery_frontier_gate.c) flips
                 * unbackable rows, loudest-first, until the floor is
                 * evidence again or stops outranking scan_fallback. */
                served_floor = utxo_recovery_settle_finalized_floor(
                    ctx, scan_fallback->nHeight, served_floor,
                    &served_hash, &have_served_hash);
                if (served_floor > scan_fallback->nHeight) {
                    /* The held floor is VERIFIED above: hash resolves at
                     * the recorded height on a trust-rooted chain. The
                     * boot consumer re-checks that agreement before any
                     * active-chain install. */
                    LOG_WARN("utxo_recovery",
                             "scan_fallback h=%d below durable finalized floor "
                             "h=%d; refusing active-tip rollback",
                             scan_fallback->nHeight, served_floor);
                    res.restored = true;
                    res.restored_height = served_floor;
                    if (have_served_hash)
                        res.restored_hash = served_hash;
                    res.skip_activate = true;
                    snprintf(res.anchor_reason, sizeof(res.anchor_reason),
                             "finalized_floor_guard");
                    return res;
                }
                /* fall through: every row outranking scan_fallback was
                 * unbackable and is now rewound — the commit is permitted. */
            }
            struct block_index *committed = scan_fallback;
            if (utxo_recovery_commit_tip(
                    ctx, &committed, "scan_fallback", false, false).ok) {
                printf("WARNING: Chain tip at height %d but coins DB is empty!\n",
                       scan_fallback->nHeight);
                if (utxo_recovery_scan_fallback_keep_commit(ctx, committed)) {
                    res.restored = true;
                    res.restored_height = committed->nHeight;
                    if (committed->phashBlock)
                        res.restored_hash = *committed->phashBlock;
                }
            } else {
                res.status = ZCL_ERR(-21,
                    "utxo_recovery_restore_chain_tip: scan_fallback commit "
                    "failed h=%d", scan_fallback->nHeight);
                LOG_WARN("utxo_recovery", "%s", res.status.message);
            }
        }
        return res;
    }

    struct block_index *best = block_map_find(
        &ctx->state->map_block_index, &best_hash);

    /* Diagnostic: log whether coins_best_block was found in block_index */
    {
        char hex[65];
        uint256_get_hex(&best_hash, hex);
        if (best)
            printf("[boot] coins_best_block %s found in block_index "
                   "at h=%d\n", hex, best->nHeight);
        else
            printf("[boot] coins_best_block %s NOT found in block_index "
                   "(map size=%zu)\n", hex,
                   ctx->state->map_block_index.size);
    }

    /* SQLite fallback: if block_map maps the hash to height 0
     * but it's not actually the genesis block */
    if (best && best->nHeight == 0 &&
        !uint256_eq(&best_hash, &ctx->params->consensus.hashGenesisBlock)) {
        char hex[65];
        uint256_get_hex(&best_hash, hex);
        LOG_WARN("chain", "coins DB best block %s mapped to height=0 " "in block_index (not genesis)", hex);
        if (ctx->ndb->open) {
            struct db_block sqlite_blk;
            if (db_block_find_by_hash(ctx->ndb, best_hash.data,
                                       &sqlite_blk) &&
                sqlite_blk.height > 0) {
                printf("Correcting: block nHeight 0→%d from SQLite\n",
                       sqlite_blk.height);
                best->nHeight = sqlite_blk.height;
            } else {
                best = NULL;
            }
        } else {
            best = NULL;
        }
    }

    if (best && best->nHeight == 0 &&
        uint256_eq(&best_hash, &ctx->params->consensus.hashGenesisBlock)) {
        int max_utxo_h = utxo_recovery_max_utxo_height(ctx);
        if (max_utxo_h > 1000) {
            struct block_index *utxo_tip =
                utxo_recovery_find_disk_backed_utxo_tip(ctx, max_utxo_h);
            if (utxo_tip && utxo_tip->phashBlock) {
                char tip_hex[65] = {0};
                uint256_get_hex(utxo_tip->phashBlock, tip_hex);
                LOG_INFO("boot", "[boot] coins_best_block is genesis but UTXOs reach " "h=%d; recovering directly to disk-backed UTXO ancestor " "h=%d hash=%s", max_utxo_h, utxo_tip->nHeight, tip_hex);
                best = utxo_tip;
                best_hash = *utxo_tip->phashBlock;
            } else {
                LOG_INFO("boot", "[boot] coins_best_block is genesis but UTXOs reach " "h=%d; no disk-backed UTXO ancestor found within " "10000 blocks", max_utxo_h);
            }
        }
    }

    /* Cold-import seed-anchor provenance (PART B). The snapshot base is a
     * legitimate null-pprev root; the _seeded backed check below accepts it
     * as consensus-backed DESPITE the null pprev when it provenance-matches,
     * so a restart past the seed restores to the base, not genesis. Absent on
     * every normal / P2P datadir → seed_anchor_hash_p stays NULL (identical). */
    struct uint256 seed_anchor_hash;
    int seed_anchor_h = -1;
    const struct uint256 *seed_anchor_hash_p = NULL;
    if (ctx->ndb && ctx->ndb->open &&
        utxo_recovery_read_cold_import_seed(ctx->ndb, &seed_anchor_h,
                                            &seed_anchor_hash))
        seed_anchor_hash_p = &seed_anchor_hash;

    /* PART C: register the seed anchor as the Invariant A trust-root terminus
     * (utxo_recovery_block_ancestry_break) so the commit treats coins_best as
     * trust-rooted, not a detached island. NULL/-1 on normal datadirs = no-op. */
    utxo_recovery_set_cold_import_trust_anchor(seed_anchor_hash_p, seed_anchor_h);

    if (best) {
        /* Correct an LDB-import header-only height-tear (glue in the gate TU). */
        utxo_recovery_relink_island_if_present(ctx, best);
        struct block_index *restore_tip = best;
        bool best_backed =
            chain_restore_block_is_consensus_backed_on_disk_seeded(
                best, ctx->datadir, seed_anchor_hash_p, seed_anchor_h);
        {
            char best_hex[65] = {0};
            char prev_hex[65] = {0};
            bool merkle_null = uint256_is_null(&best->hashMerkleRoot);
            if (best->phashBlock)
                uint256_get_hex(best->phashBlock, best_hex);
            if (best->pprev && best->pprev->phashBlock)
                uint256_get_hex(best->pprev->phashBlock, prev_hex);
            LOG_INFO("boot", "[boot] coins_best_block validation h=%d hash=%s " "status=%u file=%d pos=%u tx=%u chaintx=%lld bits=%u " "pprev_h=%d pprev=%s merkle_null=%d disk_backed=%d", best->nHeight, best_hex[0] ? best_hex : "<null>", best->nStatus, best->nFile, best->nDataPos, best->nTx, (long long)best->nChainTx, best->nBits, best->pprev ? best->pprev->nHeight : -1, prev_hex[0] ? prev_hex : "<null>", merkle_null ? 1 : 0, best_backed ? 1 : 0);
        }
        if (!best_backed) {
            restore_tip = chain_restore_nearest_consensus_backed_ancestor_on_disk_seeded(
                best, ctx->datadir, seed_anchor_hash_p, seed_anchor_h);
            if (restore_tip && restore_tip->phashBlock) {
                char bad_hex[65], good_hex[65];
                uint256_get_hex(&best_hash, bad_hex);
                uint256_get_hex(restore_tip->phashBlock, good_hex);
                LOG_INFO("boot", "[boot] coins_best_block %s at h=%d is not backed by " "real block data; using nearest consensus-backed " "ancestor h=%d hash=%s", bad_hex, best->nHeight, restore_tip->nHeight, good_hex);
            }
        } else if (has_disk_backed_competing_sibling(ctx->state, best,
                                                    ctx->datadir)) {
            restore_tip = best->pprev;
            if (restore_tip && restore_tip->phashBlock) {
                char bad_hex[65], parent_hex[65];
                uint256_get_hex(&best_hash, bad_hex);
                uint256_get_hex(restore_tip->phashBlock, parent_hex);
                LOG_INFO("boot", "[boot] coins_best_block %s at h=%d is a disk-backed " "fork leaf with a competing disk-backed sibling; " "restoring common ancestor h=%d hash=%s so normal " "validation can choose the best branch", bad_hex, best->nHeight, restore_tip->nHeight, parent_hex);
            }
        }

        if (!restore_tip) {
            LOG_INFO("boot", "[boot] coins_best_block found in index but no " "consensus-backed ancestor is available; waiting for P2P");
            return res;
        }

        /* PART B success path: the restore target IS the provenance-matched
         * cold-import seed anchor — name it loudly for a copy-prove. */
        if (seed_anchor_hash_p && restore_tip->phashBlock &&
            restore_tip->nHeight == seed_anchor_h &&
            uint256_cmp(restore_tip->phashBlock, seed_anchor_hash_p) == 0) {
            char sa_hex[65] = {0};
            uint256_get_hex(restore_tip->phashBlock, sa_hex);
            LOG_INFO("boot", "[boot] restoring to provenance-matched cold-import seed anchor h=%d hash=%s", restore_tip->nHeight, sa_hex);
        }

        struct block_index *committed = restore_tip;
        struct zcl_result crc = utxo_recovery_commit_tip(
            ctx, &committed, "coins_best_restore", true, false);
        if (!crc.ok) {
            if (crc.code == -47) {
                /* Invariant A refusal: the candidate is not derivable from
                 * the validated header frontier and the frontier block is
                 * absent from the index. Same exit shape as the "no
                 * consensus-backed ancestor" path above: leave the tip
                 * un-restored and wait for P2P; the crash-only auto-reindex
                 * remains the deeper fallback. */
                LOG_WARN("utxo_recovery", "%s", crc.message);
                return res;
            }
            res.status = ZCL_ERR(-22,
                "utxo_recovery_restore_chain_tip: coins_best_restore commit "
                "failed h=%d: %s", restore_tip->nHeight, crc.message);
            LOG_WARN("utxo_recovery", "%s", res.status.message);
            return res;
        }
        /* The gate may have LOWERED the tip to the frontier ancestor —
         * everything below (active-chain rebuild, event, result fields)
         * must describe what was actually INSTALLED. */
        restore_tip = committed;
        (void)chain_restore_rebuild_active_chain(ctx->state, restore_tip, NULL);
        printf("Restored chain tip from coins DB: height=%d\n",
               restore_tip->nHeight);
        event_emitf(EV_BOOT_CHAIN_RESTORED, 0, "height=%d",
                    restore_tip->nHeight);
        res.restored = true;
        res.restored_height = restore_tip->nHeight;
        if (restore_tip->phashBlock)
            res.restored_hash = *restore_tip->phashBlock;

        /* populate active_chain.chain from pprev +
         * block_map, and backfill nBits from on-disk block headers for
         * any pindex entry whose nBits is still zero. Without this, the
         * anchor-restore path leaves `getblockhash <h>` broken for every
         * h below the tip and GetNextWorkRequired trips `bad-diffbits`
         * on the first real-difficulty header whose pprev window
         * includes an nBits==0 entry. */
        snapsync_set_anchor(NULL);
        (void)chain_restore_finalize(ctx->state, ctx->datadir);

        return res;
    }

    /* coins_best_block not in block_map — create placeholder anchor */
    char hex[65];
    uint256_get_hex(&best_hash, hex);
    printf("Coins DB best block %s not in index (block_map size=%zu).\n",
           hex, ctx->state->map_block_index.size);

    int utxo_max_height = utxo_recovery_max_utxo_height(ctx);

    if (utxo_max_height > 0) {
        struct block_index *anchor =
            chain_restore_create_anchor(ctx->state, &best_hash,
                                        utxo_max_height);
        if (anchor) {
            snapsync_set_anchor(anchor);

            printf("Chain restore: metadata anchor at h=%d hash=%s "
                   "— waiting for real block data.\n", utxo_max_height, hex);
            /* Record-only: same band-hole producer class as the LDB
             * import anchor above (ancestry-derived). */
            utxo_recovery_note_band_unrooted_tip(
                anchor, "chain_restore_anchor");
            /* see the same call above; fire here too
             * so the fresh-anchor path gets rebuild + nBits backfill. */
            (void)chain_restore_finalize(ctx->state, ctx->datadir);
            res.restored_height = anchor->nHeight;
            if (anchor->phashBlock)
                res.restored_hash = *anchor->phashBlock;
        }
        res.skip_activate = true;
        snprintf(res.anchor_reason, sizeof(res.anchor_reason),
                 "chain_restore_anchor");
    } else {
        /* No UTXOs — wipe and start fresh */
        printf("No UTXOs found — wiping coins state.\n");
        struct zcl_result wipe =
            utxo_recovery_wipe(ctx->ndb, "boot.restore_no_utxos");
        if (!wipe.ok) {
            res.status = ZCL_ERR(wipe.code,
                "utxo_recovery_restore_chain_tip: wipe refused/failed for "
                "empty UTXO restore: %s", wipe.message);
            LOG_WARN("utxo_recovery", "%s", res.status.message);
            return res;
        }
        if (!utxo_recovery_commit_genesis(ctx, "boot.restore_no_utxos").ok) {
            res.status = ZCL_ERR(-24,
                "utxo_recovery_restore_chain_tip: genesis commit failed "
                "after empty UTXO restore");
            LOG_WARN("utxo_recovery", "%s", res.status.message);
            return res;
        }
        res.restored_height = 0;
        res.restored_hash = ctx->params->consensus.hashGenesisBlock;
    }

    res.restored = true;
    return res;
}
