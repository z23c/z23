/* boot_refold_staged.c — the -refold-staged reset, in its own file separate
 * from boot.c so each file keeps one focused responsibility. Resets the staged
 * reducer's durable derived state to genesis so the staged pipeline re-folds
 * forward over on-disk block BODIES. Contract declared in config/boot.h. */
#include "config/boot.h"
#include "platform/time_compat.h"
#include "platform/file_sync.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>          /* EXIT_FAILURE */
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>          /* _exit */
#include <dirent.h>          /* opendir/readdir — bundle auto-detect */
#include <sqlite3.h>

#include "models/database.h"
#include "storage/consensus_db.h"
#include "storage/progress_store.h"
#include "storage/coins_kv.h"
#include "storage/anchor_kv.h"
#include "storage/nullifier_kv.h"
#include "config/boot_shielded_seed.h"
#include "config/boot_snapshot_install.h"
#include "storage/disk_block_io.h"       /* block_index_have_data_readable */
#include "config/boot_internal.h"        /* boot_index_clear_coins_state */
#include "config/mint_anchor_progress.h" /* mint_anchor_progress_* */
#include "jobs/reducer_frontier.h"       /* progress_meta_delete_in_tx,
                                          * REDUCER_TRUSTED_BASE_*_KEY,
                                          * REDUCER_FRONTIER_TRUSTED_ANCHOR,
                                          * progress_store_tx_lock/unlock */
#include "jobs/stage_repair_internal.h"  /* stage_repair_force_stage_cursor */
#include "jobs/mint_fold_ceiling.h"      /* mint_fold_ceiling_set (-mint-anchor) */
#include "jobs/mint_skip_crypto.h"       /* mint_skip_crypto_set (-mint-anchor-fast) */
#include "jobs/refold_progress.h"        /* refold_progress_boot_init,
                                          * refold_progress_mark_started,
                                          * refold_progress_mark_started_from_anchor */
#include "jobs/tip_finalize_stage.h"     /* tip_finalize_stage_seed_anchor */
#include "jobs/utxo_apply_stage.h"
#include "chain/checkpoints.h"           /* get_sha3_utxo_checkpoint */
#include "chain/utxo_snapshot_loader.h"  /* uss_open/uss_iter/uss_close (mint) */
#include "event/event.h"                 /* event_emitf, EV_BOOT_VALIDATION_FAILED */
#include "services/block_index_loader.h" /* block_index_loader_torn_import_detect (B2 1c) */
#include "validation/main_state.h"       /* struct main_state */
#include "validation/chainstate.h"       /* active_chain_height, active_chain_at */
#include "chain/chain.h"                  /* struct block_index (hashBlock) */
#include "chain/chainparams.h"            /* chain_params_get (fold-span rebind);
                                          * scan_block_files_mark_data via
                                          * config/boot_internal.h above */
#include "controllers/sync_controller.h" /* sapling_tree_rebuild (re-seed tree) */
#include "sapling/incremental_merkle_tree.h" /* incremental_tree_deserialize/root */
#include "core/serialize.h"               /* struct byte_stream */
#include "core/uint256.h"                 /* struct uint256 */
#include "util/util.h"                   /* GetDataDir */
#include "util/safe_alloc.h"              /* zcl_malloc */
#include "util/blocker.h"                 /* refold.body_gap named blocker */
#include "util/log_macros.h"
#include "boot_refold_staged_snapshot.h"

/* Declared in engine/services/src/utxo_recovery_internal.h (src-private); forward
 * declare for the -refold-staged seed-provenance clear. */
void utxo_recovery_clear_cold_import_seed(struct node_db *ndb);
bool utxo_recovery_clear_cold_import_seed_checked(struct node_db *ndb);

#define BOOT_NELEM(a) (sizeof(a) / sizeof((a)[0]))

void boot_refold_staged_init(bool refold_staged)
{
    (void)refold_progress_boot_init(progress_store_db(), refold_staged);
}

static int boot_drop_bodiless_file_present(const char *datadir, int fn, int8_t *file_present,
                                           off_t *file_size, size_t memo_cap, off_t *present_size)
{
    if (fn < 0)
        return 0;  /* HAVE_DATA but no file slot — definitionally absent */
    if (fn < (int)memo_cap && file_present[fn] >= 0) {
        *present_size = file_size[fn];
        return file_present[fn];
    }
    char path[PATH_MAX];
    int n = snprintf(path, sizeof(path), "%s/blocks/blk%05d.dat", datadir, fn);
    struct stat st;
    int present = (n > 0 && (size_t)n < sizeof(path) &&
                   stat(path, &st) == 0 && st.st_size > 0) ? 1 : 0;
    *present_size = present ? st.st_size : 0;
    if (fn < (int)memo_cap) {
        file_present[fn] = (int8_t)present;
        file_size[fn] = *present_size;
    }
    return present;
}

static bool boot_drop_bodiless_body_readable(struct block_index *p, const char *datadir,
                                             off_t present_size, size_t *verified, size_t *rejected)
{
    if (!p->phashBlock || p->nDataPos == 0 ||
        (present_size > 0 && (off_t)p->nDataPos >= present_size))
        return false;
    if (block_index_have_data_readable(p, datadir)) {
        (*verified)++;
        return true;
    }
    (*rejected)++;
    return false;
}

/* Blocks-less bundle repair (the v2 snapshot judge bundle: block_index.bin +
 * snapshot, NO blocks/ dir). block_index.bin carries each entry's nStatus
 * INCLUDING BLOCK_HAVE_DATA plus the SOURCE datadir's (nFile, nDataPos). When
 * the bundle ships no bodies above the seed, those entries claim HAVE_DATA at a
 * blk file that does not exist on THIS node, so:
 *   - the have-data window extender (active_chain_extend_window_have_data) tries
 *     to fill to the bodiless slot, every stage read_block_pread_fail's, and the
 *     have_data_unreadable healer clears the flag one block at a time — but
 *   - a P2P-delivered body is then SKIPPED on write (process_block treats the
 *     entry as already-having-data from the stale flag), so the body never lands
 *     at a readable position; the window never extends past seed_h+1, and
 *     tip_finalize wedges on lookahead_tip_missing (H* frozen at the seed).
 *
 * Fix: BEFORE the staged pipeline starts, drop the borrowed have-data claim
 * whose referenced blk file is not trusted on THIS node — reset (nFile=-1,
 * nDataPos=0), clear BLOCK_HAVE_DATA, and floor validity at header-only
 * (BLOCK_VALID_TREE) so chain selection still sees the header but the body is
 * re-fetched + re-indexed cleanly via P2P. A legacy-import/datadir boot can
 * keep a non-empty blk file by the cheap stat() gate. A no-legacy snapshot boot
 * is stricter: it keeps an indexed body only if the block reads back and hashes
 * to the block-index entry, which rejects foreign or partial blk files while
 * preserving blocks this node genuinely fetched later.
 *
 * Returns the number of blocks whose borrowed have-data was dropped (0 on a
 * blocks-present bundle). The caller uses a non-zero return to retract the
 * active-chain tip to the seed: the boot's earlier CSR restore promoted the
 * active tip to the highest had-data block (the top of the borrowed span), and
 * the P2P download window follows active_chain_height(), so without the
 * retraction the node floods the TOP of the gap (header-tip successors) and
 * never fetches the connectable bottom (seed_h+1) the staged fold needs next. */
size_t boot_snapshot_drop_bodiless_have_data_above_seed(
    struct main_state *ms, const char *datadir, int seed_h,
    bool trust_existing_block_files)
{
    if (!ms || !datadir || seed_h < 0)
        return 0;

    /* Memoize stat() per nFile so a ~3k-block forward window costs ~1 stat per
     * blk file, not one per block. -1 = unknown, 0 = missing, 1 = present. */
    int8_t file_present[4096];
    off_t file_size[4096];
    memset(file_present, -1, sizeof(file_present));
    memset(file_size, 0, sizeof(file_size));

    size_t cleared = 0, kept = 0, verified = 0, rejected = 0;
    size_t iter = 0;
    struct block_index *p = NULL;
    while (block_map_next(&ms->map_block_index, &iter, NULL, &p)) {
        /* Clear borrowed have-data for absent bodies BELOW the seed too (not
         * just above): on a blocks-less bundle the ~3.1M below-seed entries
         * carry borrowed HAVE_DATA whose bodies were never shipped, and EVERY
         * have-data-gated walker (node_db_catchup, bg_validation, wallet_scan,
         * pprev-repair, utxo_mirror) then read-storms them — the crash. The
         * selected snapshot is the operational assisted base at/below seed_h;
         * those bodies are not needed for readiness. Protect ONLY the
         * seed block itself (its state is the snapshot's anchor). */
        if (!p || p->nHeight == seed_h)
            continue;
        if (!(p->nStatus & BLOCK_HAVE_DATA))
            continue;

        off_t present_size = 0;
        int present = boot_drop_bodiless_file_present(datadir, p->nFile, file_present,
            file_size, BOOT_NELEM(file_present), &present_size);

        if (present && !trust_existing_block_files)
            present = boot_drop_bodiless_body_readable(p, datadir, present_size,
                                                       &verified, &rejected);

        if (present) {
            kept++;
            continue;
        }

        /* Borrowed (bodiless) have-data claim: drop it so P2P re-fetch writes +
         * indexes the body at a readable position. Header validity is preserved
         * at BLOCK_VALID_TREE; the body stages re-run from a clean slot. */
        p->nStatus = (p->nStatus & ~(unsigned)BLOCK_HAVE_DATA);
        if ((p->nStatus & BLOCK_VALID_MASK) > BLOCK_VALID_TREE)
            p->nStatus = (p->nStatus & ~(unsigned)BLOCK_VALID_MASK)
                         | BLOCK_VALID_TREE;
        p->nFile = -1;
        p->nDataPos = 0;
        p->nTx = 0;
        cleared++;
    }

    if (cleared > 0)
        fprintf(stderr,
                "[boot] blocks-less state source: dropped borrowed have-data "
                "on %zu block(s) around seed h=%d "
                "(below+above; no trusted body on disk; %zu kept with real "
                "bodies; %zu hash-verified; %zu rejected by hash/read check; "
                "seed block protected; trust_existing_block_files=%s); "
                "have-data-gated walkers now skip them\n",
                cleared, seed_h, kept, verified, rejected,
                trust_existing_block_files ? "true" : "false");
    return cleared;
}

#ifdef ZCL_TESTING
size_t boot_snapshot_drop_bodiless_have_data_above_seed_for_test(
    struct main_state *ms, const char *datadir, int seed_h,
    bool trust_existing_block_files)
{
    return boot_snapshot_drop_bodiless_have_data_above_seed(ms, datadir,
                                                           seed_h,
                                                           trust_existing_block_files);
}
#endif

/* uss_iter callback: insert one snapshot record into coins_kv. The caller holds
 * the kernel-store (consensus.db) handle in an open BEGIN IMMEDIATE so every
 * coins_kv_add commits atomically with the rest. Stops the iteration (returns false) on a
 * coins_kv_add failure so the caller can ROLLBACK. */
struct mint_load_ctx {
    sqlite3 *pdb;
    uint64_t inserted;
    bool     failed;
};
static bool mint_load_record_cb(const struct uss_record *r, void *vctx)
{
    struct mint_load_ctx *c = vctx;
    if (!coins_kv_add(c->pdb, r->txid, r->vout, r->value,
                      (int32_t)r->height, r->is_coinbase != 0,
                      r->script, (size_t)r->script_len)) {
        c->failed = true;
        return false;
    }
    c->inserted++;
    return true;
}

static bool boot_snapshot_apply_records(sqlite3 *db, struct uss_handle *snapshot,
                                        uint64_t expected_count,
                                        struct mint_load_ctx *lc, int64_t *emitted)
{
    char *terr = NULL;
    uint8_t one = 1;
    *emitted = uss_iter(snapshot, mint_load_record_cb, lc);
    bool ok = !lc->failed && *emitted == (int64_t)expected_count &&
              lc->inserted == expected_count;
    ok = ok && progress_meta_set_in_tx(db, COINS_KV_MIGRATION_COMPLETE_KEY, &one, 1);
    if (ok && sqlite3_exec(db, "COMMIT", NULL, NULL, &terr) != SQLITE_OK)
        ok = false;
    if (!ok)
        sqlite3_exec(db, "ROLLBACK", NULL, NULL, NULL);
    if (terr)
        sqlite3_free(terr);
    return ok;
}

bool boot_snapshot_apply_to_coins_kv(sqlite3 *progress_db,
                                     struct uss_handle *snapshot,
                                     uint64_t expected_count,
                                     struct boot_snapshot_apply_result *out)
{
    if (out)
        memset(out, 0, sizeof(*out));
    if (!progress_db || !snapshot)
        LOG_FAIL("boot", "snapshot_apply: NULL argument");
    if (expected_count > (uint64_t)INT64_MAX) {
        LOG_WARN("boot", "snapshot_apply: expected_count=%llu exceeds int64",
                 (unsigned long long)expected_count);
        return false;
    }

    char *terr = NULL;
    if (sqlite3_exec(progress_db, "BEGIN IMMEDIATE", NULL, NULL, &terr)
        != SQLITE_OK) {
        LOG_WARN("boot", "snapshot_apply: BEGIN failed: %s",
                 terr ? terr : "(no msg)");
        if (terr) sqlite3_free(terr);
        return false;
    }

    struct mint_load_ctx lc = { .pdb = progress_db };
    int64_t emitted = 0;
    bool ok = boot_snapshot_apply_records(progress_db, snapshot, expected_count,
                                          &lc, &emitted);

    if (out) {
        out->inserted = lc.inserted;
        out->emitted = emitted;
    }
    if (!ok) {
        LOG_WARN("boot", "snapshot_apply: refused snapshot load "
                 "(emitted=%lld inserted=%llu expected=%llu failed=%d)",
                 (long long)emitted, (unsigned long long)lc.inserted,
                 (unsigned long long)expected_count, lc.failed ? 1 : 0);
        return false;
    }
    return true;
}

/* Re-seed coins_kv from the MINTED, SHA3-committed legacy anchor artifact (the
 * artifact the -mint-anchor ceremony produced). uss_open verifies the complete
 * payload SHA3 and legacy_uss_matches_checkpoint independently binds its
 * transparent component to the checkpoint before a single coin lands.
 * Returns true iff the snapshot was present, verified, and fully loaded into
 * coins_kv; false (with *present telling whether a file existed at all) when no
 * snapshot is available or it failed verification — the caller then falls back to
 * the node.db re-seed (which the hard-assert still guards). */
static bool boot_anchor_seed_from_snapshot(struct node_db *ndb, sqlite3 *rpdb,
                                           const struct sha3_utxo_checkpoint *cp,
                                           bool *present)
{
    if (present) *present = false;
    char path[1100];
    if (!boot_anchor_snapshot_path_resolve(ndb, path, sizeof(path)))
        return false;

    char err[256] = {0};
    struct uss_header hdr;
    struct uss_handle *h = uss_open(path, /*verify_full_sha3=*/true,
                                    /*expected_sha3=*/NULL,
                                    &hdr, err, sizeof(err));
    if (!h)
        return false;  /* absent or failed verify → fall back to node.db reseed */
    if (present) *present = true;

    if (!boot_legacy_uss_matches_checkpoint(
            h, &hdr, cp, err, sizeof(err))) {
        LOG_WARN("boot", "[boot] -refold-from-anchor: legacy artifact %s "
                 "does not match checkpoint height/hash/root/count/supply "
                 "(%s) — ignoring it", path, err[0] ? err : "component mismatch");
        uss_close(h);
        return false;
    }

    /* Bulk-load under ONE transaction so a crash mid-load rolls back cleanly. */
    if (!coins_kv_reset_for_reseed(rpdb)) {
        uss_close(h);
        return false;
    }
    struct boot_snapshot_apply_result ar = {0};
    bool ok = boot_snapshot_apply_to_coins_kv(rpdb, h, hdr.count, &ar);
    uss_close(h);

    if (ok)
        fprintf(stderr,
                "[boot] -refold-from-anchor: loaded %llu coins from the MINTED "
                "snapshot %s (SHA3 verified vs the compiled checkpoint)\n",
                (unsigned long long)ar.inserted, path);
    return ok;
}

static bool boot_progress_tx_begin(sqlite3 *db, char **err)
{
    progress_store_tx_lock();
    return sqlite3_exec(db, "BEGIN IMMEDIATE", NULL, NULL, err) == SQLITE_OK;
}

static bool boot_progress_tx_finish(sqlite3 *db, bool ok, char **err)
{
    if (ok && sqlite3_exec(db, "COMMIT", NULL, NULL, err) != SQLITE_OK)
        ok = false;
    if (!ok)
        sqlite3_exec(db, "ROLLBACK", NULL, NULL, NULL);
    if (*err) {
        sqlite3_free(*err);
        *err = NULL;
    }
    progress_store_tx_unlock();
    return ok;
}

static bool boot_progress_delete_tables(sqlite3 *db, const char *const *tables,
                                        size_t n, char **err)
{
    for (size_t i = 0; i < n; i++) {
        char dsql[96];
        snprintf(dsql, sizeof dsql, "DELETE FROM %s", tables[i]);
        if (sqlite3_exec(db, dsql, NULL, NULL, err) == SQLITE_OK)
            continue;
        if (!*err || !strstr(*err, "no such table"))
            return false;
        sqlite3_free(*err);
        *err = NULL;
    }
    return true;
}

static bool boot_progress_force_stages(sqlite3 *db, const char *const *stages,
                                       size_t n, int32_t h)
{
    for (size_t i = 0; i < n; i++)
        if (!stage_repair_force_stage_cursor(db, stages[i], h))
            return false;
    return true;
}

static bool boot_progress_raise_stage(sqlite3 *db, const char *stage, int32_t floor_h)
{
    int cur = -1;
    sqlite3_stmt *cst = NULL;
    if (sqlite3_prepare_v2(db, "SELECT cursor FROM stage_cursor WHERE name = ?",
                           -1, &cst, NULL) == SQLITE_OK) {
        sqlite3_bind_text(cst, 1, stage, -1, SQLITE_STATIC);
        if (sqlite3_step(cst) == SQLITE_ROW)  // raw-sql-ok:progress-kv-kernel-store
            cur = sqlite3_column_int(cst, 0);
    }
    if (cst)
        sqlite3_finalize(cst);
    return stage_repair_force_stage_cursor(db, stage, (cur > floor_h) ? cur : floor_h);
}

static void boot_anchor_require_proven(sqlite3 *rpdb,
                                       const struct sha3_utxo_checkpoint *cp,
                                       bool reseed_ok, int32_t anchor)
{
    uint8_t got_root[32] = {0};
    int64_t got_count = -1;
    char vreason[256] = {0};
    if (reseed_ok && coins_kv_verify_against_checkpoint(rpdb, cp, got_root,
                                                        &got_count, vreason,
                                                        sizeof vreason))
        return;
    fprintf(stderr,
            "FATAL: -refold-from-anchor: re-seeded anchor set FAILED the "
            "SHA3/count check (%s, reseed_ok=%d) — refusing to fold from an "
            "unproven anchor\n",
            reseed_ok ? vreason : "reseed failed", reseed_ok ? 1 : 0);
    event_emitf(EV_BOOT_VALIDATION_FAILED, 0,
                "check=refold_from_anchor anchor_h=%d reseed anchor set "
                "mismatch (count=%lld want=%llu) — the node.db `utxos` "
                "mirror does not reproduce the compiled checkpoint; ACTION: "
                "wipe + re-import with the two-step cold-sync recipe",
                anchor, (long long)got_count,
                (unsigned long long)cp->utxo_count);
    _exit(EXIT_FAILURE);
}

static bool boot_anchor_arm_cursors(sqlite3 *rpdb, int32_t anchor, bool minted)
{
    /* Phase 2 (one progress.kv transaction): clear the reducer-derived tables,
     * force the 8 stage cursors to the ANCHOR (NOT genesis), set the applied
     * frontier to anchor+1, drop the trusted-base declaration.
     * stage_repair_force_stage_cursor REQUIRES the caller hold the progress tx
     * lock + an open transaction. */
    static const char *const k_refold_tables[] = {
        "validate_headers_log", "body_fetch_log", "body_persist_log",
        "script_validate_log", "proof_validate_log", "utxo_apply_log",
        "tip_finalize_log", "utxo_apply_delta", "created_outputs",
    };
    static const char *const k_refold_stages[] = {
        "header_admit", "validate_headers", "body_fetch", "body_persist",
        "script_validate", "proof_validate", "utxo_apply", "tip_finalize",
    };
    char *err = NULL;
    bool ok = boot_progress_tx_begin(rpdb, &err) &&
              boot_progress_delete_tables(rpdb, k_refold_tables,
                                          BOOT_NELEM(k_refold_tables), &err) &&
              boot_progress_force_stages(rpdb, k_refold_stages,
                                         BOOT_NELEM(k_refold_stages), anchor);
    /* utxo_apply's next-height cursor convention: applied-through `anchor`
     * means the frontier value is anchor+1. */
    ok = ok && utxo_apply_frontier_set_in_tx(rpdb, anchor + 1);
    /* The UTXO snapshot does not carry historical Sprout/Sapling roots.
     * Record that absence explicitly: the fold must backfill [0,anchor)
     * before accepting an unknown shielded root. */
    ok = ok && boot_shielded_history_reset_incomplete_in_tx(rpdb, anchor);
    if (ok && minted) {
        uint8_t one = 1;
        ok = progress_meta_set_in_tx(rpdb, COINS_KV_SELF_FOLDED_KEY, &one, 1);
    }
    if (ok) {
        (void)progress_meta_delete_in_tx(rpdb, REDUCER_TRUSTED_BASE_HEIGHT_KEY);
        (void)progress_meta_delete_in_tx(rpdb, REDUCER_TRUSTED_BASE_HASH_KEY);
    }
    return boot_progress_tx_finish(rpdb, ok, &err);
}

/* B2 — the -refold-from-anchor reset (config/boot.h). Unlike the contained
 * legacy staged refold:
 *   (i)   coins_kv is FULL-reset (coins_kv_reset_for_reseed) — a height-bounded
 *         DELETE cannot restore spent-below-anchor coins, so we re-seed the
 *         WHOLE SHA3-verified anchor set. The source is the MINTED snapshot
 *         artifact when present (verified vs the compiled checkpoint by the
 *         loader); otherwise the existing node.db `utxos` re-seed fallback (the
 *         operator-paged path — the hard-assert below still guards it).
 *   (ii)  HARD-ASSERT the re-seeded set: coins_kv_commitment == the compiled
 *         checkpoint sha3_hash AND coins_kv_count == checkpoint utxo_count.
 *         On mismatch this FATALs (rolls back the cursor txn, pages
 *         EV_BOOT_VALIDATION_FAILED, _exit(EXIT_FAILURE)) — never advances on an
 *         unproven anchor set.
 *   (iii) the 8 stage cursors are forced to the ANCHOR (3,056,758), NOT genesis,
 *         coins_applied_height = anchor+1 (the utxo_apply next-height cursor
 *         convention) so the fold resumes AT the anchor.
 *   (iv)  tip_finalize_stage_seed_anchor(anchor, checkpoint block_hash, true) so
 *         the finalize served-tip prefix starts AT the anchor.
 *
 * The fold then climbs anchor -> active tip over on-disk BODIES, running the
 * REAL script_validate/proof_validate/utxo_apply/tip_finalize stages. Marks
 * refold_from_anchor (progress.kv) so the L0 floor HOLDS at the anchor (not 0)
 * and the below-anchor self-repair is suspended until utxo_apply reaches the
 * resume target. */
void boot_refold_from_anchor_reset(struct node_db *ndb)
{
    sqlite3 *rpdb = progress_store_db();
    if (!rpdb) {
        fprintf(stderr,
                "[boot] -refold-from-anchor: progress store not open; skip\n");
        return;
    }

    const struct sha3_utxo_checkpoint *cp = get_sha3_utxo_checkpoint();
    if (!cp) {
        fprintf(stderr, "FATAL: -refold-from-anchor: no compiled SHA3 UTXO "
                "checkpoint — cannot anchor the refold\n");
        event_emitf(EV_BOOT_VALIDATION_FAILED, 0,
                    "refold_from_anchor no_compiled_checkpoint");
        _exit(EXIT_FAILURE);
    }
    const int32_t anchor = cp->height;

    /* Neutralize the cold-import seed provenance so the later stage init
     * (block_index_loader_seed_stages_from_cold_import) does not re-stamp the
     * trusted anchor forward to the checkpoint. */
    utxo_recovery_clear_cold_import_seed(ndb);
    (void)node_db_state_set(ndb, "leveldb_utxo_migrated", NULL, 0);

    /* Phase 1 (own transactions): FULL coins_kv reset, then RE-SEED the anchor
     * set. PREFERRED SOURCE = the MINTED snapshot artifact (the -mint-anchor
     * ceremony's verified anchor UTXO set): the loader SHA3-verifies it AND
     * binds it to the compiled checkpoint before any coin lands, so it
     * reproduces the anchor exactly even on a contaminated datadir (§0d: the
     * node.db `utxos` mirror is the contaminated TIP, NOT the anchor — re-seeding
     * from it yields 1,344,574 ≠ 1,354,769). FALLBACK (no snapshot present) =
     * the existing node.db `utxos` re-seed, which the hard-assert below still
     * guards (FATALs if it doesn't reproduce the checkpoint — the operator-paged
     * path). Clear the node.db mirror commitment keys + header_admit_log +
     * sapling tree exactly like the from-genesis reset. */
    bool snap_present = false;
    bool reseed_ok =
        boot_anchor_seed_from_snapshot(ndb, rpdb, cp, &snap_present);
    bool seeded_from_minted_snapshot = reseed_ok;
    if (!reseed_ok) {
        if (snap_present)
            LOG_WARN("boot", "[boot] -refold-from-anchor: minted snapshot "
                     "present but unusable — falling back to the node.db reseed "
                     "(hard-assert will FATAL if it is the contaminated tip)");
        reseed_ok = coins_kv_reset_for_reseed(rpdb);
        if (reseed_ok)
            reseed_ok = coins_kv_seed_from_node_db(
                rpdb, sqlite3_db_filename(ndb->db, "main"));
    }
    (void)boot_index_clear_coins_state(ndb);
    (void)node_db_exec(ndb, "DELETE FROM header_admit_log");
    (void)node_db_state_set(ndb, "sapling_tree", NULL, 0);
    (void)node_db_state_set(ndb, "sapling_tree_rescan_height", NULL, 0);

    /* (ii) HARD-ASSERT the re-seeded anchor set against the compiled checkpoint
     * BEFORE arming any cursor. Routed through the ONE shared checkpoint verifier
     * coins_kv_verify_against_checkpoint (also used by -verify-rom) so the
     * digest/count comparison has a single impl; a wrong set must FATAL here. */
    boot_anchor_require_proven(rpdb, cp, reseed_ok, anchor);

    bool refold_ok = boot_anchor_arm_cursors(rpdb, anchor, seeded_from_minted_snapshot);
    if (!refold_ok) {
        fprintf(stderr,
                "FATAL: -refold-from-anchor: failed to force the 8 stage "
                "cursors to the anchor (h=%d) — refusing to start a half-armed "
                "fold\n", anchor);
        event_emitf(EV_BOOT_VALIDATION_FAILED, 0,
                    "check=refold_from_anchor anchor_h=%d cursor arm failed",
                    anchor);
        _exit(EXIT_FAILURE);
    }

    /* (iv) Seed the tip_finalize served-tip prefix AT the anchor (trusted seed —
     * the SHA3-verified base, same trust model snapshot_apply.c uses). */
    if (!tip_finalize_stage_seed_anchor(anchor, cp->block_hash, true))
        LOG_WARN("boot", "[boot] -refold-from-anchor: tip_finalize anchor seed "
                 "returned false (stage not yet wired?) — the runtime authority "
                 "re-seeds from the coins tip");

    fprintf(stderr,
            "[boot] -refold-from-anchor: anchor coin set RE-SEEDED + verified "
            "(count=%llu, SHA3 OK) at h=%d; the 8 stage cursors forced to the "
            "anchor; the staged pipeline re-folds forward over on-disk bodies "
            "(H* climbs from the anchor as the logs fill)\n",
            (unsigned long long)cp->utxo_count, anchor);
}

/* -load-snapshot-at-own-height=PATH (config/boot.h). EXPLICIT-ONLY recovery
 * loader. Sibling of boot_refold_from_anchor_reset EXCEPT:
 *   (i)   uss_open(path, verify_full_sha3=true,
 *         expected_sha3=NULL) recomputes the body SHA3 and compares it to the
 *         file's OWN hdr.sha3_hash; it is NOT bound to the compiled checkpoint.
 *         We additionally require uss_iter to consume EXACTLY hdr.count records
 *         (records_parsed == hdr.count). Either check failing → LOG_FAIL +
 *         FATAL-refuse; NO coin is ever stamped on a self-inconsistent file.
 *   (ii)  the fold resumes at the snapshot's OWN header height (hdr.height),
 *         NOT the compiled anchor — so a snapshot taken ABOVE the compiled
 *         checkpoint seeds at its real height and the fold climbs from there.
 *   (iii) the 8 stage cursors are forced to hdr.height, coins_applied_height =
 *         hdr.height+1 (utxo_apply next-height convention), tip_finalize seeded
 *         AT hdr.height (assisted; headers do not commit state contents).
 * The staged pipeline then folds FORWARD over on-disk BODIES from hdr.height to
 * the active tip running the REAL script/proof/utxo_apply/tip_finalize stages.
 *
 * GATED: only called when ctx->load_snapshot_at_own_height is non-NULL (an
 * operator-supplied path); a normal boot never reaches it. */

/* FIX 3 seam (see boot.h). PURE: no side effects. */
static bool boot_load_snapshot_resume_seed_from_authority(
    const struct uss_header *hdr,
    sqlite3 *rpdb,
    struct main_state *ms,
    int32_t applied)
{
    if (!hdr || !rpdb || applied <= 0)
        return false;

    int32_t seed_h = (int32_t)hdr->height;
    int32_t authority_h = applied - 1;
    if (authority_h < seed_h)
        return false;

    int32_t hstar = 0;
    int32_t served = 0;
    progress_store_tx_lock();
    bool hstar_ok = reducer_frontier_compute_hstar(rpdb, &hstar, &served);
    progress_store_tx_unlock();
    if (!hstar_ok) {
        LOG_WARN("boot",
                 "[boot] -load-snapshot-at-own-height: resume repair skipped "
                 "because H* read failed (applied=%d seed_h=%d)",
                 applied, seed_h);
        return false;
    }
    if (hstar >= authority_h)
        return true;

    if (!ms) {
        LOG_WARN("boot",
                 "[boot] -load-snapshot-at-own-height: resume repair needed "
                 "H*=%d authority_h=%d but main_state is unavailable",
                 hstar, authority_h);
        return false;
    }

    struct block_index *anchor = boot_refold_snapshot_resume_resolve_anchor(ms, authority_h);
    if (!anchor || anchor->nHeight != authority_h || !anchor->phashBlock) {
        LOG_WARN("boot",
                 "[boot] -load-snapshot-at-own-height: resume repair skipped "
                 "because authority block h=%d is not resolved (H*=%d seed_h=%d)",
                 authority_h, hstar, seed_h);
        return false;
    }

    if (!tip_finalize_stage_seed_anchor(authority_h,
                                        anchor->phashBlock->data,
                                        true)) {
        LOG_WARN("boot",
                 "[boot] -load-snapshot-at-own-height: resume repair seed "
                 "failed h=%d H*=%d seed_h=%d",
                 authority_h, hstar, seed_h);
        return false;
    }

    if (!boot_refold_snapshot_resume_stamp_cursors(rpdb, authority_h))
        return false;

    int32_t after = 0;
    int32_t after_served = 0;
    progress_store_tx_lock();
    bool after_ok =
        reducer_frontier_compute_hstar(rpdb, &after, &after_served);
    progress_store_tx_unlock();
    if (!after_ok || after < authority_h) {
        boot_refold_snapshot_resume_warn_incomplete(after_ok, after, authority_h, hstar,
                                    seed_h);
        return false;
    }

    LOG_INFO("boot",
             "[boot] -load-snapshot-at-own-height: resume repair seeded "
             "trusted reducer base h=%d (H* %d -> %d, snapshot seed h=%d)",
             authority_h, hstar, after, seed_h);
    event_emitf(EV_RECOVERY_ACTION, 0,
                "load_snapshot_at_own_height resume_repair h=%d hstar_before=%d "
                "hstar_after=%d seed_h=%d",
                authority_h, hstar, after, seed_h);
    return true;
}

static bool quarantine_progress_file(const char *datadir, const char *base,
                                     const char *suffix,
                                     int64_t stamp, unsigned seq,
                                     bool *moved_any)
{
    char src[PATH_MAX];
    int n = snprintf(src, sizeof(src), "%s/%s%s", datadir, base, suffix);
    if (n <= 0 || (size_t)n >= sizeof(src)) {
        fprintf(stderr,
                "[boot] -load-snapshot-at-own-height: %s quarantine "
                "path too long for suffix %s\n", base, suffix);
        return false;
    }

    struct stat st;
    if (stat(src, &st) != 0) {
        if (errno == ENOENT)
            return true;
        fprintf(stderr,
                "[boot] -load-snapshot-at-own-height: stat(%s) before "
                "%s quarantine failed: %s\n", src, base, strerror(errno));
        return false;
    }

    char dst[PATH_MAX];
    n = snprintf(dst, sizeof(dst), "%s/%s%s.quarantine.%lld.%ld.%u",
                 datadir, base, suffix, (long long)stamp, (long)getpid(), seq);
    if (n <= 0 || (size_t)n >= sizeof(dst)) {
        fprintf(stderr,
                "[boot] -load-snapshot-at-own-height: %s quarantine "
                "destination too long for %s\n", base, src);
        return false;
    }
    if (rename(src, dst) != 0) {
        fprintf(stderr,
                "[boot] -load-snapshot-at-own-height: rename(%s -> %s) "
                "failed: %s\n", src, dst, strerror(errno));
        return false;
    }
    if (moved_any)
        *moved_any = true;
    fprintf(stderr,
            "[boot] -load-snapshot-at-own-height: quarantined broken "
            "authority-store file %s -> %s\n", src, dst);
    return true;
}

static void fsync_datadir_best_effort(const char *datadir)
{
#ifdef O_DIRECTORY
    int fd = open(datadir, O_RDONLY | O_DIRECTORY);
#else
    int fd = open(datadir, O_RDONLY);
#endif
    if (fd < 0)
        return;
    (void)platform_file_sync(fd);
    close(fd);
}

static bool reopen_progress_store_after_verified_snapshot(const char *datadir,
                                                          sqlite3 **db_out,
                                                          const char *reason)
{
    if (db_out)
        *db_out = NULL;
    if (!datadir || !datadir[0]) {
        fprintf(stderr,
                "FATAL: -load-snapshot-at-own-height: no datadir available "
                "to rebuild the kernel store after %s\n", reason);
        event_emitf(EV_BOOT_VALIDATION_FAILED, 0,
                    "load_snapshot_at_own_height no_datadir reason=%s", reason);
        return false;
    }

    progress_store_close();
    int64_t stamp = (int64_t)platform_time_wall_time_t();
    static unsigned quarantine_seq;
    unsigned seq = ++quarantine_seq;
    /* Reset BOTH physical stores: consensus.db is the kernel authority after
     * the A3 flip, and progress.kv must go too so progress_store_open's
     * migrate-on-open cannot resurrect the old kernel from progress.kv's stale
     * pre-flip copy. The reopen then mints a fresh consensus.db and the Class C
     * projections re-fold from the re-seeded kernel. */
    bool moved_any = false;
    bool ok = true;
    const char *const bases[] = { CONSENSUS_DB_FILENAME, "progress.kv" };
    const char *const suffixes[] = { "", "-wal", "-shm" };
    for (size_t b = 0; ok && b < sizeof(bases) / sizeof(bases[0]); b++)
        for (size_t s = 0; ok && s < sizeof(suffixes) / sizeof(suffixes[0]); s++)
            ok = quarantine_progress_file(datadir, bases[b], suffixes[s], stamp,
                                          seq, &moved_any);
    if (!ok) {
        event_emitf(EV_BOOT_VALIDATION_FAILED, 0,
                    "load_snapshot_at_own_height progress_store_quarantine_failed "
                    "reason=%s", reason);
        return false;
    }
    if (moved_any)
        fsync_datadir_best_effort(datadir);

    if (!progress_store_open(datadir)) {
        event_emitf(EV_BOOT_VALIDATION_FAILED, 0,
                    "load_snapshot_at_own_height progress_store_reopen_failed "
                    "reason=%s", reason);
        return false;
    }
    sqlite3 *db = progress_store_db();
    if (!db) {
        event_emitf(EV_BOOT_VALIDATION_FAILED, 0,
                    "load_snapshot_at_own_height progress_store_reopen_null "
                    "reason=%s", reason);
        return false;
    }
    fprintf(stderr,
            "[boot] -load-snapshot-at-own-height: kernel store reopened after "
            "quarantine (reason=%s); snapshot was already SHA3-verified and "
            "passed the loader proof gate before the old authority store was "
            "moved\n",
            reason);
    event_emitf(EV_RECOVERY_ACTION, 0,
                "progress_store_quarantined_for_snapshot_reseed reason=%s "
                "moved=%d", reason, moved_any ? 1 : 0);
    if (db_out)
        *db_out = db;
    return true;
}

static bool boot_bundle_snapshot_height(const char *nm, const char *pfx, const char *sfx, size_t name_cap, long long *h)
{
    size_t plen = strlen(pfx), slen = strlen(sfx), len = strlen(nm);
    if (len <= plen + slen || len >= name_cap || strncmp(nm, pfx, plen) != 0 ||
        strcmp(nm + len - slen, sfx) != 0)
        return false;
    *h = 0;
    for (size_t i = plen; i < len - slen; i++) {
        if (nm[i] < '0' || nm[i] > '9')
            return false;
        *h = *h * 10 + (nm[i] - '0');
    }
    return true;
}

static bool boot_bundle_failed_marker(const char *datadir, const char *nm)
{
    char failp[1200];
    int fpn = snprintf(failp, sizeof(failp), "%s/%s.failed", datadir, nm);
    return fpn > 0 && (size_t)fpn < sizeof(failp) && access(failp, F_OK) == 0;
}

char *boot_autodetect_bundle_snapshot(const char *datadir)
{
    if (!datadir || !datadir[0])
        return NULL;

    /* block_index.bin is required to check chain location, not state contents. */
    char bi_path[1100];
    int bn = snprintf(bi_path, sizeof(bi_path), "%s/block_index.bin", datadir);
    if (bn < 0 || (size_t)bn >= sizeof(bi_path))
        return NULL;
    bool have_block_index = (access(bi_path, F_OK) == 0);

    DIR *d = opendir(datadir);
    if (!d)
        return NULL;

    /* Match utxo-seed-<digits>.snapshot; the highest height wins. */
    static const char PFX[] = "utxo-seed-";
    static const char SFX[] = ".snapshot";
    char best_name[256] = {0};
    long long best_h = -1;
    struct dirent *ent;
    while ((ent = readdir(d)) != NULL) {
        const char *nm = ent->d_name;
        long long h = 0;
        if (!boot_bundle_snapshot_height(nm, PFX, SFX, sizeof(best_name), &h))
            continue;
        /* Failure memory (never-stuck): a prior boot that crash-failed seeding
         * THIS snapshot wrote a sibling "<name>.failed" marker (see boot.c
         * around the autodetect reset call). Skip such a snapshot so a bad /
         * incompatible / corrupt bundle degrades to normal P2P IBD on the next
         * (systemd Restart=always) boot instead of crash-looping forever — no
         * human needed to delete the file. The explicit -load-snapshot flag is
         * unaffected (it never comes through here). */
        if (boot_bundle_failed_marker(datadir, nm)) {
            LOG_WARN("boot",
                     "[boot] starter-pack snapshot %s has a .failed marker from a "
                     "prior failed seed — skipping it; using normal P2P sync. "
                     "Delete %s.failed to retry the bundle.", nm, nm);
            continue;
        }
        if (h > best_h) {
            best_h = h;
            snprintf(best_name, sizeof(best_name), "%s", nm);
        }
    }
    closedir(d);

    if (best_h < 0)
        return NULL;  /* no starter-pack snapshot present */

    if (!have_block_index) {
        LOG_WARN("boot",
                 "[boot] starter-pack snapshot %s is present but block_index.bin "
                 "is NOT in the datadir — the snapshot seed needs the header "
                 "index to check its chain location, not authenticate contents. "
                 "Download block_index.bin; using normal P2P sync this run.",
                 best_name);
        return NULL;
    }

    char *out = zcl_malloc(1100, "autodetect_bundle_snapshot");
    int on = out ? snprintf(out, 1100, "%s/%s", datadir, best_name) : -1;
    if (on < 0 || on >= 1100) {
        free(out);
        return NULL;
    }
    return out;
}

/* True once per run: the caller should `goto` its retry label after the
 * authority store was rebuilt. */
static bool boot_snapshot_authority_retry(bool *used, const char *datadir,
                                          sqlite3 **rpdb, const char *reason)
{
    if (*used)
        return false;
    *used = true;
    return reopen_progress_store_after_verified_snapshot(datadir, rpdb, reason);
}

static bool boot_snapshot_arm_cursors(sqlite3 *rpdb, struct main_state *ms, int32_t seed_h, bool sapling_installed, bool v3, uint8_t *frontier, uint32_t flen, uint8_t *sprout, uint32_t slen, uint8_t *nullifiers, uint64_t ncount)
{
    /* Phase 2 — TWO-TIER stage reset (one progress.kv transaction).
     *
     * SOUNDNESS / why two tiers (the keystone of this loader): the snapshot
     * re-seeds ONLY the UTXO set (coins_kv) at seed_h. Two of the eight stages
     * (header_admit, validate_headers) validate ONLY PoW/Equihash from the
     * in-memory header chain and NEVER read coins; two more (body_fetch,
     * body_persist) only observe on-disk block bodies + build the forward
     * created_outputs creation index — also coins-INDEPENDENT. Their work
     * ABOVE seed_h is therefore still valid after the re-seed and MUST be
     * preserved, because:
     *   (a) rewinding validate_headers forces a P2P header RE-SYNC that, against
     *       a confused getheaders locator, collapses pindex_best_header from the
     *       on-disk header tip down to the seed — capping the WHOLE fold at the
     *       seed height (observed: header tip pinned, H* frozen one block past
     *       the seed). Keeping validate_headers at the on-disk tip keeps
     *       pindex_best_header at the real tip, so active_chain_extend_window
     *       supplies the lookahead all the way up and the coins-fold climbs over
     *       ON-DISK bodies with NO peers.
     *   (b) created_outputs (body_persist's forward creation index) is exactly
     *       what script_validate's prevout resolver reads for coins created in
     *       blocks ABOVE seed_h — deleting it would make every such prevout
     *       unresolvable.
     * The other FOUR stages (script_validate, proof_validate, utxo_apply,
     * tip_finalize) DO read/derive from the coins set, so their rows above the
     * old (contaminated) seed are stale: force them DOWN to seed_h and clear
     * their derived tables so they re-run against the freshly seeded coins.
     *
     * Coins-INDEPENDENT stages: preserve at MAX(current, seed_h) — never rewind
     * below the seed, never below where they already are. Their log tables and
     * created_outputs are KEPT. */
    static const char *const k_keep_stages[] = {
        "header_admit", "validate_headers", "body_fetch", "body_persist",
    };
    /* Coins-DEPENDENT stages: force to seed_h; their derived tables are cleared
     * (created_outputs is deliberately NOT here — it is body_persist's index). */
    static const char *const k_coins_stages[] = {
        "script_validate", "proof_validate", "utxo_apply", "tip_finalize",
    };
    static const char *const k_coins_tables[] = {
        "script_validate_log", "proof_validate_log", "utxo_apply_log",
        "tip_finalize_log", "utxo_apply_delta",
    };
    char *err = NULL;
    bool ok = boot_progress_tx_begin(rpdb, &err) &&
              boot_progress_delete_tables(rpdb, k_coins_tables,
                                          BOOT_NELEM(k_coins_tables), &err);
    /* Coins-independent stages: keep their on-disk progress (only raise to
     * seed_h if somehow behind it — never rewind the validated header/body
     * frontier below where it already stands). Read the durable cursor with a
     * direct query (we already hold the progress tx lock + an open tx). */
    for (size_t i = 0;
         ok && i < BOOT_NELEM(k_keep_stages);
         i++)
        ok = boot_progress_raise_stage(rpdb, k_keep_stages[i], seed_h);
    /* Coins-dependent stages: force DOWN to the seed to re-fold against the
     * freshly seeded coins. */
    ok = ok && boot_progress_force_stages(rpdb, k_coins_stages,
                                          BOOT_NELEM(k_coins_stages), seed_h) &&
         utxo_apply_frontier_set_in_tx(rpdb, seed_h + 1);
    /* SHIELDED SEED (v3, Sapling root-verified) or the default cursor reset
     * (v1/v2). Fail-closed. See config/boot_shielded_seed.h. */
    ok = ok && boot_shielded_cure_or_reset_in_tx(rpdb, ms, seed_h, sapling_installed, v3, frontier, flen, sprout, slen, nullifiers, ncount);
    if (ok) {
        (void)progress_meta_delete_in_tx(rpdb, REDUCER_TRUSTED_BASE_HEIGHT_KEY);
        (void)progress_meta_delete_in_tx(rpdb, REDUCER_TRUSTED_BASE_HASH_KEY);
    }
    return boot_progress_tx_finish(rpdb, ok, &err);
}

/* The exact receipt + coins authority already cover this snapshot: repair the
 * stage cursors from the authority and finish without reseeding. Fatal when
 * the repair fails. Closes h. */
static void boot_snapshot_resume_finish(
    struct uss_handle *h, const char *path, const struct uss_header *hdr,
    const uint8_t artifact_sha256[32], struct main_state *ms, int32_t applied,
    int32_t seed_h, bool prior_frontier_verified)
{
    bool repaired = boot_load_snapshot_resume_seed_from_authority(
        hdr, progress_store_db(), ms, applied);
    if (!repaired) {
        fprintf(stderr, "FATAL: persisted coins authority h=%d failed "
                "snapshot resume repair; REFUSING recovery\n", applied - 1);
        event_emitf(EV_BOOT_VALIDATION_FAILED, 0,
                    "load_snapshot resume_repair_failed applied=%d seed_h=%d",
                    applied, seed_h);
        uss_close(h);
        _exit(EXIT_FAILURE);
    }
    LOG_INFO_IN("boot_load_snapshot_at_own_height_reset", "boot", "[boot] exact assisted receipt + coins authority "
             "resume at h=%d from seed h=%d (stage repair ok)",
             applied - 1, seed_h);
    event_emitf(EV_RECOVERY_ACTION, 0,
                "load_snapshot resume_skip applied=%d seed_h=%d",
                applied, seed_h);
    boot_snapshot_install_record_proof(path, hdr, artifact_sha256,
                                       prior_frontier_verified);
    uss_close(h);
}

static const char *const k_applied_step_reason[] = {
    NULL,
    "applied_height_begin_failed",
    "applied_height_set_failed",
    "applied_height_commit_failed",
};


static bool boot_own_height_defer_or_resume(const char *path, struct uss_handle *h, struct uss_header *hdr,
                                            uint8_t *sha, struct main_state *ms, int32_t seed_h)
{
    if (ms) {
        int32_t hdr_tip = -1;
        if (boot_refold_snapshot_anchor_bind(h, ms, hdr, seed_h, &hdr_tip)) {
            LOG_WARN("boot",
                     "[boot] -load-snapshot-at-own-height: header tip h=%d "
                     "< snapshot height h=%d — headers not synced yet; "
                     "SKIPPING the snapshot seed and falling back to normal "
                     "P2P IBD (re-run once headers reach the snapshot "
                     "height).",
                     hdr_tip, seed_h);
            event_emitf(EV_RECOVERY_ACTION, 0,
                        "load_snapshot_at_own_height deferred "
                        "header_tip=%d seed_h=%d",
                        hdr_tip, seed_h);
            uss_close(h);
            return true;  /* normal boot continues; coins_kv left as-is for IBD */
        }
    } else {
        LOG_WARN("boot", "[boot] ZCL_TESTING fixture has no anchor binding");
    }

    int32_t applied = -1;
    bool marker_matches = false, install_pending = true;
    bool prior_frontier_verified = false;
    bool resume = boot_snapshot_install_resume_allowed(
        progress_store_db(), hdr, sha, &applied,
        &install_pending, &marker_matches, &prior_frontier_verified);
    if (install_pending)
        LOG_WARN("boot", "[boot] snapshot install pending/read-failed "
                 "(binding=%s): RESUME-FAST disabled; rerunning",
                 marker_matches ? "matches" : "unknown_or_mismatch");
    if (resume) {
        boot_snapshot_resume_finish(h, path, hdr, sha, ms,
                                    applied, seed_h, prior_frontier_verified);
        return true;
    }
    return false;
}

static bool boot_own_height_begin_install(const char *datadir, sqlite3 **rpdb, struct uss_header *hdr,
                                          uint8_t *sha, int32_t seed_h, bool *authority_retry_used)
{
    *rpdb = progress_store_db();
    if (!*rpdb) {
        if (boot_snapshot_authority_retry(authority_retry_used, datadir,
                                          rpdb, "progress_store_not_open"))
            return true;
        fprintf(stderr, "FATAL: -load-snapshot-at-own-height: progress store not "
                "open after verified snapshot; cannot seed\n");
        event_emitf(EV_BOOT_VALIDATION_FAILED, 0,
                    "load_snapshot_at_own_height progress_store_not_open");
        _exit(EXIT_FAILURE);
    }

    /* Interim crash convergence (not atomic): journal before mutation. */
    if (!boot_snapshot_install_marker_begin(*rpdb, hdr, sha)) {
        if (boot_snapshot_authority_retry(authority_retry_used, datadir,
                                          rpdb, "install_marker_begin_failed"))
            return true;
        fprintf(stderr, "FATAL: snapshot install marker failed before mutation\n");
        event_emitf(EV_BOOT_VALIDATION_FAILED, 0, "load_snapshot install_marker_begin_failed");
        _exit(EXIT_FAILURE);
    }
    /* Publish an incomplete-history boundary before destructive coin writes. */
    if (!boot_shielded_prepare_assisted_boundary(*rpdb, seed_h)) {
        fprintf(stderr, "FATAL: snapshot shielded boundary failed h=%d\n", seed_h);
        event_emitf(EV_BOOT_VALIDATION_FAILED, 0, "load_snapshot shielded_boundary_failed h=%d", seed_h);
        _exit(EXIT_FAILURE);
    }
    return false;
}

static bool boot_own_height_repair_and_publish(struct main_state *ms, const char *datadir,
                                               int32_t seed_h, bool trust_existing_block_files, sqlite3 **rpdb, bool *authority_retry_used)
{
    if (ms)
        boot_refold_snapshot_repair_bodiless_above_seed(
            ms, datadir, seed_h, trust_existing_block_files);

    /* Publish the durable applied frontier BEFORE the Sapling
     * rebuild runs, in its own committed transaction (the snapshot-load tx
     * above already COMMITted, and the Phase-2 stage-cursor tx below has not
     * begun yet — no tx is open here). sapling_tree_rebuild reads the durable
     * applied height to cap its endpoint; without this write it would still see
     * a stale/contaminated applied height and could rebuild past the seed. The
     * Phase-2 write at ~line 1014 sets the same value and is now idempotent. */
    {
        char *aherr = NULL;
        enum boot_applied_step step = boot_refold_snapshot_publish_applied_height(
            *rpdb, seed_h, *authority_retry_used, &aherr);
        if (step != BOOT_APPLIED_OK) {
            if (boot_snapshot_authority_retry(authority_retry_used, datadir,
                                              rpdb,
                                              k_applied_step_reason[step]))
                return true;
            boot_refold_snapshot_applied_height_die(step, seed_h, aherr);
        }
        if (aherr) sqlite3_free(aherr);
        LOG_INFO("boot", "[boot] -load-snapshot-at-own-height: pre-rebuild "
                 "applied-height=%d (seed_h+1) committed so the Sapling "
                 "rebuild endpoint caps to the seed", seed_h + 1);
    }
    return false;
}

static void boot_own_height_rebuild_sapling(struct node_db *ndb, struct main_state *ms, bool sapling_installed_from_frontier)
{
    if (ms && !sapling_installed_from_frontier) {
        boot_refold_snapshot_rebuild_sapling_tree(ndb, ms);
    } else if (!ms) {
        LOG_WARN("boot", "[boot] -load-snapshot-at-own-height: no main_state — "
                 "cleared sapling_tree to NULL; the catchup service rebuilds it "
                 "from genesis on next run");
    }
}

void boot_load_snapshot_at_own_height_reset(struct node_db *ndb,
                                            const char *path,
                                            const char *datadir,
                                            struct main_state *ms,
                                            bool trust_existing_block_files)
{
    boot_refold_snapshot_preflight(path, ms);

    uint8_t artifact_sha256[32] = {0};
    struct uss_header hdr;
    struct uss_handle *h = boot_refold_snapshot_open_verified(path, &hdr,
                                                       artifact_sha256);
    const int32_t seed_h = (int32_t)hdr.height;

    /* If this is a v2 snapshot it carries a Sapling commitment-tree frontier
     * after the UTXO records. Capture a HEAP COPY now (the mmap'd handle is
     * closed before the Sapling re-seed at the end of this function); the copy
     * is installed + root-verified there to SKIP the block-replay rebuild,
     * letting a fresh node seed WITHOUT a blocks/ directory. NULL on a v1 file
     * (the existing rebuild runs unchanged). */
    uint8_t *embedded_frontier = NULL;
    uint32_t embedded_frontier_len = 0;

    /* v3 ALSO carries the Sprout frontier + nullifier set (the Phase-2 seed
     * installs them to cure the empty-sapling_anchors birth defect). NULL/0 on
     * v1/v2 — the old cursor-reset path runs. See config/boot_shielded_seed.h. */
    bool     embedded_shielded_v3 = false;
    uint8_t *embedded_sprout = NULL, *embedded_nullifiers = NULL;
    uint32_t embedded_sprout_len = 0;
    uint64_t embedded_nullifier_count = 0;

    if (boot_own_height_defer_or_resume(path, h, &hdr, artifact_sha256, ms, seed_h)) return;

    uss_close(h);
    h = NULL;

    bool authority_retry_used = false;
    sqlite3 *rpdb = NULL;

retry_authority_store:
    if (boot_own_height_begin_install(datadir, &rpdb, &hdr, artifact_sha256, seed_h, &authority_retry_used))
        goto retry_authority_store;
#ifdef ZCL_TESTING
    if (boot_shielded_consume_boundary_interrupt_for_test()) return;
#endif

    /* Neutralize the cold-import seed provenance so the later stage init
     * (block_index_loader_seed_stages_from_cold_import) does not re-stamp the
     * trusted anchor forward to the checkpoint. */
    utxo_recovery_clear_cold_import_seed(ndb);
    (void)node_db_state_set(ndb, "leveldb_utxo_migrated", NULL, 0);

    /* Phase 1 (own transactions): FULL coins_kv reset, then RE-SEED from the
     * snapshot. Bulk-load under ONE transaction so a crash mid-load rolls back. */
    if (!coins_kv_reset_for_reseed(rpdb)) {
        if (boot_snapshot_authority_retry(&authority_retry_used, datadir,
                                          &rpdb, "coins_kv_reset_failed"))
            goto retry_authority_store;
        fprintf(stderr, "FATAL: -load-snapshot-at-own-height: "
                "coins_kv_reset_for_reseed failed\n");
        event_emitf(EV_BOOT_VALIDATION_FAILED, 0,
                    "load_snapshot_at_own_height coins_kv_reset_failed");
        _exit(EXIT_FAILURE);
    }

    char err2[256] = {0};
    struct uss_header hdr2;
    h = uss_open(path, /*verify_full_sha3=*/true,
                 /*expected_sha3=*/NULL, &hdr2, err2, sizeof(err2));
    boot_refold_snapshot_reopen_check(h, &hdr, &hdr2, artifact_sha256, err2, false);

    struct boot_snapshot_apply_result ar = {0};
    bool load_ok = boot_snapshot_apply_to_coins_kv(rpdb, h, hdr.count, &ar);
    if (!load_ok && !authority_retry_used) {
        uss_close(h);
        h = NULL;
        if (boot_snapshot_authority_retry(&authority_retry_used, datadir,
                                          &rpdb, "snapshot_apply_failed"))
            goto retry_authority_store;
        h = uss_open(path, /*verify_full_sha3=*/true,
                     /*expected_sha3=*/NULL, &hdr2, err2, sizeof(err2));
        boot_refold_snapshot_reopen_check(h, &hdr, &hdr2, artifact_sha256, err2, true);
    }

    /* Capture heap copies of the embedded shielded state (v2 = Sapling frontier;
     * v3 = Sapling+Sprout frontiers + nullifiers) — all inside the SHA3-verified
     * body, so integrity-bound. See config/boot_shielded_seed.h. */
    boot_capture_shielded(h, load_ok, &embedded_frontier,
                          &embedded_frontier_len, &embedded_shielded_v3,
                          &embedded_sprout, &embedded_sprout_len,
                          &embedded_nullifiers, &embedded_nullifier_count);

    uss_close(h);
    h = NULL;

    if (!load_ok) {
        if (boot_snapshot_authority_retry(&authority_retry_used, datadir,
                                          &rpdb, "snapshot_load_failed"))
            goto retry_authority_store;
        boot_refold_snapshot_load_failed_die(&ar, hdr.count);
    }
    fprintf(stderr,
            "[boot] -load-snapshot-at-own-height: digest-verified assisted snapshot %s "
            "(body SHA3 OK, height=%d, count=%llu) — seeded coins_kv\n",
            path, seed_h, (unsigned long long)hdr.count);

    if (boot_own_height_repair_and_publish(ms, datadir, seed_h, trust_existing_block_files,
                                           &rpdb, &authority_retry_used))
        goto retry_authority_store;

    (void)boot_index_clear_coins_state(ndb);

    /* SAPLING COMMITMENT-TREE RE-SEED at the seed height.
     *
     * Why this is needed: this loader keeps body_persist/validate_headers at the
     * on-disk header/body tip (so db_tip stays HIGH) while it re-seeds coins_kv
     * at seed_h. The Sapling note-commitment tree (node_state["sapling_tree"])
     * is consumed by the wallet witness machinery + the MMR controllers
     * (node_db_catchup_service.c, wallet_rescan_controller_witness.c,
     * blockchain_controller_mmr.c). The OLD behavior here BLINDLY cleared
     * node_state["sapling_tree"] to NULL — but the catchup service resumes its
     * tree from db_tip+1 deserializing exactly that blob, so a NULL blob at a
     * HIGH db_tip would silently rebuild the tree as if EMPTY below db_tip:
     * a wrong (truncated) commitment tree, breaking wallet note witnesses and
     * the MMR root. (NOTE: this re-seed does NOT unblock proof_validate —
     * proof_validate is stateless w.r.t. this tree; it reads each shielded
     * spend's OWN embedded anchor. See the blocker note returned by the task.)
     *
     * Correct re-seed: clear ALL stale resume markers together, then drive the
     * dedicated, consensus-validating rebuilder (sync_controller_sapling_tree.c
     * sapling_tree_rebuild) which replays note commitments from a SHA3-verified
     * flat-file checkpoint (<datadir>/sapling_tree_ckpt.dat) — or from Sapling
     * activation when no checkpoint is present — validating each per-height root
     * against hashFinalSaplingRoot, and re-persists node_state["sapling_tree"]
     * coherent with the chain tip. It is bounded by the flat-file checkpoint
     * (no unconditional 2.6M-block replay) and is a no-op below Sapling
     * activation. Requires the in-memory active chain (ms); when absent (unit
     * tests) we fall back to the old NULL-clear so the catchup path still owns
     * the rebuild. */
    (void)node_db_state_set(ndb, "sapling_tree", NULL, 0);
    (void)node_db_state_set(ndb, "sapling_tree_rescan_height", NULL, 0);
    (void)node_db_state_set(ndb, "sapling_tree_rebuild_height", NULL, 0);

    bool sapling_installed_from_frontier = boot_refold_snapshot_install_embedded_frontier(
        ndb, ms, seed_h, embedded_frontier, embedded_frontier_len);

    boot_own_height_rebuild_sapling(ndb, ms, sapling_installed_from_frontier);

    bool refold_ok = boot_snapshot_arm_cursors(
        rpdb, ms, seed_h, sapling_installed_from_frontier, embedded_shielded_v3,
        embedded_frontier, embedded_frontier_len, embedded_sprout,
        embedded_sprout_len, embedded_nullifiers, embedded_nullifier_count);
    if (!refold_ok) {
        if (boot_snapshot_authority_retry(&authority_retry_used, datadir,
                                          &rpdb, "stage_cursor_arm_failed"))
            goto retry_authority_store;
        boot_refold_snapshot_cursor_arm_die(seed_h);
    }

    boot_refold_snapshot_seal_install(rpdb, &hdr, artifact_sha256, seed_h,
                               sapling_installed_from_frontier);

    free(embedded_frontier);
    embedded_frontier = NULL;
    free(embedded_sprout);
    free(embedded_nullifiers);
    boot_snapshot_install_record_proof(path, &hdr, artifact_sha256,
                                       sapling_installed_from_frontier);
    fprintf(stderr,
            "[boot] -load-snapshot-at-own-height: coin set RE-SEEDED + "
            "digest-verified assisted state (count=%llu, body SHA3 OK) at h=%d; coins-dependent "
            "stages (script_validate/proof_validate/utxo_apply/tip_finalize) "
            "forced to h=%d, coins-independent stages "
            "(header_admit/validate_headers/body_fetch/body_persist) KEPT at the "
            "on-disk header/body tip; the staged pipeline re-folds the coins "
            "delta forward over ON-DISK bodies (H* climbs from h=%d, no P2P "
            "header re-sync needed)\n",
            (unsigned long long)hdr.count, seed_h, seed_h, seed_h);
}

/* -load-verify-boot eligibility probe (config/boot.h). Pure: decides whether a
 * NORMAL boot should route the verified legacy-artifact load+anchor-fold instead
 * of the cold-import seed. Reuses the exact loader + shared transparent-component
 * checkpoint predicate. See boot.h for the full contract.
 *
 * SAFETY (load-bearing): malformed/full-payload corruption fails uss_open;
 * transparent checkpoint mismatch fails legacy_uss_matches_checkpoint. Either
 * returns FALSE before mutation. A healthy coins authority also returns FALSE. */
bool boot_load_verify_snapshot_eligible(struct node_db *ndb,
                                        struct sqlite3 *progress_db)
{
    if (!ndb || !progress_db)
        return false;

    const struct sha3_utxo_checkpoint *cp = get_sha3_utxo_checkpoint();
    if (!cp)
        return false;  /* no compiled checkpoint to anchor against */

    /* (3) NEVER reset a healthy node: if coins_kv already provably holds the
     * live coin set, the load-verify route must not fire (it FULL-resets
     * coins_kv). Probe this BEFORE touching the file so a synced node short-
     * circuits cheaply. */
    if (coins_kv_is_proven_authority(progress_db, NULL))
        return false;

    char path[1100];
    if (!boot_anchor_snapshot_path_resolve(ndb, path, sizeof(path)))
        return false;

    /* (1)+(2) Present + verified: first bind every byte and the exact legacy
     * layout, then bind the independently recomputed transparent component.
     * Read-only mmap; no coins_kv mutation in this probe. */
    char err[256] = {0};
    struct uss_header hdr;
    struct uss_handle *h = uss_open(path, /*verify_full_sha3=*/true,
                                    /*expected_sha3=*/NULL,
                                    &hdr, err, sizeof(err));
    if (!h)
        return false;  /* absent or failed SHA3/header verify → safe fallback */

    bool checkpoint_ok =
        boot_legacy_uss_matches_checkpoint(h, &hdr, cp, err, sizeof(err));
    uss_close(h);
    if (!checkpoint_ok) {
        LOG_WARN("boot", "[boot] -load-verify-boot: legacy artifact %s does "
                 "not match checkpoint height/hash/root/count/supply (%s) — "
                 "running the proven boot path", path,
                 err[0] ? err : "component mismatch");
        return false;
    }

    LOG_INFO("boot", "[boot] -load-verify-boot: verified baked anchor snapshot "
             "present (%s, SHA3 == compiled checkpoint, count=%llu) and coins_kv "
             "does not satisfy operational authority predicate — routing the "
             "LOAD+VERIFY anchor seed + anchor->tip delta fold", path,
             (unsigned long long)cp->utxo_count);
    return true;
}

/* -mint-anchor (config/boot.h). The ANCHOR-SET MINT boot-time reset:
 *   (1) reset the staged reducer to GENESIS exactly like -refold-staged
 *       (boot_mint_anchor_genesis_reset truncates coins_kv, forces the cursors
 *       to 0, and clears reducer logs + node.db commitment keys) so the fold
 *       re-derives every coin from the on-disk BODIES, never the borrowed
 *       node.db `utxos` mirror;
 *   (2) cap the fold at the compiled SHA3 UTXO checkpoint anchor — header_admit
 *       refuses to admit above the ceiling, so the eight-stage pipeline
 *       converges AT the anchor instead of folding to the tip;
 *   (3) mark refold_in_progress (progress.kv) so the L0 frontier floor drops to
 *       0 and the below-anchor self-repair is suspended while the fold re-walks
 *       the frozen prefix (the from-genesis refold semantics).
 * The driver boot_mint_anchor_run() (engine/composition/src/boot_mint_anchor.c) then drives
 * the fold to the anchor and writes + hard-asserts the snapshot. */
void boot_mint_anchor_reset(struct node_db *ndb, bool fast)
{
    const struct sha3_utxo_checkpoint *cp = get_sha3_utxo_checkpoint();
    if (!cp) {
        fprintf(stderr, "FATAL: -mint-anchor: no compiled SHA3 UTXO checkpoint "
                "— nothing to mint toward\n");
        event_emitf(EV_BOOT_VALIDATION_FAILED, 0,
                    "mint_anchor no_compiled_checkpoint");
        _exit(EXIT_FAILURE);
    }

    int32_t resume_through = -1;
    bool legacy_adopted = false;
    boot_mint_anchor_require_producer_lane(progress_store_db(), fast);
    bool resume = mint_anchor_progress_can_resume(progress_store_db(), cp,
                                                  &resume_through,
                                                  &legacy_adopted);
    if (resume) {
        fprintf(stderr,
                "[boot] -mint-anchor: resuming existing checkpoint-bound fold "
                "at applied-through=%d (anchor h=%d%s); NOT resetting to "
                "genesis\n",
                resume_through, cp->height,
                legacy_adopted ? ", legacy marker adopted" : "");
    } else {
        /* (1) genesis reset — identical machinery to -refold-staged. */
        if (!boot_mint_anchor_genesis_reset(ndb)) {
            fprintf(stderr,
                    "FATAL: -mint-anchor: genesis reset did not complete; "
                    "refusing to mark or drive a partial producer state\n");
            event_emitf(EV_BOOT_VALIDATION_FAILED, 0,
                        "mint_anchor genesis_reset_failed");
            _exit(EXIT_FAILURE);
        }
        if (!mint_anchor_progress_mark(progress_store_db(), cp)) {
            fprintf(stderr,
                    "FATAL: -mint-anchor: could not persist the checkpoint-"
                    "bound resume marker — refusing to start a non-resumable "
                    "anchor mint\n");
            event_emitf(EV_BOOT_VALIDATION_FAILED, 0,
                        "mint_anchor resume_marker_persist_failed");
            _exit(EXIT_FAILURE);
        }
    }

    /* (2) cap the fold AT the anchor (inclusive). header_admit stops here. */
    mint_fold_ceiling_set(cp->height);

    /* (2b) OFFLINE FAST-MINT (-mint-anchor-fast): flip the process-global
     * crypto pass-through so script_validate/proof_validate skip their per-block
     * ECDSA/Groth16 verification while folding genesis..anchor. The state
     * transition (utxo_apply) is untouched, so the minted coins_kv set is
     * IDENTICAL to the full-validated fold; boot_mint_anchor_run still
     * HARD-ASSERTS SHA3==checkpoint + count before retaining the legacy output,
     * so a wrong set is removed. `fast` is true ONLY when the caller gated on
     * ctx->mint_anchor (engine/composition/src/boot.c) — this TU is the lone caller of
     * mint_skip_crypto_set, so a normal boot can never arm the pass-through. */
    if (fast) {
        mint_skip_crypto_set(true);
        fprintf(stderr,
                "[boot] -mint-anchor-fast: OFFLINE FAST-MINT — script_validate/"
                "proof_validate crypto PASS-THROUGH for the genesis..%d fold; the "
                "state fold is unchanged and the SHA3==checkpoint hard-assert "
                "still certifies the minted set (FATAL on mismatch)\n",
                cp->height);
    }

    /* (3) suspend the below-anchor self-repair while the frozen prefix re-folds
     * (the from-genesis refold L0 floor = 0). */
    (void)refold_progress_mark_started(progress_store_db());

    if (!resume) {
        fprintf(stderr,
                "[boot] -mint-anchor: reset to genesis; fold CAPPED at the SHA3 "
                "checkpoint anchor h=%d (want count=%llu); the staged pipeline folds "
                "genesis..anchor over on-disk bodies, then the mint writes + asserts "
                "the snapshot\n",
                cp->height, (unsigned long long)cp->utxo_count);
    } else {
        fprintf(stderr,
                "[boot] -mint-anchor: resumed fold remains CAPPED at the SHA3 "
                "checkpoint anchor h=%d (want count=%llu); the mint writes + asserts "
                "the snapshot only after the frontier reaches the anchor\n",
                cp->height, (unsigned long long)cp->utxo_count);
    }
}
