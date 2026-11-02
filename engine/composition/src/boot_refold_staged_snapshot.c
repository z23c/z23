/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * The -load-snapshot-at-own-height loader's named steps (open and verify,
 * anchor bind, applied-height publication, Sapling frontier install, seal) and
 * the resume-repair steps, split out of boot_refold_staged.c unchanged to keep
 * that file under its size ceiling. Private contract in
 * boot_refold_staged_snapshot.h; only boot_refold_staged.c calls these. */
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


/* Resolve the block the resume repair seeds at: the active chain slot, else
 * the ancestor on the best header chain. May return NULL or a block at the
 * wrong height; the caller checks. */
struct block_index *boot_refold_snapshot_resume_resolve_anchor(struct main_state *ms,
                                                      int32_t authority_h)
{
    struct block_index *anchor =
        active_chain_at(&ms->chain_active, authority_h);
    if ((!anchor || anchor->nHeight != authority_h) &&
        ms->pindex_best_header &&
        ms->pindex_best_header->nHeight >= authority_h) {
        anchor = block_index_get_ancestor(ms->pindex_best_header,
                                          authority_h);
    }
    return anchor;
}

/* Stamp every stage cursor to the authority height in ONE progress.kv
 * transaction under the progress-store tx lock; true when committed. */
bool boot_refold_snapshot_resume_stamp_cursors(sqlite3 *rpdb, int32_t authority_h)
{
    char *cerr = NULL;
    bool cursor_ok = true;
    progress_store_tx_lock();
    if (sqlite3_exec(rpdb, "BEGIN IMMEDIATE", NULL, NULL, &cerr)
        != SQLITE_OK) {
        LOG_WARN_IN("boot_load_snapshot_resume_seed_from_authority", "boot",
                 "[boot] -load-snapshot-at-own-height: resume repair cursor "
                 "BEGIN failed h=%d: %s",
                 authority_h, cerr ? cerr : "(no msg)");
        cursor_ok = false;
    }
    if (cursor_ok) {
        static const char *const k_upstream_stages[] = {
            "header_admit", "validate_headers", "body_fetch", "body_persist",
            "script_validate", "proof_validate", "utxo_apply",
        };
        int next_h = authority_h + 1;
        for (size_t i = 0;
             cursor_ok &&
             i < sizeof(k_upstream_stages) / sizeof(k_upstream_stages[0]);
             i++) {
            if (!stage_repair_force_stage_cursor(rpdb, k_upstream_stages[i],
                                                 next_h)) {
                LOG_WARN_IN("boot_load_snapshot_resume_seed_from_authority", "boot",
                         "[boot] -load-snapshot-at-own-height: resume repair "
                         "cursor stamp failed stage=%s h=%d",
                         k_upstream_stages[i], next_h);
                cursor_ok = false;
            }
        }
    }
    if (cursor_ok &&
        !stage_repair_force_stage_cursor(rpdb, "tip_finalize",
                                         authority_h)) {
        LOG_WARN_IN("boot_load_snapshot_resume_seed_from_authority", "boot",
                 "[boot] -load-snapshot-at-own-height: resume repair cursor "
                 "stamp failed stage=tip_finalize h=%d", authority_h);
        cursor_ok = false;
    }
    if (cursor_ok &&
        sqlite3_exec(rpdb, "COMMIT", NULL, NULL, &cerr) != SQLITE_OK) {
        LOG_WARN_IN("boot_load_snapshot_resume_seed_from_authority", "boot",
                 "[boot] -load-snapshot-at-own-height: resume repair cursor "
                 "COMMIT failed h=%d: %s",
                 authority_h, cerr ? cerr : "(no msg)");
        cursor_ok = false;
    }
    if (!cursor_ok)
        sqlite3_exec(rpdb, "ROLLBACK", NULL, NULL, NULL);
    if (cerr)
        sqlite3_free(cerr);
    progress_store_tx_unlock();
    return cursor_ok;
}

/* One WARN line for a resume repair that did not bring H* up to the
 * authority height. */
void boot_refold_snapshot_resume_warn_incomplete(bool after_ok, int32_t after,
                                        int32_t authority_h, int32_t hstar,
                                        int32_t seed_h)
{
    LOG_WARN_IN("boot_load_snapshot_resume_seed_from_authority", "boot",
                 "[boot] -load-snapshot-at-own-height: resume repair incomplete "
                 "H*=%d want=%d before=%d seed_h=%d",
                 after_ok ? after : -1, authority_h, hstar, seed_h);
}


/* Refuse an empty path, a missing chain context and a shieldless seed before
 * any file or database is touched. */
void boot_refold_snapshot_preflight(const char *path, struct main_state *ms)
{
    if (!path || !path[0]) {
        fprintf(stderr, "FATAL: -load-snapshot-at-own-height: empty path\n");
        event_emitf(EV_BOOT_VALIDATION_FAILED, 0,
                    "load_snapshot_at_own_height empty_path");
        _exit(EXIT_FAILURE);
    }
    boot_snapshot_install_require_chain_context(ms);

    /* D1: refuse a shieldless v1 seed past Sapling activation up front; it
     * otherwise wedges on shielded backfill. v2/v3 seeds pass. */
    boot_seed_refuse_shieldless_or_die(path);
}

/* Open the snapshot and verify it. Fatal on any failure; returns the open
 * handle. */
struct uss_handle *boot_refold_snapshot_open_verified(
    const char *path, struct uss_header *hdr_out, uint8_t artifact_sha256[32])
{
    /* (i) Open + verify the snapshot body digest against its header (NOT the
     * compiled checkpoint). expected_sha3=NULL skips the checkpoint binding;
     * verify_full_sha3=true still recomputes the whole body and compares it to
     * hdr.sha3_hash, so a corrupt/forged body is rejected before any coin lands. */
    char err[256] = {0};
    struct uss_header hdr;
    struct uss_handle *h = uss_open(path, /*verify_full_sha3=*/true,
                                    /*expected_sha3=*/NULL, &hdr, err, sizeof(err));
    if (!h) {
        fprintf(stderr, "FATAL: -load-snapshot-at-own-height: uss_open(%s) failed "
                "(body SHA3 verify): %s — REFUSING to seed\n", path, err);
        event_emitf(EV_BOOT_VALIDATION_FAILED, 0,
                    "load_snapshot_at_own_height uss_open_failed path=%s err=%s",
                    path, err);
        _exit(EXIT_FAILURE);
    }
    if (!uss_artifact_sha256(h, artifact_sha256)) {
        uss_close(h);
        fprintf(stderr, "FATAL: snapshot exact artifact hash failed\n");
        _exit(EXIT_FAILURE);
    }
    if (hdr.height > (uint32_t)INT32_MAX) {
        uss_close(h);
        fprintf(stderr, "FATAL: snapshot height exceeds signed chain range\n");
        event_emitf(EV_BOOT_VALIDATION_FAILED, 0,
                    "load_snapshot snapshot_height_out_of_range");
        _exit(EXIT_FAILURE);
    }
    *hdr_out = hdr;
    return h;
}

/* Bind the snapshot to this node's validated header at seed_h. Returns true
 * when the seed must be DEFERRED (headers not synced to seed_h; *hdr_tip_out
 * is set); every other failure is fatal and does not return. */
bool boot_refold_snapshot_anchor_bind(struct uss_handle *h,
                                      struct main_state *ms,
                                      const struct uss_header *hdr,
                                      int32_t seed_h, int32_t *hdr_tip_out)
{
    /* Require the snapshot to name this node's validated header at its height.
     * Body SHA3 proves file integrity, not state derivation or contents.
     * Require the snapshot's hdr.anchor_block_hash to byte-equal the in-memory
     * active-chain block hash at seed_h (both internal little-endian; the
     * snapshot writer fed cp->block_hash, same representation as
     * block_index.hashBlock). The prior block-index load (`--importblockindex`
     * is a documented prerequisite) populates ms->chain_active up to the tip, so
     * the slot at seed_h is present on the supported recovery path. FATAL on a
     * mismatch — never stamp a coin against a forged anchor. */
    const struct block_index *bi = active_chain_at(&ms->chain_active, seed_h);
    if (!bi && ms->pindex_best_header &&
        ms->pindex_best_header->nHeight >= seed_h) {
        /* seed_h is above the coins-best active-chain WINDOW but within
         * this node's PoW-proven header chain. The block_index map + the
         * on-disk bodies span to the header tip (pindex_best_header); only
         * the VISIBLE active window was pinned to coins-best by the boot
         * restore (utxo_recovery_restore_chain_tip -> csr_commit_tip).
         * Widen the window forward to the header tip with the SAME
         * primitive the reducer uses for its lookahead: it fills chain[]
         * by walking pprev and NEVER publishes finalized authority, so the
         * consensus anchor-hash cross-check below reads the real
         * PoW-proven block_index at seed_h. A pprev gap leaves the slot
         * NULL and the FATAL below still fires (never bind against a
         * missing/forged anchor). The loader's header docstring assumed
         * `--importblockindex` supplies this slot; it does NOT (header
         * import sets only pindex_best_header, never c->chain[]), so the
         * window is extended here. */
        active_chain_extend_window(&ms->chain_active, ms->pindex_best_header);
        bi = active_chain_at(&ms->chain_active, seed_h);
    }
    if (!bi) {
        int32_t hdr_tip =
            ms->pindex_best_header ? ms->pindex_best_header->nHeight : -1;
        /* Distinguish two NULL-slot causes:
         *
         *  (a) Headers simply not synced to seed_h yet (hdr_tip < seed_h) —
         *      e.g. a FRESH datadir. We cannot check its chain location NOW;
         *      that never authenticates contents. Degrade to a WARN
         *      and RETURN cleanly so the node falls back to normal P2P IBD
         *      and downloads headers/blocks the usual way. (Auto-seeding the
         *      snapshot once headers later reach seed_h is a follow-up — the
         *      seed is simply skipped this run.)
         *
         *  (b) Headers ARE at/above seed_h but the slot is still NULL after
         *      active_chain_extend_window (a real pprev/data gap below the
         *      header tip) — genuine corruption. KEEP the fail-closed FATAL:
         *      never stamp a coin against a missing/forged anchor. */
        *hdr_tip_out = hdr_tip;
        if (hdr_tip < seed_h)
            return true;
        fprintf(stderr,
                "FATAL: -load-snapshot-at-own-height: the in-memory active "
                "chain has NO block at the snapshot height h=%d — cannot "
                "check its declared chain location (header tip h=%d). This "
                "does not authenticate state contents. REFUSING to seed.\n",
                seed_h, hdr_tip);
        event_emitf(EV_BOOT_VALIDATION_FAILED, 0,
                    "load_snapshot_at_own_height no_index_block seed_h=%d",
                    seed_h);
        uss_close(h);
        _exit(EXIT_FAILURE);
    }
    if (!boot_snapshot_anchor_hash_matches(bi->hashBlock.data,
                                           hdr->anchor_block_hash)) {
        fprintf(stderr,
                "FATAL: -load-snapshot-at-own-height: snapshot anchor hash "
                "DOES NOT MATCH this node's PoW-proven header at h=%d — the "
                "snapshot is for a DIFFERENT (or forged) chain. REFUSING to "
                "seed coins_kv.\n",
                seed_h);
        event_emitf(EV_BOOT_VALIDATION_FAILED, 0,
                    "load_snapshot_at_own_height anchor_hash_mismatch "
                    "seed_h=%d", seed_h);
        uss_close(h);
        _exit(EXIT_FAILURE);
    }
    fprintf(stderr,
            "[boot] -load-snapshot-at-own-height: anchor hash MATCHES the "
            "validated local header at h=%d — chain location verified; "
            "snapshot state contents remain assisted/unproven\n", seed_h);
    return false;
}

/* After reopening the snapshot (after the coins reset, or after the authority
 * store was rebuilt) refuse unless it is byte-for-byte the artifact that was
 * verified. Fatal on a change. */
void boot_refold_snapshot_reopen_check(
    struct uss_handle *h, const struct uss_header *hdr,
    const struct uss_header *hdr2, const uint8_t artifact_sha256[32],
    const char *err2, bool after_apply_retry)
{
    uint8_t applied_artifact_sha256[32] = {0};
    if (!h || !uss_artifact_sha256(h, applied_artifact_sha256) ||
        memcmp(applied_artifact_sha256, artifact_sha256, 32) != 0 ||
        !boot_snapshot_install_headers_equal(hdr, hdr2)) {
        fprintf(stderr,
                "FATAL: -load-snapshot-at-own-height: snapshot changed %s "
                "(%s) — refusing to seed\n",
                after_apply_retry ? "while recovering authority store"
                                  : "after verification",
                h ? "header mismatch" : err2);
        event_emitf(EV_BOOT_VALIDATION_FAILED, 0,
                    "load_snapshot_at_own_height snapshot_changed_%s",
                    after_apply_retry ? "after_apply_retry" : "after_verify");
        if (h)
            uss_close(h);
        _exit(EXIT_FAILURE);
    }
}

/* Fatal: the snapshot records did not load as the header promised. */
void boot_refold_snapshot_load_failed_die(
    const struct boot_snapshot_apply_result *ar, uint64_t want)
{
    fprintf(stderr, "FATAL: -load-snapshot-at-own-height: load FAILED "
            "(inserted=%llu emitted=%lld want count=%llu) "
            "— REFUSING to seed\n",
            (unsigned long long)ar->inserted, (long long)ar->emitted,
            (unsigned long long)want);
    event_emitf(EV_BOOT_VALIDATION_FAILED, 0,
                "load_snapshot_at_own_height load_mismatch inserted=%llu "
                "want=%llu", (unsigned long long)ar->inserted,
                (unsigned long long)want);
    _exit(EXIT_FAILURE);
}

/* Drop the borrowed have-data above the seed and retract the active tip. */
void boot_refold_snapshot_repair_bodiless_above_seed(
    struct main_state *ms, const char *datadir, int32_t seed_h,
    bool trust_existing_block_files)
{
    /* Blocks-less bundle repair: the shipped block_index.bin claims HAVE_DATA at
     * the SOURCE's blk file coordinates for blocks above the seed, but a
     * blocks-less judge bundle has no bodies there. Drop the borrowed have-data
     * for any above-seed block whose blk file is absent so P2P re-fetches +
     * re-indexes the body cleanly (else the window never extends past seed_h+1
     * and tip_finalize wedges on lookahead_tip_missing). No-op when the bodies
     * are really present (live / legacy-import datadirs). */
    size_t bodiless = boot_snapshot_drop_bodiless_have_data_above_seed(
        ms, datadir, seed_h, trust_existing_block_files);
    /* On a blocks-less bundle, retract the active-chain tip to the seed. The
     * boot's earlier CSR restore promoted the active tip to the top of the
     * now-cleared borrowed span (e.g. 3,159,325), and the P2P download window
     * follows active_chain_height(); without this the node floods the TOP of
     * the gap and never fetches the connectable bottom (seed_h+1) the staged
     * fold needs next. active_chain_move_window_tip re-pins chain[] to the
     * seed block (walking pprev); it publishes NO finalized authority — the
     * staged pipeline re-publishes the served tip as it folds forward. */
    if (bodiless > 0) {
        struct block_index *seed_bi =
            active_chain_at(&ms->chain_active, seed_h);
        if (seed_bi &&
            active_chain_move_window_tip(&ms->chain_active, seed_bi)) {
            fprintf(stderr,
                    "[boot] -load-snapshot-at-own-height: blocks-less bundle "
                    "— retracted active-chain tip to seed h=%d so P2P fills "
                    "the gap bottom-up\n", seed_h);
        } else {
            LOG_WARN_IN("boot_load_snapshot_at_own_height_reset", "boot",
                     "[boot] -load-snapshot-at-own-height: blocks-less "
                     "active-tip retract to seed h=%d failed (seed slot %s) "
                     "— download may still target the gap top",
                     seed_h, seed_bi ? "present" : "NULL");
        }
    }
}

/* Publish the durable applied frontier (seed_h + 1) in its own committed
 * transaction. On a BEGIN or COMMIT error *aherr holds the sqlite message,
 * unless the authority retry is still unused (then it is already freed). */
enum boot_applied_step boot_refold_snapshot_publish_applied_height(
    sqlite3 *rpdb, int32_t seed_h, bool retry_used, char **aherr)
{
    if (sqlite3_exec(rpdb, "BEGIN IMMEDIATE", NULL, NULL, aherr)
        != SQLITE_OK) {
        if (!retry_used) {
            sqlite3_free(*aherr);
            *aherr = NULL;
        }
        return BOOT_APPLIED_BEGIN_FAILED;
    }
    if (!utxo_apply_frontier_set_in_tx(rpdb, seed_h + 1)) {
        sqlite3_exec(rpdb, "ROLLBACK", NULL, NULL, NULL);
        return BOOT_APPLIED_SET_FAILED;
    }
    if (sqlite3_exec(rpdb, "COMMIT", NULL, NULL, aherr) != SQLITE_OK) {
        sqlite3_exec(rpdb, "ROLLBACK", NULL, NULL, NULL);
        if (!retry_used) {
            sqlite3_free(*aherr);
            *aherr = NULL;
        }
        return BOOT_APPLIED_COMMIT_FAILED;
    }
    return BOOT_APPLIED_OK;
}

/* Fatal: the applied-height publication failed and no retry is left. */
void boot_refold_snapshot_applied_height_die(enum boot_applied_step step,
                                             int32_t seed_h, char *aherr)
{
    if (step == BOOT_APPLIED_SET_FAILED) {
        fprintf(stderr, "FATAL: -load-snapshot-at-own-height: failed to set "
                "pre-rebuild applied-height=%d — refusing to run the Sapling "
                "rebuild with an uncapped endpoint\n", seed_h + 1);
        event_emitf(EV_BOOT_VALIDATION_FAILED, 0,
                    "load_snapshot_at_own_height applied_height_set_failed "
                    "h=%d", seed_h + 1);
        _exit(EXIT_FAILURE);
    }
    bool begin = step == BOOT_APPLIED_BEGIN_FAILED;
    fprintf(stderr, "FATAL: -load-snapshot-at-own-height: pre-rebuild "
            "applied-height %s failed: %s\n", begin ? "BEGIN" : "COMMIT",
            aherr ? aherr : "(no msg)");
    if (aherr) sqlite3_free(aherr);
    event_emitf(EV_BOOT_VALIDATION_FAILED, 0,
                "load_snapshot_at_own_height applied_height_%s_failed",
                begin ? "begin" : "commit");
    _exit(EXIT_FAILURE);
}

/* Install the embedded Sapling frontier when it verifies; returns true when
 * it was installed. */
bool boot_refold_snapshot_install_embedded_frontier(
    struct node_db *ndb, struct main_state *ms, int32_t seed_h,
    uint8_t *embedded_frontier, uint32_t embedded_frontier_len)
{
    /* FAST PATH (v2 snapshot, no blocks/ needed): if the snapshot carried a
     * Sapling frontier, deserialize it, COMPUTE its root, and VERIFY it equals
     * the PoW-proven hashFinalSaplingRoot at seed_h (the SAME endpoint check the
     * block-replay rebuild does at its final height). On a match, persist the
     * frontier + rebuild_height = seed_h and SKIP sapling_tree_rebuild — so a
     * fresh node with NO blocks/ directory installs a verified Sapling tree.
     * On ANY mismatch / parse failure / missing seed-slot root, fall through to
     * the existing rebuild (never regress v1 / blocks-present behavior). */
    bool sapling_installed_from_frontier = false;
    if (ms && embedded_frontier && embedded_frontier_len > 0) {
        const struct block_index *seed_bi =
            active_chain_at(&ms->chain_active, seed_h);
        static const uint8_t zeros32[32] = {0};
        bool seed_root_known = seed_bi &&
            memcmp(seed_bi->hashFinalSaplingRoot.data, zeros32, 32) != 0;

        struct incremental_merkle_tree ftree;
        sapling_tree_init(&ftree);
        struct byte_stream fs;
        stream_init_from_data(&fs, embedded_frontier, embedded_frontier_len);
        bool parsed = incremental_tree_deserialize(&ftree, &fs);

        if (parsed && seed_root_known) {
            struct uint256 froot;
            incremental_tree_root(&ftree, &froot);
            if (memcmp(froot.data, seed_bi->hashFinalSaplingRoot.data, 32) == 0) {
                struct byte_stream ts;
                stream_init(&ts, 4096);
                bool serialized = incremental_tree_serialize(&ftree, &ts);
                if (serialized &&
                    sapling_tree_persist_pair(ndb, ts.data, ts.size,
                                              (int64_t)seed_h)) {
                    sapling_installed_from_frontier = true;
                    fprintf(stderr,
                            "[boot] -load-snapshot-at-own-height: installed the "
                            "EMBEDDED Sapling frontier at h=%d (root verified vs "
                            "hashFinalSaplingRoot) — SKIPPED the block-replay "
                            "rebuild (no blocks/ required)\n", seed_h);
                } else {
                    LOG_WARN_IN("boot_load_snapshot_at_own_height_reset", "boot", "[boot] -load-snapshot-at-own-height: "
                             "failed to persist the embedded frontier — falling "
                             "back to the block-replay rebuild");
                }
                stream_free(&ts);
            } else {
                LOG_WARN_IN("boot_load_snapshot_at_own_height_reset", "boot", "[boot] -load-snapshot-at-own-height: embedded "
                         "frontier root MISMATCH vs hashFinalSaplingRoot at "
                         "h=%d — falling back to the block-replay rebuild",
                         seed_h);
            }
        } else {
            LOG_WARN_IN("boot_load_snapshot_at_own_height_reset", "boot", "[boot] -load-snapshot-at-own-height: embedded "
                     "frontier %s (parsed=%d seed_root_known=%d) — falling back "
                     "to the block-replay rebuild",
                     parsed ? "unverifiable" : "unparseable",
                     parsed, seed_root_known);
        }
        /* Clear the half-set blob if we did NOT fully install, so the rebuild
         * below starts from a clean node_state. */
        if (!sapling_installed_from_frontier) {
            (void)node_db_state_set(ndb, "sapling_tree", NULL, 0);
            (void)node_db_state_set(ndb, "sapling_tree_rebuild_height", NULL, 0);
        }
    }
    return sapling_installed_from_frontier;
}

/* Drive the dedicated, consensus-validating rebuilder
 * (sync_controller_sapling_tree.c sapling_tree_rebuild). Fatal on failure. */
void boot_refold_snapshot_rebuild_sapling_tree(struct node_db *ndb,
                                               struct main_state *ms)
{
    char datadir[1024] = {0};
    GetDataDir(true, datadir, sizeof(datadir));
    int appended = sapling_tree_rebuild(ndb, &ms->chain_active, datadir);
    if (appended < 0) {
        fprintf(stderr,
                "FATAL: -load-snapshot-at-own-height: "
                "sapling_tree_rebuild failed (returned %d) — refusing "
                "to claim coherent wallet/MMR state\n", appended);
        event_emitf(EV_BOOT_VALIDATION_FAILED, 0,
                    "load_snapshot_at_own_height sapling_tree_rebuild_failed "
                    "rc=%d", appended);
        _exit(EXIT_FAILURE);
    } else {
        fprintf(stderr,
                "[boot] -load-snapshot-at-own-height: Sapling commitment "
                "tree REBUILT + re-persisted (%d commitments) coherent with "
                "the chain tip\n", appended);
    }
}

/* Fatal: the 8 stage cursors could not be forced to the seed height. */
void boot_refold_snapshot_cursor_arm_die(int32_t seed_h)
{
    fprintf(stderr,
            "FATAL: -load-snapshot-at-own-height: failed to force the 8 stage "
            "cursors to h=%d — refusing to start a half-armed fold\n", seed_h);
    event_emitf(EV_BOOT_VALIDATION_FAILED, 0,
                "load_snapshot_at_own_height seed_h=%d cursor arm failed",
                seed_h);
    _exit(EXIT_FAILURE);
}

/* Seed the tip anchor and clear the install journal. Fatal if either fails. */
void boot_refold_snapshot_seal_install(sqlite3 *rpdb,
                                       const struct uss_header *hdr,
                                       const uint8_t artifact_sha256[32],
                                       int32_t seed_h, bool frontier_installed)
{
    /* Seed every durable reducer anchor; retain the journal until success. */
    if (!tip_finalize_stage_seed_anchor(seed_h, hdr->anchor_block_hash, true)) {
        fprintf(stderr, "FATAL: snapshot tip anchor failed h=%d; journal retained\n", seed_h);
        event_emitf(EV_BOOT_VALIDATION_FAILED, 0, "load_snapshot tip_finalize_seed_failed h=%d", seed_h);
        _exit(EXIT_FAILURE);
    }
    if (!boot_snapshot_install_marker_complete(
            rpdb, artifact_sha256, frontier_installed)) {
        fprintf(stderr, "FATAL: snapshot journal clear failed after tip seed h=%d\n", seed_h);
        event_emitf(EV_BOOT_VALIDATION_FAILED, 0, "load_snapshot install_marker_final_clear_failed h=%d", seed_h);
        _exit(EXIT_FAILURE);
    }
}
