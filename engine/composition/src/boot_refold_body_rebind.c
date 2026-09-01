/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0.
 *
 * Purpose: the fold-span LOCAL body rebind and the boot torn-import AUTO-ARM.
 * Holds the once-per-process rebind state (datadir, scanned latch, attempt
 * counter), the body-span contiguity gate that drives it, and
 * boot_refold_from_anchor_arm_if_torn.
 *
 * Split out of boot_refold_staged.c along the file-size ceiling seam (E1) at
 * the section boundary that file already declared. That file keeps the
 * -refold-staged / -load-snapshot / -mint-anchor resets themselves. Contracts
 * are declared in config/boot.h; nothing crosses this seam beyond those
 * already-public functions, so this TU needs no private header.
 */
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

/* ── Fold-span LOCAL body rebind (header-only-import self-heal) ───────────────
 * A header-only rebuild (e.g. `--importblockindex`, or a header-seed load)
 * populates the block index with correct hashes/heights but NO BLOCK_HAVE_DATA:
 * a header import cannot carry the body positions (nFile/nDataPos), which point
 * into the SOURCE node's block files. When the from-anchor fold then checks the
 * span it sees a body gap — even though the bodies are on THIS node's local disk
 * (a snapshot/refold datadir keeps the ingested bodies in blk*.dat). Before
 * naming the gap blocker (which defers to a slow peer/reducer body-fetch), try a
 * LOCAL rebind: scan_block_files_mark_data parses the ACTUAL blk*.dat bytes,
 * marks HAVE_DATA + nDataPos, and links pprev from the parsed body header — it
 * never trusts a stored position row. Idempotent and once-per-process (the
 * O(disk) scan is not repeated). The datadir is set once by boot
 * (boot_refold_body_rebind_set_datadir) so the pure contiguity predicate keeps
 * its signature and every caller benefits without threading. */
static char g_refold_rebind_datadir[PATH_MAX];
static bool g_refold_rebind_datadir_set = false;
static bool g_refold_rebind_scanned = false;
static int  g_refold_rebind_scan_attempts = 0; /* boot-thread single writer */

void boot_refold_body_rebind_set_datadir(const char *datadir)
{
    if (datadir && datadir[0]) {
        snprintf(g_refold_rebind_datadir, sizeof(g_refold_rebind_datadir),
                 "%s", datadir);
        g_refold_rebind_datadir_set = true;
    } else {
        g_refold_rebind_datadir[0] = '\0';
        g_refold_rebind_datadir_set = false;
    }
}

/* True iff at least one non-empty blk*.dat exists under datadir/blocks (a cheap
 * stat probe over the first few files — the scan itself walks the rest). */
static bool refold_have_local_block_files(const char *datadir)
{
    for (int ci = 0; ci < 3; ci++) {
        char p[576];
        int n = snprintf(p, sizeof(p), "%s/blocks/blk%05d.dat", datadir, ci);
        if (n < 0 || (size_t)n >= sizeof(p))
            continue;
        struct stat st;
        if (stat(p, &st) == 0 && st.st_size > 0)
            return true;
    }
    return false;
}

/* First height in (anchor, target] whose active-chain slot is absent or lacks
 * BLOCK_HAVE_DATA; -1 iff the whole span is body-contiguous. */
static int32_t refold_span_first_missing(struct main_state *ms,
                                         int32_t anchor_height,
                                         int32_t resume_target)
{
    for (int32_t h = anchor_height + 1; h <= resume_target; h++) {
        const struct block_index *bi = active_chain_at(&ms->chain_active, h);
        if (!bi || !(bi->nStatus & BLOCK_HAVE_DATA))
            return h;
    }
    return -1;
}

/* CUTOVER DEFECT 2 — body-span contiguity gate. See config/boot.h for the
 * contract. PURE except for (a) the once-per-process LOCAL body rebind on a gap
 * (mark HAVE_DATA from local blk*.dat) and (b) the optional named-blocker raise
 * on a gap the rebind cannot close. It scans the active-chain block_index over
 * (anchor_height, resume_target] and verifies each slot has BLOCK_HAVE_DATA. The
 * from-anchor fold replays on-disk BODIES across this span; a missing/pruned
 * body would pin utxo_apply at that height (the prevout_unresolved wedge
 * relocated). Gate BEFORE arming so the failure is a NAMED blocker the
 * operator/peer-fetch path can act on, never a silent stall. */
bool boot_refold_body_span_contiguous(struct main_state *ms,
                                      int32_t anchor_height,
                                      int32_t resume_target,
                                      int32_t *out_first_missing,
                                      bool raise_blocker)
{
    if (out_first_missing)
        *out_first_missing = -1;
    if (!ms)
        return false;   /* cannot prove contiguity without the chain */
    if (resume_target <= anchor_height)
        return true;    /* empty span — nothing to fold, trivially contiguous */

    int32_t first_missing =
        refold_span_first_missing(ms, anchor_height, resume_target);

    /* LOCAL rebind: on a real gap, mark HAVE_DATA from local block files ONCE,
     * then re-check. Fires ONLY on a gap — a contiguous span never scans, so a
     * healthy boot pays nothing. The scan parses the actual body bytes and links
     * pprev from the header; it never trusts a stored position row. */
    if (first_missing >= 0 && g_refold_rebind_datadir_set &&
        !g_refold_rebind_scanned &&
        refold_have_local_block_files(g_refold_rebind_datadir)) {
        g_refold_rebind_scanned = true;
        g_refold_rebind_scan_attempts++;
        LOG_INFO("boot",
                 "[boot] fold-span body gap at h=%d in (%d..%d] — rebinding "
                 "HAVE_DATA from local block files (blk*.dat) before naming a "
                 "gap", first_missing, anchor_height, resume_target);
        (void)scan_block_files_mark_data(ms, g_refold_rebind_datadir,
                                         chain_params_get());
        first_missing =
            refold_span_first_missing(ms, anchor_height, resume_target);
        if (first_missing < 0)
            LOG_INFO("boot",
                     "[boot] fold-span body gap CLOSED by the local block-file "
                     "rebind — the from-anchor fold can arm from disk bodies");
    }

    if (first_missing < 0) {
        /* Whole span contiguous: clear any stale gap blocker so a re-armed fold
         * over a now-filled span starts clean. */
        if (raise_blocker)
            blocker_clear("refold.body_gap");
        return true;
    }

    if (out_first_missing)
        *out_first_missing = first_missing;
    if (raise_blocker) {
        const struct block_index *bi =
            active_chain_at(&ms->chain_active, first_missing);
        char reason[BLOCKER_REASON_MAX];
        snprintf(reason, sizeof(reason),
                 "from-anchor fold span (%d..%d] has a missing/pruned "
                 "block body at height=%d (%s); refusing to arm the "
                 "fold — utxo_apply would pin here. ACTION: fetch the "
                 "body (peer/disk) so the span is contiguous, then retry",
                 anchor_height, resume_target, first_missing,
                 bi ? "BLOCK_HAVE_DATA clear" : "no block_index slot");
        struct blocker_record r;
        if (blocker_init(&r, "refold.body_gap", "boot",
                         BLOCKER_DEPENDENCY, reason)) {
            r.escape_deadline_secs = 0;   /* no auto-escape: needs a body */
            r.retry_budget = -1;
            (void)blocker_set(&r);
        }
        fprintf(stderr,
                "[boot] -refold-from-anchor: BODY-SPAN GAP at height=%d "
                "in (%d..%d] — NOT arming the fold; raised named blocker "
                "refold.body_gap (fill the body, then retry)\n",
                first_missing, anchor_height, resume_target);
    }
    return false;
}

#ifdef ZCL_TESTING
int boot_refold_body_rebind_scan_attempts_for_test(void)
{
    return g_refold_rebind_scan_attempts;
}
void boot_refold_body_rebind_reset_for_test(void)
{
    g_refold_rebind_datadir[0] = '\0';
    g_refold_rebind_datadir_set = false;
    g_refold_rebind_scanned = false;
    g_refold_rebind_scan_attempts = 0;
}
#endif

/* B2 1c — the boot torn-import AUTO-ARM. Consults the PURE detect predicate
 * (block_index_loader_torn_import_detect — no side-effects) and, on a detected
 * tear, ARMS a from-anchor refold (reset 1a + mark 1b) so the node REPAIRS by
 * re-folding the proven anchor set forward instead of dead-ending at an operator
 * page. Returns true iff a from-anchor refold is (or is already) armed — the
 * caller then SKIPS block_index_loader_seed_stages_from_cold_import.
 *
 * IDEMPOTENT: if a from-anchor refold is already in progress (e.g. the explicit
 * -refold-from-anchor flag armed it at boot.c, or a prior crashed boot left the
 * durable key), it returns true WITHOUT re-resetting.
 *
 * FAIL-LOUD: boot_refold_from_anchor_reset _exit()s (FATAL) if the re-seeded
 * anchor set fails the SHA3/count assert — a genuinely-unrecoverable tear thus
 * stops here. When this returns FALSE (no tear detected), the caller proceeds to
 * the existing seed path, whose torn-import gate
 * (block_index_loader_torn_import_gate_fires) remains the EV_OPERATOR_NEEDED +
 * BLOCKER_PERMANENT fallback.
 *
 * DEFAULT SELF-HEAL: this is now called UNCONDITIONALLY on every boot from the
 * single seed-vs-anchor decision site (engine/composition/src/boot_services.c). It is safe
 * to run flag-free because the PURE detect predicate only fires on a DURABLY
 * proven tear, and the reset it triggers can only ever stamp the SHA3-verified
 * anchor set (or FATAL) — never an unproven one. A HEALTHY (untorn) datadir
 * returns false here and takes the normal seed path unchanged. */
bool boot_refold_from_anchor_arm_if_torn(struct main_state *ms,
                                         struct node_db *ndb,
                                         struct sqlite3 *progress_db)
{
    if (!ms || !ndb || !progress_db)
        return false;

    /* Already armed (explicit flag at boot.c, or a mid-fold restart): the
     * durable from-anchor signal is live — do NOT re-reset, just take over. */
    if (refold_from_anchor_active())
        return true;

    const struct sha3_utxo_checkpoint *cp = get_sha3_utxo_checkpoint();
    if (!cp)
        return false;  /* no checkpoint to anchor against — defer to the gate */
    const int32_t checkpoint = cp->height;

    int32_t hole_h = -1;
    int32_t ceiling = -1;
    if (!block_index_loader_torn_import_detect(ms, progress_db, checkpoint,
                                               &hole_h, &ceiling))
        return false;  /* no durable tear → caller runs the normal seed path */

    /* SAFETY (load-bearing): the AUTO-ARM must NEVER route a torn datadir into
     * the node.db `utxos` reseed + the hard-assert FATAL. boot_refold_from_anchor_reset
     * (the explicit -refold-from-anchor flag path) DELIBERATELY allows that
     * node.db fallback as the operator-paged path (its contract). But the
     * auto-arm runs by DEFAULT on a torn boot, so if no SHA3-verified snapshot is
     * reachable it must DECLINE — return false WITHOUT resetting — so the caller
     * (boot_services.c) falls through to the normal cold-import seed, whose torn
     * gate (block_index_loader_torn_import_gate_fires) raises the honest
     * EV_OPERATOR_NEEDED + seed.torn_import PERMANENT blocker. Without this the
     * default auto-arm would turn the current honest operator_needed halt into a
     * _exit(EXIT_FAILURE) on a torn-but-no-snapshot datadir — a regression. */
    if (!anchor_snapshot_verified_reachable(ndb, cp)) {
        LOG_WARN("boot", "[boot] from-anchor auto-arm: torn cold-import detected "
                 "at h=%d (frontier=%d) but NO SHA3-verified anchor snapshot is "
                 "reachable — DECLINING the auto-arm (would otherwise fall into "
                 "the contaminated node.db reseed + FATAL); deferring to the "
                 "honest operator_needed halt (block_index_loader_torn_import_"
                 "gate_fires)", (int)hole_h, (int)ceiling);
        return false;
    }

    /* CUTOVER DEFECT 2 — body-span gate BEFORE arming. The from-anchor fold
     * replays on-disk BODIES over (anchor, resume_target]; a missing/pruned body
     * in that span pins utxo_apply mid-fold (the prevout_unresolved wedge,
     * relocated to the gap height). Capture resume_target from the SAME
     * active_chain_height read the post-reset mark uses, then verify every body
     * is present. On a gap: raise the NAMED blocker refold.body_gap and DECLINE
     * the arm (return false) so the caller defers to the normal seed path / a
     * peer-fetch fills the body — never a silent stall mid-fold. */
    int32_t resume_target = (int32_t)active_chain_height(&ms->chain_active);
    int32_t first_missing = -1;
    if (!boot_refold_body_span_contiguous(ms, cp->height, resume_target,
                                          &first_missing, /*raise_blocker=*/true)) {
        LOG_WARN("boot", "[boot] from-anchor auto-arm: torn cold-import detected "
                 "at h=%d (frontier=%d) but the fold span (%d..%d] has a missing "
                 "block body at h=%d — DECLINING the auto-arm and raising "
                 "refold.body_gap (would otherwise pin utxo_apply mid-fold)",
                 (int)hole_h, (int)ceiling, (int)checkpoint, (int)resume_target,
                 (int)first_missing);
        return false;
    }

    LOG_WARN("boot",
             "[boot] from-anchor auto-arm: torn cold-import detected (durable "
             "unresolved prevout at h=%d, frontier=%d) — arming a from-anchor "
             "refold (re-seed the SHA3 anchor set + fold forward) instead of "
             "halting; the anchor set is HARD-ASSERTED next (FATAL on mismatch)",
             (int)hole_h, (int)ceiling);

    /* Reset FATALs internally if the re-seeded anchor set fails the SHA3/count
     * assert (a genuinely-unrecoverable tear). On return the anchor set is
     * PROVEN, so mark the from-anchor signal + resume target (the active tip the
     * fold climbs to). The verified-snapshot reachability was just confirmed
     * above, so the reset takes the snapshot reseed path (never the node.db
     * fallback). */
    boot_refold_from_anchor_reset(ndb);
    (void)refold_progress_mark_started_from_anchor(progress_db, resume_target);
    return true;
}
