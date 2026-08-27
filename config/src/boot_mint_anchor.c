/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. */
/* boot_mint_anchor.c — the ANCHOR-SET MINT driver. Contract in config/boot.h
 * (boot_mint_anchor_run). Lives here, separate from boot.c, so each file keeps
 * one focused responsibility.
 *
 * After app_init has (via boot_mint_anchor_reset) reset the staged reducer to
 * genesis and capped the fold at the compiled SHA3 UTXO checkpoint anchor, this
 * driver:
 *   (1) drives the staged reducer synchronously (reducer_kick under the
 *       activation mutex — the same drain the supervisor uses) until the
 *       utxo_apply frontier reaches the anchor (or progress stalls);
 *   (2) writes the resulting coins_kv set to a SHA3-committed snapshot artifact
 *       in the loader's USS format (coins_kv_snapshot_write);
 *   (3) HARD-ASSERTS the written commitment + count == the compiled checkpoint
 *       (FATAL + _exit on mismatch — a mismatch means our fold disagrees with
 *       zclassicd's checkpoint, the h=478544 class: page, never proceed).
 *
 * The validation policy is selected before this driver starts: normal
 * -mint-anchor keeps crypto validation on; -mint-anchor-fast passes the
 * script/proof stages through while preserving the state fold and final
 * SHA3/count hard-assert.
 *
 * OBSERVABILITY — the drive loop appends a throttled progress line
 * (height / anchor / rate / ETA / elapsed) to <datadir>/mint-progress.log (or
 * $ZCL_MINT_PROGRESS_LOG) every ~5s so a long fold is readable FROM DISK, not
 * only from stderr. Best-effort: a log-write failure never affects the fold.
 *
 * RESUMABILITY — a fresh mint does NOT re-fold from genesis after a crash. Three
 * durable mechanisms already cover resume; this driver only observes them:
 *   (1) progress.kv stage cursors are committed per drain batch (durable);
 *   (2) mint_anchor_progress (config/src/mint_anchor_progress.c) binds a
 *       checkpoint-scoped resume marker so boot_mint_anchor_reset SKIPS the
 *       genesis reset and resumes at coins_applied_height (see the "resuming
 *       existing checkpoint-bound fold" branch);
 *   (3) with -fold-inram, coins_ram flushes the in-RAM overlay to durable
 *       coins_kv every ZCL_FOLD_INRAM_FLUSH_EVERY blocks (default 50,000) and
 *       coins_ram_reconcile_boot rewinds the cursor to that flush watermark on
 *       the next boot, so a crash loses at most one flush window, not the fold.
 * The worst-case resume rewind is thus one flush window; lower
 * ZCL_FOLD_INRAM_FLUSH_EVERY to tighten it. A finer (per-batch) synchronous
 * checkpoint of the full in-RAM working set is intentionally NOT added here — it
 * would trade the fold's dominant throughput lever (a low fsync cadence) for a
 * marginal resume-granularity gain, and the mechanisms above already make the
 * mint resumable without it. */
#include "config/boot.h"
#include "config/boot_internal.h"  /* boot_full_fold_is_armed/_finish (-full-fold) */
#include "config/boot_mint_anchor_drive.h"
#include "config/mint_anchor_progress.h"
#include "config/consensus_state_producer_receipt.h"
#include "config/consensus_state_snapshot_export.h"  /* consensus_state_snapshot_export */

#include <errno.h>
#include <fcntl.h>           /* open, O_DIRECTORY */
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>          /* EXIT_FAILURE, getenv */
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>          /* _exit */
#include <sqlite3.h>

#include "chain/checkpoints.h"                  /* get_sha3_utxo_checkpoint */
#include "storage/coins_kv.h"                   /* coins_kv_snapshot_write,
                                                 * coins_kv_get_applied_height,
                                                 * coins_kv_count,
                                                 * coins_kv_commitment */
#include "storage/coins_ram.h"                  /* coins_ram_active,
                                                 * coins_ram_commitment */
#include "storage/snapshot_shielded.h"          /* snapshot_shielded_collect_from_db */
#include "storage/event_log_singleton.h"        /* event_log_set_singleton (S1.2) */
#include "storage/consensus_state_bundle_codec.h" /* CONSENSUS_STATE_VALIDATION_* */
#include "storage/progress_store.h"             /* progress_store_db */
#include "jobs/mint_skip_crypto.h"              /* mint_skip_crypto_get */
#include "jobs/proof_validate_stage.h"          /* proof_validate_lookahead_start */
#include "jobs/utxo_apply_stage.h"              /* utxo_apply_stage_cursor */
#include "jobs/stage_helpers.h"                 /* stage_cursor_persisted */
#include "services/chain_activation_service.h"  /* reducer_kick,
                                                 * boot_activation_controller */
#include "event/event.h"                        /* event_emitf */
#include "util/blocker.h"                       /* blocker_init, blocker_set */
#include "util/log_macros.h"
#include "core/utiltime.h"                       /* GetTimeMicros */

bool boot_mint_anchor_normal_boot_gate(sqlite3 *progress_db)
{
    char reason[512];
    if (mint_anchor_normal_boot_allowed(progress_db, reason, sizeof(reason)))
        return true;
    fprintf(stderr, "FATAL: normal node boot refused by producer evidence "
            "containment: %s\n",
            reason[0] ? reason : "validation-profile scan failed");
    event_emitf(EV_BOOT_VALIDATION_FAILED, 0,
                "producer_evidence_contained reason=%s",
                reason[0] ? reason : "profile_scan_failed");
    return false;
}

void boot_mint_anchor_require_producer_lane(sqlite3 *progress_db,
                                            bool checkpoint_fold)
{
    if (mint_anchor_producer_lane_bind(progress_db, checkpoint_fold))
        return;
    fprintf(stderr, "FATAL: -mint-anchor producer datadir is bound to a "
            "different validation profile; refusing mixed generations\n");
    event_emitf(EV_BOOT_VALIDATION_FAILED, 0,
                "mint_anchor producer_lane_profile_mismatch");
    _exit(EXIT_FAILURE);
}

/* The utxo_apply frontier is a NEXT-height cursor: applied-through `h` means
 * coins_applied_height == h+1. Read it; return -1 when unknown (absent). */
static int32_t mint_applied_through(sqlite3 *pdb)
{
    int32_t frontier = 0;
    bool found = false;
    if (!coins_kv_get_applied_height(pdb, &frontier, &found) || !found)
        return -1;
    return frontier - 1;
}

/* The IMMEDIATE fold frontier: the utxo_apply STAGE cursor (next height to
 * apply; batch-committed by the drain). This is the drive loop's progress
 * metric. mint_applied_through above reads the durable coins_applied_height
 * key, which under -fold-inram is written only at coins_ram FLUSH boundaries
 * (every ZCL_FOLD_INRAM_FLUSH_EVERY blocks, coins_ram.c) — it reads -1 for the
 * whole first flush window and then lags by up to a window, so a drive loop
 * gated on it can neither see progress (a false "stall") nor see the anchor
 * being reached (a false "incomplete" after a COMPLETE fold whose tail is
 * still overlay-resident). Returns -1 when nothing has been applied. */
static int32_t mint_frontier_through(void)
{
    uint64_t cursor = utxo_apply_stage_cursor();
    if (cursor == 0)
        return -1;
    if (cursor > (uint64_t)INT32_MAX)
        return INT32_MAX;
    return (int32_t)cursor - 1;
}

/* Fail-closed stall diagnosis: the fold frontier stopped below the anchor.
 * Read the eight durable stage cursors, name the WALLED stage (the earliest
 * pipeline stage sitting at the minimum cursor — upstream of the wall runs
 * ahead, downstream can never pass it), register a typed PERMANENT blocker
 * carrying all eight cursors, and page the operator via EV_OPERATOR_NEEDED.
 * The bodies-gap wording is used ONLY when the wall is body_fetch (headers
 * validated but no on-disk body to fetch at the frontier) — every other wall
 * names its stage instead of blaming the body import. Public (config/boot.h)
 * so the mint-fold livelock regression test can assert the blocker payload. */
void boot_mint_anchor_report_frontier_walled(sqlite3 *pdb, int32_t frontier,
                                             int32_t anchor, int stall_kicks)
{
    /* Pipeline order; tip_finalize is read for the report but excluded from
     * wall selection (it intentionally trails the fold during a mint). */
    static const char *const stages[8] = {
        "header_admit", "validate_headers", "body_fetch", "body_persist",
        "script_validate", "proof_validate", "utxo_apply", "tip_finalize" };
    uint64_t cur[8] = {0};
    for (int i = 0; i < 8; i++)
        cur[i] = stage_cursor_persisted(pdb, stages[i], "mint_anchor");

    int wall = 0;
    for (int i = 1; i < 7; i++)          /* exclude tip_finalize (index 7) */
        if (cur[i] < cur[wall])
            wall = i;
    bool bodies_gap = (wall == 2);       /* body_fetch */

    char reason[BLOCKER_REASON_MAX];
    snprintf(reason, sizeof(reason),
             "mint fold frontier walled at h=%d (anchor=%d) after %d "
             "no-progress kicks; wall=%s cursors ha=%llu vh=%llu bf=%llu "
             "bp=%llu sv=%llu pv=%llu ua=%llu tf=%llu",
             frontier, anchor, stall_kicks, stages[wall],
             (unsigned long long)cur[0], (unsigned long long)cur[1],
             (unsigned long long)cur[2], (unsigned long long)cur[3],
             (unsigned long long)cur[4], (unsigned long long)cur[5],
             (unsigned long long)cur[6], (unsigned long long)cur[7]);

    struct blocker_record rec;
    if (blocker_init(&rec, "mint_fold.frontier_walled", "mint_anchor",
                     BLOCKER_PERMANENT, reason))
        (void)blocker_set(&rec);
    event_emitf(EV_OPERATOR_NEEDED, 0,
                "condition=mint_fold_frontier_walled %s", reason);

    if (bodies_gap)
        fprintf(stderr,
                "[mint-anchor] fold stalled at applied-through=%d (target "
                "anchor=%d): body_fetch is the walled stage — the on-disk "
                "bodies below the anchor are incomplete; cannot mint. Import "
                "the full header+body history first. (%s)\n",
                frontier, anchor, reason);
    else
        fprintf(stderr,
                "[mint-anchor] fold stalled at applied-through=%d (target "
                "anchor=%d): stage %s is walled — NOT a bodies gap; inspect "
                "its stage log at the frontier height. (%s)\n",
                frontier, anchor, stages[wall], reason);
}

/* Lane A1 — emit the contained full-history zcl.consensus_state_bundle.v1 into
 * the mint datadir once the producer source receipt has been finalized. This is
 * the exporter's (config/consensus_state_snapshot_export.h) ONLY viable caller:
 * its receipt-binding proof requires the exporting process to be the EXACT
 * binary that folded (running_binary_digest == SHA3(/proc/self/exe)), so an
 * offline verb from a different binary is provably impossible — the export must
 * happen here, in-process, right after finalize.
 *
 * The exporter demands a durable, overlay-free, fully-proven source generation,
 * so this first QUIESCES the in-RAM fold overlay: coins_ram_flush_final drains
 * the un-flushed tail into durable coins_kv (co-advancing coins_applied_height
 * to anchor+1) and coins_ram_shutdown frees the map so coins_ram_active() is
 * false (the exporter refuses while the overlay is live). It then exports to
 * <datadir>/consensus-state-bundle-<anchor>.sqlite.
 *
 * Idempotent across re-runs of the SAME binary: an already-present bundle at
 * that name is a completed export (the exporter only ever links a fully
 * validated immutable inode and publishes NOTHING on any failure), so it is
 * treated as done. A failed export never touches the verified anchor snapshot
 * or the receipt; it pages EV_OPERATOR_NEEDED, registers the typed PERMANENT
 * blocker mint_bundle.export_failed, and returns false so the one-shot exits
 * non-zero (the systemd unit shows the miss). Returns true on a fresh export or
 * an already-present bundle. Public (config/boot.h) so the
 * consensus_state_snapshot_export test group can prove the wiring fires. */
bool boot_mint_anchor_export_bundle(sqlite3 *pdb, const char *datadir,
                                    int32_t anchor,
                                    const uint8_t block_hash[32])
{
    const char *dir = (datadir && datadir[0]) ? datadir : ".";
    char name[128];
    int nn = snprintf(name, sizeof(name),
                      "consensus-state-bundle-%d.sqlite", anchor);
    if (nn <= 0 || (size_t)nn >= sizeof(name)) {
        event_emitf(EV_OPERATOR_NEEDED, 0,
                    "condition=mint_bundle_export_failed reason=name_overflow "
                    "anchor=%d", anchor);
        LOG_FAIL("mint_anchor",
                 "[mint-anchor] consensus-state bundle name overflow anchor=%d",
                 anchor);
    }

    int dir_fd = open(dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (dir_fd < 0) {
        event_emitf(EV_OPERATOR_NEEDED, 0,
                    "condition=mint_bundle_export_failed reason=datadir_open "
                    "anchor=%d errno=%d", anchor, errno);
        LOG_FAIL("mint_anchor",
                 "[mint-anchor] consensus-state bundle: cannot open datadir %s "
                 "for export (errno=%d)", dir, errno);
    }

    /* Already exported by a prior run? A present name is always a completed,
     * fully validated immutable bundle — nothing to redo (a failed export
     * leaves no file). Retry-on-rerun therefore comes for free: missing ->
     * export; present -> success no-op; prior failure -> absent, so retried. */
    struct stat existing;
    if (fstatat(dir_fd, name, &existing, AT_SYMLINK_NOFOLLOW) == 0) {
        (void)close(dir_fd);
        fprintf(stderr,
                "[mint-anchor] consensus-state bundle already present (prior "
                "run): %s/%s — nothing to export\n", dir, name);
        return true;
    }

    /* Quiesce the in-RAM fold overlay so the durable coins set IS the effective
     * set the exporter proves (it refuses while coins_ram_active()). */
    if (coins_ram_active()) {
        if (!coins_ram_flush_final()) {
            (void)close(dir_fd);
            event_emitf(EV_OPERATOR_NEEDED, 0,
                        "condition=mint_bundle_export_failed "
                        "reason=coins_ram_flush anchor=%d", anchor);
            struct blocker_record frec;
            if (blocker_init(&frec, "mint_bundle.export_failed", "mint_anchor",
                             BLOCKER_PERMANENT,
                             "consensus-state bundle export aborted: coins RAM "
                             "overlay flush failed before export"))
                (void)blocker_set(&frec);
            LOG_FAIL("mint_anchor",
                     "[mint-anchor] consensus-state bundle export aborted: "
                     "coins RAM overlay flush to durable coins_kv failed");
        }
        coins_ram_shutdown();
        fprintf(stderr,
                "[mint-anchor] coins RAM overlay flushed to durable coins_kv "
                "and released for the consensus-state bundle export\n");
    }

    struct consensus_state_snapshot_export_request request = {
        .output_dir_fd = dir_fd,
        .output_name = name,
        .expected_height = anchor,
    };
    memcpy(request.expected_block_hash, block_hash, 32);
    struct consensus_state_export_result res;
    bool exported = consensus_state_snapshot_export(pdb, &request, &res);
    (void)close(dir_fd);

    if (!exported || res.status != CONSENSUS_EXPORT_EXPORTED) {
        event_emitf(EV_OPERATOR_NEEDED, 0,
                    "condition=mint_bundle_export_failed anchor=%d status=%d "
                    "reason=%s", anchor, (int)res.status,
                    res.reason[0] ? res.reason : "unknown");
        char breason[640];
        snprintf(breason, sizeof(breason),
                 "consensus-state bundle export refused anchor=%d status=%d: %s "
                 "(verified anchor snapshot + receipt intact)",
                 anchor, (int)res.status,
                 res.reason[0] ? res.reason : "unknown");
        struct blocker_record frec;
        if (blocker_init(&frec, "mint_bundle.export_failed", "mint_anchor",
                         BLOCKER_PERMANENT, breason))
            (void)blocker_set(&frec);
        LOG_FAIL("mint_anchor",
                 "[mint-anchor] consensus-state bundle export FAILED (anchor=%d "
                 "status=%d): %s — the verified anchor snapshot and producer "
                 "receipt are unaffected", anchor, (int)res.status,
                 res.reason[0] ? res.reason : "unknown");
    }

    char digest_hex[65];
    for (int i = 0; i < 32; i++)
        snprintf(digest_hex + 2 * i, 3, "%02x", res.artifact_digest[i]);
    fprintf(stderr,
            "[mint-anchor] SUCCESS: exported %s at h=%d -> %s/%s (digest=%s "
            "coins=%llu anchors=%llu nullifiers=%llu profile=%s)\n",
            CONSENSUS_STATE_BUNDLE_SCHEMA, res.height, dir, name, digest_hex,
            (unsigned long long)res.utxo_count,
            (unsigned long long)res.anchor_count,
            (unsigned long long)res.nullifier_count,
            res.validation_profile == CONSENSUS_STATE_VALIDATION_FULL
                ? "full" : "checkpoint_fold");
    return true;
}

bool boot_mint_anchor_stamp_sovereign_markers(sqlite3 *pdb)
{
    if (!pdb)
        LOG_FAIL("mint_anchor", "stamp sovereign markers: NULL db");
    if (!coins_kv_mark_migration_complete(pdb))
        LOG_FAIL("mint_anchor",
                 "stamp sovereign markers: migration-complete stamp failed");
    if (!coins_kv_mark_self_folded(pdb))
        LOG_FAIL("mint_anchor",
                 "stamp sovereign markers: self-folded stamp failed");
    return true;
}

bool boot_mint_anchor_run(const char *datadir)
{
    const struct sha3_utxo_checkpoint *cp = get_sha3_utxo_checkpoint();
    if (!cp) {
        fprintf(stderr, "FATAL: -mint-anchor: no compiled SHA3 UTXO checkpoint\n");
        event_emitf(EV_BOOT_VALIDATION_FAILED, 0,
                    "mint_anchor no_compiled_checkpoint");
        _exit(EXIT_FAILURE);
    }
    /* -full-fold (boot_full_fold.c) overrides the target to the local header TIP
     * and skips the checkpoint ceremony; disarmed → target == cp->height. */
    int32_t ff_target = -1;
    const bool full_fold = boot_full_fold_is_armed(&ff_target);
    const int32_t anchor = full_fold ? ff_target : cp->height;

    sqlite3 *pdb = progress_store_db();
    if (!pdb) {
        fprintf(stderr, "FATAL: -mint-anchor: progress store not open\n");
        _exit(EXIT_FAILURE);
    }
    struct chain_activation_controller *ctl = boot_activation_controller();
    if (!ctl) {
        fprintf(stderr, "FATAL: -mint-anchor: no activation controller\n");
        _exit(EXIT_FAILURE);
    }

    /* Producer-START ownership of the durable source receipt (see
     * config/consensus_state_producer_receipt.h): record the running executable
     * + source-identity claim and publish the source-epoch digest BEFORE the
     * fold, so every stamped stage row carries it — the binding the contained
     * full-history exporter's stage-row proof requires. Best-effort: a build
     * with no exact 64-hex source identity cannot earn a v2 receipt, but the
     * mint's primary artifact (the verified anchor snapshot) is still
     * produced. */
    {
        uint8_t profile = mint_skip_crypto_get()
                              ? CONSENSUS_STATE_VALIDATION_CHECKPOINT_FOLD
                              : CONSENSUS_STATE_VALIDATION_FULL;
        char rc_err[256] = {0};
        if (!consensus_state_producer_receipt_begin(pdb, profile, rc_err,
                                                    sizeof(rc_err)))
            LOG_WARN("mint_anchor",
                     "[mint-anchor] source receipt begin skipped (mint still "
                     "runs; artifact not exporter-admissible): %s", rc_err);
        else
            fprintf(stderr,
                    "[mint-anchor] durable source receipt session opened "
                    "(profile=%s)\n",
                    profile == CONSENSUS_STATE_VALIDATION_FULL
                        ? "full" : "checkpoint_fold");
    }

    /* (1) Drive the fold to the anchor. reducer_kick_unbudgeted drains the same
     * eight-stage pipeline the supervisor uses, under the activation mutex (no
     * race with the background ticks) AND with the reducer-drive guard held so
     * the supervisor yields its 2s stage ticks for the whole drain. Unlike the
     * budgeted reducer_kick, each call folds back-to-back until convergence
     * instead of stopping every 2s and returning here to re-read the frontier —
     * so the genesis..anchor fold is not chopped into 2s slices. The
     * header_admit ceiling (boot_mint_anchor_reset) caps the fold AT the anchor,
     * so the pipeline converges there and the kick returns 0 advances. We loop
     * until the utxo_apply frontier reaches the anchor; we also break on a
     * no-progress plateau so a bodies-missing datadir cannot spin forever (the
     * caller then reports the mint as incomplete, not a false anchor). */
    /* Progress metric: the IMMEDIATE utxo_apply stage frontier
     * (mint_frontier_through), NOT the durable coins_applied_height. Under
     * -fold-inram the durable key only moves at coins_ram flush boundaries
     * (every ZCL_FOLD_INRAM_FLUSH_EVERY blocks), so gating on it makes the
     * stall detector blind for a whole flush window AND leaves the anchor
     * break unreachable when the fold's tail is overlay-resident. On resume
     * the stage cursor already reflects the durable resume point. */
    /* S1.2 — skip event_log emission during the offline mint. The mint's only
     * output (utxo-anchor.snapshot) is built from coins_kv (progress.kv,
     * written directly by utxo_apply) + node.db shielded state; it never reads
     * the event_log or its projections. So the fold-thread EV_BLOCK_HEADER
     * emission — serialize + pwrite + fsync per block — is
     * pure overhead here. Every fold-path emitter routes through
     * event_log_singleton() and is NULL-tolerant (skips on NULL), so unwiring
     * the singleton suppresses all of them for the mint's duration.
     *
     * Two env escapes keep the emission on for A/B measurement:
     *   ZCL_EVENTLOG_SYNC_PER_APPEND=1  (the S1.1 kill switch — restore the OLD
     *                                    per-append-fsync baseline: emission ON)
     *   ZCL_MINT_KEEP_EVENTLOG=1        (keep emission ON but let S1.1 batch it
     *                                    — isolates the S1.2 delta). */
    bool keep_eventlog = (getenv("ZCL_EVENTLOG_SYNC_PER_APPEND") != NULL) ||
                         (getenv("ZCL_MINT_KEEP_EVENTLOG") != NULL);
    if (!keep_eventlog) {
        event_log_set_singleton(NULL);
        fprintf(stderr,
                "[mint-anchor] S1.2: event_log emission suppressed for the fold "
                "(artifact reads coins_kv + shielded only)\n");
    }

    /* S1.3: progress.kv synchronous=OFF for the fold's duration. This is the
     * same IBD durability trade the live sync path already makes via
     * progress_store_set_sync_mode() from the staged-sync supervisor tick —
     * which never runs here (the mint boots its stages offline, with no
     * liveness contracts), so without this the whole genesis→anchor fold pays
     * an fsync barrier on every stage-batch COMMIT. The crash-ordering
     * invariant survives: block bodies are fdatasync()ed BEFORE each COMMIT
     * by the pre-commit veto hook, so a lost COMMIT can only leave the cursor
     * BEHIND the bodies — the fold resumes from the earlier cursor and
     * re-folds the window. Restored to NORMAL + a durable checkpoint before
     * the snapshot/receipt/export below. Opt out: ZCL_MINT_PROGRESS_SYNC_OFF=0. */
    const char *sync_env = getenv("ZCL_MINT_PROGRESS_SYNC_OFF");
    bool mint_sync_off = !(sync_env && strcmp(sync_env, "0") == 0);
    if (mint_sync_off) {
        progress_store_set_sync_mode(/*ibd=*/true);
        fprintf(stderr,
                "[mint-anchor] S1.3: progress.kv synchronous=OFF for the fold "
                "(bodies still fdatasync'd before each COMMIT; restored to "
                "NORMAL+checkpoint at the anchor)\n");
    }

    int32_t last_through = mint_frontier_through();
    if (last_through < 0)
        last_through = mint_applied_through(pdb);  /* pre-init fallback */
    int stall_kicks = 0;
    struct mint_rebuild_wait_state rebuild_wait = {0};
    const int kStallLimit = 64;   /* consecutive no-progress kicks → walled */
    char progress_log[1200];
    boot_mint_anchor_progress_log_path(datadir, progress_log, sizeof(progress_log));
    const int64_t drive_start_us = GetTimeMicros();
    fprintf(stderr,
            "[mint-anchor] driving the genesis..%d fold; "
            "starting at applied-through=%d; progress log -> %s\n",
            anchor, last_through, progress_log);
    boot_mint_anchor_progress_log_tick(progress_log, last_through, anchor,
                           drive_start_us, /*force=*/true);

    /* Serial mint pipeline: mark this drive thread so every stage step reads the
     * un-flushed overlay via coins_kv_overlay_safe() (the writer bracket only
     * spans utxo_apply). Sound ONLY because the mint fold is single-threaded.
     * Balanced on every exit path below. */
    coins_ram_mint_drive_enter();

    /* Cross-height proof pre-verification (jobs/pv_lookahead.h): workers
     * verify shielded proofs AHEAD of this drive so the pv stage consumes
     * cached verdicts instead of paying 13-18ms serial per block. The workers
     * never touch coins_kv/coins_ram (pure block-body readers), so the
     * single-threaded-overlay invariant above is untouched. Skip-crypto mints
     * never verify, so the pool would only waste cores there. A start failure
     * degrades to the serial fold (verdict-identical either way). */
    bool lookahead = false;
    if (!mint_skip_crypto_get()) {
        lookahead = proof_validate_lookahead_start();
        fprintf(stderr, "[mint-anchor] proof lookahead %s\n",
                lookahead ? "started" : "unavailable — folding serially");
    }

    /* WAL policy: once the overlay is the write path, hold auto-checkpoints off
     * and TRUNCATE the WAL at each overlay flush boundary (where the durable
     * coins_applied_height advances), bounding WAL growth without an fsync per
     * commit. SQLite default when the overlay is opted out (ZCL_FOLD_INRAM=0). */
    bool wal_manual = false;
    int32_t last_durable = -1;

    for (;;) {
        int32_t through = mint_frontier_through();
        if (through >= anchor)
            break;

        /* Bounded drain chunk: returns within ZCL_MINT_KICK_BUDGET_MS (or at
         * the first frontier-stalled round) so THIS loop reliably regains
         * control to log progress and run the stall detector below — an
         * unbounded kick can otherwise spin silently for hours with no
         * progress line and no stall guard ever running. */
        (void)reducer_kick_unbudgeted(ctl);

        if (!wal_manual && coins_ram_active()) {
            mint_wal_autocheckpoint(pdb, 0);
            wal_manual = true;
            last_durable = mint_applied_through(pdb);
            fprintf(stderr,
                    "[mint-anchor] S1.3+: WAL auto-checkpoint disabled; the WAL "
                    "is TRUNCATEd at each overlay flush boundary\n");
        }
        /* A flush landed iff the durable applied-through advanced. */
        if (wal_manual) {
            int32_t durable_now = mint_applied_through(pdb);
            if (durable_now > last_durable) {
                (void)progress_store_checkpoint();
                last_durable = durable_now;
            }
        }

        int32_t now = mint_frontier_through();
        /* Throttled on-disk progress (every ~5s) — readable while the fold
         * runs, regardless of the sparse stderr cadence below. */
        boot_mint_anchor_progress_log_tick(progress_log, now, anchor, drive_start_us,
                               /*force=*/false);
        if (now > last_through) {
            last_through = now;
            stall_kicks = 0;
            rebuild_wait = (struct mint_rebuild_wait_state){0};
            if (boot_mint_anchor_should_log_progress(now, anchor))
                fprintf(stderr, "[mint-anchor] applied-through=%d / %d\n",
                        now, anchor);
        } else if (utxo_apply_sapling_rebuild_paused() &&
                   mint_rebuild_wait_max_s() > 0) {
            /* NOT a stall — the deferred Sapling rebuild holds utxo_apply
             * paused on purpose. Hold the stall counter and nap; the fold
             * resumes by itself once the rebuild publishes its frontier. */
            if (boot_mint_anchor_drive_rebuild_wait(&rebuild_wait) ==
                MINT_REBUILD_WAIT_TIMEOUT) {
                mint_drive_stop(pdb, mint_sync_off, wal_manual, lookahead);
                boot_mint_anchor_report_frontier_walled(pdb, now, anchor,
                                                        stall_kicks);
                return false;
            }
        } else if (++stall_kicks < kStallLimit) {
            /* No progress and nothing legitimately paused. Nap before the
             * next round: without it the 64-kick budget is spent in about a
             * second, so a fold that merely needs a moment to warm up reads
             * as permanently walled. */
            mint_drive_nap_ms(200);
        } else {
            /* Fail CLOSED with a named blocker: register
             * mint_fold.frontier_walled (all eight stage cursors in the
             * reason), page EV_OPERATOR_NEEDED, and print a diagnosis that
             * names the walled stage — "bodies incomplete" only when
             * body_fetch really is the wall. */
            mint_drive_stop(pdb, mint_sync_off, wal_manual, lookahead);
            boot_mint_anchor_report_frontier_walled(pdb, now, anchor,
                                                    kStallLimit);
            return false;
        }
    }

    if (lookahead)
        proof_validate_lookahead_stop();
    coins_ram_mint_drive_exit();

    int32_t through = mint_frontier_through();
    int64_t count = coins_kv_count(pdb);
    boot_mint_anchor_progress_log_tick(progress_log, through, anchor, drive_start_us,
                           /*force=*/true);

    /* Restore durability BEFORE any artifact derives from the DB (shared by the
     * mint ceremony AND the -full-fold early return): NORMAL first (set_sync_mode
     * does not checkpoint), then wal_checkpoint(TRUNCATE) so every fold write is
     * durably in the main db. */
    if (mint_sync_off) {
        progress_store_set_sync_mode(/*ibd=*/false);
        if (!progress_store_checkpoint())
            LOG_WARN("mint_anchor",
                     "pre-export wal_checkpoint failed; artifact remains "
                     "SHA3-gated");
    }
    /* Restore auto-checkpointing + a final TRUNCATE (independent of the sync-off
     * restore — wal_manual can be set with ZCL_MINT_PROGRESS_SYNC_OFF=0). */
    if (wal_manual) {
        mint_wal_autocheckpoint(pdb, 1000);
        (void)progress_store_checkpoint();
    }

    /* -full-fold: SKIP the cp->height ceremony; verdict + tip bundle export. */
    if (full_fold)
        return boot_full_fold_conclude(pdb, datadir, through, count, anchor,
                                       kStallLimit);

    fprintf(stderr,
            "[mint-anchor] fold reached the anchor: applied-through=%d, "
            "coins_kv count=%lld — writing the snapshot\n",
            through, (long long)count);

    /* (2) Write the snapshot artifact. Output path: $ZCL_MINT_ANCHOR_OUT, else
     * <datadir>/utxo-anchor.snapshot. */
    char out_path[1100];
    const char *env_out = getenv("ZCL_MINT_ANCHOR_OUT");
    if (env_out && env_out[0]) {
        snprintf(out_path, sizeof(out_path), "%s", env_out);
    } else {
        snprintf(out_path, sizeof(out_path), "%s/utxo-anchor.snapshot",
                 datadir ? datadir : ".");
    }

    /* Collect the live SHIELDED frontier at the anchor (Sapling + Sprout
     * commitment-tree frontiers + the nullifier set) so the legacy artifact is
     * a locally self-minted current-state candidate, not a coins-only borrow.
     * It still omits historical anchor rows and therefore is not a complete
     * sovereign bundle. The transparent set is checked against the compiled
     * checkpoint; Sprout and nullifier completeness still require the canonical
     * bundle proof manifest and copy proof. FAIL LOUD if the
     * frontier is unavailable — never emit a coins-only snapshot mislabeled
     * shielded (the birth-defect this cure exists to close). */
    struct snapshot_shielded shielded;
    if (!snapshot_shielded_collect_from_db(pdb, anchor, &shielded)) {
        fprintf(stderr,
                "FATAL: -mint-anchor: shielded-frontier collection at h=%d "
                "failed — refusing to emit a coins-only snapshot mislabeled "
                "shielded\n", anchor);
        event_emitf(EV_BOOT_VALIDATION_FAILED, 0,
                    "mint_anchor shielded_collect_failed h=%d", anchor);
        _exit(EXIT_FAILURE);
    }

    uint8_t got_sha3[32] = {0};
    uint64_t got_count = 0;
    int64_t  got_supply = 0;
    if (!coins_kv_snapshot_write(pdb, out_path, anchor, cp->block_hash,
                                 &shielded, got_sha3, &got_count, &got_supply)) {
        snapshot_shielded_free_collected(&shielded);
        fprintf(stderr, "FATAL: -mint-anchor: snapshot write to %s failed\n",
                out_path);
        event_emitf(EV_BOOT_VALIDATION_FAILED, 0,
                    "mint_anchor snapshot_write_failed path=%s", out_path);
        _exit(EXIT_FAILURE);
    }
    snapshot_shielded_free_collected(&shielded);

    /* Coins-only commitment over the SAME effective set the writer streamed.
     * got_sha3 is the v3 BODY SHA3 (coins + shielded section), so it is NOT the
     * coins commitment the compiled checkpoint pins; compute that separately,
     * mirroring the writer's overlay predicate (coins_ram_active), so the value
     * covers any un-flushed in-RAM fold tail exactly as the writer did. */
    uint8_t coins_sha3[32] = {0};
    int crc = coins_ram_active() ? coins_ram_commitment(coins_sha3)
                                 : coins_kv_commitment(pdb, coins_sha3);
    if (crc != 0) {
        fprintf(stderr, "FATAL: -mint-anchor: coins commitment computation at "
                "h=%d failed — cannot verify the minted set\n", anchor);
        event_emitf(EV_BOOT_VALIDATION_FAILED, 0,
                    "mint_anchor coins_commitment_failed h=%d", anchor);
        unlink(out_path);
        _exit(EXIT_FAILURE);
    }

    /* (3) HARD-ASSERT the written set == the compiled checkpoint. The writer's
     * body SHA3 equals coins_kv_commitment (same record encoder),
     * so a match here proves our independently-folded anchor set reproduces
     * zclassicd's checkpoint exactly. A MISMATCH means our fold disagrees with
     * the checkpoint (the h=478544 class): page EV_BOOT_VALIDATION_FAILED and
     * _exit — NEVER retain an unproven artifact. */
    bool sha3_match = memcmp(coins_sha3, cp->sha3_hash, 32) == 0;
    bool count_match = got_count == cp->utxo_count;
    if (!sha3_match || !count_match) {
        char want_hex[65], got_hex[65];
        for (int i = 0; i < 32; i++) {
            snprintf(want_hex + 2 * i, 3, "%02x", cp->sha3_hash[i]);
            snprintf(got_hex + 2 * i, 3, "%02x", coins_sha3[i]);
        }
        fprintf(stderr,
                "FATAL: -mint-anchor: minted anchor set FAILED the SHA3/count "
                "check (count=%llu want=%llu, sha3=%s want=%s) — our genesis.."
                "%d fold disagrees with the compiled checkpoint. Refusing to "
                "retain; the artifact at %s is NOT trustworthy.\n",
                (unsigned long long)got_count,
                (unsigned long long)cp->utxo_count, got_hex, want_hex,
                anchor, out_path);
        event_emitf(EV_BOOT_VALIDATION_FAILED, 0,
                    "check=mint_anchor anchor_h=%d minted set mismatch "
                    "(count=%llu want=%llu sha3_match=%d) — fold disagrees with "
                    "the compiled checkpoint; do NOT trust the artifact",
                    anchor, (unsigned long long)got_count,
                    (unsigned long long)cp->utxo_count, sha3_match ? 1 : 0);
        /* Remove the bad artifact so a later -refold-from-anchor cannot load it. */
        unlink(out_path);
        _exit(EXIT_FAILURE);
    }

    /* (3b) HARD-ASSERT the shielded keystone: anchors/nullifiers/frontier
     * folds == the compiled ROM state checkpoint (boot_mint_anchor_rom_keystone.c). */
    boot_mint_anchor_rom_keystone_assert(pdb, out_path);

    char sha3_hex[65];
    for (int i = 0; i < 32; i++)
        snprintf(sha3_hex + 2 * i, 3, "%02x", coins_sha3[i]);
    fprintf(stderr,
            "[mint-anchor] SUCCESS: minted a checkpoint-matching anchor UTXO "
            "set at h=%d "
            "(count=%llu, supply=%lld zatoshi, coins_sha3=%s) — matches the "
            "compiled checkpoint. Locally self-minted legacy v3 current-state "
            "candidate (history incomplete; non-serving and not canonically "
            "publishable): "
            "%s\n",
            anchor, (unsigned long long)got_count, (long long)got_supply,
            sha3_hex, out_path);
    if (!mint_anchor_progress_clear(pdb))
        LOG_WARN("mint_anchor",
                 "[mint-anchor] verified snapshot was written, but clearing "
                 "the resume marker failed; future -mint-anchor runs may "
                 "resume/rewrite the same verified artifact");

    /* Producer-END ownership: finalize the durable source receipt, binding it
     * to the completed (anchor, cp->block_hash) generation and the H*+1 fold
     * cursor, and verifying the SAME running executable that opened the start
     * session. This is what lets the contained full-history exporter admit a
     * producer THIS binary ran itself. Best-effort: a missing start session
     * (unstamped build) or an incomplete header corpus leaves no receipt, and
     * the exporter then correctly refuses (fail closed). */
    bool receipt_finalized = false;
    {
        char rc_err[256] = {0};
        if (!consensus_state_producer_receipt_finalize(pdb, anchor,
                                                       cp->block_hash, rc_err,
                                                       sizeof(rc_err)))
            LOG_WARN("mint_anchor",
                     "[mint-anchor] source receipt finalize skipped (artifact "
                     "verified; not exporter-admissible): %s", rc_err);
        else {
            receipt_finalized = true;
            fprintf(stderr,
                    "[mint-anchor] durable source receipt finalized at h=%d "
                    "(fold_cursor=%d) — exporter can now admit this producer\n",
                    anchor, anchor + 1);
        }
    }

    /* Producer-END part 2 (lane A1): emit the contained full-history
     * zcl.consensus_state_bundle.v1 into the datadir. The exporter's ONLY
     * viable caller is this in-process point (its proof binds the running
     * binary to the fold), so it runs here right after the receipt is
     * finalized. Only a FULL-validation mint yields a serving bundle; a
     * -mint-anchor-fast (checkpoint_fold) generation is non-serving by
     * construction and the exporter would correctly refuse it, so skip the
     * attempt for that profile rather than fail the one-shot. A skipped
     * finalize (unstamped build) has no receipt to export against. A real
     * export failure returns false so main.c's `minted ? 0 : 1` surfaces it to
     * systemd — the verified anchor snapshot + receipt stay intact regardless. */
    bool bundle_ok = true;
    if (receipt_finalized) {
        if (!mint_skip_crypto_get()) {
            /* Stamp the EARNED migration-complete + self-folded markers before
             * export. The checkpoint HARD-ASSERT above (_exit on mismatch)
             * proved this coins_kv reproduces the compiled checkpoint, so the
             * markers are earned here — and a fresh full-validation producer has
             * no other stamper. The exporter's proof refuses a source lacking
             * BOTH markers, so without this a full-validation bundle export
             * always refuses. Fail CLOSED: page + PERMANENT blocker + exit
             * non-zero, never an unearned marker on a non-agreement path. */
            if (!boot_mint_anchor_stamp_sovereign_markers(pdb)) {
                event_emitf(EV_OPERATOR_NEEDED, 0,
                            "condition=mint_bundle_export_failed "
                            "reason=marker_stamp anchor=%d", anchor);
                struct blocker_record frec;
                if (blocker_init(&frec, "mint_bundle.export_failed",
                                 "mint_anchor", BLOCKER_PERMANENT,
                                 "consensus-state authority markers "
                                 "(migration-complete + self-folded) could not "
                                 "be stamped after a checkpoint-matched mint; "
                                 "export cannot proceed on an unmarked source"))
                    (void)blocker_set(&frec);
                LOG_FAIL("mint_anchor",
                         "[mint-anchor] failed to stamp the earned "
                         "migration-complete/self-folded markers at h=%d — "
                         "refusing to export against an unproven source",
                         anchor);
            }
            bundle_ok = boot_mint_anchor_export_bundle(pdb, datadir, anchor,
                                                       cp->block_hash);
        } else
            fprintf(stderr,
                    "[mint-anchor] consensus-state bundle export skipped: "
                    "checkpoint-fold state is non-serving and not canonically "
                    "publishable (verified anchor snapshot produced)\n");
    }
    return bundle_ok;
}
