/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0.
 * purpose: Drive checkpoint-bound anchor minting and emit its verified snapshot. */
/* boot_mint_anchor.c — the ANCHOR-SET MINT driver. Contract in config/boot.h
 * (boot_mint_anchor_run). Separate from boot.c to keep one responsibility.
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
 *   (2) mint_anchor_progress (engine/composition/src/mint_anchor_progress.c) binds a
 *       checkpoint-scoped resume marker so boot_mint_anchor_reset SKIPS the
 *       genesis reset and resumes at coins_applied_height (see the "resuming
 *       existing checkpoint-bound fold" branch);
 *   (3) with -fold-inram, coins_ram flushes the in-RAM overlay to durable
 *       coins_kv every ZCL_FOLD_INRAM_FLUSH_EVERY blocks (default 50,000) and
 *       coins_ram_reconcile_boot rewinds the cursor to that flush watermark on
 *       the next boot, so a crash loses at most one flush window, not the fold.
 * The worst-case resume rewind is one flush window; lower
 * ZCL_FOLD_INRAM_FLUSH_EVERY to tighten it. */
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
#include "storage/event_log_singleton.h"        /* event_log_set_singleton */
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
 * first flush window and lags by up to a window afterwards. Returns -1 when nothing has been applied. */
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
/* consecutive no-progress kicks → walled */
static const int kStallLimit = 64;
/* Mutable state of the fold drive loop, shared by the per-round helpers. */
struct mint_drive_state {
    sqlite3 *pdb;
    struct chain_activation_controller *ctl;
    const char *progress_log;
    int64_t drive_start_us;
    int32_t anchor;
    int32_t last_through;
    int32_t last_durable;
    int stall_kicks;
    struct mint_rebuild_wait_state rebuild_wait;
    bool mint_sync_off;
    bool lookahead;
    bool wal_manual;
};
/* Fail-closed lookup of the compiled checkpoint: absence is fatal. */
static const struct sha3_utxo_checkpoint *mint_require_checkpoint(void)
{
    const struct sha3_utxo_checkpoint *cp = get_sha3_utxo_checkpoint();
    if (!cp) {
        fprintf(stderr, "FATAL: -mint-anchor: no compiled SHA3 UTXO checkpoint\n");
        event_emitf(EV_BOOT_VALIDATION_FAILED, 0,
                    "mint_anchor no_compiled_checkpoint");
        _exit(EXIT_FAILURE);
    }
    return cp;
}
/* Fail-closed lookup of the progress store and activation controller. */
static sqlite3 *mint_require_store(struct chain_activation_controller **ctl_out)
{
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
    *ctl_out = ctl;
    return pdb;
}
static uint8_t mint_receipt_profile(void)
{
    return mint_skip_crypto_get() ? CONSENSUS_STATE_VALIDATION_CHECKPOINT_FOLD
                                  : CONSENSUS_STATE_VALIDATION_FULL;
}
static void mint_receipt_opened_note(uint8_t profile)
{
    fprintf(stderr,
            "[mint-anchor] durable source receipt session opened "
            "(profile=%s)\n",
            profile == CONSENSUS_STATE_VALIDATION_FULL
                ? "full" : "checkpoint_fold");
}
static void mint_suppress_eventlog(void)
{
    /* Skip event_log emission during the offline mint: its only output
     * (utxo-anchor.snapshot) is built from coins_kv (progress.kv) + node.db
     * shielded state and never reads the event_log. Every fold-path emitter
     * routes through event_log_singleton() and is NULL-tolerant, so unwiring
     * the singleton suppresses all of them for the mint's duration.
     *
     * Env escapes keep emission on:
     *   ZCL_EVENTLOG_SYNC_PER_APPEND=1  (per-append-fsync baseline, emission ON)
     *   ZCL_MINT_KEEP_EVENTLOG=1        (emission ON, batched). */
    bool keep_eventlog = (getenv("ZCL_EVENTLOG_SYNC_PER_APPEND") != NULL) ||
                         (getenv("ZCL_MINT_KEEP_EVENTLOG") != NULL);
    if (!keep_eventlog) {
        event_log_set_singleton(NULL);
        fprintf(stderr,
                "[mint-anchor] S1.2: event_log emission suppressed for the fold "
                "(artifact reads coins_kv + shielded only)\n");
    }
}
static bool mint_progress_sync_off_begin(void)
{
    /* progress.kv synchronous=OFF for the fold's duration: the same IBD
     * durability trade the live sync path makes via
     * progress_store_set_sync_mode() from the supervisor tick, which does not
     * run in the offline mint. The crash-ordering
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
    return mint_sync_off;
}
static int32_t mint_initial_through(sqlite3 *pdb)
{
    int32_t last_through = mint_frontier_through();
    if (last_through < 0)
        last_through = mint_applied_through(pdb);  /* pre-init fallback */
    return last_through;
}
static bool mint_lookahead_start(void)
{
    bool lookahead = false;
    if (!mint_skip_crypto_get()) {
        lookahead = proof_validate_lookahead_start();
        fprintf(stderr, "[mint-anchor] proof lookahead %s\n",
                lookahead ? "started" : "unavailable — folding serially");
    }
    return lookahead;
}
/* Per-round WAL policy: switch to manual checkpointing once the overlay is
 * active, then TRUNCATE the WAL when a flush advanced the durable height. */
static void mint_drive_wal_policy(struct mint_drive_state *d)
{
    if (!d->wal_manual && coins_ram_active()) {
        mint_wal_autocheckpoint(d->pdb, 0);
        d->wal_manual = true;
        d->last_durable = mint_applied_through(d->pdb);
        fprintf(stderr,
                "[mint-anchor] S1.3+: WAL auto-checkpoint disabled; the WAL "
                "is TRUNCATEd at each overlay flush boundary\n");
    }
    /* A flush landed iff the durable applied-through advanced. */
    if (d->wal_manual) {
        int32_t durable_now = mint_applied_through(d->pdb);
        if (durable_now > d->last_durable) {
            (void)progress_store_checkpoint();
            d->last_durable = durable_now;
        }
    }
}
/* One drive round. Returns false when the fold is walled (state already
 * stopped and the blocker reported); the caller returns false. */
static bool mint_drive_round(struct mint_drive_state *d)
{
    /* Bounded drain chunk: returns within ZCL_MINT_KICK_BUDGET_MS (or at
     * the first frontier-stalled round) so THIS loop reliably regains
     * control to log progress and run the stall detector below. */
    (void)reducer_kick_unbudgeted(d->ctl);
    mint_drive_wal_policy(d);
    int32_t now = mint_frontier_through();
    /* Throttled on-disk progress (every ~5s) — readable while the fold
     * runs, regardless of the sparse stderr cadence below. */
    boot_mint_anchor_progress_log_tick(d->progress_log, now, d->anchor,
                                       d->drive_start_us, /*force=*/false);
    if (now > d->last_through) {
        d->last_through = now;
        d->stall_kicks = 0;
        d->rebuild_wait = (struct mint_rebuild_wait_state){0};
        if (boot_mint_anchor_should_log_progress(now, d->anchor))
            fprintf(stderr, "[mint-anchor] applied-through=%d / %d\n",
                    now, d->anchor);
    } else if (utxo_apply_sapling_rebuild_paused() &&
               mint_rebuild_wait_max_s() > 0) {
        /* NOT a stall — the deferred Sapling rebuild holds utxo_apply
         * paused on purpose. Hold the stall counter and nap; the fold
         * resumes by itself once the rebuild publishes its frontier. */
        if (boot_mint_anchor_drive_rebuild_wait(&d->rebuild_wait) ==
            MINT_REBUILD_WAIT_TIMEOUT) {
            mint_drive_stop(d->pdb, d->mint_sync_off, d->wal_manual,
                            d->lookahead);
            boot_mint_anchor_report_frontier_walled(d->pdb, now, d->anchor,
                                                    d->stall_kicks);
            return false;
        }
    } else if (++d->stall_kicks < kStallLimit) {
        /* No progress and nothing legitimately paused. Nap before the
         * next round so a slow warm-up does not exhaust the 64-kick
         * budget. */
        mint_drive_nap_ms(200);
    } else {
        /* Fail CLOSED with a named blocker: register
         * mint_fold.frontier_walled (all eight stage cursors in the
         * reason), page EV_OPERATOR_NEEDED, and print a diagnosis that
         * names the walled stage — "bodies incomplete" only when
         * body_fetch really is the wall. */
        mint_drive_stop(d->pdb, d->mint_sync_off, d->wal_manual, d->lookahead);
        boot_mint_anchor_report_frontier_walled(d->pdb, now, d->anchor,
                                                kStallLimit);
        return false;
    }
    return true;
}
/* Drive rounds until the fold frontier reaches the anchor; false = walled. */
static bool mint_drive_until_anchor(struct mint_drive_state *d)
{
    for (;;) {
        int32_t through = mint_frontier_through();
        if (through >= d->anchor)
            break;
        if (!mint_drive_round(d))
            return false;
    }
    return true;
}
static void mint_drive_leave(bool lookahead)
{
    if (lookahead)
        proof_validate_lookahead_stop();
    coins_ram_mint_drive_exit();
}
static void mint_anchor_out_path(char *out_path, size_t cap, const char *datadir)
{
    const char *env_out = getenv("ZCL_MINT_ANCHOR_OUT");
    if (env_out && env_out[0]) {
        snprintf(out_path, cap, "%s", env_out);
    } else {
        snprintf(out_path, cap, "%s/utxo-anchor.snapshot",
                 datadir ? datadir : ".");
    }
}
static void mint_collect_shielded_or_die(sqlite3 *pdb, int32_t anchor,
                                         struct snapshot_shielded *shielded)
{
    if (!snapshot_shielded_collect_from_db(pdb, anchor, shielded)) {
        fprintf(stderr,
                "FATAL: -mint-anchor: shielded-frontier collection at h=%d "
                "failed — refusing to emit a coins-only snapshot mislabeled "
                "shielded\n", anchor);
        event_emitf(EV_BOOT_VALIDATION_FAILED, 0,
                    "mint_anchor shielded_collect_failed h=%d", anchor);
        _exit(EXIT_FAILURE);
    }
}
static void mint_snapshot_write_or_die(sqlite3 *pdb, const char *out_path,
                                       int32_t anchor,
                                       const struct sha3_utxo_checkpoint *cp,
                                       struct snapshot_shielded *shielded,
                                       uint8_t got_sha3[32],
                                       uint64_t *got_count, int64_t *got_supply)
{
    if (!coins_kv_snapshot_write(pdb, out_path, anchor, cp->block_hash,
                                 shielded, got_sha3, got_count, got_supply)) {
        snapshot_shielded_free_collected(shielded);
        fprintf(stderr, "FATAL: -mint-anchor: snapshot write to %s failed\n",
                out_path);
        event_emitf(EV_BOOT_VALIDATION_FAILED, 0,
                    "mint_anchor snapshot_write_failed path=%s", out_path);
        _exit(EXIT_FAILURE);
    }
}
static void mint_coins_commitment_or_die(sqlite3 *pdb, uint8_t coins_sha3[32],
                                         int32_t anchor, const char *out_path)
{
    /* Coins-only commitment over the SAME effective set the writer streamed.
     * got_sha3 is the v3 BODY SHA3 (coins + shielded section), so it is NOT the
     * coins commitment the compiled checkpoint pins; compute that separately,
     * mirroring the writer's overlay predicate (coins_ram_active), so the value
     * covers any un-flushed in-RAM fold tail exactly as the writer did. */
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
}
static void mint_assert_checkpoint_match(const struct sha3_utxo_checkpoint *cp,
                                         const uint8_t coins_sha3[32],
                                         uint64_t got_count, int32_t anchor,
                                         const char *out_path)
{
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
}
static void mint_print_success(int32_t anchor, uint64_t got_count,
                               int64_t got_supply, const uint8_t coins_sha3[32],
                               const char *out_path)
{
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
}
static void mint_receipt_finalized_note(int32_t anchor)
{
    fprintf(stderr,
            "[mint-anchor] durable source receipt finalized at h=%d "
            "(fold_cursor=%d) — exporter can now admit this producer\n",
            anchor, anchor + 1);
}
/* Page and register the PERMANENT blocker for a failed marker stamp. */
static void mint_report_marker_stamp_failed(int32_t anchor)
{
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
}
static void mint_bundle_export_skipped_note(void)
{
    fprintf(stderr,
            "[mint-anchor] consensus-state bundle export skipped: "
            "checkpoint-fold state is non-serving and not canonically "
            "publishable (verified anchor snapshot produced)\n");
}
bool boot_mint_anchor_run(const char *datadir)
{
    const struct sha3_utxo_checkpoint *cp = mint_require_checkpoint();
    /* -full-fold (boot_full_fold.c) overrides the target to the local header TIP
     * and skips the checkpoint ceremony; disarmed → target == cp->height. */
    int32_t ff_target = -1;
    const bool full_fold = boot_full_fold_is_armed(&ff_target);
    const int32_t anchor = full_fold ? ff_target : cp->height;
    struct chain_activation_controller *ctl = NULL;
    sqlite3 *pdb = mint_require_store(&ctl);
    /* Producer-START ownership of the durable source receipt (see
     * config/consensus_state_producer_receipt.h): record the running executable
     * + source-identity claim and publish the source-epoch digest BEFORE the
     * fold, so every stamped stage row carries it — the binding the contained
     * full-history exporter's stage-row proof requires. Best-effort: a build
     * with no exact 64-hex source identity cannot earn a v2 receipt, but the
     * mint's primary artifact (the verified anchor snapshot) is still
     * produced. */
    {
        uint8_t profile = mint_receipt_profile();
        char rc_err[256] = {0};
        if (!consensus_state_producer_receipt_begin(pdb, profile, rc_err,
                                                    sizeof(rc_err)))
            LOG_WARN("mint_anchor",
                     "[mint-anchor] source receipt begin skipped (mint still "
                     "runs; artifact not exporter-admissible): %s", rc_err);
        else
            mint_receipt_opened_note(profile);
    }
    /* (1) Drive the fold to the anchor. reducer_kick_unbudgeted drains the same
     * eight-stage pipeline the supervisor uses, under the activation mutex (no
     * race with the background ticks) AND with the reducer-drive guard held so
     * the supervisor yields its 2s stage ticks for the whole drain. Unlike the
     * budgeted reducer_kick, each call folds back-to-back until convergence.
     * The header_admit ceiling (boot_mint_anchor_reset) caps the fold AT the anchor,
     * so the pipeline converges there and the kick returns 0 advances. We loop
     * until the utxo_apply frontier reaches the anchor; we also break on a
     * no-progress plateau so a bodies-missing datadir cannot spin forever (the
     * caller then reports the mint as incomplete, not a false anchor). */
    /* Progress metric: the IMMEDIATE utxo_apply stage frontier
     * (mint_frontier_through), NOT the durable coins_applied_height, which under
     * -fold-inram only moves at coins_ram flush boundaries. On resume the
     * stage cursor already reflects the durable resume point. */
    mint_suppress_eventlog();
    const bool mint_sync_off = mint_progress_sync_off_begin();
    struct mint_drive_state ds = { .pdb = pdb, .ctl = ctl, .anchor = anchor,
                                   .last_durable = -1,
                                   .mint_sync_off = mint_sync_off };
    ds.last_through = mint_initial_through(pdb);
    char progress_log[1200];
    boot_mint_anchor_progress_log_path(datadir, progress_log, sizeof(progress_log));
    ds.progress_log = progress_log;
    ds.drive_start_us = GetTimeMicros();
    fprintf(stderr,
            "[mint-anchor] driving the genesis..%d fold; "
            "starting at applied-through=%d; progress log -> %s\n",
            anchor, ds.last_through, progress_log);
    boot_mint_anchor_progress_log_tick(progress_log, ds.last_through, anchor,
                           ds.drive_start_us, /*force=*/true);
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
    ds.lookahead = mint_lookahead_start();
    /* WAL policy: once the overlay is the write path, hold auto-checkpoints off
     * and TRUNCATE the WAL at each overlay flush boundary (where the durable
     * coins_applied_height advances), bounding WAL growth without an fsync per
     * commit. SQLite default when the overlay is opted out (ZCL_FOLD_INRAM=0). */
    if (!mint_drive_until_anchor(&ds))
        return false;
    mint_drive_leave(ds.lookahead);
    int32_t through = mint_frontier_through();
    int64_t count = coins_kv_count(pdb);
    boot_mint_anchor_progress_log_tick(progress_log, through, anchor, ds.drive_start_us,
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
    if (ds.wal_manual) {
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
    mint_anchor_out_path(out_path, sizeof(out_path), datadir);
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
    mint_collect_shielded_or_die(pdb, anchor, &shielded);
    uint8_t got_sha3[32] = {0};
    uint64_t got_count = 0;
    int64_t  got_supply = 0;
    mint_snapshot_write_or_die(pdb, out_path, anchor, cp, &shielded, got_sha3,
                               &got_count, &got_supply);
    snapshot_shielded_free_collected(&shielded);
    uint8_t coins_sha3[32] = {0};
    mint_coins_commitment_or_die(pdb, coins_sha3, anchor, out_path);
    mint_assert_checkpoint_match(cp, coins_sha3, got_count, anchor, out_path);
    /* (3b) HARD-ASSERT the shielded keystone: anchors/nullifiers/frontier
     * folds == the compiled ROM state checkpoint (boot_mint_anchor_rom_keystone.c). */
    boot_mint_anchor_rom_keystone_assert(pdb, out_path);
    mint_print_success(anchor, got_count, got_supply, coins_sha3, out_path);
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
            mint_receipt_finalized_note(anchor);
        }
    }
    /* Producer-END part 2: emit the contained full-history
     * zcl.consensus_state_bundle.v1 into the datadir. The exporter's proof
     * binds the running binary to the fold, so this in-process point is its
     * only caller. Only a FULL-validation mint yields a serving bundle; a
     * -mint-anchor-fast (checkpoint_fold) generation is non-serving, so the
     * attempt is skipped for that profile. A skipped finalize (unstamped
     * build) has no receipt to export against. A real export failure returns
     * false so main.c's `minted ? 0 : 1` surfaces it; the verified anchor
     * snapshot + receipt stay intact regardless. */
    bool bundle_ok = true;
    if (receipt_finalized) {
        if (!mint_skip_crypto_get()) {
            /* Stamp the EARNED migration-complete + self-folded markers before
             * export. The checkpoint HARD-ASSERT above (_exit on mismatch)
             * proved this coins_kv reproduces the compiled checkpoint, so the
             * markers are earned here; a fresh full-validation producer has
             * no other stamper. The exporter's proof refuses a source lacking
             * BOTH markers. Fail CLOSED: page + PERMANENT blocker + exit
             * non-zero, never an unearned marker on a non-agreement path. */
            if (!boot_mint_anchor_stamp_sovereign_markers(pdb)) {
                mint_report_marker_stamp_failed(anchor);
                LOG_FAIL("mint_anchor",
                         "[mint-anchor] failed to stamp the earned "
                         "migration-complete/self-folded markers at h=%d — "
                         "refusing to export against an unproven source",
                         anchor);
            }
            bundle_ok = boot_mint_anchor_export_bundle(pdb, datadir, anchor,
                                                       cp->block_hash);
        } else
            mint_bundle_export_skipped_note();
    }
    return bundle_ok;
}
