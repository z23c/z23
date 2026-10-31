/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * boot_full_fold.c — the -full-fold (GENESIS-FOLD-TO-TIP) boot mode.
 *
 * -full-fold reuses the entire -mint-anchor OFFLINE driver (engine/composition/src/
 * boot_mint_anchor.c: genesis reset OR resume, reducer_kick_unbudgeted self-
 * drive over on-disk BODIES, no P2P/services) but folds toward the LOCAL HEADER
 * TIP instead of the compiled SHA3 checkpoint, and skips the terminal checkpoint
 * snapshot/assert/export ceremony (there is no baked checkpoint at the tip).
 *
 * It composes the three defects a plain -fold-inram normal boot hits:
 *   A  legacy UTXO seed  — boot_mint_anchor_genesis_reset neutralizes the
 *      cold-import LevelDB seed and clears coins_kv; the fold builds the set from
 *      genesis. (The narrower -nolegacyutxoimport flag, implied by -full-fold,
 *      also skips the boot.c LDB import while KEEPING the ~/.zclassic body link.)
 *   B  premature at_tip promote — this runs on the offline mint path (boot.c
 *      skips the normal restore/promote ladder + all services for
 *      ctx->mint_anchor), so nothing promotes the header tip to coins_best /
 *      tip_finalize. The header tip is the fold TARGET (ceiling), not the coins
 *      tip.
 *   C  P2P-triggered drain — the fold is driven by boot_mint_anchor_run's
 *      reducer_kick_unbudgeted self-drive over local HAVE_DATA bodies, no P2P.
 *
 * The driver override (arm/is_armed) is read by boot_mint_anchor_run to pick the
 * tip target and skip the ceremony. The reset (ceiling + arm + optional genesis
 * reset) runs at the boot.c mint-anchor reset site when ctx->full_fold. */

#include "config/boot.h"
#include "config/boot_internal.h"        /* boot_mint_anchor_genesis_reset,
                                          * boot_full_fold_arm/reset decls */

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>          /* getenv, EXIT_FAILURE */
#include <string.h>          /* memcmp */
#include <unistd.h>          /* _exit */
#include <sqlite3.h>

#include "models/database.h"             /* struct node_db, node_db_prepare_readonly_query */
#include "models/block.h"                /* struct db_block, db_block_find_by_height */
#include "jobs/mint_skip_crypto.h"       /* mint_skip_crypto_get */
#include "config/consensus_state_producer_receipt.h"
#include "storage/progress_store.h"      /* progress_store_db */
#include "storage/coins_kv.h"            /* coins_kv_get_applied_height */
#include "jobs/mint_fold_ceiling.h"      /* mint_fold_ceiling_set */
#include "jobs/refold_progress.h"        /* refold_progress_mark_started */
#include "jobs/reducer_frontier.h"       /* reducer_frontier_compute_hstar */
#include "jobs/tip_finalize_stage.h"     /* tip_finalize_stage_set_authoritative_tip */
#include "jobs/utxo_apply_stage.h"       /* utxo_apply_stage_succeeded_at */
#include "jobs/stage_helpers.h"          /* stage_cursor_persisted */
#include "services/chain_activation_service.h" /* reducer_kick_unbudgeted */
#include "storage/coins_ram.h"           /* coins_ram_flush_final */
#include "validation/main_state.h"       /* struct main_state */
#include "event/event.h"                 /* event_emitf, EV_BOOT_VALIDATION_FAILED */
#include "util/ar_step_readonly.h"       /* AR_STEP_ROW_READONLY */
#include "util/log_macros.h"

/* ── Driver override, consumed by boot_mint_anchor_run ────────────────────
 * When armed, the mint driver folds toward g_full_fold_target (the header tip)
 * instead of the compiled SHA3 checkpoint and returns success at the target
 * WITHOUT the checkpoint ceremony. Disarmed by default → a plain -mint-anchor
 * run is byte-for-byte unchanged. Set once on the boot thread before the offline
 * driver runs; read on the same thread. */
static bool    g_full_fold_armed  = false;
static int32_t g_full_fold_target = -1;
/* The boot-time node.db handle, stashed by boot_full_fold_reset so the
 * terminal export can resolve the header hash at the fold target (the same
 * blocks projection the checkpoint-pinned exporter reads). Same process,
 * same open handle — boot keeps it open through main.c's mint call. */
static struct node_db *g_ff_ndb   = NULL;

void boot_full_fold_arm(int32_t tip_target)
{
    g_full_fold_armed  = true;
    g_full_fold_target = tip_target;
}

bool boot_full_fold_is_armed(int32_t *out_target)
{
    if (out_target)
        *out_target = g_full_fold_target;
    return g_full_fold_armed;
}

/* Terminal verdict for a -full-fold run, called by boot_mint_anchor_run after
 * the drive loop + durability restore, IN PLACE OF the checkpoint ceremony. The
 * fold reached the local header TIP with COMPLETE self-derived shielded state
 * (anchors + nullifiers folded by the real stages, no gap). Reports the terminal
 * H*; if the frontier stopped short of the tip (e.g. a missing body), names the
 * walled stage via the shared typed-blocker reporter. Returns true iff reached. */
bool boot_full_fold_finish(sqlite3 *pdb, int32_t through, int64_t count,
                           int32_t target, int stall_limit)
{
    bool reached = through >= target;
    fprintf(stderr,
            "[full-fold] fold %s the tip target h=%d: applied-through=%d, "
            "coins_kv count=%lld — complete self-derived shielded state, no "
            "checkpoint ceremony\n",
            reached ? "REACHED" : "STOPPED SHORT OF", target, through,
            (long long)count);
    if (!reached)
        boot_mint_anchor_report_frontier_walled(pdb, through, target,
                                                stall_limit);
    return reached;
}

/* One-shot tip-height consensus-state bundle export, called by
 * boot_mint_anchor_run when a -full-fold run REACHED the local header tip
 * under FULL validation. The checkpoint mint's terminal ceremony is bound to
 * cp->height/cp->block_hash; this is the same producer-END sequence — receipt
 * finalize, earned sovereign markers, bundle export — bound to the header TIP
 * the fold actually reached, so a -full-fold producer doubles as a cold-start
 * weld artifact factory. The receipt's running-binary binding makes this
 * callable ONLY by the binary that ran the fold, and the export proof
 * (consensus_export_prove_source) re-verifies the frozen source at the target
 * (coins applied height, genesis-complete cursors, contiguous stamped stage
 * rows, FULL profile, H* == target) and refuses anything short — fail closed:
 * a refusal leaves no file and names a PERMANENT blocker. Returns false on any
 * refusal so main.c's minted ? 0 : 1 surfaces the failure. */
bool boot_full_fold_export_bundle(sqlite3 *pdb, const char *datadir,
                                  int32_t target)
{
    if (!pdb || target <= 0)
        LOG_FAIL("full_fold",
                 "[full-fold] bundle export: bad args pdb=%p target=%d",
                 (void *)pdb, target);

    /* The PoW anchor the receipt + bundle bind to: the header THIS node holds
     * at the fold target, from the same blocks projection the checkpoint-
     * pinned exporter reads (db_block_find_by_height; internal byte order —
     * the export request copies it verbatim). */
    struct db_block blk;
    if (!g_ff_ndb || !db_block_find_by_height(g_ff_ndb, target, &blk)) {
        fprintf(stderr,
                "[full-fold] bundle export REFUSED: no header row at the fold "
                "target h=%d (import the header chain first)\n", target);
        LOG_FAIL("full_fold",
                 "[full-fold] bundle export: header row missing at target "
                 "h=%d", target);
    }

    /* Producer-END ownership: finalize the durable source receipt at
     * (target, tip hash). Same call the checkpoint mint makes; fails closed if
     * the running executable is not the receipt-session opener. */
    char rc_err[256] = {0};
    if (!consensus_state_producer_receipt_finalize(pdb, target, blk.hash,
                                                   rc_err, sizeof rc_err)) {
        fprintf(stderr,
                "[full-fold] source receipt finalize FAILED at h=%d: %s — "
                "bundle export cannot proceed on an unreceipted fold\n",
                target, rc_err);
        LOG_FAIL("full_fold",
                 "[full-fold] source receipt finalize failed at h=%d: %s",
                 target, rc_err);
    }
    fprintf(stderr,
            "[full-fold] durable source receipt finalized at h=%d "
            "(fold_cursor=%d) — exporting the tip-height consensus-state "
            "bundle\n", target, target + 1);

    /* The markers are EARNED here by construction: this process self-folded
     * the complete genesis..target history under FULL validation, and the
     * export proof re-checks the stamped stage-row prefix before admitting
     * the bundle. The exporter requires BOTH markers on the source; without
     * them a fresh full-validation producer's export always refuses. */
    if (!boot_mint_anchor_stamp_sovereign_markers(pdb)) {
        fprintf(stderr,
                "[full-fold] sovereign marker stamp FAILED at h=%d — refusing "
                "to export against an unmarked source\n", target);
        LOG_FAIL("full_fold",
                 "[full-fold] sovereign marker stamp failed at h=%d", target);
    }

    return boot_mint_anchor_export_bundle(pdb, datadir, target, blk.hash);
}

/* H* read under the progress-store lock (the frontier walk's contract). */
static bool full_fold_read_hstar(sqlite3 *pdb, int32_t *hstar)
{
    int32_t served_floor = 0;
    progress_store_tx_lock();
    bool ok = reducer_frontier_compute_hstar(pdb, hstar, &served_floor);
    progress_store_tx_unlock();
    return ok;
}

/* True iff the ONLY thing holding H* at target-1 is tip_finalize's missing
 * lookahead witness for the target: every upstream stage cursor already covers
 * the target (next-height cursors >= target+1), utxo_apply verifiably folded
 * the target block, and the finalized tip_finalize row at target-1 exists and
 * names THIS header hash as its successor witness. Anything else (a lagging
 * upstream stage, a hash mismatch, a missing row) is a real defect the trusted
 * tip must never paper over. */
static bool full_fold_upstream_covers_target(sqlite3 *pdb, int32_t target)
{
    /* {stage cursor, success-checked log table or NULL}. Mirrors the H*
     * stage set (reducer_frontier k_logs) plus the two log-less stages. */
    static const struct { const char *stage; const char *log; } upstream[7] = {
        { "header_admit", NULL }, { "validate_headers", "validate_headers_log" },
        { "body_fetch", NULL }, { "body_persist", "body_persist_log" },
        { "script_validate", "script_validate_log" },
        { "proof_validate", "proof_validate_log" },
        { "utxo_apply", "utxo_apply_log" } };
    for (int i = 0; i < 7; i++) {
        /* Log-backed stages: the SAME contiguous ok=1 prefix walk H* uses
         * must reach the target (a cursor alone proves nothing). The two
         * log-less stages (header_admit, body_fetch) keep the cursor test. */
        const char *log_table = upstream[i].log;
        if (!log_table) {
            if (stage_cursor_persisted(pdb, upstream[i].stage, "full_fold") <
                (uint64_t)target + 1) {
                fprintf(stderr, "[full-fold] trailing drain: stage %s cursor "
                        "short of target h=%d\n", upstream[i].stage, target);
                return false;
            }
            continue;
        }
        int32_t contig = -1;
        if (!reducer_frontier_log_frontier(pdb, log_table, upstream[i].stage,
                                           &contig))
            LOG_FAIL("full_fold", "[full-fold] trailing drain: %s contiguity "
                     "read failed", log_table);
        if (contig < target) {
            fprintf(stderr, "[full-fold] trailing drain: %s ok=1 rows reach "
                    "h=%d only, target h=%d\n", log_table, contig, target);
            return false;
        }
    }
    return true;
}

static bool full_fold_gap_is_lookahead_only(sqlite3 *pdb, int32_t target,
                                            const uint8_t target_hash[32])
{
    if (!full_fold_upstream_covers_target(pdb, target) ||
        !utxo_apply_stage_succeeded_at(target))
        return false;

    /* tip_finalize: the row at target-1 must be a genuine finalized ok=1 row
     * (not an anchor, not a failure) naming THIS header as its witness, and
     * NO row may exist at the target yet — a drain only fills an absent row
     * and never replaces a recorded one (a failed row stays a failure). */
    struct tip_finalize_row_probe prev, own;
    if (!tip_finalize_stage_row_probe(pdb, target - 1, &prev) ||
        !tip_finalize_stage_row_probe(pdb, target, &own))
        LOG_FAIL("full_fold", "[full-fold] trailing drain: tip_finalize row "
                 "read failed near target h=%d", target);
    if (!prev.found || !prev.ok || !prev.is_finalized || !prev.has_hash ||
        memcmp(prev.hash, target_hash, 32) != 0) {
        fprintf(stderr, "[full-fold] trailing drain: no finalized ok=1 "
                "tip_finalize row at h=%d naming the target\n", target - 1);
        return false;
    }
    if (own.found) {
        fprintf(stderr, "[full-fold] trailing drain: tip_finalize row already "
                "present at target h=%d — not overwriting\n", target);
        return false;
    }
    return true;
}

/* Drive the trailing tip_finalize stage to the fold target before the tip
 * bundle export.
 *
 * WHY IT TRAILS. The mint drive loop stops the instant utxo_apply's cursor
 * reaches the target, but tip_finalize is the LAST stage and finalizes height
 * N only with N+1 as its canonicity witness (one-block lookahead; its log row
 * at N carries hash(N+1)). So when utxo_apply lands on the target, the
 * tip_finalize_log is contiguous only to target-1 and H* (the MIN over the
 * success-checked logs) reads target-1, while the export proof
 * (export_check_generation) requires H* == target exactly. The target block
 * itself has no successor under the fold ceiling, so no amount of stage
 * stepping can write its finalized row.
 *
 * THE DRAIN. (1) Kick the reducer until it converges, so every trailing stage
 * folds whatever its lookahead allows. (2) If H* is then exactly one short of
 * the target and utxo_apply verifiably folded the target block, publish the
 * target as the trusted tip with its header hash — the same authority anchor
 * the at-tip regtest follower and the clean-restart restore use — after
 * flushing the coins overlay (the authority write is coin-frontier guarded on
 * the DURABLE applied height). export_check_generation is untouched: anything
 * short of H* == target still refuses there. Called inside the mint drive
 * bracket, before the drive is left. Returns true iff H* == target. */
bool boot_full_fold_drain_trailing(struct chain_activation_controller *ctl,
                                   sqlite3 *pdb, int32_t target,
                                   const uint8_t target_hash[32])
{
    if (!ctl || !pdb || target <= 0 || !target_hash)
        LOG_FAIL("full_fold", "[full-fold] drain trailing: bad args");

    /* Bounded: a converged reducer returns 0 advances immediately. */
    for (int round = 0; round < 64; round++)
        if (reducer_kick_unbudgeted(ctl) == 0)
            break;

    int32_t hstar = -1;
    if (!full_fold_read_hstar(pdb, &hstar))
        LOG_FAIL("full_fold", "[full-fold] drain trailing: H* read failed");
    if (hstar == target)
        return true;
    if (hstar != target - 1 ||
        !full_fold_gap_is_lookahead_only(pdb, target, target_hash)) {
        fprintf(stderr,
                "[full-fold] trailing drain: H*=%d short of target h=%d and "
                "not the lookahead-only gap — not publishing the tip\n",
                hstar, target);
        return false;
    }
    if (coins_ram_active() && !coins_ram_flush_final())
        LOG_FAIL("full_fold",
                 "[full-fold] drain trailing: coins overlay flush failed");
    tip_finalize_stage_set_authoritative_tip(target, target_hash);
    if (!full_fold_read_hstar(pdb, &hstar))
        LOG_FAIL("full_fold", "[full-fold] drain trailing: H* re-read failed");
    fprintf(stderr,
            "[full-fold] trailing drain: tip_finalize published the fold "
            "target h=%d as the trusted tip (lookahead-only gap); H*=%d\n",
            target, hstar);
    return hstar == target;
}

/* Resolve the header hash at the fold target and drain (see above). Called by
 * boot_mint_anchor_run for a -full-fold run that will export. */
bool boot_full_fold_drain_for_export(struct chain_activation_controller *ctl,
                                     sqlite3 *pdb, int32_t target)
{
    struct db_block blk;
    if (!g_ff_ndb || !db_block_find_by_height(g_ff_ndb, target, &blk))
        LOG_FAIL("full_fold",
                 "[full-fold] drain trailing: no header row at target h=%d",
                 target);
    return boot_full_fold_drain_trailing(ctl, pdb, target, blk.hash);
}

/* The -full-fold terminal path, called by boot_mint_anchor_run in place of the
 * checkpoint ceremony: the H* verdict, then — on REACHED under FULL validation
 * — the tip-height bundle export. A checkpoint_fold-profile (-mint-anchor-fast)
 * fold is non-serving by construction; skip the export exactly like the
 * checkpoint mint. An export refusal fails the run (main.c: minted ? 0 : 1). */
bool boot_full_fold_conclude(sqlite3 *pdb, const char *datadir,
                             int32_t through, int64_t count, int32_t target,
                             int stall_limit)
{
    const bool reached =
        boot_full_fold_finish(pdb, through, count, target, stall_limit);
    if (reached && !mint_skip_crypto_get() &&
        !boot_full_fold_export_bundle(pdb, datadir, target))
        return false;   /* the refusal is already event+blocker loud */
    return reached;
}

/* Highest block height present in node.db's `blocks` table (the imported header
 * tip). Returns -1 if unavailable. This is the -full-fold ceiling: header_admit
 * admits up to it and the pipeline converges there; if a body is missing below
 * it, body_fetch walls with a typed blocker naming the exact height (fail loud,
 * never a silent short stop). */
static int32_t full_fold_header_tip_height(struct node_db *ndb)
{
    sqlite3_stmt *stmt = NULL;
    if (!node_db_prepare_readonly_query(ndb,
            "SELECT MAX(height) FROM blocks", &stmt))
        return -1;
    int32_t tip = -1;
    if (AR_STEP_ROW_READONLY(stmt) == SQLITE_ROW &&
        sqlite3_column_type(stmt, 0) != SQLITE_NULL)
        tip = (int32_t)sqlite3_column_int(stmt, 0);
    sqlite3_finalize(stmt);
    return tip;
}

bool boot_full_fold_resolve_target(int32_t header_tip, int32_t requested_target,
                                   int32_t *out_target)
{
    if (requested_target <= 0) {
        /* No pin: the historical -full-fold behavior — arm at the header
         * tip. */
        if (out_target)
            *out_target = header_tip;
        return true;
    }
    if (requested_target > header_tip)
        return false;   /* fail closed: never silently clamp to the tip */
    if (out_target)
        *out_target = requested_target;
    return true;
}

void boot_full_fold_reset(struct node_db *ndb, struct main_state *state,
                          int32_t requested_target)
{
    (void)state;
    g_ff_ndb = ndb;
    sqlite3 *rpdb = progress_store_db();
    if (!rpdb) {
        fprintf(stderr, "FATAL: -full-fold: progress store not open\n");
        event_emitf(EV_BOOT_VALIDATION_FAILED, 0,
                    "full_fold progress_store_not_open");
        _exit(EXIT_FAILURE);
    }

    int32_t header_tip = full_fold_header_tip_height(ndb);
    if (header_tip <= 0) {
        fprintf(stderr,
                "FATAL: -full-fold: node.db `blocks` has no header tip — run "
                "`--importblockindex <zclassicd-datadir> <datadir>/node.db` "
                "first so there is a header chain to fold toward\n");
        event_emitf(EV_BOOT_VALIDATION_FAILED, 0, "full_fold no_header_tip");
        _exit(EXIT_FAILURE);
    }

    int32_t tip = -1;
    if (!boot_full_fold_resolve_target(header_tip, requested_target, &tip)) {
        fprintf(stderr,
                "[full-fold] refusing: -full-fold-target=%d is above the "
                "local header tip h=%d\n", requested_target, header_tip);
        event_emitf(EV_BOOT_VALIDATION_FAILED, 0,
                    "full_fold target_above_header_tip");
        _exit(EXIT_FAILURE);
    }
    if (requested_target > 0)
        fprintf(stderr,
                "[full-fold] target pinned to h=%d (local header tip h=%d)\n",
                tip, header_tip);

    /* Resume decision: continue from the durable applied height unless the
     * datadir is fresh (applied <= genesis) or a genesis re-fold is forced. The
     * reducer fold is a valid prefix by construction, so a resume is sound. */
    int32_t applied = -1;
    bool applied_found = false;
    (void)coins_kv_get_applied_height(rpdb, &applied, &applied_found);
    bool force_genesis = getenv("ZCL_FULL_FOLD_FROM_GENESIS") != NULL;
    bool resume = !force_genesis && applied_found && applied > 1;

    if (resume) {
        fprintf(stderr,
                "[full-fold] RESUMING the genesis fold at durable "
                "applied-height=%d toward the fold target h=%d; NOT resetting "
                "to genesis (the reducer fold is a valid prefix)\n",
                applied, tip);
    } else {
        if (!boot_mint_anchor_genesis_reset(ndb)) {
            fprintf(stderr,
                    "FATAL: -full-fold: genesis reset did not complete; refusing "
                    "to drive a partial state\n");
            event_emitf(EV_BOOT_VALIDATION_FAILED, 0,
                        "full_fold genesis_reset_failed");
            _exit(EXIT_FAILURE);
        }
        fprintf(stderr,
                "[full-fold] reset to genesis; fold TARGET = h=%d (all eight "
                "stages fold genesis..target over on-disk bodies; H* climbs "
                "as the logs fill — complete self-derived shielded state, no "
                "borrowed snapshot)\n", tip);
    }

    /* Cap header_admit at the resolved target so the whole pipeline converges
     * there, and arm the mint driver's full-fold override (skip the
     * ceremony). */
    mint_fold_ceiling_set(tip);
    boot_full_fold_arm(tip);

    /* Suspend the below-cursor self-repair while the prefix (re-)folds, and set
     * the L0 floor so it matches where the fold actually starts:
     *   - from GENESIS: floor 0 (refold_progress_mark_started).
     *   - RESUME from a durable applied height (a partial from-genesis fold OR a
     *     checkpoint-seeded state): floor at `applied`. Dropping the floor to 0
     *     on a seeded resume would make utxo_apply try to fold from height 0 and
     *     stall on the absent below-anchor *_log rows, so hold it at the anchor
     *     (refold_progress_mark_started_from_anchor). */
    if (resume)
        (void)refold_progress_mark_started_from_anchor(rpdb, applied);
    else
        (void)refold_progress_mark_started(rpdb);
}
