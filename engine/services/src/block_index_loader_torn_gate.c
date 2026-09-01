/* Copyright 2026 Rhett Creighton - Apache License 2.0 */
// one-result-type-ok:torn-import-verdict-predicate — the single function here
// is a boolean VERDICT predicate (tear fires / does not). On a fire the
// actionable reason does NOT travel via a return code: it is published as a
// typed PERMANENT blocker ('seed.torn_import', owner='validation_pack') plus
// EV_OPERATOR_NEEDED naming the hole — exactly where an operator reads it. A
// struct zcl_result would bury that diagnostic in a discarded enum.
/*
 * Block Index Loader — (2a.5) BOOT-TIME TORN-IMPORT GATE.
 *
 * This file owns ONLY the durable forward-evidence torn-import verdict, kept
 * apart from the seed-loader plumbing in block_index_loader_rebuild.c so each
 * stays a readable, single-purpose TU. The seed loader calls
 * block_index_loader_torn_import_gate_fires() right before its forward-only
 * early-return.
 *
 * THE TEAR CLASS: a cold-import coin set matches the recorded count yet is
 * MISSING a canonical coinbase. The active chain spends it at the apply
 * frontier, so forward validation records a DURABLE `ok=0 prevout_unresolved`
 * row at the SPENDING block (== coins_applied_height), ABOVE seed H —
 * persistent proof the trusted base is torn.
 *
 * THE VERDICT FIRES ONLY WHEN ALL THREE HOLD (the durability guard):
 *   (1) hole_found && hole_h in (checkpoint, ceiling], ceiling = the
 *       FORWARD-APPLY frontier (coins_applied_height raised by the active
 *       chain height), NOT seed H — the hole can sit ABOVE H and a
 *       (checkpoint, H] window would miss it.
 *   (2) hole_status is 'prevout_unresolved' — EXCLUDE 'internal_error' (and
 *       every other class). script_validate persists status='internal_error'
 *       DURABLY (ok=0) for TRANSIENT, RESURRECTABLE infra failures (sapling-
 *       verification-ctx-init-failed / error-computing-signature-hash;
 *       script_validate_contextual.c:55-58,112-116), which the stale-script-
 *       hole repair re-attempts. Firing a PERMANENT wipe verdict on those
 *       would false-reject a HEALTHY node that hit a transient blip and
 *       rebooted before re-validation. 'block_decode_failed' is a FUTURE
 *       class, deliberately NOT accepted here: coin_backfill returns
 *       NOT_APPLICABLE for any lowest hole whose status != 'prevout_unresolved'
 *       (stage_repair_coin_backfill.c backfill_run G2 short-circuit), so it
 *       never reaches a refuse()
 *       and never persists the (3) marker — accepting it would be a dead
 *       branch that LOOKS covered but can never fire. Before this gate may
 *       accept block_decode_failed, coin_backfill must (a) handle decode-failed
 *       holes and (b) durably persist a terminal marker for that class.
 *   (3) coin_backfill has DURABLY REFUSED this hole as unprovable: the
 *       progress.kv meta key 'coin_backfill.refused.<h>.<holehash-hex>' is
 *       present. coin_backfill (the RUNTIME reducer self-heal stage) writes
 *       this row from persist_terminal_refusal() at every TERMINAL
 *       REFUSED_UNPROVABLE/REFUSED_SPENT verdict that carries a bound hole
 *       hash — the txindex_miss:v2 path (resolve_creator -> active-chain
 *       bounded fallback -> persist_terminal_refusal, guarded on node.db
 *       tx_index_complete>=3 so an in-progress IBD miss is never marked
 *       terminal), plus the corrupt creator_* classes, enumerate metadata-tear,
 *       round-cap, and the proven-spend write at stage_repair_coin_backfill.c.
 *       This is the
 *       DURABLE, COPY-PORTABLE proof the boot gate reads via
 *       coin_backfill_meta_present — NOT the in-memory, non-persisted blocker
 *       coin_backfill.unprovable.<h> (that is raised per-tick by the page latch
 *       and is gone on the next boot; the gate runs BEFORE coin_backfill ticks
 *       this boot, so it can ONLY rely on the durable row a PRIOR boot wrote).
 *       It is also the REFUSAL-LATENCY guard: an ok=0 prevout row coin_backfill
 *       has NOT yet durably refused is still being worked, so the gate WAITS
 *       rather than racing a not-yet-confirmed hole. internal_error is NEVER
 *       refused by coin_backfill (transient), so it never gets a marker.
 *
 * We deliberately do NOT require coin_backfill_owner_ack()
 * (env ZCL_REDUCER_COIN_BACKFILL_ACK): that ack gates DESTRUCTIVE coin_backfill
 * writes; THIS verdict is purely DIAGNOSTIC (refuse-to-bless + raise blocker +
 * EV_OPERATOR_NEEDED), so a per-process env requirement would (a) be wrong — a
 * fresh boot / copy-prove has no ack set — and (b) silently disable the
 * diagnosis. The refusal marker (3) is the durable, copy-portable proof; the
 * env is not.
 *
 * script_validate writes NO row for a not-yet-fetched body (JOB_IDLE;
 * script_validate_stage.c:401/409/425/435); an ok=0 prevout_unresolved /
 * block_decode_failed row exists ONLY after the body decoded and a prevout
 * genuinely failed (:267-285) or the body was undecodable (:230-234). A node
 * that has not reached the height has no row → strict no-op.
 *
 * A REFUSAL + typed PERMANENT blocker, NOT a heal/reconcile/backfill (no new
 * repair rung). Stamps NOTHING — H* stays pinned at the checkpoint; the VALUE
 * is a CLEAR actionable verdict naming the hole, not an opaque HOLD. */

#include "services/block_index_loader.h"
#include "validation/main_state.h"
#include "validation/chainstate.h"
#include "chain/chain.h"
#include "storage/progress_store.h"
#include "storage/coins_kv.h"
#include "core/uint256.h"
#include "event/event.h"

#include <sqlite3.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "util/log_macros.h"
#include "util/blocker.h"

/* The read-only progress.kv hole scanner + coin_backfill key builder live in
 * the jobs backfill-util TU
 * (engine/jobs/src/stage_repair_coin_backfill_util.h, private to the backfill
 * TUs) and are exported non-static. Forward-declare their EXACT signatures
 * here rather than dragging the private jobs header onto this services TU's
 * include path (which would trip the E3 shape-includes lint). The caller of
 * the scanner MUST hold progress_store_tx_lock (the _unlocked variant). See
 * stage_repair_coin_backfill_util.c:77/106/133. */
bool find_lowest_prevout_unresolved_hole_unlocked(
    struct sqlite3 *db, int cursor, const char *wanted_status, int *out_height,
    char status_out[32], struct uint256 *hash_out, bool *hash_found);
bool coin_backfill_refusal_marker_read(struct sqlite3 *db, int height,
                                       const struct uint256 *hash,
                                       bool *out_active,
                                       bool *out_legacy_spent,
                                       bool *out_legacy_txindex_miss);

/* PURE detect predicate: runs the EXACT three-condition durability
 * guard of the verdict below but with NO event/blocker side-effects, so the
 * boot from-anchor auto-arm can consult the SAME tear decision without paging
 * an operator. Contract in services/block_index_loader.h. Read-only on
 * progress.kv. */
bool block_index_loader_torn_import_detect(struct main_state *ms,
                                           struct sqlite3 *progress_db,
                                           int32_t checkpoint,
                                           int32_t *out_hole_h,
                                           int32_t *out_ceiling)
{
    if (out_hole_h)  *out_hole_h  = -1;
    if (out_ceiling) *out_ceiling = -1;
    if (!ms || !progress_db)
        return false;

    int32_t applied = 0;
    bool applied_found = false;
    int active_h = active_chain_height(&ms->chain_active);
    int hole_h = -1;
    char hole_status[32];
    struct uint256 hole_hash;
    bool hole_found = false;
    bool hole_hash_found = false;
    bool backfill_refused = false;

    progress_store_tx_lock();
    bool applied_read_ok =
        coins_kv_get_applied_height(progress_db, &applied, &applied_found);
    if (!applied_read_ok)
        LOG_WARN("torn_gate", "coins_applied_height read failed — torn-import "
                 "ceiling falls back to active_h=%d (read error, not "
                 "absent-key)", active_h);
    /* ceiling = the forward-apply frontier. coins_applied_height is the
     * NEXT-height cursor (applied-through B means value B+1), so it equals the
     * blocked height directly; raise by the active chain height so a hole
     * recorded by script_validate slightly ahead of the coins cursor is still
     * inside the window. Both are read-only forward frontiers. */
    int32_t ceiling = applied_found ? applied : 0;
    if (active_h > ceiling)
        ceiling = active_h;
    if (ceiling > checkpoint) {
        /* find_lowest_..._unlocked selects ok=0 rows with height < cursor;
         * cursor = ceiling+1 admits a hole AT the ceiling (the live spending
         * block == coins_applied_height). Scan for 'prevout_unresolved'
         * specifically so a lower transient internal_error never masks the
         * genuine tear that sits above it. One lock span (the lock is
         * recursive): the hole scan AND the refusal-marker read see a
         * consistent progress.kv snapshot. */
        (void)find_lowest_prevout_unresolved_hole_unlocked(
            progress_db, (int)ceiling + 1, "prevout_unresolved", &hole_h,
            hole_status, &hole_hash, &hole_hash_found);
        hole_found = (hole_h > 0);
        /* (3) require coin_backfill's durable refusal of THIS hole, keyed by
         * the hole's own (height, block_hash) in the repair_marker table — the
         * exact row the producer writes. A hole the helper could not hash-bind
         * (hole_hash_found false) cannot be matched to a refusal marker, so it
         * never fires. */
        if (hole_found && hole_hash_found) {
            bool legacy_spent = false;
            bool legacy_txindex_miss = false;
            (void)coin_backfill_refusal_marker_read(
                progress_db, hole_h, &hole_hash, &backfill_refused,
                &legacy_spent, &legacy_txindex_miss);
            if (legacy_spent || legacy_txindex_miss) {
                LOG_WARN("torn_gate",
                         "ignoring legacy coin_backfill refusal marker h=%d; "
                         "runtime repair must re-prove it", hole_h);
                backfill_refused = false;
            }
        }
    }
    progress_store_tx_unlock();

    /* (2) status filter: ONLY a durable prevout_unresolved tear fires.
     * 'internal_error' (transient) and 'block_decode_failed' (a FUTURE class
     * coin_backfill never refuses — see the rationale comment) are excluded. */
    bool hole_is_tear =
        hole_found && strcmp(hole_status, "prevout_unresolved") == 0;

    bool fires = hole_is_tear && backfill_refused &&
                 hole_h > checkpoint && hole_h <= (int)ceiling;
    if (out_hole_h)  *out_hole_h  = fires ? hole_h : -1;
    if (out_ceiling) *out_ceiling = ceiling;
    return fires;
}

bool block_index_loader_torn_import_gate_fires(struct main_state *ms,
                                               struct sqlite3 *progress_db,
                                               int32_t H, int32_t checkpoint)
{
    if (!ms || !progress_db)
        return false;

    int32_t hole_h = -1;
    int32_t ceiling = -1;
    if (!block_index_loader_torn_import_detect(ms, progress_db, checkpoint,
                                               &hole_h, &ceiling))
        return false;

    /* Self-contained reason < BLOCKER_REASON_MAX (256): the load-bearing
     * coordinates (h, frontier, seed H) plus a short ACTION token. The full
     * recovery recipe rides the EV_OPERATOR_NEEDED payload below (no cap). */
    char reason[BLOCKER_REASON_MAX];
    snprintf(reason, sizeof(reason),
             "torn cold-import coin set: durable unresolved prevout at h=%d "
             "(coin_backfill refused unprovable; frontier=%d seed H=%d). "
             "ACTION: wipe+re-import (two-step cold-sync)",
             hole_h, (int)ceiling, H);
    LOG_WARN("block_index", "cold-import seed REFUSED at H=%d: %s", H, reason);
    struct blocker_record rec;
    if (blocker_init(&rec, "seed.torn_import", "validation_pack",
                     BLOCKER_PERMANENT, reason) &&
        blocker_set(&rec) == 0)
        event_emitf(EV_OPERATOR_NEEDED, 0,
                    "check=seed.torn_import seed_h=%d first_hole_h=%d "
                    "ceiling=%d torn cold-import coin set: forward validation "
                    "found an unresolved prevout at h=%d (coin_backfill refused "
                    "it as unprovable; forward-apply frontier=%d, seed H=%d); "
                    "the imported trusted base is coin-incomplete. ACTION: wipe "
                    "~/.zclassic-c23 and re-import with the two-step cold-sync "
                    "recipe (--importblockindex then a normal boot)",
                    H, hole_h, (int)ceiling, hole_h, (int)ceiling, H);
    return true;
}
