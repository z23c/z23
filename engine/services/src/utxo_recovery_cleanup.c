// one-result-type-ok:utxo-count-return — utxo_recovery_clean_above_tip
// returns int (count of UTXOs deleted, 0 if refused or none found), the same
// established contract it carried before this file was split out of
// utxo_recovery_service.c (E1 800-line ceiling); callers (engine/composition/src/boot.c,
// the orphan_utxo_above_tip Condition) key off the count, not an ok/fail
// verdict, and struct zcl_result would only wrap that same integer. The
// static helper utxo_recovery_query_rewind_overshoot is a void diagnostic
// read with no failure path (see its own doc comment) — nothing here needs
// struct zcl_result.

/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * UTXO cleanup — the boot-time "delete node.db `utxos` rows above the
 * active chain tip" repair, split out of utxo_recovery_service.c to keep
 * that file under the app/ 800-line file-size ceiling (E1). Shares the
 * guarded rewind primitive (coins_rewind_above_tip, engine/modules/storage) with the
 * continuous orphan_utxo_above_tip Condition and the stale-cursor repair in
 * utxo_recovery_stale_cursor.c.
 *
 * SAFETY: a single-block overshoot of <= UTXO_BOOT_REWIND_MAX_ROWS (32) rows
 * is always auto-healable. A LARGER overshoot is also auto-healed, UNGUARDED,
 * when it is provably MIRROR-ONLY: the kernel coins_kv store is the proven
 * authority (coins_kv_is_proven_authority) AND its own durable
 * applied-height-derived coins-best (coins_applied_height - 1) matches tip_h
 * exactly — i.e. the kernel itself holds nothing above the cursor, so every
 * row above tip lives solely in the node.db `utxos` mirror, a derived
 * projection consensus reads never depend on (utxo_mirror_sync_service.h).
 * Any other overshoot shape (legacy/non-canonical datadir, or the kernel's
 * OWN derived height disagreeing with tip_h) is refused and raises the
 * PERMANENT UTXO_RECOVERY_REWIND_OVERSHOOT_BLOCKER_ID — genuine
 * block_index/coins drift that stays owner-investigated. */

#include "services/utxo_recovery_service.h"

#include "chain/chain.h"           /* block_index */
#include "event/event.h"
#include "models/database.h"       /* struct node_db */
#include "storage/coins_kv.h"      /* coins_kv_is_proven_authority */
#include "storage/coins_view_sqlite.h" /* coins_rewind_above_tip */
#include "storage/progress_store.h"    /* progress_store_db */
#include "validation/main_state.h" /* struct main_state, active_chain_tip */

#include <sqlite3.h>
#include <stdio.h>

#include "util/ar_step_readonly.h"
#include "util/blocker.h"
#include "util/log_macros.h"

#include "utxo_recovery_internal.h" /* UTXO_BOOT_REWIND_MAX_ROWS */

/* Read-only re-query of the exact predicate coins_rewind_above_tip's guard
 * evaluates internally (engine/modules/storage/src/coins_view_sqlite.c), used ONLY to
 * populate the typed blocker's structured fields after a refusal — never to
 * decide anything (the guard already ran and refused before this is called).
 * Leaves out_rows and out_max_height at -1 (unknown) on any read failure so
 * the blocker reason can say so rather than claim a fabricated 0. */
static void utxo_recovery_query_rewind_overshoot(sqlite3 *db,
                                                  int64_t tip_height,
                                                  int64_t *out_rows,
                                                  int64_t *out_max_height)
{
    *out_rows = -1;
    *out_max_height = -1;
    if (!db)
        return;

    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(db,
            "SELECT COUNT(*), COALESCE(MAX(height),0) "
            "FROM utxos WHERE height > ?",
            -1, &stmt, NULL) != SQLITE_OK) {
        LOG_WARN("utxo_recovery",
            "rewind_overshoot: count prepare failed: %s",
            sqlite3_errmsg(db));
        return;
    }
    sqlite3_bind_int64(stmt, 1, tip_height);
    if (AR_STEP_ROW_READONLY(stmt) == SQLITE_ROW) {
        *out_rows = sqlite3_column_int64(stmt, 0);
        *out_max_height = sqlite3_column_int64(stmt, 1);
    }
    sqlite3_finalize(stmt);
}

int utxo_recovery_clean_above_tip(struct node_db *ndb,
                                   struct main_state *state)
{
    if (!ndb || !state || !ndb->open)
        return 0;

    struct block_index *tip = active_chain_tip(&state->chain_active);
    int tip_h = tip ? tip->nHeight : 0;
    if (tip_h <= 0) return 0;

    int deleted_total = coins_rewind_above_tip(
        ndb->db, tip_h, UTXO_BOOT_REWIND_MAX_ROWS);
    if (deleted_total == 0) {
        /* Nothing above tip: whatever tripped the guard on a prior pass (if
         * any) is gone — resolve the typed blocker. No-op if it was never
         * set. */
        blocker_clear(UTXO_RECOVERY_REWIND_OVERSHOOT_BLOCKER_ID);
        return 0;
    }
    if (deleted_total < 0) {
        /* MIRROR-ONLY overshoot: node.db `utxos` is a derived, rebuildable
         * read-model projection (utxo_mirror_sync_service.h) consensus reads
         * never depend on. When the kernel coins_kv store is the PROVEN
         * authority (coins_kv_is_proven_authority) AND its own durable
         * applied-height-derived coins-best (applied_height - 1) matches
         * tip_h EXACTLY (the kernel itself holds nothing above the cursor),
         * the overshoot above lives ENTIRELY in the mirror: an unguarded
         * purge here never touches kernel coins/anchors/nullifiers, so the
         * 32-row/single-block guard above (sized for legacy-datadir crash
         * recovery, where the mirror IS the authority) does not need to
         * apply. Deliberately NOT reducer_frontier_derive_coins_best_now:
         * that helper also cross-checks a hash witness against
         * validate_headers_log/tip_finalize_log and hard-fails the whole
         * height derivation on any read error from either — including
         * "table does not exist", which is a legitimate shape early in boot
         * or on a coins_kv-only store. A pure height check needs no hash
         * witness at all. Any other shape — kernel not proven-authority, or
         * the kernel's OWN derived height disagreeing with tip_h — falls
         * through to the guarded refusal below; that is genuine
         * block_index/coins drift and stays owner-investigated. */
        int32_t kernel_applied = -1;
        bool kernel_proven = coins_kv_is_proven_authority(
            progress_store_db(), &kernel_applied);
        int32_t kernel_h = kernel_applied - 1;
        bool mirror_only_overshoot = kernel_proven && kernel_h == tip_h;
        if (mirror_only_overshoot) {
            int healed = coins_rewind_above_tip(ndb->db, tip_h, -1);
            if (healed > 0) {
                LOG_WARN("utxo_recovery",
                    "utxo_recovery: mirror-only overshoot above tip h=%d "
                    "self-healed (rows=%d) — kernel coins_kv derived "
                    "coins-best h=%d matches tip exactly; node.db `utxos` "
                    "carries no consensus weight (utxo_mirror_sync_service.h)",
                    tip_h, healed, kernel_h);
                event_emitf(EV_RECOVERY_ACTION, 0,
                    "action=utxo_mirror_purge_above_tip height=%d count=%d "
                    "mirror_only=1", tip_h, healed);
                blocker_clear(UTXO_RECOVERY_REWIND_OVERSHOOT_BLOCKER_ID);
                return healed;
            }
            LOG_WARN("utxo_recovery",
                "utxo_recovery: mirror-only overshoot above tip h=%d "
                "detected (kernel coins-best h=%d) but the unguarded purge "
                "returned %d — falling through to the guarded refusal path",
                tip_h, kernel_h, healed);
        }

        LOG_WARN("chain", "ABORT: refusing or failing boot UTXO rewind above tip h=%d " "(guard=%d). Only a single-block overshoot with a bounded row " "count is auto-healable; investigate block_index/coins drift.", tip_h, UTXO_BOOT_REWIND_MAX_ROWS);
        event_emitf(EV_BOOT_VALIDATION_FAILED, 0,
            "wipe_blocked tip=%d guard=%d",
            tip_h, UTXO_BOOT_REWIND_MAX_ROWS);

        /* Advance-or-named-blocker law: this refusal is a no-op an operator
         * must investigate, not just a log line that scrolls away. Register
         * a typed, dumpstate-visible blocker (dumpstate blocker / zcl_state
         * subsystem=blocker) carrying the guard's own numbers. Semantics are
         * unchanged — the refusal above still refuses and still returns 0;
         * this only makes it observable. */
        int64_t overshoot_rows = -1, overshoot_max_h = -1;
        utxo_recovery_query_rewind_overshoot(ndb->db, tip_h,
            &overshoot_rows, &overshoot_max_h);

        char reason[BLOCKER_REASON_MAX];
        snprintf(reason, sizeof(reason),
            "boot UTXO rewind above tip refused: tip_height=%d "
            "max_height=%lld row_count=%lld guard=%d — only a single-block "
            "overshoot within the guard is auto-healable; investigate "
            "block_index/coins drift (see condition orphan_utxo_above_tip).",
            tip_h, (long long)overshoot_max_h, (long long)overshoot_rows,
            UTXO_BOOT_REWIND_MAX_ROWS);

        struct blocker_record rec;
        if (blocker_init(&rec, UTXO_RECOVERY_REWIND_OVERSHOOT_BLOCKER_ID,
                         "utxo_recovery", BLOCKER_PERMANENT, reason)) {
            blocker_set(&rec);
        }
        return 0;
    }

    /* Bounded overshoot auto-healed: resolve the typed blocker too, in case
     * a prior larger overshoot at this same boot/condition-poll cadence had
     * raised it. */
    blocker_clear(UTXO_RECOVERY_REWIND_OVERSHOOT_BLOCKER_ID);

    event_emitf(EV_RECOVERY_ACTION, 0,
        "action=utxo_prune_above_tip height=%d count=%d",
        tip_h, deleted_total);
    printf("Boot: removed %d UTXOs above tip h=%d\n",
           deleted_total, tip_h);
    return deleted_total;
}
