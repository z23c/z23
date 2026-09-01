/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

// one-result-type-ok:legacy-repair-moved-verbatim
//
// utxo_recovery_repair_stale_cursor_from_sync_projection moved VERBATIM
// from utxo_recovery_service.c (wave 2 file split; the whole file is a
// wave-3 delete). Its bool return is the public contract in
// services/utxo_recovery_service.h — every refusal already logs + emits
// the typed EV_BOOT_VALIDATION_FAILED event, and the boot caller treats
// false as "no repair" (not an error). Converting a doomed module to
// zcl_result would be churn against the deletion plan.

/* Legacy stale-cursor repair — advance a lagging node_state
 * 'coins_best_block' anchor to the sync-projection tip when the mirror
 * proves the coins are really there. Split from utxo_recovery_service.c
 * (wave 2).
 *
 * wave-3 delete (whole file): the boot call site (engine/composition/src/boot.c) is
 * gated on !derived — on canonical datadirs (coins_applied_height present
 * in progress.kv) the coins-best fact is DERIVED via
 * reducer_frontier_derive_coins_best and this legacy node_state-anchor
 * repair never runs. It survives only for legacy datadirs until
 * canonical-plan step 5 (docs/work/canonical-frontier-derived-state-plan.md).
 */

#include "services/utxo_recovery_service.h"
#include "models/database.h"
#include "storage/coins_view_sqlite.h"
#include "event/event.h"

#include <sqlite3.h>

#include "util/ar_step_readonly.h"
#include "util/log_macros.h"

#include "utxo_recovery_internal.h"

static bool urs_block_height_for_hash(struct node_db *ndb,
                                      const uint8_t hash[32],
                                      int64_t *out_height)
{
    if (!ndb || !ndb->open || !ndb->db || !hash || !out_height)
        return false;

    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(ndb->db,
            "SELECT height FROM blocks WHERE hash=? AND status>=3",
            -1, &st, NULL) != SQLITE_OK) {
        LOG_WARN("chain", "stale cursor repair: block lookup prepare "
                 "failed: %s", sqlite3_errmsg(ndb->db));
        return false;
    }
    sqlite3_bind_blob(st, 1, hash, 32, SQLITE_STATIC);
    bool ok = false;
    if (AR_STEP_ROW_READONLY(st) == SQLITE_ROW) {
        *out_height = sqlite3_column_int64(st, 0);
        ok = true;
    }
    sqlite3_finalize(st);
    return ok;
}

static bool urs_utxo_height_summary(struct node_db *ndb,
                                    bool *out_have_utxos,
                                    int64_t *out_max_height)
{
    if (!ndb || !ndb->open || !ndb->db ||
        !out_have_utxos || !out_max_height)
        return false;

    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(ndb->db,
            "SELECT MAX(height), COUNT(*) FROM utxos",
            -1, &st, NULL) != SQLITE_OK) {
        LOG_WARN("chain", "stale cursor repair: utxo summary prepare "
                 "failed: %s", sqlite3_errmsg(ndb->db));
        return false;
    }

    bool ok = false;
    if (AR_STEP_ROW_READONLY(st) == SQLITE_ROW) {
        *out_have_utxos = sqlite3_column_int64(st, 1) > 0;
        *out_max_height = sqlite3_column_type(st, 0) == SQLITE_INTEGER
            ? sqlite3_column_int64(st, 0) : -1;
        ok = true;
    }
    sqlite3_finalize(st);
    return ok;
}

bool utxo_recovery_repair_stale_cursor_from_sync_projection(
    struct node_db *ndb)
{
    if (!ndb || !ndb->open || !ndb->db)
        return false;

    uint8_t coins_hash[32];
    size_t len = 0;
    if (!node_db_state_get(ndb, "coins_best_block",
                           coins_hash, sizeof(coins_hash), &len) ||
        len != sizeof(coins_hash))
        return false;

    int64_t sync_h = -1;
    if (!node_db_state_get_int(ndb, "sync_projection_tip_height", &sync_h) ||
        sync_h <= 0)
        return false;

    uint8_t sync_hash[32];
    len = 0;
    if (!node_db_state_get(ndb, "sync_projection_tip_hash",
                           sync_hash, sizeof(sync_hash), &len) ||
        len != sizeof(sync_hash))
        return false;

    int64_t coins_h = -1;
    if (!urs_block_height_for_hash(ndb, coins_hash, &coins_h))
        return false;

    int64_t resolved_sync_h = -1;
    if (!urs_block_height_for_hash(ndb, sync_hash, &resolved_sync_h) ||
        resolved_sync_h != sync_h)
        return false;
    if (sync_h <= coins_h)
        return false;

    bool have_utxos = false;
    int64_t max_utxo_h = -1;
    if (!urs_utxo_height_summary(ndb, &have_utxos, &max_utxo_h) ||
        !have_utxos)
        return false;

    if (max_utxo_h + UTXO_CHECKPOINT_NEAR_WINDOW < sync_h) {
        LOG_WARN("chain", "stale cursor repair refused: coins_h=%lld "
                 "sync_h=%lld max_utxo_h=%lld below sync window=%d",
                 (long long)coins_h, (long long)sync_h,
                 (long long)max_utxo_h, UTXO_CHECKPOINT_NEAR_WINDOW);
        event_emitf(EV_BOOT_VALIDATION_FAILED, 0,
            "stale_cursor_repair_refused coins_h=%lld sync_h=%lld "
            "max_utxo_h=%lld below_window=%d",
            (long long)coins_h, (long long)sync_h,
            (long long)max_utxo_h, UTXO_CHECKPOINT_NEAR_WINDOW);
        return false;
    }

    if (max_utxo_h > sync_h + 1) {
        LOG_WARN("chain", "stale cursor repair refused: coins_h=%lld "
                 "sync_h=%lld max_utxo_h=%lld exceeds one-block guard",
                 (long long)coins_h, (long long)sync_h,
                 (long long)max_utxo_h);
        event_emitf(EV_BOOT_VALIDATION_FAILED, 0,
            "stale_cursor_repair_refused coins_h=%lld sync_h=%lld "
            "max_utxo_h=%lld",
            (long long)coins_h, (long long)sync_h,
            (long long)max_utxo_h);
        return false;
    }

    if (max_utxo_h > sync_h) {
        int deleted = coins_rewind_above_tip(
            ndb->db, sync_h, UTXO_BOOT_REWIND_MAX_ROWS);
        if (deleted < 0)
            return false;
    } else {
        (void)node_db_exec(ndb,
            "DELETE FROM node_state WHERE key='utxo_commitment'");
    }

    if (!node_db_state_set(ndb, "coins_best_block",
                           sync_hash, sizeof(sync_hash)))
        return false;
    /* The height metadata must land too: coins_best_block (hash) and its
     * height are read together by the coins-integrity gate, so a hash
     * written without its height is exactly the inconsistency that gate
     * trips on. Don't claim a successful repair if this write fails. */
    if (!node_db_state_set_int(ndb, "cec.coins_best_block_height", sync_h)) {
        LOG_WARN("chain", "stale cursor repair: coins_best_block advanced "
                 "to h=%lld but height-metadata write failed; reporting "
                 "repair incomplete", (long long)sync_h);
        return false;
    }

    LOG_WARN("chain", "stale cursor repair: advanced coins_best_block "
             "from h=%lld to sync projection h=%lld (max_utxo_h=%lld)",
             (long long)coins_h, (long long)sync_h,
             (long long)max_utxo_h);
    event_emitf(EV_RECOVERY_ACTION, 0,
        "action=repair_stale_coins_cursor from=%lld to=%lld max_utxo=%lld",
        (long long)coins_h, (long long)sync_h, (long long)max_utxo_h);
    return true;
}
