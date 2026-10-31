/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * coins_ram boot crash-replay reconcile: after a crash between overlay flushes,
 * rewinds the utxo_apply cursor and purges the stale replay tail. Moved out of
 * engine/modules/storage/src/coins_ram.c unchanged; behaviour is identical.
 */
#include "base/serialize_le.h"
#include "storage/coins_ram.h"
#include "coins_ram_internal.h"
#include "storage/progress_store.h"
#include "util/log_macros.h"

#include <sqlite3.h>
#include <stdbool.h>
#include <stdint.h>

/* ── boot crash-replay reconcile ─────────────────────────────────────── */

static bool coins_ram_boot_replay_marker_present(sqlite3 *db, bool *present)
{
    if (present)
        *present = false;
    if (!db)
        return false;

    uint8_t buf[64] = {0};
    size_t len = 0;
    bool found = false;
    if (!progress_meta_get(db, "mint_anchor_in_progress_v1",
                           buf, sizeof(buf), &len, &found))
        return false;
    if (found) {
        if (present)
            *present = true;
        return true;
    }
    len = 0;
    found = false;
    if (!progress_meta_get(db, "refold_in_progress",
                           buf, sizeof(buf), &len, &found))
        return false;
    if (present)
        *present = found;
    return true;
}

/* The persisted utxo_apply cursor, -1 when no row exists. A failed read is an
 * error, not an absent row: treating it as absent skipped reconciliation and
 * kept rows written past the last durable flush. */
static bool coins_ram_boot_read_apply_cursor(struct sqlite3 *db,
                                             int64_t *cursor)
{
    *cursor = -1;
    progress_store_tx_lock();
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db,
            "SELECT cursor FROM stage_cursor WHERE name='utxo_apply'",
            -1, &st, NULL) != SQLITE_OK) {
        progress_store_tx_unlock();
        LOG_FAIL("coins_ram", "reconcile_boot: cursor read prepare failed");
    }
    int rc = sqlite3_step(st);  // raw-sql-ok:progress-kv-kernel-store
    if (rc == SQLITE_ROW)
        *cursor = sqlite3_column_int64(st, 0);
    sqlite3_finalize(st);
    progress_store_tx_unlock();
    if (rc != SQLITE_ROW && rc != SQLITE_DONE)
        LOG_FAIL("coins_ram", "reconcile_boot: cursor read failed (sqlite %d)",
                 rc);
    return true;
}

bool coins_ram_reconcile_boot(
    struct sqlite3 *db, coins_ram_frontier_writer_fn writer)
{
    if (!coins_ram_enabled()) return true;  /* flag off: nothing to reconcile */
    if (!db)
        LOG_FAIL("coins_ram", "reconcile_boot: NULL db");
    if (!writer) LOG_FAIL("coins_ram", "reconcile_boot: NULL frontier writer");
    /* Read the durable flush watermark. Absent → this datadir was never
     * bulk-folded in RAM mode; nothing to rewind. */
    uint8_t wm[8] = {0};
    size_t wlen = 0;
    bool wfound = false;
    if (!progress_meta_get(db, COINS_RAM_FLUSHED_HEIGHT_KEY, wm, sizeof(wm),
                           &wlen, &wfound))
        LOG_FAIL("coins_ram", "reconcile_boot: watermark read failed");
    int32_t watermark = -1;
    bool replay_marker = false;
    if (!coins_ram_boot_replay_marker_present(db, &replay_marker))
        LOG_FAIL("coins_ram", "reconcile_boot: replay marker read failed");
    if (!wfound) {
        if (!replay_marker)
            return true;
    } else if (wlen != 8) {
        LOG_WARN("coins_ram", "reconcile_boot: watermark malformed (len=%zu)",
                 wlen);
        return false;
    } else {
        watermark = (int32_t)zcl_read_u64_le(wm);
    }

    /* Read the persisted utxo_apply cursor. */
    int64_t cursor = -1;
    if (!coins_ram_boot_read_apply_cursor(db, &cursor))
        return false;

    /* Cursor below the durable watermark (+1) → coins_kv already holds more
     * than the cursor claims. Do not purge durable log evidence in that
     * inconsistent-but-conservative shape; another reconcile owns cursor lift. */
    int64_t want_cursor = (int64_t)watermark + 1;
    if (cursor < 0 || cursor < want_cursor)
        return true;

    bool rewind_cursor = cursor > want_cursor;
    bool purge_equal_tail = replay_marker && cursor == want_cursor;
    if (!rewind_cursor && !purge_equal_tail)
        return true;

    /* Crash between flushes: the cursor advanced past the last durable flush,
     * or a mint/refold marker says a prior crash/stop left replay-domain rows
     * at the exact replay cursor. Rewind cursor + coins_applied_height when
     * needed, and purge downstream rows at/above the replay point: those rows
     * were written before the overlay flushed, so after process death they no
     * longer describe durable coins. This includes durable `coins` rows whose
     * creation height is at/above the replay cursor: keeping them makes the
     * replayed block collide with its own stale output. Keeping log/finalize
     * rows also leaves tip_finalize ahead of the coin frontier and can trap
     * mint/refold in an unwind/replay loop. */
    progress_store_tx_lock();
    char *err = NULL;
    bool ok = true;
    if (sqlite3_exec(db, "BEGIN IMMEDIATE", NULL, NULL, &err) != SQLITE_OK) ok = false;
    if (ok && rewind_cursor) {
        sqlite3_stmt *u2 = NULL;
        if (sqlite3_prepare_v2(db,
            "UPDATE stage_cursor SET cursor=?1, updated_at=strftime('%s','now') "
            "WHERE name='utxo_apply'", -1, &u2, NULL) != SQLITE_OK) {
            ok = false;
        } else {
            sqlite3_bind_int64(u2, 1, want_cursor);
            if (sqlite3_step(u2) != SQLITE_DONE) ok = false;  // raw-sql-ok:progress-kv-kernel-store
            sqlite3_finalize(u2);
        }
    }
    if (ok && rewind_cursor &&
        !writer(db, (int32_t)want_cursor))
        ok = false;
    if (ok && !coins_ram_purge_replay_tail(db, want_cursor))
        ok = false;
    if (ok && sqlite3_exec(db, "COMMIT", NULL, NULL, &err) != SQLITE_OK) ok = false;
    if (!ok) sqlite3_exec(db, "ROLLBACK", NULL, NULL, NULL);
    if (err) sqlite3_free(err);
    progress_store_tx_unlock();
    if (!ok)
        LOG_FAIL("coins_ram", "reconcile_boot: rewind commit failed");

    if (rewind_cursor) {
        LOG_INFO("coins_ram",
                 "[coins_ram] crash-replay: rewound utxo_apply cursor %lld -> "
                 "%lld (durable flush watermark=%d); the fold re-applies the "
                 "tail",
                 (long long)cursor, (long long)want_cursor, watermark);
    } else {
        LOG_INFO("coins_ram",
                 "[coins_ram] crash-replay: purged stale replay tail at "
                 "utxo_apply cursor %lld (durable flush watermark=%d)",
                 (long long)want_cursor, watermark);
    }
    return true;
}
