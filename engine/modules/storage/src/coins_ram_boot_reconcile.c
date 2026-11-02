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

/* Turn the watermark read into a status: 1 continue, 0 nothing to rewind,
 * -1 malformed. */
static int coins_ram_boot_take_flush_watermark(bool wfound, size_t wlen,
                                               const uint8_t *wm,
                                               bool replay_marker,
                                               int32_t *watermark)
{
    *watermark = -1;
    if (!wfound) {
        if (!replay_marker)
            return 0;
        return 1;
    }
    if (wlen != 8) {
        LOG_WARN_IN("coins_ram_reconcile_boot", "coins_ram", "reconcile_boot: watermark malformed (len=%zu)",
                 wlen);
        return -1;
    }
    *watermark = (int32_t)zcl_read_u64_le(wm);
    return 1;
}

/* Report whether the cursor needs a rewind or an equal-cursor purge.
 * Sets *rewind_cursor on every path. */
static bool coins_ram_boot_cursor_needs_work(int64_t cursor,
                                             int64_t want_cursor,
                                             bool replay_marker,
                                             bool *rewind_cursor)
{
    *rewind_cursor = false;
    if (cursor < 0 || cursor < want_cursor)
        return false;
    *rewind_cursor = cursor > want_cursor;
    bool purge_equal_tail = replay_marker && cursor == want_cursor;
    if (!*rewind_cursor && !purge_equal_tail)
        return false;
    return true;
}

/* Rewind utxo_apply to want_cursor and write the frontier inside the open
 * transaction. Returns 0 on success, -1 when prepare, step, or the writer fails. */
static int coins_ram_boot_rewind_cursor_and_frontier(
    struct sqlite3 *db, coins_ram_frontier_writer_fn writer,
    int64_t want_cursor)
{
    sqlite3_stmt *u2 = NULL;
    int prep = sqlite3_prepare_v2(db,
            "UPDATE stage_cursor SET cursor=?1, updated_at=strftime('%s','now') "
            "WHERE name='utxo_apply'", -1, &u2, NULL);
    if (prep != SQLITE_OK)
        return -1;
    sqlite3_bind_int64(u2, 1, want_cursor);
    int step = sqlite3_step(u2);  // raw-sql-ok:progress-kv-kernel-store
    sqlite3_finalize(u2);
    if (step != SQLITE_DONE)
        return -1;
    return writer(db, (int32_t)want_cursor) ? 0 : -1;
}

/* Hold the progress-store lock across the replay repair transaction.
 * Returns false when begin, rewind, purge, or commit fails. */
static bool coins_ram_boot_commit_replay_repair(
    struct sqlite3 *db, coins_ram_frontier_writer_fn writer,
    bool rewind_cursor, int64_t want_cursor)
{
    progress_store_tx_lock();
    char *err = NULL;
    bool ok = true;
    if (sqlite3_exec(db, "BEGIN IMMEDIATE", NULL, NULL, &err) != SQLITE_OK) ok = false;
    if (ok && rewind_cursor &&
        coins_ram_boot_rewind_cursor_and_frontier(db, writer, want_cursor) != 0)
        ok = false;
    if (ok && !coins_ram_purge_replay_tail(db, want_cursor))
        ok = false;
    if (ok && sqlite3_exec(db, "COMMIT", NULL, NULL, &err) != SQLITE_OK) ok = false;
    if (!ok) sqlite3_exec(db, "ROLLBACK", NULL, NULL, NULL);
    if (err) sqlite3_free(err);
    progress_store_tx_unlock();
    return ok;
}

/* Log the crash-replay cursor rewind, or the equal-cursor tail purge. */
static void coins_ram_boot_log_replay_outcome(bool rewind_cursor,
                                              int64_t cursor,
                                              int64_t want_cursor,
                                              int32_t watermark)
{
    if (rewind_cursor) {
        LOG_INFO_IN("coins_ram_reconcile_boot", "coins_ram",
                 "[coins_ram] crash-replay: rewound utxo_apply cursor %lld -> "
                 "%lld (durable flush watermark=%d); the fold re-applies the "
                 "tail",
                 (long long)cursor, (long long)want_cursor, watermark);
    } else {
        LOG_INFO_IN("coins_ram_reconcile_boot", "coins_ram",
                 "[coins_ram] crash-replay: purged stale replay tail at "
                 "utxo_apply cursor %lld (durable flush watermark=%d)",
                 (long long)want_cursor, watermark);
    }
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
    int wm_rc = coins_ram_boot_take_flush_watermark(wfound, wlen, wm,
                                                    replay_marker, &watermark);
    if (wm_rc < 0)
        return false;
    if (wm_rc == 0)
        return true;

    /* Read the persisted utxo_apply cursor. */
    int64_t cursor = -1;
    if (!coins_ram_boot_read_apply_cursor(db, &cursor))
        return false;

    /* Cursor below the durable watermark (+1) → coins_kv already holds more
     * than the cursor claims. Do not purge durable log evidence in that
     * inconsistent-but-conservative shape; another reconcile owns cursor lift. */
    int64_t want_cursor = (int64_t)watermark + 1;
    bool rewind_cursor = false;
    if (!coins_ram_boot_cursor_needs_work(cursor, want_cursor, replay_marker,
                                          &rewind_cursor))
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
    if (!coins_ram_boot_commit_replay_repair(db, writer, rewind_cursor,
                                             want_cursor))
        LOG_FAIL("coins_ram", "reconcile_boot: rewind commit failed");

    coins_ram_boot_log_replay_outcome(rewind_cursor, cursor, want_cursor,
                                      watermark);
    return true;
}
