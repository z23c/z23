/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * stage_repair_rewind — the DESTRUCTIVE header-solution poison rewind. When a
 * solutionless validate failure (or a skipped-invalid body fetch) poisons the
 * reducer at the frontier, this TU rewinds the downstream stage cursors and
 * deletes their logs so the reducer re-derives them forward from a backfilled
 * header solution.
 *
 * SAFETY (load-bearing, pinned by test_stage_repair):
 *   - the rewind is REFUSED unless height == active_tip_height + 1 (frontier
 *     only — never a deep rewind);
 *   - the rewind is REFUSED if ANY ok=1 row sits at/above the frontier in any
 *     success_checked_logs table (the ~47279 regression guard protecting the
 *     Tier-2 public-tip floor);
 *   - tip_finalize_log is DELIBERATELY ABSENT from the deletion set — its rows
 *     are never deleted; only the tip_finalize *cursor* is rewound.
 * Do not alter this logic; relocate only. */

#include "jobs/stage_repair.h"
#include "jobs/stage_repair_internal.h"
#include "jobs/utxo_apply_stage.h"

#include "platform/time_compat.h"
#include "storage/coins_kv.h"
#include "storage/nullifier_kv.h"
#include "storage/anchor_kv.h"
#include "storage/progress_store.h"
#include "util/log_macros.h"
#include "util/stage.h"

#include <sqlite3.h>
#include <limits.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

#define STAGE_REPAIR_HASH_MISMATCH_REASON "header-source-hash-mismatch"

static bool body_fetch_skipped_invalid(sqlite3 *db, int height, bool *out)
{
    *out = false;
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db,
            "SELECT source, ok, COALESCE(fail_reason,'') "
            "FROM body_fetch_log WHERE height = ?",
            -1, &st, NULL) != SQLITE_OK) {
        LOG_WARN("stage_repair",
                 "[stage_repair] body_fetch row prepare failed: %s",
                 sqlite3_errmsg(db));
        return false;
    }
    sqlite3_bind_int(st, 1, height);
    int rc = sqlite3_step(st);  // raw-sql-ok:progress-kv-kernel-store
    if (rc == SQLITE_ROW) {
        const unsigned char *source = sqlite3_column_text(st, 0);
        int ok = sqlite3_column_int(st, 1);
        const unsigned char *reason = sqlite3_column_text(st, 2);
        *out = ok == 0 &&
               source && strcmp((const char *)source, "skipped_invalid") == 0 &&
               reason && strcmp((const char *)reason,
                                "header_validation_failed") == 0;
    } else if (rc != SQLITE_DONE) {
        LOG_WARN("stage_repair",
                 "[stage_repair] body_fetch row step failed rc=%d: %s",
                 rc, sqlite3_errmsg(db));
        sqlite3_finalize(st);
        return false;
    }
    sqlite3_finalize(st);
    return true;
}

static enum stage_repair_header_solution_poison
poison_mode_unlocked(sqlite3 *db, int height)
{
    if (!db || height < 0)
        return STAGE_REPAIR_POISON_NONE;

    struct validate_row vh;
    if (!stage_repair_read_validate_row(db, height, &vh))
        return STAGE_REPAIR_POISON_NONE;

    if (vh.found && vh.ok == 0 &&
        strcmp(vh.fail_reason, STAGE_REPAIR_SOLUTIONLESS_REASON) == 0)
        return STAGE_REPAIR_POISON_VALIDATE_SOLUTIONLESS;
    if (vh.found && vh.ok == 0 &&
        strcmp(vh.fail_reason, STAGE_REPAIR_HASH_MISMATCH_REASON) == 0)
        return STAGE_REPAIR_POISON_VALIDATE_HASH_MISMATCH;

    bool skipped = false;
    if (!body_fetch_skipped_invalid(db, height, &skipped))
        return STAGE_REPAIR_POISON_NONE;

    if (!skipped)
        return STAGE_REPAIR_POISON_NONE;
    if (vh.found && vh.ok == 1)
        return STAGE_REPAIR_POISON_DOWNSTREAM_STALE;
    if (vh.found && vh.ok == 0 &&
        strcmp(vh.fail_reason, STAGE_REPAIR_SOLUTIONLESS_REASON) == 0)
        return STAGE_REPAIR_POISON_VALIDATE_SOLUTIONLESS;
    if (vh.found && vh.ok == 0 &&
        strcmp(vh.fail_reason, STAGE_REPAIR_HASH_MISMATCH_REASON) == 0)
        return STAGE_REPAIR_POISON_VALIDATE_HASH_MISMATCH;
    return STAGE_REPAIR_POISON_NONE;
}

enum stage_repair_header_solution_poison
stage_repair_header_solution_poison_mode(sqlite3 *db, int height)
{
    progress_store_tx_lock();
    enum stage_repair_header_solution_poison mode =
        poison_mode_unlocked(db, height);
    progress_store_tx_unlock();
    return mode;
}

bool stage_repair_header_solution_repairable_validate_frontier(
    sqlite3 *db,
    int *out_height)
{
    if (out_height)
        *out_height = -1;
    if (!db || !out_height)
        LOG_FAIL("stage_repair", "repairable validate frontier invalid args");

    progress_store_tx_lock();

    int tip_finalize_cursor = -1;
    int validate_cursor = -1;
    bool ok = stage_repair_cursor_at_unlocked(db, "tip_finalize",
                                              &tip_finalize_cursor) &&
              stage_repair_cursor_at_unlocked(db, "validate_headers",
                                              &validate_cursor);
    if (!ok) {
        progress_store_tx_unlock();
        return false;
    }

    int start_height = tip_finalize_cursor >= 0 ? tip_finalize_cursor + 1 : 0;
    int end_height = validate_cursor > 0 ? validate_cursor - 1 : INT_MAX;
    if (end_height < start_height) {
        progress_store_tx_unlock();
        return true;
    }

    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db,
            "SELECT height FROM validate_headers_log "
            "WHERE height >= ? AND height <= ? AND ok = 0 "
            "AND fail_reason IN (?, ?) "
            "ORDER BY height ASC LIMIT 1",
            -1, &st, NULL) != SQLITE_OK) {
        LOG_WARN("stage_repair",
                 "[stage_repair] repairable validate frontier prepare "
                 "failed: %s",
                 sqlite3_errmsg(db));
        progress_store_tx_unlock();
        return false;
    }
    sqlite3_bind_int(st, 1, start_height);
    sqlite3_bind_int(st, 2, end_height);
    sqlite3_bind_text(st, 3, STAGE_REPAIR_SOLUTIONLESS_REASON, -1,
                      SQLITE_STATIC);
    sqlite3_bind_text(st, 4, STAGE_REPAIR_HASH_MISMATCH_REASON, -1,
                      SQLITE_STATIC);
    int rc = sqlite3_step(st);  // raw-sql-ok:progress-kv-kernel-store
    if (rc == SQLITE_ROW) {
        *out_height = sqlite3_column_int(st, 0);
    } else if (rc != SQLITE_DONE) {
        LOG_WARN("stage_repair",
                 "[stage_repair] repairable validate frontier step "
                 "failed rc=%d: %s",
                 rc, sqlite3_errmsg(db));
        sqlite3_finalize(st);
        progress_store_tx_unlock();
        return false;
    }
    sqlite3_finalize(st);
    progress_store_tx_unlock();
    return true;
}

/* Returns rows deleted, or -1 on failure (callers `goto rollback` on n < 0).
 * Every failure must be -1, not a row count: a bind failure leaves the param
 * NULL, the WHERE matches nothing, and the DELETE silently no-ops — returning
 * a count would commit a rewind that left stale rows behind. */
static int delete_from_table(sqlite3 *db, const char *table, int height)
{
    char sql[160];
    snprintf(sql, sizeof(sql), "DELETE FROM %s WHERE height >= ?", table);
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) != SQLITE_OK) {
        LOG_ERR("stage_repair",
                "[stage_repair] delete prepare failed table=%s: %s",
                table, sqlite3_errmsg(db));
        return -1;  // raw-return-ok:logged-above
    }
    if (sqlite3_bind_int(st, 1, height) != SQLITE_OK) {
        LOG_ERR("stage_repair",
                "[stage_repair] delete bind failed table=%s: %s",
                table, sqlite3_errmsg(db));
        sqlite3_finalize(st);
        return -1;  // raw-return-ok:logged-above
    }
    int rc = sqlite3_step(st);  // raw-sql-ok:progress-kv-kernel-store
    int changed = sqlite3_changes(db);
    sqlite3_finalize(st);
    if (rc != SQLITE_DONE) {
        LOG_ERR("stage_repair",
                "[stage_repair] delete step failed table=%s rc=%d: %s",
                table, rc, sqlite3_errmsg(db));
        return -1;  // raw-return-ok:logged-above
    }
    return changed;
}

bool stage_repair_force_stage_cursor(sqlite3 *db, const char *name, int height)
{
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db,
            "INSERT INTO stage_cursor(name, cursor, updated_at) "
            "VALUES(?,?,?) "
            "ON CONFLICT(name) DO UPDATE SET "
            "cursor=excluded.cursor, updated_at=excluded.updated_at",
            -1, &st, NULL) != SQLITE_OK) {
        LOG_WARN("stage_repair",
                 "[stage_repair] cursor prepare failed stage=%s: %s",
                 name, sqlite3_errmsg(db));
        return false;
    }
    sqlite3_bind_text(st, 1, name, -1, SQLITE_STATIC);
    sqlite3_bind_int64(st, 2, (sqlite3_int64)height);
    sqlite3_bind_int64(st, 3,
                       (sqlite3_int64)platform_time_wall_unix());
    int rc = sqlite3_step(st);  // raw-sql-ok:progress-kv-kernel-store
    sqlite3_finalize(st);
    if (rc != SQLITE_DONE) {
        LOG_WARN("stage_repair",
                 "[stage_repair] cursor step failed stage=%s rc=%d: %s",
                 name, rc, sqlite3_errmsg(db));
        return false;
    }
    return true;
}

static bool table_has_success_at_or_above(sqlite3 *db, const char *table,
                                          int height, bool *out)
{
    *out = false;
    char sql[160];
    snprintf(sql, sizeof(sql),
             "SELECT 1 FROM %s WHERE height >= ? AND ok = 1 LIMIT 1", table);
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) != SQLITE_OK) {
        LOG_WARN("stage_repair",
                 "[stage_repair] success-check prepare failed table=%s: %s",
                 table, sqlite3_errmsg(db));
        return false;
    }
    sqlite3_bind_int(st, 1, height);
    int rc = sqlite3_step(st);  // raw-sql-ok:progress-kv-kernel-store
    if (rc == SQLITE_ROW) {
        *out = true;
    } else if (rc != SQLITE_DONE) {
        LOG_WARN("stage_repair",
                 "[stage_repair] success-check step failed table=%s rc=%d: %s",
                 table, rc, sqlite3_errmsg(db));
        sqlite3_finalize(st);
        return false;
    }
    sqlite3_finalize(st);
    return true;
}

bool stage_repair_header_solution_poison_rewind(
    sqlite3 *db,
    int height,
    int active_tip_height,
    struct stage_repair_header_solution_result *out)
{
    if (out)
        memset(out, 0, sizeof(*out));
    if (!db || height < 0 || active_tip_height < -1)
        LOG_FAIL("stage_repair", "header poison rewind invalid args");
    if (height != active_tip_height + 1) {
        LOG_WARN("stage_repair",
                 "[stage_repair] reject non-frontier repair h=%d active_tip=%d",
                 height, active_tip_height);
        return false;
    }
    if (!stage_table_ensure(db))
        return false;
    /* The delete list below includes `nullifiers`; ensure it exists so a
     * datadir that predates the table (stage init not yet run) does not fail
     * the whole rewind on "no such table". Idempotent. */
    if (!nullifier_kv_ensure_schema(db))
        return false;  /* nullifier_kv logged the failure */
    if (!anchor_kv_ensure_schema(db)) {
        LOG_WARN("stage_repair",
                 "[stage_repair] header poison rewind could not ensure "
                 "anchor schema h=%d active_tip=%d",
                 height, active_tip_height);
        return false;
    }

    /* tip_finalize_log is DELIBERATELY ABSENT here: doctrine forbids deleting
     * tip_finalize_log rows (a prior deletion collapsed the public tip to
     * ~47279). The frontier rewind below rewinds the tip_finalize *cursor*
     * (downstream_stages) so the surviving rows are re-finalized forward; the
     * ok=1 guard (success_checked_logs, which DOES include tip_finalize_log)
     * already refuses the whole repair if any finalized row exists at/above
     * the frontier, so the Tier-2 public-tip floor is never disturbed. */
    static const char *const downstream_logs[] = {
        "body_fetch_log",
        "body_persist_log",
        "script_validate_log",
        "proof_validate_log",
        "utxo_apply_log",
        "utxo_apply_delta",
        /* Belt-and-braces rewind-invariant hold (storage/nullifier_kv.h):
         * provably empty in-range — the success_checked_logs ok=1 guard
         * already refused the rewind if any utxo_apply row succeeded
         * at/above the frontier, and only successful applies insert
         * nullifiers. */
        "nullifiers",
        "sprout_anchors",
        "sapling_anchors",
    };
    static const char *const downstream_stages[] = {
        "body_fetch",
        "body_persist",
        "script_validate",
        "proof_validate",
        "utxo_apply",
        "tip_finalize",
    };
    static const char *const success_checked_logs[] = {
        "body_fetch_log",
        "body_persist_log",
        "script_validate_log",
        "proof_validate_log",
        "utxo_apply_log",
        "tip_finalize_log",
    };

    progress_store_tx_lock();
    char *err = NULL;
    if (sqlite3_exec(db, "BEGIN IMMEDIATE", NULL, NULL, &err) !=
        SQLITE_OK) {
        LOG_WARN("stage_repair",
                 "[stage_repair] BEGIN failed: %s",
                 err ? err : "(no message)");
        if (err) sqlite3_free(err);
        progress_store_tx_unlock();
        return false;
    }

    enum stage_repair_header_solution_poison mode =
        poison_mode_unlocked(db, height);
    if (out) {
        out->target_height = height;
        out->mode = mode;
    }
    if (mode == STAGE_REPAIR_POISON_NONE) {
        sqlite3_exec(db, "ROLLBACK", NULL, NULL, NULL);
        progress_store_tx_unlock();
        return true;
    }
    if (mode == STAGE_REPAIR_POISON_VALIDATE_HASH_MISMATCH) {
        sqlite3_exec(db, "ROLLBACK", NULL, NULL, NULL);
        progress_store_tx_unlock();
        LOG_WARN("stage_repair",
                 "[stage_repair] source-hash mismatch h=%d is repaired by "
                 "hash-bound header backfill + validate_headers recheck, "
                 "not destructive poison_rewind",
                 height);
        return true;
    }

    for (size_t i = 0;
         i < sizeof(success_checked_logs) / sizeof(success_checked_logs[0]);
         i++) {
        bool has_success = false;
        if (!table_has_success_at_or_above(db, success_checked_logs[i],
                                           height, &has_success))
            goto rollback;
        if (has_success) {
            LOG_WARN("stage_repair",
                     "[stage_repair] reject repair h=%d: %s has successful "
                     "rows at/above frontier",
                     height, success_checked_logs[i]);
            goto rollback;
        }
    }

    int deleted = 0;
    int rewound = 0;
    if (mode == STAGE_REPAIR_POISON_VALIDATE_SOLUTIONLESS) {
        int n = delete_from_table(db, "validate_headers_log", height);
        if (n < 0) goto rollback;
        deleted += n;
        if (!stage_repair_force_stage_cursor(db, "validate_headers", height))
            goto rollback;
        rewound++;
    }

    for (size_t i = 0; i < sizeof(downstream_logs) / sizeof(downstream_logs[0]);
         i++) {
        int n = delete_from_table(db, downstream_logs[i], height);
        if (n < 0) goto rollback;
        deleted += n;
    }
    for (size_t i = 0;
         i < sizeof(downstream_stages) / sizeof(downstream_stages[0]); i++) {
        if (!stage_repair_force_stage_cursor(db, downstream_stages[i], height))
            goto rollback;
        rewound++;
    }

    /* THIRD production writer of the utxo_apply stage cursor (after the forward
     * apply and the reorg unwind): the downstream_stages force loop above just
     * forced the "utxo_apply" cursor DOWN to `height`, so the contiguous applied
     * frontier (coins_applied_height) must move with it inside THIS same
     * BEGIN IMMEDIATE — otherwise the cursor moves while the frontier keeps its
     * old (higher) value, leaving a DURABLE stale-HIGH frontier that the boot
     * backfill (if-absent only) can never correct, breaking P2's "frontier ==
     * cursor by construction" on the exact self-heal path P2 feeds.
     *
     * WHY setting the frontier to `height` is coins-consistent (not a fragile
     * cross-stage assumption): the success_checked_logs ok=1 guard above
     * (which INCLUDES utxo_apply_log) already refused the whole rewind if ANY
     * ok=1 utxo_apply row existed at/above `height`. So NO ok=1 utxo_apply
     * happened at/above `height` → NO coins were mutated at/above `height` →
     * the coin set is EXACTLY consistent with a frontier of `height`. We do NOT
     * replay inverse deltas or touch coins_kv rows here: by that same guard
     * there are no committed coin mutations at/above `height` to undo. This
     * co-write makes frontier == cursor hold by construction on this path too.
     * A PLAIN set (the rewind decreases the frontier); ROLLBACK on failure
     * exactly like the surrounding writes (goto rollback). */
    if (!utxo_apply_frontier_set_in_tx(db, height))
        goto rollback;

    if (sqlite3_exec(db, "COMMIT", NULL, NULL, &err) != SQLITE_OK) {
        LOG_WARN("stage_repair",
                 "[stage_repair] COMMIT failed: %s",
                 err ? err : "(no message)");
        if (err) sqlite3_free(err);
        sqlite3_exec(db, "ROLLBACK", NULL, NULL, NULL);
        progress_store_tx_unlock();
        return false;
    }
    progress_store_tx_unlock();

    if (out) {
        out->repaired = true;
        out->deleted_rows = deleted;
        out->rewound_cursors = rewound;
    }
    LOG_WARN("stage_repair",
             "[stage_repair] header-solution poison repaired h=%d mode=%d "
             "deleted=%d rewound=%d",
             height, mode, deleted, rewound);
    return true;

rollback:
    sqlite3_exec(db, "ROLLBACK", NULL, NULL, NULL);
    progress_store_tx_unlock();
    return false;
}
