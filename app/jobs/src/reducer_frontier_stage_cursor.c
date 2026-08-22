/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * F1 — reducer_frontier_stage_cursor_derived: make the per-stage LOG the READ
 * authority for a stage frontier while the stage_cursor table keeps being
 * written (dual-write, single-read). Split out of reducer_frontier.c so the
 * derived-reader machinery (the schema-fallback guard + the hot-path memo)
 * lives in its own translation unit; it reads the k_logs stage->log mapping
 * through reducer_frontier_cursor_log_table (reducer_frontier.c) and derives
 * the contiguous ok=1 prefix through reducer_frontier_log_frontier
 * (the existing DRY reader). See jobs/reducer_frontier.h for the contract. */

#include "jobs/reducer_frontier.h"
#include "reducer_frontier_stage_cursor_internal.h"

#include "storage/progress_store.h"
#include "util/log_macros.h"

#include <sqlite3.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

/* Raw stage_cursor point read — the derived reader's fallback, upper clamp, and
 * memo HIT/MISS key. Deliberately NOT the log-derived value. *out=0 on an
 * absent row; *found (optional) reports presence. false only on a real SQLite
 * error — exactly what the pre-F1 raw floor read could fail on. */
static bool raw_stage_cursor(sqlite3 *db, const char *name, int64_t *out,
                             bool *found)
{
    *out = 0;
    if (found) *found = false;
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db, "SELECT cursor FROM stage_cursor WHERE name = ?",
                           -1, &st, NULL) != SQLITE_OK)
        LOG_FAIL("reducer", "prepare stage_cursor failed: %s",
                 sqlite3_errmsg(db));
    sqlite3_bind_text(st, 1, name, -1, SQLITE_STATIC);
    bool rc_ok = true;
    int rc = sqlite3_step(st);  // raw-sql-ok:progress-kv-kernel-store
    if (rc == SQLITE_ROW) {
        *out = sqlite3_column_int64(st, 0);
        if (found) *found = true;
    } else if (rc != SQLITE_DONE) {
        LOG_WARN("reducer", "step stage_cursor %s failed: %s",
                 name, sqlite3_errmsg(db));
        rc_ok = false;
    }
    sqlite3_finalize(st);
    return rc_ok;
}

/* True iff `table` exists (PRAGMA table_info returns >= 1 column row; a missing
 * table returns zero rows and never errors). The derived reader consults this
 * before attempting a log walk so a partial reducer schema (stage_cursor
 * present but the *_log tables not yet created — early boot, minimal test
 * fixtures) gracefully falls back to the raw cursor instead of tripping the
 * LOG_FAIL inside reducer_trusted_anchor / log_contiguous_prefix. */
static bool reducer_log_table_present(sqlite3 *db, const char *table)
{
    char sql[96];
    int n = snprintf(sql, sizeof(sql), "PRAGMA table_info(%s)", table);
    if (n <= 0 || n >= (int)sizeof(sql))
        return false;  // raw-return-ok:bounded-name-cannot-overflow
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) != SQLITE_OK)
        return false;  // raw-return-ok:absent-table-means-fall-back-to-raw
    bool present = sqlite3_step(st) == SQLITE_ROW;  // raw-sql-ok:progress-kv-kernel-store
    sqlite3_finalize(st);
    return present;
}

/* ── Derived-cursor memo (keeps the hot-path floor read O(1)) ─────────────
 * A downstream stage reads an upstream stage's derived frontier once per block
 * on the fold path; that frontier only changes when the upstream's own cursor
 * moves. Memoize (epoch, db, name, raw) -> derived value so a repeated read of
 * a STATIC upstream returns WITHOUT re-walking its log — this preserves the
 * reducer's O(1)-per-finalize fast-forward ratchet (a full contiguity scan on
 * every floor read would make per-block work O(cursor - anchor); the
 * test_tip_finalize_stage "no historical frontier rows" gate enforces exactly
 * this). A MISS — first read, the upstream advanced/rewound so raw moved, or
 * progress_store reopened so the epoch moved — re-walks once. A stale entry can
 * only be stale-LOW (the log grew under an unchanged cursor — a repair refill),
 * a safe conservative floor that self-corrects on the next cursor move. The raw
 * cursor SELECT (which decides HIT/MISS) issues no contiguity scan, so a HIT
 * costs one point read. Thread-local: the single reducer drive thread keeps it
 * warm; observers on other threads keep their own copy.
 *
 * STALE-LOW HEAL CHECK: raw-keyed invalidation only fires when the upstream
 * cursor MOVES, but a vetoed (value < raw) entry names a transient hole/fail
 * row that heals under a STATIC cursor — validate_headers records ok=0
 * "no-header-solution-backfill-required" rows ahead of the Equihash solution
 * fetch, recheck rewrites them ok=1 once the solution lands, and once the
 * header chain reaches the network tip the raw cursor stops moving entirely.
 * Without a heal check the floor then pins for a full block interval per hole
 * (the C3 cold-start freeze: body_fetch idle at a healed height until the next
 * network block). So a vetoed HIT pays ONE extra point read at the blocking
 * height: still absent/failing keeps the memoized floor; flipped ok=1 falls
 * through to a single re-walk that memoizes the healed frontier. A veto-free
 * entry (value == raw) cannot go stale — the contiguous-to-cursor log only
 * shrinks under a cursor-moving rewind — and stays a pure hit.
 *
 * Enough slots for all eight stage-cursor names across two live progress-store
 * epochs without round-robin thrash (a `find` matches ANY slot, so a stored
 * name only evicts on a genuinely new key). */
#define STAGE_DERIVED_MEMO_SLOTS 16
struct stage_derived_memo_slot {
    uint64_t       epoch;
    const void    *db;
    char           name[64];
    int64_t        raw;
    uint64_t       value;
    bool           valid;
};
static _Thread_local struct stage_derived_memo_slot
    g_stage_derived_memo[STAGE_DERIVED_MEMO_SLOTS];
static _Thread_local unsigned g_stage_derived_memo_rr;

static struct stage_derived_memo_slot *
stage_derived_memo_find(uint64_t epoch, const void *db, const char *name)
{
    for (unsigned i = 0; i < STAGE_DERIVED_MEMO_SLOTS; i++) {
        struct stage_derived_memo_slot *s = &g_stage_derived_memo[i];
        if (s->valid && s->epoch == epoch && s->db == db &&
            strcmp(s->name, name) == 0)
            return s;
    }
    return NULL;
}

static void stage_derived_memo_store(uint64_t epoch, const void *db,
                                     const char *name, int64_t raw,
                                     uint64_t value)
{
    struct stage_derived_memo_slot *s = stage_derived_memo_find(epoch, db, name);
    if (!s) {
        s = &g_stage_derived_memo[g_stage_derived_memo_rr];
        g_stage_derived_memo_rr =
            (g_stage_derived_memo_rr + 1u) % STAGE_DERIVED_MEMO_SLOTS;
    }
    s->epoch = epoch;
    s->db    = db;
    snprintf(s->name, sizeof(s->name), "%s", name);
    s->raw   = raw;
    s->value = value;
    s->valid = true;
}

#ifdef ZCL_TESTING
void reducer_frontier_stage_cursor_derived_reset_memo_for_testing(void)
{
    for (unsigned i = 0; i < STAGE_DERIVED_MEMO_SLOTS; i++)
        g_stage_derived_memo[i].valid = false;
    g_stage_derived_memo_rr = 0;
}
#endif

/* Point read used ONLY to invalidate a stale-LOW memo entry (see "STALE-LOW
 * HEAL CHECK" above): true when `table` has a row at `height` with ok == 1.
 * False on an absent row, any other ok value, or any read error — a read
 * error keeps the conservative memoized floor; compute_hstar reads the same
 * logs and surfaces a genuine fault there. Table names come from the fixed
 * k_logs mapping (reducer_frontier_cursor_log_table), never caller input. */
static bool log_row_ok_one(sqlite3 *db, const char *table, int64_t height)
{
    char sql[96];
    int n = snprintf(sql, sizeof(sql),
                     "SELECT ok FROM %s WHERE height = ?", table);
    if (n <= 0 || n >= (int)sizeof(sql))
        return false;  // raw-return-ok:bounded-name-cannot-overflow
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) != SQLITE_OK)
        return false;  // raw-return-ok:stale-memo-probe-stays-conservative
    sqlite3_bind_int64(st, 1, (sqlite3_int64)height);
    int rc = sqlite3_step(st);  // raw-sql-ok:progress-kv-kernel-store
    bool ok_one = (rc == SQLITE_ROW &&
                   sqlite3_column_type(st, 0) == SQLITE_INTEGER &&
                   sqlite3_column_int(st, 0) == 1);
    sqlite3_finalize(st);
    return ok_one;
}

bool reducer_frontier_stage_cursor_derived(sqlite3 *progress_db,
                                           const char *name,
                                           uint64_t *out, bool *found)
{
    if (out)   *out = 0;
    if (found) *found = false;
    if (!progress_db || !name || !name[0])
        LOG_FAIL("reducer", "stage_cursor_derived: NULL/empty arg");

    /* Recursive lock: safe whether or not the caller already holds it, and it
     * makes the raw read + the log walk one internally-consistent snapshot. */
    progress_store_tx_lock();

    /* The raw stage_cursor row is (a) the fallback whenever the log frontier
     * cannot be derived, (b) the upper clamp, and (c) the memo HIT/MISS key.
     * Reading it is the ONLY hard failure mode — it exactly matches what the
     * pre-F1 raw read (a single `SELECT cursor FROM stage_cursor`) could fail
     * on, so this stays a strict superset-safe replacement (never fails where
     * the raw read succeeded). The point read issues no contiguity scan. */
    int64_t raw = 0;
    bool row_present = false;
    if (!raw_stage_cursor(progress_db, name, &raw, &row_present)) {
        progress_store_tx_unlock();
        return false;  /* raw_stage_cursor already logged the cause */
    }
    if (raw < 0)
        raw = 0;
    uint64_t value = (uint64_t)raw;

    uint64_t epoch = progress_store_epoch();
    struct stage_derived_memo_slot *hit =
        stage_derived_memo_find(epoch, progress_db, name);
    if (hit && hit->raw == raw) {
        /* STALE-LOW HEAL CHECK (see the memo contract above): a vetoed entry
         * (value < raw) names the row whose absence/failure ended the walk;
         * that row can flip ok=1 under a static cursor, so confirm the floor
         * is still blocked before serving the memoized value. */
        bool healed = false;
        if (hit->value < (uint64_t)raw) {
            bool served_tip_hit = false;
            const char *hit_log =
                reducer_frontier_cursor_log_table(name, &served_tip_hit);
            /* The vetoed frame names the blocking row directly for an
             * upstream stage (frame = frontier_h + 1); tip_finalize's
             * served-tip frame stops AT the last proven row, so its blocker
             * sits one higher. */
            int64_t blocking_h = served_tip_hit ? (int64_t)hit->value + 1
                                                : (int64_t)hit->value;
            healed = hit_log &&
                     log_row_ok_one(progress_db, hit_log, blocking_h);
        }
        if (!healed) {
            progress_store_tx_unlock();
            if (out)   *out = hit->value;
            if (found) *found = row_present;
            return true;  /* static upstream — no contiguity scan */
        }
    }

    /* Only the six success-checked logs carry a contiguous-ok=1 frontier. A
     * stage without one (header_admit, body_fetch) keeps the raw cursor as its
     * frontier — there is nothing to derive. The log walk also reads
     * tip_finalize_log (the anchor scan), so both must be present; a partial
     * schema falls back to the raw cursor silently. */
    bool served_tip = false;
    const char *log_table = reducer_frontier_cursor_log_table(name, &served_tip);
    if (log_table &&
        reducer_log_table_present(progress_db, log_table) &&
        reducer_log_table_present(progress_db, "tip_finalize_log")) {
        int32_t frontier_h = 0;
        if (reducer_frontier_log_frontier(progress_db, log_table, name,
                                          &frontier_h)) {
            /* Convert the frontier HEIGHT into `name`'s cursor frame (upstream:
             * next-height = h+1; tip_finalize served-tip: h itself), then CLAMP
             * to the raw cursor. The log may only veto the cursor DOWN to the
             * proven prefix, never raise it above the durable row: in a
             * contiguous state `frame` == raw exactly (the F1 equivalence); a
             * durable hole below the cursor makes `frame` < raw (log wins). */
            int64_t frame = served_tip ? (int64_t)frontier_h
                                       : (int64_t)frontier_h + 1;
            if (frame < 0)
                frame = 0;
            if ((uint64_t)frame < value)
                value = (uint64_t)frame;
        }
        /* else: tables present but the walk hit a read fault — keep the raw
         * cursor (the pre-F1 value); compute_hstar reads the same logs and
         * surfaces a genuine fault there. */
    }

    stage_derived_memo_store(epoch, progress_db, name, raw, value);
    progress_store_tx_unlock();

    if (out)   *out = value;
    if (found) *found = row_present;
    return true;
}
