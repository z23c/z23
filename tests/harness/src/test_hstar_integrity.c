/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_hstar_integrity — the W4-4 per-row integrity tag (stage_row_itag).
 *
 * H* is a pure fold over progress.kv stage rows, trusting the `ok` column bytes
 * as read from SQLite. A flipped bit in a stage row could silently RAISE H* past
 * unfolded state. Each *_log row now carries a truncated-SHA3 `itag` over its
 * H*-load-bearing fields; the reducer fold recomputes and compares it, treating
 * a row whose tag does not verify as NOT ok. These cases prove:
 *
 *   1. clean tagged rows fold to the SAME H* as before (no regression),
 *   2. a flipped ok bit (0 -> 1) does NOT advance H* past the corrupted height
 *      and fires a typed error (corruption LOWERS the frontier, never raises it),
 *   3. the tag verify primitive returns MATCH / MISMATCH / ABSENT correctly,
 *   4. the schema migration backfills legacy rows and is idempotent,
 *   5. the per-boot watermark keeps a normal fold O(delta) (measured numbers),
 *   6. mutating a row below that watermark invalidates it and lowers H*.
 *
 * The fixture writes rows with plain sqlite3 INSERT — TEST scaffolding building
 * the durable image, not production reducer code. compute_hstar is the unit
 * under test. */

#include "test/test_core.h"

#include "jobs/reducer_frontier.h"
#include "jobs/stage_row_itag.h"
#include "event/event.h"
#include "platform/time_compat.h"

#include <sqlite3.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

/* Production write path (src-private headers; forward-declared like the reindex
 * epilogue does) — exercised by the migration/backfill case. */
bool body_persist_log_ensure_schema(struct sqlite3 *db);
bool body_persist_log_insert(struct sqlite3 *db, int height,
                             const char *source, bool ok);

#define HI_CHECK(name, expr) do {                                  \
    printf("hstar_integrity: %s... ", (name));                     \
    if (expr) { printf("OK\n"); }                                  \
    else { printf("FAIL\n"); failures++; }                         \
} while (0)

/* The anchor the production algorithm clamps to; fixtures sit just above it. */
#define A REDUCER_FRONTIER_TRUSTED_ANCHOR  /* 3056758 */

/* ── fixture: the production schema WITH the itag column ─────────────────── */

static bool build_schema(sqlite3 *db)
{
    static const char *const ddl =
        "CREATE TABLE IF NOT EXISTS stage_cursor ("
        "  name TEXT PRIMARY KEY,"
        "  cursor INTEGER NOT NULL,"
        "  updated_at INTEGER NOT NULL);"
        "CREATE TABLE IF NOT EXISTS progress_meta ("
        "  key TEXT PRIMARY KEY, value BLOB);"
        "CREATE TABLE IF NOT EXISTS header_admit_log ("
        "  height INTEGER PRIMARY KEY, hash BLOB NOT NULL,"
        "  parent_hash BLOB, admitted_at INTEGER NOT NULL);"
        "CREATE TABLE IF NOT EXISTS validate_headers_log ("
        "  height INTEGER PRIMARY KEY, hash BLOB NOT NULL, ok INTEGER NOT NULL,"
        "  fail_reason TEXT, validated_at INTEGER, itag BLOB);"
        "CREATE TABLE IF NOT EXISTS script_validate_log ("
        "  height INTEGER PRIMARY KEY, status TEXT, ok INTEGER NOT NULL,"
        "  block_hash BLOB, itag BLOB);"
        "CREATE TABLE IF NOT EXISTS body_persist_log ("
        "  height INTEGER PRIMARY KEY, source TEXT, ok INTEGER NOT NULL,"
        "  itag BLOB);"
        "CREATE TABLE IF NOT EXISTS proof_validate_log ("
        "  height INTEGER PRIMARY KEY, status TEXT, ok INTEGER NOT NULL,"
        "  block_hash BLOB, itag BLOB);"
        "CREATE TABLE IF NOT EXISTS utxo_apply_log ("
        "  height INTEGER PRIMARY KEY, status TEXT, ok INTEGER NOT NULL,"
        "  spent_count INTEGER, added_count INTEGER, itag BLOB);"
        "CREATE TABLE IF NOT EXISTS utxo_apply_delta ("
        "  height INTEGER PRIMARY KEY, branch_hash BLOB NOT NULL,"
        "  spent_blob BLOB NOT NULL, added_blob BLOB NOT NULL);"
        "CREATE TABLE IF NOT EXISTS tip_finalize_log ("
        "  height INTEGER PRIMARY KEY, status TEXT, ok INTEGER NOT NULL,"
        "  tip_hash BLOB, itag BLOB);";
    char *err = NULL;
    if (sqlite3_exec(db, ddl, NULL, NULL, &err) != SQLITE_OK) {
        fprintf(stderr, "[test_hstar_integrity] schema: %s\n",
                err ? err : "(null)");
        sqlite3_free(err);
        return false;
    }
    return true;
}

static bool stamp_proven_authority(sqlite3 *db, int64_t applied_height)
{
    char *err = NULL;
    if (sqlite3_exec(db,
            "CREATE TABLE IF NOT EXISTS coins(k BLOB PRIMARY KEY, v BLOB);"
            "INSERT OR IGNORE INTO coins(k,v) VALUES(x'00', x'00');",
            NULL, NULL, &err) != SQLITE_OK) {
        sqlite3_free(err);
        return false;
    }
    uint8_t ah[8];
    for (int i = 0; i < 8; i++)
        ah[i] = (uint8_t)((uint64_t)applied_height >> (8 * i));
    uint8_t one = 1;
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db,
            "INSERT OR REPLACE INTO progress_meta(key,value) VALUES(?,?)",
            -1, &st, NULL) != SQLITE_OK)
        return false;
    sqlite3_bind_text(st, 1, "coins_applied_height", -1, SQLITE_STATIC);
    sqlite3_bind_blob(st, 2, ah, 8, SQLITE_STATIC);
    bool ok = sqlite3_step(st) == SQLITE_DONE;
    sqlite3_finalize(st);
    if (!ok) return false;
    st = NULL;
    if (sqlite3_prepare_v2(db,
            "INSERT OR REPLACE INTO progress_meta(key,value) VALUES(?,?)",
            -1, &st, NULL) != SQLITE_OK)
        return false;
    sqlite3_bind_text(st, 1, "coins_kv_migration_complete", -1, SQLITE_STATIC);
    sqlite3_bind_blob(st, 2, &one, 1, SQLITE_STATIC);
    ok = sqlite3_step(st) == SQLITE_DONE;
    sqlite3_finalize(st);
    return ok;
}

static bool set_cursor(sqlite3 *db, const char *name, int64_t cursor)
{
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db,
            "INSERT INTO stage_cursor(name,cursor,updated_at) VALUES(?,?,0) "
            "ON CONFLICT(name) DO UPDATE SET cursor=excluded.cursor",
            -1, &st, NULL) != SQLITE_OK)
        return false;
    sqlite3_bind_text(st, 1, name, -1, SQLITE_STATIC);
    sqlite3_bind_int64(st, 2, cursor);
    bool ok = sqlite3_step(st) == SQLITE_DONE;
    sqlite3_finalize(st);
    return ok;
}

static bool set_all_cursors(sqlite3 *db, int64_t c)
{
    return set_cursor(db, "validate_headers", c)
        && set_cursor(db, "body_fetch", c)
        && set_cursor(db, "body_persist", c)
        && set_cursor(db, "proof_validate", c)
        && set_cursor(db, "script_validate", c)
        && set_cursor(db, "utxo_apply", c)
        && set_cursor(db, "tip_finalize", c);
}

static void synth_hash(uint8_t out[32], int32_t h, uint8_t tag)
{
    memset(out, 0, 32);
    out[0] = (uint8_t)(h & 0xff);
    out[1] = (uint8_t)((h >> 8) & 0xff);
    out[2] = (uint8_t)((h >> 16) & 0xff);
    out[31] = tag;
}

static bool put_header_admit(sqlite3 *db, int32_t h, const uint8_t hash[32])
{
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db,
            "INSERT INTO header_admit_log(height,hash,admitted_at) "
            "VALUES(?,?,0)", -1, &st, NULL) != SQLITE_OK)
        return false;
    sqlite3_bind_int(st, 1, h);
    sqlite3_bind_blob(st, 2, hash, 32, SQLITE_STATIC);
    bool ok = sqlite3_step(st) == SQLITE_DONE;
    sqlite3_finalize(st);
    return ok;
}

static bool put_utxo_delta(sqlite3 *db, int32_t h, const uint8_t hash[32])
{
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db,
            "INSERT INTO utxo_apply_delta"
            "(height,branch_hash,spent_blob,added_blob) "
            "VALUES(?,?,x'',x'')", -1, &st, NULL) != SQLITE_OK)
        return false;
    sqlite3_bind_int(st, 1, h);
    sqlite3_bind_blob(st, 2, hash, 32, SQLITE_STATIC);
    bool ok = sqlite3_step(st) == SQLITE_DONE;
    sqlite3_finalize(st);
    return ok;
}

/* Insert one row into a *_log table, computing and binding the production itag
 * over the row's H*-load-bearing fields. `hash_col`/`hash` is the optional
 * 32-byte block hash column; `status` is the optional status text. */
static bool put_tagged_row(sqlite3 *db, const char *table, const char *hash_col,
                           int32_t height, int ok, const uint8_t hash[32],
                           const char *status)
{
    bool profile = strcmp(table, "script_validate_log") == 0 ||
                   strcmp(table, "proof_validate_log") == 0 ||
                   strcmp(table, "utxo_apply_log") == 0;
    const char *row_status = (profile && ok == 1) ? "verified" : status;

    uint8_t itag[STAGE_ROW_ITAG_LEN];
    stage_row_itag_compute(table, (int64_t)height, ok,
                           row_status, row_status ? strlen(row_status) : 0,
                           itag);

    char sql[320];
    if (hash_col && row_status)
        snprintf(sql, sizeof(sql),
                 "INSERT INTO %s(height,status,ok,%s,itag) VALUES(?,?,?,?,?)",
                 table, hash_col);
    else if (hash_col)
        snprintf(sql, sizeof(sql),
                 "INSERT INTO %s(height,ok,%s,itag) VALUES(?,?,?,?)",
                 table, hash_col);
    else if (row_status)
        snprintf(sql, sizeof(sql),
                 "INSERT INTO %s(height,status,ok,itag) VALUES(?,?,?,?)", table);
    else
        snprintf(sql, sizeof(sql),
                 "INSERT INTO %s(height,ok,itag) VALUES(?,?,?)", table);

    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) != SQLITE_OK) {
        fprintf(stderr, "[test_hstar_integrity] prepare %s: %s\n",
                table, sqlite3_errmsg(db));
        return false;
    }
    int col = 1;
    sqlite3_bind_int64(st, col++, height);
    if (row_status)
        sqlite3_bind_text(st, col++, row_status, -1, SQLITE_STATIC);
    sqlite3_bind_int(st, col++, ok);
    if (hash_col) {
        if (hash) sqlite3_bind_blob(st, col++, hash, 32, SQLITE_STATIC);
        else      sqlite3_bind_null(st, col++);
    }
    sqlite3_bind_blob(st, col++, itag, STAGE_ROW_ITAG_LEN, SQLITE_STATIC);
    bool done = sqlite3_step(st) == SQLITE_DONE;
    sqlite3_finalize(st);
    return done;
}

/* A fully consistent ok=1 row across all stage logs at height h, with the
 * validate_headers.hash and script_validate.block_hash AGREEING (tag 0). */
static bool put_consistent_height(sqlite3 *db, int32_t h)
{
    uint8_t hh[32];
    synth_hash(hh, h, 0);
    return put_header_admit(db, h, hh)
        && put_tagged_row(db, "validate_headers_log", "hash", h, 1, hh, NULL)
        && put_tagged_row(db, "script_validate_log", "block_hash", h, 1, hh, "ok")
        && put_tagged_row(db, "body_persist_log", NULL, h, 1, NULL, NULL)
        && put_tagged_row(db, "proof_validate_log", "block_hash", h, 1, hh, NULL)
        && put_tagged_row(db, "utxo_apply_log", NULL, h, 1, NULL, NULL)
        && put_utxo_delta(db, h, hh)
        && put_tagged_row(db, "tip_finalize_log", NULL, h, 1, NULL, "ok");
}

/* Raw UPDATE of just the ok column (leaving the itag stale) — models a flipped
 * verdict bit that a naive fold would trust. */
static bool corrupt_ok_only(sqlite3 *db, const char *table, int32_t height,
                            int new_ok)
{
    char sql[128];
    snprintf(sql, sizeof(sql), "UPDATE %s SET ok=? WHERE height=?", table);
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) != SQLITE_OK)
        return false;
    sqlite3_bind_int(st, 1, new_ok);
    sqlite3_bind_int(st, 2, height);
    bool ok = sqlite3_step(st) == SQLITE_DONE && sqlite3_changes(db) == 1;
    sqlite3_finalize(st);
    return ok;
}

static bool itag_mismatch_event_seen(void)
{
    static char buf[8192];
    size_t n = event_dump_json(buf, sizeof(buf), 64);
    if (n == 0 || n >= sizeof(buf))
        buf[sizeof(buf) - 1] = '\0';
    return strstr(buf, "stage_row_itag_mismatch") != NULL;
}

/* ── cases ───────────────────────────────────────────────────────────── */

/* (1) Clean tagged rows fold to the SAME H* as an untagged fixture would —
 *     every valid tag verifies and the contiguity result is unchanged. */
static int case_clean_rows_identical(void)
{
    int failures = 0;
    sqlite3 *db = NULL;
    if (sqlite3_open(":memory:", &db) != SQLITE_OK) return 1;
    reducer_frontier_provable_tip_reset();
    HI_CHECK("clean: schema", build_schema(db));
    HI_CHECK("clean: proven authority", stamp_proven_authority(db, A + 1));

    const int32_t tip = A + 6;
    bool built = true;
    for (int32_t h = A + 1; h <= tip; h++)
        built = built && put_consistent_height(db, h);
    HI_CHECK("clean: rows built", built);
    HI_CHECK("clean: cursors", set_all_cursors(db, tip + 1));

    int32_t hstar = -1, served = -1;
    bool ok = reducer_frontier_compute_hstar(db, &hstar, &served);
    HI_CHECK("clean: returns true", ok);
    HI_CHECK("clean: hstar == tip (tags do not lower a clean fold)",
             hstar == tip);
    HI_CHECK("clean: no false mismatch event", !itag_mismatch_event_seen());

    sqlite3_close(db);
    return failures;
}

/* (2) THE LAW: flipping a FAIL row's ok bit 0 -> 1 (leaving the stale tag) must
 *     NOT advance H* past that height. Without the tag the fold would climb to
 *     the tip; the integrity check pins it at the last verified height and
 *     fires a typed error. */
static int case_flipped_ok_does_not_raise(void)
{
    int failures = 0;
    sqlite3 *db = NULL;
    if (sqlite3_open(":memory:", &db) != SQLITE_OK) return 1;
    reducer_frontier_provable_tip_reset();
    HI_CHECK("flip: schema", build_schema(db));
    HI_CHECK("flip: proven authority", stamp_proven_authority(db, A + 1));

    const int32_t tip = A + 6;
    const int32_t bad = A + 3;   /* the corrupted height */
    bool built = true;
    for (int32_t h = A + 1; h <= tip; h++) {
        if (h == bad) {
            /* body_persist FAILS here: baseline H* = bad-1. The row is tagged
             * over ok=0 (its true, honest verdict). status is passed NULL to
             * mirror production EXACTLY: body_persist_log has no `status` column
             * and body_persist_log_insert() computes its itag with status=NULL
             * (body_persist is not a status-covered log, so the value never
             * enters the tag). A non-NULL status here made put_tagged_row emit
             * an INSERT naming a `status` column that does not exist. */
            uint8_t hh[32];
            synth_hash(hh, h, 0);
            built = built
                && put_header_admit(db, h, hh)
                && put_tagged_row(db, "validate_headers_log", "hash", h, 1, hh, NULL)
                && put_tagged_row(db, "script_validate_log", "block_hash", h, 1, hh, "ok")
                && put_tagged_row(db, "body_persist_log", NULL, h, 0, NULL, NULL)
                && put_tagged_row(db, "proof_validate_log", "block_hash", h, 1, hh, NULL)
                && put_tagged_row(db, "utxo_apply_log", NULL, h, 1, NULL, NULL)
                && put_utxo_delta(db, h, hh)
                && put_tagged_row(db, "tip_finalize_log", NULL, h, 1, NULL, "ok");
        } else {
            built = built && put_consistent_height(db, h);
        }
    }
    HI_CHECK("flip: rows built", built);
    HI_CHECK("flip: cursors", set_all_cursors(db, tip + 1));

    /* Baseline: the honest ok=0 at `bad` caps H* at bad-1. */
    int32_t hstar = -1, served = -1;
    bool ok = reducer_frontier_compute_hstar(db, &hstar, &served);
    HI_CHECK("flip: baseline returns true", ok);
    HI_CHECK("flip: baseline hstar == bad-1", hstar == bad - 1);

    /* Corrupt: flip body_persist ok 0 -> 1, leaving the tag (over ok=0) stale.
     * A naive fold would now climb to the tip. */
    HI_CHECK("flip: corrupt ok 0->1", corrupt_ok_only(db, "body_persist_log", bad, 1));

    /* Fresh boot so the watermark re-verifies the whole range. */
    reducer_frontier_provable_tip_reset();
    hstar = -1; served = -1;
    ok = reducer_frontier_compute_hstar(db, &hstar, &served);
    HI_CHECK("flip: post-corrupt returns true", ok);
    HI_CHECK("flip: H* did NOT advance past the corrupted height (== bad-1)",
             hstar == bad - 1);
    HI_CHECK("flip: H* is NOT raised to the tip", hstar != tip);
    HI_CHECK("flip: typed mismatch event fired", itag_mismatch_event_seen());

    sqlite3_close(db);
    return failures;
}

/* (3) The tag verify primitive itself: MATCH for a good tag, MISMATCH for a
 *     changed field, ABSENT for a missing/short tag. */
static int case_verify_primitive(void)
{
    int failures = 0;
    uint8_t tag[STAGE_ROW_ITAG_LEN];
    stage_row_itag_compute("utxo_apply_log", 12345, 1, "verified", 8, tag);

    HI_CHECK("verify: exact match",
             stage_row_itag_verify("utxo_apply_log", 12345, 1, "verified", 8,
                                   tag, sizeof(tag)) == STAGE_ROW_ITAG_MATCH);
    HI_CHECK("verify: flipped ok -> mismatch",
             stage_row_itag_verify("utxo_apply_log", 12345, 0, "verified", 8,
                                   tag, sizeof(tag)) == STAGE_ROW_ITAG_MISMATCH);
    HI_CHECK("verify: changed height -> mismatch",
             stage_row_itag_verify("utxo_apply_log", 12346, 1, "verified", 8,
                                   tag, sizeof(tag)) == STAGE_ROW_ITAG_MISMATCH);
    HI_CHECK("verify: changed status -> mismatch (covered log)",
             stage_row_itag_verify("utxo_apply_log", 12345, 1, "unverified", 10,
                                   tag, sizeof(tag)) == STAGE_ROW_ITAG_MISMATCH);
    HI_CHECK("verify: wrong table -> mismatch",
             stage_row_itag_verify("proof_validate_log", 12345, 1, "verified", 8,
                                   tag, sizeof(tag)) == STAGE_ROW_ITAG_MISMATCH);
    HI_CHECK("verify: NULL tag -> absent",
             stage_row_itag_verify("utxo_apply_log", 12345, 1, "verified", 8,
                                   NULL, 0) == STAGE_ROW_ITAG_ABSENT);
    HI_CHECK("verify: short tag -> absent",
             stage_row_itag_verify("utxo_apply_log", 12345, 1, "verified", 8,
                                   tag, 4) == STAGE_ROW_ITAG_ABSENT);

    /* A non-covered log ignores status in the tag: two different statuses must
     * produce the SAME verdict (both MATCH), proving status is not folded in. */
    uint8_t tf[STAGE_ROW_ITAG_LEN];
    stage_row_itag_compute("tip_finalize_log", 7, 1, "ok", 2, tf);
    HI_CHECK("verify: tip_finalize ignores status in tag",
             stage_row_itag_verify("tip_finalize_log", 7, 1, "anchor", 6,
                                   tf, sizeof(tf)) == STAGE_ROW_ITAG_MATCH);
    return failures;
}

/* (4) Migration: a legacy table with untagged rows gets tags backfilled by the
 *     production ensure_schema, and re-running is idempotent. */
static int case_migration_backfill_idempotent(void)
{
    int failures = 0;
    sqlite3 *db = NULL;
    if (sqlite3_open(":memory:", &db) != SQLITE_OK) return 1;

    /* Legacy schema: body_persist_log WITHOUT the itag column, plus the
     * progress_meta the backfill flag lives in. */
    char *err = NULL;
    bool schema = sqlite3_exec(db,
        "CREATE TABLE body_persist_log ("
        "  height INTEGER PRIMARY KEY, source TEXT NOT NULL,"
        "  ok INTEGER NOT NULL, persisted_at INTEGER NOT NULL);"
        "CREATE TABLE IF NOT EXISTS progress_meta (key TEXT PRIMARY KEY, value BLOB);"
        "INSERT INTO body_persist_log VALUES(100,'verified',1,0);"
        "INSERT INTO body_persist_log VALUES(101,'upstream_failed',0,0);"
        "INSERT INTO body_persist_log VALUES(102,'verified',1,0);",
        NULL, NULL, &err) == SQLITE_OK;
    if (err) sqlite3_free(err);
    HI_CHECK("migrate: legacy schema + untagged rows", schema);

    /* Production ensure_schema: ADD COLUMN itag + one-time backfill. */
    HI_CHECK("migrate: ensure_schema (adds itag + backfills)",
             body_persist_log_ensure_schema(db));

    /* Every row now carries a 16-byte tag that verifies against its own
     * (height, ok). */
    int verified = 0, rows = 0;
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db,
            "SELECT height, ok, itag FROM body_persist_log ORDER BY height",
            -1, &st, NULL) == SQLITE_OK) {
        while (sqlite3_step(st) == SQLITE_ROW) {
            rows++;
            int64_t h = sqlite3_column_int64(st, 0);
            int ok = sqlite3_column_int(st, 1);
            const void *tag = sqlite3_column_type(st, 2) == SQLITE_BLOB
                                  ? sqlite3_column_blob(st, 2) : NULL;
            size_t tag_len = tag ? (size_t)sqlite3_column_bytes(st, 2) : 0;
            if (stage_row_itag_verify("body_persist_log", h, ok, NULL, 0,
                                      tag, tag_len) == STAGE_ROW_ITAG_MATCH)
                verified++;
        }
        sqlite3_finalize(st);
    }
    HI_CHECK("migrate: all 3 rows backfilled + verify", rows == 3 && verified == 3);

    /* The durable flag is set so later boots skip the O(rows) scan. */
    bool flag = false;
    st = NULL;
    if (sqlite3_prepare_v2(db,
            "SELECT value FROM progress_meta WHERE key='itag_bf:body_persist_log'",
            -1, &st, NULL) == SQLITE_OK) {
        if (sqlite3_step(st) == SQLITE_ROW &&
            sqlite3_column_bytes(st, 0) == 1 &&
            ((const uint8_t *)sqlite3_column_blob(st, 0))[0] == 1)
            flag = true;
        sqlite3_finalize(st);
    }
    HI_CHECK("migrate: durable backfill flag set", flag);

    /* Idempotent: a second ensure_schema is a no-op and the rows stay valid. */
    HI_CHECK("migrate: ensure_schema idempotent",
             body_persist_log_ensure_schema(db));
    /* A production insert on the migrated table tags its new row too. */
    HI_CHECK("migrate: production insert tags new row",
             body_persist_log_insert(db, 103, "verified", true));
    int ok103 = 0;
    st = NULL;
    if (sqlite3_prepare_v2(db,
            "SELECT ok, itag FROM body_persist_log WHERE height=103",
            -1, &st, NULL) == SQLITE_OK) {
        if (sqlite3_step(st) == SQLITE_ROW) {
            const void *tag = sqlite3_column_type(st, 1) == SQLITE_BLOB
                                  ? sqlite3_column_blob(st, 1) : NULL;
            size_t tag_len = tag ? (size_t)sqlite3_column_bytes(st, 1) : 0;
            ok103 = stage_row_itag_verify("body_persist_log", 103,
                                          sqlite3_column_int(st, 0), NULL, 0,
                                          tag, tag_len) == STAGE_ROW_ITAG_MATCH;
        }
        sqlite3_finalize(st);
    }
    HI_CHECK("migrate: new production row verifies", ok103);

    sqlite3_close(db);
    return failures;
}

/* (5) Performance: build ~100k rows across all six logs and measure the fold
 *     cost with the watermark COLD (first fold, full per-row verify) vs WARM
 *     (subsequent fold, O(delta)). The warm fold must be materially cheaper —
 *     that is what keeps a normal at-tip fold O(delta), not O(chain). */
static int case_fold_perf(void)
{
    int failures = 0;
    sqlite3 *db = NULL;
    if (sqlite3_open(":memory:", &db) != SQLITE_OK) return 1;
    HI_CHECK("perf: schema", build_schema(db));
    HI_CHECK("perf: proven authority", stamp_proven_authority(db, A + 1));
    (void)sqlite3_exec(db, "PRAGMA journal_mode=MEMORY; PRAGMA synchronous=OFF;",
                       NULL, NULL, NULL);

    const int32_t N = 100000;
    const int32_t tip = A + N;
    bool built = true;
    (void)sqlite3_exec(db, "BEGIN", NULL, NULL, NULL);
    for (int32_t h = A + 1; h <= tip && built; h++)
        built = put_consistent_height(db, h);
    (void)sqlite3_exec(db, built ? "COMMIT" : "ROLLBACK", NULL, NULL, NULL);
    HI_CHECK("perf: 100k-row fixture built", built);
    HI_CHECK("perf: cursors", set_all_cursors(db, tip + 1));

    /* COLD fold: watermark reset -> every scanned row is tag-verified. */
    reducer_frontier_provable_tip_reset();
    int32_t hstar = -1, served = -1;
    int64_t t0 = platform_time_monotonic_us();
    bool ok1 = reducer_frontier_compute_hstar(db, &hstar, &served);
    int64_t cold_us = platform_time_monotonic_us() - t0;

    /* WARM fold: the watermark now sits at H*, so no row below it is re-hashed. */
    t0 = platform_time_monotonic_us();
    bool ok2 = reducer_frontier_compute_hstar(db, &hstar, &served);
    int64_t warm_us = platform_time_monotonic_us() - t0;

    HI_CHECK("perf: cold fold ok", ok1);
    HI_CHECK("perf: warm fold ok", ok2);
    HI_CHECK("perf: hstar == tip", hstar == tip);
    printf("hstar_integrity: PERF 100k rows x6 logs: cold(full-verify)=%lld us  "
           "warm(watermark)=%lld us  saved=%lld us\n",
           (long long)cold_us, (long long)warm_us,
           (long long)(cold_us - warm_us));
    /* The warm fold skips per-row hashing below the watermark, so it must be
     * cheaper than the cold full-verify fold (allow a generous margin for a
     * loaded parallel test host). */
    HI_CHECK("perf: warm fold cheaper than cold (watermark saves work)",
             warm_us <= cold_us);

    /* The warm prefix is trusted only while immutable. A repair/corruption
     * that changes it on the same connection must revoke the watermark; an
     * append above H* remains O(delta). This is the lifecycle hole regression
     * caught by the full parallel push gate. */
    const int32_t hole = tip - 7;
    char delete_sql[128];
    snprintf(delete_sql, sizeof(delete_sql),
             "DELETE FROM script_validate_log WHERE height=%d", hole);
    HI_CHECK("perf: below-watermark hole punched",
             sqlite3_exec(db, delete_sql, NULL, NULL, NULL) == SQLITE_OK);
    hstar = -1;
    bool ok3 = reducer_frontier_compute_hstar(db, &hstar, &served);
    HI_CHECK("perf: mutation invalidates watermark", ok3 && hstar == hole - 1);

    sqlite3_close(db);
    return failures;
}

int test_hstar_integrity(void)
{
    int failures = 0;
    printf("\n--- hstar_integrity (W4-4 per-row integrity tag) ---\n");
    /* Initialize the event ring so the typed mismatch event is recorded and the
     * flip case can assert it fired (event_emit no-ops until initialized). */
    event_log_init();
    failures += case_clean_rows_identical();
    failures += case_flipped_ok_does_not_raise();
    failures += case_verify_primitive();
    failures += case_migration_backfill_idempotent();
    failures += case_fold_perf();
    if (failures == 0)
        printf("hstar_integrity: all cases passed\n");
    else
        printf("hstar_integrity: %d failure(s)\n", failures);
    return failures;
}
