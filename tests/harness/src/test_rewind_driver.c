/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Dedicated unit test for the generic recovery driver
 * rewind_to_nearest_self_verified_base() (engine/jobs/src/rewind_driver.c).
 *
 * The driver has SEVEN distinct branches, previously exercised only
 * incidentally by ONE scenario (the tip_label_divergence -> driver wiring case
 * in test_validation_pack_conditions.c, which only reached branch 3). This
 * group drives each branch directly against a throwaway progress.kv built with
 * the same real stage-log schema the production *_log_store.c modules emit
 * (the test_reducer_frontier.c fixture style) so H* / base-selection are the
 * REAL computations, not mocks:
 *
 *   1. no progress-db open            -> false (hard store error, no escalate)
 *   2. H*-compute failure             -> false (malformed durable base key)
 *   3. no self-verified base found    -> escalate ONCE (typed rewind_driver.<tag>)
 *   4. base already at/above H*       -> no-op + clears any stale blocker
 *   5. stage_rederive_range store err -> false (missing body_fetch_log table)
 *   6. refused_no_inverse / not-ok    -> escalate ONCE (2nd call never multiplies)
 *   7. success                        -> ok + clears + reports base/rewound
 *
 * Plus THE sovereignty property: when both a borrowed finalized_utxo_sha3
 * (HIGHER) and a self-verified rung (LOWER, the compiled checkpoint) exist, the
 * driver rewinds to the LOWER self-verified one — a borrowed root can never win.
 *
 * Fixtures write rows with plain sqlite3_exec/INSERT — TEST scaffolding
 * building the durable image, not production reducer code, so it does not route
 * through the AR lifecycle (mirrors test_reducer_frontier.c's own note). The
 * driver + reducer_frontier_compute_hstar + stage_rederive_range are the units
 * under test. */

#include "test/test_core.h"

#include "coins/utxo_commitment.h"
#include "config/db_service.h"
#include "config/runtime.h"
#include "jobs/reducer_frontier.h"
#include "jobs/rewind_driver.h"
#include "models/database.h"
#include "storage/progress_store.h"
#include "util/blocker.h"

#include <sqlite3.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define RD_CHECK(name, expr) do {                                  \
    printf("rewind_driver: %s... ", (name));                       \
    if (expr) { printf("OK\n"); }                                  \
    else { printf("FAIL\n"); failures++; }                         \
} while (0)

/* The compiled SHA3 UTXO checkpoint anchor the driver's base selector always
 * exposes as a self-verified rung (self_derived=true, height A). Fixtures sit
 * just above it so the contiguous-prefix walk has a few heights to traverse
 * without building three million rows. */
#define A REDUCER_FRONTIER_TRUSTED_ANCHOR  /* 3056758 */

/* ── fixture builders (test_reducer_frontier.c parity, trimmed) ─────────── */

/* Base schema: every table reducer_frontier_compute_hstar / stage_rederive_
 * range read/write EXCEPT body_fetch_log — deliberately omitted so the
 * store-error case can trigger a "no such table" failure inside the body-stage
 * rewind loop. rd_build_schema_full() adds body_fetch_log for the paths that
 * must commit. */
static bool rd_exec(sqlite3 *db, const char *sql)
{
    char *err = NULL;
    if (sqlite3_exec(db, sql, NULL, NULL, &err) != SQLITE_OK) {
        fprintf(stderr, "[test_rewind_driver] exec: %s\n", err ? err : "(null)");
        sqlite3_free(err);
        return false;
    }
    return true;
}

static bool rd_build_schema(sqlite3 *db)
{
    return rd_exec(db,
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
        "  fail_reason TEXT, validated_at INTEGER);"
        "CREATE TABLE IF NOT EXISTS script_validate_log ("
        "  height INTEGER PRIMARY KEY, status TEXT, ok INTEGER NOT NULL,"
        "  block_hash BLOB);"
        "CREATE TABLE IF NOT EXISTS body_persist_log ("
        "  height INTEGER PRIMARY KEY, source TEXT, ok INTEGER NOT NULL);"
        "CREATE TABLE IF NOT EXISTS proof_validate_log ("
        "  height INTEGER PRIMARY KEY, status TEXT, ok INTEGER NOT NULL,"
        "  block_hash BLOB);"
        "CREATE TABLE IF NOT EXISTS utxo_apply_log ("
        "  height INTEGER PRIMARY KEY, status TEXT, ok INTEGER NOT NULL,"
        "  spent_count INTEGER, added_count INTEGER);"
        "CREATE TABLE IF NOT EXISTS utxo_apply_delta ("
        "  height INTEGER PRIMARY KEY, branch_hash BLOB NOT NULL,"
        "  spent_blob BLOB NOT NULL, added_blob BLOB NOT NULL);"
        "CREATE TABLE IF NOT EXISTS tip_finalize_log ("
        "  height INTEGER PRIMARY KEY, status TEXT, ok INTEGER NOT NULL,"
        "  tip_hash BLOB);");
}

static bool rd_build_schema_full(sqlite3 *db)
{
    return rd_build_schema(db) &&
           rd_exec(db,
        "CREATE TABLE IF NOT EXISTS body_fetch_log ("
        "  height INTEGER PRIMARY KEY, source TEXT, ok INTEGER NOT NULL);");
}

/* Stamp coins_kv proven-authority so compute_hstar treats the baked
 * TRUSTED_ANCHOR as a real finality floor (mirrors test_reducer_frontier.c). */
static bool rd_stamp_proven_authority(sqlite3 *db, int64_t applied_height)
{
    if (!rd_exec(db,
            "CREATE TABLE IF NOT EXISTS coins(k BLOB PRIMARY KEY, v BLOB);"
            "INSERT OR IGNORE INTO coins(k,v) VALUES(x'00', x'00');"))
        return false;
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

static bool rd_set_cursor(sqlite3 *db, const char *name, int64_t cursor)
{
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db,
            "INSERT INTO stage_cursor(name,cursor,updated_at) VALUES(?,?,0) "
            "ON CONFLICT(name) DO UPDATE SET "
            "cursor=excluded.cursor, updated_at=excluded.updated_at",
            -1, &st, NULL) != SQLITE_OK)
        return false;
    sqlite3_bind_text(st, 1, name, -1, SQLITE_STATIC);
    sqlite3_bind_int64(st, 2, cursor);
    bool ok = sqlite3_step(st) == SQLITE_DONE;
    sqlite3_finalize(st);
    return ok;
}

static bool rd_set_all_cursors(sqlite3 *db, int64_t c)
{
    return rd_set_cursor(db, "validate_headers", c)
        && rd_set_cursor(db, "body_fetch", c)
        && rd_set_cursor(db, "body_persist", c)
        && rd_set_cursor(db, "proof_validate", c)
        && rd_set_cursor(db, "script_validate", c)
        && rd_set_cursor(db, "utxo_apply", c)
        && rd_set_cursor(db, "tip_finalize", c);
}

static void rd_synth_hash(uint8_t out[32], int32_t h, uint8_t tag)
{
    memset(out, 0, 32);
    out[0] = (uint8_t)(h & 0xff);
    out[1] = (uint8_t)((h >> 8) & 0xff);
    out[2] = (uint8_t)((h >> 16) & 0xff);
    out[31] = tag;
}

/* Insert a (height, ok[, status][, hash]) row; the profile-bound stages carry
 * the "verified" evidence label on ok=1, matching production. */
static bool rd_put_log_row(sqlite3 *db, const char *table, const char *hash_col,
                           int32_t height, int ok, const uint8_t hash[32],
                           const char *status)
{
    char sql[256];
    bool profile_bound = strcmp(table, "script_validate_log") == 0 ||
                         strcmp(table, "proof_validate_log") == 0 ||
                         strcmp(table, "utxo_apply_log") == 0;
    const char *row_status = profile_bound && ok == 1 ? "verified" : status;
    if (hash_col && row_status)
        snprintf(sql, sizeof(sql),
                 "INSERT INTO %s(height,status,ok,%s) VALUES(?,?,?,?)",
                 table, hash_col);
    else if (hash_col)
        snprintf(sql, sizeof(sql),
                 "INSERT INTO %s(height,ok,%s) VALUES(?,?,?)", table, hash_col);
    else if (row_status)
        snprintf(sql, sizeof(sql),
                 "INSERT INTO %s(height,status,ok) VALUES(?,?,?)", table);
    else
        snprintf(sql, sizeof(sql),
                 "INSERT INTO %s(height,ok) VALUES(?,?)", table);

    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) != SQLITE_OK) {
        fprintf(stderr, "[test_rewind_driver] prepare %s: %s\n",
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
    bool done = sqlite3_step(st) == SQLITE_DONE;
    sqlite3_finalize(st);
    return done;
}

static bool rd_put_header_admit(sqlite3 *db, int32_t h, const uint8_t hash[32])
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

static bool rd_put_utxo_delta(sqlite3 *db, int32_t h, const uint8_t hash[32])
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

/* A full consistent ok=1 row across ALL stage logs at height h. */
static bool rd_put_consistent_height(sqlite3 *db, int32_t h)
{
    uint8_t hh[32];
    rd_synth_hash(hh, h, 0);
    return rd_put_header_admit(db, h, hh)
        && rd_put_log_row(db, "validate_headers_log", "hash", h, 1, hh, NULL)
        && rd_put_log_row(db, "script_validate_log", "block_hash", h, 1, hh, "ok")
        && rd_put_log_row(db, "body_persist_log", NULL, h, 1, NULL, NULL)
        && rd_put_log_row(db, "proof_validate_log", "block_hash", h, 1, hh, NULL)
        && rd_put_log_row(db, "utxo_apply_log", NULL, h, 1, NULL, NULL)
        && rd_put_utxo_delta(db, h, hh)
        && rd_put_log_row(db, "tip_finalize_log", NULL, h, 1, NULL, "ok");
}

/* A rewindable utxo frontier row at height h (ok=1 utxo_apply_log + a
 * matching empty inverse delta). Placed at the base height A so the coins
 * inverse-rewind of [A, utxo_cursor) has a complete row set to walk and
 * COMMITS instead of refusing. */
static bool rd_put_utxo_frontier_row(sqlite3 *db, int32_t h)
{
    uint8_t hh[32];
    rd_synth_hash(hh, h, 0);
    return rd_put_log_row(db, "utxo_apply_log", NULL, h, 1, NULL, NULL)
        && rd_put_utxo_delta(db, h, hh);
}

/* clamp-up rows: a script/header ok=0 at A+1 pins H* exactly at the anchor A
 * (the proven test_reducer_frontier.c case_clamp_up topology). */
static bool rd_put_clamp_up_at_anchor(sqlite3 *db)
{
    uint8_t zero[32] = {0};
    return rd_put_log_row(db, "script_validate_log", "block_hash", A + 1, 0,
                          NULL, "not_script_valid")
        && rd_put_log_row(db, "validate_headers_log", "hash", A + 1, 0, zero,
                          NULL);
}

/* Count blocker_snapshot_all() entries whose id matches exactly — proves an
 * escalation is a single updated-in-place record, never a growing set. */
static int rd_count_blockers_named(const char *id)
{
    struct blocker_snapshot snaps[BLOCKER_CAP];
    int n = blocker_snapshot_all(snaps, BLOCKER_CAP);
    int count = 0;
    for (int i = 0; i < n; i++)
        if (strcmp(snaps[i].id, id) == 0)
            count++;
    return count;
}

/* Open a fresh throwaway progress.kv in a tmp dir. Caller closes + cleans. */
static sqlite3 *rd_open_progress(char dir[256], const char *tag)
{
    test_make_tmpdir(dir, 256, "rewind_driver", tag);
    progress_store_close();
    if (!progress_store_open(dir))
        return NULL;
    return progress_store_db();
}

static void rd_reset(void)
{
    blocker_reset_for_testing();
    app_runtime_set_current(NULL);
}

/* ── cases ───────────────────────────────────────────────────────────── */

/* Branch 1: no progress-db open -> hard store error (false), NO escalation. */
static int case_no_progress_db(void)
{
    int failures = 0;
    rd_reset();
    progress_store_close();  /* progress_store_db() -> NULL */

    struct rewind_driver_result out;
    bool rv = rewind_to_nearest_self_verified_base(INT32_MAX, "unit-nodb",
                                                   "nodb", &out);
    RD_CHECK("no-db: returns false (hard store error)", !rv);
    RD_CHECK("no-db: not escalated (below the escalate seam)", !out.escalated);
    RD_CHECK("no-db: not ok / not nothing", !out.ok && !out.nothing);
    RD_CHECK("no-db: hstar stays -1 (never computed)", out.hstar == -1);
    RD_CHECK("no-db: named no blocker",
             !blocker_exists("rewind_driver.nodb"));
    return failures;
}

/* Branch 2: H*-compute failure -> false. A malformed (TEXT-typed) durable
 * trusted-base key makes reducer_frontier_compute_hstar fail closed (the
 * proven test_reducer_frontier.c "TEXT authority fails closed" topology), so
 * the driver returns false BEFORE any base selection / escalation. */
static int case_hstar_compute_failure(void)
{
    int failures = 0;
    rd_reset();
    char dir[256];
    sqlite3 *db = rd_open_progress(dir, "hstarfail");
    RD_CHECK("hstar-fail: progress store opens + schema",
             db && rd_build_schema(db));
    RD_CHECK("hstar-fail: proven authority",
             db && rd_stamp_proven_authority(db, A + 101));
    /* A well-formed durable base key, then corrupt it to a TEXT value —
     * compute_hstar reads it and MUST fail closed on the wrong storage class. */
    RD_CHECK("hstar-fail: malformed durable base key planted",
             db && rd_exec(db,
                 "INSERT OR REPLACE INTO progress_meta(key,value) "
                 "VALUES('" REDUCER_TRUSTED_BASE_HEIGHT_KEY
                 "', CAST('12345678' AS TEXT))"));

    struct rewind_driver_result out;
    bool rv = rewind_to_nearest_self_verified_base(INT32_MAX, "unit-hstarfail",
                                                   "hstarfail", &out);
    RD_CHECK("hstar-fail: returns false", !rv);
    RD_CHECK("hstar-fail: not escalated", !out.escalated);
    RD_CHECK("hstar-fail: hstar never set (-1)", out.hstar == -1);
    RD_CHECK("hstar-fail: named no blocker",
             !blocker_exists("rewind_driver.hstarfail"));

    progress_store_close();
    test_cleanup_tmpdir(dir);
    return failures;
}

/* Branch 3: no self-verified base at/below H* -> escalate ONCE.
 * A schema-only progress.kv (no proven-authority stamp) drops H* to 0 via
 * compute_hstar's phantom-anchor guard — cleanly, not a DB error — so the
 * ceiling is 0 and the compiled checkpoint at A (=3,056,758) is ABOVE it: no
 * self-verified base exists at/below the ceiling and the driver names its typed
 * dependency blocker. A second call against the same persistent cause must NOT
 * multiply that named blocker. */
static int case_no_base_escalates_once(void)
{
    int failures = 0;
    rd_reset();
    char dir[256];
    sqlite3 *db = rd_open_progress(dir, "nobase");
    RD_CHECK("no-base: progress store opens + schema",
             db && rd_build_schema(db));
    RD_CHECK("no-base: cursors", db && rd_set_all_cursors(db, 1));

    const char *bid = "rewind_driver.nobase";
    struct rewind_driver_result out;
    bool rv = rewind_to_nearest_self_verified_base(INT32_MAX, "unit-nobase",
                                                   "nobase", &out);
    RD_CHECK("no-base: returns true (clean escalation, not an error)", rv);
    RD_CHECK("no-base: H* computed to 0 (phantom-anchor guard)",
             out.hstar == 0);
    RD_CHECK("no-base: out.escalated", out.escalated);
    RD_CHECK("no-base: no base selected (base_height stays -1)",
             out.base_height == -1);
    RD_CHECK("no-base: driver named its typed dependency blocker",
             blocker_exists(bid));
    RD_CHECK("no-base: exactly one named blocker after first drive",
             rd_count_blockers_named(bid) == 1);

    /* Second drive, same persistent cause: escalate ONCE — the named blocker
     * is updated in place, never a second distinct entry. */
    bool rv2 = rewind_to_nearest_self_verified_base(INT32_MAX, "unit-nobase",
                                                    "nobase", &out);
    RD_CHECK("no-base: second drive still escalates (true)", rv2);
    RD_CHECK("no-base: STILL exactly one named blocker (escalate ONCE)",
             rd_count_blockers_named(bid) == 1);

    progress_store_close();
    test_cleanup_tmpdir(dir);
    return failures;
}

/* Branch 4: base already at/above H* -> no-op, and clears any stale blocker.
 * Proven authority + a clamp-up ok=0 at A+1 pins H*=A; the compiled checkpoint
 * base at A satisfies base.height >= H*, so the driver clears the escalation
 * blocker and reports out.nothing. A stale blocker is pre-set to prove the
 * clear fires. */
static int case_base_at_or_above_hstar_noop(void)
{
    int failures = 0;
    rd_reset();
    char dir[256];
    sqlite3 *db = rd_open_progress(dir, "noop");
    RD_CHECK("noop: progress store opens + schema", db && rd_build_schema(db));
    RD_CHECK("noop: proven authority",
             db && rd_stamp_proven_authority(db, A + 1));
    RD_CHECK("noop: clamp-up rows pin H* at anchor",
             db && rd_put_clamp_up_at_anchor(db));
    RD_CHECK("noop: cursors", db && rd_set_all_cursors(db, A + 2));

    const char *bid = "rewind_driver.noop";
    struct blocker_record stale;
    RD_CHECK("noop: stale escalation blocker pre-set",
             blocker_init(&stale, bid, "test", BLOCKER_DEPENDENCY,
                          "stale escalation to be cleared") &&
             blocker_set(&stale) >= 0);
    RD_CHECK("noop: stale blocker present before drive", blocker_exists(bid));

    struct rewind_driver_result out;
    bool rv = rewind_to_nearest_self_verified_base(INT32_MAX, "unit-noop",
                                                   "noop", &out);
    RD_CHECK("noop: returns true", rv);
    RD_CHECK("noop: H* pinned at anchor A", out.hstar == A);
    RD_CHECK("noop: out.nothing (no rewind needed)", out.nothing);
    RD_CHECK("noop: not escalated / not ok", !out.escalated && !out.ok);
    RD_CHECK("noop: base is the compiled checkpoint at A", out.base_height == A);
    RD_CHECK("noop: base is self-derived", out.base_self_derived);
    RD_CHECK("noop: base kind is compiled_checkpoint",
             strcmp(out.base_kind, "compiled_checkpoint") == 0);
    RD_CHECK("noop: stale escalation blocker CLEARED", !blocker_exists(bid));

    progress_store_close();
    test_cleanup_tmpdir(dir);
    return failures;
}

/* Branch 5: stage_rederive_range hard store error -> false.
 * H*=A+5 with the compiled checkpoint base at A (< H*), and a full rewindable
 * utxo frontier over [A, A+6) so the coins inverse-rewind SUCCEEDS — but the
 * base schema OMITS body_fetch_log, so the very first body-stage delete in the
 * rewind loop hits "no such table" and stage_rederive_range returns false. The
 * driver propagates that as a hard store error (false), NOT an escalation. */
static int case_stage_rederive_store_error(void)
{
    int failures = 0;
    rd_reset();
    char dir[256];
    sqlite3 *db = rd_open_progress(dir, "storeerr");
    /* rd_build_schema: NO body_fetch_log on purpose. */
    RD_CHECK("store-err: progress store opens + schema",
             db && rd_build_schema(db));
    RD_CHECK("store-err: proven authority",
             db && rd_stamp_proven_authority(db, A + 1));
    bool built = db != NULL;
    for (int32_t h = A + 1; h <= A + 5; h++)
        built = built && rd_put_consistent_height(db, h);
    /* Complete the rewindable frontier down to the base height A. */
    built = built && rd_put_utxo_frontier_row(db, A);
    RD_CHECK("store-err: rows built (H*=A+5, frontier covers [A,A+6))", built);
    RD_CHECK("store-err: cursors at A+6", db && rd_set_all_cursors(db, A + 6));

    const char *bid = "rewind_driver.storeerr";
    struct rewind_driver_result out;
    bool rv = rewind_to_nearest_self_verified_base(INT32_MAX, "unit-storeerr",
                                                   "storeerr", &out);
    RD_CHECK("store-err: returns false (hard store error from rederive)", !rv);
    RD_CHECK("store-err: not escalated (store error is not a refusal)",
             !out.escalated);
    RD_CHECK("store-err: not ok", !out.ok);
    RD_CHECK("store-err: base was selected before the store error (A)",
             out.base_height == A);
    RD_CHECK("store-err: named no blocker (false path never escalates)",
             !blocker_exists(bid));

    progress_store_close();
    test_cleanup_tmpdir(dir);
    return failures;
}

/* Branch 6: stage_rederive_range LCC refusal (refused_no_inverse) -> escalate
 * ONCE. Same H*=A+5 / base-A topology, but the first suffix height A+1 carries
 * a malformed inverse blob. H* still reaches A+5 because the success log and
 * branch hash are present; the coin rewind of [A+1,A+6) REFUSES rather than
 * manufacture a coin hole.
 * The driver names its typed blocker; a second identical drive must not
 * multiply it. */
static int case_rederive_refused_escalates_once(void)
{
    int failures = 0;
    rd_reset();
    char dir[256];
    sqlite3 *db = rd_open_progress(dir, "refused");
    RD_CHECK("refused: progress store opens + schema (full)",
             db && rd_build_schema_full(db));
    RD_CHECK("refused: proven authority",
             db && rd_stamp_proven_authority(db, A + 1));
    bool built = db != NULL;
    for (int32_t h = A + 1; h <= A + 5; h++)
        built = built && rd_put_consistent_height(db, h);
    char corrupt_first_delta[112];
    snprintf(corrupt_first_delta, sizeof(corrupt_first_delta),
             "UPDATE utxo_apply_delta SET spent_blob=x'01' WHERE height=%d",
             A + 1);
    built = built && rd_exec(db, corrupt_first_delta);
    RD_CHECK("refused: rows built (inverse hole at first suffix height)", built);
    RD_CHECK("refused: cursors at A+6", db && rd_set_all_cursors(db, A + 6));

    const char *bid = "rewind_driver.refused";
    struct rewind_driver_result out;
    bool rv = rewind_to_nearest_self_verified_base(INT32_MAX, "unit-refused",
                                                   "refused", &out);
    RD_CHECK("refused: returns true (clean refusal, not a hard error)", rv);
    RD_CHECK("refused: H* reaches A+5", out.hstar == A + 5);
    RD_CHECK("refused: base selected at A (< H*)", out.base_height == A);
    RD_CHECK("refused: out.escalated (LCC refusal)", out.escalated);
    RD_CHECK("refused: not ok / not nothing", !out.ok && !out.nothing);
    RD_CHECK("refused: driver named its typed blocker", blocker_exists(bid));
    RD_CHECK("refused: exactly one named blocker after first drive",
             rd_count_blockers_named(bid) == 1);

    bool rv2 = rewind_to_nearest_self_verified_base(INT32_MAX, "unit-refused",
                                                    "refused", &out);
    RD_CHECK("refused: second drive still escalates (true)", rv2);
    RD_CHECK("refused: STILL exactly one named blocker (escalate ONCE)",
             rd_count_blockers_named(bid) == 1);

    progress_store_close();
    test_cleanup_tmpdir(dir);
    return failures;
}

/* Branch 7: success -> commit a rewind, clear the blocker, report the base +
 * rewound flags. H*=A+5, compiled checkpoint base at A (< H*), a full
 * rewindable frontier over [A, A+6), and the FULL schema (body_fetch_log
 * present) so the whole rewind transaction commits. A stale escalation blocker
 * is pre-set to prove the success path clears it. */
static int case_success(void)
{
    int failures = 0;
    rd_reset();
    char dir[256];
    sqlite3 *db = rd_open_progress(dir, "success");
    RD_CHECK("success: progress store opens + schema (full)",
             db && rd_build_schema_full(db));
    RD_CHECK("success: proven authority",
             db && rd_stamp_proven_authority(db, A + 1));
    bool built = db != NULL;
    for (int32_t h = A + 1; h <= A + 5; h++)
        built = built && rd_put_consistent_height(db, h);
    built = built && rd_put_utxo_frontier_row(db, A);
    RD_CHECK("success: rows built (H*=A+5, frontier covers [A,A+6))", built);
    RD_CHECK("success: cursors at A+6", db && rd_set_all_cursors(db, A + 6));

    const char *bid = "rewind_driver.success";
    struct blocker_record stale;
    RD_CHECK("success: stale escalation blocker pre-set",
             blocker_init(&stale, bid, "test", BLOCKER_DEPENDENCY,
                          "stale escalation to be cleared on success") &&
             blocker_set(&stale) >= 0);

    struct rewind_driver_result out;
    bool rv = rewind_to_nearest_self_verified_base(INT32_MAX, "unit-success",
                                                   "success", &out);
    RD_CHECK("success: returns true", rv);
    RD_CHECK("success: out.ok (rewind committed)", out.ok);
    RD_CHECK("success: not escalated / not nothing",
             !out.escalated && !out.nothing);
    RD_CHECK("success: H* reaches A+5", out.hstar == A + 5);
    RD_CHECK("success: base_height == A", out.base_height == A);
    RD_CHECK("success: base_self_derived", out.base_self_derived);
    RD_CHECK("success: base kind compiled_checkpoint",
             strcmp(out.base_kind, "compiled_checkpoint") == 0);
    RD_CHECK("success: rewound (at least one cursor lowered)", out.rewound);
    RD_CHECK("success: coins_rewound (inverse-delta fired)", out.coins_rewound);
    RD_CHECK("success: cursors_rewound > 0", out.cursors_rewound > 0);
    RD_CHECK("success: stale escalation blocker CLEARED", !blocker_exists(bid));

    /* Idempotent: the cursors now sit at the base, so a second drive is a
     * clean no-op (nothing left above H*... below the base) — proves the
     * committed rewind actually moved the cursors. */
    struct rewind_driver_result out2;
    bool rv2 = rewind_to_nearest_self_verified_base(INT32_MAX, "unit-success",
                                                    "success", &out2);
    RD_CHECK("success: second drive returns true", rv2);
    RD_CHECK("success: second drive did not re-escalate", !out2.escalated);

    progress_store_close();
    test_cleanup_tmpdir(dir);
    return failures;
}

/* THE sovereignty property: with BOTH a borrowed finalized_utxo_sha3 (HIGHER,
 * at A+4) and a self-verified rung (LOWER, the compiled checkpoint at A), the
 * driver rewinds to the LOWER self-verified base — a borrowed root can never
 * become the rewind target while any self-verified rung is available. Mirrors
 * test_reducer_frontier.c's case_sovereign_base_ignores_borrowed_higher_stamp
 * node_db wiring, but asserts the DRIVER's selection (out.base_*), not just the
 * selector. */
static int case_sovereign_rewinds_to_lower_self_verified(void)
{
    int failures = 0;
    rd_reset();
    char dir[256];
    sqlite3 *db = rd_open_progress(dir, "sovereign");
    RD_CHECK("sovereign: progress store opens + schema (full)",
             db && rd_build_schema_full(db));
    RD_CHECK("sovereign: proven authority",
             db && rd_stamp_proven_authority(db, A + 1));
    bool built = db != NULL;
    for (int32_t h = A + 1; h <= A + 5; h++)
        built = built && rd_put_consistent_height(db, h);
    built = built && rd_put_utxo_frontier_row(db, A);
    RD_CHECK("sovereign: rows built (H*=A+5)", built);
    RD_CHECK("sovereign: cursors at A+6", db && rd_set_all_cursors(db, A + 6));

    /* Wire a real node_db + db_service so enumerate_rewind_bases()'s
     * app_runtime_node_db() resolves, and stamp a BORROWED finalized_utxo_sha3
     * at A+4 — strictly HIGHER (nearer H*, cheaper under naive height-only
     * selection) than the self-verified compiled checkpoint at A. */
    struct node_db ndb;
    struct db_service dbsvc;
    struct app_runtime_context runtime;
    memset(&ndb, 0, sizeof(ndb));
    memset(&dbsvc, 0, sizeof(dbsvc));
    memset(&runtime, 0, sizeof(runtime));
    bool ndb_ok = node_db_open(&ndb, ":memory:");
    RD_CHECK("sovereign: node_db opens", ndb_ok);
    db_service_init(&dbsvc);
    RD_CHECK("sovereign: db_service attaches",
             ndb_ok && db_service_attach(&dbsvc, &ndb));
    RD_CHECK("sovereign: db_service starts",
             ndb_ok && db_service_start(&dbsvc));
    runtime.db_service = &dbsvc;
    app_runtime_set_current(&runtime);

    uint8_t borrowed_hash[32];
    memset(borrowed_hash, 0xCD, sizeof(borrowed_hash));
    RD_CHECK("sovereign: borrowed utxo_sha3 stamped at A+4 (higher)",
             utxo_commitment_sha3_save(ndb.db, borrowed_hash, A + 4, 7));

    struct rewind_driver_result out;
    bool rv = rewind_to_nearest_self_verified_base(A + 5, "unit-sovereign",
                                                   "sovereign", &out);
    RD_CHECK("sovereign: drive returns true", rv);
    /* THE assertion: the driver rewound to the LOWER self-verified base (A),
     * NOT the higher borrowed stamp (A+4). */
    RD_CHECK("sovereign: base is the LOWER self-verified height A, "
             "not the higher borrowed A+4",
             out.base_height == A);
    RD_CHECK("sovereign: base is self_derived (not the borrowed root)",
             out.base_self_derived);
    RD_CHECK("sovereign: base kind is compiled_checkpoint",
             strcmp(out.base_kind, "compiled_checkpoint") == 0);
    RD_CHECK("sovereign: driver NEVER targeted the borrowed A+4",
             out.base_height != A + 4);
    RD_CHECK("sovereign: rewind committed on the sovereign base", out.ok);

    app_runtime_set_current(NULL);
    db_service_stop(&dbsvc);
    node_db_close(&ndb);

    progress_store_close();
    test_cleanup_tmpdir(dir);
    return failures;
}

int test_rewind_driver(void);
int test_rewind_driver(void)
{
    int failures = 0;
    printf("\n--- rewind_driver (recovery driver branches) ---\n");
    blocker_module_init();

    failures += case_no_progress_db();
    failures += case_hstar_compute_failure();
    failures += case_no_base_escalates_once();
    failures += case_base_at_or_above_hstar_noop();
    failures += case_stage_rederive_store_error();
    failures += case_rederive_refused_escalates_once();
    failures += case_success();
    failures += case_sovereign_rewinds_to_lower_self_verified();

    rd_reset();
    progress_store_close();

    if (failures == 0)
        printf("rewind_driver: all cases passed\n");
    else
        printf("rewind_driver: %d failure(s)\n", failures);
    return failures;
}
