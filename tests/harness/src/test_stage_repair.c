/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

#include "test/test_core.h"

#include "jobs/stage_repair.h"
#include "primitives/block.h"
#include "storage/progress_store.h"
#include "util/blocker.h"
#include "util/stage.h"

#include <sqlite3.h>
#include <stdint.h>
#include <string.h>

/* These tests pin the destructive poison-rewind safety guards in
 * engine/jobs/src/stage_repair.c. A prior unguarded rewind collapsed the
 * public tip from ~3.13M to ~47279, so each guard below is load-bearing:
 *   - a rewind is refused when any ok=1 row sits at/above the frontier
 *     (the regression guard that protects the Tier-2 public-tip floor);
 *   - a non-frontier rewind (height != active_tip+1) is refused;
 *   - a POISON_NONE height is a safe no-op (returns true, repaired=false);
 *   - header save/load round-trips, and rejects a hash mismatch and an
 *     oversized solution. */

#define STR_CHECK(name, expr) do { \
    printf("stage_repair: %s... ", (name)); \
    if ((expr)) printf("OK\n"); \
    else { printf("FAIL\n"); failures++; } \
} while (0)

static bool exec_sql(sqlite3 *db, const char *sql)
{
    char *err = NULL;
    int rc = sqlite3_exec(db, sql, NULL, NULL, &err);
    if (rc != SQLITE_OK) {
        printf("SQL failed: %s\n", err ? err : "(no message)");
        if (err) sqlite3_free(err);
        return false;
    }
    return true;
}

static bool seed_schema(sqlite3 *db)
{
    return
        exec_sql(db,
            "CREATE TABLE IF NOT EXISTS validate_headers_log ("
            "height INTEGER PRIMARY KEY, hash BLOB NOT NULL, ok INTEGER NOT NULL,"
            "fail_reason TEXT, validated_at INTEGER NOT NULL)") &&
        exec_sql(db,
            "CREATE TABLE IF NOT EXISTS body_fetch_log ("
            "height INTEGER PRIMARY KEY, hash BLOB NOT NULL, source TEXT NOT NULL,"
            "bytes INTEGER NOT NULL DEFAULT 0, fetched_at INTEGER NOT NULL,"
            "ok INTEGER NOT NULL, fail_reason TEXT)") &&
        exec_sql(db,
            "CREATE TABLE IF NOT EXISTS body_persist_log ("
            "height INTEGER PRIMARY KEY, source TEXT, ok INTEGER,"
            "persisted_at INTEGER)") &&
        exec_sql(db,
            "CREATE TABLE IF NOT EXISTS script_validate_log ("
            "height INTEGER PRIMARY KEY, status TEXT, ok INTEGER)") &&
        exec_sql(db,
            "CREATE TABLE IF NOT EXISTS proof_validate_log ("
            "height INTEGER PRIMARY KEY, status TEXT, ok INTEGER)") &&
        exec_sql(db,
            "CREATE TABLE IF NOT EXISTS utxo_apply_log ("
            "height INTEGER PRIMARY KEY, status TEXT, ok INTEGER)") &&
        exec_sql(db,
            "CREATE TABLE IF NOT EXISTS utxo_apply_delta ("
            "height INTEGER PRIMARY KEY)") &&
        exec_sql(db,
            "CREATE TABLE IF NOT EXISTS tip_finalize_log ("
            "height INTEGER PRIMARY KEY, status TEXT, ok INTEGER)");
}

/* Seed every stage cursor. The poison-rewind has a downstream success-check
 * over the *_log tables, not the cursors, but the rewind also rewinds the
 * cursors so they must exist. */
static bool seed_cursors(sqlite3 *db, int validate_cursor,
                         int downstream_cursor)
{
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db,
            "INSERT OR REPLACE INTO stage_cursor(name,cursor,updated_at) "
            "VALUES(?,?,1)",
            -1, &st, NULL) != SQLITE_OK)
        return false;
    static const char *const names[] = {
        "validate_headers",
        "body_fetch",
        "body_persist",
        "script_validate",
        "proof_validate",
        "utxo_apply",
        "tip_finalize",
    };
    bool ok = true;
    for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); i++) {
        sqlite3_reset(st);
        sqlite3_clear_bindings(st);
        sqlite3_bind_text(st, 1, names[i], -1, SQLITE_STATIC);
        sqlite3_bind_int(st, 2, i == 0 ? validate_cursor : downstream_cursor);
        if (sqlite3_step(st) != SQLITE_DONE) {
            ok = false;
            break;
        }
    }
    sqlite3_finalize(st);
    return ok;
}

/* Seed the DOWNSTREAM-STALE poison shape at `height`: validate_headers ok=1,
 * body_fetch skipped_invalid/header_validation_failed, and ok=0 downstream
 * rows. This is the shape stage_repair_header_solution_poison_mode classifies
 * as STAGE_REPAIR_POISON_DOWNSTREAM_STALE. */
static bool seed_downstream_poison(sqlite3 *db, int height)
{
    char sql[4096];
    snprintf(sql, sizeof(sql),
        "INSERT OR REPLACE INTO validate_headers_log"
        "(height,hash,ok,fail_reason,validated_at) "
        "VALUES(%d,zeroblob(32),1,NULL,1);"
        "INSERT OR REPLACE INTO body_fetch_log"
        "(height,hash,source,bytes,fetched_at,ok,fail_reason) "
        "VALUES(%d,zeroblob(32),'skipped_invalid',0,1,0,"
        "'header_validation_failed');"
        "INSERT OR REPLACE INTO body_persist_log"
        "(height,source,ok,persisted_at) VALUES(%d,'upstream_failed',0,1);"
        "INSERT OR REPLACE INTO script_validate_log"
        "(height,status,ok) VALUES(%d,'upstream_failed',0);"
        "INSERT OR REPLACE INTO proof_validate_log"
        "(height,status,ok) VALUES(%d,'upstream_failed',0);"
        "INSERT OR REPLACE INTO utxo_apply_log"
        "(height,status,ok) VALUES(%d,'upstream_failed',0);"
        "INSERT OR REPLACE INTO utxo_apply_delta(height) VALUES(%d);"
        "INSERT OR REPLACE INTO tip_finalize_log"
        "(height,status,ok) VALUES(%d,'upstream_failed',0);",
        height, height, height, height, height, height, height, height);
    return exec_sql(db, sql);
}

static bool seed_validate_poison(sqlite3 *db, int height, const char *reason)
{
    char sql[512];
    snprintf(sql, sizeof(sql),
        "INSERT OR REPLACE INTO validate_headers_log"
        "(height,hash,ok,fail_reason,validated_at) "
        "VALUES(%d,zeroblob(32),0,%s,1);"
        "INSERT OR REPLACE INTO body_fetch_log"
        "(height,hash,source,bytes,fetched_at,ok,fail_reason) "
        "VALUES(%d,zeroblob(32),'skipped_invalid',0,1,0,"
        "'header_validation_failed');",
        height, reason ? reason : "NULL", height);
    return exec_sql(db, sql);
}

static int cursor_for(sqlite3 *db, const char *name)
{
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db,
            "SELECT cursor FROM stage_cursor WHERE name=?",
            -1, &st, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_text(st, 1, name, -1, SQLITE_STATIC);
    int out = -1;
    if (sqlite3_step(st) == SQLITE_ROW)
        out = sqlite3_column_int(st, 0);
    sqlite3_finalize(st);
    return out;
}

static bool set_one_cursor(sqlite3 *db, const char *name, int cursor)
{
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db,
            "INSERT OR REPLACE INTO stage_cursor(name,cursor,updated_at) "
            "VALUES(?,?,1)",
            -1, &st, NULL) != SQLITE_OK)
        return false;
    sqlite3_bind_text(st, 1, name, -1, SQLITE_STATIC);
    sqlite3_bind_int(st, 2, cursor);
    bool ok = sqlite3_step(st) == SQLITE_DONE;
    sqlite3_finalize(st);
    return ok;
}

/* INSERT OR REPLACE a (height,status,ok) row into a 3-column *_log table. */
static bool put_log(sqlite3 *db, const char *table, int height,
                    const char *status, int ok)
{
    char sql[160];
    snprintf(sql, sizeof(sql),
             "INSERT OR REPLACE INTO %s(height,status,ok) VALUES(?,?,?)",
             table);
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) != SQLITE_OK)
        return false;
    sqlite3_bind_int(st, 1, height);
    sqlite3_bind_text(st, 2, status, -1, SQLITE_STATIC);
    sqlite3_bind_int(st, 3, ok);
    bool done = sqlite3_step(st) == SQLITE_DONE;
    sqlite3_finalize(st);
    return done;
}

static bool row_exists(sqlite3 *db, const char *table, int height)
{
    char sql[128];
    snprintf(sql, sizeof(sql), "SELECT 1 FROM %s WHERE height=?", table);
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) != SQLITE_OK)
        return false;
    sqlite3_bind_int(st, 1, height);
    bool found = sqlite3_step(st) == SQLITE_ROW;
    sqlite3_finalize(st);
    return found;
}

/* Build a deterministic, self-consistent header (hash matches the bytes) at
 * `height`. */
static void make_header(struct block_header *h, int height)
{
    block_header_init(h);
    h->nVersion = 4;
    h->hashPrevBlock.data[0] = (uint8_t)(height - 1);
    h->hashPrevBlock.data[1] = 0xA7;
    h->hashMerkleRoot.data[0] = (uint8_t)height;
    h->hashMerkleRoot.data[1] = 0xB8;
    h->hashFinalSaplingRoot.data[0] = (uint8_t)height;
    h->hashFinalSaplingRoot.data[1] = 0xC9;
    h->nTime = 1700000000u + (uint32_t)height;
    h->nBits = 0x1f07ffff;
    h->nNonce.data[0] = (uint8_t)height;
    h->nNonce.data[1] = 0xDA;
    h->nSolutionSize = 32;
    for (size_t i = 0; i < h->nSolutionSize; i++)
        h->nSolution[i] = (uint8_t)(height + (int)i);
}

/* Open a fresh progress_store in a tmpdir and seed schema + stage_cursor. */
static bool setup_case(const char *tag, char *dir, size_t dir_n, sqlite3 **db)
{
    test_make_tmpdir(dir, dir_n, "stage_repair", tag);
    if (!progress_store_open(dir))
        return false;
    *db = progress_store_db();
    /* stage_table_ensure creates the stage_cursor table the rewind rewinds. */
    return seed_schema(*db) && stage_table_ensure(*db);
}

static void teardown_case(const char *dir)
{
    progress_store_close();
    test_cleanup_tmpdir(dir);
}

int test_stage_repair(void)
{
    printf("\n=== stage_repair poison-rewind safety guard tests ===\n");
    int failures = 0;

    /* --- Guard 1: ok=1 row AT the frontier refuses the whole rewind. ---
     * This is the regression guard: a finalized (ok=1) row at/above the
     * frontier means the public tip is anchored there; the rewind must
     * refuse so the Tier-2 floor is never disturbed. */
    {
        char dir[256];
        sqlite3 *db = NULL;
        bool ok = setup_case("ok1_at_frontier", dir, sizeof(dir), &db);
        ok = ok && seed_cursors(db, 5, 5);
        ok = ok && seed_downstream_poison(db, 2);
        /* Poison the height we want to rewind (2), but plant a finalized
         * ok=1 row exactly AT the frontier (height 2). */
        ok = ok && exec_sql(db,
            "INSERT OR REPLACE INTO tip_finalize_log(height,status,ok) "
            "VALUES(2,'finalized',1)");

        struct stage_repair_header_solution_result res;
        /* frontier = active_tip+1 = 2 */
        bool rv = stage_repair_header_solution_poison_rewind(db, 2, 1, &res);

        ok = ok && rv == false;            /* refused */
        /* Nothing was deleted: the poisoned rows survive the refusal. */
        ok = ok && row_exists(db, "body_fetch_log", 2);
        ok = ok && row_exists(db, "validate_headers_log", 2);
        ok = ok && row_exists(db, "tip_finalize_log", 2);
        ok = ok && res.repaired == false;
        /* Cursors untouched. */
        ok = ok && cursor_for(db, "body_fetch") == 5;
        STR_CHECK("ok=1 row at frontier refuses the destructive rewind", ok);
        teardown_case(dir);
    }

    /* --- Guard 1b: ok=1 row ABOVE the frontier also refuses. --- */
    {
        char dir[256];
        sqlite3 *db = NULL;
        bool ok = setup_case("ok1_above_frontier", dir, sizeof(dir), &db);
        ok = ok && seed_cursors(db, 5, 5);
        ok = ok && seed_downstream_poison(db, 2);
        /* Finalized ok=1 row strictly ABOVE the frontier (height 4 > 2). */
        ok = ok && exec_sql(db,
            "INSERT OR REPLACE INTO utxo_apply_log(height,status,ok) "
            "VALUES(4,'applied',1)");

        struct stage_repair_header_solution_result res;
        bool rv = stage_repair_header_solution_poison_rewind(db, 2, 1, &res);

        ok = ok && rv == false;
        ok = ok && row_exists(db, "body_fetch_log", 2);
        ok = ok && res.repaired == false;
        ok = ok && cursor_for(db, "body_fetch") == 5;
        STR_CHECK("ok=1 row above frontier refuses the destructive rewind", ok);
        teardown_case(dir);
    }

    /* --- Guard 2: non-frontier rewind (height != active_tip+1) refused. --- */
    {
        char dir[256];
        sqlite3 *db = NULL;
        bool ok = setup_case("non_frontier", dir, sizeof(dir), &db);
        ok = ok && seed_cursors(db, 5, 5);
        ok = ok && seed_downstream_poison(db, 2);

        struct stage_repair_header_solution_result res;
        /* height=2 but active_tip=10 => frontier should be 11, not 2. */
        bool rv = stage_repair_header_solution_poison_rewind(db, 2, 10, &res);

        ok = ok && rv == false;
        /* Refused before any mutation: rows and cursors intact. */
        ok = ok && row_exists(db, "body_fetch_log", 2);
        ok = ok && cursor_for(db, "body_fetch") == 5;
        ok = ok && res.repaired == false;
        STR_CHECK("non-frontier rewind is refused", ok);
        teardown_case(dir);
    }

    /* --- Guard 3: POISON_NONE is a safe no-op (returns true, repaired=false).
     * A clean frontier with no poison shape must not delete anything. --- */
    {
        char dir[256];
        sqlite3 *db = NULL;
        bool ok = setup_case("poison_none", dir, sizeof(dir), &db);
        ok = ok && seed_cursors(db, 5, 5);
        /* No poison rows seeded at the frontier height 2. */

        struct stage_repair_header_solution_result res;
        bool rv = stage_repair_header_solution_poison_rewind(db, 2, 1, &res);

        ok = ok && rv == true;             /* no-op succeeds */
        ok = ok && res.repaired == false;
        ok = ok && res.mode == STAGE_REPAIR_POISON_NONE;
        /* Cursors untouched by the no-op. */
        ok = ok && cursor_for(db, "body_fetch") == 5;
        STR_CHECK("POISON_NONE frontier is a safe no-op", ok);
        teardown_case(dir);
    }

    /* --- Sanity: a clean DOWNSTREAM_STALE rewind (no ok=1 at/above frontier)
     * succeeds, deletes the downstream poison rows, rewinds the cursors, and
     * preserves the (ok=0) tip_finalize_log row (doctrine forbids deleting
     * tip_finalize_log rows). This proves the guards above reject the
     * dangerous case rather than the whole code path. --- */
    {
        char dir[256];
        sqlite3 *db = NULL;
        bool ok = setup_case("downstream_rewind", dir, sizeof(dir), &db);
        ok = ok && seed_cursors(db, 5, 5);
        ok = ok && seed_downstream_poison(db, 2);

        struct stage_repair_header_solution_result res;
        bool rv = stage_repair_header_solution_poison_rewind(db, 2, 1, &res);

        ok = ok && rv == true;
        ok = ok && res.repaired == true;
        ok = ok && res.mode == STAGE_REPAIR_POISON_DOWNSTREAM_STALE;
        /* Downstream rows deleted; validate row (ok=1) preserved. */
        ok = ok && !row_exists(db, "body_fetch_log", 2);
        ok = ok && row_exists(db, "validate_headers_log", 2);
        /* tip_finalize_log ok=0 row MUST survive (deletion banned). */
        ok = ok && row_exists(db, "tip_finalize_log", 2);
        /* Downstream cursors rewound to the frontier. */
        ok = ok && cursor_for(db, "body_fetch") == 2;
        ok = ok && cursor_for(db, "tip_finalize") == 2;
        /* validate_headers cursor untouched on a downstream rewind. */
        ok = ok && cursor_for(db, "validate_headers") == 5;
        STR_CHECK("downstream rewind deletes downstream, keeps tip_finalize_log",
                  ok);
        teardown_case(dir);
    }

    /* --- Classifier: source-hash mismatch is repairable; invalid is not. --- */
    {
        char dir[256];
        sqlite3 *db = NULL;
        bool ok = setup_case("validate_source_mismatch", dir, sizeof(dir), &db);
        ok = ok && seed_cursors(db, 5, 5);
        ok = ok && seed_validate_poison(
            db, 2, "'header-source-hash-mismatch'");

        ok = ok && stage_repair_header_solution_poison_mode(db, 2) ==
                   STAGE_REPAIR_POISON_VALIDATE_HASH_MISMATCH;

        struct stage_repair_header_solution_result res;
        bool rv = stage_repair_header_solution_poison_rewind(db, 2, 1, &res);
        ok = ok && rv == true;
        ok = ok && res.repaired == false;
        ok = ok && row_exists(db, "validate_headers_log", 2);
        ok = ok && row_exists(db, "body_fetch_log", 2);
        STR_CHECK("header-source hash mismatch is non-destructive repairable "
                  "validate poison",
                  ok);
        teardown_case(dir);
    }

    {
        char dir[256];
        sqlite3 *db = NULL;
        bool ok = setup_case("validate_invalid_solution", dir, sizeof(dir), &db);
        ok = ok && seed_cursors(db, 5, 5);
        ok = ok && seed_validate_poison(db, 2, "'invalid-solution'");

        ok = ok && stage_repair_header_solution_poison_mode(db, 2) ==
                   STAGE_REPAIR_POISON_NONE;
        STR_CHECK("invalid validate failure stays non-repairable", ok);
        teardown_case(dir);
    }

    /* --- Guard 4: header save/load round-trip. --- */
    {
        char dir[256];
        sqlite3 *db = NULL;
        bool ok = setup_case("header_roundtrip", dir, sizeof(dir), &db);

        struct block_header h;
        make_header(&h, 100);
        struct uint256 hash;
        block_header_get_hash(&h, &hash);

        ok = ok && stage_repair_header_solution_save(db, 100, &hash, &h);

        struct block_header loaded;
        ok = ok && stage_repair_header_solution_load(db, 100, &hash, &loaded);
        ok = ok && loaded.nVersion == h.nVersion;
        ok = ok && loaded.nTime == h.nTime;
        ok = ok && loaded.nBits == h.nBits;
        ok = ok && loaded.nSolutionSize == h.nSolutionSize;
        ok = ok && memcmp(loaded.nSolution, h.nSolution, h.nSolutionSize) == 0;
        ok = ok && uint256_eq(&loaded.hashPrevBlock, &h.hashPrevBlock);
        ok = ok && uint256_eq(&loaded.hashMerkleRoot, &h.hashMerkleRoot);
        /* The loaded header must hash to the stored hash. */
        struct uint256 rehash;
        block_header_get_hash(&loaded, &rehash);
        ok = ok && uint256_eq(&rehash, &hash);
        ok = ok && stage_repair_header_solution_available(db, 100, NULL);
        STR_CHECK("header solution save/load round-trips", ok);
        teardown_case(dir);
    }

    /* --- Guard 5a: save refuses a hash that does not match the header. --- */
    {
        char dir[256];
        sqlite3 *db = NULL;
        bool ok = setup_case("hash_mismatch", dir, sizeof(dir), &db);

        struct block_header h;
        make_header(&h, 200);
        struct uint256 wrong;
        memset(&wrong, 0, sizeof(wrong));
        wrong.data[0] = 0xFF;   /* deliberately not block_header_get_hash(h) */

        bool rv = stage_repair_header_solution_save(db, 200, &wrong, &h);
        ok = ok && rv == false;                 /* refused */
        /* Nothing persisted, so it is not available. */
        ok = ok && !stage_repair_header_solution_available(db, 200, NULL);
        STR_CHECK("save refuses a hash that mismatches the header bytes", ok);
        teardown_case(dir);
    }

    /* --- Guard 5b: save refuses an oversized solution (> MAX_SOLUTION_SIZE
     * via nSolutionSize past the backing array). --- */
    {
        char dir[256];
        sqlite3 *db = NULL;
        bool ok = setup_case("oversized_solution", dir, sizeof(dir), &db);

        struct block_header h;
        make_header(&h, 300);
        struct uint256 hash;
        block_header_get_hash(&h, &hash);
        /* Claim a solution length larger than the backing buffer. */
        h.nSolutionSize = sizeof(h.nSolution) + 1;

        bool rv = stage_repair_header_solution_save(db, 300, &hash, &h);
        ok = ok && rv == false;                 /* refused */
        ok = ok && !stage_repair_header_solution_available(db, 300, NULL);
        STR_CHECK("save refuses an oversized solution", ok);
        teardown_case(dir);
    }

    /* --- Guard 5c: save refuses a zero-length solution. --- */
    {
        char dir[256];
        sqlite3 *db = NULL;
        bool ok = setup_case("zero_solution", dir, sizeof(dir), &db);

        struct block_header h;
        make_header(&h, 400);
        struct uint256 hash;
        block_header_get_hash(&h, &hash);
        h.nSolutionSize = 0;

        bool rv = stage_repair_header_solution_save(db, 400, &hash, &h);
        ok = ok && rv == false;
        STR_CHECK("save refuses a zero-length solution", ok);
        teardown_case(dir);
    }

    /* --- Load round-trip rejection: a stored row whose expected_hash differs
     * is rejected by load. --- */
    {
        char dir[256];
        sqlite3 *db = NULL;
        bool ok = setup_case("load_expected_mismatch", dir, sizeof(dir), &db);

        struct block_header h;
        make_header(&h, 500);
        struct uint256 hash;
        block_header_get_hash(&h, &hash);
        ok = ok && stage_repair_header_solution_save(db, 500, &hash, &h);

        struct uint256 expected_wrong;
        memset(&expected_wrong, 0, sizeof(expected_wrong));
        expected_wrong.data[0] = 0xEE;
        struct block_header loaded;
        bool rv = stage_repair_header_solution_load(db, 500, &expected_wrong,
                                                    &loaded);
        ok = ok && rv == false;                 /* expected-hash guard rejects */
        /* But loading with the correct expected hash succeeds. */
        ok = ok && stage_repair_header_solution_load(db, 500, &hash, &loaded);
        STR_CHECK("load rejects a mismatched expected hash", ok);
        teardown_case(dir);
    }

    /* === proof_validate internal_error symmetry (self-verified-tip-plan
     * Act 1) ===
     *
     * The script path already re-derives a transient script_validate
     * internal_error instead of trusting it as a terminal ok=0. These pin the
     * PROOF-stage twin: a transient proof_validate internal_error at a height
     * where script PASSED must also be re-derived, never frozen as "invalid"
     * (the inverse Law-7 lie). The witness: after the one-shot rewind the
     * proof_validate_log row at the hole is DELETED (so proof_validate
     * re-derives it with a fresh validated_at on the next step), the proof
     * cursor is rewound to the hole, and a second pass is a one-shot no-op. */

#ifdef ZCL_TESTING
    /* --- Witness A: a transient proof internal_error (script ok=1) is
     * re-derived: the verdict row is dropped and the proof cursor rewinds. --- */
    {
        char dir[256];
        sqlite3 *db = NULL;
        bool ok = setup_case("proof_internal_error", dir, sizeof(dir), &db);
        /* script/proof advanced to cursor 5; utxo pinned at the hole (3) — a
         * transient proof internal_error leaves utxo_apply stuck there, so no
         * coins rewind is exercised (rewind_coins == false). */
        ok = ok && set_one_cursor(db, "script_validate", 5);
        ok = ok && set_one_cursor(db, "proof_validate", 5);
        ok = ok && set_one_cursor(db, "utxo_apply", 3);
        ok = ok && set_one_cursor(db, "tip_finalize", 3);
        /* script PASSED at h=3 and h=4; proof recorded a transient
         * internal_error at h=3 (ok=0) and verified h=4. */
        ok = ok && put_log(db, "script_validate_log", 3, "verified", 1);
        ok = ok && put_log(db, "script_validate_log", 4, "verified", 1);
        ok = ok && put_log(db, "proof_validate_log", 3, "internal_error", 0);
        ok = ok && put_log(db, "proof_validate_log", 4, "verified", 1);

        bool repaired = false;
        int height = -1;
        bool rv = stage_repair_proof_internal_error_rewind_for_testing(
            db, &repaired, &height);

        ok = ok && rv == true;
        ok = ok && repaired == true;
        ok = ok && height == 3;
        /* The "could not determine validity" verdict is GONE — proof_validate
         * will re-derive it (a fresh row, not the frozen ok=0). This is the
         * Law-7 witness: a transient is never persisted as terminal. */
        ok = ok && !row_exists(db, "proof_validate_log", 3);
        ok = ok && !row_exists(db, "proof_validate_log", 4);
        /* script verdicts are untouched (they passed; the proof twin must NOT
         * re-run script). */
        ok = ok && row_exists(db, "script_validate_log", 3);
        ok = ok && row_exists(db, "script_validate_log", 4);
        /* cursors rewound to the hole so the forward stages replay it. */
        ok = ok && cursor_for(db, "proof_validate") == 3;
        ok = ok && cursor_for(db, "tip_finalize") == 3;
        /* script cursor untouched. */
        ok = ok && cursor_for(db, "script_validate") == 5;
        STR_CHECK("transient proof internal_error is re-derived, not frozen",
                  ok);
        teardown_case(dir);
    }

    /* --- Witness B: a genuine proof_invalid (consensus reject) stays
     * terminal — the symmetry must not erase real verdicts. --- */
    {
        char dir[256];
        sqlite3 *db = NULL;
        bool ok = setup_case("proof_invalid_terminal", dir, sizeof(dir), &db);
        ok = ok && set_one_cursor(db, "script_validate", 5);
        ok = ok && set_one_cursor(db, "proof_validate", 5);
        ok = ok && set_one_cursor(db, "utxo_apply", 3);
        ok = ok && set_one_cursor(db, "tip_finalize", 3);
        ok = ok && put_log(db, "script_validate_log", 3, "verified", 1);
        /* A real consensus reject, NOT a transient. */
        ok = ok && put_log(db, "proof_validate_log", 3, "proof_invalid", 0);

        bool repaired = false;
        int height = -1;
        bool rv = stage_repair_proof_internal_error_rewind_for_testing(
            db, &repaired, &height);

        ok = ok && rv == true;
        ok = ok && repaired == false;       /* no transient hole found */
        /* The genuine reject row survives; cursor unchanged. */
        ok = ok && row_exists(db, "proof_validate_log", 3);
        ok = ok && cursor_for(db, "proof_validate") == 5;
        STR_CHECK("genuine proof_invalid stays terminal (not erased)", ok);
        teardown_case(dir);
    }

    /* --- Witness C: a proof internal_error at a height where SCRIPT also
     * failed is the script path's domain — the proof twin leaves it alone. --- */
    {
        char dir[256];
        sqlite3 *db = NULL;
        bool ok = setup_case("proof_script_codomain", dir, sizeof(dir), &db);
        ok = ok && set_one_cursor(db, "script_validate", 5);
        ok = ok && set_one_cursor(db, "proof_validate", 5);
        ok = ok && set_one_cursor(db, "utxo_apply", 3);
        ok = ok && set_one_cursor(db, "tip_finalize", 3);
        /* script FAILED at h=3 (its own rewind owns this height). */
        ok = ok && put_log(db, "script_validate_log", 3, "internal_error", 0);
        ok = ok && put_log(db, "proof_validate_log", 3, "internal_error", 0);

        bool repaired = false;
        int height = -1;
        bool rv = stage_repair_proof_internal_error_rewind_for_testing(
            db, &repaired, &height);

        ok = ok && rv == true;
        ok = ok && repaired == false;       /* script owns the hole */
        ok = ok && row_exists(db, "proof_validate_log", 3);
        ok = ok && cursor_for(db, "proof_validate") == 5;
        STR_CHECK("proof+script co-failure is left to the script rewind", ok);
        teardown_case(dir);
    }

    /* --- Witness D: the one-shot marker bounds the retry. Re-inject the SAME
     * transient hole after a rewind; the second pass must NOT rewind again
     * (otherwise a persistently-failing transient loops forever). --- */
    {
        char dir[256];
        sqlite3 *db = NULL;
        bool ok = setup_case("proof_oneshot_marker", dir, sizeof(dir), &db);
        ok = ok && set_one_cursor(db, "script_validate", 5);
        ok = ok && set_one_cursor(db, "proof_validate", 5);
        ok = ok && set_one_cursor(db, "utxo_apply", 3);
        ok = ok && set_one_cursor(db, "tip_finalize", 3);
        ok = ok && put_log(db, "script_validate_log", 3, "verified", 1);
        ok = ok && put_log(db, "proof_validate_log", 3, "internal_error", 0);

        bool repaired1 = false;
        int height1 = -1;
        ok = ok && stage_repair_proof_internal_error_rewind_for_testing(
                       db, &repaired1, &height1);
        ok = ok && repaired1 == true && height1 == 3;

        /* Simulate the transient re-reproducing: proof re-records the same
         * internal_error and the cursor re-advances. */
        ok = ok && set_one_cursor(db, "proof_validate", 5);
        ok = ok && put_log(db, "proof_validate_log", 3, "internal_error", 0);

        bool repaired2 = false;
        int height2 = -1;
        ok = ok && stage_repair_proof_internal_error_rewind_for_testing(
                       db, &repaired2, &height2);
        /* Second pass is a marker-bounded no-op: the row survives, the cursor
         * is not rewound a second time. The still-present internal_error
         * surfaces as a named marker-seen refusal, never a silent loop. */
        ok = ok && repaired2 == false;
        ok = ok && row_exists(db, "proof_validate_log", 3);
        ok = ok && cursor_for(db, "proof_validate") == 5;
        STR_CHECK("one-shot marker bounds the proof rewind to one attempt", ok);
        teardown_case(dir);
    }

    /* A completed first transition above a durable trusted base must survive
     * L1 reconcile. Rewinding 19->18 here would replace the anchor row with a
     * finalized transition row and then strand the next retry on a hash
     * mismatch — the fresh bundle-install wedge reproduced by C3. */
    {
        char dir[256];
        sqlite3 *db = NULL;
        bool ok = setup_case("trusted_base_transition", dir, sizeof(dir),
                             &db);
        ok = ok && seed_cursors(db, 19, 19) &&
             exec_sql(db,
                "ALTER TABLE tip_finalize_log ADD COLUMN tip_hash BLOB;") &&
             exec_sql(db,
                "INSERT OR REPLACE INTO tip_finalize_log"
                "(height,status,ok,tip_hash) VALUES"
                "(18,'finalized',1,"
                "X'0100000000000000000000000000000000000000000000000000000000000000');"
                "INSERT OR REPLACE INTO progress_meta(key,value) VALUES"
                "('reducer_trusted_base_height',X'1200000000000000');"
                "INSERT OR REPLACE INTO progress_meta(key,value) VALUES"
                "('reducer_trusted_base_hash',zeroblob(32));");

        struct stage_reducer_frontier_reconcile_result out;
        memset(&out, 0, sizeof(out));
        out.hstar = 18;
        out.tip_finalize_cursor_before = 19;
        out.coins_applied_found = true;
        out.coins_applied_height = 19;
        bool rv =
            stage_reducer_frontier_reconcile_tip_finalize_cursor_for_testing(
                db, true, &out);
        ok = ok && rv && !out.clamped_tip_finalize &&
             out.tip_finalize_cursor_after == 19 &&
             cursor_for(db, "tip_finalize") == 19;
        STR_CHECK("trusted-base completed transition is never rewound", ok);
        teardown_case(dir);
    }

    /* === tip_finalize rewind-churn refusal (defence-in-depth
     * under the coins-frontier clamp) ===
     *
     * A repeated rewind-to-the-same-height pass (e.g. tip_finalize
     * bouncing between two adjacent heights) can have each rewind "succeed"
     * while H* never moves — a livelock that reads as progress. The witness
     * below drives the apply-only tip_finalize clamp directly (bypassing
     * the full frontier snapshot) at a fixed height with flat H*: the first
     * 3 asks must rewind normally, the 4th must refuse and name the
     * "tip_finalize.rewind_churn" blocker instead, and an H* advance must
     * reset the memo (and clear the blocker) so progress resumes. */
    {
        char dir[256];
        sqlite3 *db = NULL;
        bool ok = setup_case("tip_finalize_rewind_churn", dir, sizeof(dir),
                             &db);
        ok = ok && seed_cursors(db, 5, 5);
        blocker_module_init();
        blocker_clear("tip_finalize.rewind_churn");
        stage_reducer_frontier_reset_rewind_churn_memo_for_testing();

        /* hstar pinned at 18 the whole time; the cursor is fixed at 25 (>
         * hstar+1), so every pass is asked to rewind to hstar+1=19
         * (simulating something else re-advancing the served cursor back to
         * 25 between reconcile ticks — the exact live shape). */
        struct stage_reducer_frontier_reconcile_result out;
        bool rv;

        memset(&out, 0, sizeof(out));
        out.hstar = 18;
        out.tip_finalize_cursor_before = 25;
        rv = stage_reducer_frontier_reconcile_tip_finalize_cursor_for_testing(
            db, true, &out);
        ok = ok && rv && out.clamped_tip_finalize &&
             out.tip_finalize_cursor_after == 19 &&
             cursor_for(db, "tip_finalize") == 19 &&
             !blocker_exists("tip_finalize.rewind_churn");
        STR_CHECK("rewind-churn: 1st rewind applies normally", ok);

        memset(&out, 0, sizeof(out));
        out.hstar = 18;
        out.tip_finalize_cursor_before = 25;
        rv = stage_reducer_frontier_reconcile_tip_finalize_cursor_for_testing(
            db, true, &out);
        ok = ok && rv && out.clamped_tip_finalize &&
             out.tip_finalize_cursor_after == 19 &&
             cursor_for(db, "tip_finalize") == 19 &&
             !blocker_exists("tip_finalize.rewind_churn");
        STR_CHECK("rewind-churn: 2nd rewind applies normally", ok);

        memset(&out, 0, sizeof(out));
        out.hstar = 18;
        out.tip_finalize_cursor_before = 25;
        rv = stage_reducer_frontier_reconcile_tip_finalize_cursor_for_testing(
            db, true, &out);
        ok = ok && rv && out.clamped_tip_finalize &&
             out.tip_finalize_cursor_after == 19 &&
             cursor_for(db, "tip_finalize") == 19 &&
             !blocker_exists("tip_finalize.rewind_churn");
        STR_CHECK("rewind-churn: 3rd rewind applies normally", ok);

        /* 4th ask at the SAME target height with the SAME flat hstar must
         * be refused: no further write, the cursor stays at 19 (from the
         * 3rd apply), and the typed blocker is named. */
        memset(&out, 0, sizeof(out));
        out.hstar = 18;
        out.tip_finalize_cursor_before = 25;
        rv = stage_reducer_frontier_reconcile_tip_finalize_cursor_for_testing(
            db, true, &out);
        ok = ok && rv && !out.clamped_tip_finalize &&
             out.tip_finalize_cursor_after == 25 &&
             cursor_for(db, "tip_finalize") == 19 &&
             blocker_exists("tip_finalize.rewind_churn");
        STR_CHECK("rewind-churn: 4th consecutive ask is refused and names "
                  "the blocker",
                  ok);

        /* H* advancing to 19 (still pinned relative to the fixed cursor 25)
         * changes the clamp target from 19 to hstar+1=20 — a different
         * target height, so the streak is fresh: the rewind is allowed
         * again (proving progress resumes) and the stale blocker clears. */
        memset(&out, 0, sizeof(out));
        out.hstar = 19;
        out.tip_finalize_cursor_before = 25;
        rv = stage_reducer_frontier_reconcile_tip_finalize_cursor_for_testing(
            db, true, &out);
        ok = ok && rv && out.clamped_tip_finalize &&
             out.tip_finalize_cursor_after == 20 &&
             cursor_for(db, "tip_finalize") == 20 &&
             !blocker_exists("tip_finalize.rewind_churn");
        STR_CHECK("rewind-churn: an H* advance resets the memo and clears "
                  "the blocker",
                  ok);

        /* A wholly independent fresh pin (hstar=20, cursor fixed at 30,
         * target=21) churns the same way: 3 rewinds apply, the 4th is
         * refused again — the guard re-arms per-streak, it does not
         * permanently latch after firing once. */
        memset(&out, 0, sizeof(out));
        out.hstar = 20;
        out.tip_finalize_cursor_before = 30;
        rv = stage_reducer_frontier_reconcile_tip_finalize_cursor_for_testing(
            db, true, &out);
        ok = ok && rv && out.clamped_tip_finalize &&
             out.tip_finalize_cursor_after == 21 &&
             cursor_for(db, "tip_finalize") == 21 &&
             !blocker_exists("tip_finalize.rewind_churn");

        memset(&out, 0, sizeof(out));
        out.hstar = 20;
        out.tip_finalize_cursor_before = 30;
        rv = stage_reducer_frontier_reconcile_tip_finalize_cursor_for_testing(
            db, true, &out);
        ok = ok && rv && out.clamped_tip_finalize &&
             out.tip_finalize_cursor_after == 21 &&
             cursor_for(db, "tip_finalize") == 21 &&
             !blocker_exists("tip_finalize.rewind_churn");

        memset(&out, 0, sizeof(out));
        out.hstar = 20;
        out.tip_finalize_cursor_before = 30;
        rv = stage_reducer_frontier_reconcile_tip_finalize_cursor_for_testing(
            db, true, &out);
        ok = ok && rv && out.clamped_tip_finalize &&
             out.tip_finalize_cursor_after == 21 &&
             cursor_for(db, "tip_finalize") == 21 &&
             !blocker_exists("tip_finalize.rewind_churn");

        memset(&out, 0, sizeof(out));
        out.hstar = 20;
        out.tip_finalize_cursor_before = 30;
        rv = stage_reducer_frontier_reconcile_tip_finalize_cursor_for_testing(
            db, true, &out);
        ok = ok && rv && !out.clamped_tip_finalize &&
             out.tip_finalize_cursor_after == 30 &&
             cursor_for(db, "tip_finalize") == 21 &&
             blocker_exists("tip_finalize.rewind_churn");
        STR_CHECK("rewind-churn: a fresh pin re-arms the same 3-strike "
                  "refusal",
                  ok);

        blocker_clear("tip_finalize.rewind_churn");
        stage_reducer_frontier_reset_rewind_churn_memo_for_testing();
        teardown_case(dir);
    }

    /* --- A dry-run (apply=false) never engages the churn gate: it never
     * writes, so it must never refuse or count toward the streak, no matter
     * how many times it is polled at the same pinned height. --- */
    {
        char dir[256];
        sqlite3 *db = NULL;
        bool ok = setup_case("tip_finalize_rewind_churn_dryrun", dir,
                             sizeof(dir), &db);
        ok = ok && seed_cursors(db, 5, 5);
        blocker_module_init();
        blocker_clear("tip_finalize.rewind_churn");
        stage_reducer_frontier_reset_rewind_churn_memo_for_testing();

        struct stage_reducer_frontier_reconcile_result out;
        bool rv = true;
        for (int i = 0; i < 6 && ok; i++) {
            memset(&out, 0, sizeof(out));
            out.hstar = 18;
            out.tip_finalize_cursor_before = 20;
            rv = stage_reducer_frontier_reconcile_tip_finalize_cursor_for_testing(
                db, false, &out);
            ok = ok && rv && out.clamped_tip_finalize &&
                 out.tip_finalize_cursor_after == 19 &&
                 !blocker_exists("tip_finalize.rewind_churn");
        }
        /* The cursor itself was never written by a dry-run. */
        ok = ok && cursor_for(db, "tip_finalize") == 5;
        STR_CHECK("rewind-churn: a dry-run never engages the gate", ok);

        blocker_clear("tip_finalize.rewind_churn");
        stage_reducer_frontier_reset_rewind_churn_memo_for_testing();
        teardown_case(dir);
    }
#endif /* ZCL_TESTING */

    return failures;
}
