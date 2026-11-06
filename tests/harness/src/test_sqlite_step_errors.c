/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: a SQLite step that fails is an error, never "no row". Each case
 * injects a deterministic SQLITE_INTERRUPT through sqlite3_progress_handler
 * on an isolated fixture database and requires the reader to report failure
 * instead of a short or empty answer:
 *   - coins_kv_get_coins_sqlite: a fill scan cut short must not hand back a
 *     partial coins set as complete (live outputs would read as spent);
 *   - db_utxo_serialize_snapshot: a UTXO walk cut short must not produce a
 *     truncated snapshot reported as written, with a valid-looking SHA3;
 *   - script_validate_log_verdict_at: a failed read must be -1 (the caller's
 *     fatal path), not 0 (no verdict row, which skips the hash binding).
 * The handler is counted first on an uninterrupted call so the interrupt
 * lands at a known point of the same deterministic statement sequence.
 */

#include "test/test_core.h"

#include "coins/coins_view.h"
#include "core/uint256.h"
#include "models/database.h"
#include "models/utxo.h"
#include "primitives/transaction.h"
#include "storage/coins_kv.h"

#include "../../../engine/jobs/src/script_validate_log_store.h"

#include <sqlite3.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define SSE_CHECK(name, expr) do {                                         \
    if (expr) { printf("  sqlite_step_errors: %s... OK\n", (name)); }      \
    else { printf("  sqlite_step_errors: %s... FAIL\n", (name));           \
           failures++; }                                                    \
} while (0)

/* Counts VM callbacks; interrupts from the fire_at-th one on (0 = never). */
struct sse_budget {
    long calls;
    long fire_at;
};

static int sse_progress(void *ctx)
{
    struct sse_budget *b = ctx;
    b->calls++;
    return b->fire_at > 0 && b->calls >= b->fire_at;
}

static void sse_arm(sqlite3 *db, struct sse_budget *b, long fire_at)
{
    b->calls = 0;
    b->fire_at = fire_at;
    sqlite3_progress_handler(db, 1, sse_progress, b);
}

static void sse_disarm(sqlite3 *db)
{
    sqlite3_progress_handler(db, 0, NULL, NULL);
}

/* ── coins_kv_get_coins_sqlite: interrupt inside the second (fill) scan ── */

enum { SSE_VOUTS = 64 };

static bool sse_seed_coins(sqlite3 *db, const uint8_t txid[32])
{
    uint8_t script[3] = {0x51, 0x52, 0x53};
    if (!coins_kv_ensure_schema(db))
        return false;
    for (uint32_t v = 0; v < SSE_VOUTS; v++)
        if (!coins_kv_add(db, txid, v, 1000 + (int64_t)v, 7, false, script,
                          sizeof(script)))
            return false;
    return true;
}

static int sse_case_coins_fill_scan(sqlite3 *db)
{
    int failures = 0;
    uint8_t txid[32];
    memset(txid, 0x5c, sizeof(txid));
    SSE_CHECK("coins fixture seeds 64 outputs", sse_seed_coins(db, txid));

    struct coins c;
    struct sse_budget b;
    sse_arm(db, &b, 0);
    bool whole = coins_kv_get_coins_sqlite(db, txid, &c);
    long full = b.calls;
    sse_disarm(db);
    SSE_CHECK("uninterrupted read returns every output",
              whole && c.num_vout == SSE_VOUTS);
    coins_free(&c);

    /* The size scan and the fill scan run the same query over the same rows,
     * so three quarters of the way through lands inside the fill scan. */
    sse_arm(db, &b, (full * 3) / 4);
    bool got = coins_kv_get_coins_sqlite(db, txid, &c);
    bool fired = b.calls >= b.fire_at;
    sse_disarm(db);
    SSE_CHECK("interrupt fired during the read", fired && full > 8);
    SSE_CHECK("a fill scan cut short is a failure, not a partial set", !got);
    if (got)
        coins_free(&c);
    return failures;
}

/* ── db_utxo_serialize_snapshot: interrupt in the middle of the walk ────── */

static bool sse_seed_utxos(struct node_db *ndb, int n)
{
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(ndb->db,
            "INSERT INTO utxos(txid,vout,value,script,script_type,height,"
            "is_coinbase) VALUES(?,0,5000,x'51',0,?,0)",
            -1, &st, NULL) != SQLITE_OK)
        return false;
    bool ok = node_db_exec(ndb, "BEGIN");
    for (int i = 0; ok && i < n; i++) {
        uint8_t txid[32];
        memset(txid, 0, sizeof(txid));
        txid[0] = (uint8_t)(i >> 8);
        txid[1] = (uint8_t)i;
        txid[31] = 0x77;
        sqlite3_reset(st);
        sqlite3_bind_blob(st, 1, txid, 32, SQLITE_TRANSIENT);
        sqlite3_bind_int(st, 2, 10 + i);
        ok = sqlite3_step(st) == SQLITE_DONE;  // raw-sql-ok:test-fixture-setup
    }
    sqlite3_finalize(st);
    return ok && node_db_exec(ndb, "COMMIT");
}

static int sse_case_utxo_snapshot(const char *dir)
{
    int failures = 0;
    char dbpath[512], snap[512];
    snprintf(dbpath, sizeof(dbpath), "%s/node.db", dir);
    snprintf(snap, sizeof(snap), "%s/utxo.snap", dir);

    struct node_db ndb;
    memset(&ndb, 0, sizeof(ndb));
    bool open = node_db_open(&ndb, dbpath);
    SSE_CHECK("node.db fixture opens", open);
    if (!open)
        return failures;
    SSE_CHECK("node.db fixture seeds 200 utxos", sse_seed_utxos(&ndb, 200));

    uint8_t sha3[32];
    struct sse_budget b;
    sse_arm(ndb.db, &b, 0);
    int64_t whole = db_utxo_serialize_snapshot(&ndb, snap, 50, sha3);
    long full = b.calls;
    sse_disarm(ndb.db);
    SSE_CHECK("uninterrupted snapshot writes every utxo", whole == 200);

    sse_arm(ndb.db, &b, full / 2);
    int64_t cut = db_utxo_serialize_snapshot(&ndb, snap, 50, sha3);
    bool fired = b.calls >= b.fire_at;
    sse_disarm(ndb.db);
    static const uint8_t zero[32];
    SSE_CHECK("interrupt fired during the walk", fired && full > 8);
    SSE_CHECK("a walk cut short fails the snapshot", cut == -1);
    SSE_CHECK("a failed snapshot leaves no commitment",
              memcmp(sha3, zero, sizeof(zero)) == 0);
    node_db_close(&ndb);
    return failures;
}

/* ── script_validate_log_verdict_at: a failed read is -1, not "no row" ─── */

static int sse_case_verdict_at(sqlite3 *db)
{
    int failures = 0;
    SSE_CHECK("verdict fixture table",
              sqlite3_exec(db,
                  "CREATE TABLE script_validate_log(height INTEGER PRIMARY "
                  "KEY, ok INTEGER, status TEXT, block_hash BLOB);"
                  "INSERT INTO script_validate_log VALUES(5,1,'ok',"
                  "zeroblob(32));", NULL, NULL, NULL) == SQLITE_OK);

    struct script_validate_verdict_row row;
    SSE_CHECK("uninterrupted read finds the row",
              script_validate_log_verdict_at(db, 5, &row) == 1);

    struct sse_budget b;
    sse_arm(db, &b, 1);
    int rc = script_validate_log_verdict_at(db, 5, &row);
    sse_disarm(db);
    SSE_CHECK("an interrupted read is an error (-1), not absent (0)",
              rc == -1);
    return failures;
}

int test_sqlite_step_errors(void);
int test_sqlite_step_errors(void)
{
    int failures = 0;
    char dir[256];
    test_make_tmpdir(dir, sizeof(dir), "sqlite_step_errors", "main");

    char path[512];
    snprintf(path, sizeof(path), "%s/fixture.sqlite", dir);
    sqlite3 *db = NULL;
    bool open = sqlite3_open(path, &db) == SQLITE_OK;
    SSE_CHECK("fixture database opens", open);
    if (open) {
        failures += sse_case_coins_fill_scan(db);
        failures += sse_case_verdict_at(db);
    }
    sqlite3_close(db);

    failures += sse_case_utxo_snapshot(dir);
    test_cleanup_tmpdir(dir);
    return failures;
}
