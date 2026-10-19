/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Regression tests for reducer_frontier_compute_hstar. Each case builds an
 * in-memory progress.kv with the real stage-log schema for one tear topology
 * and asserts the exact (hstar, served_floor). Fixture rows use plain
 * sqlite3_exec: test scaffolding, not production reducer code. */

#include "test/test_core.h"
#include "json/json.h"

#include "coins/utxo_commitment.h"
#include "config/db_service.h"
#include "config/runtime.h"
#include "jobs/reducer_frontier.h"
#include "models/database.h"
#include "storage/progress_store.h"
#include "storage/seal_kv.h"
#include "util/blocker.h"

#include <sqlite3.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define RF_CHECK(name, expr) do {                                  \
    printf("reducer_frontier: %s... ", (name));                    \
    if (expr) { printf("OK\n"); }                                  \
    else { printf("FAIL\n"); failures++; }                         \
} while (0)

struct body_note_writer_args {
    struct uint256 hashes[2];
    int file;
    int64_t pos;
    enum reducer_frontier_body_read_reason reason;
    bool alternate_hashes;
};

static _Atomic bool g_body_note_threads_go;
static _Atomic bool g_body_note_raise_done;

static void *body_note_writer(void *arg)
{
    struct body_note_writer_args *a = arg;
    while (!atomic_load(&g_body_note_threads_go)) {
    }
    for (int i = 0; i < 1000; i++)
        reducer_frontier_body_read_note_record(
            42, a->file, a->pos, a->reason,
            &a->hashes[a->alternate_hashes ? i % 2 : 0]);
    return NULL;
}

static void *body_note_clearer(void *arg)
{
    (void)arg;
    while (!atomic_load(&g_body_note_threads_go)) {
    }
    while (!atomic_load(&g_body_note_raise_done)) {
    }
    for (int i = 0; i < 1000; i++) {
        struct reducer_frontier_body_read_note note;
        if (reducer_frontier_body_read_note_snapshot(&note))
            (void)reducer_frontier_body_read_note_clear_if(&note);
    }
    return NULL;
}

static void *body_note_raise_writer(void *arg)
{
    struct body_note_writer_args *a = arg;
    while (!atomic_load(&g_body_note_threads_go)) {
    }
    reducer_frontier_body_read_note_record(
        42, a->file, a->pos, a->reason, &a->hashes[0]);
    atomic_store(&g_body_note_raise_done, true);
    for (int i = 1; i < 1000; i++)
        reducer_frontier_body_read_note_record(
            42, a->file, a->pos, a->reason, &a->hashes[0]);
    return NULL;
}

/* Private-header declaration mirrored byte-for-byte (engine/jobs/src/
 * reducer_frontier_rewind_bases.h): the sovereignty case below calls the real
 * linked selector directly. */
struct reducer_frontier_rewind_base {
    int32_t height;
    bool    self_derived;
    bool    ratified;
    char    kind[32];
    char    commitment_sha3[65];
};
extern bool reducer_frontier_nearest_self_verified_base(
    int32_t at_or_below, struct reducer_frontier_rewind_base *out);

/* The trusted anchor the algorithm clamps to; fixtures sit just above it. */
#define A REDUCER_FRONTIER_TRUSTED_ANCHOR  /* 3056758 */

/* ── fixture builder ─────────────────────────────────────────────────── */

/* Create the per-stage log tables and the stage_cursor / progress_meta
 * tables exactly as production does. Returns false on any SQLite error. */
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
        "  tip_hash BLOB);";
    char *err = NULL;
    if (sqlite3_exec(db, ddl, NULL, NULL, &err) != SQLITE_OK) {
        fprintf(stderr, "[test_reducer_frontier] schema: %s\n",
                err ? err : "(null)");
        sqlite3_free(err);
        return false;
    }
    return true;
}

/* Stamp coins_kv proven-authority on the fixture db. `applied_height` is the
 * NEXT height to apply, so coverage through H needs H+1. compute_hstar treats
 * the baked TRUSTED_ANCHOR as a floor only when this frontier covers it,
 * else the floor drops to 0. Mirrors coins_kv_is_proven_authority: 8-byte LE
 * coins_applied_height, 1-byte migration-complete stamp, non-empty `coins`. */
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

/* Insert an ok row into a *_log table with (height, ok) plus an optional
 * 32-byte hash blob in `hash_col` (NULL => none). validate_headers_log's hash
 * is NOT NULL, so a hash is always supplied there via hbyte. */
static bool put_log_row(sqlite3 *db, const char *table, const char *hash_col,
                        int32_t height, int ok, const uint8_t hash[32],
                        const char *status)
{
    char sql[256];
    bool profile_bound = strcmp(table, "script_validate_log") == 0 ||
                         strcmp(table, "proof_validate_log") == 0 ||
                         strcmp(table, "utxo_apply_log") == 0;
    /* Successful validation rows carry the exact production evidence label;
     * failure rows keep the caller's diagnosis. */
    const char *row_status = profile_bound && ok == 1 ? "verified" : status;
    if (hash_col && row_status)
        snprintf(sql, sizeof(sql),
                 "INSERT INTO %s(height,status,ok,%s) VALUES(?,?,?,?)",
                 table, hash_col);
    else if (hash_col)
        snprintf(sql, sizeof(sql),
                 "INSERT INTO %s(height,ok,%s) VALUES(?,?,?)",
                 table, hash_col);
    else if (row_status)
        snprintf(sql, sizeof(sql),
                 "INSERT INTO %s(height,status,ok) VALUES(?,?,?)", table);
    else
        snprintf(sql, sizeof(sql),
                 "INSERT INTO %s(height,ok) VALUES(?,?)", table);

    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) != SQLITE_OK) {
        fprintf(stderr, "[test_reducer_frontier] prepare %s: %s\n",
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
    if (!done)
        fprintf(stderr, "[test_reducer_frontier] step %s h=%d: %s\n",
                table, height, sqlite3_errmsg(db));
    return done;
}

/* A deterministic 32-byte hash keyed by height + a tag byte, so we can make
 * two logs agree (same tag) or disagree (different tag) at a height. */
static void synth_hash(uint8_t out[32], int32_t h, uint8_t tag)
{
    memset(out, 0, 32);
    out[0] = (uint8_t)(h & 0xff);
    out[1] = (uint8_t)((h >> 8) & 0xff);
    out[2] = (uint8_t)((h >> 16) & 0xff);
    out[31] = tag;
}

static bool put_header_admit(sqlite3 *db, int32_t h,
                             const uint8_t hash[32])
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

static bool put_utxo_delta(sqlite3 *db, int32_t h,
                           const uint8_t hash[32])
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

/* Write a full consistent ok=1 row across ALL stage logs at height h, with
 * validate_headers.hash and script_validate.block_hash AGREEING (tag 0). */
static bool put_consistent_height(sqlite3 *db, int32_t h)
{
    uint8_t hh[32];
    synth_hash(hh, h, 0);
    return put_header_admit(db, h, hh)
        && put_log_row(db, "validate_headers_log", "hash", h, 1, hh, NULL)
        && put_log_row(db, "script_validate_log", "block_hash", h, 1, hh,
                       "ok")
        && put_log_row(db, "body_persist_log", NULL, h, 1, NULL, NULL)
        && put_log_row(db, "proof_validate_log", "block_hash", h, 1, hh,
                       NULL)
        && put_log_row(db, "utxo_apply_log", NULL, h, 1, NULL, NULL)
        && put_utxo_delta(db, h, hh)
        && put_log_row(db, "tip_finalize_log", NULL, h, 1, NULL, "ok");
}

static bool put_validate_failure(sqlite3 *db, int32_t h, const char *reason)
{
    uint8_t hh[32];
    synth_hash(hh, h, 0);

    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db,
            "INSERT INTO validate_headers_log(height,hash,ok,fail_reason) "
            "VALUES(?,?,0,?)",
            -1, &st, NULL) != SQLITE_OK) {
        fprintf(stderr, "[test_reducer_frontier] prepare validate fail: %s\n",
                sqlite3_errmsg(db));
        return false;
    }
    sqlite3_bind_int64(st, 1, h);
    sqlite3_bind_blob(st, 2, hh, 32, SQLITE_STATIC);
    sqlite3_bind_text(st, 3, reason ? reason : "", -1, SQLITE_STATIC);
    bool ok = sqlite3_step(st) == SQLITE_DONE;
    sqlite3_finalize(st);
    if (!ok)
        fprintf(stderr, "[test_reducer_frontier] step validate fail h=%d: %s\n",
                h, sqlite3_errmsg(db));
    return ok;
}

static bool put_tip_anchor(sqlite3 *db, int32_t h)
{
    return put_log_row(db, "tip_finalize_log", NULL, h, 1, NULL, "anchor");
}

static bool set_log_status(sqlite3 *db, const char *table, int32_t height,
                           const char *status)
{
    char sql[128];
    int n = snprintf(sql, sizeof(sql),
                     "UPDATE %s SET status=? WHERE height=?", table);
    if (n < 0 || n >= (int)sizeof(sql))
        return false;
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) != SQLITE_OK)
        return false;
    sqlite3_bind_text(st, 1, status, -1, SQLITE_STATIC);
    sqlite3_bind_int(st, 2, height);
    bool ok = sqlite3_step(st) == SQLITE_DONE &&
              sqlite3_changes(db) == 1;
    sqlite3_finalize(st);
    return ok;
}

static bool set_hash_value(sqlite3 *db, const char *table,
                           const char *column, int32_t height,
                           const void *value, int length, bool as_text)
{
    char sql[160];
    int n = snprintf(sql, sizeof(sql), "UPDATE %s SET %s=? WHERE height=?",
                     table, column);
    if (n <= 0 || n >= (int)sizeof(sql))
        return false;
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) != SQLITE_OK)
        return false;
    int rc = as_text
        ? sqlite3_bind_text(st, 1, value, length, SQLITE_STATIC)
        : sqlite3_bind_blob(st, 1, value, length, SQLITE_STATIC);
    sqlite3_bind_int(st, 2, height);
    bool ok = rc == SQLITE_OK && sqlite3_step(st) == SQLITE_DONE &&
              sqlite3_changes(db) == 1;
    sqlite3_finalize(st);
    return ok;
}

/* Set every reducer cursor to `c` (next-height frame == tip+1). tip_finalize
 * gets the same value: compute_hstar and reducer_anchor_candidate_ok
 * normalize its cursor to the next-height frame, so `c` and `c-1` yield the
 * same H*. */
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

/* ── cases ───────────────────────────────────────────────────────────── */

/* A provenance marker is not a coverage proof: coins and every stage agree
 * through K, the authority marker is valid, but K is far below the compiled
 * checkpoint A. A stale future anchor row must affect only served_floor;
 * H* stays the real folded K, never raised to A. */
static int case_partial_authority_does_not_enable_compiled_floor(void)
{
    int failures = 0;
    sqlite3 *db = NULL;
    if (sqlite3_open(":memory:", &db) != SQLITE_OK) return 1;
    RF_CHECK("partial-authority: schema", build_schema(db));

    const int32_t k = 3;
    RF_CHECK("partial-authority: proven only through K",
             stamp_proven_authority(db, k + 1));
    bool built = true;
    for (int32_t h = 1; h <= k; h++)
        built = built && put_consistent_height(db, h);
    RF_CHECK("partial-authority: real prefix rows", built);
    RF_CHECK("partial-authority: stale future anchor is present",
             put_tip_anchor(db, A + 100));
    RF_CHECK("partial-authority: cursors stop at K+1",
             set_all_cursors(db, k + 1));

    int32_t hstar = -1, served = -1;
    RF_CHECK("partial-authority: computation succeeds",
             reducer_frontier_compute_hstar(db, &hstar, &served));
    RF_CHECK("partial-authority: H* is honest folded prefix K", hstar == k);
    RF_CHECK("partial-authority: H* stays below uncovered checkpoint",
             hstar < A);
    RF_CHECK("partial-authority: stale served floor remains diagnostic",
             served == A + 100);
    sqlite3_close(db);

    /* Off-by-one boundary: coins_applied_height names the NEXT block. A value
     * equal to A therefore covers only through A-1 and must not enable floor A. */
    db = NULL;
    if (sqlite3_open(":memory:", &db) != SQLITE_OK) return failures + 1;
    RF_CHECK("partial-boundary: schema", build_schema(db));
    RF_CHECK("partial-boundary: proven through A-1",
             stamp_proven_authority(db, A));
    RF_CHECK("partial-boundary: empty cursors", set_all_cursors(db, 0));
    hstar = -1;
    served = -1;
    RF_CHECK("partial-boundary: computation succeeds",
             reducer_frontier_compute_hstar(db, &hstar, &served));
    RF_CHECK("partial-boundary: applied==A does not enable floor A",
             hstar == 0 && served == 0);
    sqlite3_close(db);
    return failures;
}

/* (a) Fully-consistent multi-row fixture: every log ok=1 and hashes agree
 *     over [A+1 .. A+5]. H* must reach the tip A+5; served_floor == A+5. */
static int case_consistent(void)
{
    int failures = 0;
    sqlite3 *db = NULL;
    if (sqlite3_open(":memory:", &db) != SQLITE_OK) { return 1; }
    RF_CHECK("consistent: schema", build_schema(db));
    RF_CHECK("consistent: proven authority", stamp_proven_authority(db, A + 1));

    const int32_t tip = A + 5;
    bool built = true;
    for (int32_t h = A + 1; h <= tip; h++)
        built = built && put_consistent_height(db, h);
    RF_CHECK("consistent: rows built", built);
    /* cursor names the NEXT height to process == tip+1. */
    RF_CHECK("consistent: cursors", set_all_cursors(db, tip + 1));

    int32_t hstar = -1, served = -1;
    bool ok = reducer_frontier_compute_hstar(db, &hstar, &served);
    RF_CHECK("consistent: returns true", ok);
    /* Mutation-sensitive: if the prefix walk stops early or off-by-one,
     * hstar != tip and this fails. */
    RF_CHECK("consistent: hstar == tip", hstar == tip);
    RF_CHECK("consistent: served_floor == tip", served == tip);

    sqlite3_close(db);
    return failures;
}

/* Every successful stage receipt above a trusted base must bind the same
 * selected-chain hash.  A proof receipt from fork B beside headers/scripts
 * from fork A, or a UTXO delta from B, cannot advance the serving frontier. */
static int case_proof_and_utxo_fork_split(void)
{
    int failures = 0;
    sqlite3 *db = NULL;
    if (sqlite3_open(":memory:", &db) != SQLITE_OK) return 1;
    RF_CHECK("proof-utxo-split: schema", build_schema(db));
    RF_CHECK("proof-utxo-split: proven authority", stamp_proven_authority(db, A + 1));
    bool built = true;
    for (int32_t h = A + 1; h <= A + 3; h++)
        built = built && put_consistent_height(db, h);
    RF_CHECK("proof-utxo-split: rows", built);
    RF_CHECK("proof-utxo-split: cursors", set_all_cursors(db, A + 4));

    uint8_t canonical[32], forked[32];
    synth_hash(canonical, A + 2, 0);
    synth_hash(forked, A + 2, 9);
    RF_CHECK("proof-utxo-split: proof fork fixture",
             set_hash_value(db, "proof_validate_log", "block_hash", A + 2,
                            forked, 32, false));
    int32_t hstar = -1, served = -1;
    RF_CHECK("proof-utxo-split: proof computation",
             reducer_frontier_compute_hstar(db, &hstar, &served));
    RF_CHECK("proof-utxo-split: proof fork caps H*", hstar == A + 1);
    RF_CHECK("proof-utxo-split: proof restore",
             set_hash_value(db, "proof_validate_log", "block_hash", A + 2,
                            canonical, 32, false));

    RF_CHECK("proof-utxo-split: UTXO fork fixture",
             set_hash_value(db, "utxo_apply_delta", "branch_hash", A + 2,
                            forked, 32, false));
    RF_CHECK("proof-utxo-split: UTXO computation",
             reducer_frontier_compute_hstar(db, &hstar, &served));
    RF_CHECK("proof-utxo-split: UTXO fork caps H*", hstar == A + 1);
    static const char text_hash[] = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    RF_CHECK("proof-utxo-split: text UTXO hash fixture",
             set_hash_value(db, "utxo_apply_delta", "branch_hash", A + 2,
                            text_hash, 32, true));
    RF_CHECK("proof-utxo-split: text UTXO computation",
             reducer_frontier_compute_hstar(db, &hstar, &served));
    RF_CHECK("proof-utxo-split: text UTXO hash caps H*", hstar == A + 1);

    sqlite3_close(db);
    return failures;
}

/* Checkpoint-fold rows are transparent state-production evidence, never a
 * serving validation receipt. Every consensus-validation column must cap H*
 * below the first such row. A text-typed hash is likewise not a hash proof. */
static int case_validation_evidence_contained(void)
{
    int failures = 0;
    sqlite3 *db = NULL;
    if (sqlite3_open(":memory:", &db) != SQLITE_OK) { return 1; }
    RF_CHECK("evidence: schema", build_schema(db));
    RF_CHECK("evidence: proven authority", stamp_proven_authority(db, A + 1));

    const int32_t tip = A + 3;
    bool built = true;
    for (int32_t h = A + 1; h <= tip; h++)
        built = built && put_consistent_height(db, h);
    RF_CHECK("evidence: rows built", built);
    RF_CHECK("evidence: cursors", set_all_cursors(db, tip + 1));

    static const char *const tables[] = {
        "script_validate_log", "proof_validate_log", "utxo_apply_log",
    };
    for (size_t i = 0; i < sizeof(tables) / sizeof(tables[0]); i++) {
        RF_CHECK("evidence: checkpoint row fixture",
                 set_log_status(db, tables[i], A + 2, "checkpoint_fold"));
        int32_t hstar = -1, served = -1;
        RF_CHECK("evidence: checkpoint computation succeeds",
                 reducer_frontier_compute_hstar(db, &hstar, &served));
        RF_CHECK("evidence: checkpoint row caps H*", hstar == A + 1);
        RF_CHECK("evidence: restore verified row",
                 set_log_status(db, tables[i], A + 2, "verified"));
    }

    sqlite3_stmt *st = NULL;
    bool text_hash = sqlite3_prepare_v2(db,
        "UPDATE script_validate_log SET block_hash=? WHERE height=?",
        -1, &st, NULL) == SQLITE_OK;
    if (text_hash) {
        static const char thirty_two_a[] = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        sqlite3_bind_text(st, 1, thirty_two_a, 32, SQLITE_STATIC);
        sqlite3_bind_int(st, 2, A + 2);
        text_hash = sqlite3_step(st) == SQLITE_DONE;
    }
    if (st)
        sqlite3_finalize(st);
    RF_CHECK("evidence: text-typed hash fixture", text_hash);
    int32_t hstar = -1, served = -1;
    RF_CHECK("evidence: malformed hash computation succeeds",
             reducer_frontier_compute_hstar(db, &hstar, &served));
    RF_CHECK("evidence: text-typed hash caps H*", hstar == A + 1);

    sqlite3_close(db);
    return failures;
}

/* (b) Torn fixture: utxo_apply ran forward, but script_validate has an ok=0
 * laggard at A+4. The contiguous-prefix MIN caps H* at A+3. tip_finalize has
 * stale ok=0 debris above A+3 and a fresh ok=1 at A+3, so served_floor is
 * A+3. */
static int case_torn(void)
{
    int failures = 0;
    sqlite3 *db = NULL;
    if (sqlite3_open(":memory:", &db) != SQLITE_OK) { return 1; }
    RF_CHECK("torn: schema", build_schema(db));
    RF_CHECK("torn: proven authority", stamp_proven_authority(db, A + 1));

    bool built = true;
    /* A+1..A+3 fully consistent and finalized. */
    for (int32_t h = A + 1; h <= A + 3; h++)
        built = built && put_consistent_height(db, h);

    /* script_validate fails at A+4; the other logs are ok=1 there, so the
     * MIN over logs caps the prefix at A+3. */
    uint8_t h4[32]; synth_hash(h4, A + 4, 0);
    built = built
        && put_log_row(db, "validate_headers_log", "hash", A + 4, 1, h4, NULL)
        && put_log_row(db, "script_validate_log", "block_hash", A + 4, 0, NULL,
                       "not_script_valid")
        && put_log_row(db, "body_persist_log", NULL, A + 4, 1, NULL, NULL)
        && put_log_row(db, "proof_validate_log", NULL, A + 4, 1, NULL, NULL)
        /* utxo_apply forged forward (ok=1) far past the finalize laggard. */
        && put_log_row(db, "utxo_apply_log", NULL, A + 4, 1, NULL, NULL)
        && put_log_row(db, "utxo_apply_log", NULL, A + 5, 1, NULL, NULL)
        && put_log_row(db, "utxo_apply_log", NULL, A + 6, 1, NULL, NULL)
        /* stale ok=0 debris above A+3 must NOT raise served_floor. */
        && put_log_row(db, "tip_finalize_log", NULL, A + 4, 0, NULL, "stale")
        && put_log_row(db, "tip_finalize_log", NULL, A + 5, 0, NULL, "stale");
    RF_CHECK("torn: rows built", built);
    RF_CHECK("torn: vh hash", true);

    /* Cursors: validate_headers far ahead, utxo_apply ahead, tip_finalize
     * lagging at the failure. */
    bool cur = set_cursor(db, "validate_headers", A + 7)
            && set_cursor(db, "body_fetch", A + 7)
            && set_cursor(db, "body_persist", A + 7)
            && set_cursor(db, "proof_validate", A + 7)
            && set_cursor(db, "script_validate", A + 5)
            && set_cursor(db, "utxo_apply", A + 7)
            && set_cursor(db, "tip_finalize", A + 5);
    RF_CHECK("torn: cursors", cur);

    /* coins_applied ahead of H* (the live "coins consistent, flag drift"
     * case): an 8-byte LE int64 blob, like coins_kv writes. */
    int64_t applied = A + 6;
    uint8_t blob[8];
    for (int i = 0; i < 8; i++) blob[i] = (uint8_t)((uint64_t)applied >> (8*i));
    sqlite3_stmt *st = NULL;
    bool meta_ok =
        sqlite3_prepare_v2(db,
            "INSERT OR REPLACE INTO progress_meta(key,value) "
            "VALUES('coins_applied_height',?)", -1, &st, NULL) == SQLITE_OK;
    if (meta_ok) {
        sqlite3_bind_blob(st, 1, blob, 8, SQLITE_STATIC);
        meta_ok = sqlite3_step(st) == SQLITE_DONE;
        sqlite3_finalize(st);
    }
    RF_CHECK("torn: coins_applied meta", meta_ok);

    int32_t hstar = -1, served = -1;
    bool ok = reducer_frontier_compute_hstar(db, &hstar, &served);
    RF_CHECK("torn: returns true", ok);
    /* The prefix caps at A+3; trusting the forward utxo_apply cursor would
     * give A+6. */
    RF_CHECK("torn: hstar == A+3", hstar == A + 3);
    /* served_floor is the deepest ok=1 finalize (A+3). */
    RF_CHECK("torn: served_floor == A+3", served == A + 3);
    /* H* must never exceed served_floor in a torn view (invariant). */
    RF_CHECK("torn: hstar <= served_floor", hstar <= served);

    sqlite3_close(db);
    return failures;
}

/* (b2) Sparse imported base: reducer logs are absent across the imported
 * middle, then a seed-anchor row marks a later trusted base with dense rows
 * above it. H* starts from that anchor, not the compiled checkpoint, and
 * ignores a stale higher anchor whose upstream cursors never reached it. */
static int case_sparse_seed_anchor(void)
{
    int failures = 0;
    sqlite3 *db = NULL;
    if (sqlite3_open(":memory:", &db) != SQLITE_OK) { return 1; }
    RF_CHECK("sparse-anchor: schema", build_schema(db));
    const int32_t base = A + 100;
    const int32_t stale_high = A + 200;
    const int32_t tip = base + 5;
    RF_CHECK("sparse-anchor: proven authority through imported base",
             stamp_proven_authority(db, base + 1));
    bool built = put_tip_anchor(db, stale_high) && put_tip_anchor(db, base);
    for (int32_t h = base + 1; h <= tip; h++)
        built = built && put_consistent_height(db, h);
    RF_CHECK("sparse-anchor: rows built", built);
    RF_CHECK("sparse-anchor: cursors", set_all_cursors(db, tip + 1));

    int32_t hstar = -1, served = -1;
    bool ok = reducer_frontier_compute_hstar(db, &hstar, &served);
    RF_CHECK("sparse-anchor: returns true", ok);
    RF_CHECK("sparse-anchor: hstar reaches dense tip", hstar == tip);
    RF_CHECK("sparse-anchor: stale high anchor ignored", hstar < stale_high);
    RF_CHECK("sparse-anchor: served_floor sees stale public anchor",
             served == stale_high);

    sqlite3_close(db);
    return failures;
}

static bool put_int64_le_meta(sqlite3 *db, const char *key, int64_t v);

/* (b2.1) Blocks-less verified bundle base: the loader writes the tip_finalize
 * anchor row and the trusted-base declaration at `base` and sets cursors to
 * at least base+1. Rowless state above base keeps H* at the trusted base; a
 * real ok=0 row is covered by the collapse case below. */
static int case_durable_base_accepts_rowless_first(void)
{
    int failures = 0;
    sqlite3 *db = NULL;
    if (sqlite3_open(":memory:", &db) != SQLITE_OK) { return 1; }
    RF_CHECK("rowless-base: schema", build_schema(db));

    const int32_t base = A + 100;
    RF_CHECK("rowless-base: proven authority",
             stamp_proven_authority(db, base + 1));
    RF_CHECK("rowless-base: seed anchor row", put_tip_anchor(db, base));
    RF_CHECK("rowless-base: durable trusted base key",
             put_int64_le_meta(db, REDUCER_TRUSTED_BASE_HEIGHT_KEY, base));

    /* No rows at base+1 in any log; cursors sit past base+1. */
    RF_CHECK("rowless-base: cursors", set_all_cursors(db, base + 2));

    int32_t hstar = -1, served = -1;
    bool ok = reducer_frontier_compute_hstar(db, &hstar, &served);
    RF_CHECK("rowless-base: returns true", ok);
    RF_CHECK("rowless-base: hstar == durable base", hstar == base);
    RF_CHECK("rowless-base: served_floor == seed anchor", served == base);

    RF_CHECK("rowless-base: exact-length TEXT authority planted",
             sqlite3_exec(db,
                 "UPDATE progress_meta SET value=CAST('12345678' AS TEXT) "
                 "WHERE key='" REDUCER_TRUSTED_BASE_HEIGHT_KEY "'",
                 NULL, NULL, NULL) == SQLITE_OK);
    RF_CHECK("rowless-base: TEXT authority fails closed",
             !reducer_frontier_compute_hstar(db, &hstar, &served));
    RF_CHECK("rowless-base: high-bit BLOB authority planted",
             put_int64_le_meta(db, REDUCER_TRUSTED_BASE_HEIGHT_KEY,
                               INT64_MIN));
    RF_CHECK("rowless-base: high-bit BLOB authority fails closed",
             !reducer_frontier_compute_hstar(db, &hstar, &served));

    sqlite3_close(db);
    return failures;
}

static int case_durable_base_survives_header_failure(void)
{
    int failures = 0;
    sqlite3 *db = NULL;
    if (sqlite3_open(":memory:", &db) != SQLITE_OK) { return 1; }
    RF_CHECK("header-fail-base: schema", build_schema(db));

    const int32_t base = A + 100;
    RF_CHECK("header-fail-base: proven authority",
             stamp_proven_authority(db, base + 1));
    RF_CHECK("header-fail-base: seed anchor row", put_tip_anchor(db, base));
    RF_CHECK("header-fail-base: durable trusted base key",
             put_int64_le_meta(db, REDUCER_TRUSTED_BASE_HEIGHT_KEY, base));
    RF_CHECK("header-fail-base: validate failure row",
             put_validate_failure(db, base + 1,
                                  "no-header-solution-backfill-required"));
    RF_CHECK("header-fail-base: cursors", set_all_cursors(db, base + 2));

    int32_t hstar = -1, served = -1;
    bool ok = reducer_frontier_compute_hstar(db, &hstar, &served);
    RF_CHECK("header-fail-base: returns true", ok);
    RF_CHECK("header-fail-base: hstar stays at durable base", hstar == base);
    RF_CHECK("header-fail-base: served_floor == seed anchor", served == base);

    sqlite3_close(db);
    return failures;
}

/* (b3) Anchor-collapse guard. A cold import seeded a trusted base at `base`
 * (tip_finalize anchor row and durable REDUCER_TRUSTED_BASE_HEIGHT_KEY) over
 * a log-less region [A+1 .. base-1]. The block at base+1 spends a coin the
 * import never installed, so script_validate records ok=0 there while every
 * other stage is ok=1.
 *
 * reducer_anchor_candidate_ok(base) probes base+1, finds script_validate
 * ok=0 and rejects the base, so the anchor collapses to the compiled
 * checkpoint A while served_floor still reports the imported tip. hstar == A
 * is the consensus-safe answer: H* must never float up over a real ok=0. */
static bool put_int64_le_meta(sqlite3 *db, const char *key, int64_t v)
{
    uint8_t blob[8];
    for (int i = 0; i < 8; i++)
        blob[i] = (uint8_t)((uint64_t)v >> (8 * i));
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db,
            "INSERT OR REPLACE INTO progress_meta(key,value) VALUES(?,?)",
            -1, &st, NULL) != SQLITE_OK)
        return false;
    sqlite3_bind_text(st, 1, key, -1, SQLITE_STATIC);
    sqlite3_bind_blob(st, 2, blob, 8, SQLITE_STATIC);
    bool ok = sqlite3_step(st) == SQLITE_DONE;
    sqlite3_finalize(st);
    return ok;
}

static int case_anchor_collapse_after_forward_ok0(void)
{
    int failures = 0;
    sqlite3 *db = NULL;
    if (sqlite3_open(":memory:", &db) != SQLITE_OK) { return 1; }
    RF_CHECK("collapse: schema", build_schema(db));
    RF_CHECK("collapse: proven authority", stamp_proven_authority(db, A + 1));

    const int32_t base = A + 100;   /* the cold-import terminal tip */

    /* Trusted base declared as the import path writes it: seed-anchor row
     * and the durable height key. */
    RF_CHECK("collapse: seed anchor row", put_tip_anchor(db, base));
    RF_CHECK("collapse: durable trusted base key",
             put_int64_le_meta(db, REDUCER_TRUSTED_BASE_HEIGHT_KEY, base));

    /* [A+1 .. base-1] is log-less. base+1: every stage ok=1 except
     * script_validate (ok=0, prevout_unresolved); no tip_finalize row. */
    uint8_t h1[32]; synth_hash(h1, base + 1, 0);
    bool row =
        put_log_row(db, "validate_headers_log", "hash", base + 1, 1, h1, NULL)
        && put_log_row(db, "script_validate_log", "block_hash", base + 1, 0,
                       NULL, "prevout_unresolved")
        && put_log_row(db, "body_persist_log", NULL, base + 1, 1, NULL, NULL)
        && put_log_row(db, "proof_validate_log", NULL, base + 1, 1, NULL, NULL)
        && put_log_row(db, "utxo_apply_log", NULL, base + 1, 1, NULL, NULL);
    RF_CHECK("collapse: spend-block rows", row);

    /* Cursors reach base+2 so the candidate gate probes the ok=0 at base+1. */
    RF_CHECK("collapse: cursors", set_all_cursors(db, base + 2));
    RF_CHECK("collapse: coins_applied meta",
             put_int64_le_meta(db, "coins_applied_height", base + 1));

    int32_t hstar = -1, served = -1;
    bool ok = reducer_frontier_compute_hstar(db, &hstar, &served);
    RF_CHECK("collapse: returns true", ok);
    /* The base is rejected over the real ok=0; H* collapses to A. */
    RF_CHECK("collapse: hstar == anchor (refuses to float over real ok=0)",
             hstar == A);
    /* served_floor still reports the imported tip's seed anchor. */
    RF_CHECK("collapse: served_floor == base (imported tip)", served == base);
    RF_CHECK("collapse: hstar < served_floor (the torn-view gap)",
             hstar < served);

    sqlite3_close(db);
    return failures;
}

/* (c) Clamp-up: the only logged row is an ok=0 failure just above the
 * anchor, so the prefix is the anchor and a hash split below it must never
 * pull it lower. H* is clamped up to the anchor even with an empty finalize
 * log. */
static int case_clamp_up(void)
{
    int failures = 0;
    sqlite3 *db = NULL;
    if (sqlite3_open(":memory:", &db) != SQLITE_OK) { return 1; }
    RF_CHECK("clamp: schema", build_schema(db));
    RF_CHECK("clamp: proven authority", stamp_proven_authority(db, A + 1));

    /* script_validate fails at anchor+1, so the prefix is the anchor.
     * validate_headers_log has no `status` column: status=NULL there. */
    uint8_t zero[32] = {0};
    bool built =
        put_log_row(db, "script_validate_log", "block_hash", A + 1, 0, NULL,
                    "not_script_valid")
        && put_log_row(db, "validate_headers_log", "hash", A + 1, 0,
                       zero, NULL);
    RF_CHECK("clamp: rows built", built);
    RF_CHECK("clamp: cursors", set_all_cursors(db, A + 2));

    int32_t hstar = -1, served = -1;
    bool ok = reducer_frontier_compute_hstar(db, &hstar, &served);
    RF_CHECK("clamp: returns true", ok);
    /* The hard guard raises H* to the anchor; it must NEVER be below it. */
    RF_CHECK("clamp: hstar == anchor", hstar == A);
    RF_CHECK("clamp: hstar >= TRUSTED_ANCHOR", hstar >= A);
    RF_CHECK("clamp: served_floor == 0 (no ok=1 finalize)", served == 0);

    sqlite3_close(db);
    return failures;
}

/* (d) Hash split: validate_headers and script_validate hashes disagree at
 * A+3, so H* caps at A+2 though every log is ok=1 through A+5. */
static int case_hash_split(void)
{
    int failures = 0;
    sqlite3 *db = NULL;
    if (sqlite3_open(":memory:", &db) != SQLITE_OK) { return 1; }
    RF_CHECK("split: schema", build_schema(db));
    RF_CHECK("split: proven authority", stamp_proven_authority(db, A + 1));

    bool built = true;
    for (int32_t h = A + 1; h <= A + 2; h++)
        built = built && put_consistent_height(db, h);

    /* A+3: both ok=1 in every log, but the two hash columns DISAGREE
     * (tag 0 vs tag 9). */
    uint8_t hv[32], hs[32];
    synth_hash(hv, A + 3, 0);
    synth_hash(hs, A + 3, 9);
    built = built
        && put_log_row(db, "validate_headers_log", "hash", A + 3, 1, hv, NULL)
        && put_log_row(db, "script_validate_log", "block_hash", A + 3, 1, hs,
                       "ok")
        && put_log_row(db, "body_persist_log", NULL, A + 3, 1, NULL, NULL)
        && put_log_row(db, "proof_validate_log", NULL, A + 3, 1, NULL, NULL)
        && put_log_row(db, "utxo_apply_log", NULL, A + 3, 1, NULL, NULL)
        && put_log_row(db, "tip_finalize_log", NULL, A + 3, 1, NULL, "ok");
    for (int32_t h = A + 4; h <= A + 5; h++)
        built = built && put_consistent_height(db, h);
    RF_CHECK("split: rows built", built);
    RF_CHECK("split: cursors", set_all_cursors(db, A + 6));

    int32_t hstar = -1, served = -1;
    bool ok = reducer_frontier_compute_hstar(db, &hstar, &served);
    RF_CHECK("split: returns true", ok);
    /* H* caps at A+2, the block before the split. */
    RF_CHECK("split: hstar == A+2", hstar == A + 2);
    /* served_floor still reaches the deepest ok=1 finalize (A+5). */
    RF_CHECK("split: served_floor == A+5", served == A + 5);

    sqlite3_close(db);
    return failures;
}

/* (e) Hash split at A+1: the prefix would reach A+3, but the hashes disagree
 * at the first height above the anchor, so H* clamps to the anchor. Drives
 * the "never below the anchor" lower clamp. */
static int case_split_at_floor(void)
{
    int failures = 0;
    sqlite3 *db = NULL;
    if (sqlite3_open(":memory:", &db) != SQLITE_OK) { return 1; }
    RF_CHECK("floor: schema", build_schema(db));
    RF_CHECK("floor: proven authority", stamp_proven_authority(db, A + 1));

    /* A+1: ok=1 everywhere but hashes disagree (tag 0 vs tag 7). */
    uint8_t hv[32], hs[32];
    synth_hash(hv, A + 1, 0);
    synth_hash(hs, A + 1, 7);
    bool built =
        put_log_row(db, "validate_headers_log", "hash", A + 1, 1, hv, NULL)
        && put_log_row(db, "script_validate_log", "block_hash", A + 1, 1, hs,
                       "ok")
        && put_log_row(db, "body_persist_log", NULL, A + 1, 1, NULL, NULL)
        && put_log_row(db, "proof_validate_log", NULL, A + 1, 1, NULL, NULL)
        && put_log_row(db, "utxo_apply_log", NULL, A + 1, 1, NULL, NULL)
        && put_log_row(db, "tip_finalize_log", NULL, A + 1, 1, NULL, "ok");
    for (int32_t h = A + 2; h <= A + 3; h++)
        built = built && put_consistent_height(db, h);
    RF_CHECK("floor: rows built", built);
    RF_CHECK("floor: cursors", set_all_cursors(db, A + 4));

    int32_t hstar = -1, served = -1;
    bool ok = reducer_frontier_compute_hstar(db, &hstar, &served);
    RF_CHECK("floor: returns true", ok);
    /* Split at the first height above the anchor: H* is the anchor itself,
     * never below it. */
    RF_CHECK("floor: hstar == anchor", hstar == A);
    RF_CHECK("floor: hstar >= TRUSTED_ANCHOR", hstar >= A);

    sqlite3_close(db);
    return failures;
}

/* (f) Pre-flip schema: proof_validate_log has no block_hash column (see
 * proof_validate_null_hash_rearm.c). The split scan must not error on the
 * absent column and must still derive agreement from the witnesses the
 * schema carries (validate_headers.hash, header_admit.hash,
 * script_validate.block_hash, utxo_apply_delta.branch_hash). */
static int case_preflip_no_proof_block_hash(void)
{
    int failures = 0;
    sqlite3 *db = NULL;
    if (sqlite3_open(":memory:", &db) != SQLITE_OK) { return 1; }
    RF_CHECK("preflip: schema", build_schema(db));
    RF_CHECK("preflip: proven authority", stamp_proven_authority(db, A + 1));

    /* Recreate proof_validate_log without block_hash (pre-flip shape). */
    char *err = NULL;
    RF_CHECK("preflip: drop proof block_hash column",
             sqlite3_exec(db,
                 "DROP TABLE proof_validate_log;"
                 "CREATE TABLE proof_validate_log ("
                 "  height INTEGER PRIMARY KEY, status TEXT,"
                 "  ok INTEGER NOT NULL);",
                 NULL, NULL, &err) == SQLITE_OK);
    sqlite3_free(err);

    /* A+1..A+5 consistent across every carried witness; proof rows ok=1
     * with no block_hash. */
    bool built = true;
    for (int32_t h = A + 1; h <= A + 5; h++) {
        uint8_t hh[32];
        synth_hash(hh, h, 0);
        built = built
            && put_header_admit(db, h, hh)
            && put_log_row(db, "validate_headers_log", "hash", h, 1, hh, NULL)
            && put_log_row(db, "script_validate_log", "block_hash", h, 1, hh,
                           "ok")
            && put_log_row(db, "body_persist_log", NULL, h, 1, NULL, NULL)
            && put_log_row(db, "proof_validate_log", NULL, h, 1, NULL, NULL)
            && put_log_row(db, "utxo_apply_log", NULL, h, 1, NULL, NULL)
            && put_utxo_delta(db, h, hh)
            && put_log_row(db, "tip_finalize_log", NULL, h, 1, NULL, "ok");
    }
    RF_CHECK("preflip: rows built", built);
    RF_CHECK("preflip: cursors", set_all_cursors(db, A + 6));

    int32_t hstar = -1, served = -1;
    bool ok = reducer_frontier_compute_hstar(db, &hstar, &served);
    /* (1) No missing-column abort: compute_hstar returns true. */
    RF_CHECK("preflip: compute returns true (no missing-column abort)", ok);
    /* (2) The resolved prefix reaches A+5: an absent witness is not a split. */
    RF_CHECK("preflip: hstar == A+5", hstar == A + 5);

    /* A real disagreement in a CARRIED witness (script) at A+3 still clamps. */
    uint8_t bad[32];
    synth_hash(bad, A + 3, 9);
    RF_CHECK("preflip: script fork fixture",
             set_hash_value(db, "script_validate_log", "block_hash", A + 3,
                            bad, 32, false));
    hstar = -1; served = -1;
    RF_CHECK("preflip: recompute",
             reducer_frontier_compute_hstar(db, &hstar, &served));
    RF_CHECK("preflip: carried-witness fork caps H* at A+2", hstar == A + 2);

    sqlite3_close(db);
    return failures;
}

static int case_dump_reports_validate_failure_owner(void)
{
    int failures = 0;
    char dir[256];
    test_make_tmpdir(dir, sizeof(dir), "reducer_frontier", "dump");

    progress_store_close();
    bool opened = progress_store_open(dir);
    RF_CHECK("dump: progress_store opens", opened);
    if (!opened) {
        test_cleanup_tmpdir(dir);
        return failures;
    }

    sqlite3 *db = progress_store_db();
    RF_CHECK("dump: schema", db && build_schema(db));
    RF_CHECK("dump: proven authority", db && stamp_proven_authority(db, A + 1));

    const int32_t fail_h = A + 3;
    bool built = put_consistent_height(db, A + 1)
              && put_consistent_height(db, A + 2)
              && put_validate_failure(db, fail_h,
                                      "header-source-hash-mismatch")
              && put_log_row(db, "script_validate_log", "block_hash",
                             fail_h, 0, NULL, "upstream_failed")
              && put_log_row(db, "body_persist_log", NULL,
                             fail_h, 1, NULL, NULL)
              && put_log_row(db, "proof_validate_log", NULL,
                             fail_h, 1, NULL, NULL)
              && put_log_row(db, "utxo_apply_log", NULL,
                             fail_h, 1, NULL, NULL);
    RF_CHECK("dump: rows built", built);
    RF_CHECK("dump: cursors", set_all_cursors(db, fail_h + 1));

    struct json_value out;
    json_init(&out);
    bool dumped = reducer_frontier_dump_state_json(&out, NULL);
    RF_CHECK("dump: returns true", dumped);
    if (dumped) {
        RF_CHECK("dump: hstar reaches block before validate failure",
                 json_get_int(json_get(&out, "hstar")) == fail_h - 1);
        RF_CHECK("dump: first validate failure found",
                 json_get_bool(json_get(&out,
                                        "first_validate_failure_found")));
        RF_CHECK("dump: first validate failure height",
                 json_get_int(json_get(&out,
                                       "first_validate_failure_height"))
                     == fail_h);
        RF_CHECK("dump: first validate failure reason",
                 strcmp(json_get_str(json_get(&out,
                           "first_validate_failure_reason")),
                        "header-source-hash-mismatch") == 0);
        RF_CHECK("dump: first validate failure owner",
                 strcmp(json_get_str(json_get(&out,
                           "first_validate_failure_repair_owner")),
                        "stale_validate_headers_repair") == 0);
        RF_CHECK("dump: hstar blocker found",
                 json_get_bool(json_get(&out,
                                        "first_hstar_blocker_found")));
        RF_CHECK("dump: hstar blocker stage",
                 strcmp(json_get_str(json_get(&out,
                           "first_hstar_blocker_stage")),
                        "validate_headers") == 0);
        RF_CHECK("dump: hstar blocker height",
                 json_get_int(json_get(&out,
                                       "first_hstar_blocker_height"))
                     == fail_h);
        RF_CHECK("dump: hstar blocker kind",
                 strcmp(json_get_str(json_get(&out,
                           "first_hstar_blocker_kind")),
                        "ok0_failure") == 0);
        RF_CHECK("dump: hstar blocker reason",
                 strcmp(json_get_str(json_get(&out,
                           "first_hstar_blocker_reason")),
                        "header-source-hash-mismatch") == 0);
        RF_CHECK("dump: hstar blocker owner",
                 strcmp(json_get_str(json_get(&out,
                           "first_hstar_blocker_repair_owner")),
                        "stale_validate_headers_repair") == 0);
        RF_CHECK("dump: hstar next height",
                 json_get_int(json_get(&out, "hstar_next_height")) == fail_h);
        RF_CHECK("dump: hstar next blocked",
                 json_get_bool(json_get(&out, "hstar_next_blocked")));
        RF_CHECK("dump: hstar next primary kind",
                 strcmp(json_get_str(json_get(&out,
                           "hstar_next_primary_kind")),
                        "ok0_failure") == 0);
        RF_CHECK("dump: hstar next primary table",
                 strcmp(json_get_str(json_get(&out,
                           "hstar_next_primary_log_table")),
                        "validate_headers_log") == 0);
    }
    json_free(&out);

    progress_store_close();
    test_cleanup_tmpdir(dir);
    return failures;
}

static const struct json_value *dumped_cursor(const struct json_value *out,
                                             const char *stage)
{
    const struct json_value *arr = json_get(out, "stage_cursors");
    if (!arr || arr->type != JSON_ARR)
        return NULL;
    for (size_t i = 0; i < arr->num_children; i++) {
        const struct json_value *c = &arr->children[i];
        if (strcmp(json_get_str(json_get(c, "stage")), stage) == 0)
            return c;
    }
    return NULL;
}

/* Run-ahead visibility: a stage cursor above H* has consumed heights nothing
 * verified, and the dump must report it as unproven, while a cursor level
 * with H* is not. header_admit and body_fetch sit outside the H*-bearing log
 * set, so moving them cannot move H*: the marking is derived at query time,
 * not stored. */
static int case_dump_marks_run_ahead_stage_cursors(void)
{
    int failures = 0;
    char dir[256];
    test_make_tmpdir(dir, sizeof(dir), "reducer_frontier", "runahead");

    progress_store_close();
    bool opened = progress_store_open(dir);
    RF_CHECK("runahead: progress_store opens", opened);
    if (!opened) {
        test_cleanup_tmpdir(dir);
        return failures;
    }

    sqlite3 *db = progress_store_db();
    RF_CHECK("runahead: schema", db && build_schema(db));
    RF_CHECK("runahead: proven authority", db && stamp_proven_authority(db, A + 1));

    const int32_t tip = A + 3;
    bool built = db != NULL;
    for (int32_t h = A + 1; h <= tip; h++)
        built = built && put_consistent_height(db, h);
    RF_CHECK("runahead: rows built", built);
    RF_CHECK("runahead: log cursors", db && set_all_cursors(db, tip + 1));
    RF_CHECK("runahead: header_admit cursor",
             db && set_cursor(db, "header_admit", tip + 1));

    struct json_value probe;
    json_init(&probe);
    bool probed = reducer_frontier_dump_state_json(&probe, NULL);
    RF_CHECK("runahead: probe dump returns true", probed);
    int64_t hstar = probed ? json_get_int(json_get(&probe, "hstar")) : -1;
    json_free(&probe);
    RF_CHECK("runahead: fixture hstar known", hstar == tip);

    RF_CHECK("runahead: level cursor set to hstar+1",
             db && set_cursor(db, "header_admit", hstar + 1));
    RF_CHECK("runahead: run-ahead cursor set to hstar+8",
             db && set_cursor(db, "body_fetch", hstar + 8));

    struct json_value out;
    json_init(&out);
    bool dumped = reducer_frontier_dump_state_json(&out, NULL);
    RF_CHECK("runahead: returns true", dumped);
    if (dumped) {
        RF_CHECK("runahead: cursor moves did not move hstar",
                 json_get_int(json_get(&out, "hstar")) == hstar);

        const struct json_value *ahead = dumped_cursor(&out, "body_fetch");
        RF_CHECK("runahead: run-ahead cursor is serialized", ahead != NULL);
        if (ahead) {
            RF_CHECK("runahead: run-ahead cursor marked above hstar",
                     json_get_bool(json_get(ahead, "above_hstar")));
            RF_CHECK("runahead: run-ahead depth is 7 heights",
                     json_get_int(json_get(ahead, "heights_above_hstar"))
                         == 7);
            RF_CHECK("runahead: run-ahead consumed height is hstar+7",
                     json_get_int(json_get(ahead, "consumed_height"))
                         == hstar + 7);
            RF_CHECK("runahead: run-ahead trust says it may be wrong",
                     strcmp(json_get_str(json_get(ahead, "trust")),
                            "unproven_may_be_wrong") == 0);
        }

        const struct json_value *level = dumped_cursor(&out, "header_admit");
        RF_CHECK("runahead: level cursor is serialized", level != NULL);
        if (level) {
            RF_CHECK("runahead: level cursor NOT marked above hstar",
                     !json_get_bool(json_get(level, "above_hstar")));
            RF_CHECK("runahead: level cursor depth is zero",
                     json_get_int(json_get(level, "heights_above_hstar"))
                         == 0);
            RF_CHECK("runahead: level cursor consumed height is hstar",
                     json_get_int(json_get(level, "consumed_height"))
                         == hstar);
            RF_CHECK("runahead: level cursor trust is within-verified",
                     strcmp(json_get_str(json_get(level, "trust")),
                            "within_verified_hstar") == 0);
        }

        RF_CHECK("runahead: exactly one cursor counted above hstar",
                 json_get_int(json_get(&out,
                     "stage_cursors_above_hstar_count")) == 1);
        RF_CHECK("runahead: deepest run-ahead reported",
                 json_get_int(json_get(&out,
                     "stage_cursors_above_hstar_max_depth")) == 7);
        RF_CHECK("runahead: note names hstar as the only proven height",
                 strstr(json_get_str(json_get(&out,
                            "stage_cursors_trust_note")),
                        "only proven height") != NULL);

        /* Pin the wire text via json_write, the dumpstate reply's writer. */
        static char wire[32768];
        size_t need = json_write(&out, wire, sizeof(wire));
        RF_CHECK("runahead: serialized dump not truncated",
                 need < sizeof(wire));
        RF_CHECK("runahead: wire carries the unproven marking",
                 strstr(wire, "\"trust\":\"unproven_may_be_wrong\"") != NULL);
        RF_CHECK("runahead: wire carries the run-ahead depth",
                 strstr(wire, "\"heights_above_hstar\":7") != NULL);
        RF_CHECK("runahead: wire carries the within-verified marking",
                 strstr(wire, "\"trust\":\"within_verified_hstar\"") != NULL);
        RF_CHECK("runahead: wire carries the run-ahead count",
                 strstr(wire, "\"stage_cursors_above_hstar_count\":1") != NULL);
    }
    json_free(&out);

    /* Five cursors run ahead together while the verified height does not
     * move; the aggregate must count all five. */
    bool ran_ahead = db != NULL
        && set_cursor(db, "validate_headers", hstar + 8)
        && set_cursor(db, "body_fetch", hstar + 8)
        && set_cursor(db, "body_persist", hstar + 8)
        && set_cursor(db, "script_validate", hstar + 8)
        && set_cursor(db, "proof_validate", hstar + 8);
    RF_CHECK("runahead: five cursors run ahead", ran_ahead);

    struct json_value five;
    json_init(&five);
    bool dumped_five = reducer_frontier_dump_state_json(&five, NULL);
    RF_CHECK("runahead-five: returns true", dumped_five);
    if (dumped_five) {
        RF_CHECK("runahead-five: verified height did not move",
                 json_get_int(json_get(&five, "hstar")) == hstar);
        RF_CHECK("runahead-five: five cursors counted above hstar",
                 json_get_int(json_get(&five,
                     "stage_cursors_above_hstar_count")) == 5);
        RF_CHECK("runahead-five: deepest run-ahead is 7 heights",
                 json_get_int(json_get(&five,
                     "stage_cursors_above_hstar_max_depth")) == 7);
        const struct json_value *utxo = dumped_cursor(&five, "utxo_apply");
        RF_CHECK("runahead-five: the cursor left behind is not marked",
                 utxo && !json_get_bool(json_get(utxo, "above_hstar")));
    }
    json_free(&five);

    progress_store_close();
    test_cleanup_tmpdir(dir);
    return failures;
}

static int case_dump_reports_unavailable_store(void)
{
    int failures = 0;

    progress_store_close();
    struct json_value closed;
    json_init(&closed);
    bool dumped_closed = reducer_frontier_dump_state_json(&closed, NULL);
    RF_CHECK("dump-unavailable: closed store returns true", dumped_closed);
    if (dumped_closed) {
        RF_CHECK("dump-unavailable: closed store open=false",
                 !json_get_bool(json_get(&closed, "open")));
        RF_CHECK("dump-unavailable: closed store schema_ready=false",
                 !json_get_bool(json_get(&closed, "schema_ready")));
        RF_CHECK("dump-unavailable: closed store missing=progress_store",
                 strcmp(json_get_str(json_get(&closed, "schema_missing")),
                        "progress_store") == 0);
    }
    json_free(&closed);

    char dir[256];
    test_make_tmpdir(dir, sizeof(dir), "reducer_frontier", "dump_empty");
    bool opened = progress_store_open(dir);
    RF_CHECK("dump-unavailable: empty store opens", opened);
    if (opened) {
        struct json_value empty;
        json_init(&empty);
        bool dumped_empty = reducer_frontier_dump_state_json(&empty, NULL);
        RF_CHECK("dump-unavailable: empty store returns true", dumped_empty);
        if (dumped_empty) {
            RF_CHECK("dump-unavailable: empty store open=true",
                     json_get_bool(json_get(&empty, "open")));
            RF_CHECK("dump-unavailable: empty store schema_ready=false",
                     !json_get_bool(json_get(&empty, "schema_ready")));
            RF_CHECK("dump-unavailable: empty store missing=validate log",
                     strcmp(json_get_str(json_get(&empty, "schema_missing")),
                            "validate_headers_log") == 0);
        }
        json_free(&empty);
    }

    progress_store_close();
    test_cleanup_tmpdir(dir);
    return failures;
}

static int case_dump_reports_hstar_log_hole(void)
{
    int failures = 0;
    char dir[256];
    test_make_tmpdir(dir, sizeof(dir), "reducer_frontier", "dump_hole");

    progress_store_close();
    bool opened = progress_store_open(dir);
    RF_CHECK("dump-hole: progress_store opens", opened);
    if (!opened) {
        test_cleanup_tmpdir(dir);
        return failures;
    }

    sqlite3 *db = progress_store_db();
    RF_CHECK("dump-hole: schema", db && build_schema(db));
    RF_CHECK("dump-hole: proven authority", db && stamp_proven_authority(db, A + 1));

    const int32_t hole_h = A + 3;
    bool built = put_consistent_height(db, A + 1)
              && put_consistent_height(db, A + 2);
    uint8_t hh[32];
    synth_hash(hh, hole_h, 0);
    built = built
        && put_log_row(db, "validate_headers_log", "hash", hole_h, 1,
                       hh, NULL)
        && put_log_row(db, "script_validate_log", "block_hash", hole_h, 1,
                       hh, "ok")
        /* body_persist_log intentionally has NO row at hole_h. */
        && put_log_row(db, "proof_validate_log", NULL, hole_h, 1, NULL, NULL)
        && put_log_row(db, "utxo_apply_log", NULL, hole_h, 1, NULL, NULL)
        && put_log_row(db, "tip_finalize_log", NULL, hole_h, 1, NULL, "ok");
    RF_CHECK("dump-hole: rows built", built);
    RF_CHECK("dump-hole: cursors", set_all_cursors(db, hole_h + 1));

    struct json_value out;
    json_init(&out);
    bool dumped = reducer_frontier_dump_state_json(&out, NULL);
    RF_CHECK("dump-hole: returns true", dumped);
    if (dumped) {
        RF_CHECK("dump-hole: hstar before hole",
                 json_get_int(json_get(&out, "hstar")) == hole_h - 1);
        RF_CHECK("dump-hole: blocker found",
                 json_get_bool(json_get(&out,
                                        "first_hstar_blocker_found")));
        RF_CHECK("dump-hole: blocker stage",
                 strcmp(json_get_str(json_get(&out,
                           "first_hstar_blocker_stage")),
                        "body_persist") == 0);
        RF_CHECK("dump-hole: blocker height",
                 json_get_int(json_get(&out,
                                       "first_hstar_blocker_height"))
                     == hole_h);
        RF_CHECK("dump-hole: blocker kind",
                 strcmp(json_get_str(json_get(&out,
                           "first_hstar_blocker_kind")),
                        "log_hole") == 0);
        RF_CHECK("dump-hole: blocker reason",
                 strcmp(json_get_str(json_get(&out,
                           "first_hstar_blocker_reason")),
                        "missing-success-row") == 0);
        /* kind=log_hole names its repair owner (never empty). */
        RF_CHECK("dump-hole: blocker repair owner",
                 strcmp(json_get_str(json_get(&out,
                           "first_hstar_blocker_repair_owner")),
                        "reducer_frontier_reconcile_light") == 0);
        RF_CHECK("dump-hole: hstar next repair owner",
                 strcmp(json_get_str(json_get(&out,
                           "hstar_next_primary_repair_owner")),
                        "reducer_frontier_reconcile_light") == 0);
        RF_CHECK("dump-hole: hstar next kind",
                 strcmp(json_get_str(json_get(&out,
                           "hstar_next_primary_kind")),
                        "log_hole") == 0);
        RF_CHECK("dump-hole: hstar next table",
                 strcmp(json_get_str(json_get(&out,
                           "hstar_next_primary_log_table")),
                        "body_persist_log") == 0);
    }
    json_free(&out);

    progress_store_close();
    test_cleanup_tmpdir(dir);
    return failures;
}

static int case_dump_reports_hstar_hash_split(void)
{
    int failures = 0;
    char dir[256];
    test_make_tmpdir(dir, sizeof(dir), "reducer_frontier", "dump_split");

    progress_store_close();
    bool opened = progress_store_open(dir);
    RF_CHECK("dump-split: progress_store opens", opened);
    if (!opened) {
        test_cleanup_tmpdir(dir);
        return failures;
    }

    sqlite3 *db = progress_store_db();
    RF_CHECK("dump-split: schema", db && build_schema(db));
    RF_CHECK("dump-split: proven authority", db && stamp_proven_authority(db, A + 1));

    bool built = true;
    for (int32_t h = A + 1; h <= A + 2; h++)
        built = built && put_consistent_height(db, h);

    const int32_t split_h = A + 3;
    uint8_t hv[32], hs[32];
    synth_hash(hv, split_h, 0);
    synth_hash(hs, split_h, 9);
    built = built
        && put_log_row(db, "validate_headers_log", "hash", split_h, 1,
                       hv, NULL)
        && put_log_row(db, "script_validate_log", "block_hash", split_h, 1,
                       hs, "ok")
        && put_log_row(db, "body_persist_log", NULL, split_h, 1, NULL, NULL)
        && put_log_row(db, "proof_validate_log", NULL, split_h, 1, NULL, NULL)
        && put_log_row(db, "utxo_apply_log", NULL, split_h, 1, NULL, NULL)
        && put_log_row(db, "tip_finalize_log", NULL, split_h, 1, NULL, "ok");
    RF_CHECK("dump-split: rows built", built);
    RF_CHECK("dump-split: cursors", set_all_cursors(db, split_h + 1));

    struct json_value out;
    json_init(&out);
    bool dumped = reducer_frontier_dump_state_json(&out, NULL);
    RF_CHECK("dump-split: returns true", dumped);
    if (dumped) {
        RF_CHECK("dump-split: hstar before split",
                 json_get_int(json_get(&out, "hstar")) == split_h - 1);
        RF_CHECK("dump-split: blocker found",
                 json_get_bool(json_get(&out,
                                        "first_hstar_blocker_found")));
        RF_CHECK("dump-split: blocker stage",
                 strcmp(json_get_str(json_get(&out,
                           "first_hstar_blocker_stage")),
                        "script_validate") == 0);
        RF_CHECK("dump-split: blocker height",
                 json_get_int(json_get(&out,
                                       "first_hstar_blocker_height"))
                     == split_h);
        RF_CHECK("dump-split: blocker kind",
                 strcmp(json_get_str(json_get(&out,
                           "first_hstar_blocker_kind")),
                        "hash_split") == 0);
        RF_CHECK("dump-split: blocker reason",
                 strcmp(json_get_str(json_get(&out,
                           "first_hstar_blocker_reason")),
                        "validate-script-hash-mismatch") == 0);
        RF_CHECK("dump-split: blocker repair owner",
                 strcmp(json_get_str(json_get(&out,
                           "first_hstar_blocker_repair_owner")),
                        "reducer_frontier_reconcile_light") == 0);
        RF_CHECK("dump-split: hstar next repair owner",
                 strcmp(json_get_str(json_get(&out,
                           "hstar_next_primary_repair_owner")),
                        "reducer_frontier_reconcile_light") == 0);
        RF_CHECK("dump-split: hstar next kind",
                 strcmp(json_get_str(json_get(&out,
                           "hstar_next_primary_kind")),
                        "hash_split") == 0);
        RF_CHECK("dump-split: hstar next table",
                 strcmp(json_get_str(json_get(&out,
                           "hstar_next_primary_log_table")),
                        "script_validate_log") == 0);
    }
    json_free(&out);

    progress_store_close();
    test_cleanup_tmpdir(dir);
    return failures;
}

static int case_dump_ignores_tip_finalize_pending_edge(void)
{
    int failures = 0;
    char dir[256];
    test_make_tmpdir(dir, sizeof(dir), "reducer_frontier", "dump_tipfin_edge");

    progress_store_close();
    bool opened = progress_store_open(dir);
    RF_CHECK("dump-tipfin-edge: progress_store opens", opened);
    if (!opened) {
        test_cleanup_tmpdir(dir);
        return failures;
    }

    sqlite3 *db = progress_store_db();
    RF_CHECK("dump-tipfin-edge: schema", db && build_schema(db));
    RF_CHECK("dump-tipfin-edge: proven authority",
             db && stamp_proven_authority(db, A + 4));

    const int32_t pending_h = A + 3;
    bool built = put_consistent_height(db, A + 1)
              && put_consistent_height(db, A + 2);
    uint8_t hh[32];
    synth_hash(hh, pending_h, 0);
    built = built
        && put_log_row(db, "validate_headers_log", "hash", pending_h, 1,
                       hh, NULL)
        && put_log_row(db, "script_validate_log", "block_hash", pending_h, 1,
                       hh, "ok")
        && put_log_row(db, "body_persist_log", NULL, pending_h, 1, NULL, NULL)
        && put_log_row(db, "proof_validate_log", NULL, pending_h, 1, NULL, NULL)
        && put_log_row(db, "utxo_apply_log", NULL, pending_h, 1, NULL, NULL);
    RF_CHECK("dump-tipfin-edge: rows built", built);
    RF_CHECK("dump-tipfin-edge: upstream cursors",
             set_cursor(db, "validate_headers", pending_h + 1) &&
             set_cursor(db, "body_fetch", pending_h + 1) &&
             set_cursor(db, "body_persist", pending_h + 1) &&
             set_cursor(db, "script_validate", pending_h + 1) &&
             set_cursor(db, "proof_validate", pending_h + 1) &&
             set_cursor(db, "utxo_apply", pending_h + 1));
    RF_CHECK("dump-tipfin-edge: tip_finalize cursor",
             set_cursor(db, "tip_finalize", pending_h));

    struct json_value out;
    json_init(&out);
    bool dumped = reducer_frontier_dump_state_json(&out, NULL);
    RF_CHECK("dump-tipfin-edge: returns true", dumped);
    if (dumped) {
        RF_CHECK("dump-tipfin-edge: hstar is finalized row frontier",
                 json_get_int(json_get(&out, "hstar")) == pending_h - 1);
        RF_CHECK("dump-tipfin-edge: next height is served tip edge",
                 json_get_int(json_get(&out, "hstar_next_height")) ==
                     pending_h);
        RF_CHECK("dump-tipfin-edge: no false blocker",
                 !json_get_bool(json_get(&out, "hstar_next_blocked")));
        RF_CHECK("dump-tipfin-edge: no false repair owner",
                 strcmp(json_get_str(json_get(&out,
                           "hstar_next_primary_repair_owner")), "") == 0);
        RF_CHECK("dump-tipfin-edge: pending edge named",
                 json_get_bool(json_get(&out,
                           "hstar_next_pending_edge")));
        RF_CHECK("dump-tipfin-edge: pending edge stage",
                 strcmp(json_get_str(json_get(&out,
                           "hstar_next_pending_stage")),
                        "tip_finalize") == 0);
        RF_CHECK("dump-tipfin-edge: pending edge table",
                 strcmp(json_get_str(json_get(&out,
                           "hstar_next_pending_log_table")),
                        "tip_finalize_log") == 0);
        RF_CHECK("dump-tipfin-edge: pending edge detail",
                 strcmp(json_get_str(json_get(&out,
                           "hstar_next_pending_detail")),
                        "tip-finalize-edge-pending") == 0);
        RF_CHECK("dump-tipfin-edge: first blocker absent",
                 !json_get_bool(json_get(&out,
                           "first_hstar_blocker_found")));
    }
    json_free(&out);

    progress_store_close();
    test_cleanup_tmpdir(dir);
    return failures;
}

static int case_dump_reports_tip_finalize_real_hole(void)
{
    int failures = 0;
    char dir[256];
    test_make_tmpdir(dir, sizeof(dir), "reducer_frontier",
                     "dump_tipfin_hole");

    progress_store_close();
    bool opened = progress_store_open(dir);
    RF_CHECK("dump-tipfin-hole: progress_store opens", opened);
    if (!opened) {
        test_cleanup_tmpdir(dir);
        return failures;
    }

    sqlite3 *db = progress_store_db();
    RF_CHECK("dump-tipfin-hole: schema", db && build_schema(db));
    RF_CHECK("dump-tipfin-hole: proven authority",
             db && stamp_proven_authority(db, A + 4));

    const int32_t hole_h = A + 3;
    bool built = put_consistent_height(db, A + 1)
              && put_consistent_height(db, A + 2);
    uint8_t hh[32];
    synth_hash(hh, hole_h, 0);
    built = built
        && put_log_row(db, "validate_headers_log", "hash", hole_h, 1,
                       hh, NULL)
        && put_log_row(db, "script_validate_log", "block_hash", hole_h, 1,
                       hh, "ok")
        && put_log_row(db, "body_persist_log", NULL, hole_h, 1, NULL, NULL)
        && put_log_row(db, "proof_validate_log", NULL, hole_h, 1, NULL, NULL)
        && put_log_row(db, "utxo_apply_log", NULL, hole_h, 1, NULL, NULL);
    RF_CHECK("dump-tipfin-hole: rows built", built);
    RF_CHECK("dump-tipfin-hole: upstream cursors",
             set_cursor(db, "validate_headers", hole_h + 1) &&
             set_cursor(db, "body_fetch", hole_h + 1) &&
             set_cursor(db, "body_persist", hole_h + 1) &&
             set_cursor(db, "script_validate", hole_h + 1) &&
             set_cursor(db, "proof_validate", hole_h + 1) &&
             set_cursor(db, "utxo_apply", hole_h + 1));
    RF_CHECK("dump-tipfin-hole: tip_finalize cursor beyond hole",
             set_cursor(db, "tip_finalize", hole_h + 1));

    struct json_value out;
    json_init(&out);
    bool dumped = reducer_frontier_dump_state_json(&out, NULL);
    RF_CHECK("dump-tipfin-hole: returns true", dumped);
    if (dumped) {
        RF_CHECK("dump-tipfin-hole: hstar before hole",
                 json_get_int(json_get(&out, "hstar")) == hole_h - 1);
        RF_CHECK("dump-tipfin-hole: next height is hole",
                 json_get_int(json_get(&out, "hstar_next_height")) ==
                     hole_h);
        RF_CHECK("dump-tipfin-hole: not a pending edge",
                 !json_get_bool(json_get(&out,
                           "hstar_next_pending_edge")));
        RF_CHECK("dump-tipfin-hole: blocker found",
                 json_get_bool(json_get(&out,
                           "first_hstar_blocker_found")));
        RF_CHECK("dump-tipfin-hole: blocker stage",
                 strcmp(json_get_str(json_get(&out,
                           "first_hstar_blocker_stage")),
                        "tip_finalize") == 0);
        RF_CHECK("dump-tipfin-hole: blocker table",
                 strcmp(json_get_str(json_get(&out,
                           "first_hstar_blocker_log_table")),
                        "tip_finalize_log") == 0);
        RF_CHECK("dump-tipfin-hole: blocker height",
                 json_get_int(json_get(&out,
                           "first_hstar_blocker_height")) == hole_h);
        RF_CHECK("dump-tipfin-hole: blocker kind",
                 strcmp(json_get_str(json_get(&out,
                           "first_hstar_blocker_kind")),
                        "log_hole") == 0);
        RF_CHECK("dump-tipfin-hole: blocker reason",
                 strcmp(json_get_str(json_get(&out,
                           "first_hstar_blocker_reason")),
                        "missing-success-row") == 0);
        RF_CHECK("dump-tipfin-hole: blocker repair owner",
                 strcmp(json_get_str(json_get(&out,
                           "first_hstar_blocker_repair_owner")),
                        "reducer_frontier_reconcile_light") == 0);
        RF_CHECK("dump-tipfin-hole: hstar next blocked",
                 json_get_bool(json_get(&out, "hstar_next_blocked")));
        RF_CHECK("dump-tipfin-hole: hstar next primary table",
                 strcmp(json_get_str(json_get(&out,
                           "hstar_next_primary_log_table")),
                        "tip_finalize_log") == 0);
        RF_CHECK("dump-tipfin-hole: hstar next repair owner",
                 strcmp(json_get_str(json_get(&out,
                           "hstar_next_primary_repair_owner")),
                        "reducer_frontier_reconcile_light") == 0);
    }
    json_free(&out);

    progress_store_close();
    test_cleanup_tmpdir(dir);
    return failures;
}

static int case_log_frontier_above_tip_finalize_cursor(void)
{
    int failures = 0;
    sqlite3 *db = NULL;
    if (sqlite3_open(":memory:", &db) != SQLITE_OK) { return 1; }
    RF_CHECK("tipfin-above: schema", build_schema(db));

    bool built = true;
    for (int32_t h = A + 1; h <= A + 3; h++)
        built = built &&
            put_log_row(db, "tip_finalize_log", NULL, h, 1, NULL, "ok");
    RF_CHECK("tipfin-above: rows built", built);
    RF_CHECK("tipfin-above: served-height cursor",
             set_cursor(db, "tip_finalize", A + 3));

    int32_t frontier = -1;
    bool ok = reducer_frontier_log_frontier_above(db, "tip_finalize_log",
                                                  "tip_finalize", A,
                                                  &frontier);
    RF_CHECK("tipfin-above: returns true", ok);
    RF_CHECK("tipfin-above: frontier includes served cursor height",
             frontier == A + 3);

    sqlite3_close(db);
    return failures;
}

/* Scan a JSON array for the first object whose "kind" field equals `kind`
 * and whose "height" field equals `height`. Returns NULL if not found. */
static const struct json_value *find_rewind_base(const struct json_value *arr,
                                                  const char *kind,
                                                  int32_t height)
{
    size_t n = arr ? json_size(arr) : 0;
    for (size_t i = 0; i < n; i++) {
        const struct json_value *item = json_at(arr, i);
        if (!item)
            continue;
        const char *k = json_get_str(json_get(item, "kind"));
        if (k && strcmp(k, kind) == 0 &&
            json_get_int(json_get(item, "height")) == height)
            return item;
    }
    return NULL;
}

/* Pillar 3 observability: the reducer_frontier dump lists every currently
 * available self-verified rewind base (the compiled checkpoint + every
 * self-valid seal_kv ring slot + the optional finalized utxo_sha3 stamp) and
 * reports the O(delta) distance from H* to the nearest one. */
static int case_dump_reports_rewind_bases(void)
{
    int failures = 0;
    char dir[256];
    test_make_tmpdir(dir, sizeof(dir), "reducer_frontier", "rewind_bases");

    progress_store_close();
    bool opened = progress_store_open(dir);
    RF_CHECK("rewind: progress_store opens", opened);
    if (!opened) {
        test_cleanup_tmpdir(dir);
        return failures;
    }

    sqlite3 *db = progress_store_db();
    RF_CHECK("rewind: schema", db && build_schema(db));
    RF_CHECK("rewind: proven authority", db && stamp_proven_authority(db, A + 1));
    RF_CHECK("rewind: seal schema", seal_kv_ensure_schema(db));

    bool built = true;
    for (int32_t h = A + 1; h <= A + 5; h++)
        built = built && put_consistent_height(db, h);
    RF_CHECK("rewind: rows built", built);
    RF_CHECK("rewind: cursors", set_all_cursors(db, A + 6));

    /* One self-derived sealed candidate at A+2, closer to the tip than the
     * compiled checkpoint at A. */
    struct seal_record r;
    memset(&r, 0, sizeof(r));
    r.height = A + 2;
    memset(r.coins_sha3, 0xAB, sizeof(r.coins_sha3));
    r.utxo_count = 3;
    r.supply = 12345;
    r.sealed_at = 1;
    progress_store_tx_lock();
    bool tx_ok = sqlite3_exec(db, "BEGIN IMMEDIATE", NULL, NULL, NULL)
                     == SQLITE_OK;
    bool inserted = tx_ok && seal_kv_insert_candidate_in_tx(db, &r);
    sqlite3_exec(db, inserted ? "COMMIT" : "ROLLBACK", NULL, NULL, NULL);
    progress_store_tx_unlock();
    RF_CHECK("rewind: seal candidate inserted", inserted);

    struct json_value out;
    json_init(&out);
    bool dumped = reducer_frontier_dump_state_json(&out, NULL);
    RF_CHECK("rewind: dump returns true", dumped);
    if (dumped) {
        RF_CHECK("rewind: hstar reaches last consistent height",
                 json_get_int(json_get(&out, "hstar")) == A + 5);

        const struct json_value *bases = json_get(&out, "rewind_bases");
        RF_CHECK("rewind: rewind_bases is present", bases != NULL);
        RF_CHECK("rewind: rewind_bases_count >= 2",
                 json_get_int(json_get(&out, "rewind_bases_count")) >= 2);

        const struct json_value *compiled =
            find_rewind_base(bases, "compiled_checkpoint", A);
        RF_CHECK("rewind: compiled checkpoint entry present",
                 compiled != NULL);
        if (compiled) {
            RF_CHECK("rewind: compiled checkpoint self_derived",
                     json_get_bool(json_get(compiled, "self_derived")));
            RF_CHECK("rewind: compiled checkpoint distance_from_tip",
                     json_get_int(json_get(compiled, "distance_from_tip"))
                         == 5);
        }

        const struct json_value *sealed =
            find_rewind_base(bases, "sealed_coins_sha3", A + 2);
        RF_CHECK("rewind: sealed candidate entry present", sealed != NULL);
        if (sealed) {
            RF_CHECK("rewind: sealed candidate self_derived",
                     json_get_bool(json_get(sealed, "self_derived")));
            RF_CHECK("rewind: sealed candidate not yet ratified",
                     !json_get_bool(json_get(sealed, "ratified")));
            RF_CHECK("rewind: sealed candidate distance_from_tip",
                     json_get_int(json_get(sealed, "distance_from_tip"))
                         == 3);
            const char *sha3_hex = json_get_str(json_get(sealed,
                                                          "commitment_sha3"));
            RF_CHECK("rewind: sealed candidate commitment hex present",
                     sha3_hex && strlen(sha3_hex) == 64);
        }

        /* The seal candidate at A+2 is closer to H* than the checkpoint, so
         * it is the nearest; the optional finalized_utxo_sha3 entry is
         * process-global, so bound the distance instead of asserting kind. */
        int64_t nearest_distance =
            json_get_int(json_get(&out, "nearest_rewind_distance"));
        RF_CHECK("rewind: nearest distance is non-negative",
                 nearest_distance >= 0);
        RF_CHECK("rewind: nearest distance at most the sealed candidate's",
                 nearest_distance <= 3);
    }
    json_free(&out);

    progress_store_close();
    test_cleanup_tmpdir(dir);
    return failures;
}

/* Sovereignty invariant (docs/work/self-verified-tip-plan.md): a rewind base
 * must be self-derived. A borrowed finalized_utxo_sha3 stamp
 * (self_derived=false) must never win over a self-verified rung (the
 * compiled checkpoint at A), even at a higher height.
 *
 * Fixture: rows [A+1..A+5] consistent (H*=A+5), a borrowed stamp at A+4, no
 * closer self-verified candidate. Proves:
 *   (1) reducer_frontier_nearest_self_verified_base() (used by
 *       rewind_driver.c) returns the lower self-verified A, not A+4.
 *   (2) the legacy height-only nearest_rewind_base_* JSON keys still pick
 *       the borrowed A+4, so the two selectors disagree. */
static int case_sovereign_base_ignores_borrowed_higher_stamp(void)
{
    int failures = 0;
    char dir[256];
    test_make_tmpdir(dir, sizeof(dir), "reducer_frontier", "sovereign_base");

    progress_store_close();
    bool opened = progress_store_open(dir);
    RF_CHECK("sovereign-base: progress_store opens", opened);
    if (!opened) {
        test_cleanup_tmpdir(dir);
        return failures;
    }

    sqlite3 *db = progress_store_db();
    RF_CHECK("sovereign-base: schema", db && build_schema(db));
    RF_CHECK("sovereign-base: proven authority",
             db && stamp_proven_authority(db, A + 1));

    bool built = true;
    for (int32_t h = A + 1; h <= A + 5; h++)
        built = built && put_consistent_height(db, h);
    RF_CHECK("sovereign-base: rows built", built);
    RF_CHECK("sovereign-base: cursors", set_all_cursors(db, A + 6));

    /* Wire a real node_db + db_service into app_runtime so
     * enumerate_rewind_bases() resolves a live handle (same seam as
     * test_dbquery_secret_denylist.c), and stamp a BORROWED
     * finalized_utxo_sha3 at A+4, higher than the checkpoint at A. */
    struct node_db ndb;
    struct db_service dbsvc;
    struct app_runtime_context runtime;
    memset(&ndb, 0, sizeof(ndb));
    memset(&dbsvc, 0, sizeof(dbsvc));
    memset(&runtime, 0, sizeof(runtime));
    bool ndb_ok = node_db_open(&ndb, ":memory:");
    RF_CHECK("sovereign-base: node_db opens", ndb_ok);
    db_service_init(&dbsvc);
    RF_CHECK("sovereign-base: db_service attaches",
             ndb_ok && db_service_attach(&dbsvc, &ndb));
    RF_CHECK("sovereign-base: db_service starts",
             ndb_ok && db_service_start(&dbsvc));
    runtime.db_service = &dbsvc;
    app_runtime_set_current(&runtime);

    uint8_t borrowed_hash[32];
    memset(borrowed_hash, 0xCD, sizeof(borrowed_hash));
    RF_CHECK("sovereign-base: borrowed utxo_sha3 stamp saved",
             utxo_commitment_sha3_save(ndb.db, borrowed_hash, A + 4, 7));

    /* (1) The driver-facing selector returns the lower self-verified A. */
    struct reducer_frontier_rewind_base base;
    memset(&base, 0, sizeof(base));
    bool found = reducer_frontier_nearest_self_verified_base(A + 5, &base);
    RF_CHECK("sovereign-base: selector finds a base", found);
    if (found) {
        RF_CHECK("sovereign-base: selector picks the LOWER self-verified "
                 "height, not the higher borrowed one",
                 base.height == A);
        RF_CHECK("sovereign-base: selector's pick is self_derived",
                 base.self_derived);
        RF_CHECK("sovereign-base: selector's pick is compiled_checkpoint",
                 strcmp(base.kind, "compiled_checkpoint") == 0);
        RF_CHECK("sovereign-base: selector never returns the borrowed height",
                 base.height != A + 4);
    }

    /* (2) The legacy height-only keys pick the higher borrowed stamp. */
    struct json_value out;
    json_init(&out);
    bool dumped = reducer_frontier_dump_state_json(&out, NULL);
    RF_CHECK("sovereign-base: dump returns true", dumped);
    if (dumped) {
        RF_CHECK("sovereign-base: hstar reaches the built tip",
                 json_get_int(json_get(&out, "hstar")) == A + 5);
        RF_CHECK("sovereign-base: legacy nearest picks the HIGHER borrowed "
                 "height",
                 json_get_int(json_get(&out, "nearest_rewind_base_height"))
                     == A + 4);
        RF_CHECK("sovereign-base: legacy nearest is NOT self_derived (it is "
                 "the borrowed stamp)",
                 !json_get_bool(json_get(&out,
                           "nearest_rewind_base_self_derived")));
        RF_CHECK("sovereign-base: new self-verified key picks the LOWER "
                 "compiled checkpoint",
                 json_get_int(json_get(&out,
                           "nearest_self_verified_base_height")) == A);
        RF_CHECK("sovereign-base: new self-verified key names "
                 "compiled_checkpoint",
                 strcmp(json_get_str(json_get(&out,
                           "nearest_self_verified_base_kind")),
                        "compiled_checkpoint") == 0);
        /* The two keys disagree: a height-first selector would rewind to
         * the borrowed A+4. */
        RF_CHECK("sovereign-base: legacy and self-verified nearest heights "
                 "now DIFFER (the fix)",
                 json_get_int(json_get(&out, "nearest_rewind_base_height"))
                     != json_get_int(json_get(&out,
                           "nearest_self_verified_base_height")));
    }
    json_free(&out);

    app_runtime_set_current(NULL);
    db_service_stop(&dbsvc);
    node_db_close(&ndb);

    progress_store_close();
    test_cleanup_tmpdir(dir);
    return failures;
}

/* The body torn-read repair note, quarantine and typed blocker that
 * stage_repair_read_active_block_checked records when a HAVE_DATA body cannot
 * be read, and the clear-on-successful-read path. The end-to-end refetch
 * chain is in test_have_data_unreadable.c. */
static int case_body_read_repair_note(void)
{
    int failures = 0;
    blocker_module_init();
    blocker_reset_for_testing();
    blocker_set_rate_limit_ms_for_testing(0); /* re-sets always replace */
    reducer_frontier_body_read_note_reset_for_testing();
    struct uint256 hash_a = {{1}};
    struct uint256 hash_low = {{2}};
    struct uint256 hash_high = {{3}};

    RF_CHECK("body_read_note: inactive at start",
             !reducer_frontier_body_read_note_active() &&
             reducer_frontier_body_read_note_height() == -1);

    /* Below the quarantine bound: note recorded, no blocker yet. */
    reducer_frontier_body_read_note_record(
        3143721, 49, 129998574, REDUCER_FRONTIER_BODY_READ_DISK, &hash_a);
    reducer_frontier_body_read_note_record(
        3143721, 49, 129998574, REDUCER_FRONTIER_BODY_READ_DISK, &hash_a);
    RF_CHECK("body_read_note: height/file/pos exposed",
             reducer_frontier_body_read_note_active() &&
             reducer_frontier_body_read_note_height() == 3143721 &&
             reducer_frontier_body_read_note_file() == 49 &&
             reducer_frontier_body_read_note_pos() == 129998574);
    RF_CHECK("body_read_note: count == 2 (below bound)",
             reducer_frontier_body_read_note_count_for_testing() == 2);
    RF_CHECK("body_read_note: no blocker below the quarantine bound",
             !blocker_exists("reducer_frontier.body_read_torn"));

    /* Crossing REDUCER_FRONTIER_BODY_READ_QUARANTINE_MAX raises ONE typed
     * TRANSIENT blocker naming height/nFile/reason. */
    reducer_frontier_body_read_note_record(
        3143721, 49, 129998574, REDUCER_FRONTIER_BODY_READ_DISK, &hash_a);
    RF_CHECK("body_read_note: quarantine raises typed blocker",
             blocker_exists("reducer_frontier.body_read_torn"));
    {
        struct blocker_snapshot snaps[16];
        int n = blocker_snapshot_all(snaps, 16);
        bool named = false;
        for (int i = 0; i < n; i++) {
            if (strcmp(snaps[i].id, "reducer_frontier.body_read_torn") != 0)
                continue;
            named = snaps[i].class == BLOCKER_TRANSIENT &&
                    strstr(snaps[i].reason, "height=3143721") != NULL &&
                    strstr(snaps[i].reason, "nFile=49") != NULL &&
                    strstr(snaps[i].reason, "disk_read_failed") != NULL;
        }
        RF_CHECK("body_read_note: blocker names height+file+reason, TRANSIENT",
                 named);
    }

    /* A successful read of the noted height retires the note and its
     * blocker. */
    struct reducer_frontier_body_read_note completed_note;
    bool captured = reducer_frontier_body_read_note_snapshot(&completed_note);
    if (captured)
        (void)reducer_frontier_body_read_note_clear_if(&completed_note);
    RF_CHECK("body_read_note: matching clear retires note + blocker",
             !reducer_frontier_body_read_note_active() &&
             !blocker_exists("reducer_frontier.body_read_torn"));

    /* A lower failing height supersedes and restarts the count; a higher
     * one never displaces a lower pending one. */
    reducer_frontier_body_read_note_record(
        3100000, 7, 42, REDUCER_FRONTIER_BODY_READ_WRONG, &hash_low);
    RF_CHECK("body_read_note: fresh lower note counts from 1",
             reducer_frontier_body_read_note_height() == 3100000 &&
             reducer_frontier_body_read_note_count_for_testing() == 1);
    struct reducer_frontier_body_read_note low_note;
    bool have_low = reducer_frontier_body_read_note_snapshot(&low_note);
    reducer_frontier_body_read_note_record(
        3100000, 8, 43, REDUCER_FRONTIER_BODY_READ_WRONG, &hash_high);
    struct reducer_frontier_body_read_note replacement_note;
    bool have_replacement =
        reducer_frontier_body_read_note_snapshot(&replacement_note);
    bool stale_clear = reducer_frontier_body_read_note_clear_if(&low_note);
    RF_CHECK("body_read_note: same-height reorg replaces identity and rejects "
             "stale clear",
             have_low && have_replacement && !stale_clear &&
             replacement_note.generation > low_note.generation &&
             uint256_eq(&replacement_note.block_hash, &hash_high) &&
             reducer_frontier_body_read_note_active());
    reducer_frontier_body_read_note_record(
        3300000, 9, 9, REDUCER_FRONTIER_BODY_READ_DISK, &hash_high);
    RF_CHECK("body_read_note: higher height does not displace the lower one",
             reducer_frontier_body_read_note_height() == 3100000 &&
             reducer_frontier_body_read_note_count_for_testing() == 1);

    /* clear_at only fires for the currently-noted height. */
    struct reducer_frontier_body_read_note wrong_note;
    bool have_wrong = reducer_frontier_body_read_note_snapshot(&wrong_note);
    wrong_note.height = 3300000;
    if (have_wrong)
        (void)reducer_frontier_body_read_note_clear_if(&wrong_note);
    RF_CHECK("body_read_note: clear_at(non-noted height) is a no-op",
             reducer_frontier_body_read_note_height() == 3100000);

    reducer_frontier_body_read_note_reset_for_testing();
    struct body_note_writer_args wa = {
        .hashes = {{{0x11}}, {{0x12}}},
        .file = 11,
        .pos = 111,
        .reason = REDUCER_FRONTIER_BODY_READ_DISK,
        .alternate_hashes = true,
    };
    struct body_note_writer_args wb = {
        .hashes = {{{0x21}}, {{0x22}}},
        .file = 22,
        .pos = 222,
        .reason = REDUCER_FRONTIER_BODY_READ_WRONG,
        .alternate_hashes = true,
    };
    pthread_t ta;
    pthread_t tb;
    atomic_store(&g_body_note_threads_go, false);
    bool ta_started = pthread_create(&ta, NULL, body_note_writer, &wa) == 0;
    bool tb_started = pthread_create(&tb, NULL, body_note_writer, &wb) == 0;
    atomic_store(&g_body_note_threads_go, true);
    if (ta_started)
        pthread_join(ta, NULL);
    if (tb_started)
        pthread_join(tb, NULL);
    bool threads = ta_started && tb_started;
    struct reducer_frontier_body_read_note concurrent_note;
    bool coherent = threads &&
        reducer_frontier_body_read_note_snapshot(&concurrent_note);
    bool from_a = concurrent_note.file == wa.file &&
        concurrent_note.pos == wa.pos && concurrent_note.reason == wa.reason &&
        (uint256_eq(&concurrent_note.block_hash, &wa.hashes[0]) ||
         uint256_eq(&concurrent_note.block_hash, &wa.hashes[1]));
    bool from_b = concurrent_note.file == wb.file &&
        concurrent_note.pos == wb.pos && concurrent_note.reason == wb.reason &&
        (uint256_eq(&concurrent_note.block_hash, &wb.hashes[0]) ||
         uint256_eq(&concurrent_note.block_hash, &wb.hashes[1]));
    RF_CHECK("body_read_note: concurrent writers publish one coherent record",
             coherent && (from_a || from_b));

    reducer_frontier_body_read_note_reset_for_testing();
    struct body_note_writer_args wc = wa;
    wc.alternate_hashes = false;
    reducer_frontier_body_read_note_record(
        42, wc.file, wc.pos, wc.reason, &wc.hashes[0]);
    reducer_frontier_body_read_note_record(
        42, wc.file, wc.pos, wc.reason, &wc.hashes[0]);
    RF_CHECK("body_read_note: concurrent fixture starts below threshold",
             !blocker_exists("reducer_frontier.body_read_torn"));
    pthread_t writer;
    pthread_t clearer;
    atomic_store(&g_body_note_threads_go, false);
    atomic_store(&g_body_note_raise_done, false);
    bool writer_started =
        pthread_create(&writer, NULL, body_note_raise_writer, &wc) == 0;
    bool clearer_started =
        pthread_create(&clearer, NULL, body_note_clearer, NULL) == 0;
    atomic_store(&g_body_note_threads_go, true);
    if (writer_started)
        pthread_join(writer, NULL);
    if (clearer_started)
        pthread_join(clearer, NULL);
    struct reducer_frontier_body_read_note final_note;
    bool final_active = reducer_frontier_body_read_note_snapshot(&final_note);
    bool final_blocker =
        blocker_exists("reducer_frontier.body_read_torn");
    RF_CHECK("body_read_note: concurrent set/clear keeps blocker generation "
             "coherent",
             writer_started && clearer_started &&
             atomic_load(&g_body_note_raise_done) &&
             ((!final_active && !final_blocker) ||
              (final_active &&
               ((final_note.count >=
                 REDUCER_FRONTIER_BODY_READ_QUARANTINE_MAX) ==
                final_blocker))));

    reducer_frontier_body_read_note_reset_for_testing();
    blocker_reset_for_testing();
    blocker_set_rate_limit_ms_for_testing(BLOCKER_DEFAULT_RATE_LIMIT_MS);
    return failures;
}

/* Raw stage_cursor row for `name`, or -1 if absent. */
static int64_t raw_stage_cursor(sqlite3 *db, const char *name)
{
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db, "SELECT cursor FROM stage_cursor WHERE name=?",
                           -1, &st, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_text(st, 1, name, -1, SQLITE_STATIC);
    int64_t v = -1;
    if (sqlite3_step(st) == SQLITE_ROW)
        v = sqlite3_column_int64(st, 0);
    sqlite3_finalize(st);
    return v;
}

/* The log-derived cursor for `name` as int64 (-1 on read error). */
static int64_t derived_stage_cursor(sqlite3 *db, const char *name)
{
    uint64_t out = 0;
    bool found = false;
    if (!reducer_frontier_stage_cursor_derived(db, name, &out, &found))
        return -1;
    return (int64_t)out;
}

/* ── F1: log-derived stage cursor equivalence ────────────────────────────
 *
 * reducer_frontier_stage_cursor_derived is each stage's *_log contiguous ok=1
 * prefix in the cursor frame, clamped to the stage_cursor row (the log may
 * only veto the cursor down). States pinned:
 *   (1) CONSISTENT: derived == raw for every stage.
 *   (2) TORN (durable hole below the cursor): derived drops to the proven
 *       prefix, raw is unchanged, only the holed stage diverges.
 *   (3) INSTALL (anchor row + cursors over a log-less region): derived
 *       floors at the anchor height, matching the forced cursor.
 *   (4) LOGLESS stage (body_fetch): derived == raw.
 *   (5) HEAL-UNDER-STATIC-CURSOR: a vetoed memo entry drops once the
 *       blocking row flips ok=1 without the raw cursor moving. */
static int case_derived_stage_cursor_equivalence(void)
{
    int failures = 0;

    /* Upstream stages (next-height frame) + tip_finalize (served-tip frame). */
    static const char *const upstream[] = {
        "validate_headers", "script_validate", "body_persist",
        "proof_validate", "utxo_apply",
    };
    const size_t n_up = sizeof(upstream) / sizeof(upstream[0]);

    /* (1) CONSISTENT ─────────────────────────────────────────────────── */
    {
        sqlite3 *db = NULL;
        reducer_frontier_stage_cursor_derived_reset_memo_for_testing();
        if (sqlite3_open(":memory:", &db) != SQLITE_OK) return 1;
        RF_CHECK("derived-equiv: consistent schema", build_schema(db));
        RF_CHECK("derived-equiv: consistent proven authority",
                 stamp_proven_authority(db, A + 1));
        const int32_t tip = A + 5;
        bool built = true;
        for (int32_t h = A + 1; h <= tip; h++)
            built = built && put_consistent_height(db, h);
        RF_CHECK("derived-equiv: consistent rows", built);
        /* Upstream cursors name the next height (tip+1); tip_finalize uses the
         * served-tip frame (tip). */
        bool cur = true;
        for (size_t i = 0; i < n_up; i++)
            cur = cur && set_cursor(db, upstream[i], tip + 1);
        cur = cur && set_cursor(db, "tip_finalize", tip);
        RF_CHECK("derived-equiv: consistent cursors", cur);

        for (size_t i = 0; i < n_up; i++) {
            int64_t d = derived_stage_cursor(db, upstream[i]);
            int64_t r = raw_stage_cursor(db, upstream[i]);
            RF_CHECK("derived-equiv: consistent upstream derived == raw",
                     d == r && d == tip + 1);
        }
        int64_t dtf = derived_stage_cursor(db, "tip_finalize");
        int64_t rtf = raw_stage_cursor(db, "tip_finalize");
        RF_CHECK("derived-equiv: consistent tip_finalize derived == raw",
                 dtf == rtf && dtf == tip);
        sqlite3_close(db);
    }

    /* (2) TORN — a hole in ONE upstream log below its cursor ──────────── */
    {
        sqlite3 *db = NULL;
        reducer_frontier_stage_cursor_derived_reset_memo_for_testing();
        if (sqlite3_open(":memory:", &db) != SQLITE_OK) return 1;
        RF_CHECK("derived-equiv: torn schema", build_schema(db));
        RF_CHECK("derived-equiv: torn proven authority",
                 stamp_proven_authority(db, A + 1));
        const int32_t tip = A + 5;
        bool built = true;
        for (int32_t h = A + 1; h <= tip; h++)
            built = built && put_consistent_height(db, h);
        RF_CHECK("derived-equiv: torn rows", built);
        bool cur = true;
        for (size_t i = 0; i < n_up; i++)
            cur = cur && set_cursor(db, upstream[i], tip + 1);
        cur = cur && set_cursor(db, "tip_finalize", tip);
        RF_CHECK("derived-equiv: torn cursors", cur);
        /* Delete script_validate_log's row at A+3 so its prefix stops at A+2
         * while its cursor stays tip+1. */
        char del_sql[128];
        snprintf(del_sql, sizeof(del_sql),
                 "DELETE FROM script_validate_log WHERE height=%d", A + 3);
        RF_CHECK("derived-equiv: torn hole punched",
                 sqlite3_exec(db, del_sql, NULL, NULL, NULL) == SQLITE_OK);

        int64_t dsv = derived_stage_cursor(db, "script_validate");
        int64_t rsv = raw_stage_cursor(db, "script_validate");
        /* The log vetoes the cursor down to (A+2)+1 = A+3, below tip+1. */
        RF_CHECK("derived-equiv: torn script_validate derived == log frontier",
                 dsv == A + 3);
        RF_CHECK("derived-equiv: torn script_validate raw cursor unchanged",
                 rsv == tip + 1);
        RF_CHECK("derived-equiv: torn derived < raw (log wins)", dsv < rsv);
        /* Every OTHER stage's log is intact, so its derived value still equals
         * its raw cursor — only the holed stage diverges. */
        int64_t dvh = derived_stage_cursor(db, "validate_headers");
        RF_CHECK("derived-equiv: torn intact stage derived == raw",
                 dvh == raw_stage_cursor(db, "validate_headers") &&
                 dvh == tip + 1);
        sqlite3_close(db);
    }

    /* (3) INSTALL — anchor row + cursors forced over a log-less region ── */
    {
        sqlite3 *db = NULL;
        reducer_frontier_stage_cursor_derived_reset_memo_for_testing();
        if (sqlite3_open(":memory:", &db) != SQLITE_OK) return 1;
        RF_CHECK("derived-equiv: install schema", build_schema(db));
        const int32_t base = A + 100;
        RF_CHECK("derived-equiv: install proven authority",
                 stamp_proven_authority(db, base + 1));
        RF_CHECK("derived-equiv: install seed anchor row", put_tip_anchor(db, base));
        RF_CHECK("derived-equiv: install durable trusted base",
                 put_int64_le_meta(db, REDUCER_TRUSTED_BASE_HEIGHT_KEY, base));
        /* No log rows above `base`; force cursors as
         * consensus_state_snapshot_install_activate does. */
        bool cur = true;
        for (size_t i = 0; i < n_up; i++)
            cur = cur && set_cursor(db, upstream[i], base + 1);
        cur = cur && set_cursor(db, "tip_finalize", base);
        RF_CHECK("derived-equiv: install cursors", cur);

        for (size_t i = 0; i < n_up; i++) {
            int64_t d = derived_stage_cursor(db, upstream[i]);
            RF_CHECK("derived-equiv: install upstream floors at anchor == raw",
                     d == base + 1);
        }
        int64_t dtf = derived_stage_cursor(db, "tip_finalize");
        RF_CHECK("derived-equiv: install tip_finalize floors at anchor == raw",
                 dtf == base);
        sqlite3_close(db);
    }

    /* (4) LOGLESS stage — body_fetch has no success-checked *_log ─────── */
    {
        sqlite3 *db = NULL;
        reducer_frontier_stage_cursor_derived_reset_memo_for_testing();
        if (sqlite3_open(":memory:", &db) != SQLITE_OK) return 1;
        RF_CHECK("derived-equiv: logless schema", build_schema(db));
        RF_CHECK("derived-equiv: logless proven authority",
                 stamp_proven_authority(db, A + 1));
        RF_CHECK("derived-equiv: logless cursor", set_cursor(db, "body_fetch",
                                                             A + 42));
        int64_t d = derived_stage_cursor(db, "body_fetch");
        int64_t r = raw_stage_cursor(db, "body_fetch");
        RF_CHECK("derived-equiv: logless body_fetch derived == raw",
                 d == r && d == A + 42);
        sqlite3_close(db);
    }

    /* (5) HEAL-UNDER-STATIC-CURSOR: see the case header. */
    {
        sqlite3 *db = NULL;
        reducer_frontier_stage_cursor_derived_reset_memo_for_testing();
        if (sqlite3_open(":memory:", &db) != SQLITE_OK) return 1;
        RF_CHECK("derived-heal: schema", build_schema(db));
        RF_CHECK("derived-heal: proven authority",
                 stamp_proven_authority(db, A + 1));
        const int32_t tip = A + 5;
        bool built = true;
        for (int32_t h = A + 1; h <= tip; h++)
            built = built && put_consistent_height(db, h);
        RF_CHECK("derived-heal: rows", built);
        bool cur = true;
        for (size_t i = 0; i < n_up; i++)
            cur = cur && set_cursor(db, upstream[i], tip + 1);
        cur = cur && set_cursor(db, "tip_finalize", tip);
        RF_CHECK("derived-heal: cursors", cur);
        /* An ok=0 validate verdict below the static cursor. */
        char fail_sql[160];
        snprintf(fail_sql, sizeof(fail_sql),
                 "UPDATE validate_headers_log SET ok=0, "
                 "fail_reason='no-header-solution-backfill-required' "
                 "WHERE height=%d", A + 3);
        RF_CHECK("derived-heal: solution-missing row recorded",
                 sqlite3_exec(db, fail_sql, NULL, NULL, NULL) == SQLITE_OK);

        /* First read walks, vetoes the cursor down to the prefix, memoizes. */
        RF_CHECK("derived-heal: blocked derived == log frontier",
                 derived_stage_cursor(db, "validate_headers") == A + 3);
        /* Second read is the memo path (same assertion, memo-served). */
        RF_CHECK("derived-heal: memo holds the blocked floor",
                 derived_stage_cursor(db, "validate_headers") == A + 3);

        /* Recheck heals the row ok=1; the raw cursor does NOT move. */
        char heal_sql[96];
        snprintf(heal_sql, sizeof(heal_sql),
                 "UPDATE validate_headers_log SET ok=1, fail_reason=NULL "
                 "WHERE height=%d", A + 3);
        RF_CHECK("derived-heal: recheck rewrites the row ok=1",
                 sqlite3_exec(db, heal_sql, NULL, NULL, NULL) == SQLITE_OK);

        /* The next derived read sees the healed frontier though raw is
         * unchanged. */
        RF_CHECK("derived-heal: healed row drops the stale-LOW memo",
                 derived_stage_cursor(db, "validate_headers") == tip + 1);
        sqlite3_close(db);
    }

    return failures;
}

/* A consensus store with no reducer stage schema yet (no state source landed)
 * reports one WARN per interval and fails closed; the per-stage "cursor below
 * hstar" diagnostic is likewise emitted once per stage per interval, not once
 * per call. */
static int case_unseeded_store_warnings_are_throttled(void)
{
    int failures = 0;
    sqlite3 *db = NULL;
    if (sqlite3_open(":memory:", &db) != SQLITE_OK) return 1;
    reducer_frontier_log_throttles_reset_for_test();

    int32_t hstar = -1, served = -1;
    bool any_ok = false;
    for (int i = 0; i < 50; i++)
        any_ok = any_ok || reducer_frontier_compute_hstar(db, &hstar, &served);
    RF_CHECK("unseeded: compute fails closed on a schema-less store", !any_ok);
    RF_CHECK("unseeded: 50 calls emit exactly one schema warning",
             reducer_frontier_schema_warn_emitted_for_test() == 1);

    RF_CHECK("unseeded: schema", build_schema(db));
    RF_CHECK("unseeded: empty cursors", set_all_cursors(db, 0));
    bool all_ok = true;
    for (int i = 0; i < 50; i++)
        all_ok = all_ok &&
                 reducer_frontier_compute_hstar(db, &hstar, &served);
    uint64_t first = reducer_frontier_cursor_warn_emitted_for_test();
    RF_CHECK("unseeded: seeded schema computes", all_ok && hstar == 0);
    RF_CHECK("unseeded: each stage warns once across 50 calls",
             first > 0 && first <= 16);
    for (int i = 0; i < 50; i++)
        (void)reducer_frontier_compute_hstar(db, &hstar, &served);
    RF_CHECK("unseeded: 50 more calls emit no further cursor warnings",
             reducer_frontier_cursor_warn_emitted_for_test() == first);
    sqlite3_close(db);
    return failures;
}

int test_reducer_frontier(void)
{
    int failures = 0;
    printf("\n--- reducer_frontier (L0 H* authority) ---\n");
    failures += case_body_read_repair_note();
    failures += case_derived_stage_cursor_equivalence();
    failures += case_partial_authority_does_not_enable_compiled_floor();
    failures += case_consistent();
    failures += case_unseeded_store_warnings_are_throttled();
    failures += case_proof_and_utxo_fork_split();
    failures += case_validation_evidence_contained();
    failures += case_torn();
    failures += case_sparse_seed_anchor();
    failures += case_durable_base_accepts_rowless_first();
    failures += case_durable_base_survives_header_failure();
    failures += case_anchor_collapse_after_forward_ok0();
    failures += case_clamp_up();
    failures += case_hash_split();
    failures += case_split_at_floor();
    failures += case_preflip_no_proof_block_hash();
    failures += case_dump_reports_validate_failure_owner();
    failures += case_dump_marks_run_ahead_stage_cursors();
    failures += case_dump_reports_unavailable_store();
    failures += case_dump_reports_hstar_log_hole();
    failures += case_dump_reports_hstar_hash_split();
    failures += case_dump_ignores_tip_finalize_pending_edge();
    failures += case_dump_reports_tip_finalize_real_hole();
    failures += case_log_frontier_above_tip_finalize_cursor();
    failures += case_dump_reports_rewind_bases();
    failures += case_sovereign_base_ignores_borrowed_higher_stamp();
    if (failures == 0)
        printf("reducer_frontier: all cases passed\n");
    else
        printf("reducer_frontier: %d failure(s)\n", failures);
    return failures;
}
