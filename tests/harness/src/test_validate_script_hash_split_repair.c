/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Deterministic fault-injection test for the hash_split / validate-script-
 * hash-mismatch wedge class — script_validate recorded an ok=1 verdict for a
 * NON-canonical body at a height, so its block_hash disagrees with the
 * canonical header validate_headers re-derived. apply_hash_agreement
 * (engine/reducer/jobs/src/reducer_frontier.c) then caps H* at the height BELOW the split.
 *
 * THE GAP this test pins closed: before the fix, this class had NO repair owner.
 * diagnostic_repair_hint (reducer_frontier_dump.c) returned "" for
 * "validate-script-hash-mismatch", and the only existing reconcile rewound the
 * validate_headers cursor — which re-derives the SAME canonical hash and never
 * touches the stale script row, so the split could sit forever as a silent
 * operator-needed wedge. The fix adds maybe_repair_validate_script_hash_split to
 * the reducer_frontier_reconcile_light replay ladder (a one-shot stale_script
 * replay that deletes the stale script+proof verdicts and rewinds the cursors so
 * script_validate re-derives against the canonical body), and names that
 * condition as the repair owner in the dump.
 *
 * Fixture: six success-checked logs seeded ok=1 contiguously A+1..A+5 with
 * matching per-height block hashes EXCEPT script_validate_log[A+3].block_hash,
 * which is corrupted to differ from validate_headers_log[A+3].hash.
 *
 *   PHASE A — the wedge is real and now NAMED:
 *     - reducer_frontier_compute_hstar caps H* at A+2 (apply_hash_agreement).
 *     - the new detector finds the split at A+3.
 *     - the reducer_frontier dump reports kind=hash_split,
 *       reason=validate-script-hash-mismatch, AND repair_owner=
 *       reducer_frontier_reconcile_light (was "" before the fix).
 *
 *   PHASE B — the repair fires and AUTO-TERMINATES:
 *     - the one-shot rewind deletes script_validate_log[A+3] and rewinds the
 *       script_validate cursor to A+3.
 *     - a SECOND rewind is a no-op (one-shot marker) — never thrashes.
 *
 *   PHASE C — after re-derivation, H* CLIMBS past the split (the heal):
 *     - re-seed the rewound script/proof rows with the canonical hash (what the
 *       real stages produce on replay) + restore cursors → H* climbs to A+5.
 *
 * Negative control (PHASE A repair_owner goes RED): in reducer_frontier_dump.c,
 * delete the "validate-script-hash-mismatch" -> reducer_frontier_reconcile_light
 * mapping in diagnostic_repair_hint — the dump reports an empty repair_owner and
 * the c4 assertion fails.
 * Negative control (PHASE C never climbs): in
 * stage_repair_reducer_frontier_coin.c, make stale_script_hash_split_unlocked
 * always return -1 (no detection) — the rewind is a no-op, the split persists,
 * and the H*==A+5 assertion stays at A+2 (RED).
 *
 * Scratch files live under ./test-tmp/<name>_<pid>/ per the no-/tmp convention.
 */

#include "test/test_core.h"

#include "core/arith_uint256.h"
#include "jobs/reducer_frontier.h"
#include "jobs/stage_repair.h"
#include "json/json.h"
#include "storage/coins_kv.h"
#include "storage/progress_store.h"
#include "validation/chainstate.h"
#include "validation/main_state.h"

#include <sqlite3.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/* Mirrors engine/reducer/jobs/src/stage_repair_reducer_frontier_internal.h (a src-private
 * header; same mirror idiom as test_stage_repair_coin_backfill.c). This is the
 * PRODUCTION routing discriminator: maybe_repair_validate_script_hash_split
 * calls stage_repair_classify_hash_split, which reads
 * active_chain_at(H)->phashBlock — so it can ONLY be exercised through a real
 * main_state + active chain. PHASES A-C below drive only the *_for_testing
 * progress-store primitives and never reach this function, which is exactly
 * why the live coins-above-H* mis-route (the body-readability gate that
 * livelocked a script-side split) shipped green. PHASE D-F closes that gap. */
enum rf_hash_split_side {
    RF_SPLIT_INDETERMINATE = 0,
    RF_SPLIT_SCRIPT_SIDE,
    RF_SPLIT_VALIDATE_SIDE,
};
enum rf_hash_split_side stage_repair_classify_hash_split(
    struct main_state *ms, sqlite3 *db, int height, bool *out_err);

#define VSH_CHECK(name, expr) do {                                  \
    printf("validate_script_hash_split_repair: %s... ", (name));    \
    if (expr) printf("OK\n");                                       \
    else { printf("FAIL\n"); failures++; }                          \
} while (0)

/* The compiled trusted anchor (SHA3 checkpoint) the algorithm clamps to. */
#define A REDUCER_FRONTIER_TRUSTED_ANCHOR  /* 3,056,758 */

/* The split height: A+3 (a hole at A+3 caps H* at A+2). */
#define SPLIT_H (A + 3)
#define TOP_H   (A + 5)

/* Canonical per-height block hash; `corrupt` flips one byte so a script row's
 * block_hash diverges from the canonical validate_headers hash at the SAME
 * height (the hash_split signature). Both remain valid 32-byte blobs. */
static void fill_hash(uint8_t out[32], int32_t h, bool corrupt)
{
    memset(out, 0, 32);
    out[0] = (uint8_t)(h & 0xff);
    out[1] = (uint8_t)((h >> 8) & 0xff);
    out[2] = (uint8_t)((h >> 16) & 0xff);
    out[3] = corrupt ? 0xBD : 0xCA;
}

static bool vsh_build_schema(sqlite3 *db)
{
    static const char *const ddl =
        "CREATE TABLE IF NOT EXISTS stage_cursor (name TEXT PRIMARY KEY,"
        "  cursor INTEGER NOT NULL, updated_at INTEGER NOT NULL);"
        "CREATE TABLE IF NOT EXISTS progress_meta (key TEXT PRIMARY KEY,"
        "  value BLOB);"
        "CREATE TABLE IF NOT EXISTS header_admit_log ("
        "  height INTEGER PRIMARY KEY, hash BLOB NOT NULL,"
        "  parent_hash BLOB, admitted_at INTEGER NOT NULL);"
        "CREATE TABLE IF NOT EXISTS validate_headers_log ("
        "  height INTEGER PRIMARY KEY, hash BLOB NOT NULL, ok INTEGER NOT NULL,"
        "  fail_reason TEXT, validated_at INTEGER);"
        "CREATE TABLE IF NOT EXISTS script_validate_log ("
        "  height INTEGER PRIMARY KEY, status TEXT NOT NULL, ok INTEGER NOT NULL,"
        "  tx_count INTEGER NOT NULL, input_count INTEGER NOT NULL,"
        "  first_failure_txid BLOB, first_failure_vin INTEGER,"
        "  first_failure_serror INTEGER, validated_at INTEGER NOT NULL,"
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
    return sqlite3_exec(db, ddl, NULL, NULL, NULL) == SQLITE_OK;  // raw-sql-ok:test-seed
}

static bool vsh_set_cursor(sqlite3 *db, const char *name, int64_t cursor)
{
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db,
            "INSERT OR REPLACE INTO stage_cursor(name,cursor,updated_at)"
            " VALUES(?,?,0)",
            -1, &st, NULL) != SQLITE_OK)
        return false;
    sqlite3_bind_text(st, 1, name, -1, SQLITE_STATIC);
    sqlite3_bind_int64(st, 2, cursor);
    bool ok = sqlite3_step(st) == SQLITE_DONE;  // raw-sql-ok:test-seed
    sqlite3_finalize(st);
    return ok;
}

static bool vsh_put_vh(sqlite3 *db, int32_t h)
{
    uint8_t hash[32];
    fill_hash(hash, h, false);
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db,
            "INSERT OR REPLACE INTO validate_headers_log(height,hash,ok)"
            " VALUES(?,?,1)",
            -1, &st, NULL) != SQLITE_OK)
        return false;
    sqlite3_bind_int64(st, 1, h);
    sqlite3_bind_blob(st, 2, hash, 32, SQLITE_TRANSIENT);
    bool ok = sqlite3_step(st) == SQLITE_DONE;  // raw-sql-ok:test-seed
    sqlite3_finalize(st);
    return ok;
}

/* script_validate_log row, ok=1. block_hash = canonical(h) unless `corrupt`. */
static bool vsh_put_sv(sqlite3 *db, int32_t h, bool corrupt)
{
    uint8_t hash[32];
    fill_hash(hash, h, corrupt);
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db,
            "INSERT OR REPLACE INTO script_validate_log"
            "(height,status,ok,tx_count,input_count,validated_at,block_hash)"
            " VALUES(?,'verified',1,0,0,0,?)",
            -1, &st, NULL) != SQLITE_OK)
        return false;
    sqlite3_bind_int64(st, 1, h);
    sqlite3_bind_blob(st, 2, hash, 32, SQLITE_TRANSIENT);
    bool ok = sqlite3_step(st) == SQLITE_DONE;  // raw-sql-ok:test-seed
    sqlite3_finalize(st);
    return ok;
}

static bool vsh_put_simple(sqlite3 *db, const char *sql, int32_t h)
{
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) != SQLITE_OK)
        return false;
    sqlite3_bind_int64(st, 1, h);
    bool ok = sqlite3_step(st) == SQLITE_DONE;  // raw-sql-ok:test-seed
    sqlite3_finalize(st);
    return ok;
}

static bool vsh_put_pv(sqlite3 *db, int32_t h)
{
    uint8_t hash[32];
    fill_hash(hash, h, false);
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db,
            "INSERT OR REPLACE INTO proof_validate_log"
            "(height,status,ok,block_hash) VALUES(?,'verified',1,?)",
            -1, &st, NULL) != SQLITE_OK)
        return false;
    sqlite3_bind_int64(st, 1, h);
    sqlite3_bind_blob(st, 2, hash, 32, SQLITE_TRANSIENT);
    bool ok = sqlite3_step(st) == SQLITE_DONE;  // raw-sql-ok:test-seed
    sqlite3_finalize(st);
    return ok;
}

static bool vsh_put_bp(sqlite3 *db, int32_t h)
{
    return vsh_put_simple(db,
        "INSERT OR REPLACE INTO body_persist_log(height,source,ok)"
        " VALUES(?,'x',1)", h);
}

static bool vsh_put_ua(sqlite3 *db, int32_t h)
{
    return vsh_put_simple(db,
        "INSERT OR REPLACE INTO utxo_apply_log(height,status,ok) "
        "VALUES(?,'verified',1)", h);
}

static bool vsh_put_chain_binding(sqlite3 *db, int32_t h)
{
    uint8_t hash[32];
    uint8_t parent[32];
    fill_hash(hash, h, false);
    fill_hash(parent, h - 1, false);
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db,
            "INSERT OR REPLACE INTO header_admit_log"
            "(height,hash,parent_hash,admitted_at) VALUES(?,?,?,1)",
            -1, &st, NULL) != SQLITE_OK)
        return false;
    sqlite3_bind_int64(st, 1, h);
    sqlite3_bind_blob(st, 2, hash, 32, SQLITE_TRANSIENT);
    sqlite3_bind_blob(st, 3, parent, 32, SQLITE_TRANSIENT);
    bool ok = sqlite3_step(st) == SQLITE_DONE;  // raw-sql-ok:test-seed
    sqlite3_finalize(st);
    if (!ok)
        return false;

    st = NULL;
    if (sqlite3_prepare_v2(db,
            "INSERT OR REPLACE INTO utxo_apply_delta"
            "(height,branch_hash,spent_blob,added_blob) VALUES(?,?,x'',x'')",
            -1, &st, NULL) != SQLITE_OK)
        return false;
    sqlite3_bind_int64(st, 1, h);
    sqlite3_bind_blob(st, 2, hash, 32, SQLITE_TRANSIENT);
    ok = sqlite3_step(st) == SQLITE_DONE;  // raw-sql-ok:test-seed
    sqlite3_finalize(st);
    return ok;
}

static bool vsh_put_tf(sqlite3 *db, int32_t h)
{
    return vsh_put_simple(db,
        "INSERT OR REPLACE INTO tip_finalize_log(height,status,ok)"
        " VALUES(?,'final',1)", h);
}

/* Stamp coins_applied + the migration-complete rung so
 * coins_kv_is_proven_authority returns true and compute_hstar keeps the anchor
 * floor (mirrors test_contaminated_coin_above_anchor cca_set_applied). */
static bool vsh_set_applied(sqlite3 *db, int32_t height)
{
    if (!progress_meta_table_ensure(db))
        return false;
    char *err = NULL;
    if (sqlite3_exec(db, "BEGIN IMMEDIATE", NULL, NULL, &err) != SQLITE_OK) {
        if (err) sqlite3_free(err);
        return false;
    }
    bool ok = coins_kv_set_applied_height_in_tx(db, height);
    const char *finish = ok ? "COMMIT" : "ROLLBACK";
    if (sqlite3_exec(db, finish, NULL, NULL, &err) != SQLITE_OK) {
        if (err) sqlite3_free(err);
        return false;
    }
    if (ok) {
        uint8_t one = 1;
        ok = progress_meta_set(db, COINS_KV_MIGRATION_COMPLETE_KEY, &one, 1);
    }
    return ok;
}

/* Compute H* off the shared progress.kv handle (lock-wrapped like production). */
static bool vsh_hstar(sqlite3 *db, int32_t *hstar)
{
    int32_t served = -1;
    progress_store_tx_lock();
    bool ok = reducer_frontier_compute_hstar(db, hstar, &served);
    progress_store_tx_unlock();
    return ok;
}

/* Does a script_validate_log row exist at height h? */
static bool vsh_sv_row_present(sqlite3 *db, int32_t h)
{
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db,
            "SELECT 1 FROM script_validate_log WHERE height = ?",
            -1, &st, NULL) != SQLITE_OK)
        return false;
    sqlite3_bind_int64(st, 1, h);
    bool present = sqlite3_step(st) == SQLITE_ROW;  // raw-sql-ok:test-seed
    sqlite3_finalize(st);
    return present;
}

static int64_t vsh_cursor(sqlite3 *db, const char *name)
{
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db,
            "SELECT cursor FROM stage_cursor WHERE name = ?",
            -1, &st, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_text(st, 1, name, -1, SQLITE_STATIC);
    int64_t cur = -1;
    if (sqlite3_step(st) == SQLITE_ROW)  // raw-sql-ok:test-seed
        cur = sqlite3_column_int64(st, 0);
    sqlite3_finalize(st);
    return cur;
}

/* Does a validate_headers_log row exist at height h? */
static bool vsh_vh_row_present(sqlite3 *db, int32_t h)
{
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db,
            "SELECT 1 FROM validate_headers_log WHERE height = ?",
            -1, &st, NULL) != SQLITE_OK)
        return false;
    sqlite3_bind_int64(st, 1, h);
    bool present = sqlite3_step(st) == SQLITE_ROW;  // raw-sql-ok:test-readback
    sqlite3_finalize(st);
    return present;
}

/* ── PHASE D-F production fixture helpers ───────────────────────────────────
 * The orchestrator (stage_reducer_frontier_reconcile_light) queries
 * proof_validate_log.status / utxo_apply_log.status (the value_overflow +
 * stale_proof ladder) and the body_fetch_log / header_admit_log columns that
 * the PHASE A-C minimal schema omits, so the production fixture builds its own
 * orchestrator-compatible schema. Successful proof/UTXO rows use the exact
 * `verified` evidence label consumed by the serving reducer. */
static bool vsh_prod_exec(sqlite3 *db, const char *sql)
{
    char *err = NULL;
    int rc = sqlite3_exec(db, sql, NULL, NULL, &err);  // raw-sql-ok:test-seed
    if (rc != SQLITE_OK) {
        printf("vsh_prod: SQL failed: %s\n", err ? err : "(no message)");
        if (err) sqlite3_free(err);
        return false;
    }
    return true;
}

static bool vsh_prod_schema(sqlite3 *db)
{
    return vsh_prod_exec(db,
        "CREATE TABLE IF NOT EXISTS header_admit_log("
        " height INTEGER PRIMARY KEY, hash BLOB NOT NULL,"
        " parent_hash BLOB, admitted_at INTEGER NOT NULL);"
        "CREATE TABLE IF NOT EXISTS validate_headers_log("
        " height INTEGER PRIMARY KEY, hash BLOB NOT NULL, ok INTEGER NOT NULL,"
        " fail_reason TEXT, validated_at INTEGER);"
        "CREATE TABLE IF NOT EXISTS script_validate_log("
        " height INTEGER PRIMARY KEY, status TEXT NOT NULL, ok INTEGER NOT NULL,"
        " tx_count INTEGER NOT NULL, input_count INTEGER NOT NULL,"
        " first_failure_txid BLOB, first_failure_vin INTEGER,"
        " first_failure_serror INTEGER, validated_at INTEGER NOT NULL,"
        " block_hash BLOB);"
        "CREATE TABLE IF NOT EXISTS body_persist_log("
        " height INTEGER PRIMARY KEY, source TEXT, ok INTEGER NOT NULL);"
        "CREATE TABLE IF NOT EXISTS body_fetch_log("
        " height INTEGER PRIMARY KEY, hash BLOB, source TEXT, bytes INTEGER,"
        " fetched_at INTEGER, ok INTEGER, fail_reason TEXT);"
        "CREATE TABLE IF NOT EXISTS proof_validate_log("
        " height INTEGER PRIMARY KEY, status TEXT, ok INTEGER NOT NULL,"
        " block_hash BLOB);"
        "CREATE TABLE IF NOT EXISTS utxo_apply_log("
        " height INTEGER PRIMARY KEY, status TEXT, ok INTEGER NOT NULL);"
        "CREATE TABLE IF NOT EXISTS utxo_apply_delta("
        " height INTEGER PRIMARY KEY, branch_hash BLOB NOT NULL,"
        " spent_blob BLOB NOT NULL, added_blob BLOB NOT NULL);"
        "CREATE TABLE IF NOT EXISTS tip_finalize_log("
        " height INTEGER PRIMARY KEY, status TEXT, ok INTEGER NOT NULL,"
        " tip_hash BLOB);");
}

static bool vsh_prod_put_ha(sqlite3 *db, int32_t h)
{
    uint8_t hash[32];
    uint8_t parent[32];
    fill_hash(hash, h, false);
    fill_hash(parent, h - 1, false);
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db,
            "INSERT OR REPLACE INTO header_admit_log"
            "(height,hash,parent_hash,admitted_at) VALUES(?,?,?,1)",
            -1, &st, NULL) != SQLITE_OK)
        return false;
    sqlite3_bind_int64(st, 1, h);
    sqlite3_bind_blob(st, 2, hash, 32, SQLITE_TRANSIENT);
    sqlite3_bind_blob(st, 3, parent, 32, SQLITE_TRANSIENT);
    bool ok = sqlite3_step(st) == SQLITE_DONE;  // raw-sql-ok:test-seed
    sqlite3_finalize(st);
    return ok;
}

static bool vsh_prod_put_bf(sqlite3 *db, int32_t h)
{
    uint8_t hash[32];
    fill_hash(hash, h, false);
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db,
            "INSERT OR REPLACE INTO body_fetch_log"
            "(height,hash,source,bytes,fetched_at,ok,fail_reason) "
            "VALUES(?,?,'disk',0,1,1,NULL)",
            -1, &st, NULL) != SQLITE_OK)
        return false;
    sqlite3_bind_int64(st, 1, h);
    sqlite3_bind_blob(st, 2, hash, 32, SQLITE_TRANSIENT);
    bool ok = sqlite3_step(st) == SQLITE_DONE;  // raw-sql-ok:test-seed
    sqlite3_finalize(st);
    return ok;
}

/* validate_headers_log row with a DIVERGENT (corrupt) hash — used only to
 * exercise the genuine VALIDATE-side discriminator branch, then reverted. */
static bool vsh_put_vh_corrupt(sqlite3 *db, int32_t h)
{
    uint8_t hash[32];
    fill_hash(hash, h, true);
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db,
            "INSERT OR REPLACE INTO validate_headers_log(height,hash,ok)"
            " VALUES(?,?,1)",
            -1, &st, NULL) != SQLITE_OK)
        return false;
    sqlite3_bind_int64(st, 1, h);
    sqlite3_bind_blob(st, 2, hash, 32, SQLITE_TRANSIENT);
    bool ok = sqlite3_step(st) == SQLITE_DONE;  // raw-sql-ok:test-seed
    sqlite3_finalize(st);
    return ok;
}

/* Install one active-chain block_index at height h. Its IDENTITY hash
 * (phashBlock — what the discriminator reads) is the CANONICAL per-height
 * hash fill_hash(h,false), i.e. == validate_headers' most-work header hash.
 * No BLOCK_HAVE_DATA + nFile=-1 keeps the body deliberately ABSENT: the live
 * mis-route was the OLD discriminator's body-readability gate deferring a
 * script-side split forever; the header-only classifier must route it to the
 * replay regardless. BLOCK_VALID_SCRIPTS (already set) makes the block-flag
 * reconcile a clean no-op so it does not perturb the false-clear assertion. */
static struct block_index *vsh_prod_insert(struct main_state *ms,
                                           struct uint256 *hash, int32_t h,
                                           struct block_index *prev)
{
    fill_hash(hash->data, h, false);
    struct block_index *bi =
        chainstate_insert_block_index((struct chainstate *)ms, hash);
    if (!bi)
        return NULL;
    bi->nHeight = h;
    bi->pprev = prev;
    bi->nStatus = BLOCK_VALID_SCRIPTS;   /* no HAVE_DATA -> flag repair no-op */
    bi->nFile = -1;
    bi->nDataPos = 0;
    bi->nTx = 1;
    bi->nChainTx = prev ? prev->nChainTx + 1 : 1;
    arith_uint256_set_u64(&bi->nChainWork, (uint64_t)(h - A + 1));
    return bi;
}

/* One stage_cursor write. Rows run in table order; a null db or a failed
 * write skips the rest, matching a `db && set && set` chain. */
struct vsh_cursor_spec {
    const char *name;
    int64_t at;
};

static const struct vsh_cursor_spec vsh_anchor_cursors[] = {
    { "validate_headers", TOP_H + 1 },
    { "script_validate", TOP_H + 1 },
    { "body_persist", TOP_H + 1 },
    { "proof_validate", TOP_H + 1 },
    { "utxo_apply", TOP_H + 1 },
    { "tip_finalize", TOP_H },
};

static const struct vsh_cursor_spec vsh_prod_cursors[] = {
    { "validate_headers", TOP_H + 1 },
    { "body_fetch", TOP_H + 1 },
    { "body_persist", TOP_H + 1 },
    { "script_validate", TOP_H + 1 },
    { "proof_validate", TOP_H + 1 },
    { "utxo_apply", TOP_H + 1 },
    { "tip_finalize", TOP_H },
};

static const struct vsh_cursor_spec vsh_reseed_cursors[] = {
    { "script_validate", TOP_H + 1 },
    { "proof_validate", TOP_H + 1 },
    { "tip_finalize", TOP_H },
};

static bool vsh_apply_cursors(sqlite3 *db, const struct vsh_cursor_spec *rows,
                              int n)
{
    bool ok = db != NULL;
    for (int i = 0; i < n; i++)
        ok = ok && vsh_set_cursor(db, rows[i].name, rows[i].at);
    return ok;
}

static bool vsh_schema_with_coin_authority(sqlite3 *db,
                                           bool (*build)(sqlite3 *))
{
    return db && build(db) && coins_kv_ensure_schema(db);
}

/* One height of the six ok=1 logs. Script block_hash is corrupt at the split. */
static bool vsh_put_height_logs(sqlite3 *db, int32_t h)
{
    return vsh_put_vh(db, h)                 /* canonical header */
        && vsh_put_sv(db, h, h == SPLIT_H)   /* corrupt block_hash @ A+3 */
                                             /* divergent @ A+3   */
        && vsh_put_bp(db, h)
        && vsh_put_pv(db, h)
        && vsh_put_ua(db, h)
        && vsh_put_chain_binding(db, h)
        && vsh_put_tf(db, h);
}

/* A+1..A+5. prod_rows also writes body_fetch and header_admit, per height,
 * after the six logs — the production fixture's extra rows. */
static bool vsh_seed_contiguous_logs(sqlite3 *db, bool prod_rows)
{
    bool seeded = db != NULL;
    for (int32_t h = A + 1; h <= TOP_H; h++) {
        seeded = seeded && vsh_put_height_logs(db, h);
        if (prod_rows)
            seeded = seeded
                && vsh_prod_put_bf(db, h)
                && vsh_prod_put_ha(db, h);
    }
    return seeded;
}

static bool vsh_stamp_proven_coin(sqlite3 *db, uint8_t b0, uint8_t b1,
                                  uint8_t b31, int64_t value)
{
    uint8_t txid[32] = {0};
    txid[0] = b0; txid[1] = b1; txid[31] = b31;
    uint8_t cscript[1] = {0x51};  /* OP_TRUE */
    return db
        && coins_kv_add(db, txid, 0, value, A + 1, false, cscript,
                        sizeof(cscript))
        && vsh_set_applied(db, TOP_H);
}

static const char *vsh_json_cstr(const struct json_value *v)
{
    return v ? json_get_str(v) : NULL;
}

static bool vsh_cstr_eq(const char *got, const char *want)
{
    return got && strcmp(got, want) == 0;
}

static bool vsh_compute_hstar_ok(sqlite3 *db, int32_t *hstar)
{
    return db && vsh_hstar(db, hstar);
}

static bool vsh_reseed_canonical_from_split(sqlite3 *db)
{
    bool reseed = db != NULL;
    for (int32_t h = SPLIT_H; h <= TOP_H; h++) {
        reseed = reseed
            && vsh_put_sv(db, h, false)   /* canonical block_hash now */
            && vsh_put_pv(db, h);
    }
    return reseed && vsh_apply_cursors(
        db, vsh_reseed_cursors,
        (int)(sizeof vsh_reseed_cursors / sizeof vsh_reseed_cursors[0]));
}

static bool vsh_install_canonical_chain(struct main_state *ms,
                                        struct uint256 *phash,
                                        struct block_index **pidx)
{
    bool chain_ok = true;
    struct block_index *prev = NULL;
    for (int32_t h = A + 1; h <= TOP_H; h++) {
        int i = (int)(h - (A + 1));
        pidx[i] = vsh_prod_insert(ms, &phash[i], h, prev);
        chain_ok = chain_ok && pidx[i] != NULL;
        prev = pidx[i];
    }
    return chain_ok;
}

static bool vsh_write_header_and_script(sqlite3 *db, int32_t h,
                                        bool corrupt_header,
                                        bool corrupt_script)
{
    bool header_ok = corrupt_header ? vsh_put_vh_corrupt(db, h)
                                    : vsh_put_vh(db, h);
    return header_ok && vsh_put_sv(db, h, corrupt_script);
}

static bool vsh_split_side_is(enum rf_hash_split_side side,
                              enum rf_hash_split_side want, bool err)
{
    return side == want && !err;
}

static bool vsh_dry_routed_to_script_replay(
    const struct stage_reducer_frontier_reconcile_result *dry)
{
    return dry->repaired
        && dry->stale_script_repair_height == SPLIT_H
        && dry->lowest_script_validate_hash_split == SPLIT_H
        && dry->lowest_validate_headers_hash_split == -1
        && dry->hstar == A + 2;
}

static bool vsh_dry_kept_noncanonical(
    const struct stage_reducer_frontier_reconcile_result *dry)
{
    return dry->noncanonical_found >= 1
        && dry->noncanonical_purged == 0
        && dry->lowest_noncanonical == SPLIT_H;
}

static bool vsh_apply_left_split_unrepaired(
    const struct stage_reducer_frontier_reconcile_result *rr)
{
    return !rr->stale_script_repaired
        && rr->lowest_script_validate_hash_split == SPLIT_H
        && rr->lowest_validate_headers_hash_split == -1
        && !rr->clamped_validate_headers
        && !rr->repaired
        && rr->hstar == A + 2;
}

static bool vsh_commit_canonical_replay(sqlite3 *db)
{
    return vsh_put_sv(db, SPLIT_H, false)
        && vsh_apply_cursors(
            db, vsh_prod_cursors,
            (int)(sizeof vsh_prod_cursors / sizeof vsh_prod_cursors[0]));
}

int test_validate_script_hash_split_repair(void);
int test_validate_script_hash_split_repair(void)
{
    test_reset_shared_globals();   /* monolith isolation */
    printf("\n=== validate_script_hash_split_repair tests ===\n");
    int failures = 0;

    char dir[256];
    snprintf(dir, sizeof(dir),
             "./test-tmp/vsh_split_%d", (int)getpid());
    mkdir("./test-tmp", 0755);
    mkdir(dir, 0755);

    progress_store_close();
    bool store_ok = progress_store_open(dir);
    VSH_CHECK("progress store opens", store_ok);
    sqlite3 *pk = progress_store_db();
    VSH_CHECK("progress db handle", pk != NULL);

    bool schema_ok = vsh_schema_with_coin_authority(pk, vsh_build_schema);
    VSH_CHECK("schema built", schema_ok);

    /* ── fixture: six logs ok=1 contiguous A+1..A+5; split at A+3 ──────────── */
    bool seeded = vsh_seed_contiguous_logs(pk, false);
    VSH_CHECK("six logs seeded A+1..A+5 (script hash corrupt @ A+3)", seeded);

    /* Cursors: non-served logs at TOP_H+1; tip_finalize served-tip at TOP_H. */
    bool cursors = vsh_apply_cursors(
        pk, vsh_anchor_cursors,
        (int)(sizeof vsh_anchor_cursors / sizeof vsh_anchor_cursors[0]));
    VSH_CHECK("cursors set", cursors);

    /* Proven authority so compute_hstar keeps the anchor floor (= A). */
    bool coins = vsh_stamp_proven_coin(pk, 0xDE, 0xAD, 0x5e, 1000);
    VSH_CHECK("coins proven authority stamped", coins);

    /* ── PHASE A: the wedge is real and now NAMED ──────────────────────────── */
    {
        int32_t hstar = -1;
        VSH_CHECK("A: compute_hstar returns true",
                  vsh_compute_hstar_ok(pk, &hstar));
        VSH_CHECK("A: H* capped at A+2 (split caps the frontier)",
                  hstar == A + 2);

        int detected = -1;
        bool dok = pk &&
            stage_repair_validate_script_hash_split_detect_for_testing(
                pk, &detected);
        VSH_CHECK("A: detector returns true", dok);
        VSH_CHECK("A: detector finds the split at A+3", detected == SPLIT_H);

        struct json_value dump;
        json_init(&dump);
        bool dumped = pk && reducer_frontier_dump_state_json(&dump, NULL);
        VSH_CHECK("A: dump produced", dumped);
        const struct json_value *kind =
            json_get(&dump, "first_hstar_blocker_kind");
        const struct json_value *reason =
            json_get(&dump, "first_hstar_blocker_reason");
        const struct json_value *owner =
            json_get(&dump, "first_hstar_blocker_repair_owner");
        const char *kind_s = vsh_json_cstr(kind);
        const char *reason_s = vsh_json_cstr(reason);
        const char *owner_s = vsh_json_cstr(owner);
        VSH_CHECK("A: dump kind == hash_split",
                  vsh_cstr_eq(kind_s, "hash_split"));
        VSH_CHECK("A: dump reason == validate-script-hash-mismatch",
                  vsh_cstr_eq(reason_s, "validate-script-hash-mismatch"));
        VSH_CHECK("A: dump NAMES repair_owner reducer_frontier_reconcile_light "
                  "(was empty before the fix)",
                  vsh_cstr_eq(owner_s, "reducer_frontier_reconcile_light"));
        json_free(&dump);
    }

    /* ── PHASE B: the repair fires and AUTO-TERMINATES ─────────────────────── */
    {
        bool repaired = false;
        int at = -1;
        bool rok = pk &&
            stage_repair_validate_script_hash_split_rewind_for_testing(
                pk, &repaired, &at);
        VSH_CHECK("B: rewind returns true", rok);
        VSH_CHECK("B: rewind fired at the split (A+3)",
                  repaired && at == SPLIT_H);
        VSH_CHECK("B: stale script_validate_log[A+3] row deleted",
                  pk && !vsh_sv_row_present(pk, SPLIT_H));
        VSH_CHECK("B: script_validate cursor rewound to A+3",
                  vsh_cursor(pk, "script_validate") == SPLIT_H);

        /* Second call: one-shot marker present -> no-op (never thrashes). */
        bool repaired2 = true;
        int at2 = -1;
        bool rok2 = pk &&
            stage_repair_validate_script_hash_split_rewind_for_testing(
                pk, &repaired2, &at2);
        VSH_CHECK("B: second rewind is a no-op (one-shot marker)",
                  rok2 && !repaired2);
    }

    /* ── PHASE C: after re-derivation, H* CLIMBS past the split ─────────────── */
    {
        /* The real script/proof stages, replaying from the rewound cursor,
         * re-derive the verdict against the CANONICAL body — recording the
         * canonical block hash. Simulate that here, then restore the cursors. */
        bool reseed = vsh_reseed_canonical_from_split(pk);
        VSH_CHECK("C: re-derived script/proof rows + cursors restored", reseed);

        int32_t hstar = -1;
        VSH_CHECK("C: compute_hstar returns true",
                  vsh_compute_hstar_ok(pk, &hstar));
        VSH_CHECK("C: H* CLIMBED past the split to A+5", hstar == TOP_H);
    }

    /* ── teardown ──────────────────────────────────────────────────────────── */
    progress_store_close();
    test_cleanup_tmpdir(dir);

    /* ── PHASE D-F: the PRODUCTION live shape (coins above H*, body absent) ──
     * PHASES A-C exercise only progress-store primitives, so the production
     * routing decision (maybe_repair_validate_script_hash_split ->
     * stage_repair_classify_hash_split, which reads
     * active_chain_at(H)->phashBlock) was never covered — that is why the live
     * coins-above-H* mis-route shipped green. Here we build the real shape:
     *   - a real main_state with a [A+1..A+5] active chain whose per-height
     *     IDENTITY hash (phashBlock) is the CANONICAL most-work header;
     *   - script_validate recorded the DIVERGENT non-canonical body at A+3
     *     (the script-side split that caps H* at A+2);
     *   - coins applied through A+5 (well ABOVE the A+2 frontier);
     *   - the canonical bodies deliberately NOT on disk (nFile=-1) — the live
     *     livelock was the OLD body-readability gate deferring a script-side
     *     split forever, so the header-only classifier MUST route it to the
     *     dual replay regardless of body presence.
     * Asserts: discriminator routes SCRIPT-side (and a genuine validate-side
     * shape routes VALIDATE-side); the orchestrator routes the split to the
     * dual replay; the noncanonical purge PRESERVES (not blind-purges) the
     * below-frontier evidence; the condition does NOT self-report `repaired`
     * while H* is still pinned (the false-clear guard); and once the verdict
     * is re-derived against the canonical body H* CLIMBS past the split. */
    {
        char pdir[256];
        snprintf(pdir, sizeof(pdir),
                 "./test-tmp/vsh_prod_%d", (int)getpid());
        mkdir("./test-tmp", 0755);
        mkdir(pdir, 0755);

        progress_store_close();
        bool p_open = progress_store_open(pdir);
        VSH_CHECK("D: production store opens", p_open);
        sqlite3 *pd = progress_store_db();
        VSH_CHECK("D: production db handle", pd != NULL);
        bool p_schema = vsh_schema_with_coin_authority(pd, vsh_prod_schema);
        VSH_CHECK("D: production schema built", p_schema);
        /* fresh store: drop any cached dry-run detect memo */
        stage_reducer_frontier_reset_detect_memo_for_testing();

        /* Real active chain [A+1..A+5]; canonical header = fill_hash(h,false). */
        struct main_state ms;
        main_state_init(&ms);
        struct uint256 phash[TOP_H - A + 1];
        struct block_index *pidx[TOP_H - A + 1];
        bool chain_ok = vsh_install_canonical_chain(&ms, phash, pidx);
        VSH_CHECK("D: active chain [A+1..A+5] installs", chain_ok);
        VSH_CHECK("D: active-chain window moves to A+5",
                  chain_ok &&
                  active_chain_move_window_tip(&ms.chain_active,
                                               pidx[TOP_H - (A + 1)]));

        /* Six logs ok=1 contiguous A+1..A+5; script hash corrupt @ A+3.
         * validate_headers hash == canonical == active-chain phashBlock. */
        bool p_seeded = vsh_seed_contiguous_logs(pd, true);
        VSH_CHECK("D: production logs seeded (script corrupt @ A+3)", p_seeded);

        bool p_cursors = vsh_apply_cursors(
            pd, vsh_prod_cursors,
            (int)(sizeof vsh_prod_cursors / sizeof vsh_prod_cursors[0]));
        VSH_CHECK("D: production cursors set", p_cursors);

        /* coins proven authority applied through A+5 — WELL above the A+2 H*. */
        bool p_coins = vsh_stamp_proven_coin(pd, 0xC0, 0x1d, 0xab, 2000);
        VSH_CHECK("D: coins proven authority applied @ A+5 (above H*=A+2)",
                  p_coins);

        /* D1 — the wedge is real: the split caps H* at A+2. */
        {
            int32_t hstar = -1;
            VSH_CHECK("D1: compute_hstar returns true",
                      vsh_compute_hstar_ok(pd, &hstar));
            VSH_CHECK("D1: H* capped at A+2 by the script-side split",
                      hstar == A + 2);
        }

        /* D2 — THE routing pin: the in-memory canonical header at A+3 equals
         * validate_headers (vh==active) while script diverged (sv!=active), so
         * the discriminator routes SCRIPT-side. The OLD body-readability gate
         * would have deferred here (body absent, nFile=-1); the header-only
         * classifier must NOT. */
        {
            bool cerr = true;
            enum rf_hash_split_side side =
                stage_repair_classify_hash_split(&ms, pd, SPLIT_H, &cerr);
            VSH_CHECK("D2: classify routes the live split SCRIPT-side "
                      "(no body-readability gate)",
                      vsh_split_side_is(side, RF_SPLIT_SCRIPT_SIDE, cerr));
        }

        /* D2b — direction non-regression: a GENUINE stale header (validate
         * diverged, script == canonical active header) must route VALIDATE-side
         * so the discriminator is not merely hardwired to SCRIPT-side. Probe at
         * A+4, then revert it to canonical so the orchestrator sees only A+3. */
        {
            bool cerr = true;
            VSH_CHECK("D2b: seed genuine stale-header shape @ A+4",
                      vsh_put_vh_corrupt(pd, A + 4));   /* validate diverges  */
            enum rf_hash_split_side side =
                stage_repair_classify_hash_split(&ms, pd, A + 4, &cerr);
            VSH_CHECK("D2b: classify routes a genuine stale header "
                      "VALIDATE-side",
                      vsh_split_side_is(side, RF_SPLIT_VALIDATE_SIDE, cerr));
            VSH_CHECK("D2b: revert A+4 to canonical", vsh_put_vh(pd, A + 4));
        }

        /* D2c — both verdict hashes disagree with the active header. That is
         * not a validate-only clamp: the dual replay owns it because script is
         * not canonical. */
        {
            bool cerr = true;
            VSH_CHECK("D2c: seed both-stale hash shape @ A+4",
                      vsh_write_header_and_script(pd, A + 4, true, true));
            enum rf_hash_split_side side =
                stage_repair_classify_hash_split(&ms, pd, A + 4, &cerr);
            VSH_CHECK("D2c: classify both-stale hashes SCRIPT-side",
                      vsh_split_side_is(side, RF_SPLIT_SCRIPT_SIDE, cerr));
            VSH_CHECK("D2c: revert A+4 to canonical",
                      vsh_write_header_and_script(pd, A + 4, false, false));
        }

        /* D3 + E(dry) — drive the production orchestrator dry-run. It must
         * ROUTE the split to the dual replay (stale_script_repair_height ==
         * A+3, repaired probe set, classified SCRIPT-side off the validate
         * clamp) and the noncanonical purge must PRESERVE — not blind-purge —
         * the below-frontier evidence (found, purged==0). */
        stage_reducer_frontier_reset_detect_memo_for_testing();
        {
            struct stage_reducer_frontier_reconcile_result dry;
            VSH_CHECK("D3: orchestrator dry-run succeeds",
                      stage_reducer_frontier_reconcile_light_needed(
                          pd, &ms, &dry));
            VSH_CHECK("D3: dry-run routes the split to the dual replay",
                      vsh_dry_routed_to_script_replay(&dry));
            VSH_CHECK("E: noncanonical evidence preserved, not blind-purged",
                      vsh_dry_kept_noncanonical(&dry));
        }

        /* Apply — the canonical body is absent (nFile=-1), so the replay
         * cannot re-derive this pass. The FALSE-CLEAR GUARD must hold: the
         * unresolved script-side split is NOT self-reported as `repaired` via a
         * validate/tip cursor clamp, H* stays pinned at A+2, and the evidence
         * rows survive for the replay owner. */
        {
            struct stage_reducer_frontier_reconcile_result rr;
            VSH_CHECK("F: orchestrator apply succeeds",
                      stage_reducer_frontier_reconcile_light(pd, &ms, &rr));
            VSH_CHECK("F: false-clear guard — split unresolved, NOT cleared",
                      vsh_apply_left_split_unrepaired(&rr));
            VSH_CHECK("F: below-frontier split rows survive the purge",
                      vsh_vh_row_present(pd, SPLIT_H) &&
                      vsh_sv_row_present(pd, SPLIT_H));
        }

        /* F2 — model the dual replay's COMMITTED end-state when the body is on
         * disk: it re-derives the canonical script verdict AND advances the
         * stage cursors back to the at-tip frontier. The F apply (body absent)
         * correctly clamped body_fetch/tip_finalize without climbing, so F2 must
         * restore those cursors — re-deriving the row alone leaves a clamped
         * cursor capping H*. With the split cleared and cursors at the frontier,
         * H* CLIMBS past A+3 to the header tip A+5. */
        {
            int32_t hstar = -1;
            VSH_CHECK("F2: re-derive verdict + advance cursors (replay commit)",
                      vsh_commit_canonical_replay(pd));
            VSH_CHECK("F2: compute_hstar returns true after re-derivation",
                      vsh_compute_hstar_ok(pd, &hstar));
            VSH_CHECK("F2: H* CLIMBED past the split to A+5", hstar == TOP_H);
        }

        main_state_free(&ms);
        progress_store_close();
        test_cleanup_tmpdir(pdir);
    }

    return failures;
}
