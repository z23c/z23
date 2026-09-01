/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * The chaos-fault stage-log FIXTURE builders, split out of
 * simnet_chaos_faults.c at the 800-line shape ceiling. Nothing here injects
 * a fault: every function in this file only writes the per-stage `*_log`
 * rows and `stage_cursor` values that a fault body then perturbs, so the
 * seam is "build the ledger the injector will damage" against "damage it".
 *
 * Fixture idioms below are deliberately copied (not `#include`d — the
 * originals are file-static) from tests/harness/src/test_reducer_frontier.c, so
 * the row shapes and column lists are proven-correct, not reinvented.
 *
 * The four entry points the fault bodies still reach are declared in
 * simnet_chaos_faults_internal.h; everything else stays file-static here.
 */

#include "simnet_chaos_faults_internal.h"

#include "jobs/stage_row_itag.h"
#include "util/stage.h"

#include <sqlite3.h>
#include <stdio.h>
#include <string.h>

/* The per-stage *_log tables (plus the header_admit_log MODEL table and the
 * utxo_apply_delta sidecar) are lazily created by their owning module the
 * first time its production init/step path runs — this fixture never runs
 * the full stage machinery (only tip_finalize_stage_init, for the anchor
 * write), so the rest would not exist yet. reducer_frontier_compute_hstar's
 * hash-agreement cross-check (reducer_frontier_evidence.c) additionally
 * JOINs header_admit_log and utxo_apply_delta against validate_headers_log,
 * so both need real, hash-matching rows too, not just the six k_logs[]
 * tables. CREATE TABLE IF NOT EXISTS with the EXACT production column list
 * (verified against the live source above) is idempotent and safe to call
 * unconditionally: a real ensure_schema call elsewhere on the same db is a
 * silent no-op against identical DDL text. */
bool chaos_ensure_log_tables(sqlite3 *db)
{
    static const char *const ddl =
        "CREATE TABLE IF NOT EXISTS header_admit_log ("
        "  height      INTEGER PRIMARY KEY,"
        "  hash        BLOB    NOT NULL,"
        "  parent_hash BLOB,"
        "  admitted_at INTEGER NOT NULL"
        ");"
        "CREATE TABLE IF NOT EXISTS utxo_apply_delta ("
        "  height       INTEGER PRIMARY KEY,"
        "  branch_hash  BLOB    NOT NULL,"
        "  spent_blob   BLOB    NOT NULL,"
        "  added_blob   BLOB    NOT NULL"
        ");"
        /* The six stage *_log tables carry the production `itag` column and the
         * fixture stamps it on every write (chaos_itag), so the reducer fold's
         * per-row integrity check verifies them exactly as it does a live datadir
         * — no untagged (ABSENT) rows, no stale (MISMATCH) rows. In fault (a) the
         * production seed path creates utxo_apply_log/tip_finalize_log first; the
         * CREATE-IF-NOT-EXISTS here is then a no-op and those tables keep the
         * production schema (which already ALTER-adds itag). */
        "CREATE TABLE IF NOT EXISTS validate_headers_log ("
        "  height       INTEGER PRIMARY KEY,"
        "  hash         BLOB    NOT NULL,"
        "  ok           INTEGER NOT NULL,"
        "  fail_reason  TEXT,"
        "  validated_at INTEGER NOT NULL,"
        "  itag         BLOB"
        ");"
        "CREATE TABLE IF NOT EXISTS script_validate_log ("
        "  height             INTEGER PRIMARY KEY,"
        "  status             TEXT    NOT NULL,"
        "  ok                 INTEGER NOT NULL,"
        "  tx_count           INTEGER NOT NULL,"
        "  input_count        INTEGER NOT NULL,"
        "  first_failure_txid BLOB,"
        "  first_failure_vin  INTEGER,"
        "  first_failure_serror INTEGER,"
        "  validated_at       INTEGER NOT NULL,"
        "  block_hash         BLOB,"
        "  source_epoch_digest BLOB,"
        "  itag               BLOB"
        ");"
        "CREATE TABLE IF NOT EXISTS body_persist_log ("
        "  height       INTEGER PRIMARY KEY,"
        "  source       TEXT    NOT NULL,"
        "  ok           INTEGER NOT NULL,"
        "  persisted_at INTEGER NOT NULL,"
        "  itag         BLOB"
        ");"
        "CREATE TABLE IF NOT EXISTS proof_validate_log ("
        "  height                  INTEGER PRIMARY KEY,"
        "  status                  TEXT    NOT NULL,"
        "  ok                      INTEGER NOT NULL,"
        "  sapling_spends_total    INTEGER NOT NULL,"
        "  sapling_outputs_total   INTEGER NOT NULL,"
        "  sprout_joinsplits_total INTEGER NOT NULL,"
        "  block_hash              BLOB,"
        "  source_epoch_digest     BLOB,"
        "  first_failure_txid      BLOB,"
        "  first_failure_proof_type TEXT,"
        "  validated_at            INTEGER NOT NULL,"
        "  itag                    BLOB"
        ");"
        "CREATE TABLE IF NOT EXISTS utxo_apply_log ("
        "  height               INTEGER PRIMARY KEY,"
        "  status               TEXT    NOT NULL,"
        "  ok                   INTEGER NOT NULL,"
        "  spent_count          INTEGER NOT NULL,"
        "  added_count          INTEGER NOT NULL,"
        "  total_value_delta    INTEGER NOT NULL,"
        "  first_failure_kind   TEXT,"
        "  first_failure_detail BLOB,"
        "  applied_at           INTEGER NOT NULL,"
        "  itag                 BLOB"
        ");"
        "CREATE TABLE IF NOT EXISTS tip_finalize_log ("
        "  height           INTEGER PRIMARY KEY,"
        "  status           TEXT    NOT NULL,"
        "  ok               INTEGER NOT NULL,"
        "  work_delta_high  INTEGER NOT NULL,"
        "  work_delta_low   INTEGER NOT NULL,"
        "  utxo_size_after  INTEGER NOT NULL,"
        "  reorg_depth      INTEGER NOT NULL,"
        "  finalized_at     INTEGER NOT NULL,"
        "  itag             BLOB"
        ");";
    char *err = NULL;
    if (sqlite3_exec(db, ddl, NULL, NULL, &err) != SQLITE_OK) {  // raw-sql-ok:test-fixture-schema
        fprintf(stderr, "[chaos] ensure_log_tables: %s\n", err ? err : "?");
        sqlite3_free(err);
        return false;
    }
    return true;
}

/* Each helper below matches the EXACT real CREATE TABLE column list emitted
 * by the corresponding production module (re-checked against the live
 * source at the time this file was written — every NOT NULL column without
 * a DEFAULT gets an explicit harmless value; compute_hstar's contiguity scan
 * only ever reads height/ok/status/hash, its hash-agreement cross-check also
 * reads hash/block_hash/branch_hash, so the placeholder values in the rest
 * are inert).
 *
 * Every write here is an UPSERT (INSERT ... ON CONFLICT(height) DO UPDATE),
 * not a plain INSERT: tip_finalize_stage_seed_anchor's trusted-seed path
 * ALSO writes a real production row at the anchor height into utxo_apply_log
 * (status='anchor', so it can self-finalize the first C→C+1 transition —
 * see the "seed utxo_apply anchor row" comment in
 * engine/jobs/src/tip_finalize_anchor.c). utxo_apply_log is profile_bound
 * (log_success_requires_full_validation), so a status of 'anchor' fails the
 * VERIFIED parse and would silently cap the contiguous prefix one height
 * short — exactly the off-by-one this upsert avoids. The fixture's own
 * consistent, hash-agreeing row must always win at every height it stamps,
 * never lose to whatever a production seed path wrote first. tip_finalize_log
 * is the one exception (kept OR IGNORE, see chaos_put_tip_finalize) since
 * overwriting its anchor row's status would itself change which row
 * reducer_trusted_anchor's own status='anchor' lookup finds. */

/* Compute the production integrity tag for an ok=1 stage-log row exactly as the
 * live writers do (stage_row_itag_compute decides internally whether `status` is
 * folded in — only for the three status-covered logs), so the reducer fold's
 * per-row verify MATCHes every fixture row instead of seeing a stale/absent tag.
 * All fixture rows are ok=1 (a fully consistent prefix). */
static void chaos_itag(const char *table, int32_t h, const char *status,
                       uint8_t out[STAGE_ROW_ITAG_LEN])
{
    stage_row_itag_compute(table, (int64_t)h, 1,
                           status, status ? strlen(status) : 0, out);
}

static bool chaos_put_header_admit(sqlite3 *db, int32_t h,
                                   const uint8_t hash[32])
{
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db,
            "INSERT INTO header_admit_log(height,hash,admitted_at) "
            "VALUES(?,?,0) ON CONFLICT(height) DO UPDATE SET "
            "hash=excluded.hash", -1, &st, NULL) != SQLITE_OK)
        return false;
    sqlite3_bind_int(st, 1, h);
    sqlite3_bind_blob(st, 2, hash, 32, SQLITE_STATIC);
    bool ok = sqlite3_step(st) == SQLITE_DONE;  // raw-sql-ok:test-fixture-seeding
    sqlite3_finalize(st);
    return ok;
}

bool chaos_put_validate_headers(sqlite3 *db, int32_t h,
                                       const uint8_t hash[32])
{
    uint8_t itag[STAGE_ROW_ITAG_LEN];
    chaos_itag("validate_headers_log", h, NULL, itag);
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db,
            "INSERT INTO validate_headers_log(height,hash,ok,validated_at,itag) "
            "VALUES(?,?,1,0,?) ON CONFLICT(height) DO UPDATE SET "
            "hash=excluded.hash, ok=1, itag=excluded.itag", -1, &st, NULL)
            != SQLITE_OK)
        return false;
    sqlite3_bind_int(st, 1, h);
    sqlite3_bind_blob(st, 2, hash, 32, SQLITE_STATIC);
    sqlite3_bind_blob(st, 3, itag, STAGE_ROW_ITAG_LEN, SQLITE_STATIC);
    bool ok = sqlite3_step(st) == SQLITE_DONE;  // raw-sql-ok:test-fixture-seeding
    sqlite3_finalize(st);
    return ok;
}

static bool chaos_put_script_validate(sqlite3 *db, int32_t h,
                                      const uint8_t hash[32])
{
    uint8_t itag[STAGE_ROW_ITAG_LEN];
    chaos_itag("script_validate_log", h, "verified", itag);
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db,
            "INSERT INTO script_validate_log"
            "(height,status,ok,tx_count,input_count,validated_at,block_hash,itag) "
            "VALUES(?,'verified',1,1,1,0,?,?) ON CONFLICT(height) DO UPDATE "
            "SET status='verified', ok=1, block_hash=excluded.block_hash, "
            "itag=excluded.itag",
            -1, &st, NULL) != SQLITE_OK)
        return false;
    sqlite3_bind_int(st, 1, h);
    sqlite3_bind_blob(st, 2, hash, 32, SQLITE_STATIC);
    sqlite3_bind_blob(st, 3, itag, STAGE_ROW_ITAG_LEN, SQLITE_STATIC);
    bool ok = sqlite3_step(st) == SQLITE_DONE;  // raw-sql-ok:test-fixture-seeding
    sqlite3_finalize(st);
    return ok;
}

static bool chaos_put_body_persist(sqlite3 *db, int32_t h)
{
    uint8_t itag[STAGE_ROW_ITAG_LEN];
    chaos_itag("body_persist_log", h, NULL, itag);
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db,
            "INSERT INTO body_persist_log(height,source,ok,persisted_at,itag) "
            "VALUES(?,'chaos_fixture',1,0,?) ON CONFLICT(height) DO UPDATE "
            "SET ok=1, itag=excluded.itag", -1, &st, NULL) != SQLITE_OK)
        return false;
    sqlite3_bind_int(st, 1, h);
    sqlite3_bind_blob(st, 2, itag, STAGE_ROW_ITAG_LEN, SQLITE_STATIC);
    bool ok = sqlite3_step(st) == SQLITE_DONE;  // raw-sql-ok:test-fixture-seeding
    sqlite3_finalize(st);
    return ok;
}

static bool chaos_put_proof_validate(sqlite3 *db, int32_t h,
                                     const uint8_t hash[32])
{
    uint8_t itag[STAGE_ROW_ITAG_LEN];
    chaos_itag("proof_validate_log", h, "verified", itag);
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db,
            "INSERT INTO proof_validate_log"
            "(height,status,ok,sapling_spends_total,sapling_outputs_total,"
            "sprout_joinsplits_total,block_hash,validated_at,itag) "
            "VALUES(?,'verified',1,0,0,0,?,0,?) ON CONFLICT(height) DO UPDATE "
            "SET status='verified', ok=1, block_hash=excluded.block_hash, "
            "itag=excluded.itag",
            -1, &st, NULL) != SQLITE_OK)
        return false;
    sqlite3_bind_int(st, 1, h);
    sqlite3_bind_blob(st, 2, hash, 32, SQLITE_STATIC);
    sqlite3_bind_blob(st, 3, itag, STAGE_ROW_ITAG_LEN, SQLITE_STATIC);
    bool ok = sqlite3_step(st) == SQLITE_DONE;  // raw-sql-ok:test-fixture-seeding
    sqlite3_finalize(st);
    return ok;
}

static bool chaos_put_utxo_apply(sqlite3 *db, int32_t h)
{
    /* status is overwritten 'anchor'->'verified' when this UPSERTs the row the
     * production tip_finalize seed anchor wrote (see the header comment above):
     * utxo_apply_log is status-covered, so the seed's itag (over 'anchor') would
     * no longer recompute and the fold would read a MISMATCH and cap H* one short.
     * Re-stamp the itag over the NEW ('verified') fields via excluded.itag so the
     * overwritten row verifies cleanly and H* climbs to the full height. */
    uint8_t itag[STAGE_ROW_ITAG_LEN];
    chaos_itag("utxo_apply_log", h, "verified", itag);
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db,
            "INSERT INTO utxo_apply_log"
            "(height,status,ok,spent_count,added_count,total_value_delta,"
            "applied_at,itag) VALUES(?,'verified',1,0,0,0,0,?) "
            "ON CONFLICT(height) DO UPDATE SET status='verified', ok=1, "
            "itag=excluded.itag",
            -1, &st, NULL) != SQLITE_OK)
        return false;
    sqlite3_bind_int(st, 1, h);
    sqlite3_bind_blob(st, 2, itag, STAGE_ROW_ITAG_LEN, SQLITE_STATIC);
    bool ok = sqlite3_step(st) == SQLITE_DONE;  // raw-sql-ok:test-fixture-seeding
    sqlite3_finalize(st);
    return ok;
}

static bool chaos_put_utxo_apply_delta(sqlite3 *db, int32_t h,
                                       const uint8_t hash[32])
{
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db,
            "INSERT INTO utxo_apply_delta"
            "(height,branch_hash,spent_blob,added_blob) "
            "VALUES(?,?,x'',x'') ON CONFLICT(height) DO UPDATE SET "
            "branch_hash=excluded.branch_hash", -1, &st, NULL) != SQLITE_OK)
        return false;
    sqlite3_bind_int(st, 1, h);
    sqlite3_bind_blob(st, 2, hash, 32, SQLITE_STATIC);
    bool ok = sqlite3_step(st) == SQLITE_DONE;  // raw-sql-ok:test-fixture-seeding
    sqlite3_finalize(st);
    return ok;
}

/* OR IGNORE (not upsert): fault (a) may call this for the height whose
 * tip_finalize_log row was already written by
 * tip_finalize_stage_seed_anchor() (the anchor row at N is pipeline-owned —
 * see reducer_frontier.h's frontier_next_cursor commentary). Its status
 * text ('anchor') is load-bearing for reducer_trusted_anchor's own lookup
 * (`WHERE status='anchor'`) — overwriting it would change which row that
 * scan finds, an unrelated behavior this fixture must not perturb. Silently
 * keeping the existing ok=1 row is correct: tip_finalize_log is not
 * profile_bound, so contiguity only cares about ok, not status. */
static bool chaos_put_tip_finalize(sqlite3 *db, int32_t h)
{
    /* tip_finalize_log is NOT status-covered: its itag folds only (table,height,
     * ok), so the production seed anchor row this OR IGNORE preserves at height N
     * verifies over the same fields the fixture rows below N are stamped with. */
    uint8_t itag[STAGE_ROW_ITAG_LEN];
    chaos_itag("tip_finalize_log", h, NULL, itag);
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db,
            "INSERT OR IGNORE INTO tip_finalize_log"
            "(height,status,ok,work_delta_high,work_delta_low,"
            "utxo_size_after,reorg_depth,finalized_at,itag) "
            "VALUES(?,'ok',1,0,0,0,0,0,?)", -1, &st, NULL) != SQLITE_OK)
        return false;
    sqlite3_bind_int(st, 1, h);
    sqlite3_bind_blob(st, 2, itag, STAGE_ROW_ITAG_LEN, SQLITE_STATIC);
    bool ok = sqlite3_step(st) == SQLITE_DONE;  // raw-sql-ok:test-fixture-seeding
    sqlite3_finalize(st);
    return ok;
}

/* Deterministic 32-byte hash keyed by height. */
void chaos_synth_hash(uint8_t out[32], int32_t h)
{
    memset(out, 0, 32);
    out[0] = (uint8_t)(h & 0xff);
    out[1] = (uint8_t)((h >> 8) & 0xff);
    out[2] = (uint8_t)((h >> 16) & 0xff);
    out[31] = 0xC5;
}

/* Write a full, mutually-consistent ok=1 row across every table
 * reducer_frontier_compute_hstar's contiguity scan AND hash-agreement
 * cross-check touch at height h — the same synthetic hash in
 * header_admit_log.hash, validate_headers_log.hash, script_validate_log.
 * block_hash, proof_validate_log.block_hash, and utxo_apply_delta.
 * branch_hash so the JOIN in reducer_frontier_evidence.c finds every leg
 * agreeing (no manufactured hash-split). */
static bool chaos_put_consistent_height(sqlite3 *db, int32_t h)
{
    uint8_t hh[32];
    chaos_synth_hash(hh, h);
    return chaos_put_header_admit(db, h, hh) &&
           chaos_put_validate_headers(db, h, hh) &&
           chaos_put_script_validate(db, h, hh) &&
           chaos_put_body_persist(db, h) &&
           chaos_put_proof_validate(db, h, hh) &&
           chaos_put_utxo_apply(db, h) &&
           chaos_put_utxo_apply_delta(db, h, hh) &&
           chaos_put_tip_finalize(db, h);
}

/* Stamp a full consistent prefix [0, n] and the matching stage_cursor rows
 * (upstream stages count "next height"; tip_finalize is served-tip
 * convention, so its cursor is n itself, not n+1). Returns false on the
 * first sqlite error. */
bool chaos_stamp_prefix(sqlite3 *db, int32_t n)
{
    if (!chaos_ensure_log_tables(db))
        return false;
    for (int32_t h = 0; h <= n; h++)
        if (!chaos_put_consistent_height(db, h))
            return false;
    return stage_set_named_cursor(db, "validate_headers", (uint64_t)(n + 1)) &&
           stage_set_named_cursor(db, "script_validate", (uint64_t)(n + 1)) &&
           stage_set_named_cursor(db, "body_persist", (uint64_t)(n + 1)) &&
           stage_set_named_cursor(db, "proof_validate", (uint64_t)(n + 1)) &&
           stage_set_named_cursor(db, "utxo_apply", (uint64_t)(n + 1)) &&
           stage_set_named_cursor(db, "tip_finalize", (uint64_t)n);
}
