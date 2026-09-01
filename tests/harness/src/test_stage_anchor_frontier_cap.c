/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Tests for the FIX-3 log-frontier cap — the source guard that kills the
 * log-hole wedge class at its manufacturing site (the seed-anchor cursor
 * bulldozer). Covers the shared helper and both tip_finalize jump sites:
 *
 *   T5  — stage_anchor_cap_target_at_log_frontier four-prong cap rule
 *         (direct calls on a synthetic log).
 *   T5b — panel regression: a FRESH-datadir seed above the compiled
 *         checkpoint must survive (anchor row + tip_finalize cursor at the
 *         served-tip H, upstream cursors at H+1, accepted by the reducer
 *         trusted-anchor scan whose tip_finalize read is convention-aware) —
 *         the write-ordering defeat that a naive post-insert "log empty"
 *         probe would cause. Repeat seeds must not spuriously cap.
 *   T7  — a cursor held at a rowless H is NOT bulldozed by
 *         set_authoritative_tip(H+k); with the successor present the stage
 *         then finalizes H normally (the 3,135,516 class).
 *   T8  — panel interleave: with script/proof cursors clamped to a log
 *         hole, the per-ingest seed (trusted_seed=false) cannot re-tear the
 *         clamp; once the hole is refilled the next seed stamps
 *         contiguously.
 *
 * Fixture style mirrors test_tip_finalize_stage.c (synthetic block_index
 * chain + mirrored progress.kv schemas) and test_stage_anchor.c (private
 * on-disk sqlite DBs, public API only). */

#include "test/test_core.h"

#include "chain/chain.h"
#include "jobs/reducer_frontier.h"
#include "jobs/stage_anchor.h"
#include "jobs/tip_finalize_stage.h"
#include "storage/progress_store.h"
#include "util/stage.h"
#include "validation/chainstate.h"
#include "validation/main_state.h"

#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define FC_CHECK(name, expr) do { \
    printf("frontier_cap: %s... ", (name)); \
    if ((expr)) printf("OK\n"); \
    else { printf("FAIL\n"); failures++; } \
} while (0)

/* ── Shared SQL mirrors (test-seed only) ───────────────────────────── */

static bool fc_exec(sqlite3 *db, const char *sql)
{
    char *err = NULL;
    int rc = sqlite3_exec(db, sql, NULL, NULL, &err);  // raw-sql-ok:test-seed
    if (rc != SQLITE_OK) {
        printf("frontier_cap: SQL failed: %s\n", err ? err : "(no message)");
        if (err) sqlite3_free(err);
        return false;
    }
    return true;
}

/* Stamp coins_kv proven-authority (the 3 rungs coins_kv_is_proven_authority
 * checks) so compute_hstar honors the seeded anchor as a REAL finality floor.
 * compute_hstar's phantom-anchor guard drops the floor to 0 when the store is
 * NOT proven authority — correct for a bare datadir, but the fresh-seed case
 * models a cold-sync seed whose seed path stamps proven authority. Raw SQL
 * (this TU has no coins_kv.h). Returns false on any SQLite error. */
static bool fc_stamp_proven_authority(sqlite3 *db, int64_t applied_height)
{
    if (!fc_exec(db,
            "CREATE TABLE IF NOT EXISTS coins(k BLOB PRIMARY KEY, v BLOB);"
            "INSERT OR IGNORE INTO coins(k,v) VALUES(x'00', x'00');"))
        return false;
    uint8_t ah[8];
    for (int i = 0; i < 8; i++)
        ah[i] = (uint8_t)((uint64_t)applied_height >> (8 * i));
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
    uint8_t one = 1;
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

/* Minimal mirror of a stage log table — the cap only reads `height`. The
 * `ok` column makes the "any-ok row counts" assertion meaningful. */
static bool fc_make_log(sqlite3 *db, const char *table)
{
    char sql[160];
    snprintf(sql, sizeof(sql),
             "CREATE TABLE IF NOT EXISTS %s ("
             " height INTEGER PRIMARY KEY, ok INTEGER NOT NULL DEFAULT 1)",
             table);
    return fc_exec(db, sql);
}

/* Canonical hash-bearing schemas needed by the serving frontier and by the
 * tip-finalize exact-evidence gate.  Tests may leave them empty, but must not
 * substitute height-only tables that make the fail-closed queries impossible
 * to prepare. */
static bool fc_make_exact_evidence_tables(sqlite3 *db)
{
    return fc_exec(db,
        "CREATE TABLE IF NOT EXISTS header_admit_log ("
        " height INTEGER PRIMARY KEY, hash BLOB NOT NULL,"
        " parent_hash BLOB, admitted_at INTEGER NOT NULL);"
        "CREATE TABLE IF NOT EXISTS validate_headers_log ("
        " height INTEGER PRIMARY KEY, hash BLOB NOT NULL,"
        " ok INTEGER NOT NULL, fail_reason TEXT,"
        " validated_at INTEGER NOT NULL);"
        "CREATE TABLE IF NOT EXISTS script_validate_log ("
        " height INTEGER PRIMARY KEY, status TEXT NOT NULL,"
        " ok INTEGER NOT NULL, tx_count INTEGER NOT NULL DEFAULT 0,"
        " input_count INTEGER NOT NULL DEFAULT 0,"
        " first_failure_txid BLOB, first_failure_vin INTEGER,"
        " first_failure_serror INTEGER, validated_at INTEGER NOT NULL DEFAULT 1,"
        " block_hash BLOB, source_epoch_digest BLOB);"
        "CREATE TABLE IF NOT EXISTS proof_validate_log ("
        " height INTEGER PRIMARY KEY, status TEXT NOT NULL,"
        " ok INTEGER NOT NULL, sapling_spends_total INTEGER NOT NULL DEFAULT 0,"
        " sapling_outputs_total INTEGER NOT NULL DEFAULT 0,"
        " sprout_joinsplits_total INTEGER NOT NULL DEFAULT 0,"
        " block_hash BLOB, source_epoch_digest BLOB,"
        " first_failure_txid BLOB, first_failure_proof_type TEXT,"
        " validated_at INTEGER NOT NULL DEFAULT 1);"
        "CREATE TABLE IF NOT EXISTS utxo_apply_delta ("
        " height INTEGER PRIMARY KEY, branch_hash BLOB NOT NULL,"
        " spent_blob BLOB NOT NULL, added_blob BLOB NOT NULL)");
}

static bool fc_put_row(sqlite3 *db, const char *table, int height, int ok)
{
    char sql[160];
    snprintf(sql, sizeof(sql),
             "INSERT OR REPLACE INTO %s(height, ok) VALUES(%d, %d)",
             table, height, ok);
    return fc_exec(db, sql);
}

static uint64_t fc_cursor(sqlite3 *db, const char *name)
{
    sqlite3_stmt *st = NULL;
    uint64_t out = 0;
    if (sqlite3_prepare_v2(db,
            "SELECT cursor FROM stage_cursor WHERE name = ?",
            -1, &st, NULL) != SQLITE_OK)
        return 0;
    sqlite3_bind_text(st, 1, name, -1, SQLITE_STATIC);
    if (sqlite3_step(st) == SQLITE_ROW)  // raw-sql-ok:test-readback
        out = (uint64_t)sqlite3_column_int64(st, 0);
    sqlite3_finalize(st);
    return out;
}

static bool fc_seed_cursor(sqlite3 *db, const char *name, int cursor)
{
    char sql[160];
    snprintf(sql, sizeof(sql),
             "INSERT OR REPLACE INTO stage_cursor(name,cursor,updated_at) "
             "VALUES('%s',%d,1)", name, cursor);
    return fc_exec(db, sql);
}

static bool fc_make_tip_finalize_log(sqlite3 *db)
{
    return fc_exec(db,
        "CREATE TABLE IF NOT EXISTS tip_finalize_log ("
        "  height           INTEGER PRIMARY KEY,"
        "  status           TEXT    NOT NULL,"
        "  ok               INTEGER NOT NULL,"
        "  work_delta_high  INTEGER NOT NULL DEFAULT 0,"
        "  work_delta_low   INTEGER NOT NULL DEFAULT 0,"
        "  utxo_size_after  INTEGER NOT NULL DEFAULT 0,"
        "  reorg_depth      INTEGER NOT NULL DEFAULT 0,"
        "  finalized_at     INTEGER NOT NULL DEFAULT 1,"
        "  tip_hash         BLOB"
        ")");
}

static bool fc_put_tip_hash_row(sqlite3 *db, int height, const char *status,
                                const uint8_t hash[32])
{
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db,
            "INSERT OR REPLACE INTO tip_finalize_log"
            "(height,status,ok,work_delta_high,work_delta_low,"
            " utxo_size_after,reorg_depth,finalized_at,tip_hash) "
            "VALUES(?,?,1,0,0,0,0,1,?)",
            -1, &st, NULL) != SQLITE_OK)
        return false;
    sqlite3_bind_int(st, 1, height);
    sqlite3_bind_text(st, 2, status, -1, SQLITE_STATIC);
    sqlite3_bind_blob(st, 3, hash, 32, SQLITE_STATIC);
    bool ok = sqlite3_step(st) == SQLITE_DONE;  // raw-sql-ok:test-seed
    sqlite3_finalize(st);
    return ok;
}

/* tip_finalize_log row readback: ok + status at height (-1 ok = absent). */
static int fc_tip_row(sqlite3 *db, int height, char *status, size_t n)
{
    if (status && n) status[0] = 0;
    sqlite3_stmt *st = NULL;
    int ok = -1;
    if (sqlite3_prepare_v2(db,
            "SELECT ok, status FROM tip_finalize_log WHERE height = ?",
            -1, &st, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_int(st, 1, height);
    if (sqlite3_step(st) == SQLITE_ROW) {  // raw-sql-ok:test-readback
        ok = sqlite3_column_int(st, 0);
        const unsigned char *txt = sqlite3_column_text(st, 1);
        if (txt && status && n)
            snprintf(status, n, "%s", (const char *)txt);
    }
    sqlite3_finalize(st);
    return ok;
}

/* ── T5: the helper's four-prong cap rule ──────────────────────────── */

static int fc_case_helper(void)
{
    int failures = 0;
    /* Under ./test-tmp, not the checkout root: the unlink() below is the
     * only cleanup, so a crash or a signal between open and close used to
     * strand a test_frontier_cap_<pid>.db in the repo root. */
    char dir[192];
    test_make_tmpdir(dir, sizeof(dir), "frontier_cap", "helper");
    char path[256];
    snprintf(path, sizeof(path), "%s/frontier_cap.db", dir);
    unlink(path);
    sqlite3 *db = NULL;
    FC_CHECK("T5: db open", sqlite3_open(path, &db) == SQLITE_OK);
    if (!db) return failures + 1;

    FC_CHECK("T5: make log", fc_make_log(db, "script_validate_log"));
    bool seeded = true;
    for (int h = 100; h <= 120; h++) {
        if (h == 110) continue;  /* the hole */
        seeded = seeded && fc_put_row(db, "script_validate_log", h, 1);
    }
    FC_CHECK("T5: seed rows 100..120 minus 110", seeded);

    uint64_t capped = 0;
    /* Prong 4: lowest rowless height inside [cursor, requested) caps. */
    FC_CHECK("T5: hole inside jump -> capped at the hole",
             stage_anchor_cap_target_at_log_frontier(db,
                 "script_validate_log", 100, 121, false, &capped) &&
             capped == 110);
    /* Prong 4: cursor itself rowless caps at the cursor (no-op jump). */
    FC_CHECK("T5: rowless cursor -> capped at the cursor",
             stage_anchor_cap_target_at_log_frontier(db,
                 "script_validate_log", 99, 121, false, &capped) &&
             capped == 99);
    /* Prong 1: a target at/behind the cursor passes through unchanged. */
    FC_CHECK("T5: requested <= cursor -> pass-through",
             stage_anchor_cap_target_at_log_frontier(db,
                 "script_validate_log", 121, 110, false, &capped) &&
             capped == 110);
    /* Prong 2: caller-declared seed exemption skips the scan entirely. */
    FC_CHECK("T5: seed_exempt=true -> full jump over the hole",
             stage_anchor_cap_target_at_log_frontier(db,
                 "script_validate_log", 100, 121, true, &capped) &&
             capped == 121);
    /* Any-ok row counts as coverage: an ok=0 row fills the hole. */
    FC_CHECK("T5: fill hole with ok=0 row",
             fc_put_row(db, "script_validate_log", 110, 0));
    FC_CHECK("T5: ok=0 row covers the height -> full jump",
             stage_anchor_cap_target_at_log_frontier(db,
                 "script_validate_log", 100, 121, false, &capped) &&
             capped == 121);
    /* Prong 3: an empty log is a fresh seed, never a hole. */
    FC_CHECK("T5: make empty log", fc_make_log(db, "proof_validate_log"));
    FC_CHECK("T5: empty log -> full jump",
             stage_anchor_cap_target_at_log_frontier(db,
                 "proof_validate_log", 5, 5000, false, &capped) &&
             capped == 5000);
    /* Prong 3: rows only at/above requested == nothing below to tear. */
    FC_CHECK("T5: seed high-only rows",
             fc_put_row(db, "proof_validate_log", 200, 1) &&
             fc_put_row(db, "proof_validate_log", 201, 1));
    FC_CHECK("T5: no row below requested -> full jump",
             stage_anchor_cap_target_at_log_frontier(db,
                 "proof_validate_log", 10, 50, false, &capped) &&
             capped == 50);
    /* A log TABLE that does not exist yet is fresh-seed semantics too
     * (upstream anchors can run before a stage's schema is created). */
    FC_CHECK("T5: missing table -> full jump",
             stage_anchor_cap_target_at_log_frontier(db,
                 "body_persist_log", 0, 4242, false, &capped) &&
             capped == 4242);

    sqlite3_close(db);
    unlink(path);
    test_cleanup_tmpdir(dir);
    return failures;
}

/* ── T5b: fresh-datadir seed above the compiled checkpoint ─────────── */

static int fc_case_fresh_seed(void)
{
    int failures = 0;
    char dir[256];
    test_make_tmpdir(dir, sizeof(dir), "frontier_cap", "fresh_seed");
    FC_CHECK("T5b: progress store opens", progress_store_open(dir));
    sqlite3 *db = progress_store_db();
    if (!db) { progress_store_close(); return failures + 1; }

    /* The reducer-frontier scan needs every success-checked log table. */
    bool tables =
        fc_make_exact_evidence_tables(db) &&
        fc_make_log(db, "body_persist_log") &&
        /* utxo_apply_log needs the CANONICAL columns (not the minimal
         * fc_make_log shape): the seed under test stamps its trust row
         * with status/spent/added (task #31, cold-import row gap). */
        fc_exec(db,
            "CREATE TABLE IF NOT EXISTS utxo_apply_log ("
            "  height               INTEGER PRIMARY KEY,"
            "  status               TEXT    NOT NULL,"
            "  ok                   INTEGER NOT NULL,"
            "  spent_count          INTEGER NOT NULL,"
            "  added_count          INTEGER NOT NULL,"
            "  total_value_delta    INTEGER NOT NULL,"
            "  first_failure_kind   TEXT,"
            "  first_failure_detail BLOB,"
            "  applied_at           INTEGER NOT NULL"
            ")");
    FC_CHECK("T5b: frontier log tables created", tables);

    struct main_state ms;
    memset(&ms, 0, sizeof(ms));
    main_state_init(&ms);
    FC_CHECK("T5b: stage init on an empty chain",
             tip_finalize_stage_init(&ms));
    FC_CHECK("T5b: cursor starts at 0", tip_finalize_stage_cursor() == 0);

    const int H = (int)REDUCER_FRONTIER_TRUSTED_ANCHOR + 7;
    struct uint256 hash;
    uint256_set_null(&hash);
    hash.data[0] = 0x5b;

    /* The ingest-shaped seed (trusted_seed=false): the log is empty BEFORE
     * the call, so the pre-insert-empty prong exempts the self-stamp even
     * though the anchor row is written before the cursor (the panel's
     * write-ordering defeat — a post-insert probe would cap this to 0 and
     * wedge every fresh cold-sync above the compiled checkpoint). */
    FC_CHECK("T5b: fresh seed above checkpoint succeeds",
             tip_finalize_stage_seed_anchor(H, hash.data, false));
    /* TASK #31: the tip_finalize cursor is stamped to H — the seeded served
     * tip's OWN height (cursor C == "served tip at C; C→C+1 pending"). The
     * prior pin (H+1) encoded the +1 bug: stamping H+1 claimed the unfinalized
     * H→H+1 transition and skipped it forever (one late block per cold-import
     * seed). The UPSTREAM reducer cursors keep H+1 — they use the next-height
     * convention (processed through H == next height H+1), and
     * reducer_frontier_compute_hstar normalizes tip_finalize's H to that frame
     * so the seed anchor is still accepted (the H* == H pin below). */
    FC_CHECK("T5b: tip_finalize cursor stamped to served-tip H",
             tip_finalize_stage_cursor() == (uint64_t)H &&
             fc_cursor(db, "tip_finalize") == (uint64_t)H);
    FC_CHECK("T5b: upstream cursors aligned to H+1 (empty-log prong)",
             fc_cursor(db, "script_validate") == (uint64_t)H + 1u &&
             fc_cursor(db, "proof_validate") == (uint64_t)H + 1u &&
             fc_cursor(db, "utxo_apply") == (uint64_t)H + 1u);
    char status[32];
    FC_CHECK("T5b: anchor row written at H",
             fc_tip_row(db, H, status, sizeof(status)) == 1 &&
             strcmp(status, "anchor") == 0);

    /* Model the cold-sync seed's proven-authority stamp. applied_height is the
     * NEXT height, so coverage through the seeded H is represented by H+1. */
    FC_CHECK("T5b: coins_kv proven authority stamped",
             fc_stamp_proven_authority(db, H + 1));

    /* The reducer trusted-anchor scan must ACCEPT the seed: H* anchors at
     * H (not back at the compiled checkpoint). */
    int32_t hstar = 0, served = 0;
    progress_store_tx_lock();
    bool hs_ok = reducer_frontier_compute_hstar(db, &hstar, &served);
    progress_store_tx_unlock();
    FC_CHECK("T5b: reducer accepts the seed anchor (H* == H)",
             hs_ok && hstar == H && served == H);

    /* Repeat the call: the log is now non-empty, but the anchor row covers
     * H, so the scan finds no rowless height — no spurious cap. */
    FC_CHECK("T5b: repeat seed still succeeds",
             tip_finalize_stage_seed_anchor(H, hash.data, false));
    FC_CHECK("T5b: repeat seed leaves the cursor at served-tip H",
             tip_finalize_stage_cursor() == (uint64_t)H);
    progress_store_tx_lock();
    hs_ok = reducer_frontier_compute_hstar(db, &hstar, &served);
    progress_store_tx_unlock();
    FC_CHECK("T5b: H* still anchored at H after the repeat",
             hs_ok && hstar == H);

    /* Member 3 of the #31 lattice: the
     * pipeline CONSUMES the seed anchor row — the first forward step
     * replaces it with the H→H+1 'finalized' row. The trusted base must
     * survive that via the durable REDUCER_TRUSTED_BASE_HEIGHT_KEY
     * declaration, or the frontier walk starves back to the compiled
     * checkpoint and the I4.3 sweep HOLD-wedges the node over the
     * log-less import region. Simulate the consumption and re-derive. */
    FC_CHECK("T5b: simulate pipeline consuming the anchor row",
             fc_exec(db, "UPDATE tip_finalize_log SET status='finalized' "
                         "WHERE status='anchor'"));
    progress_store_tx_lock();
    hs_ok = reducer_frontier_compute_hstar(db, &hstar, &served);
    progress_store_tx_unlock();
    FC_CHECK("T5b: H* survives anchor-row consumption (durable base)",
             hs_ok && hstar == H);

    tip_finalize_stage_shutdown();
    main_state_free(&ms);
    progress_store_close();
    test_cleanup_tmpdir(dir);
    return failures;
}

/* ── T7: held cursor at a rowless H survives set_authoritative_tip ─── */

#define FC_N 4

struct fc_chain {
    struct block_index *blocks;
    struct uint256     *hashes;
};

static bool fc_chain_build(struct fc_chain *sc, struct main_state *ms)
{
    sc->blocks = calloc(FC_N, sizeof(struct block_index));
    sc->hashes = calloc(FC_N, sizeof(struct uint256));
    if (!sc->blocks || !sc->hashes) return false;
    for (int i = 0; i < FC_N; i++) {
        uint256_set_null(&sc->hashes[i]);
        sc->hashes[i].data[0] = (uint8_t)(0xc0 + i);
        block_index_init(&sc->blocks[i]);
        sc->blocks[i].phashBlock = &sc->hashes[i];
        sc->blocks[i].nHeight = i;
        sc->blocks[i].nVersion = 4;
        sc->blocks[i].nTime = (uint32_t)(1700009000u + (uint32_t)i);
        sc->blocks[i].nBits = 0x1f07ffff;
        sc->blocks[i].nStatus = BLOCK_HAVE_DATA | BLOCK_VALID_SCRIPTS;
        arith_uint256_set_u64(&sc->blocks[i].nChainWork, (uint64_t)i + 1);
        if (i > 0) sc->blocks[i].pprev = &sc->blocks[i - 1];
        if (!block_map_insert(&ms->map_block_index, sc->blocks[i].phashBlock,
                              &sc->blocks[i]))
            return false;
    }
    return active_chain_move_window_tip(&ms->chain_active,
                                        &sc->blocks[FC_N - 1]);
}

static int fc_case_init_publishes_capped_cursor(void)
{
    int failures = 0;
    char dir[256];
    test_make_tmpdir(dir, sizeof(dir), "frontier_cap", "init_publish");
    FC_CHECK("T7b: progress store opens", progress_store_open(dir));
    sqlite3 *db = progress_store_db();
    if (!db) { progress_store_close(); return failures + 1; }

    struct main_state ms;
    memset(&ms, 0, sizeof(ms));
    main_state_init(&ms);
    struct fc_chain sc = {0};
    FC_CHECK("T7b: chain 0..3 built", fc_chain_build(&sc, &ms));

    bool seeded = fc_make_tip_finalize_log(db) &&
                  fc_put_tip_hash_row(db, 0, "finalized",
                                      sc.hashes[1].data) &&
                  fc_seed_cursor(db, "tip_finalize", 1) &&
                  /* utxo_apply stage cursor is co-committed with the finalized
                   * frontier in production (a finalized 0->1 row requires height
                   * 0 applied, so utxo_apply >= 1). Seed it consistently so the
                   * boot-open clamp (tip_finalize <= utxo_apply) sees a realistic
                   * upstream and does not fire on this frontier-cap fixture. */
                  fc_seed_cursor(db, "utxo_apply", 1);
    FC_CHECK("T7b: durable cursor/log frontier at h=1", seeded);

    FC_CHECK("T7b: stage init", tip_finalize_stage_init(&ms));
    FC_CHECK("T7b: cursor remains capped at durable frontier",
             tip_finalize_stage_cursor() == 1 &&
             fc_cursor(db, "tip_finalize") == 1);
    FC_CHECK("T7b: init publishes durable frontier, not cached high tip",
             tip_finalize_stage_last_height() == 1 &&
             active_chain_height(&ms.chain_active) == 1 &&
             active_chain_tip(&ms.chain_active) == &sc.blocks[1]);
    char status[32];
    FC_CHECK("T7b: high anchor row is evidence only",
             fc_tip_row(db, FC_N - 1, status, sizeof(status)) == 1 &&
             strcmp(status, "anchor") == 0);

    tip_finalize_stage_shutdown();
    main_state_free(&ms);
    free(sc.blocks);
    free(sc.hashes);
    progress_store_close();
    test_cleanup_tmpdir(dir);
    return failures;
}

static bool fc_seed_utxo_apply(sqlite3 *db, const struct fc_chain *sc,
                               int rows)
{
    if (!db || !sc || !sc->hashes || rows < 0 || rows > FC_N ||
        !fc_make_exact_evidence_tables(db) ||
        !fc_exec(db,
            "CREATE TABLE IF NOT EXISTS utxo_apply_log ("
            " height INTEGER PRIMARY KEY, status TEXT NOT NULL,"
            " ok INTEGER NOT NULL, spent_count INTEGER NOT NULL,"
            " added_count INTEGER NOT NULL,"
            " total_value_delta INTEGER NOT NULL,"
            " first_failure_kind TEXT, first_failure_detail BLOB,"
            " applied_at INTEGER NOT NULL)"))
        return false;

    sqlite3_stmt *header = NULL;
    sqlite3_stmt *validate = NULL;
    sqlite3_stmt *script = NULL;
    sqlite3_stmt *proof = NULL;
    sqlite3_stmt *utxo = NULL;
    sqlite3_stmt *delta = NULL;
    bool prepared =
        sqlite3_prepare_v2(db,
            "INSERT OR REPLACE INTO header_admit_log"
            "(height,hash,parent_hash,admitted_at) VALUES(?,?,?,1)",
            -1, &header, NULL) == SQLITE_OK &&
        sqlite3_prepare_v2(db,
            "INSERT OR REPLACE INTO validate_headers_log"
            "(height,hash,ok,fail_reason,validated_at)"
            " VALUES(?,?,1,NULL,1)",
            -1, &validate, NULL) == SQLITE_OK &&
        sqlite3_prepare_v2(db,
            "INSERT OR REPLACE INTO script_validate_log"
            "(height,status,ok,block_hash) VALUES(?,'verified',1,?)",
            -1, &script, NULL) == SQLITE_OK &&
        sqlite3_prepare_v2(db,
            "INSERT OR REPLACE INTO proof_validate_log"
            "(height,status,ok,block_hash) VALUES(?,'verified',1,?)",
            -1, &proof, NULL) == SQLITE_OK &&
        sqlite3_prepare_v2(db,
            "INSERT OR REPLACE INTO utxo_apply_log"
            "(height,status,ok,spent_count,added_count,"
            " total_value_delta,applied_at)"
            " VALUES(?,'verified',1,1,2,1,1)",
            -1, &utxo, NULL) == SQLITE_OK &&
        sqlite3_prepare_v2(db,
            "INSERT OR REPLACE INTO utxo_apply_delta"
            "(height,branch_hash,spent_blob,added_blob) VALUES(?,?,X'',X'')",
            -1, &delta, NULL) == SQLITE_OK;
    if (!prepared) {
        sqlite3_finalize(header);
        sqlite3_finalize(validate);
        sqlite3_finalize(script);
        sqlite3_finalize(proof);
        sqlite3_finalize(utxo);
        sqlite3_finalize(delta);
        return false;
    }

    bool ok = true;
    for (int h = 0; h < rows; h++) {
        sqlite3_bind_int(header, 1, h);
        sqlite3_bind_blob(header, 2, sc->hashes[h].data, 32, SQLITE_STATIC);
        if (h > 0)
            sqlite3_bind_blob(header, 3, sc->hashes[h - 1].data, 32,
                              SQLITE_STATIC);
        else
            sqlite3_bind_null(header, 3);
        sqlite3_bind_int(validate, 1, h);
        sqlite3_bind_blob(validate, 2, sc->hashes[h].data, 32, SQLITE_STATIC);
        sqlite3_bind_int(script, 1, h);
        sqlite3_bind_blob(script, 2, sc->hashes[h].data, 32, SQLITE_STATIC);
        sqlite3_bind_int(proof, 1, h);
        sqlite3_bind_blob(proof, 2, sc->hashes[h].data, 32, SQLITE_STATIC);
        sqlite3_bind_int(utxo, 1, h);
        sqlite3_bind_int(delta, 1, h);
        sqlite3_bind_blob(delta, 2, sc->hashes[h].data, 32, SQLITE_STATIC);
        ok = sqlite3_step(header) == SQLITE_DONE &&
             sqlite3_step(validate) == SQLITE_DONE &&
             sqlite3_step(script) == SQLITE_DONE &&
             sqlite3_step(proof) == SQLITE_DONE &&
             sqlite3_step(utxo) == SQLITE_DONE &&
             sqlite3_step(delta) == SQLITE_DONE;
        sqlite3_reset(header);
        sqlite3_clear_bindings(header);
        sqlite3_reset(validate);
        sqlite3_clear_bindings(validate);
        sqlite3_reset(script);
        sqlite3_clear_bindings(script);
        sqlite3_reset(proof);
        sqlite3_clear_bindings(proof);
        sqlite3_reset(utxo);
        sqlite3_clear_bindings(utxo);
        sqlite3_reset(delta);
        sqlite3_clear_bindings(delta);
        if (!ok)
            break;
    }
    sqlite3_finalize(header);
    sqlite3_finalize(validate);
    sqlite3_finalize(script);
    sqlite3_finalize(proof);
    sqlite3_finalize(utxo);
    sqlite3_finalize(delta);
    return ok && fc_seed_cursor(db, "utxo_apply", rows);
}

static int fc_case_held_cursor(void)
{
    int failures = 0;
    char dir[256];
    test_make_tmpdir(dir, sizeof(dir), "frontier_cap", "held_cursor");
    FC_CHECK("T7: progress store opens", progress_store_open(dir));
    sqlite3 *db = progress_store_db();
    if (!db) { progress_store_close(); return failures + 1; }

    struct main_state ms;
    memset(&ms, 0, sizeof(ms));
    main_state_init(&ms);
    struct fc_chain sc = {0};
    FC_CHECK("T7: chain 0..3 built", fc_chain_build(&sc, &ms));
    FC_CHECK("T7: utxo_apply rows 0..2 + cursor=3",
             fc_seed_utxo_apply(db, &sc, 3));
    FC_CHECK("T7: stage init", tip_finalize_stage_init(&ms));

    /* Finalize height 0 only: the cursor lands ON the rowless height 1. */
    FC_CHECK("T7: first step finalizes h=0",
             tip_finalize_stage_step_once() == JOB_ADVANCED);
    FC_CHECK("T7: cursor held at 1, no row at 1",
             tip_finalize_stage_cursor() == 1 &&
             fc_tip_row(db, 1, NULL, 0) == -1);

    /* The bulldozer: a trusted re-anchor at the tip. Without FIX-3 this
     * jumps the cursor to 4, stranding heights 1..2 behind a rowless span
     * forever (anchor writes are monotonic). The cap pins it at 1. */
    tip_finalize_stage_set_authoritative_tip(FC_N - 1,
                                             sc.hashes[FC_N - 1].data);
    FC_CHECK("T7: cursor capped at the rowless height (not bulldozed)",
             tip_finalize_stage_cursor() == 1 &&
             fc_cursor(db, "tip_finalize") == 1);
    FC_CHECK("T7: authority publish remains at capped frontier",
             tip_finalize_stage_last_height() == 1 &&
             active_chain_height(&ms.chain_active) == 1 &&
             active_chain_tip(&ms.chain_active) == &sc.blocks[1]);
    char status[32];
    FC_CHECK("T7: authority anchor row still written at the tip",
             fc_tip_row(db, FC_N - 1, status, sizeof(status)) == 1 &&
             strcmp(status, "anchor") == 0);

    /* With the successor present, the held height finalizes normally. */
    FC_CHECK("T7: next step finalizes h=1",
             tip_finalize_stage_step_once() == JOB_ADVANCED);
    FC_CHECK("T7: h=1 row finalized, cursor at 2",
             fc_tip_row(db, 1, status, sizeof(status)) == 1 &&
             strcmp(status, "finalized") == 0 &&
             tip_finalize_stage_cursor() == 2);

    tip_finalize_stage_shutdown();
    main_state_free(&ms);
    free(sc.blocks);
    free(sc.hashes);
    progress_store_close();
    test_cleanup_tmpdir(dir);
    return failures;
}

/* ── T8: clamp/seed interleave at a script+proof log hole ──────────── */

static int fc_case_interleave(void)
{
    int failures = 0;
    char dir[256];
    test_make_tmpdir(dir, sizeof(dir), "frontier_cap", "interleave");
    FC_CHECK("T8: progress store opens", progress_store_open(dir));
    sqlite3 *db = progress_store_db();
    if (!db) { progress_store_close(); return failures + 1; }

    const int tip = 9, hole = 5;
    bool seeded = fc_make_log(db, "script_validate_log") &&
                  fc_make_log(db, "proof_validate_log");
    for (int h = 0; h <= tip && seeded; h++) {
        if (h == hole) continue;  /* the repair-clamped hole */
        seeded = fc_put_row(db, "script_validate_log", h, 1) &&
                 fc_put_row(db, "proof_validate_log", h, 1);
    }
    /* FIX-2-shaped state: repair clamped both cursors to the hole. */
    seeded = seeded &&
             fc_seed_cursor(db, "script_validate", hole) &&
             fc_seed_cursor(db, "proof_validate", hole);
    FC_CHECK("T8: rows 0..9 minus the hole + clamped cursors", seeded);

    struct uint256 hash;
    uint256_set_null(&hash);
    hash.data[0] = 0x78;

    /* The per-ingest re-seed (trusted_seed=false). Pre-FIX-3 this
     * re-bulldozed the clamps to tip+1 every ~150 s — the
     * clamp->bulldoze->re-clamp livelock. */
    FC_CHECK("T8: ingest-shaped seed succeeds",
             tip_finalize_stage_seed_anchor(tip, hash.data, false));
    FC_CHECK("T8: script_validate clamp NOT re-torn (capped at the hole)",
             fc_cursor(db, "script_validate") == (uint64_t)hole);
    FC_CHECK("T8: proof_validate clamp NOT re-torn (capped at the hole)",
             fc_cursor(db, "proof_validate") == (uint64_t)hole);
    /* Stages whose logs do not exist yet keep fresh-seed semantics — the
     * cap is strictly per-stage. */
    FC_CHECK("T8: logless stage still aligned to tip+1",
             fc_cursor(db, "validate_headers") == (uint64_t)tip + 1u);
    char status[32];
    FC_CHECK("T8: anchor row written at the tip",
             fc_tip_row(db, tip, status, sizeof(status)) == 1 &&
             strcmp(status, "anchor") == 0);

    /* Drain/repair refills the hole (simulated by the refill row), after
     * which the next seed stamps contiguously to tip+1. */
    FC_CHECK("T8: refill the hole rows",
             fc_put_row(db, "script_validate_log", hole, 1) &&
             fc_put_row(db, "proof_validate_log", hole, 1));
    FC_CHECK("T8: post-refill seed succeeds",
             tip_finalize_stage_seed_anchor(tip, hash.data, false));
    FC_CHECK("T8: cursors stamp contiguously once the hole is gone",
             fc_cursor(db, "script_validate") == (uint64_t)tip + 1u &&
             fc_cursor(db, "proof_validate") == (uint64_t)tip + 1u);

    progress_store_close();
    test_cleanup_tmpdir(dir);
    return failures;
}

int test_stage_anchor_frontier_cap(void);
int test_stage_anchor_frontier_cap(void)
{
    printf("\n=== stage_anchor frontier-cap (FIX-3) tests ===\n");
    int failures = 0;

    failures += fc_case_helper();
    failures += fc_case_fresh_seed();
    failures += fc_case_init_publishes_capped_cursor();
    failures += fc_case_held_cursor();
    failures += fc_case_interleave();

    printf("=== stage_anchor frontier-cap tests: %s ===\n\n",
           failures ? "FAILED" : "ALL PASS");
    return failures;
}
