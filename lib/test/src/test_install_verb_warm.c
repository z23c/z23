/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_install_verb_warm — the -install-consensus-bundle boot-order warm.
 *
 * The terminal install verb runs BEFORE tip_finalize_stage_init, so the
 * runtime authority pair (tip_finalize_observe) and the provable-tip cache
 * (reducer_frontier) are still unpublished when the chain-binding evidence
 * gate (chain_frontier_snapshot_collect) reads them — without a warm, every
 * install target, copy or live, refuses "selected frontier changed or is
 * not durable" regardless of its durable state. The
 * verb warms both caches from the DURABLE store via
 * tip_finalize_stage_warm_authority_caches. These cases prove:
 *
 *   1. on a coherent durable image the warm publishes exactly the durable
 *      authority pair (height, own hash) and the computed H* — nothing more,
 *   2. the warm is idempotent (a second call changes nothing),
 *   3. an empty datadir never manufactures a positive H* out of nothing,
 *   4. an already-published cache is never clobbered by the warm.
 *
 * The fixture writes rows with plain sqlite3 INSERT — TEST scaffolding
 * building the durable image, not production reducer code (mirrors
 * test_hstar_integrity.c). */

#include "test/test_core.h"

#include "config/boot.h"
#include "chain/chain.h"
#include "core/serialize.h"
#include "jobs/reducer_frontier.h"
#include "jobs/stage_row_itag.h"
#include "jobs/tip_finalize_stage.h"
#include "models/database.h"
#include "sapling/incremental_merkle_tree.h"
#include "storage/anchor_kv.h"

#include <sqlite3.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

/* src-private observe cache reset seam (forward-declared like the
 * body_persist_log_* seam in test_hstar_integrity.c). */
void tip_finalize_observe_reset_last_height(void);

#define IVW_CHECK(name, expr) do {                               \
    printf("install_verb_warm: %s... ", (name));                 \
    if (expr) { printf("OK\n"); }                                \
    else { printf("FAIL\n"); failures++; }                       \
} while (0)

/* The anchor the production algorithm clamps to; fixtures sit just above it. */
#define A REDUCER_FRONTIER_TRUSTED_ANCHOR  /* 3056758 */

static bool ivw_build_schema(sqlite3 *db)
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
        fprintf(stderr, "[test_install_verb_warm] schema: %s\n",
                err ? err : "(null)");
        sqlite3_free(err);
        return false;
    }
    return true;
}

static bool ivw_stamp_proven_authority(sqlite3 *db, int64_t applied_height)
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

static bool ivw_set_cursor(sqlite3 *db, const char *name, int64_t cursor)
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

static bool ivw_set_all_cursors(sqlite3 *db, int64_t c)
{
    return ivw_set_cursor(db, "validate_headers", c)
        && ivw_set_cursor(db, "body_fetch", c)
        && ivw_set_cursor(db, "body_persist", c)
        && ivw_set_cursor(db, "proof_validate", c)
        && ivw_set_cursor(db, "script_validate", c)
        && ivw_set_cursor(db, "utxo_apply", c)
        && ivw_set_cursor(db, "tip_finalize", c);
}

static void ivw_synth_hash(uint8_t out[32], int32_t h, uint8_t tag)
{
    memset(out, 0, 32);
    out[0] = (uint8_t)(h & 0xff);
    out[1] = (uint8_t)((h >> 8) & 0xff);
    out[2] = (uint8_t)((h >> 16) & 0xff);
    out[31] = tag;
}

static bool ivw_put_tagged(sqlite3 *db, const char *table,
                           const char *hash_col, int32_t height, int ok,
                           const uint8_t hash[32], const char *status)
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
        fprintf(stderr, "[test_install_verb_warm] prepare %s: %s\n",
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

/* The finalize row the production step writes: status "ok" (non-anchor) with
 * the LOOKAHEAD tip_hash — the row at height h binds hash(h+1), exactly the
 * convention tip_finalize_stage_block_hash_at discriminates ("the ok=1 row at
 * height-1 binds the LOOKAHEAD new_tip = active_chain_at(height)"). */
static bool ivw_put_finalize(sqlite3 *db, int32_t h)
{
    uint8_t tip_hash[32];
    ivw_synth_hash(tip_hash, h + 1, 0);
    const char *status = "ok";
    uint8_t itag[STAGE_ROW_ITAG_LEN];
    stage_row_itag_compute("tip_finalize_log", (int64_t)h, 1,
                           status, strlen(status), itag);
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db,
            "INSERT INTO tip_finalize_log(height,status,ok,tip_hash,itag) "
            "VALUES(?,?,?,?,?)", -1, &st, NULL) != SQLITE_OK)
        return false;
    sqlite3_bind_int64(st, 1, h);
    sqlite3_bind_text(st, 2, status, -1, SQLITE_STATIC);
    sqlite3_bind_int(st, 3, 1);
    sqlite3_bind_blob(st, 4, tip_hash, 32, SQLITE_STATIC);
    sqlite3_bind_blob(st, 5, itag, STAGE_ROW_ITAG_LEN, SQLITE_STATIC);
    bool done = sqlite3_step(st) == SQLITE_DONE;
    sqlite3_finalize(st);
    return done;
}

/* A fully consistent ok=1 image at height h across all stage logs, with all
 * per-height hashes AGREEING (tag 0), plus the production finalize row. */
static bool ivw_put_consistent_height(sqlite3 *db, int32_t h)
{
    uint8_t hh[32];
    ivw_synth_hash(hh, h, 0);
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db,
            "INSERT INTO header_admit_log(height,hash,admitted_at) "
            "VALUES(?,?,0)", -1, &st, NULL) != SQLITE_OK)
        return false;
    sqlite3_bind_int(st, 1, h);
    sqlite3_bind_blob(st, 2, hh, 32, SQLITE_STATIC);
    bool ok = sqlite3_step(st) == SQLITE_DONE;
    sqlite3_finalize(st);
    if (!ok) return false;
    st = NULL;
    if (sqlite3_prepare_v2(db,
            "INSERT INTO utxo_apply_delta"
            "(height,branch_hash,spent_blob,added_blob) "
            "VALUES(?,?,x'',x'')", -1, &st, NULL) != SQLITE_OK)
        return false;
    sqlite3_bind_int(st, 1, h);
    sqlite3_bind_blob(st, 2, hh, 32, SQLITE_STATIC);
    ok = sqlite3_step(st) == SQLITE_DONE;
    sqlite3_finalize(st);
    if (!ok) return false;
    return ivw_put_tagged(db, "validate_headers_log", "hash", h, 1, hh, NULL)
        && ivw_put_tagged(db, "script_validate_log", "block_hash", h, 1, hh,
                          "ok")
        && ivw_put_tagged(db, "body_persist_log", NULL, h, 1, NULL, NULL)
        && ivw_put_tagged(db, "proof_validate_log", "block_hash", h, 1, hh,
                          NULL)
        && ivw_put_tagged(db, "utxo_apply_log", NULL, h, 1, NULL, NULL)
        && ivw_put_finalize(db, h);
}

/* (1)+(2) The warm publishes exactly the durable-derived values and a second
 * warm changes nothing: the computed H* into the provable-tip cache, and the
 * resolver's self-consistent runtime pair — with the served-tip cursor at
 * tip+1 that pair is (tip+1, hash(tip+1)) (the row at tip binds the lookahead
 * hash), while the chain gate's authority evidence at H*=tip resolves from
 * the durable row at tip-1 via tip_finalize_stage_block_hash_at. */
static int case_warm_publishes_durable(void)
{
    int failures = 0;
    sqlite3 *db = NULL;
    if (sqlite3_open(":memory:", &db) != SQLITE_OK) return 1;
    reducer_frontier_provable_tip_reset();
    tip_finalize_observe_reset_last_height();
    IVW_CHECK("schema", ivw_build_schema(db));
    const int32_t tip = A + 6;
    IVW_CHECK("proven authority through tip",
              ivw_stamp_proven_authority(db, tip + 1));
    bool built = true;
    for (int32_t h = A + 1; h <= tip; h++)
        built = built && ivw_put_consistent_height(db, h);
    IVW_CHECK("rows built", built);
    IVW_CHECK("cursors", ivw_set_all_cursors(db, tip + 1));

    IVW_CHECK("pre-warm: provable tip unpublished",
              !reducer_frontier_provable_tip_is_published());

    tip_finalize_stage_warm_authority_caches(db, NULL, "test_warm");

    IVW_CHECK("post-warm: provable tip published",
              reducer_frontier_provable_tip_is_published());
    IVW_CHECK("post-warm: cached H* == durable tip",
              reducer_frontier_provable_tip_cached() == tip);

    int64_t auth_h = -1;
    uint8_t auth_hash[32];
    memset(auth_hash, 0, sizeof(auth_hash));
    bool auth_known = tip_finalize_stage_authority_snapshot(&auth_h, auth_hash);
    uint8_t want_runtime_hash[32];
    ivw_synth_hash(want_runtime_hash, tip + 1, 0);
    IVW_CHECK("post-warm: authority pair known", auth_known);
    IVW_CHECK("post-warm: runtime pair height == cursor (tip+1)",
              auth_h == tip + 1);
    IVW_CHECK("post-warm: runtime pair owns its hash (hash(tip+1))",
              memcmp(auth_hash, want_runtime_hash, 32) == 0);

    /* The chain gate's authority evidence at H*=tip: the durable own-hash at
     * the served height via the convention-aware reader. */
    uint8_t gate_hash[32];
    memset(gate_hash, 0, sizeof(gate_hash));
    uint8_t want_gate_hash[32];
    ivw_synth_hash(want_gate_hash, tip, 0);
    IVW_CHECK("post-warm: gate evidence block_hash_at(H*) resolves",
              tip_finalize_stage_block_hash_at(db, tip, gate_hash));
    IVW_CHECK("post-warm: gate evidence == own hash at H*",
              memcmp(gate_hash, want_gate_hash, 32) == 0);

    /* (2) idempotent: a second warm leaves every published value untouched. */
    tip_finalize_stage_warm_authority_caches(db, NULL, "test_warm_again");
    IVW_CHECK("rewarm: cached H* unchanged",
              reducer_frontier_provable_tip_cached() == tip);
    int64_t auth_h2 = -1;
    uint8_t auth_hash2[32];
    memset(auth_hash2, 0, sizeof(auth_hash2));
    bool auth_known2 = tip_finalize_stage_authority_snapshot(&auth_h2,
                                                             auth_hash2);
    IVW_CHECK("rewarm: authority pair unchanged",
              auth_known2 && auth_h2 == tip + 1 &&
              memcmp(auth_hash2, want_runtime_hash, 32) == 0);

    sqlite3_close(db);
    return failures;
}

/* (3) An empty datadir must never manufacture a positive H* out of nothing. */
static int case_warm_empty_datadir(void)
{
    int failures = 0;
    sqlite3 *db = NULL;
    if (sqlite3_open(":memory:", &db) != SQLITE_OK) return 1;
    reducer_frontier_provable_tip_reset();
    tip_finalize_observe_reset_last_height();
    IVW_CHECK("empty: schema", ivw_build_schema(db));

    tip_finalize_stage_warm_authority_caches(db, NULL, "test_warm_empty");

    IVW_CHECK("empty: no positive H* manufactured",
              reducer_frontier_provable_tip_cached() == 0);

    sqlite3_close(db);
    return failures;
}

/* A fresh node has a real in-memory genesis tip before reducer stage tables
 * exist. The warm must publish exactly H*=0 alongside that runtime authority
 * so clean-genesis instant-on can distinguish it from an unpublished cache. */
static int case_warm_clean_genesis(void)
{
    int failures = 0;
    sqlite3 *db = NULL;
    if (sqlite3_open(":memory:", &db) != SQLITE_OK) return 1;
    reducer_frontier_provable_tip_reset();
    tip_finalize_observe_reset_last_height();
    IVW_CHECK("clean-genesis: schema", ivw_build_schema(db));

    struct uint256 genesis_hash;
    ivw_synth_hash(genesis_hash.data, 0, 0x42);
    struct block_index genesis;
    block_index_init(&genesis);
    genesis.nHeight = 0;
    genesis.phashBlock = &genesis_hash;

    tip_finalize_stage_warm_authority_caches(db, &genesis,
                                             "test_warm_clean_genesis");

    IVW_CHECK("clean-genesis: H*=0 is explicitly published",
              reducer_frontier_provable_tip_is_published() &&
              reducer_frontier_provable_tip_cached() == 0);
    int64_t authority_h = -1;
    uint8_t authority_hash[32];
    IVW_CHECK("clean-genesis: runtime authority owns genesis",
              tip_finalize_stage_authority_snapshot(&authority_h,
                                                    authority_hash) &&
              authority_h == 0 &&
              memcmp(authority_hash, genesis_hash.data, 32) == 0);

    sqlite3_close(db);
    return failures;
}

/* (4) An already-published provable tip is never clobbered by the warm. */
static int case_warm_never_clobbers_published(void)
{
    int failures = 0;
    sqlite3 *db = NULL;
    if (sqlite3_open(":memory:", &db) != SQLITE_OK) return 1;
    reducer_frontier_provable_tip_reset();
    tip_finalize_observe_reset_last_height();
    IVW_CHECK("clobber: schema", ivw_build_schema(db));
    const int32_t tip = A + 4;
    IVW_CHECK("clobber: proven authority through tip",
              ivw_stamp_proven_authority(db, tip + 1));
    bool built = true;
    for (int32_t h = A + 1; h <= tip; h++)
        built = built && ivw_put_consistent_height(db, h);
    IVW_CHECK("clobber: rows built", built);
    IVW_CHECK("clobber: cursors", ivw_set_all_cursors(db, tip + 1));

    tip_finalize_stage_warm_authority_caches(db, NULL, "test_warm");
    IVW_CHECK("clobber: warm published durable tip",
              reducer_frontier_provable_tip_cached() == tip);

    /* Simulate a NEWER runtime publication (a live advance): the warm must
     * not republish the older durable value over it. */
    reducer_frontier_provable_tip_set(tip + 5);
    tip_finalize_stage_warm_authority_caches(db, NULL, "test_warm_late");
    IVW_CHECK("clobber: newer published H* survives the warm",
              reducer_frontier_provable_tip_cached() == tip + 5);

    sqlite3_close(db);
    return failures;
}

/* (5) Post-install derived-state reconciliation: replaces the persisted
 * Sapling tree pair (node.db) from the bundle-installed frontier, resets the
 * in-process provable-tip cache, and verifies MAX(coins.height) == bundle
 * height, refusing on a mismatch. */
static bool piv_build_coins(sqlite3 *db, int32_t max_height)
{
    char *err = NULL;
    if (sqlite3_exec(db,
            "CREATE TABLE coins(txid BLOB, vout INTEGER, value INTEGER,"
            " height INTEGER, is_coinbase INTEGER, script BLOB);",
            NULL, NULL, &err) != SQLITE_OK) {
        sqlite3_free(err);
        return false;
    }
    char sql[256];
    /* Two rows below + one AT max_height so MAX(height) == max_height. */
    snprintf(sql, sizeof(sql),
             "INSERT INTO coins(txid,vout,value,height,is_coinbase,script)"
             " VALUES(x'01',0,1,%d,0,x'02'),(x'03',0,1,%d,0,x'04');",
             max_height - 1, max_height);
    return sqlite3_exec(db, sql, NULL, NULL, &err) == SQLITE_OK
           || (sqlite3_free(err), false);
}

static bool piv_seed_sapling_frontier(sqlite3 *db, int32_t height,
                                      struct uint256 *root_out)
{
    struct incremental_merkle_tree tree;
    sapling_tree_init(&tree);
    struct uint256 leaf;
    for (int i = 0; i < 32; i++)
        leaf.data[i] = (uint8_t)(0x51 + i);
    incremental_tree_append(&tree, &leaf);
    incremental_tree_root(&tree, root_out);
    return anchor_kv_ensure_schema(db) &&
           anchor_kv_reset_mark_complete_in_tx(db) &&
           anchor_kv_add_tree(db, ANCHOR_POOL_SAPLING, &tree, height);
}

static int case_post_install_invalidation(void)
{
#if defined(_WIN32)
    /* The post-install derived-state engine
     * (config/src/consensus_state_install_runtime.c) is a fail-closed
     * refusal on Windows, and its ZCL_TESTING hooks do not exist there. */
    printf("install_verb_warm: SKIP (Windows): post-install derived-state "
           "invalidation (install runtime refuses on Windows)\n");
    return 0;
#else
    int failures = 0;
    const int32_t bundle_h = A; /* 3056758 */

    char dir[256];
    test_make_tmpdir(dir, sizeof(dir), "install_verb_invalidate", "ok");
    char ndb_path[320];
    snprintf(ndb_path, sizeof(ndb_path), "%s/node.db", dir);

    struct node_db ndb;
    IVW_CHECK("invalidate: node_db open", node_db_open(&ndb, ndb_path));

    /* Seed a STALE sapling tree pair at an OLD tip (a post-install residue shape). */
    uint8_t stale_blob[64];
    memset(stale_blob, 0xAB, sizeof(stale_blob));
    IVW_CHECK("invalidate: seed stale sapling_tree",
              node_db_state_set(&ndb, "sapling_tree", stale_blob,
                                sizeof(stale_blob)) &&
              node_db_state_set_int(&ndb, "sapling_tree_rebuild_height",
                                    3155872));
    uint8_t rb[8192];
    size_t rlen = 0;
    IVW_CHECK("invalidate: stale pair present pre-call",
              node_db_state_get(&ndb, "sapling_tree", rb, sizeof(rb), &rlen));

    /* Progress store with a coin set AT the bundle height. */
    sqlite3 *pdb = NULL;
    if (sqlite3_open(":memory:", &pdb) != SQLITE_OK) {
        node_db_close(&ndb);
        return failures + 1;
    }
    IVW_CHECK("invalidate: coins at bundle height", piv_build_coins(pdb, bundle_h));
    struct uint256 installed_root;
    IVW_CHECK("invalidate: bundle Sapling frontier installed",
              piv_seed_sapling_frontier(pdb, bundle_h - 7, &installed_root));

    /* Poison the in-process provable-tip cache with the OLD tip. */
    reducer_frontier_provable_tip_set(3155872);

    IVW_CHECK("invalidate: succeeds on matching coin tip",
              boot_install_consensus_bundle_invalidate_derived_for_test(
                  &ndb, pdb, bundle_h));
    IVW_CHECK("invalidate: bundle sapling_tree replaced stale cache",
              node_db_state_get(&ndb, "sapling_tree", rb, sizeof(rb), &rlen) &&
              rlen > 0 && rlen < sizeof(rb));
    int64_t rh = 0;
    IVW_CHECK("invalidate: sapling_tree_rebuild_height is bundle height",
              node_db_state_get_int(&ndb, "sapling_tree_rebuild_height", &rh) &&
              rh == bundle_h);
    struct incremental_merkle_tree installed_tree;
    sapling_tree_init(&installed_tree);
    struct byte_stream tree_stream;
    stream_init_from_data(&tree_stream, rb, rlen);
    struct uint256 decoded_root;
    bool decoded = incremental_tree_deserialize(&installed_tree, &tree_stream);
    incremental_tree_root(&installed_tree, &decoded_root);
    IVW_CHECK("invalidate: cached tree decodes to bundle frontier",
              decoded && memcmp(decoded_root.data, installed_root.data, 32) == 0);
    IVW_CHECK("invalidate: provable-tip cache reset (served 0)",
              reducer_frontier_provable_tip_cached() == 0 &&
              !reducer_frontier_provable_tip_is_published());

    sqlite3_close(pdb);

    /* Mismatch: coin tip below the bundle height must REFUSE. */
    sqlite3 *pdb2 = NULL;
    if (sqlite3_open(":memory:", &pdb2) == SQLITE_OK) {
        IVW_CHECK("invalidate: coins below bundle height",
                  piv_build_coins(pdb2, bundle_h - 10));
        IVW_CHECK("invalidate: refuses on coin-tip mismatch",
                  !boot_install_consensus_bundle_invalidate_derived_for_test(
                      &ndb, pdb2, bundle_h));
        sqlite3_close(pdb2);
    } else {
        failures++;
    }

    /* Empty coins table (MAX==NULL) must also refuse. */
    sqlite3 *pdb3 = NULL;
    if (sqlite3_open(":memory:", &pdb3) == SQLITE_OK) {
        char *err = NULL;
        (void)sqlite3_exec(pdb3,
            "CREATE TABLE coins(txid BLOB, vout INTEGER, value INTEGER,"
            " height INTEGER, is_coinbase INTEGER, script BLOB);",
            NULL, NULL, &err);
        sqlite3_free(err);
        IVW_CHECK("invalidate: refuses on empty coin set",
                  !boot_install_consensus_bundle_invalidate_derived_for_test(
                      &ndb, pdb3, bundle_h));
        sqlite3_close(pdb3);
    } else {
        failures++;
    }

    node_db_close(&ndb);
    reducer_frontier_provable_tip_reset();
    test_rm_rf_recursive(dir);
    return failures;
#endif
}

int test_install_verb_warm(void)
{
    int failures = 0;
    failures += case_warm_publishes_durable();
    failures += case_warm_empty_datadir();
    failures += case_warm_clean_genesis();
    failures += case_warm_never_clobbers_published();
    failures += case_post_install_invalidation();
    return failures;
}
