/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * End-to-end regression for the FRESH-DATADIR SNAPSHOT BOOT seed path.
 *
 * Defect class this guards against: a snapshot import that stops at writing
 * `coins_best_block` without seeding the state the reducer folds over
 * (coins_kv, coins_applied_height, the trusted stage cursors, utxo_sha3). The
 * node then LOOKS synced (a best-block hash on disk) but H* never climbs off
 * the compiled anchor and it never reaches at_tip. The cure routes both the
 * full reindex AND the snapshot import through ONE derivation
 * (reindex_epilogue_derive_imported_snapshot); test_reindex_epilogue.c proves
 * that derivation in isolation.
 *
 * What this test adds: it drives the REAL boot entry point
 * boot_import_snapshot_db() against a genuine on-disk fixture snapshot.db —
 * exercising the whole honest path (integrity_check, _snapshot_meta height,
 * provenance gate, blocks-hash lookup, ATTACH + bulk copy, write-time SHA3,
 * coins_best_block cache write, AND the shared authority epilogue). It then
 * asserts the seeded state is SELF-CONSISTENT: coins_kv reseeded from the
 * imported UTXOs, coins_applied_height at the snapshot next-height frame,
 * coins_best_block == the snapshot tip hash, the stage cursors clamped to the
 * snapshot height, H* CLIMBED off zero (to the covered imported base), the
 * utxo_sha3 stamped, and NO stage naming a blocker. If a future edit reverts
 * boot_import_snapshot_db back to a coins_best_block-only write, this group
 * fails — it locks the "one honest code path" that seeds EVERYTHING.
 *
 * Height regime: boot_import_snapshot_db REFUSES a peer snapshot above the
 * compiled checkpoint (provenance gate) and requires a real SHA3 match AT the
 * checkpoint, so the only synthetically drivable height is BELOW the checkpoint
 * / finality anchor. A compiled checkpoint not covered by this datadir cannot
 * manufacture state above the imported tip, so the epilogue roots H* at the
 * covered imported base instead. */

#include "test/test_core.h"
#include "test/snapshot_boot_fixture.h"

#include "base/serialize_le.h"
#include "config/boot_consensus_bundle_marker.h"
#include "config/boot_snapshot_import.h"
#include "coins/utxo_commitment.h"
#include "core/serialize.h"
#include "sapling/incremental_merkle_tree.h"
#include "jobs/reducer_frontier.h"
#include "jobs/tip_finalize_stage.h"
#include "models/database.h"
#include "services/seed_integrity_gate.h"
#include "storage/coins_kv.h"
#include "storage/progress_store.h"
#include "util/blocker.h"
#include "util/boot_progress.h"
#include "validation/main_state.h"
#if !defined(_WIN32)
#include "crypto/sha3.h"
#include "services/utxo_recovery_service.h"
#include "storage/coins_view_sqlite.h"
#include "../../../engine/composition/src/boot_steps_internal.h"
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <sys/wait.h>
#include <unistd.h>
#endif

#include <errno.h>
#include <sqlite3.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#define SB_CHECK(name, expr) do {                              \
    printf("  snapshot_boot_seed: %s... ", (name));            \
    if (expr) printf("OK\n");                                  \
    else { printf("FAIL\n"); failures++; }                     \
} while (0)

/* Snapshot height BELOW the compiled checkpoint/anchor (3,056,758): the only
 * height a synthetic fixture can drive through boot_import_snapshot_db's
 * provenance + write-time-SHA3 gates. */
#define SB_SNAP_HEIGHT 1000000
#define SB_UTXO_COUNT  1200          /* > the importer's 1000-row plausibility floor */

static int sb_mkdir(const char *p)
{
    if (mkdir(p, 0700) == 0) return 0;
    return (errno == EEXIST) ? 0 : -1;
}

/* The deterministic 32-byte block hash the fixture records at SB_SNAP_HEIGHT;
 * boot_import_snapshot_db must copy it verbatim into coins_best_block. */
static void sb_tip_hash(uint8_t out[32])
{
    for (int i = 0; i < 32; i++) out[i] = (uint8_t)(0xa0 ^ (i * 7 + 3));
}

/* Build a real consensus_snapshot.db fixture: the public tables the importer
 * reads (_snapshot_meta, blocks, utxos) + a padding blob so the file clears the
 * importer's 10 MiB "likely-truncated" size floor. utxos MUST carry the exact
 * 8-column node.db schema/order because the importer bulk-copies with
 * `INSERT INTO main.utxos SELECT * FROM snapsrc.utxos`. */
static bool sb_build_fixture(const char *path, const uint8_t tip_hash[32])
{
    sqlite3 *db = NULL;
    if (sqlite3_open(path, &db) != SQLITE_OK) return false;
    bool ok = true;
    char *err = NULL;

    ok = ok && sqlite3_exec(db,
        "CREATE TABLE _snapshot_meta(key TEXT PRIMARY KEY, value TEXT);"
        "CREATE TABLE blocks(hash BLOB PRIMARY KEY, height INTEGER NOT NULL);"
        "CREATE TABLE utxos("
        "  txid BLOB NOT NULL, vout INTEGER NOT NULL,"
        "  value INTEGER NOT NULL, script BLOB NOT NULL,"
        "  script_type INTEGER NOT NULL DEFAULT 0,"
        "  address_hash BLOB, height INTEGER NOT NULL,"
        "  is_coinbase INTEGER NOT NULL DEFAULT 0,"
        "  PRIMARY KEY(txid,vout));"
        "CREATE TABLE _pad(id INTEGER PRIMARY KEY, blob BLOB);",
        NULL, NULL, &err) == SQLITE_OK;
    if (err) { sqlite3_free(err); err = NULL; }

    /* _snapshot_meta.height */
    if (ok) {
        sqlite3_stmt *st = NULL;
        ok = sqlite3_prepare_v2(db,
            "INSERT INTO _snapshot_meta(key,value) VALUES('height',?)",
            -1, &st, NULL) == SQLITE_OK;
        if (ok) {
            char h[32]; snprintf(h, sizeof(h), "%d", SB_SNAP_HEIGHT);
            sqlite3_bind_text(st, 1, h, -1, SQLITE_TRANSIENT);
            ok = sqlite3_step(st) == SQLITE_DONE;  // raw-sql-ok:test-fixture-seeding
        }
        sqlite3_finalize(st);
    }

    /* blocks row at the snapshot tip height */
    if (ok) {
        sqlite3_stmt *st = NULL;
        ok = sqlite3_prepare_v2(db,
            "INSERT INTO blocks(hash,height) VALUES(?,?)",
            -1, &st, NULL) == SQLITE_OK;
        if (ok) {
            sqlite3_bind_blob(st, 1, tip_hash, 32, SQLITE_STATIC);
            sqlite3_bind_int(st, 2, SB_SNAP_HEIGHT);
            ok = sqlite3_step(st) == SQLITE_DONE;  // raw-sql-ok:test-fixture-seeding
        }
        sqlite3_finalize(st);
    }

    /* SB_UTXO_COUNT deterministic UTXOs (all at heights <= snapshot height). */
    if (ok) ok = sqlite3_exec(db, "BEGIN", NULL, NULL, NULL) == SQLITE_OK;
    if (ok) {
        sqlite3_stmt *st = NULL;
        ok = sqlite3_prepare_v2(db,
            "INSERT INTO utxos"
            "(txid,vout,value,script,script_type,address_hash,height,is_coinbase)"
            " VALUES(?,?,?,?,0,NULL,?,?)", -1, &st, NULL) == SQLITE_OK;
        for (int i = 0; ok && i < SB_UTXO_COUNT; i++) {
            uint8_t txid[32]; memset(txid, 0, 32);
            txid[0] = (uint8_t)(i & 0xFF);
            txid[1] = (uint8_t)((i >> 8) & 0xFF);
            txid[31] = 0x5a;
            uint8_t script[6] = {0x76, 0xa9, (uint8_t)i, 0x14, 0x88, 0xac};
            sqlite3_reset(st);
            sqlite3_bind_blob(st, 1, txid, 32, SQLITE_STATIC);
            sqlite3_bind_int(st, 2, 0);
            sqlite3_bind_int64(st, 3, (int64_t)1000 + i);
            sqlite3_bind_blob(st, 4, script, sizeof(script), SQLITE_STATIC);
            sqlite3_bind_int(st, 5, (i % SB_SNAP_HEIGHT));   /* height */
            sqlite3_bind_int(st, 6, i == 0 ? 1 : 0);         /* is_coinbase */
            ok = sqlite3_step(st) == SQLITE_DONE;  // raw-sql-ok:test-fixture-seeding
        }
        sqlite3_finalize(st);
    }
    if (ok) ok = sqlite3_exec(db, "COMMIT", NULL, NULL, NULL) == SQLITE_OK;

    /* Padding: push the file past the importer's 10 MiB size floor with a
     * single ~11 MiB zeroblob (read-only-attached, never copied). */
    if (ok) {
        sqlite3_stmt *st = NULL;
        ok = sqlite3_prepare_v2(db,
            "INSERT INTO _pad(blob) VALUES(zeroblob(?))", -1, &st, NULL)
            == SQLITE_OK;
        if (ok) {
            sqlite3_bind_int(st, 1, 11 * 1024 * 1024);
            ok = sqlite3_step(st) == SQLITE_DONE;  // raw-sql-ok:test-fixture-seeding
        }
        sqlite3_finalize(st);
    }

    sqlite3_close(db);
    return ok;
}

bool test_snapshot_boot_fixture_build(const char *path, const uint8_t tip_hash[32])
{
    return sb_build_fixture(path, tip_hash);
}

static int32_t sb_trusted_base(sqlite3 *db)
{
    uint8_t blob[8] = {0}; size_t n = 0; bool found = false;
    if (!progress_meta_get(db, REDUCER_TRUSTED_BASE_HEIGHT_KEY,
                           blob, sizeof(blob), &n, &found) || !found || n != 8)
        return -1;
    int64_t v = 0;
    for (int i = 7; i >= 0; i--) v = (v << 8) | blob[i];
    return (int32_t)v;
}

static int64_t sb_cursor(sqlite3 *db, const char *name)
{
    sqlite3_stmt *st = NULL;
    int64_t out = -1;
    if (sqlite3_prepare_v2(db, "SELECT cursor FROM stage_cursor WHERE name=?",
                           -1, &st, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_text(st, 1, name, -1, SQLITE_STATIC);
    if (sqlite3_step(st) == SQLITE_ROW)  // raw-sql-ok:test-fixture-verify
        out = sqlite3_column_int64(st, 0);
    sqlite3_finalize(st);
    return out;
}

int test_snapshot_boot_seed(void);

static bool sb_sql(sqlite3 *db, const char *sql)
{
    if (!sql)
        return true;
    char *error = NULL;
    bool ok = sqlite3_exec(db, sql, NULL, NULL, &error) == SQLITE_OK;
    if (!ok)
        fprintf(stderr, "snapshot fixture SQL failed: %s\n", error ? error : sqlite3_errmsg(db));
    sqlite3_free(error);
    return ok;
}

static bool sb_cache_pair(struct node_db *ndb, int mode)
{
    if (!mode)
        return true;
    struct incremental_merkle_tree tree;
    sapling_tree_init(&tree);
    if (mode == 3) {
        struct uint256 leaf = {{1}};
        incremental_tree_append(&tree, &leaf);
    }
    struct byte_stream stream;
    stream_init(&stream, 128);
    bool ok = incremental_tree_serialize(&tree, &stream) &&
        node_db_state_set(ndb, "sapling_tree", stream.data, stream.size) &&
        node_db_state_set_int(ndb, "sapling_tree_rebuild_height", mode == 2 ? 1 : 0);
    stream_free(&stream);
    return ok;
}

struct sb_guard_case {
    const char *name, *kernel_sql, *node_sql;
    bool readable;
    int cache_mode;
};

#define SB_META(key, value) "INSERT OR REPLACE INTO progress_meta(key,value) VALUES('" key "'," value ");"
static const struct sb_guard_case sb_guard_cases[] = {
    {"one unstamped kernel coin", "CREATE TABLE coins(value); INSERT INTO coins VALUES(7);", NULL, true, 0},
    {"exactly 1000 kernel coins", "CREATE TABLE coins(value); WITH RECURSIVE n(x) AS "
        "(VALUES(1) UNION ALL SELECT x+1 FROM n WHERE x<1000) INSERT INTO coins SELECT x FROM n;", NULL, true, 0},
    {"small legacy mirror", NULL, "INSERT INTO utxos(txid,vout,value,script,height) "
        "VALUES(zeroblob(32),0,7,X'51',1);", true, 0},
    {"zero coins with proven migration", SB_META("coins_applied_height", "X'0100000000000000'")
        SB_META("coins_kv_migration_complete", "X'01'"), NULL, true, 0},
    {"zero coins with self-fold stamp", SB_META("coins_kv_self_folded", "X'01'"), NULL, true, 0},
    {"zero coins with generation", SB_META("coins_kv_authority_generation.v1", "X'0100000000000000'"), NULL, true, 0},
    {"explicit applied zero", SB_META("coins_applied_height", "X'0000000000000000'"), NULL, true, 0},
    {"positive applied progress", SB_META("coins_applied_height", "X'0200000000000000'"), NULL, true, 0},
    {"negative applied height", SB_META("coins_applied_height", "X'FFFFFFFFFFFFFFFF'"), NULL, false, 0},
    {"truncated applied height", SB_META("coins_applied_height", "X'01'"), NULL, false, 0},
    {"text provenance stamp", SB_META("coins_kv_migration_complete", "'1'"), NULL, false, 0},
    {"malformed provenance stamp", SB_META("coins_kv_self_folded", "X'02'"), NULL, false, 0},
    {"malformed generation", SB_META("coins_kv_authority_generation.v1", "X'01'"), NULL, false, 0},
    {"unreadable optional coin view", "CREATE VIEW coins AS SELECT 1 AS value;", NULL, false, 0},
    {"missing mirror is unreadable", NULL, "DROP TABLE utxos;", false, 0},
    {"failed non-genesis apply row", "CREATE TABLE utxo_apply_log(height,ok); "
        "INSERT INTO utxo_apply_log VALUES(2,0);", NULL, true, 0},
    {"non-genesis row after duplicate genesis", "CREATE TABLE utxo_apply_log(height); "
        "INSERT INTO utxo_apply_log VALUES(0),(0),(2);", NULL, true, 0},
    {"malformed row after duplicate genesis", "CREATE TABLE tip_finalize_log(height); "
        "INSERT INTO tip_finalize_log VALUES(0),(0),('bad');", NULL, false, 0},
    {"non-genesis durable row", "CREATE TABLE tip_finalize_log(height,ok); "
        "INSERT INTO tip_finalize_log VALUES(2,0);", NULL, true, 0},
    {"malformed durable row", "CREATE TABLE tip_finalize_log(height); "
        "INSERT INTO tip_finalize_log VALUES('bad');", NULL, false, 0},
    {"negative durable row", "CREATE TABLE tip_finalize_log(height); "
        "INSERT INTO tip_finalize_log VALUES(-1);", NULL, false, 0},
    {"non-genesis apply cursor", "INSERT OR REPLACE INTO stage_cursor(name,cursor,updated_at) "
        "VALUES('utxo_apply',2,0);", NULL, true, 0},
    {"non-genesis finalize cursor", "INSERT OR REPLACE INTO stage_cursor(name,cursor,updated_at) "
        "VALUES('tip_finalize',1,0);", NULL, true, 0},
    {"negative reducer cursor", "DROP TABLE stage_cursor; CREATE TABLE stage_cursor(name,cursor); "
        "INSERT INTO stage_cursor VALUES('utxo_apply',-1);", NULL, false, 0},
    {"positive cursor after duplicate genesis", "DROP TABLE stage_cursor; CREATE TABLE stage_cursor(name,cursor); "
        "INSERT INTO stage_cursor VALUES('utxo_apply',1),('utxo_apply',1),('utxo_apply',2);", NULL, true, 0},
    {"malformed cursor after duplicate genesis", "DROP TABLE stage_cursor; CREATE TABLE stage_cursor(name,cursor); "
        "INSERT INTO stage_cursor VALUES('tip_finalize',0),('tip_finalize',0),('tip_finalize','bad');", NULL, false, 0},
    {"shielded anchor only", "CREATE TABLE sapling_anchors(anchor BLOB,height INTEGER,tree BLOB); "
        "INSERT INTO sapling_anchors VALUES(zeroblob(32),0,X'00');", NULL, true, 0},
    {"shielded adoption only", "CREATE TABLE anchor_state(pool INTEGER,activation_cursor INTEGER); "
        "INSERT INTO anchor_state VALUES(1,2);", NULL, true, 0},
    {"malformed shielded adoption", "CREATE TABLE anchor_state(pool INTEGER,activation_cursor); "
        "INSERT INTO anchor_state VALUES(1,'bad');", NULL, false, 0},
    {"unknown shielded adoption pool", "CREATE TABLE anchor_state(pool,activation_cursor); "
        "INSERT INTO anchor_state VALUES(2,0);", NULL, false, 0},
    {"wrongly typed shielded pool", "CREATE TABLE anchor_state(pool,activation_cursor); "
        "INSERT INTO anchor_state VALUES('sapling',0);", NULL, false, 0},
    {"adoption after duplicate genesis", "CREATE TABLE anchor_state(pool,activation_cursor); "
        "INSERT INTO anchor_state VALUES(1,0),(1,0),(1,2);", NULL, true, 0},
    {"nullifier only", "CREATE TABLE nullifiers(nf BLOB,pool INTEGER,height INTEGER); "
        "INSERT INTO nullifiers VALUES(zeroblob(32),1,0);", NULL, true, 0},
    {"nullifier with unknown pool", "CREATE TABLE nullifiers(nf BLOB,pool,height INTEGER); "
        "INSERT INTO nullifiers VALUES(zeroblob(32),2,0);", NULL, true, 0},
    {"nullifier with wrongly typed pool", "CREATE TABLE nullifiers(nf BLOB,pool,height INTEGER); "
        "INSERT INTO nullifiers VALUES(zeroblob(32),'sapling',0);", NULL, true, 0},
    {"nullifier adoption only", SB_META("nullifier_kv.activation_cursor", "X'32'"), NULL, true, 0},
    {"text nullifier adoption", SB_META("nullifier_kv.activation_cursor", "'2'"), NULL, false, 0},
    {"interrupted shielded replay", SB_META("shielded_history.full_replay.target", "X'31'"), NULL, true, 0},
    {"interrupted refold", SB_META("refold_in_progress", "X'01'"), NULL, true, 0},
    {"malformed replay target", SB_META("shielded_history.full_replay.target", "X'FF'"), NULL, false, 0},
    {"positive cached Sapling height", NULL, NULL, true, 2},
    {"nonempty cached Sapling genesis", NULL, NULL, true, 3},
    {"half cached pair", NULL, "INSERT INTO node_state VALUES('sapling_tree',X'00');", false, 0},
    {"malformed cached pair", NULL, "INSERT INTO node_state VALUES('sapling_tree',X'00'); "
        "INSERT INTO node_state VALUES('sapling_tree_rebuild_height',zeroblob(8));", false, 0},
    {"negative cached height", NULL, "INSERT INTO node_state VALUES('sapling_tree',X'00'); "
        "INSERT INTO node_state VALUES('sapling_tree_rebuild_height',X'FFFFFFFFFFFFFFFF');", false, 0},
    {"oversized cached tree", NULL, "INSERT INTO node_state VALUES('sapling_tree',zeroblob(8193)); "
        "INSERT INTO node_state VALUES('sapling_tree_rebuild_height',zeroblob(8));", false, 0},
};
#undef SB_META

static int sb_guard_one(sqlite3 *db, struct node_db *ndb, const char *dir,
                         const struct sb_guard_case *c)
{
    int failures = 0;
    printf("snapshot bootstrap case: %s\n", c->name);
    bool seeded = sb_sql(db, "BEGIN IMMEDIATE") && sb_sql(ndb->db, "BEGIN IMMEDIATE") &&
        sb_sql(db, c->kernel_sql) && sb_sql(ndb->db, c->node_sql) && sb_cache_pair(ndb, c->cache_mode);
    SB_CHECK("shared guard fixture seeds", seeded);
    sqlite3_int64 kernel = sqlite3_total_changes64(db), derived = sqlite3_total_changes64(ndb->db);
    enum boot_snapshot_first_outcome outcome;
    struct zcl_result result = boot_prepare_snapshot_first(ndb, dir, &outcome);
    bool verdict = c->readable ? result.ok && outcome == BOOT_SNAPSHOT_FIRST_STATE_PRESERVED
        : !result.ok && strstr(result.message, "preserve this datadir") != NULL;
    SB_CHECK("shared guard preserves or refuses without either database write",
             seeded && verdict && sqlite3_total_changes64(db) == kernel &&
             sqlite3_total_changes64(ndb->db) == derived);
    SB_CHECK("shared guard isolated fixture rolls back",
             sb_sql(ndb->db, "ROLLBACK") && sb_sql(db, "ROLLBACK"));
    return failures;
}

static int sb_shared_no_source(struct node_db *ndb, const char *dir)
{
    int failures = 0;
    char source[600], hidden[620];
    snprintf(source, sizeof(source), "%s/consensus_snapshot.db", dir);
    snprintf(hidden, sizeof(hidden), "%s/consensus_snapshot.hidden", dir);
    bool seeded = rename(source, hidden) == 0 && sb_sql(ndb->db, "BEGIN IMMEDIATE") &&
        sb_sql(ndb->db, "INSERT INTO node_state VALUES('sapling_tree',X'00');");
    SB_CHECK("ordinary no-source fixture seeds unrelated incomplete cache", seeded);
    sqlite3 *db = progress_store_db();
    sqlite3_int64 kernel = sqlite3_total_changes64(db), derived = sqlite3_total_changes64(ndb->db);
    enum boot_snapshot_first_outcome outcome;
    struct zcl_result prepared = boot_prepare_snapshot_first(ndb, dir, &outcome);
    SB_CHECK("ordinary no-source boot avoids irrelevant deep eligibility checks",
        seeded && prepared.ok && outcome == BOOT_SNAPSHOT_FIRST_NO_SOURCE &&
        sqlite3_total_changes64(db) == kernel && sqlite3_total_changes64(ndb->db) == derived);
    SB_CHECK("no-source fixture restores source and derived store",
        sb_sql(ndb->db, "ROLLBACK") && rename(hidden, source) == 0);
    return failures;
}

static int sb_shared_guard_tests(const char *root)
{
    int failures = 0;
    char dir[512], snapshot[600], node_path[600];
    snprintf(dir, sizeof(dir), "%s/shared-guard", root);
    snprintf(snapshot, sizeof(snapshot), "%s/consensus_snapshot.db", dir);
    snprintf(node_path, sizeof(node_path), "%s/node.db", dir);
    uint8_t hash[32];
    sb_tip_hash(hash);
    struct node_db ndb = {0};
    bool ready = sb_mkdir(dir) == 0 && sb_build_fixture(snapshot, hash) &&
        node_db_open(&ndb, node_path) && progress_store_open(dir);
    SB_CHECK("shared guard real source and empty target open", ready);
    if (ready) {
        SB_CHECK("shared guard optional fixture tables start absent",
            sb_sql(progress_store_db(), "DROP TABLE IF EXISTS coins; DROP TABLE IF EXISTS utxo_apply_log; "
                "DROP TABLE IF EXISTS tip_finalize_log; DROP TABLE IF EXISTS sapling_anchors; "
                "DROP TABLE IF EXISTS sprout_anchors; DROP TABLE IF EXISTS anchor_state; "
                "DROP TABLE IF EXISTS nullifiers;"));
        for (size_t i = 0; i < sizeof(sb_guard_cases) / sizeof(sb_guard_cases[0]); i++)
            failures += sb_guard_one(progress_store_db(), &ndb, dir, &sb_guard_cases[i]);
        failures += sb_shared_no_source(&ndb, dir);
    }
    progress_store_close();
    if (ndb.open)
        node_db_close(&ndb);
    return failures;
}

static bool sb_shared_genesis(sqlite3 *db, struct node_db *ndb, int mode)
{
    if (!mode)
        return true;
    const uint8_t next_height[8] = {1};
    char header_progress[512];
    snprintf(header_progress, sizeof(header_progress),
        "CREATE TABLE IF NOT EXISTS header_admit_log(height INTEGER PRIMARY KEY,hash BLOB); "
        "INSERT INTO header_admit_log(height,hash) VALUES(%d,zeroblob(32)); "
        "INSERT OR REPLACE INTO stage_cursor(name,cursor,updated_at) VALUES('header_admit',%d,0); "
        "INSERT OR REPLACE INTO stage_cursor(name,cursor,updated_at) VALUES('validate_headers',%d,0);",
        SB_SNAP_HEIGHT + 100, SB_SNAP_HEIGHT + 101, SB_SNAP_HEIGHT + 101);
    return progress_meta_set(db, COINS_APPLIED_HEIGHT_KEY, next_height, sizeof(next_height)) &&
        sb_sql(db, header_progress) &&
        sb_cache_pair(ndb, mode == 2 ? 1 : 0);
}

static int sb_deny_import_write(void *table, int action, const char *name,
    const char *unused, const char *database, const char *trigger)
{
    (void)unused;
    (void)database;
    (void)trigger;
    return action == SQLITE_INSERT && name && strcmp(name, table) == 0 ?
        SQLITE_DENY : SQLITE_OK;
}

static int sb_shared_import_failure(struct node_db *ndb, const char *dir, bool committed)
{
    int failures = 0;
    sqlite3 *fault_db = committed ? progress_store_db() : ndb->db;
    char *table = committed ? "coins" : "utxos";
    int64_t kernel_before = coins_kv_count_sqlite(progress_store_db());
    sqlite3_int64 kernel_writes = sqlite3_total_changes64(progress_store_db());
    SB_CHECK("import write failure injection installed",
        sqlite3_set_authorizer(fault_db, sb_deny_import_write, table) == SQLITE_OK);
    enum boot_snapshot_first_outcome outcome;
    struct zcl_result result = boot_prepare_snapshot_first(ndb, dir, &outcome);
    SB_CHECK("import write failure injection removed",
        sqlite3_set_authorizer(fault_db, NULL, NULL) == SQLITE_OK);
    if (committed) {
        SB_CHECK("post-commit failure stops early boot with pending recovery",
            !result.ok && boot_snapshot_import_pending_or_error(ndb) &&
            node_db_utxo_count(ndb) == SB_UTXO_COUNT);
    } else {
        printf("  snapshot_boot_seed: rollback diagnostic: kernel_before=%lld "
               "kernel_after=%lld kernel_writes=%lld\n",
               (long long)kernel_before,
               (long long)coins_kv_count_sqlite(progress_store_db()),
               (long long)(sqlite3_total_changes64(progress_store_db()) - kernel_writes));
        SB_CHECK("precommit failure rolls back mirror and pending operation",
            result.ok && outcome == BOOT_SNAPSHOT_FIRST_IMPORT_FAILED &&
            !boot_snapshot_import_pending_or_error(ndb) && node_db_utxo_count(ndb) == 0 &&
            coins_kv_count_sqlite(progress_store_db()) == kernel_before &&
            sqlite3_total_changes64(progress_store_db()) == kernel_writes);
    }
    return failures;
}

static int sb_shared_import_case(const char *root, int mode)
{
    int failures = 0;
    char dir[512], snapshot[600], node_path[600];
    snprintf(dir, sizeof(dir), "%s/shared-fresh-%d", root, mode);
    snprintf(snapshot, sizeof(snapshot), "%s/consensus_snapshot.db", dir);
    snprintf(node_path, sizeof(node_path), "%s/node.db", dir);
    uint8_t hash[32];
    sb_tip_hash(hash);
    struct node_db ndb = {0};
    bool ready = sb_mkdir(dir) == 0 && sb_build_fixture(snapshot, hash) &&
        node_db_open(&ndb, node_path) && progress_store_open(dir);
    SB_CHECK("shared fresh import fixture opens", ready);
    if (ready) {
        struct main_state ms;
        memset(&ms, 0, sizeof(ms));
        main_state_init(&ms);
        seed_integrity_gate_set_node_db_for_testing(&ndb);
        bool initialized = tip_finalize_stage_init(&ms) &&
            sb_shared_genesis(progress_store_db(), &ndb, mode < 3 ? mode : 0);
        SB_CHECK("shared pristine/genesis/header-only fixture initializes", initialized);
        if (initialized && mode >= 3)
            failures += sb_shared_import_failure(&ndb, dir, mode == 3);
        enum boot_snapshot_first_outcome outcome;
        struct zcl_result selected = boot_prepare_snapshot_first(&ndb, dir, &outcome);
        SB_CHECK("shared fresh selection really imports the eligible source",
                 selected.ok && outcome == BOOT_SNAPSHOT_FIRST_IMPORTED &&
                 coins_kv_count_sqlite(progress_store_db()) == SB_UTXO_COUNT);
        if (mode == 1 || mode == 2)
            SB_CHECK("import preserves header progress above the imported anchor",
                sb_cursor(progress_store_db(), "header_admit") == SB_SNAP_HEIGHT + 101 &&
                sb_cursor(progress_store_db(), "validate_headers") == SB_SNAP_HEIGHT + 101);
        tip_finalize_stage_shutdown();
        main_state_free(&ms);
        seed_integrity_gate_reset_for_testing();
    }
    progress_store_close();
    if (ndb.open)
        node_db_close(&ndb);
    return failures;
}

static int sb_finish_fixture(const char *dir, int failures)
{
    /* This PID-scoped fixture root owns the nested shared-* directories too.
     * Keep every failed-run artifact; remove successful output recursively. */
    if (!failures)
        SB_CHECK("successful owned fixture root is fully removed", test_rm_rf_recursive(dir) == 0);
    else
        printf("snapshot_boot_seed: retained failed fixture=%s\n", dir);
    return failures;
}

static int sb_shared_bootstrap_tests(const char *dir)
{
    int failures = 0;
    enum boot_snapshot_first_outcome deferred;
    SB_CHECK("closed progress store defers snapshot preparation",
        progress_store_db() == NULL && boot_prepare_snapshot_first(NULL, NULL, &deferred).ok &&
        deferred == BOOT_SNAPSHOT_FIRST_DEFERRED);
    failures += sb_shared_guard_tests(dir);
    for (int mode = 0; mode < 5; mode++)
        failures += sb_shared_import_case(dir, mode);
    return failures;
}

#if !defined(_WIN32)
struct sb_crash_cut {
    uint8_t source_digest[32];
    uint8_t root[32];
    uint64_t count;
    int pipe_fd;
    sqlite3 *db;
    int mode;
    bool saw_reset;
};

static bool sb_file_digest(const char *path, uint8_t out[32])
{
    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0)
        return false;
    struct sha3_256_ctx ctx;
    sha3_256_init(&ctx);
    uint8_t bytes[4096];
    ssize_t n;
    while ((n = read(fd, bytes, sizeof(bytes))) != 0) {
        if (n < 0) {
            if (errno == EINTR)
                continue;
            close(fd);
            return false;
        }
        sha3_256_write(&ctx, bytes, (size_t)n);
    }
    if (close(fd) != 0)
        return false;
    sha3_256_finalize(&ctx, out);
    return true;
}

static bool sb_trace_cut_matches(const struct sb_crash_cut *cut,
    unsigned event, sqlite3_stmt *statement, const char *sql)
{
    switch (cut->mode) {
    case 0:
        return event == SQLITE_TRACE_STMT && strcmp(sql, "DETACH DATABASE snapsrc") == 0;
    case 1:
        return cut->saw_reset && event == SQLITE_TRACE_PROFILE && strcmp(sql, "COMMIT") == 0;
    case 2:
        return event == SQLITE_TRACE_STMT && strcmp(sql, "DETACH DATABASE coinssrc") == 0;
    case 3: {
        if (event != SQLITE_TRACE_STMT || strstr(sql, "DELETE FROM node_state") == NULL)
            return false;
        char *expanded = sqlite3_expanded_sql(statement);
        bool stop = expanded && strstr(expanded, "snapshot_import_pending.v1") != NULL;
        sqlite3_free(expanded);
        return stop;
    }
    default:
        return false;
    }
}

static int sb_detach_trace(unsigned event, void *opaque, void *statement, void *unused)
{
    (void)unused;
    struct sb_crash_cut *cut = opaque;
    const char *sql = sqlite3_sql(statement);
    if (!sql)
        return 0;
    if (event == SQLITE_TRACE_STMT && strcmp(sql, "DELETE FROM coins") == 0)
        cut->saw_reset = true;
    if (!sb_trace_cut_matches(cut, event, statement, sql) ||
        !sqlite3_get_autocommit(sqlite3_db_handle(statement)))
        return 0;
    /* Only inspect trace arguments here; never execute nested SQL. */
    if (write(cut->pipe_fd, cut, sizeof(*cut)) != (ssize_t)sizeof(*cut))
        _exit(5);
    for (;;)
        pause();
}

static void sb_crash_import_child(const char *dir, int pipe_fd, int mode)
{
    if (signal(SIGALRM, SIG_DFL) == SIG_ERR)
        _exit(2);
    alarm(90);
    char snapshot[600], node_path[600];
    snprintf(snapshot, sizeof(snapshot), "%s/consensus_snapshot.db", dir);
    snprintf(node_path, sizeof(node_path), "%s/node.db", dir);
    uint8_t hash[32];
    sb_tip_hash(hash);
    struct node_db ndb = {0};
    struct sb_crash_cut cut = {.pipe_fd = pipe_fd, .mode = mode};
    sqlite3 *source = NULL;
    if (!sb_build_fixture(snapshot, hash) || !sb_file_digest(snapshot, cut.source_digest) ||
        sqlite3_open_v2(snapshot, &source, SQLITE_OPEN_READONLY, NULL) != SQLITE_OK)
        _exit(3);
    utxo_commitment_sha3_compute(source, cut.root, &cut.count);
    sqlite3_close(source);
    if (cut.count != SB_UTXO_COUNT || !node_db_open(&ndb, node_path) ||
        !progress_store_open(dir) || !coins_kv_ensure_schema(progress_store_db()))
        _exit(4);
    cut.db = ndb.db;
    struct main_state ms = {0};
    main_state_init(&ms);
    seed_integrity_gate_set_node_db_for_testing(&ndb);
    if (!tip_finalize_stage_init(&ms))
        _exit(8);
    if (sqlite3_trace_v2(ndb.db, SQLITE_TRACE_STMT, sb_detach_trace, &cut) != SQLITE_OK ||
        sqlite3_trace_v2(progress_store_db(), SQLITE_TRACE_STMT | SQLITE_TRACE_PROFILE,
                         sb_detach_trace, &cut) != SQLITE_OK)
        _exit(6);
    int64_t count = 0, height = 0;
    (void)boot_import_snapshot_db(&ndb, snapshot, &count, &height, hash);
    _exit(7); /* Reaching here means the requested crash cut was never observed. */
}

static bool sb_wait_and_kill(pid_t child, int fd, struct sb_crash_cut *cut)
{
    struct pollfd pending = {.fd = fd, .events = POLLIN};
    bool ready = poll(&pending, 1, 60000) == 1 && (pending.revents & POLLIN) != 0;
    bool received = ready && read(fd, cut, sizeof(*cut)) == (ssize_t)sizeof(*cut);
    /* Reap before opening either SQLite store, including every timeout/error path. */
    int killed = kill(child, SIGKILL);
    int status = 0;
    pid_t waited;
    do {
        waited = waitpid(child, &status, 0);
    } while (waited < 0 && errno == EINTR);
    return received && killed == 0 && waited == child &&
        WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL;
}

static bool sb_cache_absent(sqlite3 *db)
{
    sqlite3_stmt *stmt = NULL;
    bool ok = sqlite3_prepare_v2(db,
        "SELECT count(*) FROM node_state WHERE key='coins_best_block'", -1, &stmt, NULL) == SQLITE_OK;
    ok = ok && sqlite3_step(stmt) == SQLITE_ROW && sqlite3_column_int64(stmt, 0) == 0;
    sqlite3_finalize(stmt);
    return ok;
}

static int sb_crash_cut_facts(struct node_db *ndb, const char *dir,
                              const struct sb_crash_cut *cut)
{
    int failures = 0;
    uint8_t root[32], digest[32];
    uint64_t count = 0;
    int64_t mirror_count = -1;
    utxo_commitment_sha3_compute(ndb->db, root, &count);
    SB_CHECK("SIGKILL cut: exact durable mirror commitment and 1200 rows",
        node_db_utxo_count_checked(ndb, &mirror_count) && mirror_count == SB_UTXO_COUNT &&
        count == cut->count && memcmp(root, cut->root, 32) == 0);
    if (cut->mode == 0)
        SB_CHECK("SIGKILL cut: best-block cache has not been written", sb_cache_absent(ndb->db));
    int32_t applied = -1;
    bool found = true;
    if (cut->mode <= 1) {
        SB_CHECK("SIGKILL cut: kernel empty, unproven, applied frontier absent",
            coins_kv_count_sqlite(progress_store_db()) == 0 &&
            !coins_kv_is_proven_authority(progress_store_db(), NULL) &&
            coins_kv_get_applied_height(progress_store_db(), &applied, &found) && !found);
    } else {
        SB_CHECK("SIGKILL cut: kernel already has exact seeded coins",
            coins_kv_count_sqlite(progress_store_db()) == SB_UTXO_COUNT &&
            coins_kv_commitment(progress_store_db(), root) == 0 &&
            memcmp(root, cut->root, 32) == 0);
    }
    char snapshot[600];
    snprintf(snapshot, sizeof(snapshot), "%s/consensus_snapshot.db", dir);
    SB_CHECK("SIGKILL cut: source snapshot bytes unchanged",
        sb_file_digest(snapshot, digest) && memcmp(digest, cut->source_digest, 32) == 0);
    return failures;
}

static int sb_terminal_authority(const uint8_t expected_root[32])
{
    int failures = 0;
    uint8_t root[32];
    int32_t applied = -1;
    SB_CHECK("restart full kernel authority agrees with committed mirror",
        coins_kv_count_sqlite(progress_store_db()) == SB_UTXO_COUNT &&
        coins_kv_commitment(progress_store_db(), root) == 0 &&
        memcmp(root, expected_root, 32) == 0 &&
        coins_kv_is_proven_authority(progress_store_db(), &applied) && applied == SB_SNAP_HEIGHT + 1);
    return failures;
}

static int sb_terminal_caches(struct node_db *ndb, const uint8_t expected_root[32])
{
    int failures = 0;
    uint8_t stamp[32], best[32], expected_best[32];
    uint64_t count = 0;
    int32_t height = -1;
    size_t n = 0;
    sb_tip_hash(expected_best);
    SB_CHECK("restart cache and commitment stamp agree",
        node_db_state_get(ndb, "coins_best_block", best, sizeof(best), &n) && n == 32 &&
        memcmp(best, expected_best, 32) == 0 &&
        utxo_commitment_sha3_load(ndb->db, stamp, &height, &count) &&
        height == SB_SNAP_HEIGHT && count == SB_UTXO_COUNT && memcmp(stamp, expected_root, 32) == 0);
    return failures;
}

static int sb_terminal_frontier(void)
{
    int failures = 0;
    static const char *const upstream[] = {
        "header_admit", "validate_headers", "body_fetch", "body_persist",
        "script_validate", "proof_validate", "utxo_apply"
    };
    for (size_t i = 0; i < sizeof(upstream) / sizeof(upstream[0]); i++)
        SB_CHECK(upstream[i], sb_cursor(progress_store_db(), upstream[i]) == SB_SNAP_HEIGHT + 1);
    int32_t hstar = -1, frontier = -1;
    progress_store_tx_lock();
    bool coherent = reducer_frontier_compute_hstar(progress_store_db(), &hstar, &frontier);
    progress_store_tx_unlock();
    SB_CHECK("restart durable frontier and H* agree with imported base",
        sb_cursor(progress_store_db(), "tip_finalize") == SB_SNAP_HEIGHT &&
        sb_trusted_base(progress_store_db()) == SB_SNAP_HEIGHT && coherent && hstar == SB_SNAP_HEIGHT);
    return failures;
}

/* app_init prepares snapshots before services initialize tip_finalize. */
static int sb_prepare_before_stage_init(struct node_db *ndb, const char *dir,
    const uint8_t expected_root[32])
{
    int failures = 0;
    tip_finalize_stage_shutdown();
    seed_integrity_gate_set_node_db_for_testing(ndb);
    enum boot_snapshot_first_outcome outcome;
    struct zcl_result prepared = boot_prepare_snapshot_first(ndb, dir, &outcome);
    SB_CHECK("cold-stage snapshot preparation completes before finalizer init",
        prepared.ok && outcome == BOOT_SNAPSHOT_FIRST_IMPORTED);
    SB_CHECK("cold-stage completion retires pending record",
        !boot_snapshot_import_pending_or_error(ndb));
    uint64_t generation = UINT64_MAX;
    SB_CHECK("cold-stage completion advances authority exactly once",
        coins_kv_get_authority_generation(progress_store_db(), &generation) && generation == 1);
    failures += sb_terminal_authority(expected_root);
    failures += sb_terminal_caches(ndb, expected_root);
    failures += sb_terminal_frontier();

    uint8_t expected_hash[32];
    sb_tip_hash(expected_hash);
    SB_CHECK("cold-stage outer transaction begins with cursor already stamped",
        sb_sql(progress_store_db(), "BEGIN IMMEDIATE"));
    SB_CHECK("cold-stage prestamped seed succeeds inside outer transaction",
        tip_finalize_stage_seed_anchor(SB_SNAP_HEIGHT, expected_hash, true));
    SB_CHECK("cold-stage prestamped seed preserves outer transaction ownership",
        sqlite3_get_autocommit(progress_store_db()) == 0);
    SB_CHECK("cold-stage outer transaction rolls back", sb_sql(progress_store_db(), "ROLLBACK"));
    failures += sb_terminal_frontier();

    sqlite3_int64 node_writes = sqlite3_total_changes64(ndb->db);
    sqlite3_int64 kernel_writes = sqlite3_total_changes64(progress_store_db());
    SB_CHECK("cold-stage repeated preparation succeeds",
        boot_prepare_snapshot_first(ndb, dir, &outcome).ok);
    SB_CHECK("cold-stage repeated preparation writes neither store",
        sqlite3_total_changes64(ndb->db) == node_writes &&
        sqlite3_total_changes64(progress_store_db()) == kernel_writes);
    SB_CHECK("cold-stage repeated preparation keeps generation one",
        coins_kv_get_authority_generation(progress_store_db(), &generation) && generation == 1);

    struct main_state ms = {0};
    main_state_init(&ms);
    SB_CHECK("finalizer initializes after cold-stage preparation", tip_finalize_stage_init(&ms));
    failures += sb_terminal_authority(expected_root);
    failures += sb_terminal_caches(ndb, expected_root);
    failures += sb_terminal_frontier();
    SB_CHECK("later finalizer init preserves authority generation",
        coins_kv_get_authority_generation(progress_store_db(), &generation) && generation == 1);
    tip_finalize_stage_shutdown();
    main_state_free(&ms);
    seed_integrity_gate_reset_for_testing();
    return failures;
}

static int sb_restart_terminal(struct node_db *ndb, const char *dir,
                               const uint8_t expected_root[32])
{
    int failures = 0;
    struct main_state ms = {0};
    main_state_init(&ms);
    seed_integrity_gate_set_node_db_for_testing(ndb);
    SB_CHECK("restart finalization stage initializes", tip_finalize_stage_init(&ms));
    enum boot_snapshot_first_outcome outcome;
    SB_CHECK("restart snapshot preparation succeeds",
        boot_prepare_snapshot_first(ndb, dir, &outcome).ok);
    struct boot_derived_coins_best derived;
    bool authority = boot_derive_coins_best(&derived);
    if (!authority)
        (void)utxo_recovery_repair_stale_cursor_from_sync_projection(ndb);
    struct coins_view_sqlite view = {0};
    bool usable = coins_view_sqlite_open(&view, ndb->db);
    if (!usable && !authority &&
        utxo_recovery_heal_torn_legacy_coins_anchor(ndb, progress_store_db(), dir))
        usable = coins_view_sqlite_open(&view, ndb->db);
    SB_CHECK("restart normal restore/repair produces usable coins view", usable);
    if (usable)
        coins_view_sqlite_close(&view);
    failures += sb_terminal_authority(expected_root);
    failures += sb_terminal_caches(ndb, expected_root);
    failures += sb_terminal_frontier();
    tip_finalize_stage_shutdown();
    main_state_free(&ms);
    seed_integrity_gate_reset_for_testing();
    return failures;
}

static int sb_crash_uninterrupted_control(const char *root, const uint8_t expected_root[32],
    bool cold_stage)
{
    int failures = 0;
    char dir[512], snapshot[600], node_path[600];
    snprintf(dir, sizeof(dir), "%s/control", root);
    snprintf(snapshot, sizeof(snapshot), "%s/consensus_snapshot.db", dir);
    snprintf(node_path, sizeof(node_path), "%s/node.db", dir);
    uint8_t hash[32];
    sb_tip_hash(hash);
    struct node_db ndb = {0};
    bool opened = sb_mkdir(dir) == 0 && sb_build_fixture(snapshot, hash) &&
        node_db_open(&ndb, node_path) && progress_store_open(dir);
    SB_CHECK("uninterrupted control opens same genuine snapshot fixture", opened);
    if (opened) {
        if (cold_stage)
            failures += sb_prepare_before_stage_init(&ndb, dir, expected_root);
        failures += sb_restart_terminal(&ndb, dir, expected_root);
    }
    progress_store_close();
    if (ndb.open)
        node_db_close(&ndb);
    return failures;
}

static int sb_pending_refusal(struct node_db *ndb, const char *dir)
{
    int failures = 0;
    sqlite3_int64 node_writes = sqlite3_total_changes64(ndb->db);
    sqlite3_int64 kernel_writes = sqlite3_total_changes64(progress_store_db());
    enum boot_snapshot_first_outcome outcome;
    struct zcl_result result = boot_prepare_snapshot_first(ndb, dir, &outcome);
    SB_CHECK("contradictory pending import refuses recovery", !result.ok);
    SB_CHECK("refused recovery performs no writes in either store",
        sqlite3_total_changes64(ndb->db) == node_writes &&
        sqlite3_total_changes64(progress_store_db()) == kernel_writes);
    return failures;
}

static int sb_pending_authority_conflicts(struct node_db *ndb, const char *dir)
{
    int failures = 0;
    uint8_t digest[32];
    sb_tip_hash(digest);
    SB_CHECK("conflicting installed marker fixture",
        boot_consensus_bundle_marker_write(dir, SB_SNAP_HEIGHT, digest));
    failures += sb_pending_refusal(ndb, dir);
    char marker[600];
    snprintf(marker, sizeof(marker), "%s/%s", dir, BOOT_CONSENSUS_BUNDLE_MARKER_NAME);
    SB_CHECK("conflicting fixture marker removed", unlink(marker) == 0);
    if (coins_kv_count_sqlite(progress_store_db()) > 0) {
        SB_CHECK("pending seeded kernel mismatch fixture",
            sb_sql(progress_store_db(), "UPDATE coins SET value=value+1"));
        failures += sb_pending_refusal(ndb, dir);
        SB_CHECK("pending seeded kernel restored",
            sb_sql(progress_store_db(), "UPDATE coins SET value=value-1"));
    }
    return failures;
}

static int sb_pending_corruption_tests(struct node_db *ndb, const char *dir)
{
    int failures = 0;
    static const char key[] = "snapshot_import_pending.v1";
    uint8_t record[97];
    size_t length = 0;
    bool saved = node_db_state_get(ndb, key, record, sizeof(record), &length) && length == 96;
    SB_CHECK("mirror commit also durably stores complete pending operation", saved);
    if (!saved)
        return failures;
    failures += sb_pending_authority_conflicts(ndb, dir);
    SB_CHECK("pending record truncation fixture",
        node_db_state_set(ndb, key, record, length - 1));
    failures += sb_pending_refusal(ndb, dir);
    SB_CHECK("pending record restored", node_db_state_set(ndb, key, record, length));
    record[0] ^= 1;
    SB_CHECK("pending record unknown version fixture",
        node_db_state_set(ndb, key, record, length));
    failures += sb_pending_refusal(ndb, dir);
    record[0] ^= 1;
    SB_CHECK("pending record version restored", node_db_state_set(ndb, key, record, length));
    record[16] ^= 1;
    SB_CHECK("pending record wrong generation fixture",
        node_db_state_set(ndb, key, record, length));
    failures += sb_pending_refusal(ndb, dir);
    record[16] ^= 1;
    SB_CHECK("pending record generation restored", node_db_state_set(ndb, key, record, length));
    SB_CHECK("pending mirror mismatch fixture",
        sqlite3_exec(ndb->db, "UPDATE utxos SET value=value+1", NULL, NULL, NULL) == SQLITE_OK);
    failures += sb_pending_refusal(ndb, dir);
    SB_CHECK("pending mirror restored",
        sqlite3_exec(ndb->db, "UPDATE utxos SET value=value-1", NULL, NULL, NULL) == SQLITE_OK);
    uint8_t old_applied[8], advanced[8];
    size_t applied_size = 0;
    bool applied_found = false;
    bool applied_saved = progress_meta_get_blob_exact(progress_store_db(),
        COINS_APPLIED_HEIGHT_KEY, old_applied, sizeof(old_applied),
        &applied_size, &applied_found) && (!applied_found || applied_size == sizeof(old_applied));
    SB_CHECK("pending applied frontier captured", applied_saved);
    if (applied_saved) {
        zcl_write_u64_le(advanced, SB_SNAP_HEIGHT + 2);
        SB_CHECK("pending advanced frontier fixture", progress_meta_set(progress_store_db(),
            COINS_APPLIED_HEIGHT_KEY, advanced, sizeof(advanced)));
        failures += sb_pending_refusal(ndb, dir);
        SB_CHECK("pending applied frontier restored",
            applied_found ? progress_meta_set(progress_store_db(), COINS_APPLIED_HEIGHT_KEY,
                old_applied, applied_size) :
                progress_meta_delete(progress_store_db(), COINS_APPLIED_HEIGHT_KEY));
    }
    char wrong_dir[600];
    snprintf(wrong_dir, sizeof(wrong_dir), "%s/unrelated-datadir", dir);
    SB_CHECK("unrelated recovery datadir fixture", sb_mkdir(wrong_dir) == 0);
    failures += sb_pending_refusal(ndb, wrong_dir);
    return failures;
}

static int sb_crashed_store_recover(struct node_db *ndb, const char *dir,
    const struct sb_crash_cut *cut)
{
    int failures = sb_crash_cut_facts(ndb, dir, cut);
    failures += sb_pending_corruption_tests(ndb, dir);
    char snapshot[600], retained[600];
    snprintf(snapshot, sizeof(snapshot), "%s/consensus_snapshot.db", dir);
    snprintf(retained, sizeof(retained), "%s/source-retained.db", dir);
    SB_CHECK("recovery source removed from discovery path", rename(snapshot, retained) == 0);
    uint64_t generation_before = UINT64_MAX, generation_after = UINT64_MAX;
    SB_CHECK("pre-recovery generation readable",
        coins_kv_get_authority_generation(progress_store_db(), &generation_before));
    if (cut->mode == 0)
        failures += sb_prepare_before_stage_init(ndb, dir, cut->root);
    failures += sb_restart_terminal(ndb, dir, cut->root);
    SB_CHECK("recovery resets authority exactly once",
        coins_kv_get_authority_generation(progress_store_db(), &generation_after) &&
        generation_before != UINT64_MAX &&
        generation_after == generation_before + (cut->mode == 0 ? 1u : 0u) &&
        generation_after == 1);
    sqlite3_int64 writes_before = sqlite3_total_changes64(progress_store_db());
    enum boot_snapshot_first_outcome repeated;
    SB_CHECK("repeated snapshot preparation succeeds",
        boot_prepare_snapshot_first(ndb, dir, &repeated).ok);
    failures += sb_terminal_authority(cut->root);
    failures += sb_terminal_caches(ndb, cut->root);
    failures += sb_terminal_frontier();
    uint64_t generation_repeated = UINT64_MAX;
    SB_CHECK("repeated recovery retains generation and kernel without writes",
        coins_kv_get_authority_generation(progress_store_db(), &generation_repeated) &&
        generation_repeated == generation_after &&
        sqlite3_total_changes64(progress_store_db()) == writes_before);
    return failures;
}

static int sb_import_sigkill_case(int mode)
{
    int failures = 0;
    SB_CHECK("SIGKILL fixture begins before any progress store opens", progress_store_db() == NULL);
    if (failures)
        return failures;
    char dir[256], node_path[600];
    char label[48];
    snprintf(label, sizeof(label), "import-sigkill-%d", mode);
    test_fmt_tmpdir(dir, sizeof(dir), "snapshot_boot_seed", label);
    int channel[2];
    if (sb_mkdir("./test-tmp") != 0 || sb_mkdir(dir) != 0 || pipe(channel) != 0)
        return 1;
    pid_t child = fork();
    if (child == 0) {
        close(channel[0]);
        sb_crash_import_child(dir, channel[1], mode);
    }
    close(channel[1]);
    struct sb_crash_cut cut = {0};
    bool killed = child > 0 && sb_wait_and_kill(child, channel[0], &cut);
    close(channel[0]);
    printf("  snapshot_boot_seed: crash cut mode=%d (mirror, reset, seed, retire)\n", mode);
    SB_CHECK("worker really SIGKILLed at requested import boundary", killed);
    /* All module initialization follows fork/reap; the worker inherits no fixture locks. */
    blocker_module_init();
    blocker_reset_for_testing();
    seed_integrity_gate_reset_for_testing();
    snprintf(node_path, sizeof(node_path), "%s/node.db", dir);
    struct node_db ndb = {0};
    bool opened = killed && node_db_open(&ndb, node_path) && progress_store_open(dir);
    SB_CHECK("crashed stores reopen only after child is reaped", opened);
    if (opened)
        failures += sb_crashed_store_recover(&ndb, dir, &cut);
    progress_store_close();
    if (ndb.open)
        node_db_close(&ndb);
    if (killed)
        failures += sb_crash_uninterrupted_control(dir, cut.root, mode == 0);
    return sb_finish_fixture(dir, failures);
}

static int sb_mirror_commit_sigkill_test(void)
{
    int failures = 0;
    for (int mode = 0; mode < 4; mode++) {
        failures += sb_import_sigkill_case(mode);
        test_reset_shared_globals();
    }
    return failures;
}
#else
static int sb_mirror_commit_sigkill_test(void) { return 0; }
#endif

int test_snapshot_boot_seed(void)
{
    int failures = sb_mirror_commit_sigkill_test();
    test_reset_shared_globals();
    printf("\n=== snapshot_boot_seed tests ===\n");

    blocker_module_init();
    blocker_reset_for_testing();
    seed_integrity_gate_reset_for_testing();

    char dir[256];
    test_fmt_tmpdir(dir, sizeof(dir), "snapshot_boot_seed", "main");
    sb_mkdir("./test-tmp");
    sb_mkdir(dir);
    failures += sb_shared_bootstrap_tests(dir);

    /* ── Build the on-disk fixture snapshot. */
    char snap_path[600];
    snprintf(snap_path, sizeof(snap_path), "%s/consensus_snapshot.db", dir);
    uint8_t tip_hash[32];
    sb_tip_hash(tip_hash);
    SB_CHECK("fixture: snapshot.db built", test_snapshot_boot_fixture_build(snap_path, tip_hash));
    {
        struct stat st;
        SB_CHECK("fixture: snapshot > 10 MiB size floor",
                 stat(snap_path, &st) == 0 &&
                 st.st_size >= (off_t)(10 * 1024 * 1024));
    }

    /* ── Fresh node.db (the running node's DB the snapshot imports INTO). */
    char ndb_path[600];
    snprintf(ndb_path, sizeof(ndb_path), "%s/node.db", dir);
    struct node_db ndb;
    bool db_ok = node_db_open(&ndb, ndb_path);
    SB_CHECK("fixture: node.db opens", db_ok);
    if (!db_ok) { blocker_reset_for_testing(); return sb_finish_fixture(dir, failures); }
    seed_integrity_gate_set_node_db_for_testing(&ndb);

    /* progress store + tip_finalize stage (the seed anchor writes cursors here). */
    SB_CHECK("fixture: progress_store opens", progress_store_open(dir));
    sqlite3 *pdb = progress_store_db();
    SB_CHECK("fixture: pdb handle", pdb != NULL);

    struct main_state ms;
    memset(&ms, 0, sizeof(ms));
    main_state_init(&ms);
    SB_CHECK("fixture: tip_finalize stage init", tip_finalize_stage_init(&ms));

    /* PRECONDITION (the "looks-synced-but-isn't" defect state we must escape):
     * a bare fresh datadir has NO reducer seed authority — coins_kv is NOT a
     * proven authority (no migration stamp) and coins_applied_height is ABSENT.
     * Prove that starting point so the post-state deltas are meaningful. */
    SB_CHECK("precond: coins_kv NOT proven-authority (no seed yet)",
             !coins_kv_is_proven_authority(pdb, NULL));
    {
        int32_t ca = 0; bool found = true;
        coins_kv_get_applied_height(pdb, &ca, &found);
        SB_CHECK("precond: coins_applied_height ABSENT", !found);
    }

    /* ── DRIVE THE REAL BOOT ENTRY POINT. */
    int64_t out_count = -1, out_height = -1;
    uint8_t out_best[32] = {0};
    int64_t progress_before = boot_progress_last_us();
    bool imported = boot_import_snapshot_db(&ndb, snap_path,
                                            &out_count, &out_height, out_best);
    SB_CHECK("import: boot_import_snapshot_db returns true", imported);
    SB_CHECK("import: SQLite work advances boot progress",
             boot_progress_last_us() > progress_before &&
             boot_progress_last_label() != NULL &&
             strcmp(boot_progress_last_label(),
                    "snapshot_import_bulk_insert") == 0);
    SB_CHECK("import: out_utxo_count == fixture count",
             out_count == SB_UTXO_COUNT);
    SB_CHECK("import: out_snap_height == snapshot height",
             out_height == SB_SNAP_HEIGHT);
    SB_CHECK("import: out_best_hash == fixture tip hash",
             memcmp(out_best, tip_hash, 32) == 0);

    /* ── POST-STATE: the seeded authority must be SELF-CONSISTENT. */

    /* coins_kv reseeded from the imported UTXOs + proven-authority stamp. */
    SB_CHECK("post: coins_kv count == imported UTXO count",
             coins_kv_count(pdb) == SB_UTXO_COUNT);
    SB_CHECK("post: coins_kv proven-authority (migration stamp set)",
             coins_kv_is_proven_authority(pdb, NULL));

    /* coins_applied_height at the snapshot next-height frame (NOT absent, NOT
     * stale) — the reducer's applied cursor now sits exactly one past tip. */
    {
        int32_t ca = -1; bool found = false;
        bool ok = coins_kv_get_applied_height(pdb, &ca, &found);
        SB_CHECK("post: coins_applied_height == snapshot height + 1",
                 ok && found && ca == SB_SNAP_HEIGHT + 1);
    }

    /* coins_best_block == the snapshot tip hash (height agreement:
     * coins_applied frame and the best-block cache describe the SAME tip). */
    {
        uint8_t cb[32] = {0}; size_t n = 0;
        bool ok = node_db_state_get(&ndb, "coins_best_block", cb, sizeof(cb), &n);
        SB_CHECK("post: coins_best_block == snapshot tip hash",
                 ok && n == 32 && memcmp(cb, tip_hash, 32) == 0);
    }

    /* Stage cursors clamped to the snapshot height (tip_finalize == H, the 8
     * upstream stages at H+1) — the reducer frontier now roots at the seed. */
    SB_CHECK("post: tip_finalize cursor == snapshot height (NOT H+1)",
             sb_cursor(pdb, "tip_finalize") == SB_SNAP_HEIGHT);
    SB_CHECK("post: utxo_apply cursor == snapshot height + 1",
             sb_cursor(pdb, "utxo_apply") == SB_SNAP_HEIGHT + 1);
    SB_CHECK("post: validate_headers cursor == snapshot height + 1",
             sb_cursor(pdb, "validate_headers") == SB_SNAP_HEIGHT + 1);
    SB_CHECK("post: reducer_trusted_base_height == snapshot height",
             sb_trusted_base(pdb) == SB_SNAP_HEIGHT);

    /* utxo_sha3 stamped over the imported set at the snapshot height. */
    {
        uint8_t expect_root[32]; uint64_t expect_count = 0;
        utxo_commitment_sha3_compute(ndb.db, expect_root, &expect_count);
        uint8_t got[32]; int32_t gh = -1; uint64_t gc = 0;
        bool ld = utxo_commitment_sha3_load(ndb.db, got, &gh, &gc);
        SB_CHECK("post: utxo_sha3 stamp present", ld);
        SB_CHECK("post: utxo_sha3 == recompute over imported set",
                 ld && memcmp(got, expect_root, 32) == 0 &&
                 gc == expect_count && gc == SB_UTXO_COUNT &&
                 gh == SB_SNAP_HEIGHT);
    }

    /* H* CLIMBED off the "pinned / looks-synced-but-isn't" state to the exact
     * imported base. The higher compiled checkpoint is not a floor here because
     * this short fixture's coin authority does not cover it. */
    {
        int32_t hs = 0, sf = 0;
        progress_store_tx_lock();
        bool ok = reducer_frontier_compute_hstar(pdb, &hs, &sf);
        progress_store_tx_unlock();
        SB_CHECK("post: H* climbed to the covered imported base",
                 ok && hs == SB_SNAP_HEIGHT && hs > 0);
    }

    /* NO stage named a blocker while seeding — the import is a clean advance,
     * never a silent stall or a named halt. */
    SB_CHECK("post: no active blocker after seed",
             blocker_count_active() == 0);

    tip_finalize_stage_shutdown();
    main_state_free(&ms);
    progress_store_close();
    seed_integrity_gate_reset_for_testing();
    node_db_close(&ndb);
    failures = sb_finish_fixture(dir, failures);

    blocker_reset_for_testing();
    return failures;
}
