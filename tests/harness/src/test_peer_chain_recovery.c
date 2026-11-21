/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0
 *
 * test_peer_chain_recovery — isolated copy-first recovery of observation history.
 * Exercises the real standalone binary against local SQLite fixtures, including
 * live WAL state and structural corruption confined to the observation b-tree. */

#if !defined(_WIN32) && !defined(_DEFAULT_SOURCE)
#define _DEFAULT_SOURCE
#endif

#include "test/test_core.h"
#include "test/host_tool_capture.h"
#include "models/database.h"
#include "services/wallet_backup_service.h"

#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#if defined(_WIN32)
#define RECOVERY_BIN "build/bin/peer_chain_recovery.exe"
#else
#define RECOVERY_BIN "build/bin/peer_chain_recovery"
#endif

struct recovery_bytes {
    unsigned char *data;
    long size;
};

static int recovery_run(const char *source, const char *destination,
                        char *out, size_t cap)
{
    const char *argv[] = {RECOVERY_BIN, source, destination, NULL};
    return test_host_tool_capture(argv, out, cap, 15000);
}

static bool recovery_exec(sqlite3 *db, const char *sql)
{
    char *error = NULL;
    int rc = sqlite3_exec(db, sql, NULL, NULL, &error);
    if (rc != SQLITE_OK)
        fprintf(stderr, "peer_chain_recovery fixture SQL failed: %s\n",
                error ? error : sqlite3_errmsg(db));
    sqlite3_free(error);
    return rc == SQLITE_OK;
}

static bool recovery_fixture(const char *path)
{
    sqlite3 *db = NULL;
    if (sqlite3_open(path, &db) != SQLITE_OK) {
        if (db) sqlite3_close(db);
        return false;
    }
    bool ok = recovery_exec(db,
        "PRAGMA page_size=4096;"
        "CREATE TABLE peer_chain_observations ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "peer_id INTEGER NOT NULL,"
        "addr TEXT NOT NULL DEFAULT '',"
        "user_agent TEXT NOT NULL DEFAULT '',"
        "version INTEGER NOT NULL DEFAULT 0,"
        "best_height INTEGER NOT NULL DEFAULT -1,"
        "tip_hash TEXT NOT NULL DEFAULT '',"
        "latency_us INTEGER NOT NULL DEFAULT 0,"
        "inbound INTEGER NOT NULL DEFAULT 0,"
        "first_seen INTEGER NOT NULL DEFAULT 0,"
        "last_seen INTEGER NOT NULL DEFAULT 0,"
        "observed_at INTEGER NOT NULL);"
        "CREATE INDEX idx_peer_chain_obs_observed_at "
        "ON peer_chain_observations(observed_at DESC);"
        "CREATE TABLE schema_migrations(version TEXT PRIMARY KEY);"
        "INSERT INTO schema_migrations VALUES('027');"
        "CREATE TABLE unrelated(id INTEGER PRIMARY KEY, value TEXT NOT NULL);"
        "INSERT INTO unrelated VALUES(1, 'survive');"
        "INSERT INTO peer_chain_observations("
        "peer_id,addr,user_agent,version,best_height,tip_hash,latency_us,"
        "inbound,first_seen,last_seen,observed_at) VALUES("
        "7,'peer','agent',70015,100,'hash',25,0,10,11,"
        "72623859790382856);");
    if (sqlite3_close(db) != SQLITE_OK) ok = false;
    return ok;
}

static bool recovery_analyze_fixture(const char *path)
{
    sqlite3 *db = NULL;
    bool ok = sqlite3_open(path, &db) == SQLITE_OK;
    if (ok) ok = recovery_exec(db,
        "CREATE TABLE unrelated_plain(value TEXT NOT NULL);"
        "INSERT INTO unrelated_plain VALUES('keep-stats');"
        "CREATE INDEX idx_unrelated_value ON unrelated(value);"
        "ANALYZE;");
    if (db && sqlite3_close(db) != SQLITE_OK) ok = false;
    return ok;
}

static bool recovery_statistics_present(sqlite3 *db, const char *table, bool *present)
{
    sqlite3_stmt *st = NULL;
    bool ok = sqlite3_prepare_v2(db,
        "SELECT 1 FROM sqlite_schema WHERE type='table' AND name=?1",
        -1, &st, NULL) == SQLITE_OK;
    if (ok) ok = sqlite3_bind_text(st, 1, table, -1, SQLITE_STATIC) == SQLITE_OK;
    int rc = ok ? sqlite3_step(st) : SQLITE_MISUSE;
    *present = rc == SQLITE_ROW;
    if (!*present && rc != SQLITE_DONE) ok = false;
    if (sqlite3_finalize(st) != SQLITE_OK) ok = false;
    return ok;
}

static bool recovery_statistics_add(sqlite3 *db, const char *statistics,
                                    const char *table, const char *index,
                                    bool table_only, int *count)
{
    char *sql = sqlite3_mprintf("SELECT count(*) FROM %s WHERE tbl=?1%s",
        statistics, table_only ? " AND idx IS NULL" : index ? " AND idx=?2" : "");
    if (!sql) return false;
    sqlite3_stmt *st = NULL;
    bool ok = sqlite3_prepare_v2(db, sql, -1, &st, NULL) == SQLITE_OK;
    if (ok) ok = sqlite3_bind_text(st, 1, table, -1, SQLITE_STATIC) == SQLITE_OK;
    if (ok && index && !table_only)
        ok = sqlite3_bind_text(st, 2, index, -1, SQLITE_STATIC) == SQLITE_OK;
    if (ok) ok = sqlite3_step(st) == SQLITE_ROW;
    if (ok) {
        *count += sqlite3_column_int(st, 0);
        ok = sqlite3_step(st) == SQLITE_DONE;
    }
    if (sqlite3_finalize(st) != SQLITE_OK) ok = false;
    sqlite3_free(sql);
    return ok;
}

static int recovery_statistics_count(const char *path, const char *table,
                                     const char *index, bool table_only)
{
    static const char *const tables[] = {
        "sqlite_stat1", "sqlite_stat2", "sqlite_stat3", "sqlite_stat4"
    };
    sqlite3 *db = NULL;
    if (sqlite3_open_v2(path, &db, SQLITE_OPEN_READONLY, NULL) != SQLITE_OK) {
        if (db) sqlite3_close(db);
        return -1;
    }
    bool ok = true;
    int count = 0;
    for (size_t i = 0; ok && i < sizeof tables / sizeof tables[0]; i++) {
        bool present = false;
        ok = recovery_statistics_present(db, tables[i], &present) &&
             (!present || recovery_statistics_add(db, tables[i], table, index,
                                                  table_only, &count));
    }
    if (sqlite3_close(db) != SQLITE_OK) ok = false;
    return ok ? count : -1;
}

static bool recovery_live_wal(const char *path, sqlite3 **writer)
{
    bool ok = sqlite3_open(path, writer) == SQLITE_OK;
    if (ok) ok = recovery_exec(*writer,
        "PRAGMA journal_mode=WAL; PRAGMA wal_autocheckpoint=0;"
        "UPDATE unrelated SET value='wal-survive' WHERE id=1;"
        "INSERT INTO peer_chain_observations("
        "peer_id,observed_at) VALUES(8,99);");
    if (!ok && *writer) {
        sqlite3_close(*writer);
        *writer = NULL;
    }
    return ok;
}

static struct recovery_bytes recovery_read(const char *path)
{
    struct recovery_bytes bytes = {NULL, -1};
    FILE *file = fopen(path, "rb");
    if (!file) return bytes;
    bool ok = fseek(file, 0, SEEK_END) == 0;
    bytes.size = ok ? ftell(file) : -1;
    if (bytes.size > 0) bytes.data = malloc((size_t)bytes.size);
    ok = bytes.size > 0 && bytes.data && fseek(file, 0, SEEK_SET) == 0 &&
         fread(bytes.data, 1, (size_t)bytes.size, file) == (size_t)bytes.size;
    if (fclose(file) != 0) ok = false;
    if (!ok) {
        free(bytes.data);
        bytes.data = NULL;
        bytes.size = -1;
    }
    return bytes;
}

static bool recovery_same_bytes(const char *path, const struct recovery_bytes *before)
{
    struct recovery_bytes after = recovery_read(path);
    bool ok = after.size == before->size && after.size > 0 &&
              memcmp(after.data, before->data, (size_t)before->size) == 0;
    free(after.data);
    return ok;
}

static bool recovery_quick_check(const char *path, bool expect_ok)
{
    sqlite3 *db = NULL;
    sqlite3_stmt *st = NULL;
    bool ok = sqlite3_open_v2(path, &db, SQLITE_OPEN_READONLY, NULL) == SQLITE_OK;
    if (ok) ok = sqlite3_prepare_v2(db, "PRAGMA quick_check(1)", -1, &st, NULL) == SQLITE_OK;
    if (ok) ok = sqlite3_step(st) == SQLITE_ROW;
    if (ok) {
        const unsigned char *text = sqlite3_column_text(st, 0);
        bool clean = text && strcmp((const char *)text, "ok") == 0;
        if (!clean)
            fprintf(stderr, "expected fixture corruption: %s\n",
                    text ? text : (const unsigned char *)"?");
        ok = clean == expect_ok;
    }
    if (st) sqlite3_finalize(st);
    if (db) sqlite3_close(db);
    return ok;
}

static bool recovery_page_location(const char *path, const char *table,
                                   int *rootpage, int *page_size)
{
    sqlite3 *db = NULL;
    sqlite3_stmt *st = NULL;
    bool ok = sqlite3_open_v2(path, &db, SQLITE_OPEN_READONLY, NULL) == SQLITE_OK;
    if (ok) ok = sqlite3_prepare_v2(db, "PRAGMA page_size", -1, &st, NULL) == SQLITE_OK;
    if (ok) ok = sqlite3_step(st) == SQLITE_ROW;
    if (ok) *page_size = sqlite3_column_int(st, 0);
    if (st) sqlite3_finalize(st);
    st = NULL;
    if (ok) ok = sqlite3_prepare_v2(db,
        "SELECT rootpage FROM sqlite_schema WHERE type='table' AND name=?1",
        -1, &st, NULL) == SQLITE_OK;
    if (ok) ok = sqlite3_bind_text(st, 1, table, -1, SQLITE_STATIC) == SQLITE_OK;
    if (ok) ok = sqlite3_step(st) == SQLITE_ROW;
    if (ok) *rootpage = sqlite3_column_int(st, 0);
    if (st) sqlite3_finalize(st);
    if (db) sqlite3_close(db);
    return ok && *rootpage > 1 && *page_size >= 512;
}

static bool recovery_corrupt_observed_at(const char *path)
{
    int rootpage = 0, page_size = 0;
    if (!recovery_page_location(path, "peer_chain_observations", &rootpage, &page_size))
        return false;
    FILE *file = fopen(path, "r+b");
    unsigned char header[7];
    bool ok = file && fseek(file, (long)(rootpage - 1) * page_size, SEEK_SET) == 0 &&
              fread(header, 1, sizeof header, file) == sizeof header &&
              header[0] == 0x0d && header[3] == 0 && header[4] == 1;
    /* A leaf cell pointer outside the page is structural b-tree corruption.
     * Dropping the leaf still succeeds because it need not decode the row. */
    ok = ok && fseek(file, (long)(rootpage - 1) * page_size + 5, SEEK_SET) == 0 &&
         fputc(0xff, file) == 0xff && fputc(0xff, file) == 0xff;
    if (file && fclose(file) != 0) ok = false;
    return ok;
}

static bool recovery_zero_observation_root(const char *path)
{
    int rootpage = 0, page_size = 0;
    if (!recovery_page_location(path, "peer_chain_observations", &rootpage, &page_size))
        return false;
    FILE *file = fopen(path, "r+b");
    unsigned char *zero = calloc(1, (size_t)page_size);
    bool ok = file && zero && fseek(file, (long)(rootpage - 1) * page_size, SEEK_SET) == 0 &&
              fwrite(zero, 1, (size_t)page_size, file) == (size_t)page_size;
    if (file && fclose(file) != 0) ok = false;
    free(zero);
    return ok;
}

static int recovery_zero_pages(const char *path)
{
    int rootpage = 0, page_size = 0;
    if (!recovery_page_location(path, "peer_chain_observations", &rootpage, &page_size))
        return -1;
    FILE *file = fopen(path, "rb");
    unsigned char *page = malloc((size_t)page_size);
    bool ok = file && page;
    int zero_pages = 0;
    while (ok) {
        size_t got = fread(page, 1, (size_t)page_size, file);
        if (got == 0) {
            if (ferror(file)) ok = false;
            break;
        }
        if (got != (size_t)page_size) {
            ok = false;
            break;
        }
        bool zero = true;
        for (int i = 0; i < page_size; i++) {
            if (page[i] != 0) {
                zero = false;
                break;
            }
        }
        if (zero) zero_pages++;
    }
    if (file && fclose(file) != 0) ok = false;
    free(page);
    return ok ? zero_pages : -1;
}

static bool recovery_corrupt_unrelated(const char *path)
{
    int rootpage = 0, page_size = 0;
    if (!recovery_page_location(path, "unrelated", &rootpage, &page_size)) return false;
    FILE *file = fopen(path, "r+b");
    bool ok = file && fseek(file, (long)(rootpage - 1) * page_size, SEEK_SET) == 0 &&
              fputc(0xff, file) == 0xff;
    if (file && fclose(file) != 0) ok = false;
    return ok;
}

static bool recovery_verify_destination(const char *path, const char *unrelated)
{
    sqlite3 *db = NULL;
    sqlite3_stmt *st = NULL;
    bool ok = recovery_quick_check(path, true) &&
              sqlite3_open_v2(path, &db, SQLITE_OPEN_READONLY, NULL) == SQLITE_OK;
    const char *sql =
        "SELECT (SELECT count(*) FROM peer_chain_observations),"
        "(SELECT value FROM unrelated WHERE id=1),"
        "(SELECT version FROM schema_migrations WHERE version='027'),"
        "(SELECT count(*) FROM sqlite_schema WHERE name IN"
        "('peer_chain_observations','idx_peer_chain_obs_observed_at'))";
    if (ok) ok = sqlite3_prepare_v2(db, sql, -1, &st, NULL) == SQLITE_OK;
    if (ok) ok = sqlite3_step(st) == SQLITE_ROW;
    if (ok) {
        const unsigned char *value = sqlite3_column_text(st, 1);
        const unsigned char *version = sqlite3_column_text(st, 2);
        ok = sqlite3_column_int(st, 0) == 0 && value && version &&
             strcmp((const char *)value, unrelated) == 0 &&
             strcmp((const char *)version, "027") == 0 &&
             sqlite3_column_int(st, 3) == 2 && sqlite3_step(st) == SQLITE_DONE;
    }
    if (st) sqlite3_finalize(st);
    if (db) sqlite3_close(db);
    return ok;
}

static bool recovery_absent(const char *path)
{
    struct stat st;
    return stat(path, &st) != 0;
}

static bool recovery_write_sentinel(const char *path)
{
    FILE *file = fopen(path, "wb");
    bool ok = file && fwrite("keep", 1, 4, file) == 4;
    if (file && fclose(file) != 0) ok = false;
    return ok;
}

/* Compare every typed cell and row in the wallet backup table set. */
static bool recovery_wallet_cells_equal(sqlite3_stmt *a, sqlite3_stmt *b, int column)
{
    int type = sqlite3_column_type(a, column);
    if (type != sqlite3_column_type(b, column)) return false;
    if (type == SQLITE_NULL) return true;
    if (type == SQLITE_INTEGER)
        return sqlite3_column_int64(a, column) == sqlite3_column_int64(b, column);
    if (type == SQLITE_FLOAT)
        return sqlite3_column_double(a, column) == sqlite3_column_double(b, column);
    const void *x = sqlite3_column_blob(a, column);
    const void *y = sqlite3_column_blob(b, column);
    int n = sqlite3_column_bytes(a, column);
    return n == sqlite3_column_bytes(b, column) && (n == 0 || (x && y && memcmp(x, y, (size_t)n) == 0));
}

static bool recovery_wallet_table_equal(sqlite3 *source, sqlite3 *dest, const char *table)
{
    sqlite3_stmt *a = NULL, *b = NULL;
    char *sql = sqlite3_mprintf("SELECT * FROM \"%w\"", table);
    bool ok = sql && sqlite3_prepare_v2(source, sql, -1, &a, NULL) == SQLITE_OK &&
              sqlite3_prepare_v2(dest, sql, -1, &b, NULL) == SQLITE_OK;
    sqlite3_free(sql);
    int rows = 0;
    if (ok) ok = sqlite3_column_count(a) == sqlite3_column_count(b);
    while (ok) {
        int x = sqlite3_step(a), y = sqlite3_step(b);
        if (x != y || (x != SQLITE_ROW && x != SQLITE_DONE)) { ok = false; break; }
        if (x == SQLITE_DONE) break;
        rows++;
        for (int i = 0; ok && i < sqlite3_column_count(a); i++)
            ok = recovery_wallet_cells_equal(a, b, i);
    }
    if (sqlite3_finalize(a) != SQLITE_OK) ok = false;
    if (sqlite3_finalize(b) != SQLITE_OK) ok = false;
    return ok && rows == 1;
}

static bool recovery_wallet_equal(sqlite3 *source, const char *path)
{
    sqlite3 *dest = NULL;
    bool ok = sqlite3_open_v2(path, &dest, SQLITE_OPEN_READONLY, NULL) == SQLITE_OK;
    size_t count = 0;
    const char *const *tables = wallet_backup_tables(&count);
    if (count != 10) ok = false;
    for (size_t i = 0; ok && i < count; i++)
        ok = recovery_wallet_table_equal(source, dest, tables[i]);
    if (dest && sqlite3_close(dest) != SQLITE_OK) ok = false;
    return ok;
}

static bool recovery_wallet_integrity(const char *path)
{
    sqlite3 *db = NULL;
    sqlite3_stmt *s = NULL;
    bool ok = sqlite3_open_v2(path, &db, SQLITE_OPEN_READONLY, NULL) == SQLITE_OK &&
              sqlite3_prepare_v2(db, "PRAGMA integrity_check", -1, &s, NULL) == SQLITE_OK &&
              sqlite3_step(s) == SQLITE_ROW && sqlite3_column_text(s, 0) &&
              strcmp((const char *)sqlite3_column_text(s, 0), "ok") == 0 && sqlite3_step(s) == SQLITE_DONE;
    if (s && sqlite3_finalize(s) != SQLITE_OK) ok = false;
    s = NULL;
    if (ok) ok = sqlite3_prepare_v2(db, "PRAGMA foreign_key_check", -1, &s, NULL) == SQLITE_OK &&
                 sqlite3_column_count(s) == 4 && sqlite3_step(s) == SQLITE_DONE;
    if (s && sqlite3_finalize(s) != SQLITE_OK) ok = false;
    if (db && sqlite3_close(db) != SQLITE_OK) ok = false;
    return ok;
}

static bool recovery_wallet_peer_empty(const char *path)
{
    sqlite3 *db = NULL;
    sqlite3_stmt *s = NULL;
    bool ok = sqlite3_open_v2(path, &db, SQLITE_OPEN_READONLY, NULL) == SQLITE_OK &&
              sqlite3_prepare_v2(db, "SELECT count(*) FROM peer_chain_observations", -1, &s, NULL) == SQLITE_OK &&
              sqlite3_step(s) == SQLITE_ROW && sqlite3_column_int64(s, 0) == 0 && sqlite3_step(s) == SQLITE_DONE;
    if (sqlite3_finalize(s) != SQLITE_OK) ok = false;
    if (db && sqlite3_close(db) != SQLITE_OK) ok = false;
    return ok;
}

static bool recovery_wallet_seed_fixture(sqlite3 *db)
{
    return recovery_exec(db,
        "INSERT INTO wallet_keys(pubkey_hash,pubkey,privkey,compressed,created_at) VALUES(zeroblob(20),x'010002',x'030004',1,11);"
        "INSERT INTO wallet_keypool(pubkey_hash,generation) VALUES(zeroblob(20),7);"
        "INSERT INTO wallet_key_encryption(id,wrapped_dek) VALUES(1,x'050006');"
        "INSERT INTO wallet_seed(id,seed,next_child) VALUES(1,x'070008090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425',42);"
        "INSERT INTO wallet_watch_only(address_hash,address,created_at) VALUES(x'010002', 'synthetic', 37);"
        "INSERT INTO wallet_scripts(script_hash,redeem_script) VALUES(x'09000a',x'0b000c');"
        "INSERT INTO wallet_sapling_keys(ivk,xsk,xfvk,diversifier,pk_d,child_index,address) VALUES(x'0d000e',x'0f0010',x'110012',x'130014',x'150016',3,'synthetic');"
        "INSERT INTO wallet_transactions(txid,raw_tx,time_received,from_me) VALUES(x'170018',x'19001a',19,1);"
        "INSERT INTO wallet_utxos(txid,vout,value,address_hash,script,height) VALUES(x'170018',0,23,x'1b001c',x'1d001e',5);"
        "INSERT INTO wallet_sapling_notes(txid,output_index,value,rcm,memo,ivk,diversifier,pk_d,cm,nullifier,witness_data,witness_height) VALUES(x'1f0020',0,29,x'210022',x'230024',x'0d000e',x'130014',x'150016',x'250026',x'270028',x'29002a',5);");
}

static int test_peer_chain_recovery_wallet_wal(void)
{
    int failures = 0;
    char dir[4096], source[4608], destination[4608], wal[4700], out[4096] = {0};
    struct node_db ndb = {0};
    sqlite3 *published = NULL, *writer = NULL;
    test_make_tmpdir(dir, sizeof(dir), "peer_chain_recovery", "wallet-wal");
    TEST("peer_chain_recovery: published WAL snapshot preserves all typed wallet rows") {
        ASSERT(snprintf(source, sizeof(source), "%s/source.db", dir) > 0);
        ASSERT(snprintf(destination, sizeof(destination), "%s/recovered.db", dir) > 0);
        ASSERT(snprintf(wal, sizeof(wal), "%s-wal", source) > 0);
        ASSERT(node_db_open(&ndb, source));
        ASSERT(recovery_wallet_seed_fixture(ndb.db));
        ASSERT(recovery_exec(ndb.db, "INSERT INTO peer_chain_observations(peer_id,observed_at) VALUES(8,99)"));
        ASSERT(recovery_exec(ndb.db, "PRAGMA wal_checkpoint(TRUNCATE);"));
        node_db_close(&ndb);
        ASSERT(recovery_zero_observation_root(source));
        ASSERT(recovery_quick_check(source, false));
        ASSERT(sqlite3_open(source, &writer) == SQLITE_OK);
        ASSERT(recovery_exec(writer, "PRAGMA wal_autocheckpoint=0;"));
        ASSERT(recovery_exec(writer, "UPDATE wallet_seed SET next_child=43 WHERE id=1; UPDATE wallet_sapling_notes SET witness_data=x'2b002c',witness_height=6"));
        struct stat wal_stat;
        ASSERT(stat(wal, &wal_stat) == 0 && wal_stat.st_size > 0);
        ASSERT(recovery_run(source, destination, out, sizeof(out)) == 0);
        ASSERT(strstr(out, "pre-recovery quick_check: ok") == NULL);
        ASSERT(strstr(out, "pre-recovery quick_check:") != NULL);
        ASSERT(recovery_wallet_integrity(destination));
        ASSERT(recovery_wallet_peer_empty(destination));
        ASSERT(recovery_wallet_equal(writer, destination));
        ASSERT(sqlite3_open(destination, &published) == SQLITE_OK);
        ASSERT(recovery_exec(published, "UPDATE wallet_sapling_notes SET witness_data=x'2b002d'"));
        ASSERT(sqlite3_close(published) == SQLITE_OK);
        published = NULL;
        ASSERT(!recovery_wallet_equal(writer, destination));
        PASS();
    } _test_next:;
    if (published) sqlite3_close(published);
    if (ndb.open) node_db_close(&ndb);
    if (writer) sqlite3_close(writer);
    (void)test_rm_rf_recursive(dir);
    return failures;
}

static int test_peer_chain_recovery_clean_wal(void)
{
    int failures = 0;
    char dir[4096], source[4608], destination[4608], temporary[4608], out[4096] = {0};
    sqlite3 *writer = NULL;
    test_make_tmpdir(dir, sizeof(dir), "peer_chain_recovery", "clean");
    TEST("peer_chain_recovery: live WAL copy recovers cleanly and preserves source") {
        ASSERT(snprintf(source, sizeof(source), "%s/source.db", dir) > 0);
        ASSERT(snprintf(destination, sizeof(destination), "%s/recovered.db", dir) > 0);
        ASSERT(snprintf(temporary, sizeof(temporary), "%s.peer_chain_recovery.tmp",
                        destination) > 0);
        ASSERT(recovery_fixture(source));
        ASSERT(recovery_live_wal(source, &writer));
        struct stat wal;
        char wal_path[4608];
        ASSERT(snprintf(wal_path, sizeof(wal_path), "%s-wal", source) > 0);
        ASSERT(stat(wal_path, &wal) == 0 && wal.st_size > 0);
        struct recovery_bytes before = recovery_read(source);
        ASSERT(before.data != NULL);
        ASSERT(recovery_run(source, destination, out, sizeof(out)) == 0);
        ASSERT(strstr(out, "pre-recovery quick_check: ok") != NULL);
        ASSERT(strstr(out, "final quick_check: ok") != NULL);
        ASSERT(recovery_same_bytes(source, &before));
        ASSERT(recovery_verify_destination(destination, "wal-survive"));
        ASSERT(recovery_absent(temporary));
        free(before.data);
        PASS();
    } _test_next:;
    if (writer) sqlite3_close(writer);
    (void)test_rm_rf_recursive(dir);
    return failures;
}

static int test_peer_chain_recovery_corrupt_observation(void)
{
    int failures = 0;
    char dir[4096], source[4608], destination[4608], out[4096] = {0};
    test_make_tmpdir(dir, sizeof(dir), "peer_chain_recovery", "corrupt");
    TEST("peer_chain_recovery: observation-only corruption resets to a clean empty table") {
        ASSERT(snprintf(source, sizeof(source), "%s/source.db", dir) > 0);
        ASSERT(snprintf(destination, sizeof(destination), "%s/recovered.db", dir) > 0);
        ASSERT(recovery_fixture(source));
        ASSERT(recovery_corrupt_observed_at(source));
        ASSERT(recovery_quick_check(source, false));
        struct recovery_bytes before = recovery_read(source);
        ASSERT(before.data != NULL);
        ASSERT(recovery_run(source, destination, out, sizeof(out)) == 0);
        ASSERT(strstr(out, "pre-recovery quick_check: ok") == NULL);
        ASSERT(strstr(out, "pre-recovery quick_check:") != NULL);
        ASSERT(strstr(out, "final quick_check: ok") != NULL);
        ASSERT(recovery_same_bytes(source, &before));
        ASSERT(recovery_verify_destination(destination, "survive"));
        free(before.data);
        PASS();
    } _test_next:;
    (void)test_rm_rf_recursive(dir);
    return failures;
}

static int test_peer_chain_recovery_zero_root(void)
{
    int failures = 0;
    char dir[4096], source[4608], destination[4608], out[4096] = {0};
    test_make_tmpdir(dir, sizeof(dir), "peer_chain_recovery", "zero-root");
    TEST("peer_chain_recovery: an all-zero 4KiB observation root is fully rebuilt") {
        ASSERT(snprintf(source, sizeof(source), "%s/source.db", dir) > 0);
        ASSERT(snprintf(destination, sizeof(destination), "%s/recovered.db", dir) > 0);
        ASSERT(recovery_fixture(source));
        ASSERT(recovery_zero_observation_root(source));
        ASSERT(recovery_zero_pages(source) == 1);
        ASSERT(recovery_quick_check(source, false));
        struct recovery_bytes before = recovery_read(source);
        ASSERT(before.data != NULL);
        ASSERT(recovery_run(source, destination, out, sizeof(out)) == 0);
        ASSERT(strstr(out, "pre-recovery quick_check: ok") == NULL);
        ASSERT(strstr(out, "final quick_check: ok") != NULL);
        ASSERT(recovery_same_bytes(source, &before));
        ASSERT(recovery_verify_destination(destination, "survive"));
        ASSERT(recovery_zero_pages(destination) == 0);
        free(before.data);
        PASS();
    } _test_next:;
    (void)test_rm_rf_recursive(dir);
    return failures;
}

static int test_peer_chain_recovery_statistics(void)
{
    int failures = 0;
    char dir[4096], source[4608], destination[4608], out[4096] = {0};
    test_make_tmpdir(dir, sizeof(dir), "peer_chain_recovery", "statistics");
    TEST("peer_chain_recovery: recovery clears only observation ANALYZE statistics") {
        ASSERT(snprintf(source, sizeof(source), "%s/source.db", dir) > 0);
        ASSERT(snprintf(destination, sizeof(destination), "%s/recovered.db", dir) > 0);
        ASSERT(recovery_fixture(source));
        ASSERT(recovery_analyze_fixture(source));
        int observation_stats = recovery_statistics_count(
            source, "peer_chain_observations", NULL, false);
        int observation_index_stats = recovery_statistics_count(
            source, "peer_chain_observations", "idx_peer_chain_obs_observed_at", false);
        int unrelated_table_stats = recovery_statistics_count(
            source, "unrelated_plain", NULL, true);
        int unrelated_index_stats = recovery_statistics_count(
            source, "unrelated", "idx_unrelated_value", false);
        ASSERT(observation_stats > 0 && observation_index_stats > 0);
        ASSERT(unrelated_table_stats > 0 && unrelated_index_stats > 0);
        ASSERT(recovery_corrupt_observed_at(source));
        ASSERT(recovery_quick_check(source, false));
        struct recovery_bytes before = recovery_read(source);
        ASSERT(before.data != NULL);
        ASSERT(recovery_run(source, destination, out, sizeof(out)) == 0);
        ASSERT(strstr(out, "final quick_check: ok") != NULL);
        ASSERT(recovery_same_bytes(source, &before));
        ASSERT(recovery_verify_destination(destination, "survive"));
        ASSERT(recovery_statistics_count(
            destination, "peer_chain_observations", NULL, false) == 0);
        ASSERT(recovery_statistics_count(
            destination, "unrelated_plain", NULL, true) == unrelated_table_stats);
        ASSERT(recovery_statistics_count(
            destination, "unrelated", "idx_unrelated_value", false) == unrelated_index_stats);
        free(before.data);
        PASS();
    } _test_next:;
    (void)test_rm_rf_recursive(dir);
    return failures;
}

static int test_peer_chain_recovery_residual_corruption(void)
{
    int failures = 0;
    char dir[4096], source[4608], destination[4608], temporary[4608], out[4096] = {0};
    test_make_tmpdir(dir, sizeof(dir), "peer_chain_recovery", "residual");
    TEST("peer_chain_recovery: unrelated residual corruption publishes nothing") {
        ASSERT(snprintf(source, sizeof(source), "%s/source.db", dir) > 0);
        ASSERT(snprintf(destination, sizeof(destination), "%s/recovered.db", dir) > 0);
        ASSERT(snprintf(temporary, sizeof(temporary), "%s.peer_chain_recovery.tmp",
                        destination) > 0);
        ASSERT(recovery_fixture(source));
        ASSERT(recovery_corrupt_unrelated(source));
        ASSERT(recovery_quick_check(source, false));
        struct recovery_bytes before = recovery_read(source);
        ASSERT(before.data != NULL);
        ASSERT(recovery_run(source, destination, out, sizeof(out)) == 1);
        ASSERT(strstr(out, "final quick_check: ok") == NULL);
        ASSERT(recovery_same_bytes(source, &before));
        ASSERT(recovery_absent(destination));
        ASSERT(recovery_absent(temporary));
        free(before.data);
        PASS();
    } _test_next:;
    (void)test_rm_rf_recursive(dir);
    return failures;
}

static int test_peer_chain_recovery_refusals(void)
{
    int failures = 0;
    char dir[4096], source[4608], destination[4608], temporary[4608], out[2048] = {0};
    test_make_tmpdir(dir, sizeof(dir), "peer_chain_recovery", "refuse");
    TEST("peer_chain_recovery: aliases, destinations, and temporary files never clobber") {
        ASSERT(snprintf(source, sizeof(source), "%s/source.db", dir) > 0);
        ASSERT(snprintf(destination, sizeof(destination), "%s/recovered.db", dir) > 0);
        ASSERT(snprintf(temporary, sizeof(temporary), "%s.peer_chain_recovery.tmp",
                        destination) > 0);
        ASSERT(recovery_fixture(source));
        struct recovery_bytes before = recovery_read(source);
        ASSERT(before.data != NULL);
        ASSERT(recovery_write_sentinel(destination));
        ASSERT(recovery_run(source, destination, out, sizeof(out)) == 1);
        struct recovery_bytes sentinel = { (unsigned char *)"keep", 4 };
        ASSERT(recovery_same_bytes(destination, &sentinel));
        ASSERT(recovery_same_bytes(source, &before));
        ASSERT(remove(destination) == 0);
        ASSERT(recovery_write_sentinel(temporary));
        ASSERT(recovery_run(source, destination, out, sizeof(out)) == 1);
        ASSERT(recovery_same_bytes(temporary, &sentinel));
        ASSERT(recovery_absent(destination));
        ASSERT(recovery_run(source, source, out, sizeof(out)) == 1);
        ASSERT(recovery_same_bytes(source, &before));
        free(before.data);
        PASS();
    } _test_next:;
    (void)test_rm_rf_recursive(dir);
    return failures;
}

static int test_peer_chain_recovery_destination_sidecars(void)
{
    int failures = 0;
    char dir[4096], source[4608], destination[4608], temporary[4608], out[2048] = {0};
    test_make_tmpdir(dir, sizeof(dir), "peer_chain_recovery", "sidecars");
    TEST("peer_chain_recovery: destination journal, WAL, and SHM files are never clobbered") {
        ASSERT(snprintf(source, sizeof(source), "%s/source.db", dir) > 0);
        ASSERT(snprintf(destination, sizeof(destination), "%s/recovered.db", dir) > 0);
        ASSERT(snprintf(temporary, sizeof(temporary), "%s.peer_chain_recovery.tmp",
                        destination) > 0);
        ASSERT(recovery_fixture(source));
        struct recovery_bytes before = recovery_read(source);
        struct recovery_bytes sentinel = { (unsigned char *)"keep", 4 };
        ASSERT(before.data != NULL);
        static const char *const suffixes[] = {"-journal", "-wal", "-shm"};
        for (size_t i = 0; i < sizeof suffixes / sizeof suffixes[0]; i++) {
            char sidecar[4608];
            ASSERT(snprintf(sidecar, sizeof(sidecar), "%s%s", destination, suffixes[i]) > 0);
            ASSERT(recovery_write_sentinel(sidecar));
            ASSERT(recovery_run(source, destination, out, sizeof(out)) == 1);
            ASSERT(recovery_same_bytes(sidecar, &sentinel));
            ASSERT(recovery_absent(destination));
            ASSERT(recovery_absent(temporary));
            ASSERT(recovery_same_bytes(source, &before));
            ASSERT(remove(sidecar) == 0);
        }
        free(before.data);
        PASS();
    } _test_next:;
    (void)test_rm_rf_recursive(dir);
    return failures;
}

static int test_peer_chain_recovery_unlink_after_publish(void)
{
    int failures = 0;
#if defined(__linux__)
    char dir[4096], source[4608], destination[4608], temporary[4608], out[4096] = {0};
    test_make_tmpdir(dir, sizeof(dir), "peer_chain_recovery", "unlink");
    TEST("peer_chain_recovery: post-publication unlink failure preserves success and destination") {
        ASSERT(snprintf(source, sizeof(source), "%s/source.db", dir) > 0);
        ASSERT(snprintf(destination, sizeof(destination), "%s/recovered.db", dir) > 0);
        ASSERT(snprintf(temporary, sizeof(temporary), "%s.peer_chain_recovery.tmp",
                        destination) > 0);
        ASSERT(recovery_fixture(source));
        struct recovery_bytes before = recovery_read(source);
        ASSERT(before.data != NULL);
        ASSERT(setenv("LD_PRELOAD", "build/fixtures/peer_chain_recovery_unlink_fault.so", 1) == 0);
        ASSERT(setenv("ZCL_TEST_PEER_RECOVERY_UNLINK", temporary, 1) == 0);
        ASSERT(recovery_run(source, destination, out, sizeof(out)) == 0);
        ASSERT(strstr(out, "final quick_check: ok") != NULL);
        ASSERT(recovery_same_bytes(source, &before));
        ASSERT(recovery_verify_destination(destination, "survive"));
        struct stat destination_stat, temporary_stat;
        ASSERT(stat(destination, &destination_stat) == 0);
        ASSERT(stat(temporary, &temporary_stat) == 0);
        ASSERT(destination_stat.st_dev == temporary_stat.st_dev &&
               destination_stat.st_ino == temporary_stat.st_ino);
        free(before.data);
        PASS();
    } _test_next:;
    (void)unsetenv("LD_PRELOAD");
    (void)unsetenv("ZCL_TEST_PEER_RECOVERY_UNLINK");
    (void)test_rm_rf_recursive(dir);
#else
    TEST("peer_chain_recovery: post-publication unlink failure preserves success and destination") {
        printf("not applicable (Linux LD_PRELOAD fault; Windows publication has no unlink step)\n");
    }
#endif
    return failures;
}

static int test_peer_chain_recovery_temporary_sync_failure(void)
{
    int failures = 0;
#if defined(__linux__)
    char dir[4096], source[4608], destination[4608], temporary[4608];
    char out[4096] = {0};
    test_make_tmpdir(dir, sizeof(dir), "peer_chain_recovery", "temporary-sync");
    TEST("peer_chain_recovery: temporary sync failure prevents publication") {
        ASSERT(snprintf(source, sizeof(source), "%s/source.db", dir) > 0);
        ASSERT(snprintf(destination, sizeof(destination), "%s/recovered.db", dir) > 0);
        ASSERT(snprintf(temporary, sizeof(temporary), "%s.peer_chain_recovery.tmp", destination) > 0);
        ASSERT(recovery_fixture(source));
        struct recovery_bytes before = recovery_read(source);
        ASSERT(before.data != NULL);
        ASSERT(setenv("LD_PRELOAD", "build/fixtures/peer_chain_recovery_unlink_fault.so", 1) == 0);
        ASSERT(setenv("ZCL_TEST_PEER_RECOVERY_FSYNC_DIR", temporary, 1) == 0);
        const char *argv[] = {RECOVERY_BIN, source, destination, NULL};
        struct zcl_spawn_evidence evidence;
        ASSERT(zcl_spawn_capture_evidence(argv, out, sizeof(out), 15000, &evidence) == 1);
        char error[ZCL_SPAWN_EVIDENCE_TAIL + 1];
        ASSERT(evidence.stderr_complete && evidence.stderr_len < sizeof(error));
        memcpy(error, evidence.stderr_tail, evidence.stderr_len);
        error[evidence.stderr_len] = '\0';
        ASSERT(strstr(error, "recovered file sync or close failed") != NULL);
        ASSERT(recovery_same_bytes(source, &before));
        ASSERT(recovery_absent(destination));
        ASSERT(recovery_absent(temporary));
        free(before.data);
        PASS();
    } _test_next:;
    (void)unsetenv("LD_PRELOAD");
    (void)unsetenv("ZCL_TEST_PEER_RECOVERY_FSYNC_DIR");
    (void)test_rm_rf_recursive(dir);
#else
    TEST("peer_chain_recovery: temporary sync failure prevents publication") {
        printf("not applicable (Linux LD_PRELOAD sync fault)\n");
    }
#endif
    return failures;
}

static int test_peer_chain_recovery_directory_sync_after_publish(bool unsupported)
{
    int failures = 0;
    const char *label = unsupported
        ? "peer_chain_recovery: unsupported directory sync withholds success"
        : "peer_chain_recovery: parent sync failure retains destination without success";
#if defined(__linux__)
    char dir[4096], canonical_dir[4096], source[4608], destination[4608];
    char temporary[4608], out[4096] = {0};
    test_make_tmpdir(dir, sizeof(dir), "peer_chain_recovery", "directory-sync");
    TEST(label) {
        ASSERT(snprintf(source, sizeof(source), "%s/source.db", dir) > 0);
        ASSERT(snprintf(destination, sizeof(destination), "%s/recovered.db", dir) > 0);
        ASSERT(snprintf(temporary, sizeof(temporary), "%s.peer_chain_recovery.tmp",
                        destination) > 0);
        ASSERT(realpath(dir, canonical_dir) != NULL);
        ASSERT(recovery_fixture(source));
        struct recovery_bytes before = recovery_read(source);
        ASSERT(before.data != NULL);
        ASSERT(setenv("LD_PRELOAD", "build/fixtures/peer_chain_recovery_unlink_fault.so", 1) == 0);
        ASSERT(setenv("ZCL_TEST_PEER_RECOVERY_FSYNC_DIR", canonical_dir, 1) == 0);
        if (unsupported) ASSERT(setenv("ZCL_TEST_PEER_RECOVERY_FSYNC_EINVAL", "1", 1) == 0);
        const char *argv[] = {RECOVERY_BIN, source, destination, NULL};
        struct zcl_spawn_evidence evidence;
        ASSERT(zcl_spawn_capture_evidence(argv, out, sizeof(out), 15000, &evidence) == 1);
        char error[ZCL_SPAWN_EVIDENCE_TAIL + 1];
        ASSERT(evidence.stderr_complete && evidence.stderr_len < sizeof(error));
        memcpy(error, evidence.stderr_tail, evidence.stderr_len);
        error[evidence.stderr_len] = '\0';
        ASSERT(strstr(error, "parent directory sync failed") != NULL);
        ASSERT(strstr(out, "published recovered copy:") == NULL);
        ASSERT(recovery_same_bytes(source, &before));
        ASSERT(recovery_verify_destination(destination, "survive"));
        ASSERT(recovery_absent(temporary));
        free(before.data);
        PASS();
    } _test_next:;
    (void)unsetenv("LD_PRELOAD");
    (void)unsetenv("ZCL_TEST_PEER_RECOVERY_FSYNC_DIR");
    (void)unsetenv("ZCL_TEST_PEER_RECOVERY_FSYNC_EINVAL");
    (void)test_rm_rf_recursive(dir);
#else
    TEST(label) {
        printf("not applicable (Linux LD_PRELOAD directory fault)\n");
    }
#endif
    return failures;
}

#if defined(__linux__)
static bool recovery_prepare_live_writes(const char *source, bool wal)
{
    if (!recovery_fixture(source)) return false;
    sqlite3 *db = NULL;
    bool ok = sqlite3_open(source, &db) == SQLITE_OK;
    if (ok && wal) ok = recovery_exec(db, "PRAGMA journal_mode=WAL");
    if (ok) ok = recovery_exec(db, "INSERT INTO unrelated VALUES(2, hex(zeroblob(600000)))");
    if (db && sqlite3_close(db) != SQLITE_OK) ok = false;
    return ok;
}

static int test_peer_chain_recovery_live_writes(void)
{
    int failures = 0;
    char dir[4096], source[4608], dest[4608], tmp[4700], out[4096];
    test_make_tmpdir(dir, sizeof(dir), "peer_chain_recovery", "active");
    const char *modes[] = { "wal", "stall" };
    for (int i = 0; i < 2; i++) {
        out[0] = 0;
        snprintf(source, sizeof(source), "%s/source%d.db", dir, i);
        snprintf(dest, sizeof(dest), "%s/dest%d.db", dir, i);
        snprintf(tmp, sizeof(tmp), "%s.peer_chain_recovery.tmp", dest);
        bool ok = recovery_prepare_live_writes(source, i == 0);
        const char *argv[] = { "build/fixtures/peer_chain_recovery_snapshot", modes[i], source, dest, NULL };
        int rc = ok ? test_host_tool_capture(argv, out, sizeof(out), 15000) : -1;
        if (i == 0) {
            bool snapshot_ok = rc == 0 && recovery_verify_destination(dest, "survive");
            printf("peer_chain_recovery: WAL snapshot survives concurrent commits... %s\n",
                   snapshot_ok ? "OK" : "FAIL");
            if (!snapshot_ok) failures++;
        } else {
            bool failed_cleanly = rc == 0 && strstr(out, "repeated restarts reached stall deadline") &&
                                  recovery_absent(dest) && recovery_absent(tmp);
            printf("peer_chain_recovery: rollback restarts stop without publication... %s\n",
                   failed_cleanly ? "OK" : "FAIL");
            if (!failed_cleanly) { fprintf(stderr, "fixture rc=%d output=%s\n", rc, out); failures++; }
        }
    }
    test_rm_rf_recursive(dir);
    return failures;
}
#endif

static bool recovery_source_fk_valid(const char *path, bool observation)
{
    sqlite3 *db = NULL;
    sqlite3_stmt *st = NULL;
    bool ok = sqlite3_open_v2(path, &db, SQLITE_OPEN_READONLY, NULL) == SQLITE_OK;
    const char *sql = observation ?
        "SELECT count(*) FROM dependent JOIN peer_chain_observations ON dependent.ref=peer_chain_observations.id" :
        "SELECT count(*) FROM dependent JOIN unrelated ON dependent.ref=unrelated.id";
    if (ok) ok = sqlite3_prepare_v2(db, sql, -1, &st, NULL) == SQLITE_OK;
    if (ok) ok = sqlite3_step(st) == SQLITE_ROW && sqlite3_column_int(st, 0) == 1;
    if (st && sqlite3_finalize(st) != SQLITE_OK) ok = false;
    st = NULL;
    if (ok) ok = sqlite3_prepare_v2(db, "SELECT 1 FROM pragma_foreign_key_check LIMIT 1", -1, &st, NULL) == SQLITE_OK;
    if (ok) ok = sqlite3_step(st) == SQLITE_DONE;
    if (st && sqlite3_finalize(st) != SQLITE_OK) ok = false;
    if (db && sqlite3_close(db) != SQLITE_OK) ok = false;
    return ok;
}

static bool recovery_prepare_foreign_keys(const char *source, bool orphan)
{
    if (!recovery_fixture(source)) return false;
    sqlite3 *db = NULL;
    bool ok = sqlite3_open(source, &db) == SQLITE_OK;
    const char *sql = orphan ?
        "PRAGMA foreign_keys=ON; CREATE TABLE dependent(id INTEGER PRIMARY KEY, ref INTEGER REFERENCES peer_chain_observations(id)); INSERT INTO dependent VALUES(1,1);" :
        "PRAGMA foreign_keys=ON; CREATE TABLE dependent(id INTEGER PRIMARY KEY, ref INTEGER REFERENCES unrelated(id)); INSERT INTO dependent VALUES(1,1);";
    if (ok) ok = recovery_exec(db, sql);
    if (db && sqlite3_close(db) != SQLITE_OK) ok = false;
    return ok && recovery_source_fk_valid(source, orphan);
}

static bool recovery_fk_result(bool orphan, int rc, const char *destination,
                               const char *temporary)
{
    if (orphan)
        return rc != 0 && recovery_absent(destination) && recovery_absent(temporary);
    return rc == 0 && recovery_verify_destination(destination, "survive") &&
           recovery_source_fk_valid(destination, false);
}

static int test_peer_chain_recovery_foreign_keys(void)
{
    int failures = 0;
    char dir[4096], source[4608], destination[4608], temporary[4700], out[4096];
    test_make_tmpdir(dir, sizeof(dir), "peer_chain_recovery", "foreign-keys");
    for (int orphan = 0; orphan < 2; orphan++) {
        snprintf(source, sizeof(source), "%s/source%d.db", dir, orphan);
        snprintf(destination, sizeof(destination), "%s/dest%d.db", dir, orphan);
        snprintf(temporary, sizeof(temporary), "%s.peer_chain_recovery.tmp", destination);
        bool ok = recovery_prepare_foreign_keys(source, orphan != 0);
        struct recovery_bytes before = recovery_read(source);
        ok = ok && before.data != NULL;
        int rc = ok ? recovery_run(source, destination, out, sizeof(out)) : -1;
        bool result = ok && recovery_same_bytes(source, &before) &&
                      recovery_source_fk_valid(source, orphan != 0);
        result = result && recovery_fk_result(orphan != 0, rc, destination, temporary);
        printf("peer_chain_recovery: %s foreign keys... %s\n",
               orphan ? "reject orphaned" : "preserve clean", result ? "OK" : "FAIL");
        if (!result) failures++;
        free(before.data);
    }
    test_rm_rf_recursive(dir);
    return failures;
}

int test_peer_chain_recovery(void)
{
    int failures = 0;
    struct stat st;
    if (stat(RECOVERY_BIN, &st) != 0 || (st.st_mode & S_IXUSR) == 0) {
        fprintf(stderr, "peer_chain_recovery: required %s missing "
                        "(run: make peer_chain_recovery)\n", RECOVERY_BIN);
        return 1;
    }
#if defined(__linux__)
    if (stat("build/fixtures/peer_chain_recovery_unlink_fault.so", &st) != 0) {
        fprintf(stderr, "peer_chain_recovery: required unlink fault fixture missing "
                        "(run: make peer-chain-recovery-unlink-fault)\n");
        return 1;
    }
#endif
#if defined(__linux__)
    const char *root_args[] = {"build/fixtures/peer_chain_recovery_snapshot", "roots", NULL};
    char root_result[256] = {0};
    if (test_host_tool_capture(root_args, root_result, sizeof(root_result), 15000) != 0) {
        fprintf(stderr, "peer_chain_recovery: root ownership fixture failed: %s\n", root_result);
        failures++;
    }
    failures += test_peer_chain_recovery_live_writes();
#endif
    failures += test_peer_chain_recovery_clean_wal();
    failures += test_peer_chain_recovery_wallet_wal();
    failures += test_peer_chain_recovery_foreign_keys();
    failures += test_peer_chain_recovery_corrupt_observation();
    failures += test_peer_chain_recovery_zero_root();
    failures += test_peer_chain_recovery_statistics();
    failures += test_peer_chain_recovery_residual_corruption();
    failures += test_peer_chain_recovery_refusals();
    failures += test_peer_chain_recovery_destination_sidecars();
    failures += test_peer_chain_recovery_unlink_after_publish();
    failures += test_peer_chain_recovery_temporary_sync_failure();
    failures += test_peer_chain_recovery_directory_sync_after_publish(false);
    failures += test_peer_chain_recovery_directory_sync_after_publish(true);
    return failures;
}
