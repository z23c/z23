/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Regression tests for database.c migration machinery.
 *
 * These tests guard the class of silent-failure bugs that the v2→v18
 * migration block previously hid: if a CREATE TABLE or ALTER TABLE
 * failed inside `node_db_migrate`, the schema_version counter still
 * advanced (or, worse, failed to persist and quietly re-applied the
 * same migration on every boot).
 */

#include "test/test_core.h"
#include "models/database.h"
#include "sha3/sha3.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static int mkdir_p(const char *p)
{
    if (mkdir(p, 0700) == 0) return 0;
    if (errno == EEXIST) return 0;
    return -1;
}

static bool db_mig_hash_file(const char *path, uint8_t out[32],
                             off_t *size_out)
{
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        return false;
    struct stat st;
    if (fstat(fd, &st) != 0) {
        close(fd);
        return false;
    }

    struct sha3_256_ctx sha;
    sha3_256_init(&sha);
    uint8_t buf[8192];
    for (;;) {
        ssize_t n = read(fd, buf, sizeof(buf));
        if (n > 0) {
            sha3_256_write(&sha, buf, (size_t)n);
            continue;
        }
        if (n < 0 && errno == EINTR)
            continue;
        if (n < 0) {
            close(fd);
            return false;
        }
        break;
    }
    close(fd);
    sha3_256_finalize(&sha, out);
    if (size_out)
        *size_out = st.st_size;
    return true;
}

#define DB_MIG_FAMILY_MAX 16

struct db_mig_family_file {
    char name[256];
    off_t size;
    mode_t mode;
    struct timespec mtime;
    struct timespec ctime;
    uint8_t sha3[32];
};

struct db_mig_family_snapshot {
    size_t count;
    struct timespec dir_mtime;
    struct timespec dir_ctime;
    struct db_mig_family_file files[DB_MIG_FAMILY_MAX];
};

static int db_mig_family_file_cmp(const void *a, const void *b)
{
    const struct db_mig_family_file *fa = a;
    const struct db_mig_family_file *fb = b;
    return strcmp(fa->name, fb->name);
}

/* Snapshot every directory entry in the SQLite database family, not merely
 * node.db.  A refusal that creates/deletes/changes WAL, SHM, rollback-journal
 * or master-journal state has mutated the database even when node.db itself
 * still hashes the same.  atime is deliberately excluded: hashing the input
 * is itself a read, while mtime/ctime and directory timestamps are avoidable. */
static bool db_mig_snapshot_family(const char *dbpath,
                                   struct db_mig_family_snapshot *out)
{
    if (!dbpath || !out)
        return false;
    memset(out, 0, sizeof(*out));

    const char *slash = strrchr(dbpath, '/');
    if (!slash || slash == dbpath || slash[1] == '\0')
        return false;
    char dir[512];
    size_t dir_len = (size_t)(slash - dbpath);
    if (dir_len >= sizeof(dir))
        return false;
    memcpy(dir, dbpath, dir_len);
    dir[dir_len] = '\0';
    const char *base = slash + 1;
    size_t base_len = strlen(base);

    struct stat dst;
    if (stat(dir, &dst) != 0)
        return false;
    out->dir_mtime = dst.st_mtim;
    out->dir_ctime = dst.st_ctim;

    DIR *d = opendir(dir);
    if (!d)
        return false;
    bool ok = true;
    struct dirent *de;
    while ((de = readdir(d)) != NULL) {
        if (strncmp(de->d_name, base, base_len) != 0)
            continue;
        char next = de->d_name[base_len];
        if (next != '\0' && next != '-' && next != '.')
            continue;
        if (out->count >= DB_MIG_FAMILY_MAX) {
            ok = false;
            break;
        }
        struct db_mig_family_file *f = &out->files[out->count];
        if (snprintf(f->name, sizeof(f->name), "%s", de->d_name) <= 0) {
            ok = false;
            break;
        }
        char path[800];
        int n = snprintf(path, sizeof(path), "%s/%s", dir, de->d_name);
        struct stat st;
        if (n <= 0 || (size_t)n >= sizeof(path) || stat(path, &st) != 0 ||
            !S_ISREG(st.st_mode) ||
            !db_mig_hash_file(path, f->sha3, &f->size)) {
            ok = false;
            break;
        }
        f->mode = st.st_mode;
        f->mtime = st.st_mtim;
        f->ctime = st.st_ctim;
        out->count++;
    }
    closedir(d);
    if (!ok)
        return false;
    qsort(out->files, out->count, sizeof(out->files[0]),
          db_mig_family_file_cmp);
    return true;
}

static bool db_mig_family_same(const struct db_mig_family_snapshot *a,
                               const struct db_mig_family_snapshot *b)
{
    if (!a || !b || a->count != b->count ||
        a->dir_mtime.tv_sec != b->dir_mtime.tv_sec ||
        a->dir_mtime.tv_nsec != b->dir_mtime.tv_nsec ||
        a->dir_ctime.tv_sec != b->dir_ctime.tv_sec ||
        a->dir_ctime.tv_nsec != b->dir_ctime.tv_nsec) {
        fprintf(stderr,
                "db_mig family metadata changed count=%zu/%zu "
                "dir_mtime=%lld.%09ld/%lld.%09ld "
                "dir_ctime=%lld.%09ld/%lld.%09ld\n",
                a ? a->count : 0, b ? b->count : 0,
                a ? (long long)a->dir_mtime.tv_sec : 0,
                a ? a->dir_mtime.tv_nsec : 0,
                b ? (long long)b->dir_mtime.tv_sec : 0,
                b ? b->dir_mtime.tv_nsec : 0,
                a ? (long long)a->dir_ctime.tv_sec : 0,
                a ? a->dir_ctime.tv_nsec : 0,
                b ? (long long)b->dir_ctime.tv_sec : 0,
                b ? b->dir_ctime.tv_nsec : 0);
        return false;
    }
    for (size_t i = 0; i < a->count; i++) {
        const struct db_mig_family_file *fa = &a->files[i];
        const struct db_mig_family_file *fb = &b->files[i];
        if (strcmp(fa->name, fb->name) != 0 || fa->size != fb->size ||
            fa->mode != fb->mode ||
            fa->mtime.tv_sec != fb->mtime.tv_sec ||
            fa->mtime.tv_nsec != fb->mtime.tv_nsec ||
            fa->ctime.tv_sec != fb->ctime.tv_sec ||
            fa->ctime.tv_nsec != fb->ctime.tv_nsec ||
            memcmp(fa->sha3, fb->sha3, sizeof(fa->sha3)) != 0) {
            fprintf(stderr, "db_mig family file changed: %s/%s\n",
                    fa->name, fb->name);
            return false;
        }
    }
    return true;
}

static bool db_mig_refuse_close_twice(const char *dbpath)
{
    struct node_db rejected;
    bool opened = node_db_open(&rejected, dbpath);
    bool ok = !opened && !rejected.open && rejected.db == NULL;
    node_db_close(&rejected);
    node_db_close(&rejected);
    return ok && !rejected.open && rejected.db == NULL;
}

static bool db_mig_refusal_preserves_family(const char *dbpath, int rounds)
{
    struct db_mig_family_snapshot before, after;
    if (!db_mig_snapshot_family(dbpath, &before))
        return false;
    for (int i = 0; i < rounds; i++) {
        if (!db_mig_refuse_close_twice(dbpath))
            return false;
    }
    return db_mig_snapshot_family(dbpath, &after) &&
           db_mig_family_same(&before, &after);
}

/* cwd-relative tmpdir to comply with the "no /tmp" project convention. */
static void db_mig_path(char *buf, size_t n, const char *tag)
{
    snprintf(buf, n, "./test-tmp/db_mig_%d_%s", (int)getpid(), tag);
}

static bool db_mig_stamp_schema(sqlite3 *db, int32_t version)
{
    sqlite3_stmt *st = NULL;
    int rc = sqlite3_prepare_v2(db,
        "UPDATE node_state SET value=? WHERE key='schema_version'",
        -1, &st, NULL);
    if (rc != SQLITE_OK)
        return false;
    rc = sqlite3_bind_blob(st, 1, &version, sizeof(version),
                           SQLITE_TRANSIENT);
    bool ok = rc == SQLITE_OK && sqlite3_step(st) == SQLITE_DONE &&
              sqlite3_changes(db) == 1;
    sqlite3_finalize(st);
    return ok;
}

static int db_mig_count(sqlite3 *db, const char *sql)
{
    sqlite3_stmt *st = NULL;
    int rc = sqlite3_prepare_v2(db, sql, -1, &st, NULL);
    if (rc != SQLITE_OK)
        return -1;
    rc = sqlite3_step(st);
    int out = rc == SQLITE_ROW ? sqlite3_column_int(st, 0) : -1;
    sqlite3_finalize(st);
    return out;
}

static bool db_mig_exec_raw(sqlite3 *db, const char *sql)
{
    char *err = NULL;
    int rc = sqlite3_exec(db, sql, NULL, NULL, &err);
    if (rc != SQLITE_OK)
        fprintf(stderr, "db_mig raw exec failed: %s sql=%s\n",
                err ? err : "(no errmsg)", sql ? sql : "(null)");
    sqlite3_free(err);
    return rc == SQLITE_OK;
}

static bool db_mig_column_exists(sqlite3 *db, const char *table,
                                 const char *column)
{
    char sql[160];
    snprintf(sql, sizeof(sql), "PRAGMA table_info(%s)", table);
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) != SQLITE_OK)
        return false;
    bool found = false;
    while (sqlite3_step(st) == SQLITE_ROW) {
        const unsigned char *name = sqlite3_column_text(st, 1);
        if (name && strcmp((const char *)name, column) == 0) {
            found = true;
            break;
        }
    }
    sqlite3_finalize(st);
    return found;
}

static bool db_mig_is_wal_file(const char *path)
{
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        return false;
    unsigned char hdr[20] = { 0 };
    ssize_t got = read(fd, hdr, sizeof(hdr));
    close(fd);
    return got == (ssize_t)sizeof(hdr) &&
           memcmp(hdr, "SQLite format 3", 16) == 0 && hdr[18] == 2;
}

static bool db_mig_raw_schema(sqlite3 *db, int32_t *version_out)
{
    sqlite3_stmt *st = NULL;
    if (!db || !version_out || sqlite3_prepare_v2(db,
            "SELECT value FROM node_state WHERE key='schema_version'",
            -1, &st, NULL) != SQLITE_OK || !st)
        return false;
    int rc = sqlite3_step(st);
    bool ok = rc == SQLITE_ROW &&
              sqlite3_column_bytes(st, 0) == (int)sizeof(*version_out);
    if (ok)
        memcpy(version_out, sqlite3_column_blob(st, 0),
               sizeof(*version_out));
    sqlite3_finalize(st);
    return ok;
}

static bool db_mig_replace_schema_blob(sqlite3 *db, const char *hex_blob)
{
    char sql[256];
    int n = snprintf(sql, sizeof(sql),
                     "UPDATE node_state SET value=X'%s' "
                     "WHERE key='schema_version'", hex_blob);
    return n > 0 && (size_t)n < sizeof(sql) && db_mig_exec_raw(db, sql) &&
           sqlite3_changes(db) == 1;
}

static bool db_mig_write_junk(const char *path)
{
    int fd = open(path, O_WRONLY | O_TRUNC | O_CLOEXEC);
    if (fd < 0)
        return false;
    static const unsigned char junk[] =
        "not a SQLite database carrying a readable schema marker";
    size_t off = 0;
    while (off < sizeof(junk)) {
        ssize_t n = write(fd, junk + off, sizeof(junk) - off);
        if (n > 0) {
            off += (size_t)n;
            continue;
        }
        if (n < 0 && errno == EINTR)
            continue;
        close(fd);
        return false;
    }
    return close(fd) == 0;
}

static bool db_mig_seed_v20_wallet_notes_db(const char *dbpath)
{
    sqlite3 *raw = NULL;
    if (sqlite3_open(dbpath, &raw) != SQLITE_OK)
        return false;

    bool ok = true;
    ok = ok && db_mig_exec_raw(raw,
        "CREATE TABLE node_state (key TEXT PRIMARY KEY,value BLOB)");
    ok = ok && db_mig_exec_raw(raw,
        "INSERT INTO node_state(key,value) "
        "VALUES('schema_version',X'14000000')");
    ok = ok && db_mig_exec_raw(raw,
        "CREATE TABLE wallet_sapling_notes ("
        "txid BLOB NOT NULL,output_index INTEGER NOT NULL,"
        "value INTEGER NOT NULL,rcm BLOB NOT NULL,memo BLOB,"
        "ivk BLOB NOT NULL,diversifier BLOB NOT NULL,"
        "pk_d BLOB NOT NULL,cm BLOB NOT NULL,"
        "nullifier BLOB NOT NULL UNIQUE,"
        "block_height INTEGER,spent_txid BLOB,address TEXT,"
        "witness_data BLOB,witness_height INTEGER DEFAULT 0,"
        "PRIMARY KEY (txid,output_index))");
    ok = ok && db_mig_exec_raw(raw,
        "CREATE TABLE znam_names ("
        "name TEXT PRIMARY KEY,"
        "owner_address TEXT NOT NULL,"
        "target_type INTEGER NOT NULL,"
        "target_value TEXT NOT NULL,"
        "reg_txid BLOB NOT NULL,"
        "reg_height INTEGER NOT NULL,"
        "last_update_txid BLOB NOT NULL)");
    ok = ok && db_mig_exec_raw(raw,
        "INSERT INTO wallet_sapling_notes"
        "(txid,output_index,value,rcm,ivk,diversifier,pk_d,cm,"
        "nullifier,block_height,address,witness_height) "
        "VALUES(X'01',0,42,X'02',X'03',X'04',X'05',X'06',"
        "X'07',100,'zs-v20-note',100)");
    sqlite3_close(raw);
    return ok;
}

static int t_fresh_reaches_latest(void)
{
    int failures = 0;
    char dir[256];
    db_mig_path(dir, sizeof(dir), "fresh");
    mkdir_p(dir);
    char dbpath[512];
    snprintf(dbpath, sizeof(dbpath), "%s/node.db", dir);

    struct node_db ndb;
    TEST("db_mig: fresh open reaches latest built-in schema version") {
        ASSERT(node_db_open(&ndb, dbpath));
        int v = node_db_schema_version(&ndb);
        ASSERT(v >= 18);
        node_db_close(&ndb);
        PASS();
    } _test_next:;
    test_cleanup_tmpdir(dir);
    return failures;
}

static int t_v20_wallet_notes_upgrade_adds_source(void)
{
    int failures = 0;
    char dir[256];
    db_mig_path(dir, sizeof(dir), "v20_wallet_notes");
    mkdir_p(dir);
    char dbpath[512];
    snprintf(dbpath, sizeof(dbpath), "%s/node.db", dir);

    TEST("db_mig: v20 wallet notes upgrade adds source after schema create") {
        ASSERT(db_mig_seed_v20_wallet_notes_db(dbpath));

        struct node_db ndb;
        ASSERT(node_db_open(&ndb, dbpath));
        ASSERT_EQ(node_db_schema_version(&ndb), NODE_DB_SCHEMA_LATEST);
        node_db_close(&ndb);

        sqlite3 *raw = NULL;
        ASSERT(sqlite3_open(dbpath, &raw) == SQLITE_OK);
        ASSERT(db_mig_column_exists(raw, "wallet_sapling_notes", "source"));
        ASSERT(db_mig_count(raw,
            "SELECT count(*) FROM sqlite_master "
            "WHERE type='index' AND name='idx_snote_view_address'") == 1);
        ASSERT(db_mig_count(raw,
            "SELECT count(*) FROM schema_migrations "
            "WHERE version='021'") == 1);
        ASSERT(db_mig_count(raw,
            "SELECT count(*) FROM schema_migrations "
            "WHERE version='022'") == 1);
        ASSERT(db_mig_count(raw,
            "SELECT count(*) FROM schema_migrations "
            "WHERE version='023'") == 1);
        ASSERT(db_mig_count(raw,
            "SELECT count(*) FROM sqlite_master "
            "WHERE type='index' AND name='idx_txo_hodl_scan'") == 1);
        ASSERT(db_mig_count(raw,
            "SELECT count(*) FROM sqlite_master "
            "WHERE type='index' AND name='idx_txi_prev_height'") == 1);
        ASSERT(db_mig_column_exists(raw, "hodl_history", "calc_version"));
        ASSERT(db_mig_column_exists(raw, "hodl_history", "source_tip_height"));
        ASSERT(db_mig_count(raw,
            "SELECT count(*) FROM wallet_sapling_notes "
            "WHERE address='zs-v20-note' AND source='local'") == 1);
        sqlite3_close(raw);
        PASS();
    } _test_next:;
    test_cleanup_tmpdir(dir);
    return failures;
}

static int t_reopen_is_idempotent(void)
{
    int failures = 0;
    char dir[256];
    db_mig_path(dir, sizeof(dir), "reopen");
    mkdir_p(dir);
    char dbpath[512];
    snprintf(dbpath, sizeof(dbpath), "%s/node.db", dir);

    TEST("db_mig: reopen does not re-apply migrations") {
        struct node_db ndb1;
        ASSERT(node_db_open(&ndb1, dbpath));
        int v1 = node_db_schema_version(&ndb1);
        ASSERT(v1 >= 18);
        node_db_close(&ndb1);

        struct node_db ndb2;
        ASSERT(node_db_open(&ndb2, dbpath));
        int v2 = node_db_schema_version(&ndb2);
        ASSERT_EQ(v1, v2);
        node_db_close(&ndb2);
        PASS();
    } _test_next:;
    test_cleanup_tmpdir(dir);
    return failures;
}

static int t_market_content_registry_schema(void)
{
    int failures = 0;
    char dir[256];
    db_mig_path(dir, sizeof(dir), "market_content");
    mkdir_p(dir);
    char dbpath[512];
    snprintf(dbpath, sizeof(dbpath), "%s/node.db", dir);

    TEST("db_mig: v57-v61 app and intent resources install once") {
        struct node_db ndb;
        ASSERT(node_db_open(&ndb, dbpath));
        ASSERT_EQ(node_db_schema_version(&ndb), NODE_DB_SCHEMA_LATEST);
        node_db_close(&ndb);

        sqlite3 *raw = NULL;
        ASSERT(sqlite3_open(dbpath, &raw) == SQLITE_OK);
        ASSERT(db_mig_count(raw,
            "SELECT count(*) FROM schema_migrations "
            "WHERE version='057'") == 1);
        ASSERT(db_mig_count(raw,
            "SELECT count(*) FROM schema_migrations "
            "WHERE version='058'") == 1);
        ASSERT(db_mig_count(raw,
            "SELECT count(*) FROM schema_migrations "
            "WHERE version='059'") == 1);
        ASSERT(db_mig_count(raw,
            "SELECT count(*) FROM schema_migrations "
            "WHERE version='060'") == 1);
        ASSERT(db_mig_count(raw,
            "SELECT count(*) FROM schema_migrations "
            "WHERE version='061'") == 1);
        ASSERT(db_mig_count(raw,
            "SELECT count(*) FROM sqlite_master "
            "WHERE type='table' AND name='market_contents'") == 1);
        ASSERT(db_mig_count(raw,
            "SELECT count(*) FROM sqlite_master WHERE type='index' AND "
            "name IN ('idx_market_contents_root',"
            "'idx_market_contents_registered')") == 2);
        ASSERT(db_mig_column_exists(raw, "vault_intents",
                                    "application_kind"));
        ASSERT(db_mig_column_exists(raw, "vault_intents",
                                    "idempotency_key"));
        ASSERT(db_mig_column_exists(raw, "vault_intents",
                                    "request_digest"));
        ASSERT(db_mig_count(raw,
            "SELECT count(*) FROM sqlite_master WHERE type='index' AND "
            "name='idx_vault_intents_application_idempotency'") == 1);
        ASSERT(db_mig_count(raw,
            "SELECT count(*) FROM sqlite_master WHERE type='table' AND "
            "name IN ('market_downloads','market_download_chunks')") == 2);
        ASSERT(db_mig_count(raw,
            "SELECT count(*) FROM sqlite_master WHERE type='index' AND "
            "name IN ('idx_market_downloads_state',"
            "'idx_market_download_chunks_plan')") == 2);
        ASSERT(db_mig_count(raw,
            "SELECT count(*) FROM sqlite_master WHERE type='table' AND "
            "name='vault_intent_inputs'") == 1);
        ASSERT(db_mig_count(raw,
            "SELECT count(*) FROM sqlite_master WHERE type='index' AND "
            "name='idx_vault_intent_inputs_plan'") == 1);
        ASSERT(db_mig_count(raw,
            "SELECT count(*) FROM sqlite_master WHERE type='table' AND "
            "name='vault_intents' AND instr(sql,'''test''')>0") == 1);
        ASSERT(db_mig_count(raw,
            "SELECT count(*) FROM pragma_foreign_key_check") == 0);
        sqlite3_close(raw);

        struct node_db reopened;
        ASSERT(node_db_open(&reopened, dbpath));
        ASSERT_EQ(node_db_schema_version(&reopened), NODE_DB_SCHEMA_LATEST);
        node_db_close(&reopened);
        PASS();
    } _test_next:;
    test_cleanup_tmpdir(dir);
    return failures;
}

static int t_memory_open(void)
{
    int failures = 0;
    TEST("db_mig: :memory: open succeeds with schema migrations") {
        struct node_db mem;
        ASSERT(node_db_open(&mem, ":memory:"));
        int v = node_db_schema_version(&mem);
        ASSERT(v >= 18);
        node_db_close(&mem);
        PASS();
    } _test_next:;
    return failures;
}

static int t_turbo_mode_roundtrip(void)
{
    int failures = 0;
    char dir[256];
    db_mig_path(dir, sizeof(dir), "turbo");
    mkdir_p(dir);
    char dbpath[512];
    snprintf(dbpath, sizeof(dbpath), "%s/node.db", dir);

    TEST("db_mig: turbo->normal mode roundtrip leaves state consistent") {
        struct node_db ndb;
        ASSERT(node_db_open(&ndb, dbpath));
        ASSERT(node_db_ibd_turbo_mode(&ndb));

        struct node_db_status st;
        node_db_get_status(&ndb, &st);
        ASSERT(st.turbo_mode);

        ASSERT(node_db_normal_mode(&ndb));
        node_db_get_status(&ndb, &st);
        ASSERT(!st.turbo_mode);

        node_db_close(&ndb);
        PASS();
    } _test_next:;
    test_cleanup_tmpdir(dir);
    return failures;
}

static int t_newer_schema_delete_refusal_is_zero_mutation(void)
{
    int failures = 0;
    char dir[256];
    db_mig_path(dir, sizeof(dir), "newer");
    mkdir_p(dir);
    char dbpath[512];
    snprintf(dbpath, sizeof(dbpath), "%s/node.db", dir);

    TEST("db_mig: DELETE-mode newer schema refusal preserves whole family") {
        struct node_db seed;
        ASSERT(node_db_open(&seed, dbpath));
        ASSERT(node_db_exec(&seed,
            "INSERT INTO snapshot_staging_utxos"
            "(txid,vout,value,script,script_type,height,is_coinbase)"
            " VALUES(X'4200000000000000000000000000000000000000000000000000000000000000',0,1,X'51',0,1,0)"));
        ASSERT(node_db_state_set(&seed, "snapshot_staging_phase",
                                 "chunk_receive", strlen("chunk_receive")));
        node_db_close(&seed);

        sqlite3 *raw = NULL;
        ASSERT(sqlite3_open(dbpath, &raw) == SQLITE_OK);
        ASSERT(db_mig_exec_raw(raw, "PRAGMA journal_mode=DELETE"));
        ASSERT(db_mig_stamp_schema(raw, NODE_DB_MAX_SCHEMA + 1));
        /* A future schema need not contain every table this older binary
         * knows.  Refusal must happen before create_schema() can add one. */
        ASSERT(db_mig_exec_raw(raw, "DROP TABLE peers"));
        sqlite3_close(raw);
        raw = NULL;

        /* Eight complete failure lifecycles, each followed by two unconditional
         * closes.  The full node.db family and directory metadata must remain
         * byte-for-byte and entry-for-entry identical. */
        ASSERT(db_mig_refusal_preserves_family(dbpath, 8));

        ASSERT(sqlite3_open(dbpath, &raw) == SQLITE_OK);
        ASSERT(db_mig_count(raw,
            "SELECT count(*) FROM sqlite_master "
            "WHERE type='table' AND name='peers'") == 0);
        ASSERT(db_mig_count(raw,
            "SELECT count(*) FROM snapshot_staging_utxos") == 1);
        ASSERT(db_mig_count(raw,
            "SELECT count(*) FROM node_state "
            "WHERE key='snapshot_staging_phase'") == 1);
        ASSERT(db_mig_count(raw,
            "SELECT count(*) FROM node_state "
            "WHERE key='schema_version'") == 1);
        sqlite3_close(raw);
        PASS();
    } _test_next:;
    test_cleanup_tmpdir(dir);
    return failures;
}

static int t_newer_schema_wal_refusal_is_zero_mutation(void)
{
    int failures = 0;
    char dir[256];
    db_mig_path(dir, sizeof(dir), "newer_wal");
    mkdir_p(dir);
    char dbpath[512];
    snprintf(dbpath, sizeof(dbpath), "%s/node.db", dir);

    TEST("db_mig: clean-WAL newer schema refusal preserves whole family") {
        struct node_db seed;
        ASSERT(node_db_open(&seed, dbpath));
        node_db_close(&seed);

        sqlite3 *raw = NULL;
        ASSERT(sqlite3_open(dbpath, &raw) == SQLITE_OK);
        ASSERT(db_mig_exec_raw(raw, "PRAGMA journal_mode=WAL"));
        ASSERT(db_mig_stamp_schema(raw, NODE_DB_MAX_SCHEMA + 1));
        sqlite3_close(raw);
        raw = NULL;

        ASSERT(db_mig_is_wal_file(dbpath));
        ASSERT(db_mig_refusal_preserves_family(dbpath, 1));
        PASS();
    } _test_next:;
    test_cleanup_tmpdir(dir);
    return failures;
}

static int t_newer_schema_only_in_uncheckpointed_wal(void)
{
    int failures = 0;
    char dir[256];
    db_mig_path(dir, sizeof(dir), "newer_live_wal");
    mkdir_p(dir);
    char dbpath[512];
    snprintf(dbpath, sizeof(dbpath), "%s/node.db", dir);

    sqlite3 *writer = NULL;
    TEST("db_mig: newer marker only in uncheckpointed WAL is refused unchanged") {
        struct node_db seed;
        ASSERT(node_db_open(&seed, dbpath));
        node_db_close(&seed);

        ASSERT(sqlite3_open(dbpath, &writer) == SQLITE_OK);
        ASSERT(db_mig_exec_raw(writer,
            "PRAGMA journal_mode=WAL;PRAGMA wal_autocheckpoint=0;"
            "BEGIN IMMEDIATE"));
        ASSERT(db_mig_stamp_schema(writer, NODE_DB_MAX_SCHEMA + 1));
        ASSERT(db_mig_exec_raw(writer, "COMMIT"));

        char wal[560], shm[560];
        snprintf(wal, sizeof(wal), "%s-wal", dbpath);
        snprintf(shm, sizeof(shm), "%s-shm", dbpath);
        struct stat wal_st;
        ASSERT(stat(wal, &wal_st) == 0 && wal_st.st_size > 0);
        ASSERT(access(shm, F_OK) == 0);

        /* Anti-vacuous: the ordinary live view sees the future marker, while
         * immutable=1 (main file only) still sees the supported old marker. */
        int32_t live_ver = 0, main_ver = 0;
        ASSERT(db_mig_raw_schema(writer, &live_ver));
        ASSERT_EQ(live_ver, NODE_DB_MAX_SCHEMA + 1);
        char uri[640];
        snprintf(uri, sizeof(uri), "file:%s?mode=ro&immutable=1", dbpath);
        sqlite3 *main_only = NULL;
        ASSERT(sqlite3_open_v2(uri, &main_only,
            SQLITE_OPEN_READONLY | SQLITE_OPEN_URI, NULL) == SQLITE_OK);
        ASSERT(db_mig_raw_schema(main_only, &main_ver));
        ASSERT(main_ver <= NODE_DB_MAX_SCHEMA);
        sqlite3_close(main_only);

        ASSERT(db_mig_refusal_preserves_family(dbpath, 1));
        sqlite3_close(writer);
        writer = NULL;
        PASS();
    } _test_next:;
    if (writer)
        sqlite3_close(writer);
    test_cleanup_tmpdir(dir);
    return failures;
}

static int t_wrong_width_schema_marker_refuses_unchanged(void)
{
    int failures = 0;
    char dir[256];
    char dbpath[512];
    sqlite3 *raw = NULL;

    db_mig_path(dir, sizeof(dir), "schema_wrong_width");
    mkdir_p(dir);
    snprintf(dbpath, sizeof(dbpath), "%s/node.db", dir);
    TEST("db_mig: malformed wrong-width schema marker refuses unchanged") {
        struct node_db seed;
        ASSERT(node_db_open(&seed, dbpath));
        node_db_close(&seed);
        ASSERT(sqlite3_open(dbpath, &raw) == SQLITE_OK);
        ASSERT(db_mig_replace_schema_blob(raw, "43"));
        sqlite3_close(raw); raw = NULL;
        ASSERT(db_mig_refusal_preserves_family(dbpath, 1));
        PASS();
    } _test_next:;
    if (raw) sqlite3_close(raw);
    test_cleanup_tmpdir(dir);
    return failures;
}

static int t_unsupported_schema_marker_refuses_unchanged(void)
{
    int failures = 0;
    char dir[256];
    char dbpath[512];
    sqlite3 *raw = NULL;
    db_mig_path(dir, sizeof(dir), "schema_unsupported");
    mkdir_p(dir);
    snprintf(dbpath, sizeof(dbpath), "%s/node.db", dir);
    TEST("db_mig: unsupported schema marker zero refuses unchanged") {
        struct node_db seed;
        ASSERT(node_db_open(&seed, dbpath));
        node_db_close(&seed);
        ASSERT(sqlite3_open(dbpath, &raw) == SQLITE_OK);
        ASSERT(db_mig_replace_schema_blob(raw, "00000000"));
        sqlite3_close(raw); raw = NULL;
        ASSERT(db_mig_refusal_preserves_family(dbpath, 1));
        PASS();
    } _test_next:;
    if (raw) sqlite3_close(raw);
    test_cleanup_tmpdir(dir);
    return failures;
}

static int t_contradictory_schema_markers_refuse_unchanged(void)
{
    int failures = 0;
    char dir[256];
    char dbpath[512];
    sqlite3 *raw = NULL;
    db_mig_path(dir, sizeof(dir), "schema_contradictory");
    mkdir_p(dir);
    snprintf(dbpath, sizeof(dbpath), "%s/node.db", dir);
    TEST("db_mig: contradictory duplicate schema markers refuse unchanged") {
        ASSERT(sqlite3_open(dbpath, &raw) == SQLITE_OK);
        ASSERT(db_mig_exec_raw(raw,
            "CREATE TABLE node_state(key TEXT,value BLOB);"
            "INSERT INTO node_state VALUES('schema_version',X'01000000');"
            "INSERT INTO node_state VALUES('schema_version',X'02000000')"));
        sqlite3_close(raw); raw = NULL;
        ASSERT(db_mig_refusal_preserves_family(dbpath, 1));
        PASS();
    } _test_next:;
    if (raw) sqlite3_close(raw);
    test_cleanup_tmpdir(dir);
    return failures;
}

static int t_unreadable_schema_store_refuses_unchanged(void)
{
    int failures = 0;
    char dir[256];
    char dbpath[512];
    sqlite3 *raw = NULL;
    db_mig_path(dir, sizeof(dir), "schema_unreadable");
    mkdir_p(dir);
    snprintf(dbpath, sizeof(dbpath), "%s/node.db", dir);
    TEST("db_mig: unreadable schema store refuses without quarantine") {
        ASSERT(sqlite3_open(dbpath, &raw) == SQLITE_OK);
        ASSERT(db_mig_exec_raw(raw,
            "CREATE TABLE node_state(key TEXT PRIMARY KEY,value BLOB);"
            "INSERT INTO node_state VALUES('schema_version',X'01000000')"));
        sqlite3_close(raw); raw = NULL;
        ASSERT(db_mig_write_junk(dbpath));
        ASSERT(db_mig_refusal_preserves_family(dbpath, 1));
        PASS();
    } _test_next:;
    if (raw) sqlite3_close(raw);
    test_cleanup_tmpdir(dir);
    return failures;
}

static int t_missing_node_state_refuses_unchanged(void)
{
    int failures = 0;
    char dir[256];
    char dbpath[512];
    sqlite3 *raw = NULL;

    db_mig_path(dir, sizeof(dir), "missing_node_state");
    mkdir_p(dir);
    snprintf(dbpath, sizeof(dbpath), "%s/node.db", dir);
    TEST("db_mig: recognized tables without node_state refuse unchanged") {
        ASSERT(sqlite3_open(dbpath, &raw) == SQLITE_OK);
        ASSERT(db_mig_exec_raw(raw,
            "CREATE TABLE blocks(hash BLOB PRIMARY KEY,height INTEGER)"));
        sqlite3_close(raw); raw = NULL;
        ASSERT(db_mig_refusal_preserves_family(dbpath, 1));
        PASS();
    } _test_next:;
    if (raw) sqlite3_close(raw);
    test_cleanup_tmpdir(dir);
    return failures;
}

static int t_existing_empty_database_may_initialize(void)
{
    int failures = 0;
    char dir[256];
    char dbpath[512];
    sqlite3 *raw = NULL;
    db_mig_path(dir, sizeof(dir), "existing_empty");
    mkdir_p(dir);
    snprintf(dbpath, sizeof(dbpath), "%s/node.db", dir);
    TEST("db_mig: genuinely empty existing SQLite database may initialize") {
        ASSERT(sqlite3_open(dbpath, &raw) == SQLITE_OK);
        sqlite3_close(raw); raw = NULL;
        struct node_db fresh;
        ASSERT(node_db_open(&fresh, dbpath));
        ASSERT_EQ(node_db_schema_version(&fresh), NODE_DB_SCHEMA_LATEST);
        node_db_close(&fresh);
        PASS();
    } _test_next:;
    if (raw) sqlite3_close(raw);
    test_cleanup_tmpdir(dir);
    return failures;
}

static int t_supported_current_schema_reopens_normally(void)
{
    int failures = 0;
    char dir[256];
    db_mig_path(dir, sizeof(dir), "supported_current");
    mkdir_p(dir);
    char dbpath[512];
    snprintf(dbpath, sizeof(dbpath), "%s/node.db", dir);

    TEST("db_mig: supported current schema passes preflight and remains writable") {
        struct node_db first;
        ASSERT(node_db_open(&first, dbpath));
        ASSERT_EQ(node_db_schema_version(&first), NODE_DB_SCHEMA_LATEST);
        node_db_close(&first);
        struct node_db reopened;
        ASSERT(node_db_open(&reopened, dbpath));
        ASSERT(node_db_state_set(&reopened, "preflight_supported", "yes", 3));
        node_db_close(&reopened);
        PASS();
    } _test_next:;
    test_cleanup_tmpdir(dir);
    return failures;
}

static int t_v29_incompatible_schema_fails_without_stamp(void)
{
    int failures = 0;
    char dir[256];
    db_mig_path(dir, sizeof(dir), "v29_incompatible");
    mkdir_p(dir);
    char dbpath[512];
    snprintf(dbpath, sizeof(dbpath), "%s/node.db", dir);

    TEST("db_mig: v29 incompatible AppEvent schema fails without stamp") {
        struct node_db seed;
        ASSERT(node_db_open(&seed, dbpath));
        node_db_close(&seed);

        sqlite3 *raw = NULL;
        ASSERT(sqlite3_open(dbpath, &raw) == SQLITE_OK);
        ASSERT(db_mig_exec_raw(raw,
            "DELETE FROM schema_migrations WHERE version='029';"
            "DROP INDEX idx_app_events_topic_cursor;"
            "DROP INDEX idx_app_events_author_sequence;"
            "DROP INDEX idx_app_events_previous;"
            "DROP TABLE app_events;"
            "CREATE TABLE app_events(event_id BLOB)"));
        ASSERT(db_mig_stamp_schema(raw, 28));
        sqlite3_close(raw);
        raw = NULL;

        struct node_db rejected;
        ASSERT(!node_db_open(&rejected, dbpath));
        ASSERT(!rejected.open && rejected.db == NULL);

        ASSERT(sqlite3_open(dbpath, &raw) == SQLITE_OK);
        ASSERT(db_mig_count(raw,
            "SELECT count(*) FROM schema_migrations "
            "WHERE version='029'") == 0);
        ASSERT(!db_mig_column_exists(raw, "app_events", "app_id"));
        sqlite3_close(raw);
        PASS();
    } _test_next:;
    test_cleanup_tmpdir(dir);
    return failures;
}

int test_db_migration_idempotent(void);

int test_db_migration_idempotent(void)
{
    printf("\n=== db_migration_idempotent tests ===\n");
    int failures = 0;
    mkdir_p("./test-tmp");
    failures += t_fresh_reaches_latest();
    failures += t_v20_wallet_notes_upgrade_adds_source();
    failures += t_reopen_is_idempotent();
    failures += t_market_content_registry_schema();
    failures += t_memory_open();
    failures += t_turbo_mode_roundtrip();
    failures += t_newer_schema_delete_refusal_is_zero_mutation();
    failures += t_newer_schema_wal_refusal_is_zero_mutation();
    failures += t_newer_schema_only_in_uncheckpointed_wal();
    failures += t_wrong_width_schema_marker_refuses_unchanged();
    failures += t_unsupported_schema_marker_refuses_unchanged();
    failures += t_contradictory_schema_markers_refuse_unchanged();
    failures += t_unreadable_schema_store_refuses_unchanged();
    failures += t_missing_node_state_refuses_unchanged();
    failures += t_existing_empty_database_may_initialize();
    failures += t_supported_current_schema_reopens_normally();
    failures += t_v29_incompatible_schema_fails_without_stamp();
    return failures;
}
