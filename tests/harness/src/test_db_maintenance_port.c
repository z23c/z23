/* SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Rhett Creighton
 *
 * Tests for the db_maintenance storage seam.
 *
 * Exercises the sqlite adapter behind db_maintenance_port (wal_checkpoint
 * TRUNCATE / ANALYZE / VACUUM plus a WAL-size probe) against isolated
 * temp-file / in-memory DBs, never the live node DB.
 *
 * Asserts each op succeeds on a WAL-mode DB, TRUNCATE shrinks the WAL to
 * zero, success clears the error buffer while NULL-conn ops fill it and
 * return false, and wal_size_bytes matches the file size after committed
 * writes and preserves its output for absent WALs and :memory: connections.
 * NULL-arg guards round it out.
 *
 * test_db_maintenance.c covers the full db_maintenance_run_now() service
 * separately. This file is hermetic.
 */

#include "test/test_core.h"

#include "adapters/outbound/persistence/db_maintenance_sqlite.h"
#include "ports/db_maintenance_port.h"
#include "util/wal_checkpoint_stats.h"

#include <limits.h>
#include <errno.h>
#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define DBMP_CHECK(name, expr) do {                       \
    printf("db_maintenance_port: %s... ", (name));        \
    if ((expr)) { printf("OK\n"); }                       \
    else { printf("FAIL\n"); failures++; }                \
} while (0)

static bool exec_sql(sqlite3 *db, const char *sql)
{
    return sqlite3_exec(db, sql, NULL, NULL, NULL) == SQLITE_OK;
}

/* Open a fresh file-backed WAL-mode DB with a little churn so ANALYZE /
 * VACUUM / checkpoint have real work to do. Returns the path so the
 * caller can clean up the sidecar files. */
static bool make_file_db(sqlite3 **out_db, char *path, size_t pathsz)
{
    int fd = test_mkstemp(path, pathsz, "zcl_dbmp_test");
    if (fd < 0) return false;
    close(fd);
    unlink(path);   /* let sqlite create it fresh */

    sqlite3 *db = NULL;
    if (sqlite3_open(path, &db) != SQLITE_OK || !db)
        return false;
    if (!exec_sql(db, "PRAGMA journal_mode=WAL;")) { sqlite3_close(db); return false; }
    if (!exec_sql(db,
            "CREATE TABLE kv(k INTEGER PRIMARY KEY, v BLOB);"
            "INSERT INTO kv VALUES(1, randomblob(64));"
            "INSERT INTO kv VALUES(2, randomblob(128));"
            "INSERT INTO kv VALUES(3, randomblob(256));"
            "DELETE FROM kv WHERE k=2;")) {
        sqlite3_close(db);
        return false;
    }
    *out_db = db;
    return true;
}

static void clean_file_db(sqlite3 *db, const char *path)
{
    if (db) sqlite3_close(db);
    char side[1100];
    unlink(path);
    snprintf(side, sizeof side, "%s-wal", path); unlink(side);
    snprintf(side, sizeof side, "%s-shm", path); unlink(side);
}

static int64_t wal_file_size(const char *db_path)
{
    char wal[1100];
    struct stat st;
    snprintf(wal, sizeof wal, "%s-wal", db_path);
    if (stat(wal, &st) != 0) return -1;
    return (int64_t)st.st_size;
}

static int t_wal_size_commits(void)
{
    int failures = 0;
    char path[256];
    sqlite3 *db = NULL;
    bool ready = make_file_db(&db, path, sizeof path);
    DBMP_CHECK("file db builds (walsize)", ready);
    if (!ready) { clean_file_db(db, path); return failures; }
    struct db_maintenance_sqlite_ctx ctx;
    struct db_maintenance_port port = {0};
    DBMP_CHECK("wal_size bind", db_maintenance_sqlite_bind(&ctx, db, &port));
    DBMP_CHECK("disable automatic checkpoint", exec_sql(db, "PRAGMA wal_autocheckpoint=0;"));
    const char *writes[] = {
        "INSERT INTO kv VALUES(4, zeroblob(64));",
        "UPDATE kv SET v=zeroblob(128) WHERE k=4;"
    };
    int64_t previous = wal_file_size(path);
    for (size_t i = 0; i < 2; ++i) {
        DBMP_CHECK("distinct WAL write commits", exec_sql(db, writes[i]));
        int64_t expected = wal_file_size(path);
        DBMP_CHECK("committed write grows real WAL", expected > 0 && expected > previous);
        int64_t bytes = -1;
        bool got = port.wal_size_bytes(port.self, &bytes);
        DBMP_CHECK("wal_size file-backed ok", got);
        DBMP_CHECK("wal_size equals real stat after commit", got && bytes == expected);
        previous = expected;
    }
    DBMP_CHECK("switch to DELETE journal", exec_sql(db, "PRAGMA journal_mode=DELETE;"));
    DBMP_CHECK("WAL file absent", wal_file_size(path) == -1);
    int64_t bytes = 12345;
    DBMP_CHECK("wal_size absent WAL false", !port.wal_size_bytes(port.self, &bytes));
    DBMP_CHECK("wal_size absent WAL preserves sentinel", bytes == 12345);
    clean_file_db(db, path);
    return failures;
}

/* ── wal_ckpt_classify ─────────────────────────────────────────────────
 *
 * The outcome ranking is the invariant: busy beats completed (SQLite
 * reports contention as a successful call whose row says busy), a failed
 * call is an error, unknown frame counts refuse to claim success, and
 * only then do drained/noop/partial split on the counts. The 0/0 empty
 * WAL is a drain, not a no-op. Pure — called directly. One function per
 * TEST, as the harness's hardcoded `goto _test_next` requires. */
static int t_wal_ckpt_classify_ranking(void)
{
    int failures = 0;
    TEST("wal_ckpt_classify: busy beats completed, error otherwise") {
        ASSERT_EQ(wal_ckpt_classify(true, true, 0, 0), WAL_CKPT_BUSY);
        ASSERT_EQ(wal_ckpt_classify(false, true, -1, -1), WAL_CKPT_BUSY);
        ASSERT_EQ(wal_ckpt_classify(false, false, 5, 0), WAL_CKPT_ERROR);
        PASS();
    } _test_next:;
    return failures;
}

static int t_wal_ckpt_classify_unknown(void)
{
    int failures = 0;
    TEST("wal_ckpt_classify: unknown frame counts classify UNKNOWN, not success") {
        ASSERT_EQ(wal_ckpt_classify(true, false, -1, 0), WAL_CKPT_UNKNOWN);
        ASSERT_EQ(wal_ckpt_classify(true, false, 0, -1), WAL_CKPT_UNKNOWN);
        ASSERT_EQ(wal_ckpt_classify(true, false, -1, -1), WAL_CKPT_UNKNOWN);
        PASS();
    } _test_next:;
    return failures;
}

static int t_wal_ckpt_classify_counts(void)
{
    int failures = 0;
    TEST("wal_ckpt_classify: drained/noop/partial split on exact counts") {
        ASSERT_EQ(wal_ckpt_classify(true, false, 0, 0), WAL_CKPT_DRAINED);
        ASSERT_EQ(wal_ckpt_classify(true, false, 5, 5), WAL_CKPT_DRAINED);
        ASSERT_EQ(wal_ckpt_classify(true, false, 5, 7), WAL_CKPT_DRAINED);
        ASSERT_EQ(wal_ckpt_classify(true, false, 5, 0), WAL_CKPT_NOOP);
        ASSERT_EQ(wal_ckpt_classify(true, false, 5, 3), WAL_CKPT_PARTIAL);
        PASS();
    } _test_next:;
    return failures;
}

/* Delegate WAL I/O except an armed file-reset failure; no replacement SQL. */
static sqlite3_io_methods dbmp_wal_io;
static const sqlite3_io_methods *dbmp_real_wal_io;
static bool dbmp_fail_reset;
static int dbmp_reset_calls;
static int dbmp_truncate(sqlite3_file *file, sqlite3_int64 size)
{
    if (dbmp_fail_reset && size == 0) {
        dbmp_reset_calls++;
        return SQLITE_IOERR_TRUNCATE;
    }
    return dbmp_real_wal_io->xTruncate(file, size);
}
static int dbmp_open(sqlite3_vfs *vfs, const char *name, sqlite3_file *file,
                     int flags, int *out_flags)
{
    sqlite3_vfs *real = vfs->pAppData;
    int rc = real->xOpen(real, name, file, flags, out_flags);
    if (rc == SQLITE_OK && (flags & SQLITE_OPEN_WAL)) {
        dbmp_real_wal_io = file->pMethods;
        dbmp_wal_io = *file->pMethods;
        dbmp_wal_io.xTruncate = dbmp_truncate;
        file->pMethods = &dbmp_wal_io;
    }
    return rc;
}
static bool dbmp_locked(bool ok, struct db_maintenance_wal_outcome wal, const char *err, const char *path)
{
    (void)path; return !ok &&
        wal.rc == SQLITE_LOCKED && wal.busy && !wal.truncated &&
        wal.truncate_rc == -1 && wal.log_frames == -1 &&
        wal.ckpt_frames == -1 && err[0] != 0;
}
static bool dbmp_busy(bool ok, struct db_maintenance_wal_outcome wal, const char *err, const char *path)
{
    return ok &&
        wal.rc == SQLITE_OK && wal.truncate_rc == SQLITE_BUSY &&
        !wal.busy && !wal.truncated && wal.log_frames > 0 &&
        wal.ckpt_frames == wal.log_frames && err[0] == 0 &&
        wal_file_size(path) > 0;
}
static bool dbmp_hard(bool ok, struct db_maintenance_wal_outcome wal, const char *err, const char *path)
{
    return !ok && dbmp_reset_calls == 1 && wal.rc == SQLITE_IOERR_TRUNCATE &&
        wal.truncate_rc == SQLITE_IOERR_TRUNCATE && !wal.busy &&
        !wal.truncated && wal.log_frames > 0 &&
        wal.ckpt_frames == wal.log_frames && err[0] != 0 &&
        wal_file_size(path) > 0;
}
static bool dbmp_remove_file(const char *path)
{
    if (unlink(path) == 0) return true;
    return errno == ENOENT;
}
static int dbmp_remove_files(const char *path)
{
    int failures = 0;
    char side[1100];
    DBMP_CHECK("checkpoint main fixture removed", dbmp_remove_file(path));
    int n = snprintf(side, sizeof side, "%s-wal", path);
    bool fits = n >= 0 && (size_t)n < sizeof side;
    DBMP_CHECK("checkpoint WAL fixture removed", fits && dbmp_remove_file(side));
    n = snprintf(side, sizeof side, "%s-shm", path);
    fits = n >= 0 && (size_t)n < sizeof side;
    DBMP_CHECK("checkpoint SHM fixture removed", fits && dbmp_remove_file(side));
    return failures;
}
static int dbmp_cleanup(sqlite3 *db, sqlite3 *reader, const char *path)
{
    int failures = 0;
    if (reader) DBMP_CHECK("reader closes", sqlite3_close(reader) == SQLITE_OK);
    if (db) {
        DBMP_CHECK("writer transaction released", exec_sql(db, "ROLLBACK;") ||
                   sqlite3_get_autocommit(db));
        DBMP_CHECK("writer closes", sqlite3_close(db) == SQLITE_OK);
    }
    failures += dbmp_remove_files(path);
    return failures;
}
/* Exercise the real maintenance caller; setup failures stop later cases. */
static int dbmp_refusal_cases(sqlite3 *db, const char *path)
{
    int failures = 0;
    sqlite3 *reader = NULL;
    struct db_maintenance_sqlite_ctx ctx;
    struct db_maintenance_port port = {0};
    char err[256];
    struct db_maintenance_wal_outcome wal;
    bool ready = exec_sql(db, "PRAGMA journal_mode=WAL; PRAGMA wal_autocheckpoint=0;"
                             "CREATE TABLE kv(k); INSERT INTO kv VALUES(1);") &&
        db_maintenance_sqlite_bind(&ctx, db, &port) &&
        sqlite3_extended_result_codes(db, 1) == SQLITE_OK;
    DBMP_CHECK("checkpoint refusal fixture ready", ready);
    if (!ready) goto cleanup;
    ready = exec_sql(db, "BEGIN IMMEDIATE; INSERT INTO kv VALUES(2);");
    DBMP_CHECK("PASSIVE write lock established", ready);
    if (!ready) goto cleanup;
    bool ok = port.wal_checkpoint(port.self, &wal, err, sizeof err);
    DBMP_CHECK("locked PASSIVE refuses with exact outcome", dbmp_locked(ok, wal, err, path));
    ready = exec_sql(db, "ROLLBACK;") &&
        sqlite3_open_v2(path, &reader, SQLITE_OPEN_READWRITE, NULL) == SQLITE_OK &&
        exec_sql(reader, "BEGIN; SELECT * FROM kv;");
    DBMP_CHECK("reader snapshot pinned", ready);
    if (!ready) goto cleanup;
    ok = port.wal_checkpoint(port.self, &wal, err, sizeof err);
    DBMP_CHECK("pinned reader keeps reset busy after PASSIVE drain", dbmp_busy(ok, wal, err, path));
    ready = exec_sql(reader, "ROLLBACK;") &&
        exec_sql(db, "INSERT INTO kv VALUES(3);");
    DBMP_CHECK("hard reset fixture ready", ready);
    if (!ready) goto cleanup;
    dbmp_reset_calls = 0;
    dbmp_fail_reset = true;
    ok = port.wal_checkpoint(port.self, &wal, err, sizeof err);
    dbmp_fail_reset = false;
    DBMP_CHECK("hard reset error propagates exact outcome", dbmp_hard(ok, wal, err, path));
cleanup:
    dbmp_fail_reset = false;
    failures += dbmp_cleanup(db, reader, path);
    return failures;
}

static int dbmp_refusal_fixture(const char *vfs_name)
{
    int failures = 0;
    char path[1024];
    int fd = test_mkstemp(path, sizeof path, "zcl_dbmp_refusal");
    DBMP_CHECK("checkpoint fixture path created", fd >= 0);
    if (fd < 0) return failures;
    DBMP_CHECK("checkpoint fixture descriptor closes", close(fd) == 0);
    sqlite3 *db = NULL;
    bool ready = sqlite3_open_v2(path, &db, SQLITE_OPEN_READWRITE,
                               vfs_name) == SQLITE_OK;
    DBMP_CHECK("checkpoint fixture opens", ready);
    if (ready) failures += dbmp_refusal_cases(db, path);
    else failures += dbmp_cleanup(db, NULL, path);
    return failures;
}

static int t_dbmp_checkpoint_refusals(void)
{
    int failures = 0;
    sqlite3_vfs *real = sqlite3_vfs_find(NULL);
    DBMP_CHECK("checkpoint fixture VFS exists", real != NULL);
    if (!real) return failures;
    sqlite3_vfs vfs = *real;
    vfs.zName = "dbmp-reset-failure";
    vfs.pAppData = real;
    vfs.xOpen = dbmp_open;
    int registered = sqlite3_vfs_register(&vfs, 0);
    DBMP_CHECK("checkpoint fixture VFS registers", registered == SQLITE_OK);
    if (registered != SQLITE_OK) return failures;
    failures += dbmp_refusal_fixture(vfs.zName);
    DBMP_CHECK("fixture VFS unregisters", sqlite3_vfs_unregister(&vfs) == SQLITE_OK);
    return failures;
}

/* Only the main file is forwarded. Native VFS journal/WAL creation can
 * use fixed pathname buffers even when the wrapper advertises a larger
 * mxPathname. Seed the size witnesses separately; do not enter those paths. */
static sqlite3_vfs *long_path_base;

static int long_path_open(sqlite3_vfs *vfs, const char *name, sqlite3_file *file,
                          int flags, int *out_flags)
{
    (void)vfs;
    if (!(flags & SQLITE_OPEN_MAIN_DB) || !(flags & SQLITE_OPEN_READONLY))
        return SQLITE_CANTOPEN;
    return long_path_base->xOpen(long_path_base, name, file, flags, out_flags);
}

static int long_path_full(sqlite3_vfs *vfs, const char *name, int size, char *out)
{
    (void)vfs;
    size_t len = strlen(name);
    if (name[0] != '/' || size <= 0 || len >= (size_t)size)
        return SQLITE_CANTOPEN;
    memcpy(out, name, len + 1);
    return SQLITE_OK;
}

static bool long_path_seed(const char *path, const char *suffix)
{
    char name[1100];
    int n = snprintf(name, sizeof name, "%s%s", path, suffix);
    if (n < 0 || (size_t)n >= sizeof name)
        return false;
    FILE *file = fopen(name, "wb");
    if (!file)
        return false;
    bool wrote = fwrite("size witness", 1, 12, file) == 12;
    return fclose(file) == 0 && wrote;
}

static int t_wal_path_probe(sqlite3 *db, const char *path, size_t length)
{
    int failures = 0;
    const char *actual = sqlite3_db_filename(db, "main");
    DBMP_CHECK("exact returned filename", actual &&
               strlen(actual) == length && strcmp(actual, path) == 0);
    struct db_maintenance_sqlite_ctx ctx;
    struct db_maintenance_port port = {0};
    DBMP_CHECK("long-path bind", db_maintenance_sqlite_bind(&ctx, db, &port));
    int64_t bytes = 777;
    bool got = port.wal_size_bytes(port.self, &bytes);
    if (length == 1019) {
        DBMP_CHECK("fitting WAL exact size", got && bytes == 12);
    } else {
        DBMP_CHECK("oversized WAL path refuses", !got);
        DBMP_CHECK("refusal preserves sentinel", bytes == 777);
    }
    return failures;
}

static int t_wal_path_case(const char *dir, size_t length, const char *vfs_name)
{
    int failures = 0;
    char path[1100], truncated[1024];
    size_t len = strlen(dir);
    bool bounded = len < length && length <= 1023 && length - len - 1 <= 250;
    DBMP_CHECK("bounded long-path components", bounded);
    if (!bounded) return failures;
    memcpy(path, dir, len);
    path[len] = '/';
    memset(path + len + 1, 'p', length - len - 1);
    path[length] = 0;
    /* Nonempty real files make the mutant return true at every refusal
     * boundary, including 1020 where truncation leaves the suffix '-wa'.
     * sqlite3_open_v2 does not read the schema; no SQL is run on witnesses. */
    DBMP_CHECK("main size witness created", long_path_seed(path, ""));
#if defined(__APPLE__)
    /* Darwin PATH_MAX is 1024 including the NUL: a -wal name longer than 1023
     * bytes cannot exist, and creating it must be refused by the kernel. */
    bool wal_can_exist = length + strlen("-wal") < (size_t)PATH_MAX;
#else
    bool wal_can_exist = true;
#endif
    errno = 0;
    bool wal_seeded = long_path_seed(path, "-wal");
    int wal_errno = errno;
    DBMP_CHECK("WAL size witness created exactly when the name can exist",
               wal_seeded == wal_can_exist);
    DBMP_CHECK("an impossible WAL witness is refused for its path length",
               wal_can_exist || wal_errno == ENAMETOOLONG);
    memcpy(truncated, path, length);
    size_t suffix = 1023 - length;
    memcpy(truncated + length, "-wal", suffix);
    truncated[1023] = 0;
    if (length != 1019)
        DBMP_CHECK("truncated-path witness created", long_path_seed(truncated, ""));
    sqlite3 *db = NULL;
    bool opened = sqlite3_open_v2(path, &db, SQLITE_OPEN_READONLY, vfs_name) == SQLITE_OK;
    DBMP_CHECK("long-path DB opens", opened);
    if (opened) failures += t_wal_path_probe(db, path, length);
    DBMP_CHECK("long-path DB closes", !db || sqlite3_close(db) == SQLITE_OK);
    clean_file_db(NULL, path);
    if (length != 1019 && length != 1023)
        DBMP_CHECK("truncated-path witness removed", unlink(truncated) == 0);
    DBMP_CHECK("long-path files removed", access(path, F_OK) != 0 && wal_file_size(path) < 0);
    return failures;
}

static bool long_path_directory(char *dir, char *root, size_t capacity)
{
    if (!test_mkdtemp(dir, capacity, "dbmp_bounds")) return false;
    memcpy(root, dir, strlen(dir) + 1);
    size_t len = strlen(dir);
    if (len > 850) return false;
    while (len < 848) {
        size_t part = 850 - len - 1;
        if (part > 180) part = 180;
        dir[len++] = '/';
        memset(dir + len, 'd', part);
        len += part;
        dir[len] = 0;
        if (mkdir(dir, 0700) != 0) {
            *strrchr(dir, '/') = 0;
            return false;
        }
    }
    return true;
}

static int long_path_cleanup(char *dir, const char *root)
{
    int failures = 0;
    while (strlen(dir) > strlen(root)) {
        DBMP_CHECK("fixture directory removed", rmdir(dir) == 0);
        *strrchr(dir, '/') = 0;
    }
    DBMP_CHECK("fixture root removed", rmdir(root) == 0);
    return failures;
}

static int t_wal_path_bounds(void)
{
    int failures = 0;
    char dir[1100] = "", root[1100] = "";
    bool ready = long_path_directory(dir, root, sizeof dir);
    DBMP_CHECK("long-path fixture ready", ready);
    if (!root[0]) return failures;
    long_path_base = sqlite3_vfs_find(NULL);
    sqlite3_vfs vfs = {0};
    bool registered = false;
    if (ready && long_path_base) {
        vfs = *long_path_base;
        vfs.pNext = NULL;
        vfs.zName = "dbmp-long-path";
        vfs.mxPathname = 4096;
        vfs.xOpen = long_path_open;
        vfs.xFullPathname = long_path_full;
        registered = sqlite3_vfs_register(&vfs, 0) == SQLITE_OK;
    }
    DBMP_CHECK("long-path VFS registered", registered);
    const size_t lengths[] = {1019, 1020, 1023};
    for (size_t i = 0; registered && i < 3; ++i)
        failures += t_wal_path_case(dir, lengths[i], vfs.zName);
    if (registered)
        DBMP_CHECK("fixture VFS removed", sqlite3_vfs_unregister(&vfs) == SQLITE_OK);
    failures += long_path_cleanup(dir, root);
    return failures;
}

int test_db_maintenance_port(void)
{
    int failures = 0;

    /* ---- each op succeeds on a real WAL-mode file DB ---- */
    {
        char path[256];
        sqlite3 *db = NULL;
        DBMP_CHECK("file db builds", make_file_db(&db, path, sizeof path));

        struct db_maintenance_sqlite_ctx ctx;
        struct db_maintenance_port port = {0};
        DBMP_CHECK("bind ok",
                   db_maintenance_sqlite_bind(&ctx, db, &port));

        char err[256] = "sentinel";
        struct db_maintenance_wal_outcome wal = {0};
        DBMP_CHECK("wal_checkpoint ok",
                   port.wal_checkpoint(port.self, &wal, err, sizeof err));
        DBMP_CHECK("wal_checkpoint clears err on success", err[0] == 0);

        /* The TRUNCATE checkpoint flushes WAL frames into the main file
         * and truncates the WAL back to zero bytes. */
        DBMP_CHECK("wal_checkpoint truncated WAL to 0",
                   wal_file_size(path) == 0);

        /* The counts are the point: a checkpoint that drained a non-empty WAL
         * must be DISTINGUISHABLE from one that moved nothing. Both report
         * success, so only these numbers separate them. */
        DBMP_CHECK("wal_checkpoint reports frames moved",
                   wal.ckpt_frames > 0);
        DBMP_CHECK("wal_checkpoint drained the whole log",
                   wal.ckpt_frames >= wal.log_frames);
        DBMP_CHECK("wal_checkpoint was not busy", !wal.busy);
        DBMP_CHECK("wal_checkpoint records SQLITE_OK", wal.rc == SQLITE_OK);
        DBMP_CHECK("wal_checkpoint records file reset",
                   wal.truncate_rc == SQLITE_OK && wal.truncated);
        DBMP_CHECK("a drain classifies as drained",
                   wal_ckpt_classify(true, wal.busy, wal.log_frames,
                                     wal.ckpt_frames) == WAL_CKPT_DRAINED);

        /* Immediately re-checkpointing an already-drained WAL moves zero
         * frames. That is a NO-OP, and it must not read as a drain of a WAL
         * that had something in it. */
        struct db_maintenance_wal_outcome again = {0};
        DBMP_CHECK("second checkpoint also succeeds",
                   port.wal_checkpoint(port.self, &again, err, sizeof err));
        DBMP_CHECK("second checkpoint moved nothing",
                   again.ckpt_frames == 0 && again.log_frames == 0);

        strcpy(err, "sentinel");
        DBMP_CHECK("analyze ok", port.analyze(port.self, err, sizeof err));
        DBMP_CHECK("analyze clears err", err[0] == '\0');

        strcpy(err, "sentinel");
        DBMP_CHECK("vacuum ok", port.vacuum(port.self, err, sizeof err));
        DBMP_CHECK("vacuum clears err", err[0] == '\0');

        clean_file_db(db, path);
    }

    failures += t_wal_size_commits();

    /* ---- wal_size_bytes: in-memory has no on-disk path -> false ---- */
    {
        sqlite3 *db = NULL;
        DBMP_CHECK("memdb opens",
                   sqlite3_open(":memory:", &db) == SQLITE_OK && db);
        struct db_maintenance_sqlite_ctx ctx;
        struct db_maintenance_port port = {0};
        db_maintenance_sqlite_bind(&ctx, db, &port);
        int64_t bytes = 12345;
        DBMP_CHECK("wal_size in-memory false",
                   !port.wal_size_bytes(port.self, &bytes));
        DBMP_CHECK("wal_size untouched on false", bytes == 12345);
        sqlite3_close(db);
    }

    /* ---- ops on an in-memory DB still succeed (no WAL file) ---- */
    {
        sqlite3 *db = NULL;
        DBMP_CHECK("memdb opens (ops)",
                   sqlite3_open(":memory:", &db) == SQLITE_OK && db);
        (void)exec_sql(db,
            "CREATE TABLE kv(k INTEGER PRIMARY KEY, v BLOB);"
            "INSERT INTO kv VALUES(1, randomblob(64));");
        struct db_maintenance_sqlite_ctx ctx;
        struct db_maintenance_port port = {0};
        db_maintenance_sqlite_bind(&ctx, db, &port);
        char err[256];
        /* A non-WAL connection has no log to reclaim; the engine reports the
         * frame counts as unknown rather than as zero, and the outcome is
         * UNKNOWN — never a claimed drain. */
        struct db_maintenance_wal_outcome wal = {0};
        DBMP_CHECK("memdb wal_checkpoint ok",
                   port.wal_checkpoint(port.self, &wal, err, sizeof err));
        DBMP_CHECK("memdb wal_checkpoint reports unknown counts",
                   wal.log_frames < 0 && wal.ckpt_frames < 0 && !wal.busy);
        DBMP_CHECK("unknown counts never classify as a drain",
                   wal_ckpt_classify(true, false, wal.log_frames,
                                     wal.ckpt_frames) == WAL_CKPT_UNKNOWN);
        DBMP_CHECK("memdb analyze ok",
                   port.analyze(port.self, err, sizeof err));
        DBMP_CHECK("memdb vacuum ok",
                   port.vacuum(port.self, err, sizeof err));
        sqlite3_close(db);
    }

    /* ---- NULL / bad-arg guards ---- */
    {
        struct db_maintenance_sqlite_ctx ctx;
        struct db_maintenance_port port = {0};

        DBMP_CHECK("bind rejects NULL ctx",
                   !db_maintenance_sqlite_bind(NULL, (sqlite3 *)0x1, &port));
        DBMP_CHECK("bind rejects NULL out_port",
                   !db_maintenance_sqlite_bind(&ctx, (sqlite3 *)0x1, NULL));

        /* NULL connection is legal at bind; ops then return false with a
         * filled error buffer and wal_size returns false untouched. */
        DBMP_CHECK("bind NULL conn ok",
                   db_maintenance_sqlite_bind(&ctx, NULL, &port));
        char err[256] = "";
        struct db_maintenance_wal_outcome wal = {0};
        DBMP_CHECK("wal_checkpoint NULL db false",
                   !port.wal_checkpoint(port.self, &wal, err, sizeof err));
        DBMP_CHECK("wal_checkpoint NULL db fills err", err[0] != 0);
        DBMP_CHECK("wal_checkpoint NULL db reports unknown counts",
                   wal.log_frames == -1 && wal.ckpt_frames == -1);
        DBMP_CHECK("wal_checkpoint NULL db records misuse",
                   wal.rc == SQLITE_MISUSE && wal.truncate_rc == -1 &&
                   !wal.truncated);
        DBMP_CHECK("analyze NULL db false",
                   !port.analyze(port.self, err, sizeof err));
        DBMP_CHECK("vacuum NULL db false",
                   !port.vacuum(port.self, err, sizeof err));
        int64_t bytes = 7;
        DBMP_CHECK("wal_size NULL db false",
                   !port.wal_size_bytes(port.self, &bytes));
        DBMP_CHECK("wal_size untouched on NULL db", bytes == 7);

        /* NULL self. */
        DBMP_CHECK("wal_checkpoint NULL self false",
                   !port.wal_checkpoint(NULL, &wal, err, sizeof err));
        DBMP_CHECK("wal_size NULL self false",
                   !port.wal_size_bytes(NULL, &bytes));

        /* NULL err buffer is tolerated (op runs; error path just can't
         * report text). NULL out for wal_size returns false. */
        struct db_maintenance_sqlite_ctx ctx2;
        struct db_maintenance_port port2 = {0};
        db_maintenance_sqlite_bind(&ctx2, NULL, &port2);
        DBMP_CHECK("wal_checkpoint NULL err tolerated (still false)",
                   !port2.wal_checkpoint(port2.self, NULL, NULL, 0));
        DBMP_CHECK("wal_size NULL out false",
                   !port2.wal_size_bytes(port2.self, NULL));
    }

    /* Root-body direct calls to the pure classifier (registered-root
     * reachability binds these to the exact definition). */
    TEST("wal_ckpt_classify: direct ranking against the exact definition") {
        ASSERT_EQ(wal_ckpt_classify(true, true, 3, 3), WAL_CKPT_BUSY);
        ASSERT_EQ(wal_ckpt_classify(false, false, 3, 3), WAL_CKPT_ERROR);
        ASSERT_EQ(wal_ckpt_classify(true, false, -1, -1), WAL_CKPT_UNKNOWN);
        ASSERT_EQ(wal_ckpt_classify(true, false, 0, 0), WAL_CKPT_DRAINED);
        ASSERT_EQ(wal_ckpt_classify(true, false, 5, 0), WAL_CKPT_NOOP);
        ASSERT_EQ(wal_ckpt_classify(true, false, 5, 3), WAL_CKPT_PARTIAL);
        PASS();
    } _test_next:;

    failures += t_wal_path_bounds();
    failures += t_dbmp_checkpoint_refusals();
    failures += t_wal_ckpt_classify_ranking();
    failures += t_wal_ckpt_classify_unknown();
    failures += t_wal_ckpt_classify_counts();

    return failures;
}
