/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0
 *
 * test_sqlq — regressions for the sqlq read-only sqlite query CLI
 * (tools/sqlq.c, built as build/bin/sqlq by `make sqlq`).
 *
 * Python and the sqlite3 CLI are both absent on a stock host; sqlq is how
 * an operator or script inspects the node's sqlite stores (the kernel
 * store's stage cursors, node.db tables, copied fixture datadirs). These
 * cases pin the exact output contract — rows tab-separated, NULL as the
 * literal "NULL", BLOBs as lowercase hex — and the read-only refusal:
 * anything that is not SELECT/PRAGMA, an unreadable path, or a SQL error
 * exits 1 and never writes. */

#include "test/test_core.h"
#include "test/host_tool_capture.h"

#include <sqlite3.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#if !defined(_WIN32)
#include <unistd.h>
#endif

#if defined(_WIN32)
#define SQLQ_BIN "build/bin/sqlq.exe"
#define SQLQ_EOL "\r\n"
#else
#define SQLQ_BIN "build/bin/sqlq"
#define SQLQ_EOL "\n"
#endif

static int sqlq_run(const char *db_path, const char *sql,
                    char *buf, size_t cap)
{
    const char *argv[] = {SQLQ_BIN, db_path, sql, NULL};
    return test_host_tool_capture(argv, buf, cap, 5000);
}

/* One small fixture database: an integer, a text, a blob, and a NULL,
 * plus a second row, so column typing and row ordering are both pinned. */
static bool sqlq_fixture(const char *dir, char *db_path, size_t db_path_cap)
{
    int n = snprintf(db_path, db_path_cap, "%s/fixture.db", dir);
    if (n <= 0 || (size_t)n >= db_path_cap) return false;
    sqlite3 *db = NULL;
    if (sqlite3_open(db_path, &db) != SQLITE_OK) {
        if (db) sqlite3_close(db);
        return false;
    }
    const char *ddl =
        "CREATE TABLE t(id INTEGER PRIMARY KEY, name TEXT, payload BLOB, "
        "note TEXT);"
        "INSERT INTO t VALUES(1, 'alpha', x'00ff10', NULL);"
        "INSERT INTO t VALUES(2, 'bravo', x'7f', 'done');";
    bool ok = sqlite3_exec(db, ddl, NULL, NULL, NULL) == SQLITE_OK;
    sqlite3_close(db);
    return ok;
}

static int test_sqlq_rows_and_typing(void)
{
    int failures = 0;
    char dir[4096], db[4608], buf[1024] = {0};
    test_make_tmpdir(dir, sizeof(dir), "sqlq", "rows");
    TEST("sqlq: rows are tab-separated; NULL and BLOB keep their contract") {
        ASSERT(sqlq_fixture(dir, db, sizeof(db)));
        ASSERT(sqlq_run(db, "SELECT id, name, payload, note FROM t ORDER BY id",
                        buf, sizeof(buf)) == 0);
        ASSERT(strcmp(buf, "1\talpha\t00ff10\tNULL" SQLQ_EOL
                           "2\tbravo\t7f\tdone" SQLQ_EOL) ==
               0);
        /* Empty results are a clean exit with no output. */
        buf[0] = 0;
        ASSERT(sqlq_run(db, "SELECT id FROM t WHERE id > 99",
                        buf, sizeof(buf)) == 0);
        ASSERT(strcmp(buf, "") == 0);
        /* PRAGMA is the second permitted read-only statement. */
        ASSERT(sqlq_run(db, "PRAGMA user_version", buf, sizeof(buf)) == 0);
        ASSERT(strcmp(buf, "0" SQLQ_EOL) == 0);
        PASS();
    } _test_next:;
    (void)test_rm_rf_recursive(dir);
    return failures;
}

static int test_sqlq_refusals(void)
{
    int failures = 0;
    char dir[4096], db[4608], missing[4608], buf[256] = {0};
    test_make_tmpdir(dir, sizeof(dir), "sqlq", "refusals");
    TEST("sqlq: writes, missing databases, and bad SQL all refuse with exit 1") {
        ASSERT(sqlq_fixture(dir, db, sizeof(db)));
        /* Ordinary writes are refused by the statement prefix guard. */
        ASSERT(sqlq_run(db, "DELETE FROM t", buf, sizeof(buf)) == 1);
        ASSERT(sqlq_run(db, "INSERT INTO t VALUES(3, 'x', x'00', 'y')",
                        buf, sizeof(buf)) == 1);
        /* PRAGMA passes the prefix guard, but persistent writes must still
         * refuse at SQLite's read-only connection boundary. */
        ASSERT(sqlq_run(db, "PRAGMA user_version=7", buf, sizeof(buf)) == 1);
        ASSERT(sqlq_run(db, "PRAGMA user_version", buf, sizeof(buf)) == 0);
        ASSERT(strcmp(buf, "0" SQLQ_EOL) == 0);
        /* Syntax errors refuse after prepare, not as a crash. */
        ASSERT(sqlq_run(db, "SELECT FROM WHERE", buf, sizeof(buf)) == 1);
        /* A missing database file is exit 1, never creation. */
        int n = snprintf(missing, sizeof(missing), "%s/missing.db", dir);
        ASSERT(n > 0 && (size_t)n < sizeof(missing));
        struct stat st;
        ASSERT(stat(missing, &st) != 0);
        ASSERT(sqlq_run(missing, "SELECT 1",
                        buf, sizeof(buf)) == 1);
        ASSERT(stat(missing, &st) != 0);
        /* The fixture survived every refusal attempt. */
        ASSERT(sqlq_run(db, "SELECT COUNT(*) FROM t", buf, sizeof(buf)) == 0);
        ASSERT(strcmp(buf, "2" SQLQ_EOL) == 0);
        PASS();
    } _test_next:;
    (void)test_rm_rf_recursive(dir);
    return failures;
}

static int test_sqlq_statement_tail(void)
{
    int failures = 0;
    char dir[4096], db[4608], buf[256] = {0};
    test_make_tmpdir(dir, sizeof(dir), "sqlq", "tail");
    TEST("sqlq: trailing SQL refuses before any result is printed") {
        ASSERT(sqlq_fixture(dir, db, sizeof(db)));
        const char *bad[] = {
            "SELECT 1; SELECT 2", "SELECT 1; SELECT FROM WHERE",
            "SELECT 1; DELETE FROM t", "PRAGMA user_version; SELECT 2",
            "SELECT 1; /* comment */ SELECT 2", "SELECT 1; -- comment\n SELECT 2",
            "SELECT 1; ; garbage", "SELECT 1; /", "SELECT 1; -"
        };
        for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
            ASSERT(sqlq_run(db, bad[i], buf, sizeof(buf)) == 1);
            ASSERT(strcmp(buf, "") == 0);
        }
        const char *good[] = {
            "SELECT 1;", "SELECT 1; \t\r\n; ;",
            "SELECT 1; -- SELECT 2", "SELECT 1; /* SELECT 2 */ ; -- end",
            "SELECT 1; /* unterminated comment", "SELECT 1 /* ; SELECT 2 */"
        };
        for (size_t i = 0; i < sizeof(good) / sizeof(good[0]); i++) {
            ASSERT(sqlq_run(db, good[i], buf, sizeof(buf)) == 0);
            ASSERT(strcmp(buf, "1" SQLQ_EOL) == 0);
        }
        ASSERT(sqlq_run(db, "SELECT COUNT(*) FROM t", buf, sizeof(buf)) == 0);
        ASSERT(strcmp(buf, "2" SQLQ_EOL) == 0);
        ASSERT(sqlq_run(db, "SELECT '; SELECT 2'; -- end", buf, sizeof(buf)) == 0);
        ASSERT(strcmp(buf, "; SELECT 2" SQLQ_EOL) == 0);
        PASS();
    } _test_next:;
    (void)test_rm_rf_recursive(dir);
    return failures;
}

#if !defined(_WIN32)
/* One query, two spellings past the link: a link named sqlq in a temp dir
 * (argv0 dispatch in z23) and `z23 sqlq` (argv+1). Both must print the
 * same rows as the standalone binary. */
static int test_sqlq_multicall_names(void)
{
    int failures = 0;
    char dir[4096], db[4608], cwd[PATH_MAX], target[PATH_MAX + 32];
    char alias[4608], buf[1024] = {0};
    const char *sql = "SELECT id, name FROM t ORDER BY id";
    const char *expect = "1\talpha" SQLQ_EOL "2\tbravo" SQLQ_EOL;
    test_make_tmpdir(dir, sizeof(dir), "sqlq", "alias");
    TEST("sqlq: argv0 link and z23 sqlq run the same query") {
        ASSERT(sqlq_fixture(dir, db, sizeof(db)));
        ASSERT(getcwd(cwd, sizeof(cwd)) != NULL);
        ASSERT(snprintf(target, sizeof(target), "%s/build/bin/z23", cwd) > 0);
        ASSERT(snprintf(alias, sizeof(alias), "%s/sqlq", dir) > 0);
        ASSERT(symlink(target, alias) == 0);
        const char *by_link[] = {alias, db, sql, NULL};
        ASSERT(test_host_tool_capture(by_link, buf, sizeof(buf), 5000) == 0);
        ASSERT(strcmp(buf, expect) == 0);
        buf[0] = 0;
        const char *by_sub[] = {"build/bin/z23", "sqlq", db, sql, NULL};
        ASSERT(test_host_tool_capture(by_sub, buf, sizeof(buf), 5000) == 0);
        ASSERT(strcmp(buf, expect) == 0);
        const char *bad_link[] = {alias, db, "SELECT 1; SELECT 2", NULL};
        ASSERT(test_host_tool_capture(bad_link, buf, sizeof(buf), 5000) == 1);
        ASSERT(strcmp(buf, "") == 0);
        const char *bad_sub[] = {"build/bin/z23", "sqlq", db,
                                 "SELECT 1; SELECT 2", NULL};
        ASSERT(test_host_tool_capture(bad_sub, buf, sizeof(buf), 5000) == 1);
        ASSERT(strcmp(buf, "") == 0);
        PASS();
    } _test_next:;
    (void)test_rm_rf_recursive(dir);
    return failures;
}
#endif

int test_sqlq(void)
{
    int failures = 0;
    struct stat st;
    if (stat(SQLQ_BIN, &st) != 0 || (st.st_mode & S_IXUSR) == 0) {
        fprintf(stderr, "sqlq: required build/bin/sqlq missing (run: make sqlq)\n");
        return 1;
    }
    failures += test_sqlq_rows_and_typing();
    failures += test_sqlq_refusals();
    failures += test_sqlq_statement_tail();
#if !defined(_WIN32)
    failures += test_sqlq_multicall_names();
#endif
    return failures;
}
