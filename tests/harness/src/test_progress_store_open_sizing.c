/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * progress_store open-time integrity gate: the quick_check that guards
 * consensus.db is sized (page cache + mmap window) BEFORE it scans, so a
 * multi-hundred-MB file is walked with kernel readahead instead of one
 * scattered 4 KiB pread per page.  The verdict must be unchanged: "ok" on an
 * intact file, not-ok on a damaged one, whatever the access path. */

#include "test/test_core.h"

#include "storage/progress_store.h"

#include <sqlite3.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

#define PO_CHECK(name, expr) do {                                      \
    if (expr) { printf("  ps_open_sizing: %s... OK\n", (name)); }       \
    else { printf("  ps_open_sizing: %s... FAIL\n", (name)); failures++; } \
} while (0)

static int64_t po_pragma(sqlite3 *db, const char *sql)
{
    sqlite3_stmt *st = NULL;
    int64_t v = INT64_MIN;
    if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) != SQLITE_OK) return v;
    if (sqlite3_step(st) == SQLITE_ROW) v = sqlite3_column_int64(st, 0);
    sqlite3_finalize(st);
    return v;
}

static bool po_build(const char *path)
{
    sqlite3 *db = NULL;
    if (sqlite3_open(path, &db) != SQLITE_OK) return false;
    bool ok = sqlite3_exec(db,
        "CREATE TABLE t(k INTEGER PRIMARY KEY, v BLOB);"
        "WITH RECURSIVE c(i) AS (SELECT 1 UNION ALL SELECT i+1 FROM c "
        "WHERE i<3000) INSERT INTO t SELECT i, randomblob(200) FROM c;",
        NULL, NULL, NULL) == SQLITE_OK;
    sqlite3_close(db);
    return ok;
}

static bool po_garble_page(const char *path)
{
    FILE *f = fopen(path, "r+b");
    if (!f) return false;
    uint8_t junk[4096];
    memset(junk, 0xEE, sizeof(junk));
    bool ok = fseek(f, 4096 * 3, SEEK_SET) == 0 &&
              fwrite(junk, 1, sizeof(junk), f) == sizeof(junk);
    fclose(f);
    return ok;
}

int test_progress_store_open_sizing(void)
{
    printf("\n=== progress_store open sizing tests ===\n");
    int failures = 0;
    char dir[256];
    test_make_tmpdir(dir, sizeof(dir), "ps_open_sizing", "gate");
    char path[300];
    snprintf(path, sizeof(path), "%s/fixture.db", dir);
    PO_CHECK("fixture built", po_build(path));

    sqlite3 *db = NULL;
    PO_CHECK("fixture opens",
             sqlite3_open_v2(path, &db, SQLITE_OPEN_READWRITE, NULL) ==
             SQLITE_OK);
    int64_t mmap_before = po_pragma(db, "PRAGMA mmap_size");
    int64_t cache_before = po_pragma(db, "PRAGMA cache_size");
    PO_CHECK("fresh connection has no mmap window", mmap_before == 0);
    PO_CHECK("intact file: gate passes",
             progress_store_quick_check_for_test(db));
    PO_CHECK("gate sized the mmap window before scanning",
             po_pragma(db, "PRAGMA mmap_size") > 0);
    PO_CHECK("gate sized the page cache before scanning",
             po_pragma(db, "PRAGMA cache_size") < cache_before);
    sqlite3_close(db);

    PO_CHECK("fixture garbled", po_garble_page(path));
    db = NULL;
    PO_CHECK("garbled fixture opens",
             sqlite3_open_v2(path, &db, SQLITE_OPEN_READWRITE, NULL) ==
             SQLITE_OK);
    PO_CHECK("damaged file: gate still refuses (verdict unchanged)",
             !progress_store_quick_check_for_test(db));
    sqlite3_close(db);

    test_cleanup_tmpdir(dir);
    return failures;
}
