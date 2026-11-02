/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * progress_store open-time integrity gate: the quick_check that guards
 * consensus.db is sized (page cache + mmap window) BEFORE it scans, so a
 * multi-hundred-MB file is walked with kernel readahead instead of one
 * scattered 4 KiB pread per page.  The verdict must be unchanged: "ok" on an
 * intact file, not-ok on a damaged one, whatever the access path. */

#include "test/test_core.h"

#include "storage/progress_store.h"

#include <pthread.h>
#include <sqlite3.h>
#include <stdatomic.h>
#include <time.h>
#include <unistd.h>
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

static int test_progress_store_lock_order(void);

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
    return failures + test_progress_store_lock_order();
}

/* Lock order: tx_lock may be held when g_lock is taken, never the reverse.
 * Thread A holds tx_lock and asks progress_store_directory_matches_fd (g_lock)
 * while thread B runs a fresh open, whose finish checks need tx_lock.  If the
 * open held g_lock across those checks, A and B would deadlock. */
static void lo_sleep_ms(long ms)
{
    struct timespec ts = { ms / 1000, (ms % 1000) * 1000000L };
    nanosleep(&ts, NULL);
}

static _Atomic int lo_a_locked, lo_a_done, lo_b_started;
static const char *lo_dir;
static _Atomic int lo_open_ok;

static void *lo_thread_a(void *arg)
{
    (void)arg;
    progress_store_tx_lock();
    atomic_store(&lo_a_locked, 1);
    while (!atomic_load(&lo_b_started))
        lo_sleep_ms(1);
    lo_sleep_ms(500); /* let B reach the finish checks and block on tx_lock */
    int dummy = 0;
    (void)progress_store_directory_matches_fd((sqlite3 *)&dummy, 0);
    atomic_store(&lo_a_done, 1);
    progress_store_tx_unlock();
    return NULL;
}

static void *lo_thread_b(void *arg)
{
    (void)arg;
    atomic_store(&lo_b_started, 1);
    atomic_store(&lo_open_ok, progress_store_open(lo_dir) ? 1 : 0);
    return NULL;
}

static int test_progress_store_lock_order(void)
{
    printf("\n=== progress_store lock order tests ===\n");
    int failures = 0;
    char dir[256];
    test_make_tmpdir(dir, sizeof(dir), "ps_lock_order", "gate");
    lo_dir = dir;
    pthread_t a, b;
    pthread_create(&a, NULL, lo_thread_a, NULL);
    while (!atomic_load(&lo_a_locked))
        lo_sleep_ms(1);
    pthread_create(&b, NULL, lo_thread_b, NULL);
    for (int i = 0; i < 3000 && !atomic_load(&lo_a_done); i++)
        lo_sleep_ms(1);
    if (!atomic_load(&lo_a_done)) {
        printf("  ps_lock_order: matches_fd under tx_lock during open... "
               "FAIL (deadlock: open holds g_lock while taking tx_lock)\n");
        fflush(stdout);
        _exit(1);
    }
    PO_CHECK("matches_fd under tx_lock does not wait on a fresh open", true);
    pthread_join(a, NULL);
    pthread_join(b, NULL);
    PO_CHECK("concurrent fresh open succeeds", atomic_load(&lo_open_ok) == 1);
    PO_CHECK("store closes", progress_store_close_checked() ==
             PROGRESS_STORE_CLOSE_OK);
    test_cleanup_tmpdir(dir);
    return failures;
}
