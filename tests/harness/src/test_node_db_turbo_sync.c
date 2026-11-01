/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * node_db_turbo_sync: bulk-sync mode must still sync the database file before
 * the write-ahead log is reset. With synchronous=OFF a checkpoint folds the
 * log into the database and discards the log without syncing either, so a
 * power failure afterwards can take back writes that had been acknowledged,
 * including a wallet record handed out to a payer. The probe VFS sees the
 * order a clean close cannot. */

#include "test/test_core.h"
#include "test/test_sync_probe_vfs.h"
#include "models/database.h"

#include <limits.h>
#include <sqlite3.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

static bool tts_exec(struct node_db *ndb, const char *sql)
{
    return sqlite3_exec(ndb->db, sql, NULL, NULL, NULL) == SQLITE_OK;
}

static bool tts_rows(struct node_db *ndb, int first, int count)
{
    sqlite3_stmt *s = NULL;
    if (sqlite3_prepare_v2(ndb->db, "INSERT INTO tts_t(id,pad) VALUES(?,?)",
                           -1, &s, NULL) != SQLITE_OK)
        return false;
    static const char pad[1024] = { 'x' };
    bool ok = tts_exec(ndb, "BEGIN IMMEDIATE");
    for (int i = 0; ok && i < count; i++) {
        sqlite3_reset(s);
        sqlite3_bind_int(s, 1, first + i);
        sqlite3_bind_blob(s, 2, pad, (int)sizeof(pad), SQLITE_STATIC);
        ok = sqlite3_step(s) == SQLITE_DONE;
    }
    sqlite3_finalize(s);
    return ok && tts_exec(ndb, "COMMIT");
}

/* Wall time of `batches` committed batches of 200 KB at `level`, then one
 * checkpoint, in milliseconds. */
static double tts_bulk_ms(struct node_db *ndb, int level, int first,
                          int batches)
{
    char sql[40];
    snprintf(sql, sizeof(sql), "PRAGMA synchronous=%d", level);
    if (!tts_exec(ndb, sql))
        return -1;
    struct timespec t0, t1;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    for (int b = 0; b < batches; b++)
        if (!tts_rows(ndb, first + b * 200, 200))
            return -1;
    if (!node_db_wal_checkpoint(ndb))
        return -1;
    clock_gettime(CLOCK_MONOTONIC, &t1);
    return (double)(t1.tv_sec - t0.tv_sec) * 1e3 +
           (double)(t1.tv_nsec - t0.tv_nsec) / 1e6;
}

int test_node_db_turbo_sync(void)
{
    int failures = 0;
    struct node_db ndb;
    memset(&ndb, 0, sizeof(ndb));
    bool vfs_on = false, db_on = false;
    char dir[PATH_MAX] = "", path[PATH_MAX + 16];
    printf("\n=== node_db turbo mode syncs before the log is reset ===\n");
    TEST("node_db_turbo_sync: database file is synced before the log truncates") {
        char cwd[PATH_MAX];
        ASSERT(getcwd(cwd, sizeof(cwd)) != NULL);
        snprintf(dir, sizeof(dir), "%s/test-tmp/tts_XXXXXX", cwd);
        ASSERT(test_mkdtemp(dir, sizeof(dir), "tts"));
        snprintf(path, sizeof(path), "%s/node.db", dir);
        ASSERT(spv_install());
        vfs_on = true;
        ASSERT(node_db_open(&ndb, path));
        db_on = true;
        ASSERT(tts_exec(&ndb, "CREATE TABLE tts_t(id INTEGER PRIMARY KEY,"
                              " pad BLOB)"));
        ASSERT(node_db_ibd_turbo_mode(&ndb));

        /* An explicit checkpoint, as the catch-up and the writer lane run. */
        ASSERT(tts_rows(&ndb, 1, 200));
        spv_reset();
        ASSERT(node_db_wal_checkpoint(&ndb));
        ASSERT(spv_first(SPV_TRUNC_WAL) >= 0);
        ASSERT(spv_first(SPV_SYNC_DB) >= 0);
        ASSERT(spv_first(SPV_SYNC_DB) < spv_first(SPV_TRUNC_WAL));

        /* An automatic checkpoint, triggered by the log size alone. */
        ASSERT(tts_exec(&ndb, "PRAGMA wal_autocheckpoint=20"));
        spv_reset();
        for (int b = 0; b < 4; b++)
            ASSERT(tts_rows(&ndb, 1000 + b * 50, 50));
        ASSERT(spv_count(SPV_SYNC_DB) > 0);
        PASS();
    } _test_next:;
    if (db_on) {
        double off = -1, normal = -1;
        if (tts_exec(&ndb, "PRAGMA wal_autocheckpoint=65536")) {
            off = tts_bulk_ms(&ndb, 0, 100000, 100);
            normal = tts_bulk_ms(&ndb, 1, 200000, 100);
        }
        printf("  bulk write, 20 MB then checkpoint: OFF %.1f ms, NORMAL "
               "%.1f ms\n", off, normal);
        node_db_close(&ndb);
    }
    if (vfs_on)
        spv_uninstall();
    if (dir[0])
        (void)test_rm_rf_recursive(dir);
    return failures;
}
