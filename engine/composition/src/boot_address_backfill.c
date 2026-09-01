/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Background explorer address-table backfill.
 *
 * Part of the boot composition root (engine/composition/src/), extracted from
 * boot_index.c. Owns exactly one thing: the one-shot background thread
 * that aggregates the explorer `addresses` table from the SQLite UTXO
 * set. It opens its own read/write sqlite handle, shares no file-scope
 * state with any other boot unit, and writes only the explorer
 * `addresses` table + the `addresses_backfilled` node_state marker — no
 * consensus state is touched. */

#include "platform/time_compat.h"
#include "config/boot_internal.h"
#include "util/log_macros.h"
#include "util/ar_step_readonly.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sqlite3.h>

/* ── Background address backfill from UTXOs ────────────────── */

/* One-shot background worker: aggregate the explorer `addresses` table
 * from the SQLite UTXO set. `arg` is a `const char *` SQLite db_path
 * whose backing string must outlive this thread. Returns NULL. */
void *backfill_addresses_thread(void *arg)
{
    const char *db_path = (const char *)arg;
    sqlite3 *db = NULL;
    if (sqlite3_open_v2(db_path, &db, SQLITE_OPEN_READWRITE, NULL) != SQLITE_OK) {
        printf("Address backfill: failed to open db\n");
        return NULL;
    }

    /* Disable mmap entirely for this background thread.
     * The previous mmap_size=64MB caused SIGSEGV after ~64K addresses:
     * when the main thread writes via WAL, the kernel may invalidate
     * mmap pages that this thread's sort cursor is scanning, triggering
     * a fault in SQLite's mmap read path. With mmap_size=0, SQLite
     * falls back to read() which is safe under concurrent WAL writes.
     * Performance is irrelevant — this is a one-time background job. */
    sqlite3_exec(db, "PRAGMA mmap_size=0", NULL, NULL, NULL);
    sqlite3_busy_timeout(db, 60000);
    /* Reduce temp store pressure — force temp tables to disk */
    sqlite3_exec(db, "PRAGMA temp_store=FILE", NULL, NULL, NULL);
    /* Use a modest cache to avoid memory bloat during aggregation */
    sqlite3_exec(db, "PRAGMA cache_size=-32768", NULL, NULL, NULL); /* 32MB */

    printf("Address backfill: aggregating UTXOs...\n");
    fflush(stdout);
    int64_t t0 = (int64_t)platform_time_wall_time_t();

    /* Ensure addresses table exists (it should, but be safe) */
    sqlite3_exec(db,
        "CREATE TABLE IF NOT EXISTS addresses ("
        "address_hash BLOB PRIMARY KEY,"
        "script_type INTEGER NOT NULL DEFAULT 0,"
        "balance INTEGER NOT NULL DEFAULT 0,"
        "utxo_count INTEGER NOT NULL DEFAULT 0,"
        "first_seen_height INTEGER NOT NULL DEFAULT 0,"
        "last_seen_height INTEGER NOT NULL DEFAULT 0"
        ")", NULL, NULL, NULL);

    sqlite3_exec(db,
        "CREATE INDEX IF NOT EXISTS idx_utxo_address"
        " ON utxos(address_hash) WHERE address_hash IS NOT NULL",
        NULL, NULL, NULL);

    /* Process in batches using a cursor over distinct address_hash values.
     * The old single-query approach (INSERT SELECT GROUP BY over 1.3M UTXOs)
     * caused SIGSEGV after ~64K addresses due to SQLite sort buffer / mmap
     * memory pressure. Batching keeps peak memory bounded. */
    int rc;
    int64_t processed = 0;
    static const int BATCH_SIZE = 10000;

    sqlite3_exec(db, "BEGIN", NULL, NULL, NULL);

    sqlite3_stmt *cursor = NULL;
    rc = sqlite3_prepare_v2(db,
        "SELECT DISTINCT address_hash FROM utxos "
        "WHERE address_hash IS NOT NULL "
        "ORDER BY address_hash",
        -1, &cursor, NULL);
    if (rc != SQLITE_OK || !cursor) {
        fprintf(stderr, "Address backfill: failed to prepare cursor: %s\n",
                sqlite3_errmsg(db));
        sqlite3_exec(db, "ROLLBACK", NULL, NULL, NULL);
        sqlite3_close(db);
        return NULL;
    }

    sqlite3_stmt *upsert = NULL;
    rc = sqlite3_prepare_v2(db,
        "INSERT OR REPLACE INTO addresses "
        "(address_hash, script_type, balance, utxo_count, "
        "first_seen_height, last_seen_height) "
        "SELECT address_hash, MAX(script_type), SUM(value), count(*), "
        "MIN(height), MAX(height) "
        "FROM utxos WHERE address_hash = ?1",
        -1, &upsert, NULL);
    if (rc != SQLITE_OK || !upsert) {
        fprintf(stderr, "Address backfill: failed to prepare upsert: %s\n",
                sqlite3_errmsg(db));
        sqlite3_finalize(cursor);
        sqlite3_exec(db, "ROLLBACK", NULL, NULL, NULL);
        sqlite3_close(db);
        return NULL;
    }

    while ((rc = AR_STEP_ROW_READONLY(cursor)) == SQLITE_ROW) {
        const void *addr_hash = sqlite3_column_blob(cursor, 0);
        int addr_len = sqlite3_column_bytes(cursor, 0);
        if (!addr_hash || addr_len <= 0)
            continue;

        sqlite3_reset(upsert);
        sqlite3_bind_blob(upsert, 1, addr_hash, addr_len, SQLITE_STATIC);
        AR_STEP_WRITE(upsert);
        processed++;

        /* Commit every BATCH_SIZE rows to release locks and memory */
        if (processed % BATCH_SIZE == 0) {
            sqlite3_exec(db, "COMMIT", NULL, NULL, NULL);
            sqlite3_exec(db, "BEGIN", NULL, NULL, NULL);
            if (processed % 100000 == 0) {
                printf("Address backfill: %lld addresses processed...\n",
                       (long long)processed);
                fflush(stdout);
            }
        }
    }

    sqlite3_finalize(cursor);
    sqlite3_finalize(upsert);
    sqlite3_exec(db, "COMMIT", NULL, NULL, NULL);

    int64_t elapsed = (int64_t)platform_time_wall_time_t() - t0;

    sqlite3_exec(db,
        "INSERT OR REPLACE INTO node_state(key,value) "
        "VALUES('addresses_backfilled', X'01')", NULL, NULL, NULL);

    sqlite3_close(db);
    printf("Address backfill: %lld addresses in %llds\n",
           (long long)processed, (long long)elapsed);
    fflush(stdout);
    return NULL;
}
