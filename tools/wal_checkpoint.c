/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * wal_checkpoint: standalone SQLite maintenance tool. It opens the database at
 * the given path, prints UTXO, block and max-height counts, runs a TRUNCATE WAL
 * checkpoint (falling back to PASSIVE) and optionally resets, marks or wipes
 * the leveldb UTXO migration state. Built by the Makefile tools/wal_checkpoint
 * target and run by the deploy sequence before SIGTERM. */

#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <db_path> [reset|mark_done]\n", argv[0]);
        return 1;
    }
    sqlite3 *db;
    int rc = sqlite3_open(argv[1], &db);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "Open failed: %s\n", sqlite3_errmsg(db));
        return 1;
    }

    sqlite3_stmt *s;
    sqlite3_prepare_v2(db, "SELECT COUNT(*) FROM utxos", -1, &s, NULL);
    if (sqlite3_step(s) == SQLITE_ROW) // raw-sql-ok:standalone-dev-tool
        printf("UTXOs: %lld\n", sqlite3_column_int64(s, 0));
    sqlite3_finalize(s);

    sqlite3_prepare_v2(db, "SELECT COUNT(*) FROM blocks", -1, &s, NULL);
    if (sqlite3_step(s) == SQLITE_ROW) // raw-sql-ok:standalone-dev-tool
        printf("Blocks: %lld\n", sqlite3_column_int64(s, 0));
    sqlite3_finalize(s);

    sqlite3_prepare_v2(db, "SELECT MAX(height) FROM blocks", -1, &s, NULL);
    if (sqlite3_step(s) == SQLITE_ROW) // raw-sql-ok:standalone-dev-tool
        printf("Max block height: %lld\n", sqlite3_column_int64(s, 0));
    sqlite3_finalize(s);

    printf("Checkpointing WAL...\n");
    int log_frames = 0, checkpointed = 0;
    rc = sqlite3_wal_checkpoint_v2(db, NULL, SQLITE_CHECKPOINT_TRUNCATE,
                                    &log_frames, &checkpointed);
    if (rc != SQLITE_OK) {
        rc = sqlite3_wal_checkpoint_v2(db, NULL, SQLITE_CHECKPOINT_PASSIVE,
                                        &log_frames, &checkpointed);
        printf("Passive checkpoint: rc=%d frames=%d checkpointed=%d\n",
               rc, log_frames, checkpointed);
    } else {
        printf("Checkpoint OK: %d frames, %d checkpointed\n",
               log_frames, checkpointed);
    }

    if (argc >= 3) {
        if (strcmp(argv[2], "reset") == 0) {
            printf("Resetting leveldb_utxo_migrated flag...\n");
            sqlite3_exec(db, "DELETE FROM node_state WHERE key='leveldb_utxo_migrated'",
                         NULL, NULL, NULL);
            printf("Done — will reimport on next boot.\n");
        } else if (strcmp(argv[2], "mark_done") == 0) {
            printf("Marking migration as done...\n");
            sqlite3_exec(db, "INSERT OR REPLACE INTO node_state(key,value) VALUES('leveldb_utxo_migrated', X'01')",
                         NULL, NULL, NULL);
            printf("Done.\n");
        } else if (strcmp(argv[2], "wipe_utxos") == 0) {
            printf("Wiping UTXOs...\n");
            sqlite3_exec(db, "DELETE FROM utxos", NULL, NULL, NULL);
            sqlite3_exec(db, "DELETE FROM node_state WHERE key='coins_best_block'", NULL, NULL, NULL);
            printf("Done — wiped %d rows.\n", sqlite3_changes(db));
        }
    }

    sqlite3_close(db);
    return 0;
}
