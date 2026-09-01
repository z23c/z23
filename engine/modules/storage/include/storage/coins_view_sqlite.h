/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

#ifndef ZCL_COINS_VIEW_SQLITE_H
#define ZCL_COINS_VIEW_SQLITE_H

#include "coins/coins_view.h"
#include "coins/utxo_commitment.h"
#include <sqlite3.h>
#include <stdbool.h>
#include <stdint.h>
#include <pthread.h>

struct coins_view_sqlite {
    struct coins_view view;          /* vtable-based polymorphism */
    sqlite3 *db; /* coins handle — dedicated for file DBs, shared for :memory: */
    bool owns_db;                    /* true when db was opened here (file DB); false when shared */
    pthread_mutex_t mutex;           /* serialize all statement access */

    /* Prepared statements (all on cvs->db) */
    sqlite3_stmt *stmt_get;          /* all vouts for a txid */
    sqlite3_stmt *stmt_have;         /* existence check */
    sqlite3_stmt *stmt_insert;       /* upsert single UTXO */
    sqlite3_stmt *stmt_delete_tx;    /* delete all vouts for txid */
    sqlite3_stmt *stmt_best_get;     /* read best block hash */
    sqlite3_stmt *stmt_best_set;     /* write best block hash */
    sqlite3_stmt *stmt_commit_get;   /* read UTXO commitment */
    sqlite3_stmt *stmt_commit_set;   /* write UTXO commitment */
};

/* Open coins view. If `db` is file-backed (`sqlite3_db_filename` returns
 * a non-empty path), opens a dedicated sqlite3 handle on that same file
 * so the flush's BEGIN IMMEDIATE runs on an independent `nVdbeWrite`
 * counter — avoids a stall where SAVEPOINT on a shared
 * handle fails with "SQL statements in progress" whenever any other
 * subsystem has a writer VDBE mid-execution.
 * `:memory:` handles fall back to the shared connection with SAVEPOINT
 * nesting (used by a handful of unit tests that pass a throwaway DB). */
bool coins_view_sqlite_open(struct coins_view_sqlite *cvs, sqlite3 *db);
void coins_view_sqlite_close(struct coins_view_sqlite *cvs);

/* coins_view vtable implementations */
bool coins_view_sqlite_get_coins(struct coins_view_sqlite *cvs,
                                  const struct uint256 *txid,
                                  struct coins *out);
bool coins_view_sqlite_have_coins(struct coins_view_sqlite *cvs,
                                   const struct uint256 *txid);
bool coins_view_sqlite_get_best_block(struct coins_view_sqlite *cvs,
                                       struct uint256 *hash);
/* Flush dirty UTXO entries and optionally persist the path commitment in the
 * same transaction. Pass NULL for `commit` when only the coins_best_block
 * anchor should be updated. */
bool coins_view_sqlite_batch_write( // one-write-path-ok:coins-sqlite-writer-contract
    struct coins_view_sqlite *cvs, struct coins_map *map_coins,
    const struct uint256 *hash_block, const struct utxo_commitment *commit);

/* UTXO commitment persistence */
bool coins_view_sqlite_read_commitment(struct coins_view_sqlite *cvs,
                                        struct utxo_commitment *uc);

/* Rewind stale UTXO/tx_index rows above a selected chain tip and clear the
 * persisted UTXO commitment in one transaction.
 *
 * max_rows >= 0: bounded auto-heal mode. Refuses unless rows above tip are
 * confined to exactly tip_height+1 and count <= max_rows.
 * max_rows < 0: unbounded explicit prune mode for recovery paths that already
 * selected a replacement tip.
 *
 * Returns deleted UTXO rows (height + txid sweep), 0 when no above-tip rows
 * exist, or -1 on guard refusal / SQL failure. */
int coins_rewind_above_tip(sqlite3 *db, int64_t tip_height, int64_t max_rows);

#endif
