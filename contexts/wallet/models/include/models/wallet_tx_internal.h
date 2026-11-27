/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 *
 * Internal helper contract shared by the wallet transaction, key and
 * Sapling note ActiveRecord model files. NOT part of the public
 * model API — controllers/services must include models/wallet_tx.h.
 *
 * This header keeps shared wallet row readers and aggregate helpers visible
 * only to the wallet model siblings that own those tables. */

#ifndef ZCL_DB_MODEL_WALLET_TX_INTERNAL_H
#define ZCL_DB_MODEL_WALLET_TX_INTERNAL_H

#include "models/wallet_tx.h"
#include <limits.h>
#include <sqlite3.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

static inline bool wallet_checked_output_valid(const void *out, size_t max, size_t size)
{
    return out && max && max <= INT_MAX && max <= SIZE_MAX / size;
}

bool db_wallet_tx_read_row(sqlite3_stmt *s, int col, struct db_wallet_tx *out);
enum db_wallet_tx_presence wallet_tx_find_checked(struct node_db *ndb,
    const uint8_t txid[32], struct db_wallet_tx *out);

/* Finalizes the statement and sets amounts and optional count to -1 on failure. */
bool wallet_tx_finish_balance(sqlite3_stmt *stmt, bool bound, int64_t *total_out, int *count_out);

/* Shared sum+count aggregate query (defined in wallet_tx_reads.c).
 * Used by db_wallet_utxo_balance_with_count and
 * db_sapling_note_balance_with_count. Keep read-only wallet aggregates in
 * wallet_tx_reads.c; keep validation, hooks, persistence, and relationships
 * in wallet_tx.c. */
bool wallet_tx_query_total_and_count(struct node_db *ndb,
                                     const char *sql,
                                     const void *bind_blob,
                                     size_t bind_blob_len,
                                     int64_t *total_out,
                                     int *count_out);

/* Shared UTXO row decoder; caller owns the returned script. */
void db_wallet_utxo_read_row(sqlite3_stmt *s, int col,
                             struct db_wallet_utxo *out);

/* SaplingNote row deserializer (defined in sapling_note.c).
 * Used by sapling list functions and by WalletTx has_many :sapling_notes
 * in wallet_tx.c. */
void db_sapling_note_read_row(sqlite3_stmt *s, int col,
                              struct db_sapling_note *out);

/* Read spent_txid column after the standard note columns (defined in
 * sapling_note.c). Used by sapling list_all and by db_wallet_tx_notes. */
void wallet_tx_read_spent_txid(sqlite3_stmt *s, int col,
                               struct db_sapling_note *n);

#endif
