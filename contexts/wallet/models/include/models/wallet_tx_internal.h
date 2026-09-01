/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 *
 * Internal helper contract shared between the wallet_tx ActiveRecord
 * model files (wallet_tx.c and sapling_note.c). NOT part of the public
 * model API — controllers/services must include models/wallet_tx.h.
 *
 * This header keeps shared wallet row readers and aggregate helpers visible
 * only to the wallet transaction / Sapling note model siblings that own those
 * tables. */

#ifndef ZCL_DB_MODEL_WALLET_TX_INTERNAL_H
#define ZCL_DB_MODEL_WALLET_TX_INTERNAL_H

#include "models/wallet_tx.h"
#include <sqlite3.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

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
